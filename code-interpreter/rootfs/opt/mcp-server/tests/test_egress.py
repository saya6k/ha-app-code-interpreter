import asyncio
import json
import os
import shutil
import stat
import tempfile

import pytest

import egress as proxy


def test_parse_allowlist_defaults_port_443_and_lowercases():
    assert proxy.parse_allowlist(["PyPI.org", "*.pythonhosted.org", "example.com:8443", ""]) == [
        ("pypi.org", 443),
        ("*.pythonhosted.org", 443),
        ("example.com", 8443),
    ]


@pytest.mark.parametrize(
    "host,port,ok",
    [
        ("pypi.org", 443, True),
        ("PYPI.ORG", 443, True),
        ("pypi.org.", 443, True),
        ("pypi.org", 80, False),
        ("evilpypi.org", 443, False),
        ("pypi.org.evil.com", 443, False),
        ("files.pythonhosted.org", 443, True),
        ("a.b.pythonhosted.org", 443, True),
        ("pythonhosted.org", 443, False),  # wildcard matches subdomains only
        ("xpythonhosted.org", 443, False),
        ("example.com", 8443, True),
        ("example.com", 443, False),
    ],
)
def test_is_allowed(host, port, ok):
    rules = proxy.parse_allowlist(["pypi.org", "*.pythonhosted.org", "example.com:8443"])
    assert proxy.is_allowed(host, port, rules) is ok


def test_empty_allowlist_denies_everything():
    assert proxy.is_allowed("pypi.org", 443, []) is False


@pytest.mark.parametrize(
    "line,expected",
    [
        ("CONNECT pypi.org:443 HTTP/1.1", ("CONNECT", "pypi.org", 443)),
        ("CONNECT pypi.org HTTP/1.1", ("CONNECT", "pypi.org", 443)),
        ("CONNECT [::1]:443 HTTP/1.1", ("CONNECT", "::1", 443)),
        ("GET http://example.com/ HTTP/1.1", ("GET", None, None)),
        ("CONNECT pypi.org:notaport HTTP/1.1", None),
        ("garbage", None),
    ],
)
def test_parse_request_line(line, expected):
    assert proxy.parse_request_line(line) == expected


@pytest.mark.parametrize(
    "host,ip", [("1.2.3.4", True), ("::1", True), ("pypi.org", False), ("1.2.3.4.nip.io", False)]
)
def test_is_ip_literal(host, ip):
    assert proxy.is_ip_literal(host) is ip


@pytest.mark.parametrize(
    "ip,public",
    [
        ("151.101.0.223", True),
        ("2a04:4e42::223", True),
        ("10.0.0.1", False),
        ("172.30.32.1", False),
        ("192.168.1.10", False),
        ("127.0.0.1", False),
        ("169.254.169.254", False),
        ("::1", False),
        ("fe80::1", False),
        ("100.64.0.1", False),
    ],
)
def test_is_public_ip(ip, public):
    assert proxy.is_public_ip(ip) is public


# ---- end-to-end against a local proxy instance (deny paths only; no internet) ----


async def _exchange(path: str, request: bytes) -> bytes:
    r, w = await asyncio.open_unix_connection(path)
    w.write(request)
    await w.drain()
    data = await asyncio.wait_for(r.read(4096), 5)
    w.close()
    return data


def _run_proxy_case(request: bytes, resolver=None):
    logs: list[dict] = []

    async def go():
        d = tempfile.mkdtemp(prefix="egress-", dir="/tmp")
        path = os.path.join(d, "proxy.sock")
        try:
            server = await proxy.serve_unix(
                path, proxy.parse_allowlist(["allowed.test"]), log=logs.append, resolver=resolver
            )
            assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
            async with server:
                reply = await _exchange(path, request)
            await asyncio.sleep(0.05)
            return reply
        finally:
            shutil.rmtree(d, ignore_errors=True)

    return asyncio.run(go()), logs


def test_denied_host_gets_403_and_is_logged():
    reply, logs = _run_proxy_case(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n")
    assert reply.startswith(b"HTTP/1.1 403")
    assert logs[0]["host"] == "example.com" and logs[0]["port"] == 443
    assert logs[0]["allowed"] is False
    assert {"bytes_up", "bytes_down", "duration_ms"} <= logs[0].keys()
    json.dumps(logs[0])


def test_plain_http_proxy_request_is_refused():
    reply, logs = _run_proxy_case(b"GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
    assert reply.startswith(b"HTTP/1.1 405")
    assert logs[0]["allowed"] is False


def test_ip_literal_target_is_refused():
    reply, logs = _run_proxy_case(b"CONNECT 1.1.1.1:443 HTTP/1.1\r\n\r\n")
    assert reply.startswith(b"HTTP/1.1 403")
    assert logs[0]["allowed"] is False


def test_allowed_name_resolving_to_private_ip_is_refused():
    async def resolver(host, port):
        return ["172.30.32.1"]

    reply, logs = _run_proxy_case(b"CONNECT allowed.test:443 HTTP/1.1\r\n\r\n", resolver)
    assert reply.startswith(b"HTTP/1.1 403")
    assert logs[0]["allowed"] is False
    assert logs[0]["reason"] == "non-public-address"


def test_tunnel_closes_and_logs_when_client_is_done_even_if_upstream_lingers(monkeypatch):
    """A keep-alive upstream must not hold the tunnel (and its log entry) open."""
    monkeypatch.setattr(proxy, "is_public_ip", lambda ip: True)
    logs: list[dict] = []

    async def go():
        async def upstream(r, w):  # echoes, never closes on its own
            while data := await r.read(65536):
                w.write(data)
                await w.drain()
            await asyncio.sleep(30)

        up = await asyncio.start_server(upstream, "127.0.0.1", 0)
        up_port = up.sockets[0].getsockname()[1]

        async def resolver(host, port):
            return ["127.0.0.1"]

        d = tempfile.mkdtemp(prefix="egress-", dir="/tmp")
        path = os.path.join(d, "proxy.sock")
        try:
            server = await proxy.serve_unix(
                path, proxy.parse_allowlist([f"allowed.test:{up_port}"]), log=logs.append, resolver=resolver
            )
            async with server:  # `up` lingers on purpose; close it without waiting
                r, w = await asyncio.open_unix_connection(path)
                w.write(f"CONNECT allowed.test:{up_port} HTTP/1.1\r\n\r\n".encode())
                assert (await r.readuntil(b"\r\n\r\n")).startswith(b"HTTP/1.1 200")
                w.write(b"ping")
                assert await asyncio.wait_for(r.readexactly(4), 5) == b"ping"
                w.write_eof()
                for _ in range(160):  # within DRAIN_AFTER_CLIENT_EOF_S + slack
                    if logs:
                        break
                    await asyncio.sleep(0.05)
                w.close()
        finally:
            up.close()
            shutil.rmtree(d, ignore_errors=True)

    asyncio.run(asyncio.wait_for(go(), 10))
    assert logs and logs[0]["allowed"] is True
    assert logs[0]["bytes_up"] == 4 and logs[0]["bytes_down"] == 4


@pytest.mark.parametrize(
    "entry",
    ["https://pypi.org", "pypi.org:0", "pypi.org:99999", "pypi.org:http", "1.2.3.4", "*.", "a b.com", "*"],
)
def test_invalid_allowlist_entries_are_rejected_by_name(entry):
    with pytest.raises(ValueError, match="invalid allowlist entry"):
        proxy.parse_rule(entry)


def test_half_closed_client_still_gets_the_upstream_answer(monkeypatch):
    """nc -N style: send, shutdown(SHUT_WR), then read."""
    monkeypatch.setattr(proxy, "is_public_ip", lambda ip: True)

    async def go():
        async def upstream(r, w):  # answers only after the client's EOF
            await r.read()
            w.write(b"pong")
            await w.drain()
            w.close()

        up = await asyncio.start_server(upstream, "127.0.0.1", 0)
        port = up.sockets[0].getsockname()[1]

        async def resolver(host, p):
            return ["127.0.0.1"]

        d = tempfile.mkdtemp(prefix="egress-", dir="/tmp")
        path = os.path.join(d, "proxy.sock")
        try:
            server = await proxy.serve_unix(path, proxy.parse_allowlist([f"allowed.test:{port}"]),
                                            log=lambda e: None, resolver=resolver)
            r, w = await asyncio.open_unix_connection(path)
            w.write(f"CONNECT allowed.test:{port} HTTP/1.1\r\n\r\n".encode())
            await r.readuntil(b"\r\n\r\n")
            w.write(b"ping")
            w.write_eof()
            got = await asyncio.wait_for(r.read(), 5)
            w.close()
            await proxy.close(server)
            up.close()
            return got
        finally:
            shutil.rmtree(d, ignore_errors=True)

    assert asyncio.run(asyncio.wait_for(go(), 10)) == b"pong"


def test_close_ends_a_handler_stuck_in_dns_quickly():
    logs = []

    async def go():
        async def stuck(host, port):
            await asyncio.sleep(3600)

        d = tempfile.mkdtemp(prefix="egress-", dir="/tmp")
        path = os.path.join(d, "proxy.sock")
        try:
            server = await proxy.serve_unix(path, proxy.parse_allowlist(["allowed.test"]),
                                            log=logs.append, resolver=stuck)
            r, w = await asyncio.open_unix_connection(path)
            w.write(b"CONNECT allowed.test:443 HTTP/1.1\r\n\r\n")
            await asyncio.sleep(0.2)
            t = asyncio.get_running_loop().time()
            await proxy.close(server)
            return asyncio.get_running_loop().time() - t
        finally:
            shutil.rmtree(d, ignore_errors=True)

    assert asyncio.run(asyncio.wait_for(go(), 10)) < 2
    assert logs and logs[0]["host"] == "allowed.test"
