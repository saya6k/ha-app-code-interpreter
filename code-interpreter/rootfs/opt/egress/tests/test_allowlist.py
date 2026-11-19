import asyncio
import json

import pytest

import proxy


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


async def _exchange(port: int, request: bytes) -> bytes:
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(request)
    await w.drain()
    data = await asyncio.wait_for(r.read(4096), 5)
    w.close()
    return data


def _run_proxy_case(request: bytes, resolver=None):
    logs: list[dict] = []

    async def go():
        server = await proxy.serve(
            "127.0.0.1",
            0,
            proxy.parse_allowlist(["allowed.test"]),
            log=logs.append,
            resolver=resolver,
        )
        port = server.sockets[0].getsockname()[1]
        async with server:
            reply = await _exchange(port, request)
        await asyncio.sleep(0.05)
        return reply

    return asyncio.run(go()), logs


def test_denied_host_gets_403_and_is_logged():
    reply, logs = _run_proxy_case(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n")
    assert reply.startswith(b"HTTP/1.1 403")
    assert logs[0]["host"] == "example.com" and logs[0]["port"] == 443
    assert logs[0]["allowed"] is False
    assert {"src_ip", "bytes_up", "bytes_down", "duration_ms"} <= logs[0].keys()
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
