"""Egress proxy sidecar: the sandbox's only way out (stdlib only).

HTTP CONNECT only. The target host:port must match the allowlist
(`host[:port]`, `*.domain` = subdomains only, port defaults to 443). Plain
HTTP proxying and IP-literal targets are refused, and names resolving only to
non-public addresses are refused (no reaching the HA host or LAN by DNS).
One JSON line per connection on stdout.

Env: EGRESS_ALLOWLIST (comma-separated), EGRESS_LISTEN (default 0.0.0.0:3128).
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import socket
import time
from typing import Awaitable, Callable

CONNECT_TIMEOUT_S = 10
HEADER_TIMEOUT_S = 10
HEADER_LIMIT = 8192

Rule = tuple[str, int]


def _norm(host: str) -> str:
    return host.strip().lower().rstrip(".")


def parse_allowlist(entries: list[str]) -> list[Rule]:
    rules = []
    for entry in entries:
        entry = entry.strip()
        if not entry:
            continue
        host, sep, port = entry.rpartition(":")
        if not sep:
            host, port = entry, "443"
        rules.append((_norm(host), int(port)))
    return rules


def is_allowed(host: str, port: int, rules: list[Rule]) -> bool:
    host = _norm(host)
    for pattern, rport in rules:
        if port != rport:
            continue
        if pattern.startswith("*."):
            if host.endswith(pattern[1:]):
                return True
        elif host == pattern:
            return True
    return False


def parse_request_line(line: str) -> tuple[str, str | None, int | None] | None:
    parts = line.split()
    if len(parts) != 3:
        return None
    method, target, _ = parts
    if method != "CONNECT":
        return (method, None, None)
    if target.startswith("["):
        host, _, rest = target[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else ""
    else:
        host, sep, port = target.rpartition(":")
        if not sep:
            host, port = target, ""
    try:
        return ("CONNECT", _norm(host), int(port) if port else 443)
    except ValueError:
        return None


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def is_public_ip(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return addr.is_global and not addr.is_multicast


async def _resolve(host: str, port: int) -> list[str]:
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(info[4][0] for info in infos))


async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter, counter: list[int]) -> None:
    try:
        while data := await src.read(65536):
            counter[0] += len(data)
            dst.write(data)
            await dst.drain()
        if dst.can_write_eof():
            dst.write_eof()
    except (ConnectionError, OSError):
        pass


async def _handle(reader, writer, rules, log, resolver) -> None:
    start = time.monotonic()
    peer = writer.get_extra_info("peername")
    entry = {
        "src_ip": peer[0] if peer else None,
        "host": None,
        "port": None,
        "allowed": False,
        "bytes_up": 0,
        "bytes_down": 0,
        "duration_ms": 0,
    }

    async def reply(status: str, reason: str | None = None) -> None:
        if reason:
            entry["reason"] = reason
        writer.write(f"HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n".encode())
        await writer.drain()

    try:
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), HEADER_TIMEOUT_S)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            entry["reason"] = "bad-request"
            return
        parsed = parse_request_line(head.split(b"\r\n", 1)[0].decode("latin-1"))
        if parsed is None:
            return await reply("400 Bad Request", "bad-request")
        method, host, port = parsed
        if method != "CONNECT":
            return await reply("405 Method Not Allowed", "method-not-allowed")
        entry["host"], entry["port"] = host, port
        if is_ip_literal(host):
            return await reply("403 Forbidden", "ip-literal")
        if not is_allowed(host, port, rules):
            return await reply("403 Forbidden", "not-allowlisted")
        try:
            addrs = await resolver(host, port)
        except OSError:
            addrs = []
        if not addrs:
            return await reply("502 Bad Gateway", "dns-failure")
        public = [a for a in addrs if is_public_ip(a)]
        if not public:
            return await reply("403 Forbidden", "non-public-address")
        entry["allowed"] = True
        upstream = None
        for addr in public:
            try:
                upstream = await asyncio.wait_for(
                    asyncio.open_connection(addr, port), CONNECT_TIMEOUT_S
                )
                break
            except (OSError, asyncio.TimeoutError):
                continue
        if upstream is None:
            return await reply("502 Bad Gateway", "connect-failed")
        up_reader, up_writer = upstream
        await reply("200 Connection Established")
        up, down = [0], [0]
        try:
            await asyncio.gather(_pipe(reader, up_writer, up), _pipe(up_reader, writer, down))
        finally:
            entry["bytes_up"], entry["bytes_down"] = up[0], down[0]
            up_writer.close()
    except (ConnectionError, OSError):
        pass
    finally:
        entry["duration_ms"] = int((time.monotonic() - start) * 1000)
        log(entry)
        writer.close()


async def serve(
    host: str,
    port: int,
    rules: list[Rule],
    *,
    log: Callable[[dict], None],
    resolver: Callable[[str, int], Awaitable[list[str]]] | None = None,
) -> asyncio.Server:
    resolver = resolver or _resolve
    return await asyncio.start_server(
        lambda r, w: _handle(r, w, rules, log, resolver), host, port, limit=HEADER_LIMIT
    )


def _print_json(entry: dict) -> None:
    print(json.dumps(entry), flush=True)


async def _main() -> None:
    rules = parse_allowlist(os.environ.get("EGRESS_ALLOWLIST", "").split(","))
    host, _, port = os.environ.get("EGRESS_LISTEN", "0.0.0.0:3128").rpartition(":")
    server = await serve(host, int(port), rules, log=_print_json)
    print(f"[egress] listening on {host}:{port}, {len(rules)} rule(s)", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(_main())
