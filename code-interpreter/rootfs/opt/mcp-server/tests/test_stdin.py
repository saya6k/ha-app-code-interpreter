"""stdin.py + stdin_reader.py: Home Assistant's stdin lines reach the handler."""

import asyncio
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import stdin

READER = Path(__file__).resolve().parents[1] / "stdin_reader.py"
LINE = '{"type": "skill.request", "user": "bob", "request": "lights"}'


def short_socket() -> Path:
    # AF_UNIX paths are limited to ~104 bytes: pytest's tmp_path can be longer.
    return Path(tempfile.mkdtemp(prefix="ci-")) / "s" / "stdin.sock"


def test_reader_forwards_each_line_to_the_server():
    path = short_socket()
    got = []

    async def go():
        server = await stdin.serve(got.append, path)
        assert oct(path.stat().st_mode & 0o777) == "0o600" and oct(path.parent.stat().st_mode & 0o777) == "0o700"
        proc = await asyncio.create_subprocess_exec(
            sys.executable, str(READER), stdin=subprocess.PIPE,
            env={**os.environ, "CI_STDIN_SOCK": str(path), "CI_STDIN_EXIT_AT_EOF": "1"})
        await proc.communicate((LINE + "\n\n" + '{"n": 2}' + "\n").encode())
        assert proc.returncode == 0
        for _ in range(50):
            if len(got) == 2:
                break
            await asyncio.sleep(0.05)
        server.close()

    asyncio.run(go())
    assert got == [LINE, '{"n": 2}']


def test_an_oversized_line_is_dropped_and_the_server_keeps_serving():
    path = short_socket()
    got = []

    async def send(data: bytes):
        _, w = await asyncio.open_unix_connection(str(path))
        w.write(data)
        await w.drain()
        w.close()

    async def go():
        server = await stdin.serve(got.append, path)
        await send(b"x" * (stdin.LINE_LIMIT + 10) + b"\n")
        await send(b"ok\n")
        for _ in range(50):
            if got:
                break
            await asyncio.sleep(0.05)
        server.close()

    asyncio.run(go())
    assert got == ["ok"]
