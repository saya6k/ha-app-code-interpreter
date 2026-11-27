"""Lines Home Assistant sends to the app's stdin (hassio.app_stdin), handed
to the MCP server (SPEC-code-mode §3.12).

Only the container's main program gets the stdin pipe (s6 services get
/dev/null), so stdin_reader.py runs as the image's CMD and passes each line
here over a root-only Unix socket. Fire-and-forget: Home Assistant expects no
answer, so outcomes go to the audit log.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from pathlib import Path
from typing import Callable

log = logging.getLogger("mcp-server")

SOCKET = Path(os.environ.get("CI_STDIN_SOCK", "/run/code-interpreter/stdin.sock"))
LINE_LIMIT = 64 * 1024


async def serve(handle: Callable[[str], None], path: Path = SOCKET) -> asyncio.AbstractServer:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with contextlib.suppress(FileNotFoundError):
        path.unlink()

    async def client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while line := await reader.readline():
                text = line.decode(errors="replace").strip()
                if text:
                    handle(text)
        except (ValueError, asyncio.LimitOverrunError):  # a line over LINE_LIMIT
            log.warning("[stdin] input line over %d bytes dropped", LINE_LIMIT)
        finally:
            writer.close()

    server = await asyncio.start_unix_server(client, path=str(path), limit=LINE_LIMIT)
    os.chmod(path, 0o600)
    return server
