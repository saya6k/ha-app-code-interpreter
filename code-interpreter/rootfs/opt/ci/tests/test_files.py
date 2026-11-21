"""ci/files.py — agent-side file ops, against a temp dir standing in for /sandbox."""

import importlib
import os
import sys
import threading
from pathlib import Path

import pytest

CI = Path(__file__).resolve().parents[1]


@pytest.fixture
def files(tmp_path, monkeypatch):
    root = tmp_path / "sbx"
    root.mkdir()
    (tmp_path / "outside.txt").write_text("secret")
    monkeypatch.setenv("CI_FILES_ROOT", str(root))
    monkeypatch.syspath_prepend(str(CI))
    mod = importlib.reload(importlib.import_module("files")) if "files" in sys.modules else importlib.import_module("files")
    mod.ROOT = str(root)
    return mod, root


def read_via(mod, path, limit):
    r, w = os.pipe()
    got = bytearray()

    def drain():
        while chunk := os.read(r, 65536):
            got.extend(chunk)
        os.close(r)

    t = threading.Thread(target=drain)
    t.start()
    reply = mod.handle({"op": "read", "path": path, "limit": limit}, [w])
    t.join(5)
    return reply, bytes(got)


def write_via(mod, path, data, max_bytes):
    r, w = os.pipe()

    def feed():
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(w, view):]
        except BrokenPipeError:
            pass
        finally:
            os.close(w)

    t = threading.Thread(target=feed)
    t.start()
    reply = mod.handle({"op": "write", "path": path, "max_bytes": max_bytes}, [r])
    t.join(5)
    return reply


def test_write_then_read_round_trip_large_binary(files):
    mod, root = files
    data = os.urandom(3 * 1024 * 1024)
    assert write_via(mod, "/sandbox/sub/dir/blob.bin", data, 5 << 20) == {
        "ok": True, "size": len(data), "path": "/sandbox/sub/dir/blob.bin"}
    reply, got = read_via(mod, "sub/dir/blob.bin", 10 << 20)
    assert reply == {"ok": True, "size": len(data), "sent": len(data)} and got == data


def test_read_limit_returns_prefix_and_full_size(files):
    mod, root = files
    (root / "t.txt").write_text("abcdefghij")
    reply, got = read_via(mod, "/sandbox/t.txt", 4)
    assert (reply["size"], reply["sent"], got) == (10, 4, b"abcd")


def test_write_over_limit_keeps_nothing(files):
    mod, root = files
    reply = write_via(mod, "big", b"x" * 2000, 1000)
    assert reply["ok"] is False and "exceeds" in reply["error"]
    assert not (root / "big").exists()


@pytest.mark.parametrize("path", ["/sandbox/../outside.txt", "../outside.txt", "/etc/passwd", "/tmp/x"])
def test_paths_outside_sandbox_are_refused(files, path):
    mod, _ = files
    reply, got = read_via(mod, path, 100)
    assert reply["ok"] is False and "outside /sandbox" in reply["error"] and got == b""


def test_symlink_out_of_sandbox_is_refused(files, tmp_path):
    mod, root = files
    (root / "link").symlink_to(tmp_path / "outside.txt")
    reply, got = read_via(mod, "link", 100)
    assert reply["ok"] is False and got == b""
    assert write_via(mod, "link", b"overwrite", 100)["ok"] is False
    assert (tmp_path / "outside.txt").read_text() == "secret"


def test_list_flat_and_recursive(files):
    mod, root = files
    (root / "a.txt").write_text("1")
    (root / "d").mkdir()
    (root / "d" / "b.txt").write_text("22")
    flat = mod.handle({"op": "list", "path": "/sandbox"}, [])
    assert [(e["path"], e["type"]) for e in flat["entries"]] == [("/sandbox/a.txt", "file"), ("/sandbox/d", "dir")]
    deep = mod.handle({"op": "list", "path": "/sandbox", "recursive": True}, [])
    assert [(e["path"], e["size"]) for e in deep["entries"] if e["type"] == "file"] == [
        ("/sandbox/a.txt", 1), ("/sandbox/d/b.txt", 2)]


def test_list_is_capped(files, monkeypatch):
    mod, root = files
    monkeypatch.setattr(mod, "LIST_CAP", 5)
    for i in range(8):
        (root / f"f{i}").write_text("")
    r = mod.handle({"op": "list", "path": "/sandbox"}, [])
    assert len(r["entries"]) == 5 and r["truncated"] is True


def test_bad_request_closes_passed_fds(files):
    mod, _ = files
    r, w = os.pipe()
    assert mod.handle({"op": "nope"}, [w])["ok"] is False
    assert os.read(r, 1) == b""  # w was closed
    os.close(r)
