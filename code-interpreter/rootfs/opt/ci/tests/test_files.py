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


# ---- review fixes (00fd254^..HEAD) -----------------------------------------

def test_fifo_is_refused_without_blocking(files):
    mod, root = files
    os.mkfifo(root / "p")
    result = {}
    t = threading.Thread(target=lambda: result.update(r=read_via(mod, "p", 100)))
    t.start()
    t.join(3)
    assert not t.is_alive(), "agent blocked opening a FIFO"
    reply, got = result["r"]
    assert reply["ok"] is False and "regular file" in reply["error"]
    w = {}
    t = threading.Thread(target=lambda: w.update(r=write_via(mod, "p", b"x", 100)))
    t.start()
    t.join(3)
    assert not t.is_alive() and w["r"]["ok"] is False


def test_failed_overwrite_keeps_the_original(files):
    mod, root = files
    (root / "data.csv").write_text("precious")
    reply = write_via(mod, "data.csv", b"x" * 2000, 1000)  # over the limit
    assert reply["ok"] is False
    assert (root / "data.csv").read_text() == "precious"
    assert sorted(p.name for p in root.iterdir()) == ["data.csv"]  # no temp file left


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory permissions")
def test_failed_write_into_readonly_file_keeps_it(files):
    mod, root = files
    f = root / "ro.txt"
    f.write_text("keep")
    os.chmod(root, 0o555)  # cannot create the temp file next to it
    try:
        assert write_via(mod, "ro.txt", b"new", 100)["ok"] is False
    finally:
        os.chmod(root, 0o755)
    assert f.read_text() == "keep"


def test_successful_overwrite_replaces_atomically(files):
    mod, root = files
    (root / "a.txt").write_text("old")
    assert write_via(mod, "a.txt", b"new", 100)["ok"] is True
    assert (root / "a.txt").read_text() == "new"
    assert sorted(p.name for p in root.iterdir()) == ["a.txt"]


def test_listing_skips_entries_it_cannot_stat_or_enter(files):
    mod, root = files
    (root / "ok.txt").write_text("1")
    locked = root / "locked"
    locked.mkdir()
    (locked / "inner.txt").write_text("2")
    os.chmod(locked, 0o600)  # readable, not traversable
    try:
        r = mod.handle({"op": "list", "path": "/sandbox", "recursive": True}, [])
    finally:
        os.chmod(locked, 0o755)
    assert r["ok"] is True
    assert "/sandbox/ok.txt" in [e["path"] for e in r["entries"]]


def test_listing_without_dot_dirs_reaches_files_past_a_big_dot_tree(files, monkeypatch):
    mod, root = files
    monkeypatch.setattr(mod, "LIST_CAP", 20)
    site = root / ".local" / "lib"
    site.mkdir(parents=True)
    for i in range(50):
        (site / f"m{i}.py").write_text("")
    (root / "out").mkdir()
    (root / "out" / "plot.png").write_text("x")
    r = mod.handle({"op": "list", "path": "/sandbox", "recursive": True, "skip_dot": True}, [])
    paths = [e["path"] for e in r["entries"]]
    assert "/sandbox/out/plot.png" in paths and not any("/." in p for p in paths)


def test_listing_reply_is_capped_by_bytes(files, monkeypatch):
    mod, root = files
    monkeypatch.setattr(mod, "REPLY_BYTES", 2000)
    for i in range(100):
        (root / (f"{i:03d}-" + "n" * 100)).write_text("")
    r = mod.handle({"op": "list", "path": "/sandbox"}, [])
    import json as _json
    assert r["truncated"] is True and len(_json.dumps(r)) <= 2000
