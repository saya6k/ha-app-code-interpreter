import os

import pytest

import sharefs
from sharefs import ShareError


@pytest.fixture
def share(tmp_path):
    root = tmp_path / "share"
    root.mkdir()
    (root / "energy.csv").write_text("a,b\n1,2\n")
    (root / "sub").mkdir()
    (root / "sub" / "x.txt").write_text("x")
    (tmp_path / "secret").write_text("nope")
    return root


@pytest.mark.parametrize("p", ["energy.csv", "/share/energy.csv", "sub/x.txt", "/sub/x.txt"])
def test_read_share_accepts_paths_inside(share, p):
    data = sharefs.read_share(p, 1000, root=share)
    assert data in (b"a,b\n1,2\n", b"x")


@pytest.mark.parametrize("p", ["../secret", "/share/../secret", "sub/../../secret", "", "sub", "missing.csv"])
def test_read_share_refuses_outside_dirs_and_missing(share, p):
    with pytest.raises(ShareError):
        sharefs.read_share(p, 1000, root=share)


def test_read_share_refuses_symlink_escape(share, tmp_path):
    (share / "link").symlink_to(tmp_path / "secret")
    with pytest.raises(ShareError, match="outside"):
        sharefs.read_share("link", 1000, root=share)


def test_read_share_size_cap(share):
    with pytest.raises(ShareError, match="larger than"):
        sharefs.read_share("energy.csv", 3, root=share)


def test_export_writes_under_sid_and_suffixes_on_collision(share):
    export_dir = share / "code-interpreter"
    p1 = sharefs.export(b"1", "plot.png", export_dir, "abc", root=share)
    p2 = sharefs.export(b"2", "plot.png", export_dir, "abc", root=share)
    p3 = sharefs.export(b"3", "plot.png", export_dir, "abc", root=share)
    assert [p.name for p in (p1, p2, p3)] == ["plot.png", "plot-1.png", "plot-2.png"]
    assert p1.parent == export_dir / "abc" and p3.read_bytes() == b"3"


@pytest.mark.parametrize("name", ["", ".", "..", "/"])
def test_export_refuses_empty_or_dot_names(share, name):
    with pytest.raises(ShareError):
        sharefs.export(b"x", name, share / "out", "abc", root=share)


def test_export_uses_only_the_basename(share):
    p = sharefs.export(b"x", "../../etc/evil.txt", share / "out", "abc", root=share)
    assert p == share / "out" / "abc" / "evil.txt"


def test_export_does_not_follow_a_planted_symlink(share, tmp_path):
    d = share / "out" / "abc"
    d.mkdir(parents=True)
    (d / "plot.png").symlink_to(tmp_path / "secret")
    p = sharefs.export(b"new", "plot.png", share / "out", "abc", root=share)
    assert p.name == "plot-1.png"
    assert (tmp_path / "secret").read_text() == "nope"


def test_export_refuses_a_symlinked_session_dir(share, tmp_path):
    (share / "out").mkdir()
    (share / "out" / "abc").symlink_to(tmp_path)
    with pytest.raises(ShareError, match="symlink"):
        sharefs.export(b"x", "a.txt", share / "out", "abc", root=share)
    assert not (tmp_path / "a.txt").exists()


def test_export_dir_must_be_inside_share(share, tmp_path):
    with pytest.raises(ShareError, match="outside"):
        sharefs.export(b"x", "a.txt", tmp_path / "elsewhere", "abc", root=share)


def test_traversal_to_a_missing_target_is_still_called_outside(share):
    with pytest.raises(ShareError, match="outside"):
        sharefs.read_share("../no/such/file", 1000, root=share)
