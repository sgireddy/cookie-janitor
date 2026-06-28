"""Safety primitive tests: symlinks must be rejected.

These are the regression tests for the BleachBit-class threat (TH-1).
If any of these starts passing through where it should raise, that is
a security regression.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from cookie_janitor.safety import fs as safe_fs


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlink tests")
def test_assert_regular_file_rejects_symlink(tmp_path: Path):
    real = tmp_path / "real"
    real.write_bytes(b"hi")
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(safe_fs.UnsafePathError, match="symlink"):
        safe_fs.assert_regular_file_owned_by_us(link)


def test_assert_regular_file_accepts_owned_regular_file(tmp_path: Path):
    p = tmp_path / "real"
    p.write_bytes(b"hi")
    st = safe_fs.assert_regular_file_owned_by_us(p)
    assert st.st_size == 2


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlink tests")
def test_open_dir_nofollow_rejects_symlinked_component(tmp_path: Path):
    real_dir = tmp_path / "real_dir"
    real_dir.mkdir()
    link_dir = tmp_path / "link_dir"
    link_dir.symlink_to(real_dir)
    with (
        pytest.raises(safe_fs.UnsafePathError, match="symlink"),
        safe_fs.open_dir_nofollow(link_dir),
    ):
        pass


def test_atomic_replace_requires_same_parent(tmp_path: Path):
    a = tmp_path / "a"
    a.write_bytes(b"x")
    other = tmp_path / "sub"
    other.mkdir()
    b = other / "b"
    b.write_bytes(b"y")
    with pytest.raises(safe_fs.UnsafePathError, match="same parent"):
        safe_fs.atomic_replace(a, b)


def test_atomic_replace_works_within_same_dir(tmp_path: Path):
    tmp_file = tmp_path / "tmp"
    target = tmp_path / "target"
    tmp_file.write_bytes(b"new")
    target.write_bytes(b"old")
    safe_fs.atomic_replace(tmp_file, target)
    assert target.read_bytes() == b"new"
    assert not tmp_file.exists()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode checks")
def test_fresh_workspace_creates_700_dir(tmp_path: Path):
    root = tmp_path / "root"
    ws = safe_fs.fresh_workspace(root)
    assert ws.is_dir()
    assert (ws.stat().st_mode & 0o777) == 0o700
    assert (root.stat().st_mode & 0o777) == 0o700


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode checks")
def test_fresh_workspace_refuses_world_readable_root(tmp_path: Path):
    root = tmp_path / "loose"
    root.mkdir(mode=0o755)
    root.chmod(0o755)
    with pytest.raises(safe_fs.UnsafePathError, match="permissions"):
        safe_fs.fresh_workspace(root)
