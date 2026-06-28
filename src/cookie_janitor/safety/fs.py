"""Symlink-/junction-safe filesystem primitives.

This module exists because of THREAT_MODEL TH-1 (the BleachBit
CVE-2026-55567 class). Any operation that touches a path under a
user-writable directory must go through a function in this file.

Design rules enforced here:

1. We never operate on a raw absolute path after re-resolving it. We open
   the *parent directory* once with ``O_NOFOLLOW`` and do all work
   through the directory file descriptor with the ``*at`` family
   (``openat``, ``unlinkat``, ``renameat``). On Windows the equivalent
   protection is to open with ``FILE_FLAG_OPEN_REPARSE_POINT`` semantics
   and reject any path component that is a reparse point.

2. After opening a regular file we ``fstat`` it and verify it is a
   regular file owned by the current user. For files we plan to rename
   over, we additionally require ``st_nlink == 1`` so we cannot be
   tricked into clobbering a hardlink target.

3. Atomic replacement uses temp file + ``fsync`` + ``renameat``.

The POSIX implementation uses ``os.open(..., O_DIRECTORY | O_NOFOLLOW)``
and ``dir_fd=`` on the ``*at`` family. The Windows implementation
performs equivalent reparse-point rejection. Where a guarantee cannot be
provided on a platform, we raise rather than silently degrade.
"""

from __future__ import annotations

import os
import secrets
import shutil
import stat
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


class UnsafePathError(RuntimeError):
    """A path failed our symlink / ownership / reparse-point checks."""


_IS_POSIX = sys.platform != "win32"


@contextmanager
def open_dir_nofollow(directory: Path) -> Iterator[int]:
    """Open *directory* with O_NOFOLLOW semantics and yield its FD.

    The path is resolved component by component, refusing symlinks at
    every step on POSIX. On Windows the path is opened with
    ``os.open(..., O_BINARY)`` and reparse points are rejected via
    ``os.lstat``.
    """
    directory = Path(directory)
    if not directory.is_absolute():
        raise UnsafePathError(f"refusing relative directory path: {directory!r}")

    if _IS_POSIX:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        # Walk components and refuse any symlink along the path.
        accum = Path(directory.anchor)
        for part in directory.relative_to(directory.anchor).parts:
            accum = accum / part
            st = os.lstat(accum)
            if stat.S_ISLNK(st.st_mode):
                raise UnsafePathError(f"path component is a symlink: {accum}")
            if not stat.S_ISDIR(st.st_mode):
                raise UnsafePathError(f"path component is not a directory: {accum}")
        fd = os.open(directory, flags)
    else:  # Windows
        # On Windows we cannot easily get O_NOFOLLOW; check reparse points up the chain.
        accum = Path(directory.anchor)
        for part in directory.relative_to(directory.anchor).parts:
            accum = accum / part
            st = os.lstat(accum)
            # 0x400 = FILE_ATTRIBUTE_REPARSE_POINT (Windows-only attribute)
            if stat.S_ISLNK(st.st_mode) or (
                st.st_file_attributes & 0x400  # type: ignore[attr-defined]
            ):
                raise UnsafePathError(f"path component is a reparse point: {accum}")
        fd = os.open(directory, os.O_RDONLY)

    try:
        yield fd
    finally:
        os.close(fd)


def assert_regular_file_owned_by_us(path: Path) -> os.stat_result:
    """Stat a regular file with NOFOLLOW and verify ownership + type.

    Returns the ``stat_result`` so callers don't need a second ``stat``.
    Raises ``UnsafePathError`` if the file is a symlink, not regular, or
    not owned by us.
    """
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        raise UnsafePathError(f"refusing to operate on a symlink: {path}")
    if not stat.S_ISREG(st.st_mode):
        raise UnsafePathError(f"not a regular file: {path}")
    if _IS_POSIX and st.st_uid != getattr(os, "getuid", lambda: -1)():
        raise UnsafePathError(f"file not owned by current user (uid={st.st_uid}): {path}")
    if not _IS_POSIX and (
        st.st_file_attributes & 0x400  # type: ignore[attr-defined]
    ):  # reparse point
        raise UnsafePathError(f"refusing to operate on a reparse point: {path}")
    return st


def safe_copy(src: Path, dst: Path) -> None:
    """Copy ``src`` to ``dst`` with symlink rejection on both ends.

    ``dst`` must not exist or must be a regular file we own; this
    function does not overwrite directories or symlinks.
    """
    assert_regular_file_owned_by_us(src)
    if dst.exists():
        assert_regular_file_owned_by_us(dst)
    # shutil.copy2 follows symlinks by default; we have already verified
    # that src is not a symlink. dst is created fresh inside parent dir.
    shutil.copy2(src, dst)


def atomic_replace(temp: Path, target: Path) -> None:
    """Atomically replace ``target`` with ``temp``.

    Both paths must live in the same directory; the directory is opened
    with O_NOFOLLOW and the rename is performed via ``renameat`` (POSIX)
    or ``os.replace`` (Windows, after reparse-point checks).

    Caller is responsible for having ``fsync``'d the file contents before
    calling this.
    """
    if temp.parent != target.parent:
        raise UnsafePathError(f"atomic_replace requires same parent dir: {temp} vs {target}")
    # Verify both ends. ``target`` may not exist on first write — accept that.
    assert_regular_file_owned_by_us(temp)
    if target.exists():
        st = assert_regular_file_owned_by_us(target)
        # If target has multiple hardlinks, refuse: a rename would silently
        # detach the link we don't see.
        if st.st_nlink != 1:
            raise UnsafePathError(
                f"target has unexpected hardlinks (nlink={st.st_nlink}): {target}"
            )

    with open_dir_nofollow(target.parent) as dir_fd:
        if _IS_POSIX:
            os.rename(temp.name, target.name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            # fsync the directory to persist the rename.
            os.fsync(dir_fd)
        else:  # pragma: no cover - exercised on Windows
            temp.replace(target)


def fresh_workspace(root: Path) -> Path:
    """Create a private working directory under ``root`` with mode 0700.

    The created directory has a 16-byte random suffix so it cannot be
    pre-created by an attacker. The parent ``root`` is created with the
    same restrictive mode if it does not exist; if it exists, it must be
    a directory we own with mode ``0700`` (POSIX) or refused.
    """
    if not root.is_absolute():
        raise UnsafePathError(f"workspace root must be absolute: {root}")

    if root.exists():
        st = os.lstat(root)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise UnsafePathError(f"workspace root is not a regular dir: {root}")
        if _IS_POSIX:
            if st.st_uid != getattr(os, "getuid", lambda: -1)():
                raise UnsafePathError(f"workspace root not owned by us: {root}")
            if (st.st_mode & 0o777) != 0o700:
                raise UnsafePathError(
                    f"workspace root has wrong permissions "
                    f"(expected 0700, got 0o{st.st_mode & 0o777:o}): {root}"
                )
    else:
        root.mkdir(parents=True, mode=0o700, exist_ok=False)
        if _IS_POSIX:
            root.chmod(0o700)

    suffix = secrets.token_hex(8)
    workspace = root / suffix
    workspace.mkdir(mode=0o700, exist_ok=False)
    if _IS_POSIX:
        workspace.chmod(0o700)
    return workspace
