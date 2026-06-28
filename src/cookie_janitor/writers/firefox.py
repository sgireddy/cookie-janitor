"""Firefox cookie writer.

Workflow:

1. Refuse if the browser is running (TH-7).
2. Stat the original cookies.sqlite via the safety primitives. Symlinks
   are rejected.
3. Copy the original to a backup directory under
   ``~/.local/state/cookie-janitor/backups/<browser>/<profile>/<ts>/`` —
   mode 0700, owned by us. The backup is verified by size + sha256 of
   both ends.
4. Copy the original to a working file ``cookies.sqlite.cj-tmp`` in the
   same directory as the original (required by ``atomic_replace``).
5. Open the working file via SQLite, delete the requested rows, run
   ``VACUUM`` to make sure value bytes are actually freed from the
   underlying pages, ``PRAGMA wal_checkpoint(TRUNCATE)`` to drop any
   WAL frames, then ``fsync`` and close.
6. ``atomic_replace`` swaps the working file into place.

If anything fails between step 4 and 6 the original is untouched; the
working file is cleaned up in the ``finally`` block. The backup from
step 3 always exists after step 3 completes, even on later failure.
"""

from __future__ import annotations

import contextlib
import hashlib
import logging
import os
import sqlite3
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from cookie_janitor.model.cookie import BrowserKind, Cookie, Profile
from cookie_janitor.safety import fs as safe_fs
from cookie_janitor.safety.process import is_running as _is_browser_running

from .types import WriteResult

log = logging.getLogger(__name__)

_BACKUP_ROOT_ENV = "COOKIE_JANITOR_BACKUP_ROOT"


def _backup_root() -> Path:
    """Return the per-user backup root: $COOKIE_JANITOR_BACKUP_ROOT or default."""
    override = os.environ.get(_BACKUP_ROOT_ENV)
    if override:
        return Path(override)
    # XDG-style default; safe on macOS and Linux. On Windows we fall back
    # to %LOCALAPPDATA% via Path.home() / "AppData/Local".
    if os.name == "nt":  # pragma: no cover - exercised on Windows
        return Path.home() / "AppData" / "Local" / "cookie-janitor" / "backups"
    return Path.home() / ".local" / "state" / "cookie-janitor" / "backups"


def _hash_file(path: Path) -> str:
    """Return hex sha256 of ``path``. Reads in 1 MiB chunks."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _make_backup(profile: Profile, root: Path) -> Path:
    """Copy the original cookies.sqlite into a fresh 0700 directory.

    Verifies the backup with a size + sha256 check before returning.
    """
    src = profile.cookies_db_path
    safe_fs.assert_regular_file_owned_by_us(src)

    ts = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
    leaf = root / profile.browser.value / profile.profile_name / ts
    leaf.mkdir(parents=True, mode=0o700, exist_ok=False)
    if os.name != "nt":
        leaf.chmod(0o700)

    backup_path = leaf / "cookies.sqlite"
    backup_path.touch(mode=0o600, exist_ok=False)
    safe_fs.safe_copy(src, backup_path)

    src_st = src.stat()
    bkp_st = backup_path.stat()
    if src_st.st_size != bkp_st.st_size:
        raise RuntimeError(f"backup size mismatch: src={src_st.st_size} bkp={bkp_st.st_size}")
    if _hash_file(src) != _hash_file(backup_path):
        raise RuntimeError(f"backup hash mismatch for {src} → {backup_path}")

    log.info("Backed up %s → %s (%d bytes)", src, backup_path, bkp_st.st_size)
    return backup_path


def _delete_rows(db_path: Path, identities: Iterable[tuple[str, str, str]]) -> int:
    """Delete cookies by ``(host, path, name)`` from a SQLite file.

    Returns the number of rows actually deleted.

    Firefox stores host-only cookies without a leading dot, and
    domain cookies with a leading dot. The Cookie.domain field
    already matches Firefox's host column verbatim so we can compare
    directly.

    After delete we run ``VACUUM`` to free pages and reclaim space
    so the cookie value bytes don't linger in the file. Then we
    truncate the WAL.
    """
    deleted = 0
    conn = sqlite3.connect(db_path, isolation_level=None)
    try:
        conn.execute("PRAGMA foreign_keys = OFF")
        conn.execute("BEGIN IMMEDIATE")
        for host, path, name in identities:
            cur = conn.execute(
                "DELETE FROM moz_cookies WHERE host = ? AND path = ? AND name = ?",
                (host, path, name),
            )
            deleted += cur.rowcount or 0
        conn.execute("COMMIT")
        conn.execute("VACUUM")
        # File may not be in WAL mode; ignore the resulting error.
        with contextlib.suppress(sqlite3.DatabaseError):
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        conn.close()
    return deleted


def delete_cookies(
    profile: Profile,
    cookies_to_delete: Iterable[Cookie],
    *,
    dry_run: bool = True,
    backup_root: Path | None = None,
) -> WriteResult:
    """Delete the given cookies from ``profile``.

    On dry-run we count and return without touching anything. On apply we
    take a verified backup, perform the delete on a copy in the same
    directory, then atomically swap. Refuses if the browser is running.
    """
    if profile.browser is not BrowserKind.FIREFOX:
        raise ValueError(f"delete_cookies(firefox) called with {profile.browser}")

    identities = [c.identity for c in cookies_to_delete]
    timestamp = datetime.now(tz=UTC)

    if dry_run:
        return WriteResult(
            profile=profile,
            requested_deletes=len(identities),
            actually_deleted=len(identities),
            backup_path=None,
            dry_run=True,
            timestamp=timestamp,
        )

    if _is_browser_running(profile.browser):
        raise RuntimeError(
            f"Refusing to write: {profile.browser.value} is currently running. "
            "Close it fully and try again."
        )

    src = profile.cookies_db_path
    safe_fs.assert_regular_file_owned_by_us(src)

    # Step 1: backup.
    root = backup_root or _backup_root()
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    if os.name != "nt":
        root.chmod(0o700)
    backup_path = _make_backup(profile, root)

    # Step 2: working copy in the SAME directory as the original
    # (atomic_replace requires same parent). Use a non-obvious name so a
    # half-finished swap is recognisable.
    working = src.with_name(src.name + ".cj-tmp")
    if working.exists():
        # A previous run left debris. Refuse rather than guess.
        raise RuntimeError(
            f"Working file already exists from a previous run: {working}. Move it aside and retry."
        )
    working.touch(mode=0o600, exist_ok=False)
    try:
        safe_fs.safe_copy(src, working)

        # Step 3: perform the delete on the working copy.
        deleted = _delete_rows(working, [c.identity for c in cookies_to_delete])

        # Step 4: durability before swap.
        with working.open("rb") as fh:
            os.fsync(fh.fileno())

        # Step 5: atomic swap.
        safe_fs.atomic_replace(working, src)
    except BaseException:
        # If anything went wrong, drop the working file. The original is
        # untouched at this point (atomic_replace either succeeded
        # completely or didn't happen).
        if working.exists():
            try:
                working.unlink()
            except OSError:
                log.exception("Failed to clean up working file %s", working)
        raise

    log.info(
        "Deleted %d/%d cookies from %s (backup at %s)",
        deleted,
        len(identities),
        src,
        backup_path,
    )
    return WriteResult(
        profile=profile,
        requested_deletes=len(identities),
        actually_deleted=deleted,
        backup_path=backup_path,
        dry_run=False,
        timestamp=timestamp,
    )


def restore_from_backup(profile: Profile, backup_path: Path) -> None:
    """Atomically replace ``profile``'s cookies.sqlite with ``backup_path``.

    Refuses if the browser is running. Verifies the backup is a regular
    file we own before swapping.
    """
    if profile.browser is not BrowserKind.FIREFOX:
        raise ValueError(f"restore_from_backup(firefox) called with {profile.browser}")
    if _is_browser_running(profile.browser):
        raise RuntimeError(f"Refusing to restore: {profile.browser.value} is currently running.")
    safe_fs.assert_regular_file_owned_by_us(backup_path)

    src = profile.cookies_db_path
    working = src.with_name(src.name + ".cj-restore-tmp")
    if working.exists():
        raise RuntimeError(f"Working file already exists: {working}")
    working.touch(mode=0o600, exist_ok=False)
    try:
        safe_fs.safe_copy(backup_path, working)
        with working.open("rb") as fh:
            os.fsync(fh.fileno())
        safe_fs.atomic_replace(working, src)
    except BaseException:
        if working.exists():
            try:
                working.unlink()
            except OSError:
                log.exception("Failed to clean up restore working file %s", working)
        raise
    log.info("Restored %s from %s", src, backup_path)
