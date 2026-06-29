"""Chromium-family cookie writer.

Deletes selected rows from the ``Cookies`` SQLite file. Same shape as
``writers.firefox`` — verified backup → working copy → SQLite delete →
``VACUUM`` → ``PRAGMA wal_checkpoint(TRUNCATE)`` → ``fsync`` →
``atomic_replace``. We deduplicate the workflow with the Firefox writer
where we can (the safety primitives and the backup helper are shared)
and keep the SQL distinct.

Chromium's cookies schema columns differ from Firefox's:

* ``host_key`` (not ``host``)
* ``is_secure`` / ``is_httponly`` (not ``isSecure`` / ``isHttpOnly``)
* ``expires_utc`` in WebKit-microseconds (not seconds)

We delete by ``(host_key, path, name)`` — those three columns are part
of Chrome's primary key and uniquely identify a cookie. We do NOT
require value match; that's correct because the same logical cookie
might have been updated between read and delete.

WAL caveat
----------
Chrome heavily uses WAL. After ``DELETE`` we ``VACUUM`` to actually
free pages and reclaim space (so cookie values don't linger on free
pages), then ``PRAGMA wal_checkpoint(TRUNCATE)`` to flush the WAL into
the main file. The atomic_replace at the end picks up just the main
file; the WAL/SHM sidecars (now empty) will be ignored on next browser
start.

This module deliberately re-uses the *exact same* on-disk backup tree
as the Firefox writer, keyed by ``profile.browser`` + ``profile.profile_name``:
``~/.local/state/cookie-janitor/backups/chromium/<profile>/<ts>/``.
``restore`` works for any browser through the dispatcher.
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
    override = os.environ.get(_BACKUP_ROOT_ENV)
    if override:
        return Path(override)
    if os.name == "nt":  # pragma: no cover - Windows
        return Path.home() / "AppData" / "Local" / "cookie-janitor" / "backups"
    return Path.home() / ".local" / "state" / "cookie-janitor" / "backups"


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _make_backup(profile: Profile, root: Path) -> Path:
    src = profile.cookies_db_path
    safe_fs.assert_regular_file_owned_by_us(src)
    ts = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
    leaf = root / profile.browser.value / profile.profile_name / ts
    leaf.mkdir(parents=True, mode=0o700, exist_ok=False)
    if os.name != "nt":
        leaf.chmod(0o700)
    backup_path = leaf / "Cookies"
    backup_path.touch(mode=0o600, exist_ok=False)
    safe_fs.safe_copy(src, backup_path)
    if src.stat().st_size != backup_path.stat().st_size:
        raise RuntimeError("Chromium backup: size mismatch")
    if _hash_file(src) != _hash_file(backup_path):
        raise RuntimeError(f"Chromium backup: hash mismatch for {src}")
    log.info("Backed up %s -> %s", src, backup_path)
    return backup_path


def _delete_rows(db_path: Path, identities: Iterable[tuple[str, str, str]]) -> int:
    """Delete cookies by ``(host_key, path, name)``.

    Returns the number of rows actually deleted. The query is robust to
    older Chrome schemas (where the host column was named ``host``
    instead of ``host_key``) by probing PRAGMA table_info up-front.
    """
    deleted = 0
    conn = sqlite3.connect(db_path, isolation_level=None)
    try:
        cur = conn.execute("PRAGMA table_info(cookies)")
        cols = {row[1] for row in cur.fetchall()}
        host_col = "host_key" if "host_key" in cols else "host"
        conn.execute("PRAGMA foreign_keys = OFF")
        conn.execute("BEGIN IMMEDIATE")
        sql = (
            f"DELETE FROM cookies WHERE {host_col} = ? AND path = ? AND name = ?"  # noqa: S608
        )
        for host, path, name in identities:
            cur = conn.execute(sql, (host, path, name))
            deleted += cur.rowcount or 0
        conn.execute("COMMIT")
        conn.execute("VACUUM")
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
    """Delete the given cookies from a Chromium profile.

    Symmetric with ``writers.firefox.delete_cookies``: dry-run by
    default, refuses if the browser is running, takes a verified
    backup, and only performs an atomic swap after a successful delete.
    """
    if profile.browser is not BrowserKind.CHROMIUM:
        raise ValueError(f"delete_cookies(chromium) called with {profile.browser}")

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
            "Close every Chromium-family browser fully and try again."
        )

    src = profile.cookies_db_path
    safe_fs.assert_regular_file_owned_by_us(src)

    root = backup_root or _backup_root()
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    if os.name != "nt":
        root.chmod(0o700)
    backup_path = _make_backup(profile, root)

    working = src.with_name(src.name + ".cj-tmp")
    if working.exists():
        raise RuntimeError(
            f"Working file already exists from a previous run: {working}."
            " Move it aside and retry."
        )
    working.touch(mode=0o600, exist_ok=False)
    try:
        safe_fs.safe_copy(src, working)
        deleted = _delete_rows(working, identities)
        with working.open("rb+") as fh:
            fh.flush()
            os.fsync(fh.fileno())
        safe_fs.atomic_replace(working, src)
    except BaseException:
        if working.exists():
            try:
                working.unlink()
            except OSError:
                log.exception("Failed to clean up working file %s", working)
        raise

    log.info(
        "Deleted %d/%d Chromium cookies from %s (backup at %s)",
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
    """Atomically restore a Chromium ``Cookies`` file from a backup."""
    if profile.browser is not BrowserKind.CHROMIUM:
        raise ValueError(f"restore_from_backup(chromium) called with {profile.browser}")
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
        with working.open("rb+") as fh:
            fh.flush()
            os.fsync(fh.fileno())
        safe_fs.atomic_replace(working, src)
    except BaseException:
        if working.exists():
            try:
                working.unlink()
            except OSError:
                log.exception("Failed to clean up restore working file %s", working)
        raise
    log.info("Restored Chromium %s from %s", src, backup_path)
