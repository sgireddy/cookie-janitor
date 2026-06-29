"""Unit tests for the Chromium cookie writer.

Same shape as the Firefox writer tests: build a synthetic Cookies DB,
delete specific rows, assert deletion happened, backup verified, etc.
We never touch a real Chrome installation.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from cookie_janitor.model.cookie import (
    BrowserKind,
    Profile,
    SameSite,
    make_cookie,
)
from cookie_janitor.writers import chromium as chromium_writer

_WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)


def _to_webkit_micros(dt: datetime) -> int:
    return int((dt - _WEBKIT_EPOCH).total_seconds() * 1_000_000)


def _seed_db(path: Path) -> None:
    """Create a small ``Cookies`` SQLite file with three rows."""
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    try:
        conn.executescript(
            """
            CREATE TABLE cookies (
                creation_utc INTEGER NOT NULL,
                host_key TEXT NOT NULL,
                top_frame_site_key TEXT NOT NULL DEFAULT '',
                name TEXT NOT NULL,
                value TEXT NOT NULL,
                encrypted_value BLOB DEFAULT '',
                path TEXT NOT NULL,
                expires_utc INTEGER NOT NULL,
                is_secure INTEGER NOT NULL,
                is_httponly INTEGER NOT NULL,
                last_access_utc INTEGER NOT NULL DEFAULT 0,
                has_expires INTEGER NOT NULL DEFAULT 1,
                is_persistent INTEGER NOT NULL DEFAULT 1,
                priority INTEGER NOT NULL DEFAULT 1,
                samesite INTEGER NOT NULL,
                source_scheme INTEGER NOT NULL DEFAULT 2,
                source_port INTEGER NOT NULL DEFAULT 443,
                is_same_party INTEGER NOT NULL DEFAULT 0,
                last_update_utc INTEGER NOT NULL DEFAULT 0
            );
            """
        )
        future = _to_webkit_micros(datetime.now(tz=UTC) + timedelta(days=30))
        for host, name in [
            (".tracker.com", "_ga"),
            (".tracker.com", "_gid"),
            (".keepme.example.com", "session"),
        ]:
            conn.execute(
                """
                INSERT INTO cookies (creation_utc, host_key, name, value,
                                     path, expires_utc, is_secure,
                                     is_httponly, samesite)
                VALUES (0, ?, ?, '', '/', ?, 1, 0, -1)
                """,
                (host, name, future),
            )
        conn.commit()
    finally:
        conn.close()


def _make_profile(db_path: Path) -> Profile:
    return Profile(
        browser=BrowserKind.CHROMIUM,
        vendor="Google Chrome",
        profile_name="Default",
        cookies_db_path=db_path,
        is_running=False,
    )


def _cookie(host: str, name: str):
    return make_cookie(
        name=name,
        domain=host,
        path="/",
        expires=datetime.now(tz=UTC) + timedelta(days=1),
        secure=True,
        http_only=False,
        same_site=SameSite.UNSPECIFIED,
        is_host_only=not host.startswith("."),
        value_bytes=b"",
    )


# -----------------------------------------------------------------------------


def test_dry_run_does_not_modify_file(tmp_path):
    db = tmp_path / "Default" / "Cookies"
    _seed_db(db)
    before = db.read_bytes()
    profile = _make_profile(db)
    result = chromium_writer.delete_cookies(
        profile,
        [_cookie(".tracker.com", "_ga")],
        dry_run=True,
        backup_root=tmp_path / "backups",
    )
    assert result.dry_run is True
    assert result.requested_deletes == 1
    assert result.actually_deleted == 1  # planned, not real
    assert result.backup_path is None
    assert db.read_bytes() == before, "dry-run must not touch the file"


def test_apply_deletes_matching_rows_and_writes_backup(tmp_path, monkeypatch):
    db = tmp_path / "Default" / "Cookies"
    _seed_db(db)
    monkeypatch.setattr(chromium_writer, "_is_browser_running", lambda _b: False)

    profile = _make_profile(db)
    result = chromium_writer.delete_cookies(
        profile,
        [
            _cookie(".tracker.com", "_ga"),
            _cookie(".tracker.com", "_gid"),
        ],
        dry_run=False,
        backup_root=tmp_path / "backups",
    )

    assert result.dry_run is False
    assert result.requested_deletes == 2
    assert result.actually_deleted == 2
    assert result.backup_path is not None
    assert result.backup_path.is_file()

    # Only the keepme cookie should remain.
    conn = sqlite3.connect(db)
    try:
        rows = conn.execute("SELECT host_key, name FROM cookies").fetchall()
    finally:
        conn.close()
    assert rows == [(".keepme.example.com", "session")]


def test_apply_refuses_when_browser_running(tmp_path, monkeypatch):
    db = tmp_path / "Default" / "Cookies"
    _seed_db(db)
    monkeypatch.setattr(chromium_writer, "_is_browser_running", lambda _b: True)
    profile = _make_profile(db)
    with pytest.raises(RuntimeError, match="running"):
        chromium_writer.delete_cookies(
            profile,
            [_cookie(".tracker.com", "_ga")],
            dry_run=False,
            backup_root=tmp_path / "backups",
        )


def test_apply_leaves_original_untouched_on_failure(tmp_path, monkeypatch):
    """If the delete step blows up, the original cookies file must
    survive unchanged and the working file must be cleaned up.

    We force a failure by monkey-patching ``_delete_rows`` to raise
    *after* the working copy has been made.
    """
    db = tmp_path / "Default" / "Cookies"
    _seed_db(db)
    before = db.read_bytes()
    monkeypatch.setattr(chromium_writer, "_is_browser_running", lambda _b: False)

    def explode(_path, _identities):
        raise RuntimeError("simulated SQLite failure")

    monkeypatch.setattr(chromium_writer, "_delete_rows", explode)
    profile = _make_profile(db)
    with pytest.raises(RuntimeError, match="simulated"):
        chromium_writer.delete_cookies(
            profile,
            [_cookie(".tracker.com", "_ga")],
            dry_run=False,
            backup_root=tmp_path / "backups",
        )
    assert db.read_bytes() == before, "original file must be untouched on failure"
    # The working file must be cleaned up.
    assert not (db.parent / "Cookies.cj-tmp").exists()


def test_restore_from_backup_round_trip(tmp_path, monkeypatch):
    db = tmp_path / "Default" / "Cookies"
    _seed_db(db)
    monkeypatch.setattr(chromium_writer, "_is_browser_running", lambda _b: False)

    profile = _make_profile(db)
    result = chromium_writer.delete_cookies(
        profile,
        [_cookie(".tracker.com", "_ga"), _cookie(".tracker.com", "_gid")],
        dry_run=False,
        backup_root=tmp_path / "backups",
    )
    assert result.backup_path is not None

    # After delete: 1 row left.
    conn = sqlite3.connect(db)
    try:
        assert conn.execute("SELECT count(*) FROM cookies").fetchone()[0] == 1
    finally:
        conn.close()

    chromium_writer.restore_from_backup(profile, result.backup_path)

    conn = sqlite3.connect(db)
    try:
        assert conn.execute("SELECT count(*) FROM cookies").fetchone()[0] == 3
    finally:
        conn.close()


def test_writer_refuses_wrong_browser_kind(tmp_path):
    db = tmp_path / "Default" / "Cookies"
    _seed_db(db)
    spoofed = Profile(
        browser=BrowserKind.FIREFOX,
        vendor="Firefox",
        profile_name="Default",
        cookies_db_path=db,
        is_running=False,
    )
    with pytest.raises(ValueError, match="chromium"):
        chromium_writer.delete_cookies(spoofed, [], dry_run=True)
