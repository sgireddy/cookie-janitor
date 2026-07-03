"""Unit tests for the Chromium cookie reader.

We build a synthetic ``Cookies`` SQLite database with the same column
layout modern Chrome uses, drop it into a fake profile tree, monkey-patch
the reader's platform helpers to point at the fake home directory, and
walk the dispatcher API end-to-end.

We do NOT touch real Chrome data on the test machine — everything is
under ``tmp_path``.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from cookie_janitor.model.cookie import BrowserKind, SameSite
from cookie_janitor.readers import chromium

# Chromium epoch: 1601-01-01 UTC, microseconds.
_WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)


def _to_webkit_micros(dt: datetime) -> int:
    return int((dt - _WEBKIT_EPOCH).total_seconds() * 1_000_000)


def _make_chrome_db(path: Path, rows: list[dict]) -> None:
    """Build a single-table ``cookies`` SQLite file with modern-Chrome columns.

    Only the columns the reader cares about are populated; the rest of
    the modern schema (``creation_utc``, ``top_frame_site_key``,
    ``priority``, …) are set to sensible defaults because Chrome's
    schema has NOT NULL constraints on most of them.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        # Tests sometimes re-seed a DB the discovery helper already
        # created. Start from a clean slate so CREATE TABLE doesn't
        # collide on the second call.
        path.unlink()
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
        for r in rows:
            conn.execute(
                """
                INSERT INTO cookies (creation_utc, host_key, name, value,
                                     encrypted_value, path, expires_utc,
                                     is_secure, is_httponly, samesite)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    r.get("creation", 0),
                    r["host_key"],
                    r["name"],
                    r.get("value", ""),
                    r.get("encrypted_value", b""),
                    r.get("path", "/"),
                    r["expires_utc"],
                    int(r.get("secure", 0)),
                    int(r.get("httponly", 0)),
                    int(r.get("samesite", -1)),
                ),
            )
        conn.commit()
    finally:
        conn.close()


# ----------------------- discover_profiles --------------------------------


def _install_fake_chrome(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Lay out a fake $HOME with a Chrome installation and two profiles."""
    home = tmp_path / "home"
    chrome = home / ".config" / "google-chrome"
    (chrome / "Default").mkdir(parents=True)
    (chrome / "Profile 1").mkdir()
    (chrome / "System Profile").mkdir()  # should be ignored
    _make_chrome_db(chrome / "Default" / "Cookies", rows=[])
    _make_chrome_db(chrome / "Profile 1" / "Cookies", rows=[])
    monkeypatch.setattr(chromium, "_platform_key", lambda: "linux")
    monkeypatch.setattr(chromium, "_home", lambda: home)
    monkeypatch.setattr(chromium, "is_running", lambda _kind: False)
    return home


def test_discover_finds_default_and_numbered_profiles(tmp_path, monkeypatch):
    _install_fake_chrome(tmp_path, monkeypatch)
    profiles = chromium.discover_profiles()
    names = {p.profile_name for p in profiles}
    assert names == {"Default", "Profile 1"}
    assert all(p.browser is BrowserKind.CHROMIUM for p in profiles)
    assert all(p.vendor == "Google Chrome" for p in profiles)


def test_discover_skips_system_profile(tmp_path, monkeypatch):
    _install_fake_chrome(tmp_path, monkeypatch)
    profiles = chromium.discover_profiles()
    assert "System Profile" not in {p.profile_name for p in profiles}


def test_discover_returns_empty_when_no_browser_installed(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(chromium, "_platform_key", lambda: "linux")
    monkeypatch.setattr(chromium, "_home", lambda: home)
    monkeypatch.setattr(chromium, "is_running", lambda _kind: False)
    assert chromium.discover_profiles() == []


def test_discover_picks_up_network_cookies_subdir(tmp_path, monkeypatch):
    """Newer Chromium builds keep the file at ``<profile>/Network/Cookies``."""
    home = tmp_path / "home"
    chrome = home / ".config" / "google-chrome"
    (chrome / "Default" / "Network").mkdir(parents=True)
    _make_chrome_db(chrome / "Default" / "Network" / "Cookies", rows=[])
    monkeypatch.setattr(chromium, "_platform_key", lambda: "linux")
    monkeypatch.setattr(chromium, "_home", lambda: home)
    monkeypatch.setattr(chromium, "is_running", lambda _kind: False)
    profiles = chromium.discover_profiles()
    assert len(profiles) == 1
    assert profiles[0].cookies_db_path.name == "Cookies"
    assert profiles[0].cookies_db_path.parent.name == "Network"


# ----------------------------- read_cookies -------------------------------


def test_read_cookies_decodes_flags_and_webkit_epoch(tmp_path, monkeypatch):
    home = _install_fake_chrome(tmp_path, monkeypatch)
    db = home / ".config" / "google-chrome" / "Default" / "Cookies"
    future = datetime.now(tz=UTC) + timedelta(days=30)
    _make_chrome_db(
        db,
        [
            {
                "host_key": ".example.com",
                "name": "session",
                "value": "plain-value",
                "path": "/",
                "expires_utc": _to_webkit_micros(future),
                "secure": 1,
                "httponly": 1,
                "samesite": 2,  # strict
            },
            {
                "host_key": "host-only.example.com",
                "name": "ho",
                "value": "v",
                "expires_utc": 0,  # session cookie
                "secure": 0,
                "httponly": 0,
                "samesite": -1,  # unspecified
            },
        ],
    )
    profiles = chromium.discover_profiles()
    profile = next(p for p in profiles if p.profile_name == "Default")
    cookies = chromium.read_cookies(profile)
    by_name = {c.name: c for c in cookies}
    assert set(by_name) == {"session", "ho"}

    s = by_name["session"]
    assert s.domain == ".example.com"
    assert s.secure is True
    assert s.http_only is True
    assert s.same_site is SameSite.STRICT
    assert s.expires is not None
    # WebKit-epoch round-trip should be exact to the nearest microsecond.
    assert abs((s.expires - future).total_seconds()) < 1

    ho = by_name["ho"]
    assert ho.is_host_only is True  # no leading '.'
    assert ho.same_site is SameSite.UNSPECIFIED
    assert ho.is_session is True  # expires_utc=0


def test_encrypted_value_is_surfaced_as_marker(tmp_path, monkeypatch):
    """Chromium encrypts ``encrypted_value`` blobs; we never decrypt
    but must NOT pretend the value is empty — the classifier and the
    UI's hash column both want a stable, distinguishable marker.
    """
    home = _install_fake_chrome(tmp_path, monkeypatch)
    db = home / ".config" / "google-chrome" / "Default" / "Cookies"
    _make_chrome_db(
        db,
        [
            {
                "host_key": ".enc.example.com",
                "name": "tracker",
                "value": "",  # encrypted-value path: plaintext blank
                "encrypted_value": b"v10\x00\x01\x02\x03ciphertext",
                "expires_utc": _to_webkit_micros(datetime.now(tz=UTC) + timedelta(days=1)),
                "secure": 1,
                "httponly": 0,
                "samesite": 0,
            }
        ],
    )
    profile = next(p for p in chromium.discover_profiles() if p.profile_name == "Default")
    cookies = chromium.read_cookies(profile)
    assert len(cookies) == 1
    # value_length should be the length of the marker, not the empty
    # string, so downstream display shows "<encrypted>" rather than
    # "(empty)".
    assert cookies[0].value_length == len(b"<encrypted>")


def test_read_survives_encrypted_value_with_text_storage_class(tmp_path, monkeypatch):
    """Regression for the v0.5.1 user report::

        Cookie Janitor couldn't read cookies for Google Chrome — Default:
        Could not decode to UTF-8 column 'encrypted_value' with text
        'v10<z\\x9eZ\\x10y\\xc6h\\xb8\\xa90...'

    Some Chrome builds end up with rows whose ``encrypted_value`` has
    TEXT storage class rather than BLOB (SQLite affinity rules + the
    way Chrome binds at INSERT time, varies by version). Python's
    sqlite3 then applies its default ``text_factory = str``, which
    raises on the AES-CBC ciphertext.

    We reproduce that exact condition here by binding via
    ``CAST(? AS TEXT)`` — that forces SQLite to store the bound bytes
    as TEXT storage class, the same shape that triggered the user's
    error. The reader must NOT raise.
    """
    home = _install_fake_chrome(tmp_path, monkeypatch)
    db = home / ".config" / "google-chrome" / "Default" / "Cookies"
    # Drop the seeded DB and rebuild with a custom binding strategy.
    db.unlink()
    _make_chrome_db(db, rows=[])  # creates the schema, no rows

    # The exact byte prefix from the real bug report: 'v10' (Chrome's
    # macOS v10 Keychain marker), then non-UTF-8 ciphertext bytes.
    raw_blob = b"v10<z\x9eZ\x10y\xc6h\xb8\xa90\xa8x\xa3\x90Q"
    future = _to_webkit_micros(datetime.now(tz=UTC) + timedelta(days=1))
    conn = sqlite3.connect(db)
    try:
        # CAST(? AS TEXT) forces TEXT storage class even though the
        # column is declared BLOB — this reproduces the failure mode
        # the user actually saw in the wild.
        conn.execute(
            """
            INSERT INTO cookies (creation_utc, host_key, name, value,
                                 encrypted_value, path, expires_utc,
                                 is_secure, is_httponly, samesite)
            VALUES (0, ?, ?, '', CAST(? AS TEXT), '/', ?, 1, 0, -1)
            """,
            (".enc.example.com", "tracker", raw_blob, future),
        )
        conn.commit()
    finally:
        conn.close()

    profile = next(p for p in chromium.discover_profiles() if p.profile_name == "Default")
    # The fix: must not raise OperationalError. Before the fix this
    # line blew up with "Could not decode to UTF-8 column ...".
    cookies = chromium.read_cookies(profile)
    assert len(cookies) == 1
    c = cookies[0]
    assert c.name == "tracker"
    assert c.domain == ".enc.example.com"
    # And the encrypted_value surfaces as our standard marker, so the
    # downstream UI and hash columns stay consistent.
    assert c.value_length == len(b"<encrypted>")


def test_read_replaces_non_utf8_bytes_in_text_columns(tmp_path, monkeypatch):
    """Defensive: a single row with a mojibake host should not poison
    the whole read. Old browsers / sketchy sites occasionally write
    Latin-1 bytes into TEXT columns; ``errors='replace'`` keeps the
    reader making progress instead of erroring out the whole profile.
    """
    home = _install_fake_chrome(tmp_path, monkeypatch)
    db = home / ".config" / "google-chrome" / "Default" / "Cookies"
    db.unlink()
    _make_chrome_db(db, rows=[])

    future = _to_webkit_micros(datetime.now(tz=UTC) + timedelta(days=1))
    conn = sqlite3.connect(db)
    try:
        # Force a non-UTF-8 byte (0xff) into the ``name`` column via
        # CAST AS TEXT — same trick as the previous test.
        conn.execute(
            """
            INSERT INTO cookies (creation_utc, host_key, name, value, path,
                                 expires_utc, is_secure, is_httponly, samesite)
            VALUES (0, ?, CAST(? AS TEXT), '', '/', ?, 0, 0, -1)
            """,
            (".broken.example.com", b"bad\xffname", future),
        )
        # And a normal row to prove the read keeps going after the bad one.
        conn.execute(
            """
            INSERT INTO cookies (creation_utc, host_key, name, value, path,
                                 expires_utc, is_secure, is_httponly, samesite)
            VALUES (0, '.good.example.com', 'ok', '', '/', ?, 0, 0, -1)
            """,
            (future,),
        )
        conn.commit()
    finally:
        conn.close()

    profile = next(p for p in chromium.discover_profiles() if p.profile_name == "Default")
    cookies = chromium.read_cookies(profile)
    assert len(cookies) == 2
    names = {c.name for c in cookies}
    # The bad row contains the replacement char rather than crashing.
    assert "ok" in names
    assert any("\ufffd" in n or "bad" in n for n in names)


def test_read_cookies_refuses_wrong_browser_kind(tmp_path, monkeypatch):
    _install_fake_chrome(tmp_path, monkeypatch)
    profile = next(iter(chromium.discover_profiles()))
    # Pretend a Firefox profile was handed to us.
    from cookie_janitor.model.cookie import Profile

    spoofed = Profile(
        browser=BrowserKind.FIREFOX,
        vendor=profile.vendor,
        profile_name=profile.profile_name,
        cookies_db_path=profile.cookies_db_path,
        is_running=False,
    )
    with pytest.raises(ValueError, match="chromium"):
        chromium.read_cookies(spoofed)


# ---------------------------------------------------------------------------
# ChromiumLockedError regression tests.
#
# On Windows in particular, `shutil.copy2` of the Cookies DB fails with
# PermissionError [Errno 13] when the browser (or a background helper like
# MicrosoftEdgeUpdate.exe / WebView2 host / Copilot) has the file locked.
# The old error path bubbled that raw errno up to the GUI, giving the user
# only "Couldn't read cookies for Microsoft Edge [Errno 13] Permission
# denied." — not useful. These tests pin the improved behaviour.
# ---------------------------------------------------------------------------


def test_read_cookies_succeeds_when_is_running_true_but_file_is_readable(tmp_path, monkeypatch):
    """CRITICAL v0.6.5 regression test.

    v0.6.4 preflighted ``is_running(BrowserKind.CHROMIUM)`` and refused
    the read if it returned True. That was wrong on Windows 11 where
    ``msedge.exe`` legitimately runs as part of the Widgets Board,
    Copilot pane, Windows Search, taskbar-pinned PWAs and WebView2
    hosts embedded in third-party apps — none of which hold a lock on
    the user's actual Edge cookie DB. The v0.6.4 preflight bricked the
    read path for every such user with a false-positive
    "Microsoft Edge is still running" dialog.

    The v0.6.5 fix: remove the preflight. Trust the file copy to be
    the arbiter — if nobody has the file locked, the copy succeeds
    and we read the cookies regardless of process names.
    """
    _install_fake_chrome(tmp_path, monkeypatch)
    # Simulate the exact Windows-11 false-positive scenario: some
    # Chromium-family process IS running (widget host, PWA, etc.) but
    # the user's actual browser is closed and the Cookies file is
    # readable.
    monkeypatch.setattr(chromium, "is_running", lambda _kind: True)
    profiles = chromium.discover_profiles()
    profile = next(iter(profiles))
    _make_chrome_db(profile.cookies_db_path, [])

    # This MUST succeed. If someone re-adds a preflight is_running
    # check in the future, this test will fail loudly.
    result = chromium.read_cookies(profile)
    assert result == []


def test_read_cookies_maps_permission_error_from_copy_to_locked_error(tmp_path, monkeypatch):
    """If ``safe_copy`` itself raises ``PermissionError`` (the classic
    Windows sharing-violation surface), we must re-raise as
    ``ChromiumLockedError`` — not leak the raw errno-13 message.

    The user-visible improvement: the GUI's error dialog now shows
    'Microsoft Edge is still running' with actionable guidance, not
    '[Errno 13] Permission denied'.
    """
    from cookie_janitor.readers.chromium import ChromiumLockedError
    from cookie_janitor.safety import fs as safe_fs

    _install_fake_chrome(tmp_path, monkeypatch)
    monkeypatch.setattr(chromium, "is_running", lambda _kind: False)

    # Build a valid DB so we get past discover -> is_running -> stat
    # -> copy. The failure must be at the copy step specifically.
    profiles = chromium.discover_profiles()
    profile = next(iter(profiles))
    _make_chrome_db(profile.cookies_db_path, [])

    def _boom(src, dst):
        raise PermissionError(13, "Permission denied", str(src))

    monkeypatch.setattr(safe_fs, "safe_copy", _boom)

    with pytest.raises(ChromiumLockedError) as excinfo:
        chromium.read_cookies(profile)

    # The chained cause preserves the underlying PermissionError so a
    # log capture / bug report still has the raw errno for us.
    assert isinstance(excinfo.value.__cause__, PermissionError)
    # The user-facing message must NOT be the bare errno line.
    msg = str(excinfo.value)
    assert profile.vendor in msg
    assert "MicrosoftEdgeUpdate" in msg or "background" in msg


def test_read_cookies_maps_oserror_from_wal_copy_to_locked_error(tmp_path, monkeypatch):
    """WAL/SHM sidecars being locked is a strong 'browser is writing'
    signal. Must also map to ``ChromiumLockedError`` (not leak OSError).
    """
    from cookie_janitor.readers.chromium import ChromiumLockedError
    from cookie_janitor.safety import fs as safe_fs

    _install_fake_chrome(tmp_path, monkeypatch)
    monkeypatch.setattr(chromium, "is_running", lambda _kind: False)
    profiles = chromium.discover_profiles()
    profile = next(iter(profiles))
    _make_chrome_db(profile.cookies_db_path, [])
    # Create a WAL sidecar so we exercise the WAL copy branch.
    wal = profile.cookies_db_path.with_name(profile.cookies_db_path.name + "-wal")
    wal.write_bytes(b"fake wal bytes")

    # Fail only on the WAL copy, not on the main file copy. Track by
    # dst filename so we don't need to distinguish arg shapes.
    original_copy = safe_fs.safe_copy

    def _flaky(src, dst):
        if str(src).endswith("-wal"):
            raise OSError(13, "sharing violation on WAL", str(src))
        return original_copy(src, dst)

    monkeypatch.setattr(safe_fs, "safe_copy", _flaky)

    with pytest.raises(ChromiumLockedError, match=r"-wal|background"):
        chromium.read_cookies(profile)
