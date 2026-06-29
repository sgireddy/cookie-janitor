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
    profile = next(
        p for p in chromium.discover_profiles() if p.profile_name == "Default"
    )
    cookies = chromium.read_cookies(profile)
    assert len(cookies) == 1
    # value_length should be the length of the marker, not the empty
    # string, so downstream display shows "<encrypted>" rather than
    # "(empty)".
    assert cookies[0].value_length == len(b"<encrypted>")


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
