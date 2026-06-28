"""End-to-end: synthesize a Firefox cookies.sqlite, run discovery, read,
classify, and assert the right decisions come out.

We do NOT use a real browser profile in CI. Everything is built from
sqlite primitives so the test is deterministic and isolated.
"""

from __future__ import annotations

import configparser
import importlib.resources
import sqlite3
import time
from pathlib import Path

import pytest

from cookie_janitor.classify.cookie_db import load_database
from cookie_janitor.model.cookie import BrowserKind, Profile, Verdict
from cookie_janitor.policy.decide import UserPolicy, decide
from cookie_janitor.readers import firefox as firefox_reader


def _create_firefox_profile(root: Path) -> Path:
    """Build a fake Firefox install root with one profile + cookies.sqlite."""
    profile_dir = root / "abc123.default-release"
    profile_dir.mkdir(parents=True)

    # profiles.ini
    cp = configparser.ConfigParser()
    cp["Profile0"] = {
        "Name": "default-release",
        "IsRelative": "1",
        "Path": profile_dir.name,
        "Default": "1",
    }
    with (root / "profiles.ini").open("w", encoding="utf-8") as fh:
        cp.write(fh)

    # cookies.sqlite — minimal schema matching real Firefox.
    db_path = profile_dir / "cookies.sqlite"
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE moz_cookies (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            value TEXT,
            host TEXT NOT NULL,
            path TEXT,
            expiry INTEGER,
            isSecure INTEGER,
            isHttpOnly INTEGER,
            sameSite INTEGER
        );
        """
    )
    rows = [
        # known analytics tracker — should be flagged for delete
        ("_ga", "GA1.2.something", ".example.test", "/", int(time.time()) + 365 * 86400, 1, 0, 1),
        # known functional session cookie for Google login — keep
        ("SID", "logged-in-token", ".google.com", "/", int(time.time()) + 730 * 86400, 1, 1, 1),
        # mystery cookie — default keep
        ("session_uuid", "abc-123", "myapp.test", "/", int(time.time()) + 86400, 1, 1, 1),
        # session cookie (no expiry, http-only, host-only) — heuristic keep
        ("csrf", "tok", "selfhost.test", "/", 0, 1, 1, 2),
    ]
    conn.executemany(
        """
        INSERT INTO moz_cookies
          (name, value, host, path, expiry, isSecure, isHttpOnly, sameSite)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    conn.commit()
    conn.close()
    return profile_dir


def _stage_linux_layout(tmp_path: Path, monkeypatch) -> Path:
    """Stage a Linux-style Firefox profile under a fake $HOME.

    Monkeypatches Path.home, the running-process probe, and the
    reader's platform key so the same fixture exercises the discovery
    code path regardless of the test host's actual OS.
    """
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    ff_root = fake_home / ".mozilla" / "firefox"
    ff_root.mkdir(parents=True)
    _create_firefox_profile(ff_root)

    monkeypatch.setattr(Path, "home", lambda: fake_home)
    monkeypatch.setattr(firefox_reader, "is_running", lambda _kind: False)
    # Force the Linux discovery path regardless of where the test runs.
    monkeypatch.setattr(firefox_reader, "_platform_key", lambda: "linux")
    return fake_home


def test_full_pipeline_against_synthetic_firefox(tmp_path: Path, monkeypatch):
    _stage_linux_layout(tmp_path, monkeypatch)

    profiles = firefox_reader.discover_profiles()
    assert len(profiles) == 1
    profile: Profile = profiles[0]
    assert profile.browser is BrowserKind.FIREFOX
    assert profile.profile_name == "default-release"
    assert profile.is_running is False

    cookies = firefox_reader.read_cookies(profile)
    assert len(cookies) == 4

    files = importlib.resources.files("cookie_janitor.data")
    with importlib.resources.as_file(files / "cookie_db_seed.csv") as p:
        db = load_database(p)

    decisions = [decide(c, policy=UserPolicy(), cookie_db=db) for c in cookies]
    by_name = {d.cookie.name: d for d in decisions}

    # Trackers go to DELETE.
    assert by_name["_ga"].verdict is Verdict.DELETE
    assert "Open Cookie Database" in by_name["_ga"].rationale

    # Functional Google session cookies stay.
    assert by_name["SID"].verdict is Verdict.KEEP

    # Default-keep for unclassified.
    assert by_name["session_uuid"].verdict is Verdict.KEEP

    # Heuristic-session keep.
    assert by_name["csrf"].verdict is Verdict.KEEP
    assert by_name["csrf"].source == "heuristic-session"


def test_user_keep_list_overrides_tracker_verdict(tmp_path: Path, monkeypatch):
    _stage_linux_layout(tmp_path, monkeypatch)

    profile = firefox_reader.discover_profiles()[0]
    cookies = firefox_reader.read_cookies(profile)
    files = importlib.resources.files("cookie_janitor.data")
    with importlib.resources.as_file(files / "cookie_db_seed.csv") as p:
        db = load_database(p)

    policy = UserPolicy(keep_domains=frozenset({"example.test"}))
    decisions = [decide(c, policy=policy, cookie_db=db) for c in cookies]
    ga = next(d for d in decisions if d.cookie.name == "_ga")
    assert ga.verdict is Verdict.KEEP
    assert ga.source.startswith("user-keep-list")


def test_reader_does_not_touch_original_file(tmp_path: Path, monkeypatch):
    _stage_linux_layout(tmp_path, monkeypatch)

    profile = firefox_reader.discover_profiles()[0]
    before = profile.cookies_db_path.stat()

    firefox_reader.read_cookies(profile)

    after = profile.cookies_db_path.stat()
    assert before.st_mtime_ns == after.st_mtime_ns
    assert before.st_size == after.st_size
    assert before.st_ino == after.st_ino


@pytest.mark.skipif(__import__("sys").platform == "win32", reason="POSIX symlinks only")
def test_reader_refuses_symlinked_cookies_db(tmp_path: Path, monkeypatch):
    fake_home = _stage_linux_layout(tmp_path, monkeypatch)
    profile_dir = next((fake_home / ".mozilla" / "firefox").glob("*.default-release"))

    # Replace cookies.sqlite with a symlink to /etc/hostname — classic
    # BleachBit-style attack. We must refuse.
    db_file = profile_dir / "cookies.sqlite"
    db_file.unlink()
    db_file.symlink_to("/etc/hostname")

    # Discovery skips it with a warning; the list should be empty.
    profiles = firefox_reader.discover_profiles()
    assert profiles == []
