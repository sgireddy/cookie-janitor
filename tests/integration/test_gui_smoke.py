"""Headless smoke tests for the GUI.

We don't need to render pixels — we need to know the model + window
wire up correctly and that the table population path doesn't throw.
Run under `QT_QPA_PLATFORM=offscreen` which pytest-qt sets automatically
when no display is available.
"""

from __future__ import annotations

import os
import sqlite3
import time
from pathlib import Path

import pytest

# We must import QApplication etc. before any model classes that touch
# the Qt type system. pytest-qt's `qtbot` fixture handles the
# QApplication lifecycle for us.
pytest.importorskip("PySide6")

from cookie_janitor.gui.model import CookiesModel
from cookie_janitor.gui.window import MainWindow
from cookie_janitor.policy.decide import UserPolicy, decide
from cookie_janitor.readers import firefox as firefox_reader

# Force the offscreen platform so we don't need a display server.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


def _make_synthetic_profile(tmp_path: Path):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    ff_root = fake_home / ".mozilla" / "firefox"
    ff_root.mkdir(parents=True)
    pdir = ff_root / "abc.default-release"
    pdir.mkdir()
    (ff_root / "profiles.ini").write_text(
        "[Profile0]\nName=default-release\nIsRelative=1\nPath=abc.default-release\nDefault=1\n"
    )
    db = pdir / "cookies.sqlite"
    conn = sqlite3.connect(db)
    conn.executescript(
        "CREATE TABLE moz_cookies(id INTEGER PRIMARY KEY, name TEXT, value TEXT,"
        " host TEXT, path TEXT, expiry INTEGER, isSecure INTEGER, isHttpOnly INTEGER,"
        " sameSite INTEGER);"
    )
    now = int(time.time())
    conn.executemany(
        "INSERT INTO moz_cookies(name,value,host,path,expiry,isSecure,isHttpOnly,sameSite)"
        " VALUES (?,?,?,?,?,?,?,?)",
        [
            ("_ga", "x", ".cnn.com", "/", now + 365 * 86400, 1, 0, 1),
            ("SID", "x", ".google.com", "/", now + 730 * 86400, 1, 1, 1),
        ],
    )
    conn.commit()
    conn.close()
    return fake_home


def test_model_renders_decisions(qtbot, tmp_path: Path, monkeypatch):
    fake_home = _make_synthetic_profile(tmp_path)
    monkeypatch.setattr(Path, "home", lambda: fake_home)
    monkeypatch.setattr(firefox_reader, "_platform_key", lambda: "linux")
    monkeypatch.setattr(firefox_reader, "is_running", lambda _kind: False)

    profile = firefox_reader.discover_profiles()[0]
    cookies = firefox_reader.read_cookies(profile)
    import importlib.resources

    from cookie_janitor.classify.cookie_db import load_database

    files = importlib.resources.files("cookie_janitor.data")
    with importlib.resources.as_file(files / "cookie_db_seed.csv") as p:
        db = load_database(p)
    decisions = [decide(c, policy=UserPolicy(), cookie_db=db) for c in cookies]

    model = CookiesModel(decisions)
    assert model.rowCount() == len(decisions)
    # Default selection picks the trackers.
    selected_names = {d.cookie.name for d in model.selected_decisions()}
    assert "_ga" in selected_names
    assert "SID" not in selected_names


def test_main_window_handles_no_profiles(qtbot, monkeypatch):
    # Now that the GUI scans three browser families, the empty-state has
    # to come up only when ALL of them return nothing.
    from cookie_janitor.readers import chromium as chromium_reader
    from cookie_janitor.readers import safari as safari_reader

    monkeypatch.setattr(firefox_reader, "discover_profiles", lambda: [])
    monkeypatch.setattr(chromium_reader, "discover_profiles", lambda: [])
    monkeypatch.setattr(safari_reader, "discover_profiles", lambda: [])
    window = MainWindow()
    qtbot.addWidget(window)
    # No crash, friendly empty-state message rendered, delete disabled.
    assert not window._delete_btn.isEnabled()
    msg = window._status.text().lower()
    # The empty-state copy must NOT name a single browser exclusively —
    # the pre-0.5 wording ("install Firefox") was actively misleading
    # for users who already had Edge/Chrome/Safari installed.
    assert "couldn't find" in msg
    assert "firefox" in msg and "chrome" in msg and "edge" in msg


def test_main_window_lists_chromium_and_safari_profiles_in_dropdown(
    qtbot, tmp_path: Path, monkeypatch
):
    """Regression for the question 'does the UI support Chrome and Safari?':
    discover Firefox + Chromium + Safari fixtures and verify all three
    end up as separate items in the profile dropdown.

    We stub each reader's ``discover_profiles`` so the test is hermetic
    and runs identically on any OS — what we care about here is the
    *wiring*, not the per-browser discovery logic (that's tested in
    test_chromium_reader.py and test_safari_reader.py).
    """
    from cookie_janitor.model.cookie import BrowserKind, Profile
    from cookie_janitor.readers import chromium as chromium_reader
    from cookie_janitor.readers import safari as safari_reader

    # Minimal Firefox profile with one classifiable cookie so the
    # MainWindow can drive _on_profile_changed without errors.
    fake_home = _make_synthetic_profile(tmp_path)
    monkeypatch.setattr(Path, "home", lambda: fake_home)
    monkeypatch.setattr(firefox_reader, "_platform_key", lambda: "linux")
    monkeypatch.setattr(firefox_reader, "is_running", lambda _kind: False)

    # Fake Chrome / Edge / Safari profiles — they only need to exist as
    # Profile objects in the list; we stub read_cookies for each so the
    # window doesn't try to open real SQLite/binarycookies files.
    chrome_db = tmp_path / "chrome-Cookies"
    chrome_db.write_bytes(b"not really sqlite, but never read")
    edge_db = tmp_path / "edge-Cookies"
    edge_db.write_bytes(b"")
    safari_db = tmp_path / "Cookies.binarycookies"
    safari_db.write_bytes(b"")

    fake_profiles = [
        Profile(
            browser=BrowserKind.CHROMIUM,
            vendor="Google Chrome",
            profile_name="Default",
            cookies_db_path=chrome_db,
            is_running=False,
        ),
        Profile(
            browser=BrowserKind.CHROMIUM,
            vendor="Microsoft Edge",
            profile_name="Default",
            cookies_db_path=edge_db,
            is_running=False,
        ),
        Profile(
            browser=BrowserKind.SAFARI,
            vendor="Safari",
            profile_name="Default",
            cookies_db_path=safari_db,
            is_running=False,
        ),
    ]
    monkeypatch.setattr(chromium_reader, "discover_profiles", lambda: fake_profiles[:2])
    monkeypatch.setattr(safari_reader, "discover_profiles", lambda: fake_profiles[2:])
    # We don't need real reads — empty cookie lists keep the table happy.
    monkeypatch.setattr(chromium_reader, "read_cookies", lambda _p: [])
    monkeypatch.setattr(safari_reader, "read_cookies", lambda _p: [])

    window = MainWindow()
    qtbot.addWidget(window)

    labels = [
        window._profile_box.itemText(i)
        for i in range(window._profile_box.count())
    ]
    # Every supported family must appear in the dropdown, identifiable
    # by its vendor string. We don't assert the exact order — that's
    # the dispatcher's contract (Firefox first, then Chromium, then
    # Safari) and is pinned in test_dispatchers.py.
    joined = " | ".join(labels)
    assert "Firefox" in joined
    assert "Google Chrome" in joined
    assert "Microsoft Edge" in joined
    assert "Safari" in joined


def test_format_read_error_renders_actionable_tcc_message(tmp_path):
    """A Safari TCC denial must produce a dialog message that names
    the actual remedy (Full Disk Access, System Settings, restart),
    not just dump the raw OSError. Pulled into its own helper exactly
    so we can assert against the strings without spinning a dialog.
    """
    from cookie_janitor.gui.window import _format_read_error
    from cookie_janitor.model.cookie import BrowserKind, Profile
    from cookie_janitor.readers.safari import (
        SafariPermissionDeniedError,
    )

    cookies_path = tmp_path / "Cookies.binarycookies"
    cookies_path.write_bytes(b"")
    profile = Profile(
        browser=BrowserKind.SAFARI,
        vendor="Safari",
        profile_name="Default",
        cookies_db_path=cookies_path,
        is_running=False,
    )
    exc = SafariPermissionDeniedError(
        cookies_path, original=PermissionError(1, "Operation not permitted")
    )
    title, body, detail = _format_read_error(profile, exc)

    assert "Full Disk Access" in title
    # The body should explain WHY this is happening (system-level, not
    # our bug) — that's the bit that separates a helpful dialog from a
    # blame-shifting one.
    assert "macOS" in body
    assert "not a Cookie Janitor bug" in body
    # The detail section carries the numbered remedy. All four steps
    # must be present so the user can follow them without checking
    # an external doc.
    assert "Privacy & Security" in detail
    assert "Full Disk Access" in detail
    assert "Quit" in detail or "relaunch" in detail.lower()
    assert "Firefox" in detail  # explains that other browsers aren't affected


def test_format_read_error_renders_actionable_locked_message(tmp_path):
    """A ChromiumLockedError must produce a dialog that names the
    actual remedy (fully quit the browser, check Task Manager) — not
    just leak '[Errno 13] Permission denied'. This is the direct
    user-visible fix for the 'couldn't read cookies for Microsoft
    Edge [Errno 13] Permission denied' bug seen on Windows in v0.6.3.
    """
    from cookie_janitor.gui.window import _format_read_error
    from cookie_janitor.model.cookie import BrowserKind, Profile
    from cookie_janitor.readers.chromium import ChromiumLockedError

    cookies_path = tmp_path / "Cookies"
    cookies_path.write_bytes(b"")
    profile = Profile(
        browser=BrowserKind.CHROMIUM,
        vendor="Microsoft Edge",
        profile_name="Default",
        cookies_db_path=cookies_path,
        is_running=True,
    )
    exc = ChromiumLockedError(
        "Microsoft Edge appears to be running. Please quit it."
    )
    title, body, detail = _format_read_error(profile, exc)

    # The title must name the actual vendor, not the family.
    # 'Microsoft Edge is still running' > 'Chromium is still running'.
    assert "Microsoft Edge" in title
    assert "running" in title
    # The body must explain WHY reading failed (the browser is holding
    # the file open) in language a non-technical user can act on. The
    # bare Errno 13 is exactly what this replaces.
    assert "Edge" in body
    assert "Errno 13" not in body
    assert "Permission denied" not in body
    # The detail section must contain the actionable Windows-specific
    # remediation steps, including the Task Manager hint that the
    # generic 'close the browser' guidance doesn't cover.
    assert "Task Manager" in detail
    assert "MicrosoftEdgeUpdate.exe" in detail or "msedge.exe" in detail
    # Non-negotiable safety copy: we do NOT try to bypass the lock.
    # If someone ever adds a --force-read shortcut, that text needs
    # rewording, and this test will scream.
    assert "does NOT try to bypass" in detail or "safe path" in detail


def test_format_read_error_falls_back_to_generic_message_for_other_errors(tmp_path):
    """Non-TCC errors must NOT get the Full Disk Access copy —
    otherwise a Chrome SQLite corruption would tell the user to grant
    Safari permissions, which would be actively misleading.
    """
    from cookie_janitor.gui.window import _format_read_error
    from cookie_janitor.model.cookie import BrowserKind, Profile

    cookies_path = tmp_path / "Cookies"
    cookies_path.write_bytes(b"")
    profile = Profile(
        browser=BrowserKind.CHROMIUM,
        vendor="Google Chrome",
        profile_name="Default",
        cookies_db_path=cookies_path,
        is_running=False,
    )
    title, body, detail = _format_read_error(profile, RuntimeError("database is locked"))
    assert title == "Couldn't read cookies"
    assert "Google Chrome" in body
    assert "database is locked" in body
    assert detail == ""  # no Safari-only guidance leaking in


def test_main_window_enables_delete_for_safari_profile_with_cookies(
    qtbot, tmp_path: Path, monkeypatch
):
    """Selecting a Safari profile with cookies must now ENABLE the
    delete button — v0.6.0 ships a real binarycookies writer. Pins
    the GUI half of the supports_delete contract.

    Previously (v0.5.x) this test asserted the button was disabled
    and the read-only banner was shown. Both expectations flipped
    when the Safari writer landed; this is the canonical recording
    of that change.
    """
    from cookie_janitor.model.cookie import (
        BrowserKind,
        Profile,
        SameSite,
        make_cookie,
    )
    from cookie_janitor.readers import chromium as chromium_reader
    from cookie_janitor.readers import safari as safari_reader

    safari_db = tmp_path / "Cookies.binarycookies"
    safari_db.write_bytes(b"")
    safari_profile = Profile(
        browser=BrowserKind.SAFARI,
        vendor="Safari",
        profile_name="Default",
        cookies_db_path=safari_db,
        is_running=False,
    )
    fake_cookie = make_cookie(
        name="trk",
        domain="tracker.example",
        path="/",
        expires=None,
        secure=False,
        http_only=False,
        same_site=SameSite.UNSPECIFIED,
        is_host_only=False,
        value_bytes=b"x",
    )
    monkeypatch.setattr(firefox_reader, "discover_profiles", lambda: [])
    monkeypatch.setattr(chromium_reader, "discover_profiles", lambda: [])
    monkeypatch.setattr(safari_reader, "discover_profiles", lambda: [safari_profile])
    monkeypatch.setattr(safari_reader, "read_cookies", lambda _p: [fake_cookie])

    window = MainWindow()
    qtbot.addWidget(window)
    # Delete is enabled iff (supports_delete AND not running AND has
    # decisions). The fake cookie above guarantees the third.
    assert window._delete_btn.isEnabled()
    # The legacy "read-only" banner must NOT fire for Safari any more
    # — that copy was wrong as of v0.6.0. (The banner can still
    # appear if Safari is *running*, but our fixture sets is_running
    # False.)
    assert "read-only" not in window._running_banner.text().lower()


def test_main_window_renders_real_decisions(qtbot, tmp_path: Path, monkeypatch):
    fake_home = _make_synthetic_profile(tmp_path)
    monkeypatch.setattr(Path, "home", lambda: fake_home)
    monkeypatch.setattr(firefox_reader, "_platform_key", lambda: "linux")
    monkeypatch.setattr(firefox_reader, "is_running", lambda _kind: False)

    window = MainWindow()
    qtbot.addWidget(window)
    assert window._proxy.rowCount() >= 1
    assert window._delete_btn.isEnabled()
