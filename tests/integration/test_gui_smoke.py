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

from cookie_janitor.gui.model import CookiesModel  # noqa: E402
from cookie_janitor.gui.window import MainWindow  # noqa: E402
from cookie_janitor.model.cookie import BrowserKind, Verdict  # noqa: E402
from cookie_janitor.policy.decide import UserPolicy, decide  # noqa: E402
from cookie_janitor.readers import firefox as firefox_reader  # noqa: E402

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
    monkeypatch.setattr(firefox_reader, "discover_profiles", lambda: [])
    window = MainWindow()
    qtbot.addWidget(window)
    # No crash, friendly empty-state message rendered, delete disabled.
    assert not window._delete_btn.isEnabled()  # noqa: SLF001
    assert "couldn't find a firefox profile" in window._status.text().lower()  # noqa: SLF001


def test_main_window_renders_real_decisions(qtbot, tmp_path: Path, monkeypatch):
    fake_home = _make_synthetic_profile(tmp_path)
    monkeypatch.setattr(Path, "home", lambda: fake_home)
    monkeypatch.setattr(firefox_reader, "_platform_key", lambda: "linux")
    monkeypatch.setattr(firefox_reader, "is_running", lambda _kind: False)

    window = MainWindow()
    qtbot.addWidget(window)
    assert window._proxy.rowCount() >= 1  # noqa: SLF001
    assert window._delete_btn.isEnabled()  # noqa: SLF001
