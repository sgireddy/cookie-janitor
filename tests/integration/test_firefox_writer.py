"""End-to-end writer tests against a synthetic Firefox cookies.sqlite.

We build the same Linux-style fixture as the reader tests, run the
classifier+decision pipeline, then have the writer delete every
``delete`` verdict. We assert:

* the requested cookies are gone from the live file,
* the kept cookies are still present and identical,
* a verified backup exists,
* the original was atomically swapped (new inode),
* restoring from the backup returns the file to its original state.
"""

from __future__ import annotations

import shutil
import sqlite3
import time
from pathlib import Path

import pytest

from cookie_janitor.classify.cookie_db import load_database
from cookie_janitor.model.cookie import Profile, Verdict
from cookie_janitor.policy.decide import UserPolicy, decide
from cookie_janitor.readers import firefox as firefox_reader
from cookie_janitor.safety import fs as safe_fs
from cookie_janitor.writers.firefox import (
    _hash_file,
    delete_cookies,
    restore_from_backup,
)

# Same fixture shape as the reader integration tests, condensed.

_SCHEMA = """
CREATE TABLE moz_cookies (
  id INTEGER PRIMARY KEY,
  name TEXT, value TEXT, host TEXT, path TEXT,
  expiry INTEGER, isSecure INTEGER, isHttpOnly INTEGER, sameSite INTEGER
);
"""

_ROWS = [
    ("_ga", "x", ".cnn.com", "/", 1, 0, 1),  # tracker
    ("_fbp", "x", ".cnn.com", "/", 1, 0, 1),  # tracker
    ("SID", "x", ".google.com", "/", 1, 1, 1),  # session/functional
    ("user_session", "x", ".github.com", "/", 1, 1, 2),  # session/functional
    ("csrf", "x", "selfhost.test", "/", 1, 1, 2),  # session heuristic
]


def _create_profile(tmp_path: Path) -> Profile:
    home = tmp_path / "home"
    home.mkdir()
    ff_root = home / ".mozilla" / "firefox"
    ff_root.mkdir(parents=True)
    pdir = ff_root / "abc.default-release"
    pdir.mkdir()

    (ff_root / "profiles.ini").write_text(
        "[Profile0]\nName=default-release\nIsRelative=1\nPath=abc.default-release\nDefault=1\n"
    )
    db_path = pdir / "cookies.sqlite"
    conn = sqlite3.connect(db_path)
    conn.executescript(_SCHEMA)
    now = int(time.time())
    conn.executemany(
        "INSERT INTO moz_cookies(name,value,host,path,expiry,isSecure,isHttpOnly,sameSite) "
        "VALUES (?,?,?,?,?,?,?,?)",
        [(n, v, h, p, now + 365 * 86400, s, ho, ss) for (n, v, h, p, s, ho, ss) in _ROWS],
    )
    conn.commit()
    conn.close()

    # Build the Profile directly so we don't depend on discovery here.
    from cookie_janitor.model.cookie import BrowserKind

    return Profile(
        browser=BrowserKind.FIREFOX,
        vendor="Firefox",
        profile_name="default-release",
        cookies_db_path=db_path,
        is_running=False,
    )


def _cookie_names_in(db: Path) -> set[str]:
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        return {row[0] for row in conn.execute("SELECT name FROM moz_cookies")}
    finally:
        conn.close()


def _make_decisions(profile: Profile):
    cookies = firefox_reader.read_cookies(profile)
    import importlib.resources

    files = importlib.resources.files("cookie_janitor.data")
    with importlib.resources.as_file(files / "cookie_db_seed.csv") as p:
        db = load_database(p)
    policy = UserPolicy()
    return [decide(c, policy=policy, cookie_db=db) for c in cookies]


def test_dry_run_changes_nothing(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("cookie_janitor.writers.firefox._is_browser_running", lambda _kind: False)
    profile = _create_profile(tmp_path)
    before_hash = _hash_file(profile.cookies_db_path)
    decisions = _make_decisions(profile)
    to_delete = [d.cookie for d in decisions if d.verdict is Verdict.DELETE]
    assert to_delete, "fixture expected at least one tracker"

    result = delete_cookies(profile, to_delete, dry_run=True)

    assert result.dry_run is True
    assert result.backup_path is None
    assert result.requested_deletes == len(to_delete)
    assert _hash_file(profile.cookies_db_path) == before_hash


def test_apply_deletes_trackers_and_backs_up(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("cookie_janitor.writers.firefox._is_browser_running", lambda _kind: False)
    profile = _create_profile(tmp_path)
    before_inode = profile.cookies_db_path.stat().st_ino
    before_names = _cookie_names_in(profile.cookies_db_path)

    decisions = _make_decisions(profile)
    to_delete = [d.cookie for d in decisions if d.verdict is Verdict.DELETE]
    to_keep_names = {d.cookie.name for d in decisions if d.verdict is Verdict.KEEP}
    delete_names = {c.name for c in to_delete}
    assert delete_names, "fixture expected at least one tracker"

    backup_root = tmp_path / "backups"
    result = delete_cookies(profile, to_delete, dry_run=False, backup_root=backup_root)

    assert result.dry_run is False
    assert result.requested_deletes == len(to_delete)
    assert result.actually_deleted == len(to_delete)
    assert result.backup_path is not None
    assert result.backup_path.is_file()

    # Live file: trackers gone, kept cookies still present.
    after_names = _cookie_names_in(profile.cookies_db_path)
    assert after_names & delete_names == set()
    assert to_keep_names.issubset(after_names)

    # Atomic swap → new inode.
    assert profile.cookies_db_path.stat().st_ino != before_inode

    # Backup matches the original pre-delete state.
    backup_names = _cookie_names_in(result.backup_path)
    assert backup_names == before_names


def test_apply_refuses_when_browser_running(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("cookie_janitor.writers.firefox._is_browser_running", lambda _kind: True)
    profile = _create_profile(tmp_path)
    before_hash = _hash_file(profile.cookies_db_path)

    with pytest.raises(RuntimeError, match="currently running"):
        delete_cookies(profile, [], dry_run=False, backup_root=tmp_path / "backups")

    assert _hash_file(profile.cookies_db_path) == before_hash


def test_restore_round_trip(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("cookie_janitor.writers.firefox._is_browser_running", lambda _kind: False)
    profile = _create_profile(tmp_path)
    before_names = _cookie_names_in(profile.cookies_db_path)

    decisions = _make_decisions(profile)
    to_delete = [d.cookie for d in decisions if d.verdict is Verdict.DELETE]

    result = delete_cookies(profile, to_delete, dry_run=False, backup_root=tmp_path / "backups")
    assert result.backup_path is not None

    restore_from_backup(profile, result.backup_path)
    assert _cookie_names_in(profile.cookies_db_path) == before_names


def test_writer_refuses_symlinked_cookies_db(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("cookie_janitor.writers.firefox._is_browser_running", lambda _kind: False)
    profile = _create_profile(tmp_path)

    # Replace cookies.sqlite with a symlink — same attack the reader rejects.
    db = profile.cookies_db_path
    real = tmp_path / "elsewhere.sqlite"
    shutil.move(db, real)
    db.symlink_to(real)

    with pytest.raises(safe_fs.UnsafePathError):
        delete_cookies(profile, [], dry_run=False, backup_root=tmp_path / "backups")
