"""Tests for the reader and writer dispatchers.

The dispatchers are the single API the rest of the app talks to. Their
job is small but easy to break by accident — adding a new browser
family requires touching both files. These tests pin the contract.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from cookie_janitor import readers, writers
from cookie_janitor.model.cookie import BrowserKind, Profile


def _fake_profile(browser: BrowserKind, db: Path) -> Profile:
    return Profile(
        browser=browser,
        vendor="test",
        profile_name="Default",
        cookies_db_path=db,
        is_running=False,
    )


# --- reader dispatcher ----------------------------------------------------


def test_discover_all_routes_to_every_family(monkeypatch):
    """Without ``only=``, the dispatcher must consult every reader."""
    called: list[str] = []

    def stub(name: str):
        def fn() -> list:
            called.append(name)
            return []

        return fn

    monkeypatch.setattr(readers.firefox, "discover_profiles", stub("firefox"))
    monkeypatch.setattr(readers.chromium, "discover_profiles", stub("chromium"))
    monkeypatch.setattr(readers.safari, "discover_profiles", stub("safari"))

    readers.discover_all_profiles()
    assert called == ["firefox", "chromium", "safari"]


def test_discover_all_respects_only_filter(monkeypatch):
    """``only=CHROMIUM`` must NOT call the Firefox or Safari readers."""
    called: list[str] = []

    def stub(name: str):
        def fn() -> list:
            called.append(name)
            return []

        return fn

    monkeypatch.setattr(readers.firefox, "discover_profiles", stub("firefox"))
    monkeypatch.setattr(readers.chromium, "discover_profiles", stub("chromium"))
    monkeypatch.setattr(readers.safari, "discover_profiles", stub("safari"))

    readers.discover_all_profiles(only=BrowserKind.CHROMIUM)
    assert called == ["chromium"]


def test_read_cookies_dispatches_on_browser_kind(monkeypatch, tmp_path):
    """Each profile.browser must route to the matching reader module."""
    db = tmp_path / "x"
    db.write_bytes(b"")
    seen: list[str] = []

    def stub(name: str):
        def fn(_profile: Profile) -> list:
            seen.append(name)
            return []

        return fn

    monkeypatch.setattr(readers.firefox, "read_cookies", stub("firefox"))
    monkeypatch.setattr(readers.chromium, "read_cookies", stub("chromium"))
    monkeypatch.setattr(readers.safari, "read_cookies", stub("safari"))

    readers.read_cookies(_fake_profile(BrowserKind.FIREFOX, db))
    readers.read_cookies(_fake_profile(BrowserKind.CHROMIUM, db))
    readers.read_cookies(_fake_profile(BrowserKind.SAFARI, db))
    assert seen == ["firefox", "chromium", "safari"]


# --- writer dispatcher ----------------------------------------------------


def test_supports_delete_matrix():
    """Pins which browser families have a working delete path today.

    As of v0.6.0 every supported family is writable, including Safari.
    If a future change adds a new family or temporarily disables one,
    this test is the canonical place to record that decision so the
    GUI's delete button + the banner copy stay in sync.
    """
    assert writers.supports_delete(BrowserKind.FIREFOX) is True
    assert writers.supports_delete(BrowserKind.CHROMIUM) is True
    assert writers.supports_delete(BrowserKind.SAFARI) is True


def test_dispatcher_routes_delete_calls(monkeypatch, tmp_path):
    db = tmp_path / "y"
    db.write_bytes(b"")
    seen: list[str] = []

    class _R:
        def __init__(self, name: str) -> None:
            self.name = name

    def stub(name: str):
        def fn(_profile, _cookies, *, dry_run, backup_root):
            seen.append(name)
            return _R(name)

        return fn

    monkeypatch.setattr(writers.firefox, "delete_cookies", stub("firefox"))
    monkeypatch.setattr(writers.chromium, "delete_cookies", stub("chromium"))
    monkeypatch.setattr(writers.safari, "delete_cookies", stub("safari"))

    writers.delete_cookies(_fake_profile(BrowserKind.FIREFOX, db), [])
    writers.delete_cookies(_fake_profile(BrowserKind.CHROMIUM, db), [])
    writers.delete_cookies(_fake_profile(BrowserKind.SAFARI, db), [])
    assert seen == ["firefox", "chromium", "safari"]


def test_safari_writer_dry_run_returns_planned_zero_actually_deleted(tmp_path):
    """The Safari writer must not raise on dry-run — the GUI calls
    dry-run during normal scanning to compute "would-be" counts.
    """
    db = tmp_path / "Cookies.binarycookies"
    db.write_bytes(b"")
    profile = _fake_profile(BrowserKind.SAFARI, db)
    result = writers.delete_cookies(profile, [], dry_run=True)
    assert result.dry_run is True
    assert result.actually_deleted == 0
    assert isinstance(result.timestamp, datetime)
    assert result.timestamp.tzinfo is UTC


def test_safari_writer_apply_with_empty_input_is_noop(tmp_path):
    """``dry_run=False`` with zero cookies to delete must NOT raise.

    Deleting an empty selection is a legitimate caller move (e.g. the
    user clicked Apply with nothing checked). It must produce a
    WriteResult with zeros and an unchanged file, not a NotImplemented.
    The check is meaningful now because v0.6.0 ships a real writer
    where this path goes through the full backup + serialize +
    atomic-swap pipeline.
    """
    import struct

    db = tmp_path / "Cookies.binarycookies"
    # Minimal but VALID file: 1 page, 0 cookies. Page = magic(4) +
    # num_cookies(4) + footer(4). File = "cook" + page_count(4) +
    # page_sizes(4) + page(12) + 8-byte trailer.
    page = b"\x00\x00\x01\x00" + struct.pack("<I", 0) + b"\x00\x00\x00\x00"
    file_bytes = (
        b"cook"
        + struct.pack(">I", 1)
        + struct.pack(">I", len(page))
        + page
        + b"\x00" * 8
    )
    db.write_bytes(file_bytes)
    db.chmod(0o600)

    profile = _fake_profile(BrowserKind.SAFARI, db)
    backup_root = tmp_path / "backups"
    result = writers.delete_cookies(
        profile, [], dry_run=False, backup_root=backup_root
    )
    assert result.dry_run is False
    assert result.actually_deleted == 0
    assert result.requested_deletes == 0
    # The on-disk file must be byte-identical to what we wrote — empty
    # deletion through the real writer must be a no-op at the byte
    # level. This pins the central safety property of the new
    # serializer.
    assert db.read_bytes() == file_bytes
