"""Unit tests for the Safari ``.binarycookies`` reader.

We build a synthetic binarycookies file in memory (the format is well
documented; see the docstring in ``readers.safari``) and feed it to the
parser. This avoids needing a real Safari installation and runs on
every platform — the parser itself is pure Python.

Profile discovery is gated on ``sys.platform == 'darwin'``, so for the
discovery tests we monkey-patch ``sys.platform`` and the home dir.
"""

from __future__ import annotations

import struct
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from cookie_janitor.model.cookie import BrowserKind, Profile, SameSite
from cookie_janitor.readers import safari

_MAC_EPOCH = datetime(2001, 1, 1, tzinfo=UTC)


# --- binarycookies builder ------------------------------------------------


def _build_cookie_record(
    *,
    domain: str,
    name: str,
    path: str,
    value: str,
    expiry: datetime | None,
    secure: bool = False,
    http_only: bool = False,
) -> bytes:
    """Construct a single cookie record matching the binarycookies format.

    Layout (all little-endian within the record):
        +0  : uint32 cookie_size
        +4  : 4 bytes (unused, 0)
        +8  : uint32 flags
        +12 : 4 bytes (unused, 0)
        +16 : uint32 domain_offset
        +20 : uint32 name_offset
        +24 : uint32 path_offset
        +28 : uint32 value_offset
        +32 : 8 bytes end_of_cookie (0xFF * 8)
        +40 : float64 expiry_seconds (since 2001-01-01 UTC)
        +48 : float64 creation_seconds
        +56 : strings, each NUL-terminated
    """
    flags = (1 if secure else 0) | (4 if http_only else 0)
    expiry_secs = 0.0 if expiry is None else (expiry - _MAC_EPOCH).total_seconds()
    strings_off = 56
    domain_b = domain.encode("utf-8") + b"\x00"
    name_b = name.encode("utf-8") + b"\x00"
    path_b = path.encode("utf-8") + b"\x00"
    value_b = value.encode("utf-8") + b"\x00"
    domain_off = strings_off
    name_off = domain_off + len(domain_b)
    path_off = name_off + len(name_b)
    value_off = path_off + len(path_b)
    strings = domain_b + name_b + path_b + value_b
    cookie_size = strings_off + len(strings)

    header = (
        struct.pack("<I", cookie_size)
        + b"\x00\x00\x00\x00"
        + struct.pack("<I", flags)
        + b"\x00\x00\x00\x00"
        + struct.pack("<IIII", domain_off, name_off, path_off, value_off)
        + b"\xff" * 8
        + struct.pack("<d", expiry_secs)
        + struct.pack("<d", 0.0)
    )
    return header + strings


def _build_page(records: list[bytes]) -> bytes:
    """Build one page of the binarycookies file."""
    num = len(records)
    # 4 (magic) + 4 (count) + 4*N (offsets) + 4 (footer) = 12 + 4N header bytes
    header_size = 12 + 4 * num
    offsets = []
    cursor = header_size
    for r in records:
        offsets.append(cursor)
        cursor += len(r)
    return (
        b"\x00\x00\x01\x00"
        + struct.pack("<I", num)
        + struct.pack(f"<{num}I", *offsets)
        + b"\x00\x00\x00\x00"
        + b"".join(records)
    )


def _build_binarycookies(pages: list[bytes]) -> bytes:
    page_sizes = [len(p) for p in pages]
    return (
        b"cook"
        + struct.pack(">I", len(pages))
        + struct.pack(f">{len(pages)}I", *page_sizes)
        + b"".join(pages)
        + b"\x00" * 8  # trailing 8 bytes, not validated
    )


# --- tests ---------------------------------------------------------------


def test_parses_two_cookies_with_correct_flags_and_expiry(tmp_path):
    future = datetime.now(tz=UTC) + timedelta(days=10)
    rec1 = _build_cookie_record(
        domain=".example.com",
        name="session",
        path="/",
        value="abc",
        expiry=future,
        secure=True,
        http_only=True,
    )
    rec2 = _build_cookie_record(
        domain="host-only.example.com",
        name="ho",
        path="/p",
        value="",
        expiry=None,
        secure=False,
        http_only=False,
    )
    data = _build_binarycookies([_build_page([rec1, rec2])])
    f = tmp_path / "Cookies.binarycookies"
    f.write_bytes(data)

    profile = Profile(
        browser=BrowserKind.SAFARI,
        vendor="Safari",
        profile_name="Default",
        cookies_db_path=f,
        is_running=False,
    )
    cookies = safari.read_cookies(profile)
    by_name = {c.name: c for c in cookies}
    assert set(by_name) == {"session", "ho"}

    s = by_name["session"]
    assert s.domain == ".example.com"
    assert s.path == "/"
    assert s.secure is True
    assert s.http_only is True
    assert s.is_host_only is False
    assert s.same_site is SameSite.UNSPECIFIED
    assert s.expires is not None
    assert abs((s.expires - future).total_seconds()) < 1

    ho = by_name["ho"]
    assert ho.is_host_only is True
    assert ho.path == "/p"
    assert ho.is_session is True  # no expiry


def test_parses_multi_page_file(tmp_path):
    a = _build_cookie_record(
        domain=".a.com",
        name="a",
        path="/",
        value="",
        expiry=datetime.now(tz=UTC) + timedelta(days=1),
    )
    b = _build_cookie_record(
        domain=".b.com",
        name="b",
        path="/",
        value="",
        expiry=datetime.now(tz=UTC) + timedelta(days=1),
    )
    data = _build_binarycookies([_build_page([a]), _build_page([b])])
    f = tmp_path / "Cookies.binarycookies"
    f.write_bytes(data)
    profile = Profile(
        browser=BrowserKind.SAFARI,
        vendor="Safari",
        profile_name="Default",
        cookies_db_path=f,
        is_running=False,
    )
    domains = sorted(c.domain for c in safari.read_cookies(profile))
    assert domains == [".a.com", ".b.com"]


def test_rejects_file_without_cook_magic(tmp_path):
    f = tmp_path / "garbage"
    f.write_bytes(b"NOPE" + b"\x00" * 12)
    profile = Profile(
        browser=BrowserKind.SAFARI,
        vendor="Safari",
        profile_name="Default",
        cookies_db_path=f,
        is_running=False,
    )
    with pytest.raises(safari.BinaryCookiesError, match="cook"):
        safari.read_cookies(profile)


def test_skips_malformed_page_without_failing_others(tmp_path, caplog):
    """A corrupt page in the middle of the file must not block earlier
    or later valid pages — log + skip is the correct behavior so a
    single bad write doesn't make every Safari cookie invisible.
    """
    good = _build_cookie_record(
        domain=".ok.com",
        name="ok",
        path="/",
        value="",
        expiry=datetime.now(tz=UTC) + timedelta(days=1),
    )
    bad_page = b"\x00\x00\x01\x00" + struct.pack("<I", 999_999) + b"\x00" * 100
    data = _build_binarycookies([_build_page([good]), bad_page])
    f = tmp_path / "Cookies.binarycookies"
    f.write_bytes(data)
    profile = Profile(
        browser=BrowserKind.SAFARI,
        vendor="Safari",
        profile_name="Default",
        cookies_db_path=f,
        is_running=False,
    )
    with caplog.at_level("WARNING", logger=safari.__name__):
        cookies = safari.read_cookies(profile)
    assert [c.domain for c in cookies] == [".ok.com"]
    assert any("malformed page" in r.message for r in caplog.records)


def test_discover_returns_empty_off_macos(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    assert safari.discover_profiles() == []


def test_discover_finds_sandboxed_path(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    home = tmp_path / "home"
    cookies = (
        home
        / "Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies"
    )
    cookies.parent.mkdir(parents=True)
    cookies.write_bytes(_build_binarycookies([_build_page([])]))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setattr(safari, "is_running", lambda _kind: False)

    profiles = safari.discover_profiles()
    assert len(profiles) == 1
    assert profiles[0].browser is BrowserKind.SAFARI
    assert profiles[0].cookies_db_path == cookies


def test_read_cookies_refuses_wrong_browser_kind(tmp_path):
    f = tmp_path / "Cookies.binarycookies"
    f.write_bytes(_build_binarycookies([_build_page([])]))
    spoofed = Profile(
        browser=BrowserKind.FIREFOX,
        vendor="Firefox",
        profile_name="Default",
        cookies_db_path=f,
        is_running=False,
    )
    with pytest.raises(ValueError, match="safari"):
        safari.read_cookies(spoofed)
