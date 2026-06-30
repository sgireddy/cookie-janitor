"""Tests for the Safari ``Cookies.binarycookies`` writer.

The writer is the riskiest module in v0.6.0 — getting the format
wrong can silently corrupt a user's cookie store. These tests pin
the contract layer by layer:

1. Pure-function serializer: byte-exact round-trip when nothing is
   dropped (the central safety property), targeted deletion when
   identities are supplied.
2. File-system pipeline: backup is created, file is atomically
   replaced, working file is cleaned up on failure, refuses to run
   while Safari is "running".
3. iCloud Safari sync detection: parses real plist shapes correctly,
   defaults to "off" on parse failure, can be overridden via env.

The round-trip property is what we lean on operationally: if the
synthetic test files round-trip, AND a user's real Safari file
round-trips (verifiable with ``serialize(data) == data`` in a one-
shot script), we have very strong evidence the writer won't corrupt
their store.
"""

from __future__ import annotations

import struct
from datetime import UTC, datetime
from pathlib import Path

import pytest

from cookie_janitor.model.cookie import BrowserKind, Profile
from cookie_janitor.readers import safari as safari_reader
from cookie_janitor.writers import safari as safari_writer
from cookie_janitor.writers.safari import (
    BinaryCookiesWriteError,
    SafariSyncEnabledError,
    serialize,
)

# --- fixture builders ------------------------------------------------------

_MAC_EPOCH = datetime(2001, 1, 1, tzinfo=UTC)


def _build_cookie_record(
    *,
    domain: str,
    name: str,
    path: str,
    value: str,
    secure: bool = False,
    http_only: bool = False,
    expires: datetime | None = None,
) -> bytes:
    """Synthesize one binarycookies cookie record.

    Mirrors what the reader expects. The string table comes after the
    fixed 56-byte header. We use a stable layout (domain, name, path,
    value) so the offsets are predictable.
    """
    flags = (0x1 if secure else 0) | (0x4 if http_only else 0)
    strings = []
    for s in (domain, name, path, value):
        strings.append(s.encode("utf-8") + b"\x00")
    domain_b, name_b, path_b, value_b = strings

    domain_off = 56
    name_off = domain_off + len(domain_b)
    path_off = name_off + len(name_b)
    value_off = path_off + len(path_b)
    total = value_off + len(value_b)

    exp_seconds = 0.0 if expires is None else (expires - _MAC_EPOCH).total_seconds()
    creation_seconds = (datetime.now(tz=UTC) - _MAC_EPOCH).total_seconds()

    rec = bytearray(total)
    struct.pack_into("<I", rec, 0, total)  # cookie_size
    struct.pack_into("<I", rec, 8, flags)
    struct.pack_into(
        "<IIII", rec, 16, domain_off, name_off, path_off, value_off
    )
    struct.pack_into("<Q", rec, 32, 0xFFFFFFFFFFFFFFFF)  # end-of-cookie sentinel
    struct.pack_into("<d", rec, 40, exp_seconds)
    struct.pack_into("<d", rec, 48, creation_seconds)
    rec[domain_off:name_off] = domain_b
    rec[name_off:path_off] = name_b
    rec[path_off:value_off] = path_b
    rec[value_off:] = value_b
    return bytes(rec)


def _build_page(records: list[bytes]) -> bytes:
    num = len(records)
    header_size = 12 + 4 * num
    offsets: list[int] = []
    cursor = header_size
    for r in records:
        offsets.append(cursor)
        cursor += len(r)
    parts = [
        b"\x00\x00\x01\x00",
        struct.pack("<I", num),
        struct.pack(f"<{num}I", *offsets) if num else b"",
        b"\x00\x00\x00\x00",
    ]
    parts.extend(records)
    return b"".join(parts)


def _build_file(pages: list[bytes], trailer: bytes = b"\x00" * 8) -> bytes:
    page_count = len(pages)
    sizes = struct.pack(f">{page_count}I", *(len(p) for p in pages))
    return b"cook" + struct.pack(">I", page_count) + sizes + b"".join(pages) + trailer


def _safari_profile(db: Path) -> Profile:
    return Profile(
        browser=BrowserKind.SAFARI,
        vendor="Safari",
        profile_name="Default",
        cookies_db_path=db,
        is_running=False,
    )


# --- serializer: round-trip ------------------------------------------------


def test_serialize_with_empty_drop_set_is_byte_identical():
    """The central safety property. If we can't faithfully reproduce
    the bytes we read, we have no business writing the file at all.
    """
    rec1 = _build_cookie_record(
        domain=".example.com", name="sid", path="/", value="abc123"
    )
    rec2 = _build_cookie_record(
        domain="tracker.test",
        name="trk",
        path="/",
        value="xyz",
        secure=True,
        http_only=True,
    )
    page = _build_page([rec1, rec2])
    source = _build_file([page])
    assert serialize(source) == source
    assert serialize(source, drop=set()) == source


def test_serialize_round_trip_across_multiple_pages_and_unicode_trailer():
    """Multi-page files with non-zero trailer bytes must also round-trip.

    A real Safari file's trailing 8 bytes are sometimes non-zero
    (possibly a hash; we don't know). Preserving them verbatim is
    safer than zeroing them — and this test pins that behaviour.
    """
    page_a = _build_page(
        [
            _build_cookie_record(
                domain=".a.test", name="x", path="/", value="1"
            ),
        ]
    )
    page_b = _build_page(
        [
            _build_cookie_record(
                domain=".b.test", name="y", path="/u", value="2"
            ),
            _build_cookie_record(
                domain=".b.test", name="z", path="/u", value="3"
            ),
        ]
    )
    trailer = b"\x01\x02\x03\x04\x05\x06\x07\x08"  # deliberately non-zero
    source = _build_file([page_a, page_b], trailer=trailer)
    assert serialize(source) == source


def test_serialize_rejects_garbage():
    with pytest.raises(BinaryCookiesWriteError, match="not a binarycookies"):
        serialize(b"not even close")


# --- serializer: targeted deletion -----------------------------------------


def test_serialize_drops_one_cookie_and_preserves_the_others():
    keep_rec = _build_cookie_record(
        domain=".keep.test", name="session", path="/", value="ok"
    )
    drop_rec = _build_cookie_record(
        domain=".drop.test", name="trk", path="/", value="bye"
    )
    source = _build_file([_build_page([keep_rec, drop_rec])])

    out = serialize(source, drop={(".drop.test", "/", "trk")})

    # Re-read through the production reader. This is the round-trip
    # that matters: we wrote, Safari (in our test, the reader) reads.
    cookies = list(safari_reader._parse(out))
    assert [c.name for c in cookies] == ["session"]
    assert cookies[0].domain == ".keep.test"


def test_serialize_keeps_pages_untouched_when_no_cookies_dropped_from_them():
    """If a delete set matches zero cookies in page B, page B's bytes
    must be byte-identical in the output — we only rebuild pages that
    actually change. This minimises diff surface and reduces the
    chance of provoking any (unknown) Safari validation.
    """
    page_a = _build_page(
        [
            _build_cookie_record(
                domain=".a.test", name="trk", path="/", value="bad"
            ),
        ]
    )
    page_b_rec = _build_cookie_record(
        domain=".b.test", name="ok", path="/", value="good"
    )
    page_b = _build_page([page_b_rec])
    source = _build_file([page_a, page_b])

    out = serialize(source, drop={(".a.test", "/", "trk")})

    # Page B in the output must equal page B in the source, byte-exact.
    # Extract page B from each by following the page-size header.
    def _page_b(buf: bytes) -> bytes:
        page_count = struct.unpack_from(">I", buf, 4)[0]
        sizes = list(struct.unpack_from(f">{page_count}I", buf, 8))
        offset = 8 + 4 * page_count + sizes[0]
        return buf[offset : offset + sizes[1]]

    assert _page_b(out) == page_b


def test_serialize_phantom_identity_is_a_noop():
    """Dropping an identity that isn't in the source must not modify
    the file. Otherwise a stale GUI selection (cookie was already
    deleted from another window) would corrupt subsequent reads.
    """
    rec = _build_cookie_record(
        domain=".real.test", name="a", path="/", value="v"
    )
    source = _build_file([_build_page([rec])])
    out = serialize(source, drop={("nonexistent.test", "/", "ghost")})
    assert out == source


# --- iCloud sync detection -------------------------------------------------


def test_payload_says_safari_sync_on_recognises_bookmarks_service():
    payload = {
        "Accounts": [
            {
                "AccountID": "x",
                "Services": [
                    {"Name": "BOOKMARKS", "Enabled": True},
                ],
            }
        ]
    }
    assert safari_writer._payload_says_safari_sync_on(payload) is True


def test_payload_says_safari_sync_on_recognises_explicit_safari_service():
    payload = {
        "Accounts": [
            {"Services": [{"Name": "SAFARI_BOOKMARKS", "Enabled": True}]}
        ]
    }
    assert safari_writer._payload_says_safari_sync_on(payload) is True


def test_payload_says_safari_sync_off_when_service_disabled():
    payload = {
        "Accounts": [
            {"Services": [{"Name": "BOOKMARKS", "Enabled": False}]}
        ]
    }
    assert safari_writer._payload_says_safari_sync_on(payload) is False


def test_payload_says_safari_sync_off_for_unrelated_services():
    payload = {
        "Accounts": [
            {"Services": [{"Name": "MAIL", "Enabled": True}]}
        ]
    }
    assert safari_writer._payload_says_safari_sync_on(payload) is False


def test_payload_says_safari_sync_off_for_malformed_input():
    """Defence: a future macOS plist shape change must not throw."""
    assert safari_writer._payload_says_safari_sync_on({}) is False
    assert safari_writer._payload_says_safari_sync_on([]) is False
    assert safari_writer._payload_says_safari_sync_on(None) is False
    assert safari_writer._payload_says_safari_sync_on(
        {"Accounts": "not a list"}
    ) is False


# --- file-system pipeline --------------------------------------------------


def test_apply_round_trips_and_creates_backup(tmp_path, monkeypatch):
    """Full pipeline: backup is taken, deletion runs, swap happens."""
    rec_keep = _build_cookie_record(
        domain=".keep.test", name="session", path="/", value="ok"
    )
    rec_drop = _build_cookie_record(
        domain=".drop.test", name="trk", path="/", value="x"
    )
    db = tmp_path / "Cookies.binarycookies"
    db.write_bytes(_build_file([_build_page([rec_keep, rec_drop])]))
    db.chmod(0o600)

    profile = _safari_profile(db)
    backup_root = tmp_path / "backups"

    # Avoid invoking real pgrep/ps on the host; Safari is "not running"
    # in this test environment.
    monkeypatch.setattr(safari_writer, "_is_browser_running", lambda _kind: False)
    monkeypatch.setattr(
        safari_writer, "_icloud_safari_sync_enabled", lambda: False
    )

    # Build a Cookie with the identity matching rec_drop.
    from cookie_janitor.model.cookie import SameSite, make_cookie

    to_drop = make_cookie(
        name="trk",
        domain=".drop.test",
        path="/",
        expires=None,
        secure=False,
        http_only=False,
        same_site=SameSite.UNSPECIFIED,
        is_host_only=False,
        value_bytes=b"x",
    )

    result = safari_writer.delete_cookies(
        profile, [to_drop], dry_run=False, backup_root=backup_root
    )

    assert result.actually_deleted == 1
    assert result.requested_deletes == 1
    assert result.backup_path is not None
    assert result.backup_path.exists()
    # The post-delete file must parse cleanly and contain only the survivor.
    survivors = list(safari_reader._parse(db.read_bytes()))
    assert [c.name for c in survivors] == ["session"]


def test_apply_with_no_changes_leaves_file_byte_identical(tmp_path, monkeypatch):
    """The byte-exact round-trip property must hold ALL THE WAY to
    the on-disk file, not just the in-memory ``serialize`` call.
    """
    rec = _build_cookie_record(
        domain=".real.test", name="a", path="/", value="v"
    )
    db = tmp_path / "Cookies.binarycookies"
    file_bytes = _build_file([_build_page([rec])])
    db.write_bytes(file_bytes)
    db.chmod(0o600)

    monkeypatch.setattr(safari_writer, "_is_browser_running", lambda _kind: False)
    monkeypatch.setattr(
        safari_writer, "_icloud_safari_sync_enabled", lambda: False
    )

    profile = _safari_profile(db)
    result = safari_writer.delete_cookies(
        profile, [], dry_run=False, backup_root=tmp_path / "backups"
    )
    assert result.actually_deleted == 0
    assert db.read_bytes() == file_bytes


def test_apply_refuses_when_safari_is_running(tmp_path, monkeypatch):
    rec = _build_cookie_record(
        domain=".x.test", name="a", path="/", value="v"
    )
    db = tmp_path / "Cookies.binarycookies"
    db.write_bytes(_build_file([_build_page([rec])]))
    db.chmod(0o600)
    monkeypatch.setattr(safari_writer, "_is_browser_running", lambda _kind: True)

    profile = _safari_profile(db)
    with pytest.raises(RuntimeError, match="Safari is currently running"):
        safari_writer.delete_cookies(
            profile, [], dry_run=False, backup_root=tmp_path / "backups"
        )


def test_apply_refuses_when_icloud_safari_sync_is_on(tmp_path, monkeypatch):
    rec = _build_cookie_record(
        domain=".x.test", name="a", path="/", value="v"
    )
    db = tmp_path / "Cookies.binarycookies"
    db.write_bytes(_build_file([_build_page([rec])]))
    db.chmod(0o600)
    monkeypatch.setattr(safari_writer, "_is_browser_running", lambda _kind: False)
    monkeypatch.setattr(safari_writer, "_icloud_safari_sync_enabled", lambda: True)
    # Make sure no leftover env-var override is in effect from another
    # test or the host environment.
    monkeypatch.delenv("COOKIE_JANITOR_ALLOW_SAFARI_SYNC", raising=False)

    profile = _safari_profile(db)
    with pytest.raises(SafariSyncEnabledError) as excinfo:
        safari_writer.delete_cookies(
            profile, [], dry_run=False, backup_root=tmp_path / "backups"
        )
    msg = str(excinfo.value)
    assert "iCloud" in msg
    assert "System Settings" in msg
    assert "COOKIE_JANITOR_ALLOW_SAFARI_SYNC" in msg


def test_apply_proceeds_when_icloud_sync_override_env_is_set(
    tmp_path, monkeypatch
):
    rec = _build_cookie_record(
        domain=".x.test", name="a", path="/", value="v"
    )
    db = tmp_path / "Cookies.binarycookies"
    db.write_bytes(_build_file([_build_page([rec])]))
    db.chmod(0o600)
    monkeypatch.setattr(safari_writer, "_is_browser_running", lambda _kind: False)
    monkeypatch.setattr(safari_writer, "_icloud_safari_sync_enabled", lambda: True)
    monkeypatch.setenv("COOKIE_JANITOR_ALLOW_SAFARI_SYNC", "1")

    profile = _safari_profile(db)
    result = safari_writer.delete_cookies(
        profile, [], dry_run=False, backup_root=tmp_path / "backups"
    )
    # No cookies dropped, but the call must have completed without
    # raising — that's the only point of this test.
    assert result.actually_deleted == 0


def test_restore_from_backup_round_trips(tmp_path, monkeypatch):
    """Restore must atomically replace the live file with the backup.

    Mirrors the recovery path the user is told about in the post-
    delete dialog ("cookie-janitor restore <backup>").
    """
    rec = _build_cookie_record(
        domain=".x.test", name="a", path="/", value="original"
    )
    original = _build_file([_build_page([rec])])
    backup = tmp_path / "backup" / "Cookies.binarycookies"
    backup.parent.mkdir(parents=True)
    backup.write_bytes(original)
    backup.chmod(0o600)

    db = tmp_path / "Cookies.binarycookies"
    db.write_bytes(b"corrupted post-delete content")
    db.chmod(0o600)

    monkeypatch.setattr(safari_writer, "_is_browser_running", lambda _kind: False)

    safari_writer.restore_from_backup(_safari_profile(db), backup)
    assert db.read_bytes() == original
