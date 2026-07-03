"""Safari ``Cookies.binarycookies`` writer.

The format is fully described in
``cookie_janitor.readers.safari`` — this module is its inverse, but
with one critical safety invariant:

**We never synthesize cookie *records* from scratch.**  For every
cookie we want to keep, we copy its raw byte slice verbatim out of
the original file. Only the file/page *envelope* (magic, page count,
page sizes, per-page cookie offsets) is recomputed. This guarantees:

* Surviving cookies are byte-identical to what Safari last wrote —
  no chance of float-encoding drift, offset-table off-by-one, or
  string-table re-encoding turning a valid cookie into a corrupt
  one.
* The minimal-diff property: if no cookies are dropped, the output
  is byte-identical to the input. We pin this with a round-trip
  test.

The file's trailing 8 bytes (variously described as a "checksum" or
"footer" in reverse-engineering write-ups) are preserved verbatim
from the original. We don't know what algorithm — if any — produced
them, and recomputing wrongly is worse than preserving a stale value.
Most Safari versions appear not to validate them.

Trade-offs we ARE accepting in this release
-------------------------------------------

1. *iCloud Safari Sync* can resurrect deleted cookies within minutes
   from another Apple device. We detect this opportunistically and
   raise :class:`SafariSyncEnabledError` so the GUI can show a clear
   warning. The user can override with the ``COOKIE_JANITOR_ALLOW_SAFARI_SYNC=1``
   environment variable if they understand the consequence.

2. *Safari running* refuses to write. Same as every other writer.
   Safari does NOT use SQLite locking; it rewrites the whole file on
   quit. If we wrote while it was running, Safari would silently
   overwrite our changes on its next save.

3. *Macros sandbox*. Cookie Janitor itself needs Full Disk Access to
   read the file — it also needs it to write. Both succeed once FDA
   is granted.
"""

from __future__ import annotations

import contextlib
import hashlib
import logging
import os
import plistlib
import struct
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from cookie_janitor.model.cookie import BrowserKind, Cookie, Profile
from cookie_janitor.safety import fs as safe_fs
from cookie_janitor.safety.process import is_running as _is_browser_running

from .types import WriteResult

log = logging.getLogger(__name__)

_BACKUP_ROOT_ENV = "COOKIE_JANITOR_BACKUP_ROOT"
_ALLOW_SYNC_ENV = "COOKIE_JANITOR_ALLOW_SAFARI_SYNC"

# --- exception types -------------------------------------------------------


class SafariWriteError(RuntimeError):
    """Base class for write-time failures specific to Safari."""


class SafariSyncEnabledError(SafariWriteError):
    """Raised when iCloud is configured to sync Safari data.

    Carries actionable copy in ``str(exc)`` for the GUI to display.
    """

    # ruff S608 / bandit B608 both fire on any string literal
    # containing "delete"; this is plain English UI copy, not SQL.
    GUIDANCE: str = (
        "iCloud → Safari is currently enabled on this Mac. If you delete"  # noqa: S608  # nosec B608
        " cookies now, they may sync back from your other Apple devices"
        " within minutes — making it look like Cookie Janitor didn't"
        " work.\n"
        "\n"
        "To delete cookies cleanly:\n"
        "  1. Open  Apple menu → System Settings → [Your Name] →"
        " iCloud → Saved to iCloud.\n"
        "  2. Find Safari in the list and turn it OFF.\n"
        "  3. Confirm 'Delete from this Mac' (or 'Keep on this Mac' —"
        " either is fine; you're only stopping the sync).\n"
        "  4. Come back to Cookie Janitor and click Delete again.\n"
        "\n"
        "If you accept the risk of resurrection and want to proceed"
        " anyway, set the environment variable"
        f" {_ALLOW_SYNC_ENV}=1 and relaunch Cookie Janitor."
    )

    def __init__(self) -> None:
        super().__init__(
            f"iCloud Safari sync is enabled; deleted cookies may resurrect. {self.GUIDANCE}"
        )


class BinaryCookiesWriteError(SafariWriteError):
    """Raised when serialization fails (offset overflow, page too large, …)."""


# --- pure serializer -------------------------------------------------------


@dataclass(frozen=True)
class _RawCookie:
    """A cookie kept as its original byte slice + parsed identity.

    The serializer needs both: the identity to match against the
    "drop" set, and the raw bytes to reassemble pages without
    recoding the cookie record.
    """

    domain: str
    name: str
    path: str
    record: bytes  # exact bytes from the source page

    @property
    def identity(self) -> tuple[str, str, str]:
        return (self.domain, self.path, self.name)


def _read_cstring_from_record(rec: bytes, off: int) -> str:
    """Read a NUL-terminated UTF-8 string starting at ``off`` within ``rec``."""
    if off >= len(rec):
        return ""
    end = rec.find(b"\x00", off)
    if end == -1:
        end = len(rec)
    return rec[off:end].decode("utf-8", errors="replace")


def _extract_page_cookies(page: bytes) -> list[_RawCookie]:
    """Pull cookies out of a page WITHOUT decoding their value bytes.

    Returns each cookie's identity (for matching) plus its exact byte
    slice (for verbatim reassembly).
    """
    if len(page) < 12 or page[:4] != b"\x00\x00\x01\x00":
        raise BinaryCookiesWriteError(f"page header invalid: {page[:4]!r}")
    num_cookies: int = struct.unpack_from("<I", page, 4)[0]
    if num_cookies == 0:
        return []
    offsets_end = 8 + 4 * num_cookies
    if offsets_end > len(page):
        raise BinaryCookiesWriteError("offset table extends past end of page")
    offsets = list(struct.unpack_from(f"<{num_cookies}I", page, 8))
    out: list[_RawCookie] = []
    for off in offsets:
        if off + 56 > len(page):
            raise BinaryCookiesWriteError(f"cookie at {off} extends past page")
        size: int = struct.unpack_from("<I", page, off)[0]
        if size < 56 or off + size > len(page):
            raise BinaryCookiesWriteError(f"cookie at {off}: impossible size {size}")
        rec = page[off : off + size]
        domain_off, name_off, path_off, value_off = struct.unpack_from("<IIII", rec, 16)
        domain = _read_cstring_from_record(rec, domain_off)
        name = _read_cstring_from_record(rec, name_off)
        path = _read_cstring_from_record(rec, path_off) or "/"
        # value is not needed for identity matching; we don't read it.
        del value_off
        out.append(_RawCookie(domain=domain, name=name, path=path, record=rec))
    return out


def _build_page(cookies: list[_RawCookie]) -> bytes:
    """Assemble a page from a list of cookie byte-slices.

    Layout: magic(4) + num(4) + offsets(4*N) + footer(4) + records.
    The 4-byte page footer is emitted as zeros — this matches the
    pattern observed in real Safari files and is what the reader
    expects.

    A page with zero cookies is still legal in the format; we use
    that to preserve page count when every cookie in an original
    page was dropped (some callers may rely on stable page indices
    when correlating with logs). Empty pages add only 12 bytes each.
    """
    num = len(cookies)
    header_size = 12 + 4 * num  # magic + num + offsets + footer
    out = bytearray()
    out += b"\x00\x00\x01\x00"
    out += struct.pack("<I", num)
    cursor = header_size
    offsets: list[int] = []
    for c in cookies:
        offsets.append(cursor)
        cursor += len(c.record)
    out += struct.pack(f"<{num}I", *offsets)
    out += b"\x00\x00\x00\x00"  # 4-byte page footer (always zeros in observed files)
    for c in cookies:
        out += c.record
    return bytes(out)


def serialize(source: bytes, drop: set[tuple[str, str, str]] | None = None) -> bytes:
    """Return a binarycookies file derived from ``source`` minus ``drop``.

    Invariants:

    * ``serialize(source, drop=set())`` == ``source`` for any source we
      can parse — the round-trip is byte-exact. This is THE safety
      property: it proves we understand the format well enough to
      preserve it.
    * The trailing 8 bytes of ``source`` are appended verbatim to the
      output. We don't know whether they're a checksum, padding, or
      something else; preserving the original value is the safest
      default and is what we observe Safari accepting in the wild.
    * Cookie records are copied verbatim; we never re-encode field
      values. Encoding drift on round-trips is impossible because we
      never decode them in the first place.

    Raises :class:`BinaryCookiesWriteError` if the source can't be
    parsed (the caller should keep the original file unchanged).
    """
    drop = drop or set()
    if len(source) < 8 or source[:4] != b"cook":
        raise BinaryCookiesWriteError("source is not a binarycookies file")
    page_count: int = struct.unpack_from(">I", source, 4)[0]
    if page_count > 100_000:
        raise BinaryCookiesWriteError(f"page_count={page_count} looks corrupt")

    page_size_offset = 8
    page_sizes = list(struct.unpack_from(f">{page_count}I", source, page_size_offset))
    cursor = page_size_offset + 4 * page_count
    pages_start = cursor
    new_pages: list[bytes] = []
    any_change = False
    for i, size in enumerate(page_sizes):
        if cursor + size > len(source):
            raise BinaryCookiesWriteError(
                f"page {i} would overrun source (offset={cursor}, size={size})"
            )
        page = source[cursor : cursor + size]
        cursor += size
        if not drop:
            # Fast path: no deletions requested. Page stays byte-identical.
            new_pages.append(page)
            continue
        original_cookies = _extract_page_cookies(page)
        survivors = [c for c in original_cookies if c.identity not in drop]
        if len(survivors) == len(original_cookies):
            new_pages.append(page)  # untouched
            continue
        any_change = True
        new_pages.append(_build_page(survivors))

    trailer = source[cursor:]  # whatever comes after the last page

    if not drop or not any_change:
        # Output is provably byte-identical to source. Belt: assert it.
        rebuilt = (
            b"cook"
            + struct.pack(">I", page_count)
            + struct.pack(f">{page_count}I", *(len(p) for p in new_pages))
            + b"".join(new_pages)
            + trailer
        )
        if rebuilt != source[: pages_start + sum(page_sizes)] + trailer:
            # This should be impossible; the round-trip property is
            # what makes the whole writer safe. If we get here, refuse
            # to write — the file would be subtly different from the
            # original.
            raise BinaryCookiesWriteError("internal round-trip mismatch on unchanged file")
        return rebuilt

    new_sizes = [len(p) for p in new_pages]
    return (
        b"cook"
        + struct.pack(">I", page_count)
        + struct.pack(f">{page_count}I", *new_sizes)
        + b"".join(new_pages)
        + trailer
    )


# --- iCloud Safari sync detection -----------------------------------------


_MOBILEME_PLIST_REL = "Library/Application Support/iCloud/Accounts"
_MOBILEME_PLIST_LEGACY = "Library/Preferences/MobileMeAccounts.plist"


def _icloud_safari_sync_enabled() -> bool:
    """Best-effort check: is iCloud Safari sync ON for the current user?

    Returns ``False`` if we can't decide — we'd rather under-warn than
    block a user's legitimate delete because we got confused by a
    plist layout change. The :class:`SafariSyncEnabledError` path is
    a *safety net*, not a security boundary.

    On non-macOS hosts always returns ``False`` (the writer isn't
    invoked there, but unit tests run on Linux and we want them to
    exercise the happy path).
    """
    # Use a local copy of sys.platform so mypy can't narrow the
    # check away on whichever OS happens to type-check this build.
    platform: str = sys.platform
    if platform != "darwin":
        return False
    home = Path.home()
    plist_paths = [
        home / _MOBILEME_PLIST_LEGACY,
        home / _MOBILEME_PLIST_REL,
    ]
    for plist_path in plist_paths:
        try:
            data = plist_path.read_bytes()
        except (FileNotFoundError, PermissionError, OSError):
            continue
        try:
            payload = plistlib.loads(data)
        except (plistlib.InvalidFileException, ValueError):
            log.warning("Couldn't parse %s; assuming sync off.", plist_path)
            continue
        if _payload_says_safari_sync_on(payload):
            return True
    return False


def _payload_says_safari_sync_on(payload: object) -> bool:
    """Walk a parsed plist looking for a Safari/Bookmarks service flagged ON.

    Real-world plist shape, as of macOS 14::

        {"Accounts": [
            {"AccountID": "...",
             "Services": [
                {"Name": "BOOKMARKS", "Enabled": True, ...},
                {"Name": "BOOKMARKS", "Description": "Safari", ...},
             ]}
        ]}

    macOS has used slightly different service identifiers across
    versions (``BOOKMARKS``, ``SAFARI_BOOKMARKS``, ``SAFARI``). We
    match any service whose ``Name`` looks Safari-ish AND has
    ``Enabled`` truthy.
    """
    if not isinstance(payload, dict):
        return False
    accounts = payload.get("Accounts")
    if not isinstance(accounts, list):
        return False
    for account in accounts:
        if not isinstance(account, dict):
            continue
        services = account.get("Services")
        if not isinstance(services, list):
            continue
        for svc in services:
            if not isinstance(svc, dict):
                continue
            name = str(svc.get("Name", "")).upper()
            if "SAFARI" not in name and "BOOKMARKS" not in name:
                continue
            if svc.get("Enabled"):
                return True
    return False


# --- backup helpers (mirror writers.firefox._backup_root etc.) -------------


def _backup_root() -> Path:
    override = os.environ.get(_BACKUP_ROOT_ENV)
    if override:
        return Path(override)
    if os.name == "nt":  # pragma: no cover
        return Path.home() / "AppData" / "Local" / "cookie-janitor" / "backups"
    return Path.home() / ".local" / "state" / "cookie-janitor" / "backups"


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _make_backup(profile: Profile, root: Path) -> Path:
    src = profile.cookies_db_path
    safe_fs.assert_regular_file_owned_by_us(src)

    ts = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
    leaf = root / profile.browser.value / profile.profile_name / ts
    leaf.mkdir(parents=True, mode=0o700, exist_ok=False)
    if os.name != "nt":
        leaf.chmod(0o700)
    backup_path = leaf / "Cookies.binarycookies"
    backup_path.touch(mode=0o600, exist_ok=False)
    safe_fs.safe_copy(src, backup_path)

    src_st = src.stat()
    bkp_st = backup_path.stat()
    if src_st.st_size != bkp_st.st_size:
        raise RuntimeError(f"backup size mismatch: src={src_st.st_size} bkp={bkp_st.st_size}")
    if _hash_file(src) != _hash_file(backup_path):
        raise RuntimeError(f"backup hash mismatch for {src} -> {backup_path}")
    log.info("Backed up %s -> %s (%d bytes)", src, backup_path, bkp_st.st_size)
    return backup_path


# --- public API ------------------------------------------------------------


def delete_cookies(
    profile: Profile,
    cookies_to_delete: Iterable[Cookie],
    *,
    dry_run: bool = True,
    backup_root: Path | None = None,
) -> WriteResult:
    """Delete the given cookies from ``profile``'s Cookies.binarycookies.

    Pipeline:

    1. Refuse if Safari is running. Safari rewrites the whole file on
       quit and would clobber our changes.
    2. Refuse if iCloud Safari sync is on, unless the user has set
       ``COOKIE_JANITOR_ALLOW_SAFARI_SYNC=1`` to acknowledge that
       deleted cookies may resurrect.
    3. Take a verified backup (mode 0700 directory, mode 0600 file,
       SHA-256 + size compared against source).
    4. Read source bytes, run :func:`serialize` to produce the new
       content, write to a sibling working file, fsync, atomic-swap.

    A dry-run skips steps 2-4 and reports the *planned* deletion
    count. The GUI uses dry-run during normal scanning to compute
    "would be deleted" counts; that path must always succeed.
    """
    if profile.browser is not BrowserKind.SAFARI:
        raise ValueError(f"delete_cookies(safari) called with {profile.browser}")

    identities = [c.identity for c in cookies_to_delete]
    timestamp = datetime.now(tz=UTC)
    if dry_run:
        return WriteResult(
            profile=profile,
            requested_deletes=len(identities),
            actually_deleted=len(identities),
            backup_path=None,
            dry_run=True,
            timestamp=timestamp,
        )

    if _is_browser_running(profile.browser):
        raise RuntimeError(
            "Refusing to write: Safari is currently running. Quit Safari (Cmd+Q) and try again."
        )

    if os.environ.get(_ALLOW_SYNC_ENV) != "1" and _icloud_safari_sync_enabled():
        raise SafariSyncEnabledError

    src = profile.cookies_db_path
    safe_fs.assert_regular_file_owned_by_us(src)

    # Step 1: backup.
    root = backup_root or _backup_root()
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    if os.name != "nt":
        root.chmod(0o700)
    backup_path = _make_backup(profile, root)

    # Step 2: serialize a new file in memory. If serialization fails
    # the original is untouched and no working file has been created
    # yet — clean failure.
    source = src.read_bytes()
    drop_set = set(identities)
    new_bytes = serialize(source, drop=drop_set)

    # Step 3: write working file in the same directory as the original
    # (atomic_replace requires same parent).
    working = src.with_name(src.name + ".cj-tmp")
    if working.exists():
        raise RuntimeError(
            f"Working file already exists from a previous run: {working}. Move it aside and retry."
        )
    working.touch(mode=0o600, exist_ok=False)
    try:
        with working.open("rb+") as fh:
            fh.write(new_bytes)
            fh.flush()
            os.fsync(fh.fileno())
        safe_fs.atomic_replace(working, src)
    except BaseException:
        if working.exists():
            try:
                working.unlink()
            except OSError:
                log.exception("Failed to clean up working file %s", working)
        raise

    # Count actually-deleted: how many requested identities were
    # present in the source. We compute this from the source bytes
    # rather than from "len(source) - len(new_bytes)" because that
    # byte delta isn't a faithful count (page envelope changes too).
    actual = _count_present(source, drop_set)
    log.info(
        "Deleted %d/%d cookies from %s (backup at %s)",
        actual,
        len(identities),
        src,
        backup_path,
    )
    return WriteResult(
        profile=profile,
        requested_deletes=len(identities),
        actually_deleted=actual,
        backup_path=backup_path,
        dry_run=False,
        timestamp=timestamp,
    )


def _count_present(source: bytes, identities: set[tuple[str, str, str]]) -> int:
    """How many of ``identities`` are actually in ``source``? Used for
    the WriteResult so we don't over-report on phantom identities.
    """
    if not identities:
        return 0
    page_count: int = struct.unpack_from(">I", source, 4)[0]
    page_size_offset = 8
    page_sizes = list(struct.unpack_from(f">{page_count}I", source, page_size_offset))
    cursor = page_size_offset + 4 * page_count
    found = 0
    for size in page_sizes:
        page = source[cursor : cursor + size]
        cursor += size
        with contextlib.suppress(BinaryCookiesWriteError):
            for c in _extract_page_cookies(page):
                if c.identity in identities:
                    found += 1
    return found


def restore_from_backup(profile: Profile, backup_path: Path) -> None:
    """Atomically replace ``profile``'s Cookies.binarycookies with the backup.

    Mirrors the Firefox writer's restore path. Refuses if Safari is
    running.
    """
    if profile.browser is not BrowserKind.SAFARI:
        raise ValueError(f"restore_from_backup(safari) called with {profile.browser}")
    if _is_browser_running(profile.browser):
        raise RuntimeError("Refusing to restore: Safari is currently running.")
    safe_fs.assert_regular_file_owned_by_us(backup_path)

    src = profile.cookies_db_path
    working = src.with_name(src.name + ".cj-restore-tmp")
    if working.exists():
        raise RuntimeError(f"Working file already exists: {working}")
    working.touch(mode=0o600, exist_ok=False)
    try:
        safe_fs.safe_copy(backup_path, working)
        with working.open("rb+") as fh:
            fh.flush()
            os.fsync(fh.fileno())
        safe_fs.atomic_replace(working, src)
    except BaseException:
        if working.exists():
            try:
                working.unlink()
            except OSError:
                log.exception("Failed to clean up restore working file %s", working)
        raise
    log.info("Restored %s from %s", src, backup_path)
