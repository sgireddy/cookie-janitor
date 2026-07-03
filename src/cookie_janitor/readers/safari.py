"""Safari cookie reader.

Safari stores cookies in a binary file:

* Sandboxed (modern macOS):
    ``~/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies``
* Legacy (pre-Mojave or non-sandboxed):
    ``~/Library/Cookies/Cookies.binarycookies``

The ``.binarycookies`` format is a documented (by reverse engineering)
big-endian binary structure. It has been stable since Safari 5.

File layout
-----------
::

    magic:           4 bytes  "cook"
    page_count:      4 bytes  big-endian uint32
    page_sizes:      page_count * 4 bytes (big-endian uint32 each)
    pages:           page_count blocks, each ``page_sizes[i]`` bytes
    footer / hash:   8 bytes  (not validated)

Each page::

    page_magic:      4 bytes  0x00000100 (little-endian within the page)
    num_cookies:     4 bytes  uint32 LE
    cookie_offsets:  num_cookies * 4 bytes (uint32 LE)
    footer:          4 bytes  0x00000000
    cookies...

Each cookie::

    cookie_size:     4 bytes  uint32 LE
    unknown:         4 bytes  (always 0 in modern files)
    flags:           4 bytes  uint32 LE   (1=secure, 4=httpOnly,
                                            other bits unused)
    unknown:         4 bytes
    domain_offset:   4 bytes  uint32 LE   (from cookie start)
    name_offset:     4 bytes  uint32 LE
    path_offset:     4 bytes  uint32 LE
    value_offset:    4 bytes  uint32 LE
    end_of_cookie:   8 bytes  0xFFFFFFFFFFFFFFFF
    expiry_epoch:    8 bytes  float64 LE (seconds since 2001-01-01)
    creation_epoch:  8 bytes  float64 LE (same epoch)
    [strings at the offsets, NUL-terminated UTF-8]

Mac Absolute Time (MAT) epoch is 2001-01-01 00:00:00 UTC. We convert.

SameSite is NOT stored in the binary format. Safari only added SameSite
runtime support in 13.1 and doesn't persist the attribute. We mark
every cookie as ``UNSPECIFIED``.

Sandboxed Safari: reading the Containers path needs **Full Disk Access**
for the calling binary. If we get ``PermissionError`` we surface it
through our normal error path; the GUI catches it and tells the user
to grant FDA in System Settings.

Writing
-------
Not implemented in this version. The format is rewritable but the risk
of corrupting Safari's store is non-trivial and we'd rather ship a
read-only scan now than a half-tested writer. ``writers.safari``
raises ``NotImplementedError`` with a clear message. The GUI greys
out the delete checkboxes for Safari rows accordingly.
"""

from __future__ import annotations

import errno
import logging
import struct
import sys
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cookie_janitor.model.cookie import (
    BrowserKind,
    Cookie,
    Profile,
    SameSite,
    make_cookie,
)
from cookie_janitor.safety import fs as safe_fs
from cookie_janitor.safety.process import is_running

log = logging.getLogger(__name__)


# Safari's binarycookies file has lived in exactly two places. We try
# both for resilience against future moves; the sandboxed path wins if
# both exist on the same machine.
_CANDIDATES_RELATIVE_TO_HOME: tuple[str, ...] = (
    "Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies",
    "Library/Cookies/Cookies.binarycookies",
)


# Mac Absolute Time epoch (Cocoa NSDate reference date).
_MAC_EPOCH = datetime(2001, 1, 1, tzinfo=UTC)


def discover_profiles() -> list[Profile]:
    """Safari has one profile per user. Returns 0 or 1 entries.

    Empty list on non-macOS platforms (we don't even try the path —
    saves an ``OSError`` per discovery and makes the intent obvious in
    the code).
    """
    # Read through a local so mypy can't narrow ``sys.platform`` based
    # on whichever OS happened to type-check this build. We want the
    # branch to remain reachable in cross-platform analysis.
    platform: str = sys.platform
    if platform != "darwin":
        return []
    running = is_running(BrowserKind.SAFARI)
    home = Path.home()
    for rel in _CANDIDATES_RELATIVE_TO_HOME:
        candidate = home / rel
        if not candidate.is_file():
            continue
        try:
            safe_fs.assert_regular_file_owned_by_us(candidate)
        except safe_fs.UnsafePathError as exc:
            log.warning("Skipping unsafe Safari cookies file %s: %s", candidate, exc)
            continue
        # Only one profile per user, but mirror the multi-profile API.
        return [
            Profile(
                browser=BrowserKind.SAFARI,
                vendor="Safari",
                profile_name="Default",
                cookies_db_path=candidate,
                is_running=running,
            )
        ]
    return []


# --- Binary parser ----------------------------------------------------------


class BinaryCookiesError(ValueError):
    """Raised when the .binarycookies file doesn't match the expected format.

    We carry on past individual corrupt cookies (log + skip) but bail
    out cleanly if the *file header* doesn't even start with ``cook``,
    so we don't accidentally interpret unrelated bytes.
    """


class SafariPermissionDeniedError(PermissionError):
    """macOS TCC denied us read access to Safari's cookies file.

    Raised when the underlying ``open()`` returns ``EPERM`` / ``EACCES``
    on a path under ``~/Library/Containers/com.apple.Safari/``. Carries
    an actionable, ready-for-the-dialog message in ``str(exc)`` so the
    GUI doesn't have to know about macOS TCC mechanics.

    Why this exists as its own class
    --------------------------------

    The bare error a user sees from Python is::

        [Errno 1] Operation not permitted:
        '/Users/.../Library/Containers/com.apple.Safari/.../Cookies.binarycookies'

    That's accurate but unactionable — nothing on screen tells the
    user *what* permission, *where* to grant it, or that they'll have
    to **restart** Cookie Janitor afterwards (TCC caches per-process).
    Giving the error a dedicated type lets the GUI render a much
    better dialog AND lets callers (CLI, tests) treat permission
    failures distinctly from "file doesn't exist" or "file is
    corrupt".
    """

    #: Multi-paragraph copy ready to drop into a QMessageBox detail field.
    GUIDANCE: str = (
        "macOS protects Safari's cookie store with a system feature called"
        " Full Disk Access (part of Privacy & Security). Cookie Janitor"
        " needs to be on that allow-list to read or audit Safari cookies.\n"
        "\n"
        "To grant it:\n"
        "  1. Open  Apple menu → System Settings → Privacy & Security →"
        " Full Disk Access.\n"
        "  2. Click the +  button and select Cookie Janitor.app"
        " (or drag it in from /Applications).\n"
        "  3. Make sure the toggle next to Cookie Janitor is ON.\n"
        "  4. Quit Cookie Janitor completely (⌘Q) and reopen it — TCC"
        " only re-checks permissions on next launch.\n"
        "\n"
        "Your other browsers (Firefox, Chrome, Edge, Brave, …) don't"
        " need this — they store cookies outside Apple's protected"
        " containers. Safari is the only family affected."
    )

    def __init__(self, path: Path, original: OSError | None = None) -> None:
        self.path = path
        self.original = original
        super().__init__(
            f"macOS denied read access to {path}. "
            f"Grant Full Disk Access to Cookie Janitor and relaunch.\n\n"
            f"{self.GUIDANCE}"
        )


def read_cookies(profile: Profile) -> list[Cookie]:
    """Parse a Safari ``Cookies.binarycookies`` file.

    We do NOT need a private copy here — the file is small (typically
    under 1 MB), Safari rewrites it as a whole on quit (not in place),
    and SQLite-style locking isn't a factor. We still open it
    read-only and the safety primitives have already validated the
    inode + ownership in ``discover_profiles``.

    Raises :class:`SafariPermissionDeniedError` when the read fails
    with ``EPERM``/``EACCES`` — almost always macOS TCC blocking us
    from Safari's protected container. The GUI catches this
    specifically and renders the Full Disk Access guidance.
    """
    if profile.browser is not BrowserKind.SAFARI:
        raise ValueError(f"read_cookies(safari) called with {profile.browser}")
    try:
        data = profile.cookies_db_path.read_bytes()
    except PermissionError as exc:
        # macOS TCC denies with EPERM (errno 1); some filesystems
        # return EACCES (errno 13). Either way we want the same UX.
        raise SafariPermissionDeniedError(profile.cookies_db_path, original=exc) from exc
    except OSError as exc:
        if exc.errno in (errno.EPERM, errno.EACCES):
            raise SafariPermissionDeniedError(profile.cookies_db_path, original=exc) from exc
        raise
    return list(_parse(data))


def _parse(data: bytes) -> Iterator[Cookie]:
    if len(data) < 8 or data[:4] != b"cook":
        raise BinaryCookiesError("not a Safari .binarycookies file (missing 'cook' magic).")
    page_count: int = struct.unpack_from(">I", data, 4)[0]
    if page_count > 100_000:
        raise BinaryCookiesError(f"page_count={page_count} looks corrupt (sanity bound 100000).")

    page_size_offset = 8
    page_sizes: list[int] = list(struct.unpack_from(f">{page_count}I", data, page_size_offset))
    cursor = page_size_offset + 4 * page_count
    for i, size in enumerate(page_sizes):
        if cursor + size > len(data):
            log.warning(
                "Safari cookies: page %d would overrun file (offset=%d, size=%d, file=%d).",
                i,
                cursor,
                size,
                len(data),
            )
            return
        page = data[cursor : cursor + size]
        cursor += size
        try:
            yield from _parse_page(page)
        except BinaryCookiesError as exc:
            log.warning("Safari cookies: skipping malformed page %d (%s).", i, exc)
            continue


def _parse_page(page: bytes) -> Iterator[Cookie]:
    if len(page) < 12:
        raise BinaryCookiesError("page too short")
    # The page magic value is 0x00000100 written little-endian as the
    # first 4 bytes, which is documented but a bit odd; we just check
    # that the byte pattern matches.
    if page[:4] != b"\x00\x00\x01\x00":
        raise BinaryCookiesError(f"unexpected page magic: {page[:4]!r}")
    num_cookies: int = struct.unpack_from("<I", page, 4)[0]
    if num_cookies > 100_000:
        raise BinaryCookiesError(f"num_cookies={num_cookies} looks corrupt (sanity bound 100000).")
    offsets_end = 8 + 4 * num_cookies
    if offsets_end > len(page):
        raise BinaryCookiesError("cookie-offset table extends past end of page")
    offsets: list[int] = list(struct.unpack_from(f"<{num_cookies}I", page, 8))
    for off in offsets:
        try:
            yield _parse_cookie(page, off)
        except BinaryCookiesError as exc:
            log.warning("Safari cookies: skipping malformed cookie at %d (%s).", off, exc)
            continue


def _parse_cookie(page: bytes, offset: int) -> Cookie:
    if offset + 56 > len(page):
        raise BinaryCookiesError("cookie record extends past end of page")
    rec = page[offset:]
    cookie_size: int = struct.unpack_from("<I", rec, 0)[0]
    if cookie_size < 56 or offset + cookie_size > len(page):
        raise BinaryCookiesError(f"impossible cookie_size={cookie_size}")
    flags: int = struct.unpack_from("<I", rec, 8)[0]
    domain_offset, name_offset, path_offset, value_offset = struct.unpack_from("<IIII", rec, 16)
    expiry_seconds: float = struct.unpack_from("<d", rec, 40)[0]
    # creation_seconds at offset 48 — we don't need it for the classifier.

    domain = _read_cstring(rec, domain_offset, cookie_size)
    name = _read_cstring(rec, name_offset, cookie_size)
    path = _read_cstring(rec, path_offset, cookie_size) or "/"
    value = _read_cstring(rec, value_offset, cookie_size)

    secure = bool(flags & 0x1)
    http_only = bool(flags & 0x4)

    expires: datetime | None
    if expiry_seconds <= 0:
        expires = None
    else:
        try:
            expires = _MAC_EPOCH + timedelta(seconds=expiry_seconds)
        except (OverflowError, OSError, ValueError):
            expires = None

    return make_cookie(
        name=name,
        domain=domain,
        path=path,
        expires=expires,
        secure=secure,
        http_only=http_only,
        # Safari's binarycookies format does not store SameSite.
        same_site=SameSite.UNSPECIFIED,
        is_host_only=not domain.startswith("."),
        value_bytes=value.encode("utf-8"),
    )


def _read_cstring(rec: bytes, off: int, max_end: int) -> str:
    """Read a NUL-terminated UTF-8 string from ``rec`` starting at ``off``.

    ``max_end`` is the end of the cookie record; we don't read past it
    even if a NUL is missing (corrupt file). Decoded permissively
    (``errors='replace'``) so a single bad byte doesn't take out a
    whole site's worth of cookies — the classifier only cares about
    matching the name/domain anyway.
    """
    if off >= max_end:
        return ""
    end = rec.find(b"\x00", off, max_end)
    if end == -1:
        end = max_end
    return rec[off:end].decode("utf-8", errors="replace")
