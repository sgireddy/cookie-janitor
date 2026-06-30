"""Chromium-family cookie reader.

Covers Google Chrome, Chromium, Microsoft Edge, Brave, Vivaldi, Opera,
and Arc. They all share a SQLite ``Cookies`` database with the schema
documented at:

  https://chromium.googlesource.com/chromium/src/+/refs/heads/main/net/extras/sqlite/sqlite_persistent_cookie_store.cc

Storage paths (per family, per OS) live in ``_VENDORS`` below. Within a
vendor directory each *profile* is a folder named ``Default``,
``Profile 1``, ``Profile 2``, … containing a ``Cookies`` file.

Encryption
----------
Chromium encrypts cookie *values* (not names, not domains, not
expiries). The flags / metadata we need for classification are all
stored in plaintext columns, so we can read everything the classifier
cares about WITHOUT decrypting:

* macOS: ``v10`` blob = AES-CBC with a key derived from the Keychain
  entry ``Chrome Safe Storage`` (or vendor-specific equivalent).
  ``v20`` (Chrome 130+) wraps v10 with App-Bound Encryption.
* Linux: ``v10`` = AES-CBC with the static password ``peanuts``.
  ``v11`` = AES-CBC with a libsecret keyring item.
* Windows: DPAPI-encrypted blob; the AES key is in ``Local State`` and
  is itself DPAPI-encrypted.

We deliberately do NOT decrypt in v0.5. Decryption requires platform
keychain access (and on Chrome 130+ macOS, code signing acrobatics for
App-Bound Encryption). The classifier doesn't need cookie *values* —
it works on names, domains, expiries, and flags. We surface the encrypted
value as ``<encrypted>`` so the UI's optional value-hash column shows
the user that there *is* a value, without exposing or pretending to
have decrypted it.

The delete path (in ``writers.chromium``) doesn't need to decrypt
either: it deletes by ``(host_key, name, path)`` row identity.

Safety
------
* Read-only access via a private copy made through ``safety.fs``.
* WAL files (``Cookies-wal``, ``Cookies-shm``) are also copied so the
  view we get is consistent. WAL frames after a browser crash carry
  cookies that aren't yet in the main file.
* We refuse to read while the browser is running (per THREAT_MODEL
  TH-3); the GUI surfaces this in the running-browser banner.
"""

from __future__ import annotations

import logging
import sqlite3
import sys
import tempfile
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


# Vendor -> per-platform path *relative to the user's home directory*
# of the directory that CONTAINS the per-profile folders.
#
# On Linux the structure is e.g.::
#     ~/.config/google-chrome/Default/Cookies
#     ~/.config/google-chrome/Profile 1/Cookies
# On macOS::
#     ~/Library/Application Support/Google/Chrome/Default/Cookies
# On Windows::
#     %LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies
# We resolve ``%LOCALAPPDATA%`` via ``Path.home() / "AppData/Local"``
# which works on every Windows version we care about (10+).
_VENDORS: tuple[tuple[str, dict[str, str]], ...] = (
    (
        "Google Chrome",
        {
            "linux": ".config/google-chrome",
            "darwin": "Library/Application Support/Google/Chrome",
            "win32": "AppData/Local/Google/Chrome/User Data",
        },
    ),
    (
        "Chromium",
        {
            "linux": ".config/chromium",
            "darwin": "Library/Application Support/Chromium",
            "win32": "AppData/Local/Chromium/User Data",
        },
    ),
    (
        "Microsoft Edge",
        {
            "linux": ".config/microsoft-edge",
            "darwin": "Library/Application Support/Microsoft Edge",
            "win32": "AppData/Local/Microsoft/Edge/User Data",
        },
    ),
    (
        "Brave",
        {
            "linux": ".config/BraveSoftware/Brave-Browser",
            "darwin": "Library/Application Support/BraveSoftware/Brave-Browser",
            "win32": "AppData/Local/BraveSoftware/Brave-Browser/User Data",
        },
    ),
    (
        "Vivaldi",
        {
            "linux": ".config/vivaldi",
            "darwin": "Library/Application Support/Vivaldi",
            "win32": "AppData/Local/Vivaldi/User Data",
        },
    ),
    (
        "Opera",
        {
            "linux": ".config/opera",
            "darwin": "Library/Application Support/com.operasoftware.Opera",
            "win32": "AppData/Roaming/Opera Software/Opera Stable",
        },
    ),
    (
        "Arc",
        {
            # Arc is currently macOS-only at the time of writing; the
            # Windows beta uses the same User-Data layout as other
            # Chromium-family browsers. Linux entry left out — no Arc
            # release exists for it yet.
            "linux": "",
            "darwin": "Library/Application Support/Arc/User Data",
            "win32": "AppData/Local/Packages/TheBrowserCompany.Arc/LocalCache/Local/Arc/User Data",
        },
    ),
)


def _platform_key() -> str:
    plat = sys.platform
    if plat.startswith("linux"):
        return "linux"
    if plat == "darwin":
        return "darwin"
    if plat == "win32":
        return "win32"
    raise RuntimeError(f"unsupported platform: {plat}")


def _home() -> Path:
    return Path.home()


# Cookies file lives one level inside each profile dir; some Chromium
# versions placed it under ``Cookies`` (no extension) while older builds
# put it at ``Network/Cookies``. Check both.
_COOKIES_FILE_CANDIDATES: tuple[str, ...] = ("Network/Cookies", "Cookies")


def _find_cookies_file(profile_dir: Path) -> Path | None:
    for name in _COOKIES_FILE_CANDIDATES:
        candidate = profile_dir / name
        if candidate.is_file():
            return candidate
    return None


def discover_profiles() -> list[Profile]:
    """Find Chromium-family profiles. Missing vendors are silently skipped."""
    plat = _platform_key()
    found: list[Profile] = []
    running = is_running(BrowserKind.CHROMIUM)
    for vendor, paths in _VENDORS:
        root_rel = paths.get(plat) or ""
        if not root_rel:
            continue
        root = _home() / root_rel
        if not root.is_dir():
            continue
        found.extend(_discover_in_root(vendor, root, running=running))
    return found


def _discover_in_root(vendor: str, root: Path, *, running: bool) -> Iterator[Profile]:
    """Enumerate ``Default``, ``Profile 1``, … inside a vendor's root."""
    # Local State JSON would also tell us the profile display names,
    # but we don't depend on it — the directory name is plenty and the
    # JSON adds an extra failure mode. (TODO follow-up: read the
    # ``profile.info_cache.<dir>.name`` field for nicer labels.)
    try:
        children = sorted(root.iterdir(), key=lambda p: p.name)
    except OSError as exc:
        log.warning("Could not list %s: %s", root, exc)
        return
    for child in children:
        if not child.is_dir():
            continue
        name = child.name
        # Chromium profile directories are named ``Default`` or
        # ``Profile <N>``. Other folders (``System Profile``, ``Crash
        # Reports``, ``GPUCache``, …) we skip.
        if not (name == "Default" or name.startswith("Profile ")):
            continue
        cookies = _find_cookies_file(child)
        if cookies is None:
            continue
        try:
            safe_fs.assert_regular_file_owned_by_us(cookies)
        except safe_fs.UnsafePathError as exc:
            log.warning("Skipping unsafe profile %s: %s", child, exc)
            continue
        yield Profile(
            browser=BrowserKind.CHROMIUM,
            vendor=vendor,
            profile_name=name,
            cookies_db_path=cookies,
            is_running=running,
        )


# --- Reading ---------------------------------------------------------------


# Chrome stores ``samesite`` as -1 (unspecified), 0 (none), 1 (lax), 2 (strict).
_SAME_SITE_MAP = {
    -1: SameSite.UNSPECIFIED,
    0: SameSite.NONE,
    1: SameSite.LAX,
    2: SameSite.STRICT,
}


# WebKit/Chromium epoch: microseconds since 1601-01-01 00:00:00 UTC.
_WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)


def _expiry_from_webkit(micros: int | None) -> datetime | None:
    """Convert Chromium's microseconds-since-1601 to a UTC ``datetime``.

    ``0`` means "session cookie / no expiry" in Chromium. We also defend
    against insanely large values that would overflow ``timedelta``.
    """
    if not micros:
        return None
    try:
        return _WEBKIT_EPOCH + timedelta(microseconds=int(micros))
    except (OverflowError, OSError, ValueError):
        return None


# Marker for "we know there's a value but it's encrypted and we don't
# decrypt". The UI's optional value-hash column renders this verbatim so
# the user understands the difference between "no value" and "encrypted".
_ENCRYPTED_VALUE_MARKER = b"<encrypted>"


def read_cookies(profile: Profile) -> list[Cookie]:
    """Read all cookies from a Chromium profile via a private copy."""
    if profile.browser is not BrowserKind.CHROMIUM:
        raise ValueError(f"read_cookies(chromium) called with {profile.browser}")

    src = profile.cookies_db_path
    safe_fs.assert_regular_file_owned_by_us(src)

    with tempfile.TemporaryDirectory(prefix="cj-cr-") as tmp:
        tmp_path = Path(tmp)
        copy_path = tmp_path / "Cookies"
        copy_path.touch(mode=0o600, exist_ok=False)
        safe_fs.safe_copy(src, copy_path)
        # Copy WAL files too if they exist — they hold writes that
        # haven't yet been checkpointed into the main file.
        for ext in ("-wal", "-shm"):
            sidecar = src.with_name(src.name + ext)
            if sidecar.is_file():
                dest = copy_path.with_name(copy_path.name + ext)
                dest.touch(mode=0o600, exist_ok=False)
                safe_fs.safe_copy(sidecar, dest)
        return list(_read_from_copy(copy_path))


def _decode_text(value: object) -> str:
    """Lossily decode whatever sqlite3 hands back into a ``str``.

    With ``text_factory = bytes`` (see :func:`_read_from_copy`) every
    TEXT column comes back as bytes. Chrome only ever stores valid
    UTF-8 in ``name``/``host_key``/``path``/``value``, but real-world
    cookie files occasionally contain mojibake — usually from very
    old browser versions or from sites that wrote raw Latin-1 bytes.
    ``errors='replace'`` keeps one bad byte from blowing up an entire
    profile's read; the classifier only matches on cookie names and
    domains, so a replacement character in a value field is harmless.
    """
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _read_from_copy(db_path: Path) -> Iterator[Cookie]:
    # We can't pass ``immutable=1`` here because the WAL frames would
    # then be ignored. ``mode=ro`` is enough since we operate on a
    # private copy and nothing else has the file open.
    uri = f"file:{db_path}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, isolation_level=None)
    # Python's sqlite3 defaults ``text_factory`` to ``str``, which
    # strict-UTF-8-decodes anything that comes back with TEXT storage
    # class. Chrome's ``encrypted_value`` is *declared* BLOB but some
    # versions wind up with rows whose storage class is TEXT (the
    # affinity rules are subtle and version-dependent). When that
    # happens the default factory raises::
    #
    #     OperationalError: Could not decode to UTF-8 column
    #     'encrypted_value' with text 'v10\x00...'
    #
    # …which kills the whole read. Setting ``text_factory = bytes``
    # disables auto-decoding *everywhere*; we decode the four columns
    # we know are real strings (name, host, path, value) ourselves
    # with ``errors='replace'`` via ``_decode_text``. The encrypted
    # blob stays as bytes — which is what we wanted anyway, since we
    # never look inside it.
    conn.text_factory = bytes
    try:
        # Probe columns. Chrome schema has gone through ~30 revisions;
        # older versions may not have ``encrypted_value`` or
        # ``is_httponly`` named exactly the same. We pick the columns we
        # need and ignore the rest.
        cur = conn.execute("PRAGMA table_info(cookies)")
        cols = {
            (row[1].decode("utf-8") if isinstance(row[1], bytes) else row[1])
            for row in cur.fetchall()
        }
        if "name" not in cols:
            log.warning(
                "Chromium cookies table at %s has no 'name' column "
                "(schema cols: %s); skipping.",
                db_path,
                sorted(cols),
            )
            return

        # Build the SELECT defensively. Older builds used ``secure`` and
        # ``httponly``; modern Chrome uses ``is_secure`` and ``is_httponly``.
        host_col = "host_key" if "host_key" in cols else "host"
        secure_col = "is_secure" if "is_secure" in cols else "secure"
        httponly_col = "is_httponly" if "is_httponly" in cols else "httponly"
        expires_col = "expires_utc" if "expires_utc" in cols else "expires"
        samesite_col = "samesite" if "samesite" in cols else None
        value_col = "value"
        encrypted_col = "encrypted_value" if "encrypted_value" in cols else None

        select_parts = [
            "name",
            host_col,
            "path",
            expires_col,
            secure_col,
            httponly_col,
            samesite_col or "0",
            value_col,
        ]
        # ``CAST(... AS BLOB)`` belt to text_factory's suspenders: even
        # if a row's encrypted_value somehow ends up with TEXT storage
        # class, the CAST forces SQLite to hand us raw bytes. Together
        # with text_factory=bytes this makes the read airtight.
        if encrypted_col:
            select_parts.append(f"CAST({encrypted_col} AS BLOB)")
        sql = f"SELECT {', '.join(select_parts)} FROM cookies"  # noqa: S608

        for row in conn.execute(sql):
            (name, host, path, expires, secure, http_only, same_site, value, *rest) = row
            encrypted = rest[0] if rest else None
            host_str = _decode_text(host)
            if encrypted:
                value_bytes: bytes = _ENCRYPTED_VALUE_MARKER
            elif isinstance(value, bytes):
                value_bytes = value
            elif value is None:
                value_bytes = b""
            else:
                value_bytes = str(value).encode("utf-8")
            yield make_cookie(
                name=_decode_text(name),
                domain=host_str,
                path=_decode_text(path) or "/",
                expires=_expiry_from_webkit(expires),
                secure=bool(secure),
                http_only=bool(http_only),
                same_site=_SAME_SITE_MAP.get(int(same_site or 0), SameSite.UNSPECIFIED),
                # Chrome marks host-only by storing the host without a
                # leading '.' (same convention as Firefox).
                is_host_only=not host_str.startswith("."),
                value_bytes=value_bytes,
            )
    finally:
        conn.close()
