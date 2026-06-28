"""Firefox-family cookie reader.

Firefox stores cookies in ``cookies.sqlite`` under each profile
directory. Values are stored in cleartext; there is no decryption step.
This makes Firefox the safest first vertical slice — we can exercise the
whole pipeline (discovery → read → classify → decide → dry-run report)
without ever touching a crypto library.

Profile discovery
-----------------

Firefox's per-OS profile root:

  Linux   : ~/.mozilla/firefox
  macOS   : ~/Library/Application Support/Firefox/Profiles
            (and the parent dir has profiles.ini)
  Windows : %APPDATA%/Mozilla/Firefox

The ``profiles.ini`` lists profiles; we honor it when present and fall
back to scanning subdirectories that contain a ``cookies.sqlite``.

Forks (LibreWolf, Waterfox, Floorp, Zen, etc.) follow the same layout
under their own vendor directory. They are listed in ``_VENDORS``.

Safety
------

We only ever **read** through this module. The write path is in
``writers.firefox`` (not yet implemented). Even the read opens a private
**copy** of the SQLite file via the safety primitives, so we never hold
a lock on the live store and we cannot be tricked into reading through a
symlink to an unrelated file.
"""

from __future__ import annotations

import configparser
import logging
import sqlite3
import sys
import tempfile
from collections.abc import Iterator
from datetime import UTC, datetime
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


# (vendor_display_name, relative_path_under_home_per_platform)
_VENDORS: tuple[tuple[str, dict[str, str]], ...] = (
    (
        "Firefox",
        {
            "linux": ".mozilla/firefox",
            "darwin": "Library/Application Support/Firefox",
            "win32": "AppData/Roaming/Mozilla/Firefox",
        },
    ),
    (
        "LibreWolf",
        {
            "linux": ".librewolf",
            "darwin": "Library/Application Support/LibreWolf",
            "win32": "AppData/Roaming/LibreWolf",
        },
    ),
    (
        "Waterfox",
        {
            "linux": ".waterfox",
            "darwin": "Library/Application Support/Waterfox",
            "win32": "AppData/Roaming/Waterfox",
        },
    ),
    (
        "Floorp",
        {
            "linux": ".floorp",
            "darwin": "Library/Application Support/Floorp",
            "win32": "AppData/Roaming/Floorp",
        },
    ),
    (
        "Zen",
        {
            "linux": ".zen",
            "darwin": "Library/Application Support/zen",
            "win32": "AppData/Roaming/zen",
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


def discover_profiles() -> list[Profile]:
    """Find all Firefox-family profiles on this machine.

    Never raises for "directory missing" — that just means the vendor is
    not installed. Logs and skips on parse errors so one bad profiles.ini
    doesn't hide the others.
    """
    plat = _platform_key()
    found: list[Profile] = []
    for vendor, paths in _VENDORS:
        root_rel = paths.get(plat)
        if not root_rel:
            continue
        root = _home() / root_rel
        if not root.is_dir():
            continue
        found.extend(_discover_in_root(vendor, root))
    return found


def _discover_in_root(vendor: str, root: Path) -> Iterator[Profile]:
    running = is_running(BrowserKind.FIREFOX)
    ini = root / "profiles.ini"
    profile_dirs: list[tuple[str, Path]] = []

    if ini.is_file():
        try:
            cp = configparser.ConfigParser()
            cp.read(ini, encoding="utf-8")
            for section in cp.sections():
                if not section.lower().startswith("profile"):
                    continue
                name = cp.get(section, "Name", fallback=section)
                rel = cp.get(section, "Path", fallback=None)
                is_relative = cp.getboolean(section, "IsRelative", fallback=True)
                if not rel:
                    continue
                base = root if is_relative else Path("/")
                profile_dirs.append((name, base / rel))
        except (configparser.Error, ValueError) as exc:
            log.warning("Could not parse %s: %s", ini, exc)

    if not profile_dirs:
        # Fallback: any subdir that looks like a profile.
        for child in root.iterdir():
            if child.is_dir() and (child / "cookies.sqlite").is_file():
                profile_dirs.append((child.name, child))

    for name, pdir in profile_dirs:
        cookies = pdir / "cookies.sqlite"
        if not cookies.is_file():
            continue
        try:
            safe_fs.assert_regular_file_owned_by_us(cookies)
        except safe_fs.UnsafePathError as exc:
            log.warning("Skipping unsafe profile %s: %s", pdir, exc)
            continue
        yield Profile(
            browser=BrowserKind.FIREFOX,
            vendor=vendor,
            profile_name=name,
            cookies_db_path=cookies,
            is_running=running,
        )


# --- Reading -----------------------------------------------------------------


_SAME_SITE_MAP = {
    0: SameSite.NONE,
    1: SameSite.LAX,
    2: SameSite.STRICT,
}


def _expiry_from_seconds(expiry: int | None) -> datetime | None:
    if not expiry:
        return None
    try:
        return datetime.fromtimestamp(int(expiry), tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


def read_cookies(profile: Profile) -> list[Cookie]:
    """Read all cookies from a Firefox profile.

    Operates on a *copy* of ``cookies.sqlite`` placed in a private temp
    directory created via the safety primitives. The original file is
    never opened for writing through this path.
    """
    if profile.browser is not BrowserKind.FIREFOX:
        raise ValueError(f"read_cookies(firefox) called with {profile.browser}")

    src = profile.cookies_db_path
    safe_fs.assert_regular_file_owned_by_us(src)

    # Private temp dir mode 0700; deleted on exit.
    with tempfile.TemporaryDirectory(prefix="cj-fx-") as tmp:
        tmp_path = Path(tmp)
        # Make sure even the temp file is mode 0600 by creating empty first.
        copy_path = tmp_path / "cookies.sqlite"
        copy_path.touch(mode=0o600, exist_ok=False)
        safe_fs.safe_copy(src, copy_path)
        return list(_read_from_copy(copy_path))


def _read_from_copy(db_path: Path) -> Iterator[Cookie]:
    # ``immutable=1`` tells SQLite the file will not be modified during
    # this connection. We open read-only via a URI so concurrent writers
    # (which there should be none of — we operate on a copy) cannot trip us.
    uri = f"file:{db_path}?mode=ro&immutable=1"
    conn = sqlite3.connect(uri, uri=True, isolation_level=None)
    try:
        cur = conn.execute(
            """
            SELECT name, host, path, expiry, isSecure, isHttpOnly,
                   sameSite, value
              FROM moz_cookies
            """
        )
        for row in cur:
            name, host, path, expiry, secure, http_only, same_site, value = row
            value_bytes = value.encode("utf-8") if isinstance(value, str) else (value or b"")
            yield make_cookie(
                name=name,
                domain=host,
                path=path,
                expires=_expiry_from_seconds(expiry),
                secure=bool(secure),
                http_only=bool(http_only),
                same_site=_SAME_SITE_MAP.get(int(same_site or 0), SameSite.UNSPECIFIED),
                # Firefox stores host-only as a leading '.' absent.
                is_host_only=not str(host).startswith("."),
                value_bytes=value_bytes,
            )
    finally:
        conn.close()
