"""Persisted user allow-list of domains that should *always* be kept.

The allow-list lives in a plain UTF-8 text file in the OS-appropriate
config directory:

* macOS:  ``~/Library/Application Support/Cookie Janitor/allowlist.txt``
* Linux:  ``$XDG_CONFIG_HOME/cookie-janitor/allowlist.txt``
          (defaults to ``~/.config/cookie-janitor/allowlist.txt``)
* Windows: ``%APPDATA%\\Cookie Janitor\\allowlist.txt``

The format is one domain per line. ``#`` starts a comment. Whitespace
and blank lines are ignored. We accept either ``example.com`` or
``.example.com`` and normalise both to the bare hostname.

Why a plain text file rather than JSON / SQLite / a settings store?
This list is user-edited, often inspected with ``cat``, and *must* be
trivially auditable. A 20-line text file beats a binary blob.
"""

from __future__ import annotations

import contextlib
import logging
import os
import sys
import tempfile
from pathlib import Path

log = logging.getLogger(__name__)


_DEFAULT_HEADER = """\
# Cookie Janitor — user allow-list.
#
# One domain per line. Cookies set on these domains (and their subdomains)
# will always be KEPT, regardless of the classifier's verdict. Use this for
# sites you actively log into and don't want to re-authenticate against.
#
# Examples:
#   accounts.google.com
#   github.com
#   bank.example.com
#
# Lines starting with '#' are comments. Edit by hand or via the GUI
# (File → Allow list…).
"""


def allowlist_path() -> Path:
    """Return the OS-appropriate path to the allow-list file.

    The directory is *not* created here. Use :func:`load_allowlist` /
    :func:`save_allowlist`, which create-on-demand.
    """
    if sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support" / "Cookie Janitor"
    elif sys.platform.startswith("win"):
        appdata = os.environ.get("APPDATA")
        base = Path(appdata) / "Cookie Janitor" if appdata else Path.home() / "Cookie Janitor"
    else:
        xdg = os.environ.get("XDG_CONFIG_HOME")
        base = Path(xdg) / "cookie-janitor" if xdg else Path.home() / ".config" / "cookie-janitor"
    return base / "allowlist.txt"


def _normalise(domain: str) -> str | None:
    """Return a clean, lowercase, dot-less hostname or ``None`` if invalid.

    Anything that isn't a sensible hostname (whitespace inside, scheme,
    path, etc.) returns ``None`` and is silently dropped at load time.
    The caller is responsible for surfacing input errors in the GUI when
    *adding* a domain interactively.
    """
    s = domain.strip().lstrip(".").lower()
    if not s:
        return None
    # Reject anything that obviously isn't a hostname. We don't want to
    # save "https://foo.com/path" or "user@host" by accident.
    if any(c in s for c in (" ", "\t", "/", ":", "@", "?", "#")):
        return None
    # A bare TLD is allowed (".local" → "local") but multi-dot hosts
    # are the common case. Either is structurally valid.
    return s


def load_allowlist(path: Path | None = None) -> frozenset[str]:
    """Read the allow-list file and return the set of normalised hosts.

    Returns an empty set if the file does not exist. Malformed lines are
    logged at DEBUG level and skipped — never raise: a corrupt config
    file must not crash the app.
    """
    p = path or allowlist_path()
    if not p.exists():
        return frozenset()
    out: set[str] = set()
    try:
        raw = p.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("Could not read allow-list at %s: %s", p, exc)
        return frozenset()
    for lineno, line in enumerate(raw.splitlines(), start=1):
        stripped = line.split("#", 1)[0].strip()
        if not stripped:
            continue
        clean = _normalise(stripped)
        if clean is None:
            log.debug("Ignoring malformed allow-list entry at %s:%d: %r", p, lineno, line)
            continue
        out.add(clean)
    return frozenset(out)


def save_allowlist(domains: frozenset[str] | set[str], path: Path | None = None) -> Path:
    """Write the allow-list atomically. Returns the path written.

    Always writes the header comment first, then one domain per line in
    sorted order. Uses a tempfile + ``os.replace`` so a crash mid-write
    can never leave a half-written allow-list.
    """
    p = path or allowlist_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    cleaned = sorted({d for d in (_normalise(x) for x in domains) if d is not None})
    payload = _DEFAULT_HEADER + "\n".join(cleaned) + ("\n" if cleaned else "")
    # Atomic write: tmp file in the same directory, then rename.
    fd, tmp_name = tempfile.mkstemp(prefix=".allowlist.", dir=str(p.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload)
        tmp_path.replace(p)
    except OSError:
        # Best-effort cleanup. If replace failed the tmp is still around.
        with contextlib.suppress(OSError):
            tmp_path.unlink()
        raise
    return p


def add_to_allowlist(domain: str, path: Path | None = None) -> frozenset[str]:
    """Append ``domain`` to the allow-list and return the new set.

    Raises ``ValueError`` if ``domain`` is not a valid hostname — caller
    should show this in the GUI rather than silently ignoring it.
    """
    clean = _normalise(domain)
    if clean is None:
        raise ValueError(f"{domain!r} is not a valid hostname.")
    current = set(load_allowlist(path))
    current.add(clean)
    save_allowlist(frozenset(current), path)
    return frozenset(current)


def remove_from_allowlist(domain: str, path: Path | None = None) -> frozenset[str]:
    """Remove ``domain`` from the allow-list and return the new set.

    Silently no-ops if the domain isn't there.
    """
    clean = _normalise(domain)
    if clean is None:
        return load_allowlist(path)
    current = set(load_allowlist(path))
    current.discard(clean)
    save_allowlist(frozenset(current), path)
    return frozenset(current)
