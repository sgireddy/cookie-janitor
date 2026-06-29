"""Browser-specific cookie writers + dispatcher.

Writers must satisfy three invariants:

1. Operate on a private copy of the cookie store, then atomically
   replace the original via the safety primitives in
   ``cookie_janitor.safety.fs``. Never write to the original directly.
2. Always produce a verified backup of the original before performing
   the swap. The backup path is reported in the result so the user (or
   the ``restore`` command) can roll back.
3. Refuse to operate while the target browser is running.

The shared ``WriteResult`` dataclass describes what happened in
machine-readable form, and is what the CLI / GUI surface.

The dispatcher (``delete_cookies`` / ``restore_from_backup`` at module
level) routes calls to the right per-family writer based on
``profile.browser``. Callers should depend on the dispatcher and let
this module pick the implementation.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from cookie_janitor.model.cookie import BrowserKind, Cookie, Profile

from . import chromium, firefox, safari
from .types import WriteResult


def delete_cookies(
    profile: Profile,
    cookies_to_delete: Iterable[Cookie],
    *,
    dry_run: bool = True,
    backup_root: Path | None = None,
) -> WriteResult:
    """Dispatch to the right writer for ``profile.browser``.

    The dispatcher is the single place callers go through — adding a
    new browser family means adding a branch here, a writer module,
    and a reader module. No registry magic.
    """
    if profile.browser is BrowserKind.FIREFOX:
        return firefox.delete_cookies(
            profile, cookies_to_delete, dry_run=dry_run, backup_root=backup_root
        )
    if profile.browser is BrowserKind.CHROMIUM:
        return chromium.delete_cookies(
            profile, cookies_to_delete, dry_run=dry_run, backup_root=backup_root
        )
    if profile.browser is BrowserKind.SAFARI:
        return safari.delete_cookies(
            profile, cookies_to_delete, dry_run=dry_run, backup_root=backup_root
        )
    raise ValueError(f"unknown browser kind: {profile.browser}")


def restore_from_backup(profile: Profile, backup_path: Path) -> None:
    if profile.browser is BrowserKind.FIREFOX:
        firefox.restore_from_backup(profile, backup_path)
        return
    if profile.browser is BrowserKind.CHROMIUM:
        chromium.restore_from_backup(profile, backup_path)
        return
    if profile.browser is BrowserKind.SAFARI:
        safari.restore_from_backup(profile, backup_path)
        return
    raise ValueError(f"unknown browser kind: {profile.browser}")


def supports_delete(browser: BrowserKind) -> bool:
    """Return ``True`` iff this build can delete cookies for the family.

    The GUI uses this to decide whether to enable the "Delete selected"
    button. It's preferable to checking ``browser is SAFARI`` at the
    call site because the surrounding plumbing already passes the
    ``BrowserKind`` around.
    """
    return browser in {BrowserKind.FIREFOX, BrowserKind.CHROMIUM}


__all__ = [
    "WriteResult",
    "chromium",
    "delete_cookies",
    "firefox",
    "restore_from_backup",
    "safari",
    "supports_delete",
]
