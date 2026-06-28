"""Detect whether a given browser is currently running.

We refuse to operate on a profile whose browser is live (see THREAT_MODEL
TH-3 and SECURITY.md hardening guarantee #6). Sqlite WAL is no help here:
writes to a live cookie store can corrupt the browser's in-memory cache
and lose unrelated cookies.

The process names are family-grouped. We match on the executable's
*basename* (case-insensitive on Windows) to avoid being fooled by spoofed
``argv[0]``.
"""

from __future__ import annotations

import sys
from collections.abc import Iterable

import psutil

from cookie_janitor.model.cookie import BrowserKind

# Names are lowercase; Windows comparison normalizes.
_PROCESS_NAMES: dict[BrowserKind, frozenset[str]] = {
    BrowserKind.CHROMIUM: frozenset(
        {
            "chrome",
            "chrome.exe",
            "google chrome",
            "google chrome helper",
            "chromium",
            "chromium-browser",
            "chromium.exe",
            "msedge",
            "msedge.exe",
            "microsoft edge",
            "brave",
            "brave-browser",
            "brave.exe",
            "opera",
            "opera.exe",
            "vivaldi",
            "vivaldi-bin",
            "vivaldi.exe",
            "arc",
            "arc.exe",
        }
    ),
    BrowserKind.FIREFOX: frozenset(
        {
            "firefox",
            "firefox-bin",
            "firefox.exe",
            "librewolf",
            "librewolf.exe",
            "waterfox",
            "waterfox.exe",
            "floorp",
            "floorp.exe",
            "zen",
            "zen.exe",
            "zen-bin",
        }
    ),
    BrowserKind.SAFARI: frozenset({"safari"}),
}


def _norm(name: str | None) -> str:
    if not name:
        return ""
    return name.strip().lower()


def running_browsers() -> set[BrowserKind]:
    """Return the set of browser families that currently have a running process."""
    seen: set[BrowserKind] = set()
    targets = dict(_PROCESS_NAMES)
    for proc in psutil.process_iter(["name"]):
        try:
            n = _norm(proc.info.get("name"))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        if not n:
            continue
        for kind, names in targets.items():
            if n in names:
                seen.add(kind)
                break
    # On macOS Safari is bundled and shows as "Safari".
    if sys.platform != "darwin":
        seen.discard(BrowserKind.SAFARI)
    return seen


def is_running(kind: BrowserKind) -> bool:
    return kind in running_browsers()


def assert_not_running(kinds: Iterable[BrowserKind]) -> None:
    """Raise if any of the given browser families is currently running."""
    live = running_browsers() & set(kinds)
    if live:
        names = ", ".join(sorted(k.value for k in live))
        raise BrowserRunningError(
            f"Refusing to operate while these browsers are running: {names}. "
            f"Please close them fully (including background tasks) and try again."
        )


class BrowserRunningError(RuntimeError):
    """A target browser is running and we will not touch its cookie store."""
