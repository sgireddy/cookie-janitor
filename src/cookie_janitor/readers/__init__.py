"""Reader dispatcher.

Each browser family lives in its own module (``firefox``, ``chromium``,
``safari``). The dispatcher's only job is to ask each one for its
profiles and to route ``read_cookies(profile)`` to the right module
based on ``profile.browser``.

Callers (CLI, GUI) should depend on the dispatcher, never on a specific
reader module — that's what keeps the GUI's profile dropdown three
modules from now generic.

We deliberately don't use a registry / decorator pattern here. A small
tuple of modules is much easier to audit than dynamic registration, and
the cost (one ``if`` per browser added) is trivial.
"""

from __future__ import annotations

from cookie_janitor.model.cookie import BrowserKind, Cookie, Profile

from . import chromium, firefox, safari


def discover_all_profiles(only: BrowserKind | None = None) -> list[Profile]:
    """Find every browser profile on this machine.

    If ``only`` is given, restrict to that family. The CLI uses this to
    implement ``--browser`` filtering; the GUI passes ``None`` so the
    dropdown shows everything.

    Order: families in a stable display order, profiles within a family
    in the order the family's reader returned them. We don't sort
    alphabetically because Firefox's ``profiles.ini`` ordering is
    intentional (the user's default profile comes first).
    """
    out: list[Profile] = []
    if only is None or only is BrowserKind.FIREFOX:
        out.extend(firefox.discover_profiles())
    if only is None or only is BrowserKind.CHROMIUM:
        out.extend(chromium.discover_profiles())
    if only is None or only is BrowserKind.SAFARI:
        out.extend(safari.discover_profiles())
    return out


def read_cookies(profile: Profile) -> list[Cookie]:
    """Read cookies for one profile by dispatching to the right module.

    Raises ``ValueError`` for unknown browser kinds — adding a new
    family means adding both the branch here and a module under
    ``readers/``. mypy's exhaustive checking on the enum keeps this
    honest.
    """
    if profile.browser is BrowserKind.FIREFOX:
        return firefox.read_cookies(profile)
    if profile.browser is BrowserKind.CHROMIUM:
        return chromium.read_cookies(profile)
    if profile.browser is BrowserKind.SAFARI:
        return safari.read_cookies(profile)
    raise ValueError(f"unknown browser kind: {profile.browser}")


__all__ = ["chromium", "discover_all_profiles", "firefox", "read_cookies", "safari"]
