"""Safari writer — read-only placeholder.

Safari's ``Cookies.binarycookies`` format is rewritable in principle —
the structure is documented well enough that we could emit a new file
and atomic_replace it. The reason we don't ship that in this release:

* The format has a few semi-undocumented footer bytes (an 8-byte
  ``checksum``-shaped quantity after the last page) that some Safari
  builds appear to validate on load. Getting it wrong can silently lose
  cookies the next time Safari starts.
* Safari Sync stores some cookies in the iCloud Keychain and can
  resurrect deleted entries shortly after we delete them, which would
  surprise users in a way no test of ours could catch.
* The macOS sandbox treats writes to the Containers directory more
  strictly than reads. Even with Full Disk Access, writing requires
  the writing binary to be Apple-signed in some macOS versions.

Until those questions are answered with tests we'd rather a Safari
deletion explicitly fail with a clear message than silently truncate
the file. The GUI greys out the delete checkboxes for Safari rows so
the user doesn't reach this path through the normal flow.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from cookie_janitor.model.cookie import BrowserKind, Cookie, Profile

from .types import WriteResult


class SafariWriteNotSupported(NotImplementedError):
    """Raised when a caller asks us to delete Safari cookies.

    A subclass of NotImplementedError so callers that want to retry
    against other browsers can catch precisely this exception.
    """


def delete_cookies(
    profile: Profile,
    cookies_to_delete: Iterable[Cookie],
    *,
    dry_run: bool = True,
    backup_root: Path | None = None,
) -> WriteResult:
    if profile.browser is not BrowserKind.SAFARI:
        raise ValueError(f"delete_cookies(safari) called with {profile.browser}")
    identities = [c.identity for c in cookies_to_delete]
    if dry_run:
        # Dry-run lets the user see what *would* be deleted even though
        # we won't actually delete it. Same semantics as the other
        # writers; this is the only path that's safe to take.
        return WriteResult(
            profile=profile,
            requested_deletes=len(identities),
            actually_deleted=0,
            backup_path=None,
            dry_run=True,
            timestamp=datetime.now(tz=UTC),
        )
    raise SafariWriteNotSupported(
        "Cookie Janitor doesn't yet delete Safari cookies. The"
        " .binarycookies format is rewritable but we want a few more"
        " tests against real Safari builds before shipping a writer."
        " For now, use Safari's built-in 'Manage Website Data' (Safari"
        " → Settings → Privacy) to delete individual cookies, or"
        " choose Conservative/Audit-only mode."
    )


def restore_from_backup(profile: Profile, backup_path: Path) -> None:
    if profile.browser is not BrowserKind.SAFARI:
        raise ValueError(f"restore_from_backup(safari) called with {profile.browser}")
    raise SafariWriteNotSupported(
        "Cookie Janitor doesn't yet restore Safari cookie backups."
    )
