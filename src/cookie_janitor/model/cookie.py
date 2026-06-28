"""Domain model for cookies and the decisions we make about them.

The cookie *value* is intentionally NOT stored on the ``Cookie`` dataclass.
Values are bearer credentials. They are loaded only at write time, into a
short-lived buffer that is overwritten after use, and they never cross
the JSON-RPC boundary to the GUI. What the GUI sees and what we log is a
short SHA-256 prefix and the value's length.
"""

from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


class BrowserKind(enum.StrEnum):
    """The browser families we know how to read.

    Forks share storage formats, so we key on the family, not the vendor.
    """

    CHROMIUM = "chromium"
    FIREFOX = "firefox"
    SAFARI = "safari"


class SameSite(enum.StrEnum):
    STRICT = "strict"
    LAX = "lax"
    NONE = "none"
    UNSPECIFIED = "unspecified"


class Category(enum.StrEnum):
    """Cookie categories used by the Open Cookie Database and the IAB TCF.

    ``UNKNOWN`` is its own category and is treated as KEEP by default
    (false-positive aversion — see THREAT_MODEL TH-7).
    """

    FUNCTIONAL = "functional"
    PERFORMANCE = "performance"
    ANALYTICS = "analytics"
    MARKETING = "marketing"
    UNKNOWN = "unknown"


class Verdict(enum.StrEnum):
    KEEP = "keep"
    DELETE = "delete"


@dataclass(frozen=True, slots=True)
class Cookie:
    """A single cookie, as it currently exists in a browser's store.

    Identity is ``(domain, path, name)``: that's what the browser's
    storage layer treats as the primary key.
    """

    name: str
    domain: str
    path: str
    expires: datetime | None
    secure: bool
    http_only: bool
    same_site: SameSite
    is_session: bool  # True iff ``expires is None`` per RFC 6265 §5.3
    is_host_only: bool  # True iff domain attribute was absent (host-only)
    value_length: int
    value_sha256_prefix: str  # first 8 lowercase hex chars; for logs only

    @property
    def identity(self) -> tuple[str, str, str]:
        return (self.domain, self.path, self.name)


def make_cookie(
    *,
    name: str,
    domain: str,
    path: str,
    expires: datetime | None,
    secure: bool,
    http_only: bool,
    same_site: SameSite,
    is_host_only: bool,
    value_bytes: bytes,
) -> Cookie:
    """Construct a Cookie, computing the value-fingerprint and immediately
    forgetting the raw value (the local ``value_bytes`` goes out of scope).
    """
    digest = hashlib.sha256(value_bytes).hexdigest()[:8]
    return Cookie(
        name=name,
        domain=domain,
        path=path,
        expires=expires,
        secure=secure,
        http_only=http_only,
        same_site=same_site,
        is_session=expires is None,
        is_host_only=is_host_only,
        value_length=len(value_bytes),
        value_sha256_prefix=digest,
    )


@dataclass(frozen=True, slots=True)
class Profile:
    """One browser profile on disk."""

    browser: BrowserKind
    vendor: str  # human-readable: "Firefox", "Google Chrome", "Brave"
    profile_name: str  # e.g. "default-release", "Default", "Profile 1"
    cookies_db_path: Path
    is_running: bool

    @property
    def display(self) -> str:
        return f"{self.vendor} — {self.profile_name}"


@dataclass(frozen=True, slots=True)
class Decision:
    """The policy's verdict on a single cookie, with a human-readable rationale.

    ``source`` names the rule that fired (e.g. ``"user-keep-list"``,
    ``"open-cookie-db"``, ``"easyprivacy"``, ``"heuristic-session"``,
    ``"default-keep-unknown"``). The rationale is shown verbatim in the GUI.
    """

    cookie: Cookie
    verdict: Verdict
    category: Category
    rationale: str
    source: str
    confidence: float  # 0.0 .. 1.0, used only for sorting / UI shading

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence out of range: {self.confidence!r}")


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Output of a scan over one profile."""

    profile: Profile
    decisions: tuple[Decision, ...] = field(default_factory=tuple)

    @property
    def counts_by_verdict(self) -> dict[Verdict, int]:
        out = {Verdict.KEEP: 0, Verdict.DELETE: 0}
        for d in self.decisions:
            out[d.verdict] += 1
        return out
