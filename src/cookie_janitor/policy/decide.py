"""Turn a Cookie + classification data into a Decision with rationale.

Rule order — first to fire wins. This is the documented order from
``docs/ARCHITECTURE.md`` §4 and ``AGENTS.md`` D10 ("user keep-list wins
over every other rule").

Modes
-----
Three classifier modes, selected by ``UserPolicy.mode``:

* ``CONSERVATIVE`` — the original 0.2.x behavior. Only deletes cookies
  the Open Cookie Database explicitly classifies as analytics/marketing.
  Anything else is kept. Recommended for users who'd rather click
  "delete" manually than risk a logout.

* ``BALANCED`` *(default)* — adds three high-precision rules on top of
  Conservative: known third-party tracker domain, tracker subdomain
  label, and tracker cookie-name. Designed to clear obvious junk without
  touching anything that could plausibly be a session.

* ``AGGRESSIVE`` — Balanced plus two heuristics that have higher
  false-positive risk in exchange for catching the long tail: long-lived
  non-session cookies that don't look like auth, and an unknown→delete
  default. The auth-shape exception (``__Host-…``, ``…session…``,
  ``…token…``, etc.) prevents the worst of the false positives.

Auditors: every rule below has both an integer "priority" (so the order
is grep-able from the code) and a single ``Decision`` construction site.
There is no clever recursion or branching across files.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from cookie_janitor.classify.cookie_db import CookieDatabase
from cookie_janitor.classify.trackers import (
    has_auth_shape,
    has_tracker_name_substring,
    has_tracking_subdomain_label,
    is_tracker_cookie_name,
    is_tracker_domain,
)
from cookie_janitor.model.cookie import (
    Category,
    Cookie,
    Decision,
    Verdict,
)


class ClassifierMode(enum.StrEnum):
    """How aggressive the classifier should be.

    Order is also a "strength" ordering — every rule that fires in
    ``CONSERVATIVE`` also fires in ``BALANCED`` and ``AGGRESSIVE``.
    """

    CONSERVATIVE = "conservative"
    BALANCED = "balanced"
    AGGRESSIVE = "aggressive"


# Long-lived = "expires more than this far in the future". Aggressive
# mode treats a cookie with no session/HTTP-only/auth-name signal AND a
# multi-month lifetime as a marketing/tracking cookie. Six months is the
# usual industry threshold (it's also the IAB TCF v2 standard).
_LONG_LIVED_THRESHOLD = timedelta(days=180)


@dataclass(frozen=True, slots=True)
class UserPolicy:
    """User-defined rules. Always consulted first."""

    keep_domains: frozenset[str] = field(default_factory=frozenset)
    keep_cookie_names: frozenset[str] = field(default_factory=frozenset)
    delete_domains: frozenset[str] = field(default_factory=frozenset)
    # Per-category preference: by default we delete Analytics and Marketing,
    # keep Functional/Performance/Unknown.
    delete_categories: frozenset[Category] = field(
        default_factory=lambda: frozenset({Category.ANALYTICS, Category.MARKETING})
    )
    mode: ClassifierMode = ClassifierMode.BALANCED


def _matches_domain(cookie_domain: str, rule_domain: str) -> bool:
    """Match like a browser: exact, or rule is a suffix after a dot."""
    c = cookie_domain.lstrip(".").lower()
    r = rule_domain.lstrip(".").lower()
    if not r:
        return False
    return c == r or c.endswith("." + r)


def _is_long_lived(cookie: Cookie, *, now: datetime | None = None) -> bool:
    """Return True iff the cookie's expiry is more than 6 months out.

    Session cookies (``expires is None``) are explicitly NOT long-lived
    — they die when the browser quits.
    """
    if cookie.expires is None:
        return False
    reference = now or datetime.now(tz=UTC)
    # Some browsers store far-past expiries for tombstoned rows; those
    # are effectively dead. Treat them as not long-lived (they'll be
    # cleaned up by the browser anyway).
    return (cookie.expires - reference) > _LONG_LIVED_THRESHOLD


def decide(
    cookie: Cookie,
    *,
    policy: UserPolicy,
    cookie_db: CookieDatabase | None,
    now: datetime | None = None,
) -> Decision:
    """Apply rules and return a Decision.

    ``now`` is injectable so tests can pin time for the long-lived rule.
    """

    mode = policy.mode

    # 1. User keep-list (domain).
    for rule in policy.keep_domains:
        if _matches_domain(cookie.domain, rule):
            return Decision(
                cookie=cookie,
                verdict=Verdict.KEEP,
                category=Category.UNKNOWN,
                rationale=f"You asked us to always keep cookies on {rule}.",
                source="user-keep-list:domain",
                confidence=1.0,
            )

    # 2. User keep-list (cookie name).
    if cookie.name in policy.keep_cookie_names:
        return Decision(
            cookie=cookie,
            verdict=Verdict.KEEP,
            category=Category.UNKNOWN,
            rationale=f"You asked us to always keep the cookie named {cookie.name!r}.",
            source="user-keep-list:name",
            confidence=1.0,
        )

    # 3. User delete-list (domain).
    for rule in policy.delete_domains:
        if _matches_domain(cookie.domain, rule):
            return Decision(
                cookie=cookie,
                verdict=Verdict.DELETE,
                category=Category.UNKNOWN,
                rationale=f"You asked us to always delete cookies on {rule}.",
                source="user-delete-list:domain",
                confidence=1.0,
            )

    # 4. Open Cookie Database lookup. Same in every mode.
    if cookie_db is not None:
        desc = cookie_db.lookup(cookie.name, cookie.domain)
        if desc is not None:
            in_delete_set = desc.category in policy.delete_categories
            verdict = Verdict.DELETE if in_delete_set else Verdict.KEEP
            short_desc = desc.description.split(".", 1)[0].strip() if desc.description else ""
            why = (
                f"Open Cookie Database classifies {cookie.name!r} as "
                f"{desc.category.value}" + (f" ({short_desc})" if short_desc else "") + "."
            )
            return Decision(
                cookie=cookie,
                verdict=verdict,
                category=desc.category,
                rationale=why,
                source="open-cookie-db",
                confidence=0.9,
            )

    # -- Rules 5-8 fire only in BALANCED and AGGRESSIVE --
    if mode is not ClassifierMode.CONSERVATIVE:
        # 5. Known third-party tracker domain.
        tracker = is_tracker_domain(cookie.domain)
        if tracker is not None:
            return Decision(
                cookie=cookie,
                verdict=Verdict.DELETE,
                category=Category.MARKETING,
                rationale=(
                    f"{tracker} is a known third-party tracking / advertising"
                    " domain — there is no first-party site to log into here."
                ),
                source="tracker-domain",
                confidence=0.95,
            )

        # 6. Tracking subdomain label (tracking.foo.com, analytics.bar.io, …).
        label = has_tracking_subdomain_label(cookie.domain)
        if label is not None:
            return Decision(
                cookie=cookie,
                verdict=Verdict.DELETE,
                category=Category.ANALYTICS,
                rationale=(
                    f"The subdomain label {label!r} in {cookie.domain}"
                    " strongly indicates a tracking / analytics endpoint."
                ),
                source="tracker-subdomain-label",
                confidence=0.9,
            )

        # 7 + 8. Tracker cookie name. Both exact-match (curated list) and
        # substring (e.g. anything containing "visid_incap_"). Auth-shape
        # names are exempted to protect real session cookies.
        auth_hint = has_auth_shape(cookie.name)

        if is_tracker_cookie_name(cookie.name) and auth_hint is None:
            return Decision(
                cookie=cookie,
                verdict=Verdict.DELETE,
                category=Category.MARKETING,
                rationale=(
                    f"{cookie.name!r} is a well-known tracking-cookie name"
                    " used across many sites for cross-site identification."
                ),
                source="tracker-cookie-name",
                confidence=0.95,
            )

        substring = has_tracker_name_substring(cookie.name)
        if substring is not None and auth_hint is None:
            return Decision(
                cookie=cookie,
                verdict=Verdict.DELETE,
                category=Category.ANALYTICS,
                rationale=(
                    f"The cookie name contains {substring!r}, which is a"
                    " standard tracking-cookie naming convention."
                ),
                source="tracker-name-substring",
                confidence=0.85,
            )

    # 9. Session-cookie heuristic: no expiry, http-only, host-only ⇒ very
    # likely a login/CSRF cookie. Keep. Fires in every mode.
    if cookie.is_session and cookie.http_only and cookie.is_host_only:
        return Decision(
            cookie=cookie,
            verdict=Verdict.KEEP,
            category=Category.FUNCTIONAL,
            rationale=(
                "Session cookie (no expiry), HTTP-only and host-only. "
                "This shape is overwhelmingly used for login sessions."
            ),
            source="heuristic-session",
            confidence=0.7,
        )

    # -- AGGRESSIVE-only rules --
    if mode is ClassifierMode.AGGRESSIVE:
        # 10. Long-lived non-session non-auth cookie. The combination of
        #     "no session shape", "no auth-looking name", and "lives for
        #     many months" is overwhelmingly marketing/analytics.
        if (
            _is_long_lived(cookie, now=now)
            and not cookie.http_only
            and has_auth_shape(cookie.name) is None
        ):
            return Decision(
                cookie=cookie,
                verdict=Verdict.DELETE,
                category=Category.MARKETING,
                rationale=(
                    "Aggressive mode: long-lived (>6 months), not HTTP-only,"
                    " and the name doesn't look like a login token —"
                    " almost certainly a tracking / preferences cookie."
                ),
                source="aggressive-long-lived",
                confidence=0.7,
            )

        # 11. Unknown → DELETE in aggressive mode, but only if it doesn't
        #     have an auth-shape name and isn't a session cookie. We're
        #     biased toward keeping anything that could plausibly be a
        #     login even in aggressive mode.
        if has_auth_shape(cookie.name) is None and not cookie.is_session:
            return Decision(
                cookie=cookie,
                verdict=Verdict.DELETE,
                category=Category.UNKNOWN,
                rationale=(
                    "Aggressive mode: we couldn't identify this cookie and"
                    " its shape doesn't look like a login session, so it's"
                    " marked for deletion. If this logs you out of a site,"
                    " add the site to your allow-list."
                ),
                source="aggressive-unknown",
                confidence=0.4,
            )

    # 12. Default: unknown → keep. False positives are worse than false
    # negatives in this tool (THREAT_MODEL TH-7).
    return Decision(
        cookie=cookie,
        verdict=Verdict.KEEP,
        category=Category.UNKNOWN,
        rationale=(
            "We couldn't identify this cookie. Kept by default — you can "
            "always delete it manually if you recognize it as a tracker."
        ),
        source="default-keep-unknown",
        confidence=0.3,
    )
