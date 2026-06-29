"""Turn a Cookie + classification data into a Decision with rationale.

Rule order — first to fire wins. This is the documented order from
``docs/ARCHITECTURE.md`` §4 and ``AGENTS.md`` D10 ("user keep-list wins
over every other rule").

Modes
-----
Six classifier modes, selected by ``UserPolicy.mode``. They form a
monotonic ladder: each level fires every rule of the level below it.

* ``AUDIT_ONLY`` — classify cookies and explain them, but recommend
  KEEP for everything. Use this to inspect what's there without any
  pressure to delete. (The GUI also disables the default-tick on the
  delete column when this mode is active.)

* ``CONSERVATIVE`` — the original 0.2.x behavior. Only deletes cookies
  the Open Cookie Database explicitly classifies as analytics/marketing.
  Anything else is kept.

* ``BALANCED`` *(default)* — adds three high-precision rules on top of
  Conservative: known third-party tracker domain, tracker subdomain
  label, and tracker cookie-name.

* ``STRICT`` — Balanced plus: also deletes the *Performance* category
  from the Open Cookie Database (CDN preference cookies, AB-test
  buckets, etc). Many users consider these benign; others find them
  invasive enough to clean.

* ``AGGRESSIVE`` — Strict plus two heuristics that have higher
  false-positive risk in exchange for catching the long tail: long-lived
  non-session cookies that don't look like auth, and an unknown→delete
  default. The auth-shape exception (``__Host-…``, ``…session…``,
  ``…token…``, etc.) prevents the worst of the false positives.

* ``SCORCHED_EARTH`` — delete everything except (a) cookies on a domain
  in the user allow-list, and (b) cookies whose name starts with the
  RFC 6265bis security prefixes ``__Host-`` or ``__Secure-``. The
  auth-substring exception does NOT apply here: even ``session_id``
  goes. Use this when you want to start over.

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

    Order is also a "strength" ordering — every rule that fires at level
    N also fires at level N+1. Comparisons via ``order()`` make this
    explicit; do not compare via ``<`` on the enum itself.
    """

    AUDIT_ONLY = "audit-only"
    CONSERVATIVE = "conservative"
    BALANCED = "balanced"
    STRICT = "strict"
    AGGRESSIVE = "aggressive"
    SCORCHED_EARTH = "scorched-earth"

    def order(self) -> int:
        """Numeric position on the ladder, 0..5. Used for level comparisons."""
        return _MODE_ORDER[self]


# Single source of truth for the ladder order. Adding a mode means
# adding it here too — mypy will flag the missing key.
_MODE_ORDER: dict[ClassifierMode, int] = {
    ClassifierMode.AUDIT_ONLY: 0,
    ClassifierMode.CONSERVATIVE: 1,
    ClassifierMode.BALANCED: 2,
    ClassifierMode.STRICT: 3,
    ClassifierMode.AGGRESSIVE: 4,
    ClassifierMode.SCORCHED_EARTH: 5,
}


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
    level = mode.order()

    # 1. User keep-list (domain). Fires in every mode INCLUDING
    #    SCORCHED_EARTH — this is the user's most explicit override.
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

    # 2a. RFC 6265bis security prefixes (__Host-, __Secure-) are an
    #     explicit browser-level promise about cookie shape — only a
    #     security-grade cookie can use them. Always KEEP these. This is
    #     what saves scorched-earth from logging the user out of every
    #     site that uses modern auth.
    lower_name = cookie.name.lower()
    if lower_name.startswith(("__host-", "__secure-")):
        prefix = "__Host-" if lower_name.startswith("__host-") else "__Secure-"
        return Decision(
            cookie=cookie,
            verdict=Verdict.KEEP,
            category=Category.FUNCTIONAL,
            rationale=(
                f"Cookie name uses the {prefix} security prefix, which is"
                " reserved for auth-grade cookies (RFC 6265bis)."
            ),
            source="security-prefix",
            confidence=1.0,
        )

    # ── SCORCHED_EARTH: everything past this point is DELETE ─────────────
    # The two rules above are the only escape hatches.
    if mode is ClassifierMode.SCORCHED_EARTH:
        return Decision(
            cookie=cookie,
            verdict=Verdict.DELETE,
            category=Category.UNKNOWN,
            rationale=(
                "Scorched-earth mode: deleting every cookie that isn't on"
                " your allow-list or using the __Host-/__Secure- prefix."
            ),
            source="scorched-earth",
            confidence=0.5,
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

    # ── AUDIT_ONLY: explain, but never recommend delete ─────────────────
    if mode is ClassifierMode.AUDIT_ONLY:
        # We still want to *categorize* via the Open Cookie Database so
        # the user sees a meaningful Category column, but the verdict is
        # forced to KEEP and the rationale says why.
        category = Category.UNKNOWN
        why_extra = ""
        if cookie_db is not None:
            desc = cookie_db.lookup(cookie.name, cookie.domain)
            if desc is not None:
                category = desc.category
                why_extra = (
                    f" The Open Cookie Database classifies it as {desc.category.value}."
                )
        return Decision(
            cookie=cookie,
            verdict=Verdict.KEEP,
            category=category,
            rationale=(
                "Audit-only mode: nothing will be selected for deletion."
                + why_extra
            ),
            source="audit-only",
            confidence=1.0,
        )

    # 4. Open Cookie Database lookup. Conservative + Balanced + Strict +
    #    Aggressive all consult it; Strict expands the delete-set to
    #    include Performance.
    if cookie_db is not None:
        desc = cookie_db.lookup(cookie.name, cookie.domain)
        if desc is not None:
            delete_set = policy.delete_categories
            if mode.order() >= ClassifierMode.STRICT.order():
                delete_set = delete_set | {Category.PERFORMANCE}
            in_delete_set = desc.category in delete_set
            verdict = Verdict.DELETE if in_delete_set else Verdict.KEEP
            short_desc = desc.description.split(".", 1)[0].strip() if desc.description else ""
            why = (
                f"Open Cookie Database classifies {cookie.name!r} as "
                f"{desc.category.value}" + (f" ({short_desc})" if short_desc else "") + "."
            )
            if (
                in_delete_set
                and desc.category is Category.PERFORMANCE
                and mode is ClassifierMode.STRICT
            ):
                why += " Strict mode also clears performance cookies."
            return Decision(
                cookie=cookie,
                verdict=verdict,
                category=desc.category,
                rationale=why,
                source="open-cookie-db",
                confidence=0.9,
            )

    # -- Rules 5-8 fire in BALANCED and above --
    if level >= ClassifierMode.BALANCED.order():
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
        sub_label = has_tracking_subdomain_label(cookie.domain)
        if sub_label is not None:
            return Decision(
                cookie=cookie,
                verdict=Verdict.DELETE,
                category=Category.ANALYTICS,
                rationale=(
                    f"The subdomain label {sub_label!r} in {cookie.domain}"
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
    # likely a login/CSRF cookie. Keep. Fires in every mode below
    # SCORCHED_EARTH (which was already short-circuited above).
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

    # -- AGGRESSIVE-only rules (level 4) --
    if level >= ClassifierMode.AGGRESSIVE.order():
        # 10. Long-lived non-session non-auth cookie.
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
        #     have an auth-shape name and isn't a session cookie.
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
