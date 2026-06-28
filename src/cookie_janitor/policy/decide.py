"""Turn a Cookie + classification data into a Decision with rationale.

Rule order — first to fire wins. This is the documented order from
``docs/ARCHITECTURE.md`` §4 and ``AGENTS.md`` D10 ("user keep-list wins
over every other rule").

The implementation is deliberately small and table-driven so it can be
read top-to-bottom by an auditor.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cookie_janitor.classify.cookie_db import CookieDatabase
from cookie_janitor.model.cookie import (
    Category,
    Cookie,
    Decision,
    Verdict,
)


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


def _matches_domain(cookie_domain: str, rule_domain: str) -> bool:
    """Match like a browser: exact, or rule is a suffix after a dot."""
    c = cookie_domain.lstrip(".").lower()
    r = rule_domain.lstrip(".").lower()
    if not r:
        return False
    return c == r or c.endswith("." + r)


def decide(
    cookie: Cookie,
    *,
    policy: UserPolicy,
    cookie_db: CookieDatabase | None,
) -> Decision:
    """Apply rules and return a Decision."""

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

    # 4. Open Cookie Database lookup.
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

    # 5. Session-cookie heuristic: no expiry, http-only, host-only ⇒ very
    # likely a login/CSRF cookie. Keep.
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

    # 6. Default: unknown → keep. False positives are worse than false
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
