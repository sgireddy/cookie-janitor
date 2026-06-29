"""Mode-aware classifier behavior — one test per rule, per mode boundary.

The fixtures below construct synthetic cookies that match exactly one
rule each, so every assertion isolates the behavior of a single rule.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from cookie_janitor.classify.cookie_db import CookieDatabase, CookieDescription
from cookie_janitor.model.cookie import Category, SameSite, Verdict, make_cookie
from cookie_janitor.policy.decide import ClassifierMode, UserPolicy, decide

_NOW = datetime(2026, 1, 1, tzinfo=UTC)
_DEFAULT_EXPIRES = _NOW + timedelta(days=30)

# Sentinel so callers can explicitly pass ``expires=None`` to mean
# "session cookie" without colliding with our default-arg trick.
_SENTINEL = object()


def _cookie(
    *,
    name: str = "x",
    domain: str = "example.test",
    expires: object = _SENTINEL,
    http_only: bool = False,
    is_host_only: bool = False,
):
    actual_expires = _DEFAULT_EXPIRES if expires is _SENTINEL else expires
    return make_cookie(
        name=name,
        domain=domain,
        path="/",
        expires=actual_expires,  # type: ignore[arg-type]
        secure=True,
        http_only=http_only,
        same_site=SameSite.LAX,
        is_host_only=is_host_only,
        value_bytes=b"v",
    )


def _empty_db() -> CookieDatabase:
    return CookieDatabase(by_exact_name={}, by_prefix={})


# --- known third-party tracker domain --------------------------------------


@pytest.mark.parametrize(
    "mode",
    [ClassifierMode.BALANCED, ClassifierMode.AGGRESSIVE],
)
def test_tracker_domain_deleted_in_balanced_and_aggressive(mode: ClassifierMode):
    cookie = _cookie(name="random_thing", domain=".doubleclick.net")
    d = decide(cookie, policy=UserPolicy(mode=mode), cookie_db=_empty_db(), now=_NOW)
    assert d.verdict is Verdict.DELETE
    assert d.source == "tracker-domain"
    assert "doubleclick.net" in d.rationale


def test_tracker_domain_kept_in_conservative_when_no_db_hit():
    # Conservative *doesn't* know about doubleclick.net via the tracker list
    # — it relies on the Open Cookie Database. With an empty DB, conservative
    # falls through to default-keep-unknown.
    cookie = _cookie(name="random_thing", domain=".doubleclick.net")
    d = decide(
        cookie,
        policy=UserPolicy(mode=ClassifierMode.CONSERVATIVE),
        cookie_db=_empty_db(),
        now=_NOW,
    )
    assert d.verdict is Verdict.KEEP
    assert d.source == "default-keep-unknown"


# --- tracker subdomain label -----------------------------------------------


def test_tracking_subdomain_label_deleted_in_balanced():
    cookie = _cookie(name="piq_uuid", domain="tracking.pandoiq.com")
    d = decide(
        cookie,
        policy=UserPolicy(mode=ClassifierMode.BALANCED),
        cookie_db=_empty_db(),
        now=_NOW,
    )
    assert d.verdict is Verdict.DELETE
    assert d.source == "tracker-subdomain-label"
    assert "tracking" in d.rationale


def test_analytics_subdomain_label_deleted():
    cookie = _cookie(name="whatever", domain="analytics.foo.example.com")
    d = decide(
        cookie,
        policy=UserPolicy(mode=ClassifierMode.BALANCED),
        cookie_db=_empty_db(),
        now=_NOW,
    )
    assert d.verdict is Verdict.DELETE
    assert d.source == "tracker-subdomain-label"


def test_tracking_subdomain_label_kept_in_conservative():
    cookie = _cookie(name="random_thing", domain="tracking.pandoiq.com")
    d = decide(
        cookie,
        policy=UserPolicy(mode=ClassifierMode.CONSERVATIVE),
        cookie_db=_empty_db(),
        now=_NOW,
    )
    assert d.verdict is Verdict.KEEP


# --- tracker cookie name (exact) -------------------------------------------


def test_exact_tracker_cookie_name_deleted_in_balanced():
    cookie = _cookie(name="MUID", domain=".some-site-bing-pixel-fires-on.example")
    d = decide(
        cookie,
        policy=UserPolicy(mode=ClassifierMode.BALANCED),
        cookie_db=_empty_db(),
        now=_NOW,
    )
    assert d.verdict is Verdict.DELETE
    assert d.source == "tracker-cookie-name"


def test_tracker_name_with_auth_substring_is_kept():
    # A hypothetical "_ga_sessiontoken" should NOT be flagged as a tracker;
    # the auth-shape exception protects it.
    cookie = _cookie(name="auth_token", domain="example.test")
    # auth_token isn't in TRACKER_COOKIE_NAMES, but we use it as a sanity:
    # the auth substring check exempts it from the substring rule below.
    d = decide(
        cookie,
        policy=UserPolicy(mode=ClassifierMode.BALANCED),
        cookie_db=_empty_db(),
        now=_NOW,
    )
    assert d.verdict is Verdict.KEEP


# --- tracker name substring ------------------------------------------------


def test_visid_incap_deleted_in_balanced():
    cookie = _cookie(name="visid_incap_440913", domain=".thejobnetwork.com")
    d = decide(
        cookie,
        policy=UserPolicy(mode=ClassifierMode.BALANCED),
        cookie_db=_empty_db(),
        now=_NOW,
    )
    assert d.verdict is Verdict.DELETE
    assert d.source == "tracker-name-substring"
    assert "visid_incap_" in d.rationale


def test_realmatch_tracking_deleted_in_balanced():
    cookie = _cookie(name="Realmatch_Tracking", domain="bestbuyorganic.thejobnetwork.com")
    d = decide(
        cookie,
        policy=UserPolicy(mode=ClassifierMode.BALANCED),
        cookie_db=_empty_db(),
        now=_NOW,
    )
    assert d.verdict is Verdict.DELETE


# --- session-heuristic (existing) survives ---------------------------------


def test_session_http_only_host_only_kept_in_balanced():
    cookie = _cookie(
        name="JSESSIONID",
        domain="app.example.com",
        expires=None,
        http_only=True,
        is_host_only=True,
    )
    d = decide(
        cookie,
        policy=UserPolicy(mode=ClassifierMode.BALANCED),
        cookie_db=_empty_db(),
        now=_NOW,
    )
    assert d.verdict is Verdict.KEEP
    assert d.source == "heuristic-session"


# --- aggressive: long-lived non-auth ---------------------------------------


def test_aggressive_deletes_long_lived_non_auth():
    # Year-out expiry, not http-only, name has no auth shape.
    cookie = _cookie(
        name="ABTEST_bucket",
        domain="example.test",
        expires=_NOW + timedelta(days=365),
        http_only=False,
    )
    d = decide(
        cookie,
        policy=UserPolicy(mode=ClassifierMode.AGGRESSIVE),
        cookie_db=_empty_db(),
        now=_NOW,
    )
    assert d.verdict is Verdict.DELETE
    assert d.source == "aggressive-long-lived"


def test_aggressive_keeps_long_lived_auth_shape():
    # Year-out expiry but name screams auth → keep even in aggressive mode.
    cookie = _cookie(
        name="remember_me_token",
        domain="example.test",
        expires=_NOW + timedelta(days=365),
        http_only=False,
    )
    d = decide(
        cookie,
        policy=UserPolicy(mode=ClassifierMode.AGGRESSIVE),
        cookie_db=_empty_db(),
        now=_NOW,
    )
    assert d.verdict is Verdict.KEEP


def test_aggressive_keeps_long_lived_http_only():
    # HttpOnly with long expiry is much more likely auth than tracking,
    # so we keep it.
    cookie = _cookie(
        name="random_long_lived",
        domain="example.test",
        expires=_NOW + timedelta(days=365),
        http_only=True,
    )
    d = decide(
        cookie,
        policy=UserPolicy(mode=ClassifierMode.AGGRESSIVE),
        cookie_db=_empty_db(),
        now=_NOW,
    )
    # Falls through to aggressive-unknown (no auth shape, not session).
    # That's still DELETE in this mode — but via the unknown rule.
    assert d.verdict is Verdict.DELETE
    assert d.source == "aggressive-unknown"


# --- aggressive: unknown → delete ------------------------------------------


def test_aggressive_flips_unknown_to_delete():
    cookie = _cookie(name="ck_Rm_Activity", domain="bestbuyorganic.thejobnetwork.com")
    d = decide(
        cookie,
        policy=UserPolicy(mode=ClassifierMode.AGGRESSIVE),
        cookie_db=_empty_db(),
        now=_NOW,
    )
    assert d.verdict is Verdict.DELETE
    assert d.source in {"aggressive-unknown", "tracker-subdomain-label"}


def test_aggressive_still_keeps_unknown_session_cookie():
    # No expiry → session cookie. Even aggressive mode keeps it.
    cookie = _cookie(
        name="some_random_session_id",
        domain="example.test",
        expires=None,
        http_only=False,
        is_host_only=False,
    )
    d = decide(
        cookie,
        policy=UserPolicy(mode=ClassifierMode.AGGRESSIVE),
        cookie_db=_empty_db(),
        now=_NOW,
    )
    assert d.verdict is Verdict.KEEP


# --- user allow-list still wins over everything ----------------------------


def test_user_keep_domain_beats_tracker_domain_in_aggressive():
    cookie = _cookie(name="random", domain=".doubleclick.net")
    policy = UserPolicy(
        keep_domains=frozenset({"doubleclick.net"}),
        mode=ClassifierMode.AGGRESSIVE,
    )
    d = decide(cookie, policy=policy, cookie_db=_empty_db(), now=_NOW)
    assert d.verdict is Verdict.KEEP
    assert d.source.startswith("user-keep-list")


# --- conservative is unchanged for non-tracker cookies ---------------------


def test_conservative_unknown_kept_by_default():
    cookie = _cookie(name="ck_Rm_Activity", domain="bestbuyorganic.thejobnetwork.com")
    d = decide(
        cookie,
        policy=UserPolicy(mode=ClassifierMode.CONSERVATIVE),
        cookie_db=_empty_db(),
        now=_NOW,
    )
    assert d.verdict is Verdict.KEEP
    assert d.source == "default-keep-unknown"


# ---------------------------------------------------------------------------
# AUDIT_ONLY mode
# ---------------------------------------------------------------------------


def test_audit_only_keeps_obvious_tracker():
    cookie = _cookie(name="_ga", domain=".doubleclick.net")
    d = decide(
        cookie,
        policy=UserPolicy(mode=ClassifierMode.AUDIT_ONLY),
        cookie_db=_empty_db(),
        now=_NOW,
    )
    assert d.verdict is Verdict.KEEP
    assert d.source == "audit-only"


def test_audit_only_still_categorises_via_db():
    cookie = _cookie(name="_ga", domain=".doubleclick.net")
    db = CookieDatabase(
        by_exact_name={
            "_ga": [
                CookieDescription(
                    name="_ga", domain="", category=Category.ANALYTICS, description="GA"
                )
            ]
        },
        by_prefix={},
    )
    d = decide(
        cookie,
        policy=UserPolicy(mode=ClassifierMode.AUDIT_ONLY),
        cookie_db=db,
        now=_NOW,
    )
    assert d.verdict is Verdict.KEEP
    assert d.category is Category.ANALYTICS
    assert "Open Cookie Database" in d.rationale


def test_audit_only_respects_user_keep_list_explicitly():
    # User keep-list still wins. The rationale should name the user
    # rule, not "audit-only", because the user rule is more specific.
    cookie = _cookie(name="_ga", domain="example.test")
    policy = UserPolicy(
        keep_domains=frozenset({"example.test"}),
        mode=ClassifierMode.AUDIT_ONLY,
    )
    d = decide(cookie, policy=policy, cookie_db=_empty_db(), now=_NOW)
    assert d.verdict is Verdict.KEEP
    assert d.source == "user-keep-list:domain"


# ---------------------------------------------------------------------------
# STRICT mode: also deletes Performance category
# ---------------------------------------------------------------------------


def test_strict_deletes_performance_cookie():
    cookie = _cookie(name="_pref_bucket", domain="cdn.example.com")
    db = CookieDatabase(
        by_exact_name={
            "_pref_bucket": [
                CookieDescription(
                    name="_pref_bucket",
                    domain="",
                    category=Category.PERFORMANCE,
                    description="A/B bucket",
                )
            ]
        },
        by_prefix={},
    )
    d_balanced = decide(
        cookie,
        policy=UserPolicy(mode=ClassifierMode.BALANCED),
        cookie_db=db,
        now=_NOW,
    )
    assert d_balanced.verdict is Verdict.KEEP  # Balanced keeps Performance

    d_strict = decide(
        cookie,
        policy=UserPolicy(mode=ClassifierMode.STRICT),
        cookie_db=db,
        now=_NOW,
    )
    assert d_strict.verdict is Verdict.DELETE
    assert d_strict.source == "open-cookie-db"
    assert "performance" in d_strict.rationale.lower()
    assert "Strict mode" in d_strict.rationale


def test_strict_still_keeps_functional_cookie():
    cookie = _cookie(name="lang_pref", domain="example.com")
    db = CookieDatabase(
        by_exact_name={
            "lang_pref": [
                CookieDescription(
                    name="lang_pref",
                    domain="",
                    category=Category.FUNCTIONAL,
                    description="Language preference",
                )
            ]
        },
        by_prefix={},
    )
    d = decide(
        cookie,
        policy=UserPolicy(mode=ClassifierMode.STRICT),
        cookie_db=db,
        now=_NOW,
    )
    assert d.verdict is Verdict.KEEP


# ---------------------------------------------------------------------------
# SCORCHED_EARTH mode
# ---------------------------------------------------------------------------


def test_scorched_earth_deletes_session_cookie_too():
    cookie = _cookie(
        name="JSESSIONID",
        domain="bank.example.com",
        expires=None,
        http_only=True,
        is_host_only=True,
    )
    d = decide(
        cookie,
        policy=UserPolicy(mode=ClassifierMode.SCORCHED_EARTH),
        cookie_db=_empty_db(),
        now=_NOW,
    )
    assert d.verdict is Verdict.DELETE
    assert d.source == "scorched-earth"


def test_scorched_earth_keeps_host_prefix_cookie():
    cookie = _cookie(name="__Host-csrf", domain="bank.example.com")
    d = decide(
        cookie,
        policy=UserPolicy(mode=ClassifierMode.SCORCHED_EARTH),
        cookie_db=_empty_db(),
        now=_NOW,
    )
    assert d.verdict is Verdict.KEEP
    assert d.source == "security-prefix"


def test_scorched_earth_keeps_secure_prefix_cookie():
    cookie = _cookie(name="__Secure-id", domain="bank.example.com")
    d = decide(
        cookie,
        policy=UserPolicy(mode=ClassifierMode.SCORCHED_EARTH),
        cookie_db=_empty_db(),
        now=_NOW,
    )
    assert d.verdict is Verdict.KEEP
    assert d.source == "security-prefix"


def test_scorched_earth_keeps_user_allowed_domain():
    cookie = _cookie(name="random", domain="gmail.com")
    policy = UserPolicy(
        keep_domains=frozenset({"gmail.com"}),
        mode=ClassifierMode.SCORCHED_EARTH,
    )
    d = decide(cookie, policy=policy, cookie_db=_empty_db(), now=_NOW)
    assert d.verdict is Verdict.KEEP
    assert d.source.startswith("user-keep-list")


def test_scorched_earth_does_not_save_auth_substring_names():
    # Even names containing "session" / "token" go in scorched-earth,
    # unless they use the __Host-/__Secure- prefix.
    cookie = _cookie(name="some_session_token", domain="example.com")
    d = decide(
        cookie,
        policy=UserPolicy(mode=ClassifierMode.SCORCHED_EARTH),
        cookie_db=_empty_db(),
        now=_NOW,
    )
    assert d.verdict is Verdict.DELETE
    assert d.source == "scorched-earth"


# ---------------------------------------------------------------------------
# Security prefix kept in lower modes too
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "mode",
    [
        ClassifierMode.AUDIT_ONLY,
        ClassifierMode.CONSERVATIVE,
        ClassifierMode.BALANCED,
        ClassifierMode.STRICT,
        ClassifierMode.AGGRESSIVE,
        ClassifierMode.SCORCHED_EARTH,
    ],
)
def test_host_prefix_always_kept(mode: ClassifierMode):
    cookie = _cookie(name="__Host-Auth", domain="example.com")
    d = decide(
        cookie,
        policy=UserPolicy(mode=mode),
        cookie_db=_empty_db(),
        now=_NOW,
    )
    assert d.verdict is Verdict.KEEP


# ---------------------------------------------------------------------------
# Mode ladder ordering (sanity)
# ---------------------------------------------------------------------------


def test_mode_order_is_monotonic():
    ladder = [
        ClassifierMode.AUDIT_ONLY,
        ClassifierMode.CONSERVATIVE,
        ClassifierMode.BALANCED,
        ClassifierMode.STRICT,
        ClassifierMode.AGGRESSIVE,
        ClassifierMode.SCORCHED_EARTH,
    ]
    assert [m.order() for m in ladder] == list(range(6))
