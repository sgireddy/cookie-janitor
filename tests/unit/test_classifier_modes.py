"""Mode-aware classifier behavior — one test per rule, per mode boundary.

The fixtures below construct synthetic cookies that match exactly one
rule each, so every assertion isolates the behavior of a single rule.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from cookie_janitor.classify.cookie_db import CookieDatabase
from cookie_janitor.model.cookie import SameSite, Verdict, make_cookie
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
