from datetime import UTC, datetime, timedelta

from cookie_janitor.classify.cookie_db import (
    CookieDatabase,
    CookieDescription,
)
from cookie_janitor.model.cookie import Category, SameSite, Verdict, make_cookie
from cookie_janitor.policy.decide import UserPolicy, decide


def _cookie(**kw):
    defaults = dict(
        name="x",
        domain="example.test",
        path="/",
        expires=datetime.now(tz=UTC) + timedelta(days=365),
        secure=True,
        http_only=True,
        same_site=SameSite.LAX,
        is_host_only=False,
        value_bytes=b"v",
    )
    defaults.update(kw)
    return make_cookie(**defaults)


def _db_with(rows: list[CookieDescription]) -> CookieDatabase:
    by_exact: dict[str, list[CookieDescription]] = {}
    for r in rows:
        by_exact.setdefault(r.name, []).append(r)
    return CookieDatabase(by_exact_name=by_exact, by_prefix={})


def test_user_keep_list_beats_known_tracker():
    cookie = _cookie(name="_ga", domain=".google.com")
    db = _db_with(
        [CookieDescription(name="_ga", domain="", category=Category.ANALYTICS, description="GA")]
    )
    policy = UserPolicy(keep_domains=frozenset({"google.com"}))
    d = decide(cookie, policy=policy, cookie_db=db)
    assert d.verdict is Verdict.KEEP
    assert d.source.startswith("user-keep-list")


def test_known_tracker_is_deleted():
    cookie = _cookie(name="_ga", domain=".example.test")
    db = _db_with(
        [CookieDescription(name="_ga", domain="", category=Category.ANALYTICS, description="GA")]
    )
    d = decide(cookie, policy=UserPolicy(), cookie_db=db)
    assert d.verdict is Verdict.DELETE
    assert d.category is Category.ANALYTICS
    assert "Open Cookie Database" in d.rationale


def test_unknown_defaults_to_keep():
    cookie = _cookie(name="mystery_thing", domain="example.test")
    d = decide(cookie, policy=UserPolicy(), cookie_db=_db_with([]))
    assert d.verdict is Verdict.KEEP
    assert d.source == "default-keep-unknown"


def test_session_http_only_host_only_is_kept_by_heuristic():
    cookie = _cookie(
        name="csrf_token",
        domain="example.test",
        expires=None,
        is_host_only=True,
        http_only=True,
    )
    d = decide(cookie, policy=UserPolicy(), cookie_db=_db_with([]))
    assert d.verdict is Verdict.KEEP
    assert d.source == "heuristic-session"


def test_user_delete_list_overrides_unknown_default():
    cookie = _cookie(name="mystery", domain="ads.example.test")
    policy = UserPolicy(delete_domains=frozenset({"ads.example.test"}))
    d = decide(cookie, policy=policy, cookie_db=_db_with([]))
    assert d.verdict is Verdict.DELETE
    assert d.source.startswith("user-delete-list")
