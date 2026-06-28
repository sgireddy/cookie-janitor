from datetime import UTC, datetime

from cookie_janitor.model.cookie import (
    Category,
    Decision,
    SameSite,
    Verdict,
    make_cookie,
)


def test_make_cookie_fingerprints_value_and_drops_raw():
    c = make_cookie(
        name="SID",
        domain=".google.com",
        path="/",
        expires=datetime(2030, 1, 1, tzinfo=UTC),
        secure=True,
        http_only=True,
        same_site=SameSite.LAX,
        is_host_only=False,
        value_bytes=b"supersecret-bearer-token",
    )
    assert c.value_length == len(b"supersecret-bearer-token")
    assert len(c.value_sha256_prefix) == 8
    assert all(ch in "0123456789abcdef" for ch in c.value_sha256_prefix)
    # Confirm there is no field on the dataclass leaking the raw bytes.
    assert not any("supersecret" in repr(getattr(c, f)) for f in c.__slots__)


def test_make_cookie_session_is_session():
    c = make_cookie(
        name="x",
        domain="example.test",
        path="/",
        expires=None,
        secure=True,
        http_only=True,
        same_site=SameSite.STRICT,
        is_host_only=True,
        value_bytes=b"abc",
    )
    assert c.is_session is True


def test_decision_confidence_validated():
    import pytest

    c = make_cookie(
        name="x",
        domain="example.test",
        path="/",
        expires=None,
        secure=False,
        http_only=False,
        same_site=SameSite.UNSPECIFIED,
        is_host_only=True,
        value_bytes=b"a",
    )
    with pytest.raises(ValueError):
        Decision(
            cookie=c,
            verdict=Verdict.KEEP,
            category=Category.UNKNOWN,
            rationale="x",
            source="x",
            confidence=1.5,
        )
