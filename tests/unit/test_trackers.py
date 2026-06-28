"""Direct tests for the curated tracker helpers (no policy involved)."""

from __future__ import annotations

import pytest

from cookie_janitor.classify.trackers import (
    has_auth_shape,
    has_tracker_name_substring,
    has_tracking_subdomain_label,
    is_tracker_cookie_name,
    is_tracker_domain,
)


@pytest.mark.parametrize(
    "host,expected",
    [
        (".doubleclick.net", "doubleclick.net"),
        ("doubleclick.net", "doubleclick.net"),
        ("googleads.g.doubleclick.net", "doubleclick.net"),
        ("connect.facebook.net", "connect.facebook.net"),
        # Suffix-match: a longer host under the tracker eTLD+1.
        ("foo.adnxs.com", "adnxs.com"),
    ],
)
def test_is_tracker_domain_matches(host: str, expected: str):
    assert is_tracker_domain(host) == expected


@pytest.mark.parametrize(
    "host",
    [
        "",
        "example.com",
        "google.com",  # not a tracker on its own; google-analytics.com is
        "doubleclick.example.com",  # tracker name as subdomain doesn't count
    ],
)
def test_is_tracker_domain_misses(host: str):
    assert is_tracker_domain(host) is None


@pytest.mark.parametrize(
    "host,expected_label",
    [
        ("tracking.pandoiq.com", "tracking"),
        ("analytics.foo.example.com", "analytics"),
        ("ads.foo.example.com", "ads"),
        ("pixel.bar.io", "pixel"),
    ],
)
def test_tracking_subdomain_label_hits(host: str, expected_label: str):
    assert has_tracking_subdomain_label(host) == expected_label


@pytest.mark.parametrize(
    "host",
    [
        "auth.example.com",
        "api.example.com",
        "login.example.com",
        "example.com",
        # Two labels only → no subdomain part to check.
        "tracking.com",
    ],
)
def test_tracking_subdomain_label_misses(host: str):
    assert has_tracking_subdomain_label(host) is None


@pytest.mark.parametrize(
    "name,expected",
    [
        ("_ga", True),
        ("_gid", True),
        ("MUID", True),
        ("_fbp", True),
        ("hubspotutk", True),
        ("session_id", False),
        ("auth_token", False),
        ("", False),
    ],
)
def test_is_tracker_cookie_name(name: str, expected: bool):
    assert is_tracker_cookie_name(name) is expected


@pytest.mark.parametrize(
    "name,expected_present",
    [
        ("visid_incap_440913", True),
        ("Realmatch_Tracking", True),
        ("_pk_id.1234", True),
        ("plain_session_id", False),
        ("csrf_token", False),
    ],
)
def test_has_tracker_name_substring(name: str, expected_present: bool):
    result = has_tracker_name_substring(name)
    assert (result is not None) is expected_present


@pytest.mark.parametrize(
    "name,expected_present",
    [
        ("__Host-auth", True),
        ("__Secure-csrf", True),
        ("sessionid", True),
        ("auth_token", True),
        ("csrf", True),
        ("xsrf-token", True),
        ("JWT", True),
        ("oauth_state", True),
        ("_ga", False),
        ("visid_incap_1", False),
    ],
)
def test_has_auth_shape(name: str, expected_present: bool):
    result = has_auth_shape(name)
    assert (result is not None) is expected_present
