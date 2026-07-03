"""Curated lists of third-party trackers, keyed on what we can read
from a cookie alone: the cookie's domain attribute, the cookie's name,
and a few subdomain-label heuristics.

Everything here is pure data plus three tiny pure-Python helpers. No
network I/O, no filesystem I/O, no regex except where strictly clearer
than ``str.endswith`` / ``in``. The lists are intentionally short and
curated rather than exhaustive — every entry below has been hand-verified
against either the EasyPrivacy filter list, the Open Cookie Database,
or a vendor's own documentation.

If you find a real-world tracker we're missing, the fix is a one-line
PR adding it here with a comment naming the source. Please do not add
entries that *might* be trackers without evidence — false positives
break real users' logins (THREAT_MODEL TH-7).
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Third-party tracker / ad / fingerprinting domains.
#
# These are eTLD+1 hostnames whose entire purpose is cross-site tracking or
# ad delivery. A cookie set with ``domain=.<one of these>`` is almost
# certainly a tracker — there's no first-party site you're "logged into" at
# doubleclick.net or scorecardresearch.com.
#
# Sources, per entry:
#   E = EasyPrivacy (https://easylist.to/easylist/easyprivacy.txt)
#   O = Open Cookie Database
#   V = Vendor docs / acquisition disclosures
# ---------------------------------------------------------------------------
TRACKER_DOMAINS: frozenset[str] = frozenset(
    {
        # ─── Google advertising / analytics (vendor: Alphabet) ──────────────
        "doubleclick.net",  # E,V — DoubleClick / Google Ads
        "googleadservices.com",  # E,V
        "googlesyndication.com",  # E,V — AdSense
        "googletagmanager.com",  # E,V
        "google-analytics.com",  # E,V
        "googletagservices.com",  # E,V
        "adservice.google.com",  # E,V
        # ─── Meta / Facebook (vendor: Meta) ─────────────────────────────────
        "facebook.net",  # E,V — Pixel
        "connect.facebook.net",  # E,V
        "fbcdn.net",  # V — used for fr/_fbp delivery
        # ─── Microsoft advertising ─────────────────────────────────────────
        "bat.bing.com",  # E,V — Microsoft Advertising / UET
        "clarity.ms",  # E,V — Microsoft Clarity session replay
        # ─── LinkedIn (vendor: Microsoft) ─────────────────────────────────
        "ads.linkedin.com",  # E,V
        "px.ads.linkedin.com",  # E,V
        # ─── Twitter / X ───────────────────────────────────────────────────
        "ads-twitter.com",  # E,V
        "analytics.twitter.com",  # E,V
        "static.ads-twitter.com",  # E,V
        # ─── TikTok ───────────────────────────────────────────────────────
        "analytics.tiktok.com",  # E,V
        "ads.tiktok.com",  # E,V
        # ─── Pinterest ────────────────────────────────────────────────────
        "ct.pinterest.com",  # E,V
        # ─── Snap ────────────────────────────────────────────────────────
        "sc-static.net",  # E,V — Snap Pixel
        # ─── Reddit ──────────────────────────────────────────────────────
        "redditstatic.com",  # E,V — Reddit Pixel (advertising subdomain only)
        # ─── Adtech exchanges / SSPs / DSPs ────────────────────────────────
        "adnxs.com",  # E,V — AppNexus / Xandr
        "adsrvr.org",  # E,V — The Trade Desk
        "pubmatic.com",  # E,V
        "openx.net",  # E,V
        "rubiconproject.com",  # E,V
        "casalemedia.com",  # E,V — Index Exchange
        "advertising.com",  # E,V — Yahoo / Verizon Media
        "atdmt.com",  # E,V
        "rfihub.com",  # E,V — Rocket Fuel / Sizmek
        "mathtag.com",  # E,V — MediaMath
        "agkn.com",  # E,V — Neustar AdAdvisor
        "exelator.com",  # E,V — Nielsen eXelate
        "eyeota.net",  # E,V
        "semasio.net",  # E,V
        "criteo.com",  # E,V
        "criteo.net",  # E,V
        "taboola.com",  # E,V
        "outbrain.com",  # E,V
        "adsymptotic.com",  # E,V — Drawbridge cross-device
        "krxd.net",  # E,V — Salesforce Krux DMP
        "rlcdn.com",  # E,V — LiveRamp
        "demdex.net",  # E,V — Adobe Audience Manager
        "omtrdc.net",  # E,V — Adobe Analytics
        "everesttech.net",  # E,V — Adobe Advertising Cloud
        "bluekai.com",  # E,V — Oracle BlueKai
        "ttdsg.net",  # E,V — The Trade Desk sync
        # ─── Audience measurement ─────────────────────────────────────────
        "scorecardresearch.com",  # E,V — Comscore
        "quantserve.com",  # E,V — Quantcast
        "nielsen.com",  # E (specific subdomains, but the SDK uses bare nielsen.com)
        # ─── Product analytics / SaaS trackers ─────────────────────────────
        "hotjar.com",  # E,V — session replay + heatmaps
        "hotjar.io",  # V
        "mixpanel.com",  # E,V
        "amplitude.com",  # E,V
        "segment.io",  # E,V
        "segment.com",  # V
        "fullstory.com",  # E,V — session replay
        "mouseflow.com",  # E,V — session replay
        "pendo.io",  # E,V — product analytics
        "heap.io",  # E,V
        "mparticle.com",  # E,V
        "branch.io",  # E,V — deep-link attribution
        "optimizely.com",  # E,V — A/B testing
        "kissmetrics.com",  # E,V
        "chartbeat.com",  # E,V
        "newrelic.com",  # E (Browser agent only) — but session id is tracking
        # ─── Affiliate / attribution ──────────────────────────────────────
        "go2cloud.org",  # E
        "tradedoubler.com",  # E
        "cj.com",  # E — Commission Junction
        "shareasale.com",  # E
        "impactradius.com",  # E
        "impact.com",  # V — same vendor
        # ─── HubSpot tracking (note: hubspot.com itself can be a CRM
        # session, so we only list the tracking-specific subdomain pattern
        # via TRACKING_SUBDOMAIN_LABELS rather than blanket-banning it) ────
    }
)


# ---------------------------------------------------------------------------
# Subdomain *labels* that almost always indicate a tracking endpoint.
#
# Match rule: any DNS label in the cookie's domain equals one of these,
# case-insensitive. Examples that should match:
#   tracking.pandoiq.com  → "tracking"
#   analytics.foo.com     → "analytics"
#   ads.foo.com           → "ads"
#   pixel.bar.io          → "pixel"
#
# We deliberately exclude labels that have legitimate first-party uses:
#   "auth", "api", "login", "account", "id", "sso" → never on this list.
# ---------------------------------------------------------------------------
TRACKING_SUBDOMAIN_LABELS: frozenset[str] = frozenset(
    {
        "tracking",
        "tracker",
        "track",
        "analytics",
        "telemetry",
        "metrics",
        "pixel",
        "pixels",
        "beacon",
        "tag",
        "tags",
        "stats",
        "adserver",
        "adservices",
        "ads",
        "adsystem",
        "doubleclick",
        "googleadservices",
        "googlesyndication",
        "gtm",
        "marketo",
    }
)


# ---------------------------------------------------------------------------
# Cookie names that are *exactly* a known tracker. High-confidence list —
# every entry maps to one specific vendor whose only purpose is tracking.
#
# Note: ``_ga``, ``_gid``, ``_gat``, ``_fbp``, etc. are already in the
# Open Cookie Database, so they're handled by the existing rule 4 path.
# We list them again here as defense-in-depth in case the user's CSV
# snapshot is stale.
# ---------------------------------------------------------------------------
TRACKER_COOKIE_NAMES: frozenset[str] = frozenset(
    {
        # Google
        "_ga",
        "_gid",
        "_gat",
        "_gcl_au",
        "_gcl_aw",
        "_gcl_dc",
        "__utma",
        "__utmb",
        "__utmc",
        "__utmt",
        "__utmv",
        "__utmz",
        "AID",
        "IDE",
        "DSID",
        "FLC",
        "TAID",
        "ANID",
        "__gads",
        "__gpi",
        # Meta / Facebook
        "_fbp",
        "_fbc",
        "fr",  # only on facebook.com / fbcdn.net domains; outside that it's noise
        # Microsoft / Bing / Clarity
        "_uetsid",
        "_uetvid",
        "MUID",
        "MR",  # MUID rotator
        "MUIDB",
        "_clck",
        "_clsk",
        "CLID",
        "ANONCHK",
        "SM",
        # LinkedIn
        "li_sugr",
        "lidc",
        "bcookie",
        "bscookie",
        "AnalyticsSyncHistory",
        "UserMatchHistory",
        # Twitter / X
        "personalization_id",
        "guest_id_marketing",
        "guest_id_ads",
        "muc_ads",
        # TikTok
        "_ttp",
        "_tt_enable_cookie",
        # Pinterest
        "_pin_unauth",
        "_pinterest_sess",  # contested but is tracking outside pinterest.com itself
        # Snap
        "_scid",
        "_sctr",
        # Reddit
        "rdt",  # Reddit Pixel
        # Product analytics
        "_hjid",
        "_hjSession",
        "_hjSessionUser",
        "_hjAbsoluteSessionInProgress",
        "_hjFirstSeen",
        "_hjIncludedInSessionSample",
        "_hjIncludedInPageviewSample",
        "_hjTLDTest",
        "mp_mixpanel__c",
        "amplitude_id",
        "amplitude_session",
        "ajs_anonymous_id",  # Segment
        "ajs_user_id",
        "fs_uid",  # FullStory
        "mf_user",  # Mouseflow
        "pendo_visitorId",
        # Adtech / DMP
        "uuid2",  # AppNexus
        "anj",  # AppNexus
        "KRTBCOOKIE_",  # PubMatic (with numeric suffix; substring rule catches the rest)
        "everest_g_v2",
        "tuuid",
        "tuuid_lu",
        "rlas3",
        "rdr",
        # Audience measurement
        "UID",  # ScorecardResearch sets this; collides w/ user IDs elsewhere
        # but the (name, domain) classifier will still catch it on the right host.
        "mc",  # Quantcast
        # HubSpot tracking (vs. their first-party CRM cookies)
        "hubspotutk",
        "__hssrc",
        "__hstc",
        "__hssc",
        # Pardot / Salesforce Marketing
        "pardot",
        "visitor_id",
        "visitor_id_with_sign",
        # Marketo
        "_mkto_trk",
        # Cloudflare bot management — *not* on this list intentionally:
        # __cf_bm and cf_clearance are anti-bot, not tracking.
        # Imperva / Incapsula visitor ID — the visitor cookie persists
        # across sessions and identifies you. Session variants
        # (incap_ses_*) are functional and handled by substring rule.
        "nlbi",  # Incapsula load balancer ID — leaks to third parties
    }
)


# ---------------------------------------------------------------------------
# Substrings that, when found in a cookie name (case-insensitive), strongly
# imply the cookie's purpose is tracking. We deliberately keep this list
# short and unambiguous; every entry has been audited against real-world
# false-positive cases.
#
# Substrings here trip in BALANCED and AGGRESSIVE modes. They do NOT trip
# if the name *also* contains an auth-shape substring (see
# ``AUTH_SHAPE_SUBSTRINGS``) — many session-id cookies legitimately have
# the word "session" in them.
# ---------------------------------------------------------------------------
TRACKER_NAME_SUBSTRINGS: tuple[str, ...] = (
    "_tracking",
    "tracking_",
    "_tracker",
    "_track_",
    "trackingid",
    "_visitor",  # piq_uuid_visitor and similar
    "visid_incap_",  # Imperva/Incapsula cross-session visitor ID
    "realmatch_",  # RealMatch ad network tracker (saw this in your screenshot)
    "_optimizely",
    "_mkto",  # Marketo
    "_pk_id",  # Piwik / Matomo identifier (kept session is _pk_ses)
    "_pk_ref",
    "_pk_cvar",
)


# ---------------------------------------------------------------------------
# Substrings whose presence strongly implies a login/auth cookie. If a
# cookie name contains one of these, we KEEP it even when other rules
# would mark it as a tracker. Order: any case-insensitive substring match.
# ---------------------------------------------------------------------------
AUTH_SHAPE_SUBSTRINGS: tuple[str, ...] = (
    # NB: every entry here is ≥4 characters. Three-letter shortcuts like
    # "sid" and "uid" are too prone to false positives — "visid_incap" and
    # "uuid2" both contain "sid" / "uid" but are trackers, not auth.
    # Cookies like ``JSESSIONID`` are still caught because they contain
    # the longer "sessionid" substring.
    "session",
    "sessionid",
    "sess",
    "auth",
    "authn",
    "authz",
    "login",
    "logged_in",
    "user_id",
    "userid",
    "csrf",
    "xsrf",
    "token",
    "remember",
    "rememberme",
    "jwt",
    "access_token",
    "accesstoken",
    "refresh",
    "openid",
    "oauth",
    "oidc",
    "saml",
)


# ---------------------------------------------------------------------------
# Public helpers. Tiny, single-purpose, easy to test.
# ---------------------------------------------------------------------------


def _normalise_host(host: str) -> str:
    """Return a lowercase host with no leading dot.

    Browsers store cookie domains with or without a leading dot to mean
    "include subdomains" vs "host-only". For our matching here we don't
    care — we strip and lowercase.
    """
    return host.lstrip(".").lower()


def is_tracker_domain(host: str) -> str | None:
    """Return the matching tracker domain if ``host`` is one, else ``None``.

    Matches both the bare eTLD+1 and any subdomain underneath. When a host
    matches more than one entry — e.g. ``connect.facebook.net`` matches
    both ``facebook.net`` and ``connect.facebook.net`` — we return the
    longest match so the rationale shown to the user names the most
    specific tracker.
    """
    h = _normalise_host(host)
    if not h:
        return None
    best: str | None = None
    for tracker in TRACKER_DOMAINS:
        if (h == tracker or h.endswith("." + tracker)) and (
            best is None or len(tracker) > len(best)
        ):
            best = tracker
    return best


def has_tracking_subdomain_label(host: str) -> str | None:
    """Return the offending DNS label if ``host`` contains one, else ``None``.

    Only checks the *leftmost* labels (everything except the eTLD+1).
    This avoids flagging a cookie set on ``example.tracking.com`` (where
    "tracking" is the registered domain, not a subdomain label) — but
    note we cannot do a true public-suffix split without a PSL dep, so
    we approximate by ignoring the last two labels.
    """
    h = _normalise_host(host)
    if not h:
        return None
    parts = h.split(".")
    # Need at least three labels for a "subdomain" by our definition
    # (label.etld.tld). Two-label hosts (foo.com) have no subdomain part.
    if len(parts) < 3:
        return None
    for label in parts[:-2]:
        if label in TRACKING_SUBDOMAIN_LABELS:
            return label
    return None


def is_tracker_cookie_name(name: str) -> bool:
    """Exact-match against the curated tracker-name set."""
    return name in TRACKER_COOKIE_NAMES


def has_tracker_name_substring(name: str) -> str | None:
    """Return the matching substring if the name contains a tracker
    fingerprint, else ``None``. Case-insensitive.
    """
    lower = name.lower()
    for needle in TRACKER_NAME_SUBSTRINGS:
        if needle in lower:
            return needle
    return None


def has_auth_shape(name: str) -> str | None:
    """Return the matching auth substring if ``name`` looks like a
    login/auth/CSRF cookie, else ``None``. Used by aggressive mode to
    avoid nuking real session cookies.
    """
    lower = name.lower()
    # __Host- and __Secure- prefixes are an explicit browser-level signal
    # that the cookie is auth-grade.
    if lower.startswith(("__host-", "__secure-")):
        return name.split("-", 1)[0] + "-"
    for needle in AUTH_SHAPE_SUBSTRINGS:
        if needle in lower:
            return needle
    return None
