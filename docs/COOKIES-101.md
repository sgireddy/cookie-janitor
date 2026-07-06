# Cookies 101

*A plain-English guide to what's on your machine, what it does, and what
Cookie Janitor does about it.*

---

## TL;DR

Websites drop small text files ("cookies") in your browser to remember
things. Some are useful — they keep you logged in and remember your
preferences. Many are designed to follow you around the web, and those
are the ones Cookie Janitor targets. Cleaning cookies is one useful
privacy step, but not a complete one — this page tells you what it does
and doesn't cover.

---

## What is a cookie, really?

A cookie is a small piece of text that a website asks your browser to
store, and hands back to that website every time you visit. Nothing more
magical than that.

When you sign into Gmail and close the tab, Google's server sends your
browser a cookie containing something like `SID=xy8...`. Next time you
open Gmail, your browser hands that cookie back, and Google's server
recognises you without asking for a password again.

Cookies were invented in 1994 to solve exactly this problem — the web is
otherwise stateless, and every page load looks like a stranger arriving.
Without cookies, every site would forget you the moment you clicked a
link.

The trouble is: the same mechanism that keeps you logged in can also be
used to follow you around, and over 30 years the industry has become
extremely good at the second use.

### The anatomy of a cookie

Every cookie has, at minimum:

- **A name.** Freely chosen by the site: `SID`, `_ga`, `csrftoken`, `xh92k3`.
- **A value.** Also freely chosen. Often opaque (`abc123...`) — the value
  usually means something only to the site's server.
- **A domain.** Which host the cookie is bound to. `.google.com` means
  "any subdomain of google.com."
- **A path.** Which URL prefix the cookie applies to. Usually `/`.
- **An expiry.** When your browser should forget it. Session cookies expire
  when you close the browser. Long-lived cookies can last years.
- **Flags.** `Secure` (only send over HTTPS), `HttpOnly` (JavaScript can't
  read it — a defence against XSS), `SameSite` (limits cross-site sending).

Cookie Janitor's classifier looks at all of these when deciding what to
do with a cookie. Names and flags are especially informative — an
`HttpOnly` cookie with `SameSite=Strict` is almost certainly session
state, not a tracker.

---

## 🟢 The Good — cookies you want to keep

### Session and authentication cookies

These are what "keep me logged in" means. Delete them and you'll be
signing back into everything tomorrow morning.

Common shapes:

- Names containing `sess`, `auth`, `token`, `sid`, or the RFC 6265bis
  `__Host-` / `__Secure-` prefixes.
- Usually flagged `HttpOnly` and `Secure`.
- Often set to expire in a few weeks or on browser close.

Examples: Google's `SID`, GitHub's `user_session`, Amazon's
`session-id`, most sites' `csrftoken`.

### Preference cookies

These remember choices you made deliberately. YouTube's dark-mode
setting. Your language on a site that supports multiple. Your timezone
on a booking site. Deleting them is harmless but mildly annoying —
you'll re-pick your preferences next visit.

### Shopping-cart cookies

For sites that let you browse without an account, your cart lives in a
cookie. Delete it mid-shop and you lose your cart. (For sites where
you're signed in, the cart is server-side and cookie-independent.)

### What Cookie Janitor does with them

Keeps them. Our classifier looks at cookie names, domains, and flags
to detect the auth-shape and preference-shape patterns, and leaves those
alone even in the more aggressive modes. You'll stay signed into
Gmail.

The one exception is **Scorched earth** mode, which trusts only the
browser-enforced `__Host-` / `__Secure-` prefixes and your allow list.
That's a deliberate choice — see the mode table below.

---

## 🟡 The Bad — cookies you probably don't need

### First-party analytics

The site's own measurement of how you use it. Which pages you visit,
how long you stay, where you clicked.

Google Analytics running on `example.com`'s own domain drops cookies
like `_ga`, `_gid`, `_gat_*`. These aren't inherently sinister — the
site owner is trying to understand their traffic — but they're also
not doing anything for you. Deleting them costs you nothing.

### A/B test bucket cookies

Sites run experiments and use cookies to remember which experimental
variant you saw so your experience stays consistent within a session.
Names often look like `_optimizely_*`, `_vwo_*`,
`ajs_anonymous_id`. Delete them and you might see a slightly different
layout on your next visit, but nothing breaks.

### Anti-bot / rate-limit cookies

CAPTCHAs and DDoS-protection services (Cloudflare's `__cf_bm`,
hCaptcha's `hcaptcha`) drop cookies to remember "we've already
verified this human." Delete them and you might have to click a
CAPTCHA one more time. Minor cost.

### What Cookie Janitor does with them

In **Balanced** mode (the default) and above: cleans them. In
**Conservative** mode: keeps them. Your choice.

---

## 🔴 The Ugly — cookies designed against you

### Third-party tracking cookies

This is the main event.

When a site embeds anything served from a different domain — an ad, a
"share on Facebook" button, an embedded YouTube video, a Google Fonts
import — that third party's server can drop its own cookie on your
browser. When you visit a different site that also embeds anything from
that same third party, your browser hands back the same cookie. That's
how a single company builds a profile of everywhere you go.

The classic examples:

- **Google's `IDE` and `NID` cookies** — DoubleClick ad network.
- **Meta's `fr` cookie** — Facebook Pixel.
- Hundreds of ad-tech companies you've never heard of, via cookies like
  `uid`, `visitor_id`, `_pinterest_ct_ua`.

A single ordinary news-site page load can drop cookies from 20+ third
parties.

### Retargeting pixels

When you look at a product on one site and then see ads for it
everywhere for two weeks, that's retargeting. It works via a third-party
cookie set when you viewed the product, read on the ad networks' pages
elsewhere.

### Cookie-banner cookies

The banner itself typically drops a cookie to remember what you clicked.
Most banners are compliance theatre — they record your click but do very
little to actually change what happens next. Some sites now use
"legitimate interest" checkboxes that opt you in by default regardless
of your choice.

There's some detail in the **Cookies and the law** section below on why
the banners are the way they are; the short version is that they
exist to record consent, not to enforce it.

### What Cookie Janitor does with them

Cleans them all, aggressively, in every mode from Balanced upward. This
is the primary target.

---

## 📦 Aside — Cookies and the prices you see

A common question: *"Does deleting cookies get me cheaper prices?"*

**Mostly no.** Amazon, airlines, hotel sites and their peers do use
personalized pricing, but the personalization is decided **server-side**
from your account and IP address, not from the cookies themselves. The
cookies just identify you to the server so it can look up the profile.
Delete them and you'll look like a new visitor — which might give you a
slightly different price, but not reliably a better one. Fingerprinting
(screen size, installed fonts, GPU details) still tells the server
it's likely you.

The one confirmed case of pure cookie-based price discrimination —
**Amazon in September 2000** — became a public scandal. Users noticed
Amazon was charging returning logged-in customers *more* for the same
DVDs than fresh visitors saw. Jeff Bezos issued a public apology and
Amazon walked it back. Since then per-user pricing has moved firmly
server-side.

Other well-documented cases:

- **Orbitz, 2012** — Mac users shown pricier hotels first, via
  User-Agent (not cookies specifically). Made the *Wall Street
  Journal* front page.
- **Staples, 2012** — showed different online prices based on
  IP-geolocated distance from a competitor store. WSJ again.
- **Airlines and travel sites** — the "keep searching the same flight
  and the price goes up" folk wisdom is partly real. Both cookie-based
  and server-side session state contribute.

**What this means for you:** deleting the cart cookie does nothing to
pricing (it just empties your cart). Deleting auth cookies makes you
look like a fresh visitor, which *might* show different prices — but
not reliably. For genuine price comparison, use an incognito window +
a VPN endpoint in a different city + a different browser than your
usual. No single browser tool, Cookie Janitor included, can fully
counter modern personalized pricing.

---

## ⚖️ Cookies and the law

The GDPR (Europe, 2018) and CCPA (California, 2020) require sites to
disclose what cookies they set and, in most cases, get explicit consent
before setting non-essential ones. That's why every site now greets you
with a banner.

In practice:

- **The banner records what you clicked,** in a cookie. It doesn't
  physically prevent the site from setting other cookies — that's up
  to the site's own code to honour.
- **"Legitimate interest"** checkboxes are often opt-out (pre-checked),
  which arguably defeats the purpose of consent but is a common pattern.
- **"Reject all"** buttons are sometimes hidden two clicks deep. The
  European regulators have started fining sites over this ("dark
  patterns").
- **Compliance ≠ privacy.** A site can be fully GDPR-compliant and still
  drop 40 tracker cookies on you, as long as you clicked "Accept."

Cookie Janitor doesn't care what the banner recorded. If a cookie is a
tracker, it's a tracker regardless of whether you consented to it. The
tool operates *after* the banner has done (or not done) its job.

This is not legal advice. If you need it, talk to a lawyer.

---

## What Cookie Janitor is NOT

Being honest about scope matters more than sounding capable.

### Not a tracker blocker

We delete cookies *after* they've been set. Trackers still ran their
JavaScript. Their servers still logged your IP address, your
User-Agent, your referrer. If you want to prevent cookies from being
set at all, install [uBlock Origin][ublock] or [Privacy Badger][pb].
Cookie Janitor **complements** them, not replaces them.

### Not fingerprinting protection

Trackers can identify you without cookies at all — via your screen
size, installed fonts, GPU details, timezone, and dozens of other
signals. If this worries you, look at [Firefox's Enhanced Tracking
Protection][ff-etp] (Strict mode) or the [Tor Browser][tor].

### Not IP-address hiding

Websites see your IP whether or not they set cookies. For that, use a
VPN or Tor. Cookie deletion doesn't affect your network address.

### Not localStorage / IndexedDB / cache hygiene

Browsers have half a dozen other storage mechanisms besides cookies.
Some trackers have moved to those. Cookie Janitor only handles cookies
— that's a scope choice for reliability, not because the other stores
don't matter.

### Not for iOS or Android

The mobile OS sandbox prevents any app from reading another app's
cookie store, by design. We won't pretend otherwise. On mobile, use
your browser's built-in privacy settings.

### The honest summary

Cookie Janitor is a good tool for one specific problem — cookies that
are cluttering up your browsers and being handed back to trackers on
every request. It is **not** a complete privacy solution, and nobody who
tells you they sell you one is being straight with you.

---

## Choosing a mode

Cookie Janitor's six modes form a single "aggressiveness" ladder.
Everything a lower mode deletes, a higher mode also deletes. Pick the
one that matches your tolerance for the *"wait, did I just get logged
out?"* risk.

| Mode | What it deletes | Good for |
|---|---|---|
| **Audit only** | Nothing. Lists and classifies cookies but never pre-selects them. | Inspecting your jar without commitment. |
| **Conservative** | Only cookies the Open Cookie Database explicitly classifies as analytics / marketing. | Anyone who'd rather click "delete" manually than risk a logout. |
| **Balanced** *(default)* | Conservative, plus: known third-party tracker domains (`doubleclick.net`, `facebook.net`, …), tracking subdomain labels (`tracking.`, `analytics.`, `ads.`), and well-known tracker cookie names (`_ga`, `_fbp`, `MUID`, `visid_incap_*`). Auth-shape names are still kept. | Most users. Clears the obvious junk without touching sessions. |
| **Strict** | Balanced, plus the Open Cookie Database's *Performance* category (CDN preferences, AB-test buckets, load-balancer affinity tokens). | Privacy-leaning users who don't need persisted UI prefs. |
| **Aggressive** | Strict, plus long-lived (>6 months) non-`HttpOnly` cookies whose name isn't auth-shaped, plus unknown cookies in general (`__Host-`/`__Secure-` still pass). | Users who want a clean jar and don't mind re-logging into the occasional obscure site. |
| **Scorched earth** | Everything except cookies on your allow list and cookies whose name uses the `__Host-` or `__Secure-` prefix. | Starting over. Will log you out of almost every site that doesn't use modern security-prefix cookies. |

Default is **Balanced**. Change from the mode selector at the top of
the main window, or via the CLI (`cookie-janitor list --mode
aggressive`). Each mode has an ⓘ button in the GUI with the same
information as this table but more compact.

---

## Further reading

- [`docs/THREAT_MODEL.md`](THREAT_MODEL.md) — what Cookie Janitor
  defends against as a piece of software, distinct from what it does
  to your cookies.
- [EFF Cover Your Tracks][cyt] — see what trackers know about your
  browser right now.
- [Mozilla's cookie explainer][mdn-cookies] — the vendor-neutral
  technical reference.
- [RFC 6265bis][rfc6265bis] — the current standard governing cookies
  in browsers, including the `__Host-` and `__Secure-` prefixes.

[ublock]: https://ublockorigin.com/
[pb]: https://privacybadger.org/
[ff-etp]: https://support.mozilla.org/en-US/kb/enhanced-tracking-protection-firefox-desktop
[tor]: https://www.torproject.org/
[cyt]: https://coveryourtracks.eff.org/
[mdn-cookies]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
[rfc6265bis]: https://datatracker.ietf.org/doc/draft-ietf-httpbis-rfc6265bis/
