"""Non-modal ``Cookies 101…`` dialog.

The dialog is the in-app "quick guide to what's on your machine" — the
medium-length version of the content that lives long-form at
:file:`docs/COOKIES-101.md`. It's opened from the Help menu, and also
from the first-launch onboarding modal via its "Read Cookies 101"
button.

Design contract:

* The two documents are consistent by construction — the mode table
  here uses the same six mode titles that :mod:`.mode_panel` ships as
  radio buttons, so users don't see one story in the ⓘ tooltip and a
  different story on this page.
* Non-modal: the dialog does not block the main window. A user can
  leave it open, click through cookies in the main table, and come
  back to the guide — the intended flow for teaching.
* No network access. The content is embedded as a Python constant; the
  only outward links are ``QTextBrowser`` HTML anchors that open in
  the OS default browser via :meth:`QDesktopServices.openUrl`.
* No writable state. The dialog is read-only; nothing here persists.
"""

from __future__ import annotations

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QTextBrowser,
    QVBoxLayout,
)

_LONG_FORM_URL = "https://github.com/sgireddy/cookie-janitor/blob/main/docs/COOKIES-101.md"


# HTML content for the dialog. This is a MEDIUM-length subset of
# docs/COOKIES-101.md — the ~1200-word review-approved copy, with the
# corrected six-mode table lifted verbatim from mode_panel.py's
# _ModeSpec entries so the two surfaces cannot drift.
#
# When updating the wording here, update docs/COOKIES-101.md too; the
# unit test asserts a set of key phrases appear in this constant so
# accidental deletions get caught in CI.
_HTML_CONTENT = """\
<h2>Cookies 101 — the good, the bad, and the ugly</h2>

<p><b>TL;DR</b> — Websites drop small text files ("cookies") in your
browser to remember things. Some are useful (they keep you logged in).
Some are neutral (they remember your dark-mode preference). Many are
designed to track you across the web, and those are the ones Cookie
Janitor targets. Cleaning cookies is one useful privacy step, but not a
complete one — this page tells you what it does and doesn't cover.</p>

<h3>What is a cookie, really?</h3>

<p>A cookie is a small piece of text that a website asks your browser
to store, and hands back to that website every time you visit. Nothing
more magical than that. When you sign into Gmail and close the tab,
Google's server sends your browser a cookie containing something like
<code>SID=xy8...</code>. Next time you open Gmail, your browser hands
that cookie back, and Google's server recognises you without asking
for a password again.</p>

<p>Cookies were invented in 1994 to solve exactly this problem — the
web is otherwise stateless, and every page load looks like a stranger
arriving. Without cookies, every site would forget you the moment you
clicked a link.</p>

<p>The trouble is: the same mechanism that keeps you logged in can
also be used to follow you around, and over 30 years the industry has
become extremely good at the second use.</p>

<h3>🟢 The Good — cookies you want to keep</h3>

<p><b>Session and authentication cookies.</b> These are what "keep me
logged in" means. Delete them and you'll be signing back into
everything tomorrow morning. Common shapes: names containing
<code>sess</code>, <code>auth</code>, <code>token</code>,
<code>sid</code>; usually flagged <code>HttpOnly</code> and
<code>Secure</code>; often set to expire in a few weeks or on browser
close.</p>

<p><b>Preference cookies.</b> These remember choices you made
deliberately. YouTube's dark-mode setting. Your language on a site
that supports multiple. Your timezone on a booking site. Deleting them
is harmless but mildly annoying — you'll re-pick your preferences next
visit.</p>

<p><b>Shopping-cart cookies.</b> For sites that let you browse without
an account, your cart lives in a cookie. Delete it mid-shop and you
lose your cart. (For sites where you're signed in, the cart is
server-side and cookie-independent.)</p>

<p><b>What Cookie Janitor does:</b> keeps them. Our classifier looks
at cookie names, domains, and flags to detect the auth-shape and
preference-shape patterns, and leaves those alone even in aggressive
modes. You'll stay signed into Gmail.</p>

<h3>🟡 The Bad — cookies you probably don't need</h3>

<p><b>First-party analytics.</b> The site's own measurement of how you
use it. Which pages you visit, how long you stay, where you clicked.
Google Analytics running on <code>example.com</code>'s own domain
drops cookies like <code>_ga</code>, <code>_gid</code>,
<code>_gat_*</code>. These aren't inherently sinister — the site
owner is trying to understand their traffic — but they're also not
doing anything for you. Deleting them costs you nothing.</p>

<p><b>A/B test bucket cookies.</b> Sites run experiments and use
cookies to remember which experimental variant you saw so your
experience stays consistent within a session. Names often look like
<code>_optimizely_*</code>, <code>_vwo_*</code>,
<code>ajs_anonymous_id</code>. Delete them and you might see a
slightly different layout on your next visit, but nothing breaks.</p>

<p><b>Anti-bot / rate-limit cookies.</b> CAPTCHAs and DDoS-protection
services (Cloudflare's <code>__cf_bm</code>, hCaptcha's
<code>hcaptcha</code>) drop cookies to remember "we've already
verified this human." Delete them and you might have to click a
CAPTCHA one more time. Minor cost.</p>

<p><b>What Cookie Janitor does:</b> in <i>Balanced</i> (the default)
and above, cleans them. In <i>Conservative</i>, keeps them. Your
choice.</p>

<h3>🔴 The Ugly — cookies designed against you</h3>

<p><b>Third-party tracking cookies.</b> This is the main event. When a
site embeds anything served from a different domain — an ad, a "share
on Facebook" button, an embedded YouTube video, a Google Fonts import
— that third party's server can drop its own cookie on your browser.
When you visit a different site that also embeds anything from that
same third party, your browser hands back the same cookie. That's how
a single company builds a profile of everywhere you go.</p>

<p>The classic examples: Google's <code>IDE</code> and
<code>NID</code> cookies (DoubleClick ad network), Meta's
<code>fr</code> cookie (Facebook Pixel), and hundreds of ad-tech
companies you've never heard of via cookies like <code>uid</code>,
<code>visitor_id</code>, <code>_pinterest_ct_ua</code>. A single
ordinary news-site page load can drop cookies from 20+ third
parties.</p>

<p><b>Retargeting pixels.</b> When you look at a product on one site
and then see ads for it everywhere for two weeks, that's retargeting.
It works via a third-party cookie set when you viewed the product,
read on the ad networks' pages elsewhere.</p>

<p><b>Cookie-banner cookies.</b> The banner itself typically drops a
cookie to remember what you clicked. Most banners are compliance
theatre — they record your click but do very little to actually change
what happens next. Some sites use "legitimate interest" checkboxes
that opt you in by default regardless of your choice.</p>

<p><b>What Cookie Janitor does:</b> cleans them all, aggressively, in
every mode from Balanced upward. This is the primary target.</p>

<h3>What Cookie Janitor is NOT</h3>

<p>Being honest about scope matters more than sounding capable:</p>

<ul>
<li><b>Not a tracker blocker.</b> We delete cookies after they've
been set. Trackers still ran their JavaScript. If you want to prevent
cookies from being set at all, install
<a href="https://ublockorigin.com/">uBlock Origin</a> or
<a href="https://privacybadger.org/">Privacy Badger</a>. Cookie Janitor
complements them, not replaces them.</li>
<li><b>Not fingerprinting protection.</b> Trackers can identify you
without cookies via screen size, fonts, GPU, timezone. If this worries
you, look at
<a href="https://support.mozilla.org/en-US/kb/enhanced-tracking-protection-firefox-desktop">Firefox
Enhanced Tracking Protection</a> (Strict) or the
<a href="https://www.torproject.org/">Tor Browser</a>.</li>
<li><b>Not IP-address hiding.</b> Sites see your IP whether or not
they set cookies. For that, use a VPN or Tor.</li>
<li><b>Not localStorage / IndexedDB / cache hygiene.</b> Browsers
have half a dozen other storage mechanisms besides cookies. Some
trackers have moved to those. Cookie Janitor only handles cookies —
a scope choice for reliability.</li>
</ul>

<p><b>The honest summary:</b> Cookie Janitor is a good tool for one
specific problem — cookies that are cluttering up your browsers and
being handed back to trackers on every request. It is not a complete
privacy solution, and nobody who tells you they sell you one is
being straight with you.</p>

<h3>Choosing a mode</h3>

<p>Six modes on a single ladder. Everything a lower mode deletes, a
higher mode also deletes.</p>

<table border="1" cellspacing="0" cellpadding="6">
<tr>
  <th>Mode</th>
  <th>What it deletes</th>
  <th>Good for</th>
</tr>
<tr>
  <td><b>Audit only</b></td>
  <td>Nothing. Lists and classifies cookies but never pre-selects them.</td>
  <td>Inspecting your jar without commitment.</td>
</tr>
<tr>
  <td><b>Conservative</b></td>
  <td>Only cookies the Open Cookie Database explicitly classifies as
      analytics / marketing.</td>
  <td>Anyone who'd rather click "delete" manually than risk a logout.</td>
</tr>
<tr>
  <td><b>Balanced</b> <i>(default)</i></td>
  <td>Conservative, plus known third-party tracker domains
      (<code>doubleclick.net</code>, <code>facebook.net</code>, …),
      tracking subdomain labels (<code>tracking.</code>,
      <code>analytics.</code>, <code>ads.</code>), and well-known
      tracker cookie names (<code>_ga</code>, <code>_fbp</code>,
      <code>MUID</code>, <code>visid_incap_*</code>). Auth-shape names
      are still kept.</td>
  <td>Most users. Clears the obvious junk without touching sessions.</td>
</tr>
<tr>
  <td><b>Strict</b></td>
  <td>Balanced, plus the Open Cookie Database's <i>Performance</i>
      category (CDN preferences, AB-test buckets, load-balancer
      affinity tokens).</td>
  <td>Privacy-leaning users who don't need persisted UI prefs.</td>
</tr>
<tr>
  <td><b>Aggressive</b></td>
  <td>Strict, plus long-lived (&gt;6 months) non-<code>HttpOnly</code>
      cookies whose name isn't auth-shaped, plus unknown cookies in
      general (<code>__Host-</code>/<code>__Secure-</code> still pass).</td>
  <td>Users who want a clean jar and don't mind re-logging into the
      occasional obscure site.</td>
</tr>
<tr>
  <td><b>Scorched earth</b></td>
  <td>Everything except cookies on your allow list and cookies whose
      name uses the <code>__Host-</code> or <code>__Secure-</code>
      prefix.</td>
  <td>Starting over. Will log you out of almost every site that
      doesn't use modern security-prefix cookies.</td>
</tr>
</table>

<p>Default is <b>Balanced</b>. Change from the mode selector at the
top of the main window.</p>

<h3>Further reading</h3>

<ul>
<li><a href="{long_form_url}">The long-form version of this page</a>
    — includes a "Cookies and pricing" aside, more on the law, and
    references.</li>
<li><a href="https://coveryourtracks.eff.org/">EFF's Cover Your
    Tracks</a> — see what trackers know about your browser right now.</li>
<li><a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies">Mozilla's
    cookie explainer</a> — the vendor-neutral technical reference.</li>
</ul>
""".replace("{long_form_url}", _LONG_FORM_URL)


class Cookies101Dialog(QDialog):
    """The Help → Cookies 101… dialog.

    Non-modal: the caller opens it with :meth:`show` (not :meth:`exec`),
    so the main window stays interactive. Callers who want a
    parent-owned lifecycle should pass ``parent`` at construction so
    the dialog is destroyed when the main window is.
    """

    def __init__(self, parent: object = None) -> None:
        super().__init__(parent)  # type: ignore[arg-type]
        self.setWindowTitle("Cookies 101")
        self.setMinimumSize(720, 600)
        self._build_ui()

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)

        # QTextBrowser renders a subset of HTML, follows <a href> links
        # via anchorClicked, and supports scrolling out of the box.
        # No JavaScript, no images, no cookies (yes, really — the widget
        # would happily set some if asked; we don't ask).
        self._body = QTextBrowser()
        self._body.setOpenExternalLinks(False)  # we route via anchorClicked
        self._body.setOpenLinks(False)
        self._body.setHtml(_HTML_CONTENT)
        self._body.anchorClicked.connect(self._open_url_externally)
        outer.addWidget(self._body, stretch=1)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        # StandardButton.Close emits `rejected`, not `accepted`, in Qt.
        buttons.button(QDialogButtonBox.StandardButton.Close).clicked.connect(self.reject)
        outer.addWidget(buttons)

    @staticmethod
    def _open_url_externally(url: QUrl) -> None:
        """Route link clicks to the OS default browser rather than
        rendering them inside the QTextBrowser (which would look
        broken — no styling, no JS, no cookies).
        """
        QDesktopServices.openUrl(url)
