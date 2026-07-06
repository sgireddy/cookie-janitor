"""Tests for the Cookies 101 dialog.

These are content-integrity tests, not pixel tests. They verify:

* The dialog constructs and renders without error under the offscreen
  Qt platform.
* Every one of the six classifier modes is named in the body — the
  bug we've explicitly designed against is the dialog going out of
  sync with :mod:`cookie_janitor.gui.mode_panel` and showing a mode
  set that doesn't match the radio buttons.
* Key content phrases are present, so an accidental delete of the
  "What Cookie Janitor is NOT" section (or similar) fails CI instead
  of shipping a hollow dialog.
* Links are anchored (not just plain text) so users can actually
  reach the referenced tools.
"""

from __future__ import annotations

import os

import pytest

pytest.importorskip("PySide6")

# Force the offscreen platform so we don't need a display server.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from cookie_janitor.gui.cookies_101_dialog import (
    _HTML_CONTENT,
    Cookies101Dialog,
)
from cookie_janitor.policy.decide import ClassifierMode


def test_dialog_constructs(qtbot):
    dlg = Cookies101Dialog()
    qtbot.addWidget(dlg)
    assert dlg.windowTitle() == "Cookies 101"
    # Non-modal is a design contract (see docstring). If someone flips
    # it in a refactor we want the test to catch it — modal blocks the
    # main window, which defeats "read this while clicking cookies".
    assert not dlg.isModal()


def test_body_contains_all_six_mode_titles():
    """Every mode shipped in ``ClassifierMode`` must appear in the
    dialog text. If a new mode is added, the dialog copy must be
    updated too — this test forces that discipline.
    """
    # Map enum -> the exact display title the mode_panel radio button
    # uses. The dialog table uses these SAME strings verbatim so users
    # don't see one thing in the tooltip and another in the guide.
    expected_titles = {
        ClassifierMode.AUDIT_ONLY: "Audit only",
        ClassifierMode.CONSERVATIVE: "Conservative",
        ClassifierMode.BALANCED: "Balanced",
        ClassifierMode.STRICT: "Strict",
        ClassifierMode.AGGRESSIVE: "Aggressive",
        ClassifierMode.SCORCHED_EARTH: "Scorched earth",
    }
    for mode, title in expected_titles.items():
        assert title in _HTML_CONTENT, (
            f"Mode {mode.name} ({title!r}) missing from dialog body — "
            f"dialog and mode_panel have drifted."
        )


def test_body_names_no_fictional_modes():
    """The prose that seeded this doc mentioned three mode names that
    don't exist in the code — "Nuke", "First-party only", "Third-party
    only". If any of those slip back into the copy, we want to catch
    it here.
    """
    fictional = ["Nuke", "First-party only", "Third-party only"]
    for name in fictional:
        assert name not in _HTML_CONTENT, (
            f"Dialog body contains fictional mode {name!r} — check "
            f"that the mode table matches mode_panel._SPECS."
        )


def test_body_contains_key_sections():
    """Guardrail against accidental section deletion during editing."""
    for phrase in [
        # Top-of-page framing
        "TL;DR",
        "What is a cookie",
        # The three verdict buckets
        "The Good",
        "The Bad",
        "The Ugly",
        # Scope-honesty section
        "Cookie Janitor is NOT",
        # Concrete tracker names (factual, not editorial)
        "_ga",
        "IDE",
        "fr",
        # Mode table anchor
        "Choosing a mode",
        # Cross-references to complementary tools
        "uBlock Origin",
        "Privacy Badger",
        "Tor Browser",
    ]:
        assert phrase in _HTML_CONTENT, f"Missing key phrase: {phrase!r}"


def test_body_links_out_to_long_form_doc():
    # The dialog is the medium version; the long form has the pricing
    # aside and legal paragraph. Users should be able to reach it.
    assert "COOKIES-101.md" in _HTML_CONTENT
    assert "https://github.com/sgireddy/cookie-janitor" in _HTML_CONTENT


def test_links_are_html_anchors_not_bare_urls():
    """Every reference to a complementary tool should be a clickable
    ``<a href>`` — bare-URL text is technically visible in
    QTextBrowser but doesn't route through ``anchorClicked``, so the
    OS-default-browser hand-off wouldn't happen.
    """
    for tool, expected_href_fragment in [
        ("uBlock Origin", "ublockorigin.com"),
        ("Privacy Badger", "privacybadger.org"),
        ("Firefox Enhanced Tracking Protection", "mozilla.org"),
        ("Tor Browser", "torproject.org"),
    ]:
        assert (
            f'href="https://{expected_href_fragment}' in _HTML_CONTENT
            or f'href="https://www.{expected_href_fragment}' in _HTML_CONTENT
            or f'href="https://support.{expected_href_fragment}' in _HTML_CONTENT
        ), f"{tool} isn't linked to {expected_href_fragment}"


def test_dialog_renders_body_text(qtbot):
    """The dialog's ``QTextBrowser`` must actually contain the copy —
    catches the case where the widget is instantiated but the HTML
    setter silently fails (has happened in Qt on empty fragments).
    """
    dlg = Cookies101Dialog()
    qtbot.addWidget(dlg)
    body_text = dlg._body.toPlainText()
    assert "Cookies 101" in body_text
    assert "Balanced" in body_text
    # A conservative lower bound — the medium-length copy is ~1200
    # words which round-trips to ~5000+ chars in QTextBrowser. If we
    # somehow shipped a truncated body it would fail here.
    assert len(body_text) > 2000, f"Dialog body suspiciously short: {len(body_text)} chars"
