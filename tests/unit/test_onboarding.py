"""Tests for the first-launch onboarding modal.

We verify the *shown-once* contract on all three dismissal paths
(Read / Skip / titlebar-close) since the property that annoys users
most is a modal that keeps reappearing.

Isolation strategy: every test uses a fresh ``QSettings`` scoped to a
throwaway organization + application name, so the tests can never
touch a developer's real Cookie Janitor settings file. The
production code calls ``QSettings()`` with no args, which uses the
process-wide organization/application set in
:func:`cookie_janitor.gui.app.main`. In tests we override those on the
QCoreApplication before constructing the QSettings-users under test.
"""

from __future__ import annotations

import os
import uuid

import pytest

pytest.importorskip("PySide6")

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QCoreApplication, QSettings

from cookie_janitor.gui.onboarding import (
    ONBOARDING_SETTINGS_KEY,
    OnboardingDialog,
    has_seen_onboarding,
    mark_onboarding_seen,
    reset_onboarding_flag,
)


@pytest.fixture
def isolated_settings(qtbot):
    """Scope QSettings to a per-test throwaway organization so we can't
    leak into (or read from) a developer's real Cookie Janitor
    settings.

    Uses UUID-derived names so parallel pytest workers don't collide.
    The teardown wipes the throwaway settings store.
    """
    org = f"cookie-janitor-test-{uuid.uuid4()}"
    app = "OnboardingTest"
    prev_org = QCoreApplication.organizationName()
    prev_app = QCoreApplication.applicationName()
    QCoreApplication.setOrganizationName(org)
    QCoreApplication.setApplicationName(app)
    # Ensure a clean slate — QSettings persists across pytest runs on
    # the same machine otherwise.
    QSettings().clear()
    yield
    QSettings().clear()
    QCoreApplication.setOrganizationName(prev_org)
    QCoreApplication.setApplicationName(prev_app)


def test_has_seen_defaults_false(isolated_settings):
    assert has_seen_onboarding() is False


def test_mark_seen_flips_flag(isolated_settings):
    assert has_seen_onboarding() is False
    mark_onboarding_seen()
    assert has_seen_onboarding() is True


def test_reset_flag(isolated_settings):
    mark_onboarding_seen()
    assert has_seen_onboarding() is True
    reset_onboarding_flag()
    assert has_seen_onboarding() is False


def test_read_button_marks_seen_and_reports_user_wants_to_read(qtbot, isolated_settings):
    dlg = OnboardingDialog()
    qtbot.addWidget(dlg)
    dlg._on_read()
    assert has_seen_onboarding() is True
    assert dlg.user_wants_to_read() is True


def test_skip_button_marks_seen_but_does_not_want_to_read(qtbot, isolated_settings):
    dlg = OnboardingDialog()
    qtbot.addWidget(dlg)
    dlg._on_skip()
    assert has_seen_onboarding() is True
    assert dlg.user_wants_to_read() is False


def test_titlebar_close_also_marks_seen(qtbot, isolated_settings):
    """The X on the titlebar is a valid "don't nag me" signal. The
    dialog's closeEvent must flip the flag regardless of whether the
    user pressed a button.
    """
    dlg = OnboardingDialog()
    qtbot.addWidget(dlg)
    assert has_seen_onboarding() is False
    dlg.close()  # triggers closeEvent
    assert has_seen_onboarding() is True
    assert dlg.user_wants_to_read() is False


def test_settings_key_is_stable(isolated_settings):
    """The key string is part of the persistence contract — if it
    changes across releases, users see the onboarding modal a second
    time on upgrade. This test pins the string.
    """
    assert ONBOARDING_SETTINGS_KEY == "ui/cookies_101_seen"


def test_second_construction_after_seen_does_not_re_prompt(qtbot, isolated_settings):
    """The window relies on ``has_seen_onboarding()`` for the "should
    I show the modal at all?" gate. This test verifies that once the
    modal has been dismissed (any path), the gate returns True — the
    modal would not be re-shown.
    """
    dlg = OnboardingDialog()
    qtbot.addWidget(dlg)
    dlg._on_skip()
    # Simulate a subsequent launch: the gate is checked, and it's now
    # True, so the app skips constructing a second modal at all.
    assert has_seen_onboarding() is True
