"""Test isolation for GUI integration tests.

The main window schedules the first-launch onboarding modal via
``QTimer.singleShot(0, self._maybe_show_onboarding)`` in
``MainWindow.__init__``. Under ``qtbot``, the event loop spins enough
to fire that timer, and ``OnboardingDialog.exec()`` then blocks
indefinitely with no user to click.

We solve this at the *has-it-been-seen* gate by monkey-patching
``has_seen_onboarding`` to always return True during integration
tests, so ``_maybe_show_onboarding`` returns early without
constructing a modal at all. The dedicated ``test_onboarding.py``
unit tests exercise the real modal with an isolated QSettings scope,
so this override doesn't hide any regression.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _stub_onboarding_already_seen(monkeypatch):
    """Pretend the first-launch modal has already been dismissed so
    integration tests that construct ``MainWindow`` don't hang.
    """
    # Import here (not at module top) so a missing PySide6 doesn't
    # prevent non-Qt integration tests from collecting.
    from cookie_janitor.gui import onboarding, window

    monkeypatch.setattr(onboarding, "has_seen_onboarding", lambda: True)
    # window.py imports the symbol at module load time; patching the
    # onboarding module alone leaves the stale reference in window.
    monkeypatch.setattr(window, "has_seen_onboarding", lambda: True)
