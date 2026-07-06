"""First-launch onboarding modal.

Shown at most once per machine (per QSettings scope), teasing the
Cookies 101 content and offering a jump into the full dialog. The
"seen" flag is set in *every* dismissal path — Read, Skip, or
titlebar-close — because clicking-away is a valid "don't nag me"
signal.

Design contract:

* Once shown, never shown again. No "show at startup" checkbox — that
  adds decision fatigue for a modal shown a single time in a machine's
  lifetime.
* The flag lives under
  :attr:`ONBOARDING_SETTINGS_KEY` in the app's :class:`QSettings`. To
  reset (e.g. for QA), the user or a script can call
  :func:`reset_onboarding_flag` or delete the platform-native settings
  store (macOS: ``defaults delete``, Linux: ``~/.config/Cookie
  Janitor.conf``, Windows: registry HKCU\\Software\\Cookie Janitor).
* Never a hard blocker. The main window has already been shown before
  this modal appears (deferred via ``QTimer.singleShot``), so if the
  user quits by X'ing the modal the app is still usable behind it.
"""

from __future__ import annotations

from PySide6.QtCore import QSettings, Qt
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
)

ONBOARDING_SETTINGS_KEY = "ui/cookies_101_seen"


def has_seen_onboarding(settings: QSettings | None = None) -> bool:
    """Return ``True`` if the onboarding modal has already been shown.

    ``settings`` may be passed for testability; in production callers
    default to a QSettings built from the app-wide organization /
    application name set in :mod:`.app`.
    """
    s = settings or QSettings()
    # QSettings.value returns Any; the boolean-typed getter takes a
    # default that also dictates the return type. On Windows the
    # underlying store is the registry (which round-trips bools as
    # QVariant.Bool); on Linux it's an INI file (strings); the type
    # hint keeps mypy honest.
    return bool(s.value(ONBOARDING_SETTINGS_KEY, False, type=bool))


def mark_onboarding_seen(settings: QSettings | None = None) -> None:
    """Persist that the user has seen the onboarding modal.

    All three dismissal paths in :class:`OnboardingDialog` call this,
    including titlebar-close, so an X-click is not a "nag me again"
    request.
    """
    s = settings or QSettings()
    s.setValue(ONBOARDING_SETTINGS_KEY, True)
    # Force the store to disk immediately. Without sync(), a crash
    # between "setValue" and the next natural flush would cause the
    # modal to reappear next launch — mild but exactly the annoyance
    # we're trying to avoid.
    s.sync()


def reset_onboarding_flag(settings: QSettings | None = None) -> None:
    """Delete the seen-flag. Used by tests; useful as a manual QA
    action too. Intentionally NOT wired into a menu item to keep the
    "shown once" contract honest.
    """
    s = settings or QSettings()
    s.remove(ONBOARDING_SETTINGS_KEY)
    s.sync()


class OnboardingDialog(QDialog):
    """The ~55-word first-launch teaser modal.

    Two outcomes the caller cares about:

    * :meth:`user_wants_to_read` — did the user click "Read Cookies
      101" (in which case the caller should open
      :class:`.cookies_101_dialog.Cookies101Dialog`)?
    * The seen-flag has been set regardless of which button the user
      pressed, including titlebar-close.

    The dialog is modal — it takes focus over the main window until
    the user chooses. Since it's shown at most once per machine and
    the buttons are two clicks large, this isn't the modal-onslaught
    pattern that users hate.
    """

    def __init__(self, parent: object = None) -> None:
        super().__init__(parent)  # type: ignore[arg-type]
        self.setWindowTitle("Welcome to Cookie Janitor")
        self.setModal(True)
        self.setMinimumWidth(480)
        self._user_wants_to_read = False
        self._build_ui()

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 20, 24, 20)
        outer.setSpacing(14)

        title = QLabel("<h3>Welcome to Cookie Janitor</h3>")
        title.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)
        outer.addWidget(title)

        body = QLabel(
            "Cookie Janitor removes tracking cookies while keeping the"
            " ones that keep you signed in. It doesn't stop all tracking"
            " — just the cookie-based kind."
            "<br><br>"
            "If you're new to what cookies actually do, a 3-minute read"
            " will make the rest of this app make more sense."
            "<br><br>"
            "<small>This won't appear again. You can re-open it from"
            " Help → Cookies 101.</small>"
        )
        body.setWordWrap(True)
        body.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)
        outer.addWidget(body)

        row = QHBoxLayout()
        row.addStretch(1)
        self._skip_btn = QPushButton("Skip — I know what I'm doing")
        self._skip_btn.clicked.connect(self._on_skip)
        row.addWidget(self._skip_btn)

        self._read_btn = QPushButton("📖 Read Cookies 101")
        self._read_btn.setDefault(True)
        self._read_btn.clicked.connect(self._on_read)
        row.addWidget(self._read_btn)
        outer.addLayout(row)

    # --- Button handlers --------------------------------------------------

    def _on_read(self) -> None:
        self._user_wants_to_read = True
        mark_onboarding_seen()
        self.accept()

    def _on_skip(self) -> None:
        self._user_wants_to_read = False
        mark_onboarding_seen()
        self.reject()

    # --- Public API -------------------------------------------------------

    def user_wants_to_read(self) -> bool:
        """Return whether the user clicked the "Read Cookies 101"
        button. False for every other dismissal path (Skip,
        titlebar-X, Esc).
        """
        return self._user_wants_to_read

    # --- Close intercept --------------------------------------------------

    def closeEvent(self, event: QCloseEvent) -> None:
        """Any dismissal path — including titlebar-X and Esc — counts
        as "user has seen it", so the modal never reappears.

        This runs after the button handlers on the button paths (they
        call accept()/reject() which triggers closeEvent) and is
        idempotent because ``mark_onboarding_seen`` just re-writes
        the same value.
        """
        mark_onboarding_seen()
        super().closeEvent(event)
