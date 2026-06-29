"""Mode selector widget: six radio buttons in a row, each with an info
button (ⓘ) that opens a detailed explanation. Emits a ``modeChanged``
signal whenever the user picks a different mode.

We deliberately render all six modes as visible peers rather than
hiding them in a dropdown — the user explicitly asked for "explicit
choices in UI" so they can compare at a glance.
"""

from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QButtonGroup,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QRadioButton,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from cookie_janitor.policy.decide import ClassifierMode


@dataclass(frozen=True, slots=True)
class _ModeSpec:
    """Display metadata for one mode. Single source of truth for both
    the radio buttons and the info dialog.
    """

    mode: ClassifierMode
    title: str
    one_liner: str
    details: str


# Order matters: this is what the user sees, left to right.
_SPECS: tuple[_ModeSpec, ...] = (
    _ModeSpec(
        mode=ClassifierMode.AUDIT_ONLY,
        title="Audit only",
        one_liner="Just look",
        details=(
            "Cookies are listed and classified, but nothing is ever ticked"
            " for deletion. Use this to see what's there before deciding"
            " how aggressive to be. The 'Delete selected…' button stays"
            " enabled — you can still tick rows by hand if you want."
        ),
    ),
    _ModeSpec(
        mode=ClassifierMode.CONSERVATIVE,
        title="Conservative",
        one_liner="Only known trackers",
        details=(
            "Deletes only cookies the Open Cookie Database explicitly"
            " classifies as Analytics or Marketing. Anything not in the"
            " database is kept. This was the default behavior in v0.2.x"
            " and is the safest setting — you will almost never get"
            " unexpectedly logged out."
        ),
    ),
    _ModeSpec(
        mode=ClassifierMode.BALANCED,
        title="Balanced",
        one_liner="Recommended for most users",
        details=(
            "Conservative, plus three high-precision rules:\n"
            "• Cookies set on a known third-party tracker domain"
            " (doubleclick.net, facebook.net, hotjar.com, …).\n"
            "• Cookies set on a host with a tracking subdomain label"
            " (tracking.foo.com, analytics.bar.io, ads.baz.example).\n"
            "• Cookies whose name is a well-known tracker"
            " (_ga, _fbp, MUID, visid_incap_*, *_tracking, …).\n\n"
            "Auth-shape names (containing 'session', 'token', 'csrf', etc.)"
            " are exempted from the name rules so you keep your logins."
        ),
    ),
    _ModeSpec(
        mode=ClassifierMode.STRICT,
        title="Strict",
        one_liner="Also clears performance cookies",
        details=(
            "Balanced, plus: also deletes cookies the Open Cookie Database"
            " classifies as Performance (CDN preferences, AB-test buckets,"
            " load-balancer affinity tokens). These are usually harmless,"
            " but they're not strictly necessary for sites to work and"
            " they can leak some information."
        ),
    ),
    _ModeSpec(
        mode=ClassifierMode.AGGRESSIVE,
        title="Aggressive",
        one_liner="Catches the long tail",
        details=(
            "Strict, plus:\n"
            "• Long-lived (>6 months) non-HttpOnly cookies whose name"
            " doesn't look like an auth token.\n"
            "• Unknown cookies in general — anything not classified by any"
            " of the rules above is deleted unless its name has an auth"
            " shape.\n\n"
            "Auth-shape names (session, csrf, token, __Host-*, __Secure-*,"
            " …) are still kept. Expect to occasionally have to re-login"
            " to obscure sites; add them to your allow list when that"
            " happens."
        ),
    ),
    _ModeSpec(
        mode=ClassifierMode.SCORCHED_EARTH,
        title="Scorched earth",
        one_liner="Delete almost everything",
        details=(
            "Deletes every cookie except:\n"
            "• Cookies on a domain in your allow list.\n"
            "• Cookies whose name uses the RFC 6265bis security prefixes"
            " __Host- or __Secure-. (Browsers only let auth-grade cookies"
            " use these prefixes, so modern login systems are safe.)\n\n"
            "This will log you out of almost every site that doesn't use"
            " modern security-prefix cookies. Useful for starting over,"
            " not for daily use."
        ),
    ),
)


class ModePanel(QWidget):
    """Six radio buttons with adjacent (ⓘ) info icons.

    Signal: ``modeChanged(ClassifierMode)`` — emitted only when the user
    picks a different mode (not when ``set_mode`` is called
    programmatically).
    """

    modeChanged = Signal(ClassifierMode)

    def __init__(self, initial: ClassifierMode = ClassifierMode.BALANCED) -> None:
        super().__init__()
        self._buttons: dict[ClassifierMode, QRadioButton] = {}
        self._group = QButtonGroup(self)
        self._group.setExclusive(True)
        self._build_ui()
        self._current = initial
        self._buttons[initial].setChecked(True)
        # Connect AFTER setting initial state so we don't fire modeChanged
        # for the default selection.
        self._group.buttonToggled.connect(self._on_button_toggled)

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        title_row = QHBoxLayout()
        title = QLabel("<b>Aggressiveness</b>")
        title_row.addWidget(title)
        compare_btn = QToolButton()
        compare_btn.setText("ⓘ Compare all modes")
        compare_btn.setAutoRaise(True)
        compare_btn.setToolTip("Open a side-by-side explanation of every mode.")
        compare_btn.clicked.connect(self._show_compare_dialog)
        title_row.addWidget(compare_btn)
        title_row.addStretch(1)
        outer.addLayout(title_row)

        row = QHBoxLayout()
        row.setSpacing(4)
        for spec in _SPECS:
            cell = self._build_cell(spec)
            row.addWidget(cell)
        row.addStretch(1)
        outer.addLayout(row)

    def _build_cell(self, spec: _ModeSpec) -> QFrame:
        """A radio button + an info button + a one-line subtitle."""
        frame = QFrame()
        frame.setFrameShape(QFrame.Shape.StyledPanel)
        cell_layout = QVBoxLayout(frame)
        cell_layout.setContentsMargins(6, 4, 6, 4)
        cell_layout.setSpacing(2)

        header = QHBoxLayout()
        header.setSpacing(2)
        rb = QRadioButton(spec.title)
        rb.setToolTip(spec.one_liner)
        self._buttons[spec.mode] = rb
        self._group.addButton(rb)
        header.addWidget(rb)
        info = QToolButton()
        info.setText("ⓘ")
        info.setAutoRaise(True)
        info.setToolTip(f"What does {spec.title} mean?")
        info.clicked.connect(lambda _checked=False, s=spec: self._show_info(s))
        header.addWidget(info)
        cell_layout.addLayout(header)

        subtitle = QLabel(f"<small>{spec.one_liner}</small>")
        subtitle.setEnabled(False)
        cell_layout.addWidget(subtitle)

        return frame

    def _on_button_toggled(self, btn: QRadioButton, checked: bool) -> None:
        if not checked:
            return
        for mode, candidate in self._buttons.items():
            if candidate is btn and mode is not self._current:
                self._current = mode
                self.modeChanged.emit(mode)
                return

    def set_mode(self, mode: ClassifierMode) -> None:
        """Programmatically select a mode without firing ``modeChanged``."""
        if mode is self._current:
            return
        self._group.blockSignals(True)
        self._buttons[mode].setChecked(True)
        self._group.blockSignals(False)
        self._current = mode

    def current_mode(self) -> ClassifierMode:
        return self._current

    def _show_info(self, spec: _ModeSpec) -> None:
        QMessageBox.information(
            self,
            f"{spec.title} mode",
            f"<b>{spec.title}</b> — {spec.one_liner}<br><br>{spec.details}".replace(
                "\n", "<br>"
            ),
        )

    def _show_compare_dialog(self) -> None:
        rows = "".join(
            f"<tr><td><b>{s.title}</b></td><td>{s.one_liner}</td></tr>"
            for s in _SPECS
        )
        body = (
            "<table cellpadding='6' cellspacing='0' border='0'>"
            + rows
            + "</table>"
            "<br><i>Click the ⓘ next to a mode for the full explanation.</i>"
            "<br><br>Allow-list matches always win, in every mode."
        )
        QMessageBox.information(self, "Classifier modes", body)
