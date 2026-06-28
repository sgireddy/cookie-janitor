"""Main window: profile picker, cookie table, filter chips, delete button."""

from __future__ import annotations

import importlib.resources
import logging

from PySide6.QtCore import QSortFilterProxyModel, Qt
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from cookie_janitor import __version__
from cookie_janitor.classify.cookie_db import CookieDatabase, load_database
from cookie_janitor.model.cookie import Decision, Profile, Verdict
from cookie_janitor.policy.decide import UserPolicy, decide
from cookie_janitor.readers import firefox as firefox_reader
from cookie_janitor.writers.firefox import delete_cookies

from .model import CookiesModel

log = logging.getLogger(__name__)


def _load_cookie_db() -> CookieDatabase:
    files = importlib.resources.files("cookie_janitor.data")
    with importlib.resources.as_file(files / "cookie_db_seed.csv") as path:
        return load_database(path)


def _scan_profiles() -> list[Profile]:
    return firefox_reader.discover_profiles()


def _decisions_for(profile: Profile, db: CookieDatabase) -> list[Decision]:
    policy = UserPolicy()
    cookies = firefox_reader.read_cookies(profile)
    return [decide(c, policy=policy, cookie_db=db) for c in cookies]


class MainWindow(QMainWindow):
    """Top-level window.

    The empty-state (no profiles, or first launch) lives here too: we
    surface clear guidance rather than a blank table.
    """

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"Cookie Janitor {__version__}")
        self.resize(1100, 700)

        self._db = _load_cookie_db()
        self._profiles: list[Profile] = []
        self._model: CookiesModel | None = None
        self._proxy = QSortFilterProxyModel(self)
        self._proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        # Filter against domain (col 3) + name (col 4) + rationale (col 6).
        self._proxy.setFilterKeyColumn(-1)

        self._build_ui()
        self._build_menu()
        self._refresh_profiles()

    # --- UI construction ---------------------------------------------------

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        outer = QVBoxLayout(central)

        # Header: profile picker + refresh.
        header = QHBoxLayout()
        header.addWidget(QLabel("Profile:"))
        self._profile_box = QComboBox()
        self._profile_box.setMinimumWidth(380)
        self._profile_box.currentIndexChanged.connect(self._on_profile_changed)
        header.addWidget(self._profile_box)
        self._refresh_btn = QPushButton("Refresh")
        self._refresh_btn.clicked.connect(self._refresh_profiles)
        header.addWidget(self._refresh_btn)
        header.addStretch(1)
        outer.addLayout(header)

        # Search box.
        search_row = QHBoxLayout()
        search_row.addWidget(QLabel("Search:"))
        self._search = QLineEdit()
        self._search.setPlaceholderText("Filter by domain, name, or reason…")
        self._search.textChanged.connect(self._proxy.setFilterFixedString)
        search_row.addWidget(self._search)
        outer.addLayout(search_row)

        # The table.
        self._table = QTableView()
        self._table.setModel(self._proxy)
        self._table.setSortingEnabled(True)
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.setWordWrap(True)
        outer.addWidget(self._table, stretch=1)

        # Footer: status + selection helpers + delete.
        footer = QHBoxLayout()
        self._status = QLabel("")
        self._status.setObjectName("status")
        footer.addWidget(self._status, stretch=1)

        self._select_default_btn = QPushButton("Select recommended")
        self._select_default_btn.setToolTip(
            "Tick every cookie the recommendation column marks as Delete."
        )
        self._select_default_btn.clicked.connect(self._select_default)
        footer.addWidget(self._select_default_btn)

        self._clear_btn = QPushButton("Clear selection")
        self._clear_btn.clicked.connect(self._clear_selection)
        footer.addWidget(self._clear_btn)

        self._delete_btn = QPushButton("Delete selected…")
        self._delete_btn.setStyleSheet(
            "QPushButton { background:#c62828; color:white; padding:6px 16px;"
            " font-weight:600; border-radius:6px; }"
            "QPushButton:disabled { background:#bbb; }"
        )
        self._delete_btn.clicked.connect(self._on_delete_clicked)
        footer.addWidget(self._delete_btn)
        outer.addLayout(footer)

    def _build_menu(self) -> None:
        menu = self.menuBar().addMenu("&File")
        about_action = QAction("&About Cookie Janitor", self)
        about_action.triggered.connect(self._show_about)
        menu.addAction(about_action)
        quit_action = QAction("&Quit", self)
        quit_action.setShortcut("Ctrl+Q")
        quit_action.triggered.connect(self.close)
        menu.addAction(quit_action)

    # --- Data flow ---------------------------------------------------------

    def _refresh_profiles(self) -> None:
        self._profiles = _scan_profiles()
        self._profile_box.blockSignals(True)
        self._profile_box.clear()
        if not self._profiles:
            self._profile_box.addItem("No Firefox profile found")
            self._set_status_empty(
                "Cookie Janitor couldn't find a Firefox profile on this Mac yet."
                " Install Firefox and visit a few sites, then click Refresh."
            )
        else:
            for p in self._profiles:
                label = f"{p.display}"
                if p.is_running:
                    label += "  (currently running — close it to delete)"
                self._profile_box.addItem(label)
        self._profile_box.blockSignals(False)

        if self._profiles:
            self._on_profile_changed(0)

    def _on_profile_changed(self, idx: int) -> None:
        if not self._profiles or idx < 0:
            return
        profile = self._profiles[idx]
        try:
            decisions = _decisions_for(profile, self._db)
        except Exception as exc:  # surface real errors instead of silent fail
            log.exception("Failed to read cookies for %s", profile.display)
            QMessageBox.warning(
                self,
                "Couldn't read cookies",
                f"Cookie Janitor couldn't read cookies for {profile.display}:\n\n{exc}",
            )
            decisions = []

        self._model = CookiesModel(decisions)
        self._proxy.setSourceModel(self._model)
        self._table.setColumnWidth(0, 30)
        self._table.setColumnWidth(1, 130)
        self._table.setColumnWidth(2, 110)
        self._table.setColumnWidth(3, 200)
        self._table.setColumnWidth(4, 180)
        self._table.setColumnWidth(5, 100)
        self._update_status()

        self._delete_btn.setEnabled(not profile.is_running and bool(decisions))
        tip = (
            "Quit Firefox first, then click Refresh."
            if profile.is_running
            else "Delete the ticked cookies. A backup is made first."
        )
        self._delete_btn.setToolTip(tip)

    def _update_status(self) -> None:
        if not self._model:
            return
        decisions = self._model.decisions()
        total = len(decisions)
        delete_count = sum(1 for d in decisions if d.verdict is Verdict.DELETE)
        keep_count = sum(1 for d in decisions if d.verdict is Verdict.KEEP)
        selected = len(self._model.selected_decisions())
        self._status.setText(
            f"<b>{total}</b> cookies — recommended: keep {keep_count}, delete {delete_count}."
            f" <b>{selected}</b> currently ticked for deletion."
        )
        # Update count live as user toggles.
        self._model.dataChanged.connect(self._update_count_only)

    def _update_count_only(self) -> None:
        if not self._model:
            return
        decisions = self._model.decisions()
        total = len(decisions)
        delete_count = sum(1 for d in decisions if d.verdict is Verdict.DELETE)
        keep_count = sum(1 for d in decisions if d.verdict is Verdict.KEEP)
        selected = len(self._model.selected_decisions())
        self._status.setText(
            f"<b>{total}</b> cookies — recommended: keep {keep_count}, delete {delete_count}."
            f" <b>{selected}</b> currently ticked for deletion."
        )

    def _set_status_empty(self, msg: str) -> None:
        self._status.setText(msg)
        self._delete_btn.setEnabled(False)

    # --- Actions -----------------------------------------------------------

    def _select_default(self) -> None:
        if self._model:
            self._model.select_default()
            self._update_count_only()

    def _clear_selection(self) -> None:
        if self._model:
            self._model.set_all_selected(selected=False)
            self._update_count_only()

    def _on_delete_clicked(self) -> None:
        if not self._model or not self._profiles:
            return
        idx = self._profile_box.currentIndex()
        if idx < 0:
            return
        profile = self._profiles[idx]
        selected = self._model.selected_decisions()
        if not selected:
            QMessageBox.information(
                self,
                "Nothing ticked",
                "No cookies are ticked. Tick the ones you want to delete first.",
            )
            return

        # Confirmation. Show count, plus the first 3 domains as a sanity check.
        sample = ", ".join(sorted({d.cookie.domain for d in selected})[:3])
        reply = QMessageBox.question(
            self,
            "Confirm deletion",
            (
                f"<b>Delete {len(selected)} cookies</b> from <i>{profile.display}</i>?"
                f"<br><br>Affected sites include: {sample}"
                f"<br><br>A full backup of your cookies will be saved first so you can"
                f" undo this from the command line."
            ),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        try:
            result = delete_cookies(profile, [d.cookie for d in selected], dry_run=False)
        except Exception as exc:
            log.exception("delete_cookies failed")
            QMessageBox.critical(
                self,
                "Deletion failed",
                f"Cookie Janitor could not complete the deletion:\n\n{exc}"
                "\n\nYour cookies file was NOT modified.",
            )
            return

        QMessageBox.information(
            self,
            "Done",
            (
                f"Deleted {result.actually_deleted} of {result.requested_deletes}"
                f" cookies.<br><br>Backup saved at:<br><code>{result.backup_path}</code>"
                f"<br><br>To undo from Terminal:<br>"
                f"<code>cookie-janitor restore {result.backup_path}</code>"
            ),
        )
        # Reload so the table reflects reality.
        self._on_profile_changed(idx)

    def _show_about(self) -> None:
        QMessageBox.about(
            self,
            "About Cookie Janitor",
            (
                f"<h3>Cookie Janitor {__version__}</h3>"
                "<p>Open-source, Apache-2.0. Source and threat model at"
                " <a href='https://github.com/sgireddy/cookie-janitor'>"
                "github.com/sgireddy/cookie-janitor</a>.</p>"
                "<p>This app never sends your cookies anywhere. Every classification"
                " has a one-line reason in the table.</p>"
            ),
        )
