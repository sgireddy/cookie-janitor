"""Main window: profile picker, cookie table, filter chips, delete button."""

from __future__ import annotations

import importlib.resources
import logging
import subprocess
import sys

from PySide6.QtCore import QPoint, QSortFilterProxyModel, Qt
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QTableView,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from cookie_janitor import __version__, readers, writers
from cookie_janitor.classify.cookie_db import CookieDatabase, load_database
from cookie_janitor.model.cookie import Decision, Profile, Verdict
from cookie_janitor.policy.allowlist import (
    add_to_allowlist,
    load_allowlist,
    remove_from_allowlist,
)
from cookie_janitor.policy.decide import ClassifierMode, UserPolicy, decide

from .allowlist_dialog import AllowlistDialog
from .by_site_model import BySiteModel
from .mode_panel import ModePanel
from .model import CookiesModel

log = logging.getLogger(__name__)


def _load_cookie_db() -> CookieDatabase:
    files = importlib.resources.files("cookie_janitor.data")
    with importlib.resources.as_file(files / "cookie_db_seed.csv") as path:
        return load_database(path)


def _scan_profiles() -> list[Profile]:
    return readers.discover_all_profiles()


def _build_policy(mode: ClassifierMode) -> UserPolicy:
    """Construct a ``UserPolicy`` for the given mode, layered with the
    persisted user allow-list. The allow-list is reloaded on every call
    so changes via the dialog or a manual edit of allowlist.txt take
    effect on the next scan / mode-change.
    """
    return UserPolicy(keep_domains=load_allowlist(), mode=mode)


def _decisions_for(
    profile: Profile, db: CookieDatabase, mode: ClassifierMode
) -> list[Decision]:
    policy = _build_policy(mode)
    cookies = readers.read_cookies(profile)
    return [decide(c, policy=policy, cookie_db=db) for c in cookies]


#: macOS deep-link URL that opens System Settings directly on the Full
#: Disk Access pane. Stable since macOS 13 Ventura; on older systems it
#: opens the old Security & Privacy app to the Privacy tab — still a
#: huge UX win over "go find this yourself in System Settings".
_FULL_DISK_ACCESS_URL = (
    "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"
)


def _open_macos_full_disk_access_pane() -> None:
    """Open System Settings on the Full Disk Access pane.

    Best-effort: if macOS refuses the URL or ``open`` isn't on PATH for
    some unusual reason, we log and move on — the dialog already told
    the user the manual path. Failure here must not crash the GUI.
    """
    # ``/usr/bin/open`` is part of the macOS base system since 10.0 and
    # is the documented way to launch a URL handler from a sandboxed /
    # unsigned app. We use the absolute path (rather than relying on
    # PATH) both to satisfy ruff's S607 and as a small defence against
    # PATH-poisoning. ``subprocess.Popen`` avoids blocking the GUI.
    try:
        subprocess.Popen(  # noqa: S603 - fixed argv, no shell, hardcoded URL
            ["/usr/bin/open", _FULL_DISK_ACCESS_URL]
        )
    except OSError as exc:
        log.warning("Couldn't open System Settings via %s: %s", _FULL_DISK_ACCESS_URL, exc)


def _format_read_error(profile: Profile, exc: BaseException) -> tuple[str, str, str]:
    """Turn a read-time exception into a (title, body, detail) triple.

    Pulled out of the MainWindow class so the formatting logic is
    testable headlessly — the GUI just calls this and wraps the result
    in a QMessageBox.

    Returns:
        (title, body, detail) where ``detail`` is the long-form
        guidance shown in the dialog's expandable area. ``detail`` is
        empty for ordinary errors.
    """
    # Late imports: keep OS-specific reader modules out of the GUI's
    # import graph on platforms where they're irrelevant, and avoid a
    # circular dependency at module load (gui.window <- readers <- ...).
    from cookie_janitor.readers.chromium import ChromiumLockedError
    from cookie_janitor.readers.safari import (
        SafariPermissionDeniedError,
    )

    if isinstance(exc, SafariPermissionDeniedError):
        return (
            "Safari needs Full Disk Access",
            # Short, one-liner the user sees at the top of the dialog.
            f"macOS is blocking Cookie Janitor from reading"
            f" {profile.display}. This is a system-level permission,"
            f" not a Cookie Janitor bug — Safari's cookie store lives"
            f" inside Apple's protected container.",
            SafariPermissionDeniedError.GUIDANCE,
        )
    if isinstance(exc, ChromiumLockedError):
        return (
            f"{profile.vendor} is still running",
            # Short, one-liner. The vendor name (Microsoft Edge, Google
            # Chrome, Brave, …) is more meaningful to users than the
            # generic "Chromium" family name.
            f"Cookie Janitor couldn't read {profile.display} because "
            f"{profile.vendor} — or one of its background helpers — "
            f"is holding the cookie database open. Fully quit "
            f"{profile.vendor} and click Refresh.",
            ChromiumLockedError.GUIDANCE,
        )
    return (
        "Couldn't read cookies",
        f"Cookie Janitor couldn't read cookies for {profile.display}:\n\n{exc}",
        "",
    )


def _redecide(
    cookies_in_order: list[Decision], db: CookieDatabase, mode: ClassifierMode
) -> list[Decision]:
    """Re-run the classifier over an existing list of decisions.

    Used when the user changes mode or edits the allow-list — we already
    have the cookies in memory; no need to hit the SQLite file again.
    Preserves order so row indices in the table stay stable.
    """
    policy = _build_policy(mode)
    return [decide(d.cookie, policy=policy, cookie_db=db) for d in cookies_in_order]


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
        self._mode: ClassifierMode = ClassifierMode.BALANCED
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

        # Row 1: profile picker + refresh.
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

        # Row 2: mode panel — six radio buttons with info (ⓘ) icons.
        self._mode_panel = ModePanel(initial=ClassifierMode.BALANCED)
        self._mode_panel.modeChanged.connect(self._on_mode_changed)
        outer.addWidget(self._mode_panel)

        # Running-browser warning banner (hidden when profile isn't running).
        self._running_banner = QLabel("")
        self._running_banner.setObjectName("running_banner")
        self._running_banner.setStyleSheet(
            "QLabel#running_banner { background:#fff3cd; color:#664d03;"
            " border:1px solid #ffecb5; border-radius:4px; padding:6px 10px; }"
        )
        self._running_banner.setWordWrap(True)
        self._running_banner.hide()
        outer.addWidget(self._running_banner)

        # Search box. Filters whichever tab is currently visible.
        search_row = QHBoxLayout()
        search_row.addWidget(QLabel("Search:"))
        self._search = QLineEdit()
        self._search.setPlaceholderText("Filter by domain, name, or reason…")
        self._search.textChanged.connect(self._on_search_changed)
        search_row.addWidget(self._search)
        outer.addLayout(search_row)

        # Tabs: "All cookies" (existing flat list) and "By site" (groupped).
        self._tabs = QTabWidget()

        # --- All-cookies tab ---
        all_tab = QWidget()
        all_layout = QVBoxLayout(all_tab)
        all_layout.setContentsMargins(0, 0, 0, 0)
        self._table = QTableView()
        self._table.setModel(self._proxy)
        self._table.setSortingEnabled(True)
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.setWordWrap(True)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._on_table_context_menu)
        all_layout.addWidget(self._table)
        self._tabs.addTab(all_tab, "All cookies")

        # --- By-site tab ---
        site_tab = QWidget()
        site_layout = QVBoxLayout(site_tab)
        site_layout.setContentsMargins(0, 0, 0, 0)
        site_layout.addWidget(
            QLabel(
                "<small>Tick a site to mark <i>all</i> its cookies for"
                " deletion. Allow-listed sites are shown but can't be"
                " ticked — remove the protection in <b>File → Allow"
                " list…</b> first if you really want to clear them."
                "</small>"
            )
        )
        site_action_row = QHBoxLayout()
        self._site_select_btn = QPushButton("Select all listed sites")
        self._site_select_btn.setToolTip(
            "Tick every site that isn't protected by your allow list."
        )
        self._site_select_btn.clicked.connect(self._on_select_all_sites)
        site_action_row.addWidget(self._site_select_btn)
        self._site_protect_btn = QPushButton("Add selected site to allow list")
        self._site_protect_btn.setToolTip(
            "Take the currently highlighted row and add its host to"
            " your allow list."
        )
        self._site_protect_btn.clicked.connect(self._on_protect_selected_site)
        site_action_row.addWidget(self._site_protect_btn)
        site_action_row.addStretch(1)
        site_layout.addLayout(site_action_row)
        self._site_table = QTableView()
        self._site_table.setSortingEnabled(True)
        self._site_table.setAlternatingRowColors(True)
        self._site_table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self._site_table.setSelectionMode(QTableView.SelectionMode.ExtendedSelection)
        self._site_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Interactive
        )
        self._site_table.horizontalHeader().setStretchLastSection(True)
        self._site_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._site_table.customContextMenuRequested.connect(self._on_site_context_menu)
        self._site_proxy = QSortFilterProxyModel(self)
        self._site_proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self._site_proxy.setFilterKeyColumn(1)  # filter on host column
        self._site_table.setModel(self._site_proxy)
        site_layout.addWidget(self._site_table)
        self._tabs.addTab(site_tab, "By site")

        # The by-site model is rebuilt every time we re-decide. Set in
        # _on_profile_changed so it always points at the current
        # CookiesModel.
        self._site_model: BySiteModel | None = None

        outer.addWidget(self._tabs, stretch=1)

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
        allowlist_action = QAction("&Allow list…", self)
        allowlist_action.setShortcut("Ctrl+L")
        allowlist_action.triggered.connect(self._show_allowlist)
        menu.addAction(allowlist_action)
        menu.addSeparator()
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
            # Pre-0.5 this said "no Firefox profile found", which was a
            # lie after the Chromium + Safari readers shipped. Keep the
            # copy generic so a user with only Edge/Chrome/Safari isn't
            # told to install Firefox.
            self._profile_box.addItem("No browser profile found")
            self._set_status_empty(
                "Cookie Janitor couldn't find any supported browser profile"
                " on this machine. Install one of Firefox, Chrome, Edge,"
                " Brave, Vivaldi, Opera, Arc, or (on macOS) Safari, visit"
                " a few sites, then click Refresh."
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
            decisions = _decisions_for(profile, self._db, self._mode)
        except Exception as exc:  # surface real errors instead of silent fail
            log.exception("Failed to read cookies for %s", profile.display)
            self._show_read_error_dialog(profile, exc)
            decisions = []

        self._install_model(
            CookiesModel(decisions),
            audit_only=self._mode is ClassifierMode.AUDIT_ONLY,
        )
        self._update_running_banner(profile)

        # Three reasons the delete button might be disabled, in order:
        #   1. This browser family has no writer yet (Safari today).
        #   2. The browser is currently running.
        #   3. There are no cookies to delete.
        can_write = writers.supports_delete(profile.browser)
        self._delete_btn.setEnabled(
            can_write and not profile.is_running and bool(decisions)
        )
        if not can_write:
            tip = (
                # ruff S608 triggers on any f-string containing the word
                # "delete"; this is plain UI copy, not a SQL query.
                f"Cookie Janitor can read {profile.vendor} cookies but"  # noqa: S608
                " doesn't yet delete them. Use this view to audit what's"
                " there; delete from inside Safari's own Settings →"
                " Privacy → Manage Website Data."
            )
        elif profile.is_running:
            tip = f"Quit {profile.vendor} first, then click Refresh."
        else:
            tip = "Delete the ticked cookies. A backup is made first."
        self._delete_btn.setToolTip(tip)

    def _show_read_error_dialog(self, profile: Profile, exc: BaseException) -> None:
        """Render the right kind of dialog for a profile-read failure.

        Safari TCC errors get a multi-paragraph guidance dialog with an
        "Open System Settings" button that deep-links straight to the
        Full Disk Access pane. Everything else gets the simple warning.
        """
        # Late import: importing here keeps Safari-specific symbols
        # out of the module's top-level type graph and matches the
        # pattern used in ``_format_read_error``.
        from cookie_janitor.readers.safari import (
            SafariPermissionDeniedError,
        )

        title, body, detail = _format_read_error(profile, exc)
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle(title)
        box.setText(body)
        if detail:
            # Putting the long-form guidance in ``setInformativeText``
            # (rather than ``setDetailedText``) keeps it visible by
            # default — the user shouldn't have to click a "Show
            # Details" disclosure to learn what to do.
            box.setInformativeText(detail)
        box.addButton(QMessageBox.StandardButton.Ok)

        # Read sys.platform via a local so mypy doesn't narrow this
        # branch into "unreachable on Linux" — the same trick used in
        # readers/safari.py. We want the branch live in every build.
        current_platform: str = sys.platform
        if isinstance(exc, SafariPermissionDeniedError) and current_platform == "darwin":
            open_settings = box.addButton(
                "Open System Settings…", QMessageBox.ButtonRole.ActionRole
            )
            box.setDefaultButton(open_settings)
        else:
            open_settings = None

        box.exec()

        if open_settings is not None and box.clickedButton() is open_settings:
            _open_macos_full_disk_access_pane()

    def _install_model(self, model: CookiesModel, *, audit_only: bool) -> None:
        """Wire a freshly built CookiesModel into both tabs and refresh.

        In audit-only mode we explicitly clear any default selection — the
        whole point of that mode is "I haven't decided yet".
        """
        if audit_only:
            model.set_all_selected(selected=False)
        self._model = model
        self._proxy.setSourceModel(model)
        # The by-site model observes the cookies model; rebuild it now.
        self._site_model = BySiteModel(model)
        self._site_proxy.setSourceModel(self._site_model)
        self._table.setColumnWidth(0, 30)
        self._table.setColumnWidth(1, 130)
        self._table.setColumnWidth(2, 110)
        self._table.setColumnWidth(3, 200)
        self._table.setColumnWidth(4, 180)
        self._table.setColumnWidth(5, 100)
        self._site_table.setColumnWidth(0, 40)
        self._site_table.setColumnWidth(1, 280)
        self._site_table.setColumnWidth(2, 80)
        self._site_table.setColumnWidth(3, 120)
        self._site_table.setColumnWidth(4, 100)
        self._update_status()

    def _on_search_changed(self, text: str) -> None:
        """Filter both tabs' proxies with the same string."""
        self._proxy.setFilterFixedString(text)
        self._site_proxy.setFilterFixedString(text)

    def _update_running_banner(self, profile: Profile) -> None:
        """Surface constraints (browser running / read-only browser) above the table.

        Two situations show a banner; if both apply we explain both so
        the user can fix the running-browser one first and then see the
        read-only one is permanent.
        """
        messages: list[str] = []
        if not writers.supports_delete(profile.browser):
            # ruff RUF001 flags the U+2139 "information source" glyph as
            # an ambiguous lookalike for 'i'; suppressing here because
            # the emoji is intentional banner iconography matching the
            # ⚠️ warning style below.
            messages.append(
                f"\u2139\ufe0f  <b>{profile.vendor} is read-only in this build of"
                f" Cookie Janitor.</b> You can audit cookies here, but deletion"
                f" isn't supported yet for {profile.vendor}."
            )
        if profile.is_running:
            # NOTE: on Windows 11 this fires as a false positive when a
            # Chromium-family process is up but is NOT the user's actual
            # browser session — Widgets Board, Copilot, Windows Search,
            # any pinned PWA, WebView2 hosts. See the comment on
            # ``_PROCESS_NAMES`` in ``safety/process.py``. We used to say
            # "Edge is running — cookies can't be deleted" here; that
            # was misleading in the false-positive case. Wording is now
            # hedged: reads work regardless (v0.6.5 fix), deletes may or
            # may not, and if a delete fails the user gets a specific
            # dialog explaining what's holding the lock.
            messages.append(
                f"\u2139\ufe0f  A background {profile.vendor} process was detected."
                f" Reading cookies is unaffected. If a delete fails, fully quit"
                f" {profile.vendor} (⌘Q on macOS / File → Exit on Windows / Linux),"
                f" including any pinned PWAs or Widgets, then click <b>Refresh</b>."
            )
        if messages:
            self._running_banner.setText("<br>".join(messages))
            self._running_banner.show()
        else:
            self._running_banner.hide()

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

        # Late import: same rationale as _format_read_error — keep Safari
        # symbols out of the GUI's top-level type graph on non-darwin.
        from cookie_janitor.writers.safari import (
            SafariSyncEnabledError,
        )

        try:
            result = writers.delete_cookies(
                profile, [d.cookie for d in selected], dry_run=False
            )
        except SafariSyncEnabledError as exc:
            # Distinct UX from a generic failure: this isn't a crash,
            # it's a deliberate refusal with a clear remedy. We didn't
            # touch the file. Show the multi-paragraph guidance with
            # informative-text so it's visible by default.
            log.warning("delete_cookies blocked by iCloud Safari sync")
            box = QMessageBox(self)
            box.setIcon(QMessageBox.Icon.Warning)
            box.setWindowTitle("iCloud Safari sync is on")
            box.setText(
                "Cookie Janitor didn't delete anything — iCloud Safari"
                " sync is enabled on this Mac and would resurrect the"
                " deleted cookies within minutes from another Apple"
                " device."
            )
            box.setInformativeText(exc.GUIDANCE)
            box.addButton(QMessageBox.StandardButton.Ok)
            box.exec()
            return
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

    # --- Mode + allow-list -------------------------------------------------

    def _on_mode_changed(self, new_mode: ClassifierMode) -> None:
        """Re-classify the current scan against the new mode.

        We deliberately re-decide rather than re-read: the cookies on disk
        haven't changed, only the policy has, so hitting SQLite again
        would be wasteful (and might surprise the user if it picked up
        intervening browser activity).
        """
        if new_mode is self._mode:
            return
        self._mode = new_mode
        self._reclassify_current_view()

    def _reclassify_current_view(self) -> None:
        """Re-decide every cookie currently in the model with the live
        policy + allow-list. Used after a mode change OR an allow-list
        edit. Cheap because we already have the cookies in memory.
        """
        if self._model is None:
            return
        existing = list(self._model.decisions())
        if not existing:
            return
        try:
            redecided = _redecide(existing, self._db, self._mode)
        except Exception:
            log.exception("Re-decide failed for mode=%s", self._mode)
            return
        self._install_model(
            CookiesModel(redecided),
            audit_only=self._mode is ClassifierMode.AUDIT_ONLY,
        )

    def _show_allowlist(self) -> None:
        dlg = AllowlistDialog(self)
        accepted = dlg.exec() == AllowlistDialog.DialogCode.Accepted
        if accepted:
            self._reclassify_current_view()

    # --- By-site tab actions -----------------------------------------------

    def _on_select_all_sites(self) -> None:
        """Tick every cookie row whose site isn't protected by the
        allow-list. Equivalent to ticking every row in the by-site tab.
        """
        if self._site_model is None or self._model is None:
            return
        all_rows: list[int] = []
        for i in range(self._site_model.rowCount()):
            site = self._site_model.site_at(i)
            if site is None or site.on_allow_list:
                continue
            all_rows.extend(site.rows)
        self._model.set_selected_for_rows(all_rows, selected=True)

    def _on_protect_selected_site(self) -> None:
        """Add the host(s) of the selected by-site row(s) to the allow-list,
        then re-decide so the protected rows flip to KEEP.
        """
        if self._site_model is None:
            return
        sel = self._site_table.selectionModel()
        hosts: list[str] = []
        for proxy_index in sel.selectedRows():
            src_index = self._site_proxy.mapToSource(proxy_index)
            site = self._site_model.site_at(src_index.row())
            if site is not None and not site.on_allow_list:
                hosts.append(site.host)
        if not hosts:
            QMessageBox.information(
                self,
                "Nothing to protect",
                "Highlight one or more sites in the table first.",
            )
            return
        try:
            for h in hosts:
                add_to_allowlist(h)
        except (OSError, ValueError) as exc:
            QMessageBox.warning(
                self,
                "Couldn't update allow-list",
                f"Cookie Janitor couldn't update the allow-list:\n\n{exc}",
            )
            return
        self._reclassify_current_view()

    def _on_table_context_menu(self, pos: QPoint) -> None:
        if self._model is None:
            return
        proxy_index = self._table.indexAt(pos)
        if not proxy_index.isValid():
            return
        source_index = self._proxy.mapToSource(proxy_index)
        decision = self._model.decisions()[source_index.row()]
        host = decision.cookie.domain.lstrip(".")
        if not host:
            return

        menu = QMenu(self._table)
        always_keep = QAction(f"Always keep cookies on {host}", menu)
        always_keep.triggered.connect(lambda: self._allowlist_add(host))
        menu.addAction(always_keep)
        # If host has labels left of an eTLD+1, also offer the registered name.
        parts = host.split(".")
        if len(parts) > 2:
            etld1 = ".".join(parts[-2:])
            if etld1 != host:
                broaden = QAction(f"Always keep cookies on *.{etld1}", menu)
                broaden.triggered.connect(lambda: self._allowlist_add(etld1))
                menu.addAction(broaden)
        menu.exec(self._table.viewport().mapToGlobal(pos))

    def _on_site_context_menu(self, pos: QPoint) -> None:
        if self._site_model is None:
            return
        proxy_index = self._site_table.indexAt(pos)
        if not proxy_index.isValid():
            return
        src_index = self._site_proxy.mapToSource(proxy_index)
        site = self._site_model.site_at(src_index.row())
        if site is None:
            return
        menu = QMenu(self._site_table)
        if site.on_allow_list:
            unprotect = QAction(
                f"Remove {site.host} from allow list (will allow cleaning)", menu
            )
            unprotect.triggered.connect(lambda: self._allowlist_remove(site.host))
            menu.addAction(unprotect)
        else:
            protect = QAction(f"Always keep cookies on {site.host}", menu)
            protect.triggered.connect(lambda: self._allowlist_add(site.host))
            menu.addAction(protect)
            tick_only = QAction(
                f"Tick every cookie on {site.host} for deletion", menu
            )
            site_row = src_index.row()

            def _tick(row: int = site_row) -> None:
                if self._site_model is not None:
                    self._site_model.select_site_rows(row, selected=True)

            tick_only.triggered.connect(_tick)
            menu.addAction(tick_only)
        menu.exec(self._site_table.viewport().mapToGlobal(pos))

    def _allowlist_remove(self, host: str) -> None:
        try:
            remove_from_allowlist(host)
        except OSError as exc:
            QMessageBox.warning(
                self,
                "Couldn't update allow-list",
                f"Cookie Janitor couldn't remove {host!r} from the allow-list:\n\n{exc}",
            )
            return
        self._reclassify_current_view()

    def _allowlist_add(self, host: str) -> None:
        try:
            add_to_allowlist(host)
        except (OSError, ValueError) as exc:
            QMessageBox.warning(
                self,
                "Couldn't update allow-list",
                f"Cookie Janitor couldn't add {host!r} to the allow-list:\n\n{exc}",
            )
            return
        self._reclassify_current_view()
