"""Modal dialog for inspecting and editing the user allow-list.

The dialog reads the on-disk allow-list when it opens, lets the user
add / remove entries, and writes back atomically on accept. Cancel
discards changes. All persistence goes through
:mod:`cookie_janitor.policy.allowlist` — no direct file I/O here.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
)

from cookie_janitor.policy.allowlist import (
    allowlist_path,
    load_allowlist,
    save_allowlist,
)


class AllowlistDialog(QDialog):
    """Add / remove domains from the persistent allow-list."""

    def __init__(self, parent: object = None) -> None:
        super().__init__(parent)  # type: ignore[arg-type]
        self.setWindowTitle("Allow list — cookies to always keep")
        self.setMinimumSize(520, 420)
        self._build_ui()
        self._reload()

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)

        intro = QLabel(
            "Cookies set on these domains (and their subdomains) will always"
            " be kept, regardless of what the classifier recommends. Use this"
            " for sites you actively log into.<br><br>"
            f"<small>Stored at <code>{allowlist_path()}</code></small>"
        )
        intro.setWordWrap(True)
        intro.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)
        outer.addWidget(intro)

        self._list = QListWidget()
        self._list.setSortingEnabled(True)
        outer.addWidget(self._list, stretch=1)

        row = QHBoxLayout()
        self._add_btn = QPushButton("Add domain…")
        self._add_btn.clicked.connect(self._on_add)
        row.addWidget(self._add_btn)
        self._remove_btn = QPushButton("Remove selected")
        self._remove_btn.clicked.connect(self._on_remove)
        row.addWidget(self._remove_btn)
        row.addStretch(1)
        outer.addLayout(row)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._on_save)
        buttons.rejected.connect(self.reject)
        outer.addWidget(buttons)

    def _reload(self) -> None:
        self._list.clear()
        for d in sorted(load_allowlist()):
            self._list.addItem(QListWidgetItem(d))

    def _current_set(self) -> set[str]:
        return {self._list.item(i).text() for i in range(self._list.count())}

    def _on_add(self) -> None:
        text, ok = QInputDialog.getText(
            self,
            "Add domain",
            "Domain to always keep cookies for (e.g. github.com):",
        )
        if not ok or not text.strip():
            return
        cleaned = text.strip().lstrip(".").lower()
        if any(c in cleaned for c in (" ", "/", ":", "@")):
            QMessageBox.warning(
                self,
                "Not a hostname",
                f"{text!r} doesn't look like a hostname. Try something"
                " like <code>example.com</code>.",
            )
            return
        if cleaned in self._current_set():
            return
        self._list.addItem(QListWidgetItem(cleaned))

    def _on_remove(self) -> None:
        for item in self._list.selectedItems():
            self._list.takeItem(self._list.row(item))

    def _on_save(self) -> None:
        try:
            save_allowlist(frozenset(self._current_set()))
        except OSError as exc:
            QMessageBox.critical(
                self,
                "Couldn't save allow-list",
                f"Cookie Janitor could not write the allow-list:\n\n{exc}",
            )
            return
        self.accept()
