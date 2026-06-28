"""Qt models that wrap our domain objects.

We deliberately keep these dumb: a model holds a list of ``Decision``
objects and renders one column per attribute. Filtering is done with a
``QSortFilterProxyModel`` upstream so the underlying list is never
mutated by UI interactions.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import cast

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QPersistentModelIndex,
    Qt,
)
from PySide6.QtGui import QBrush, QColor

from cookie_janitor.model.cookie import Decision, Verdict

_Index = QModelIndex | QPersistentModelIndex

_COLUMNS: tuple[tuple[str, str], ...] = (
    ("", "checkbox"),  # delete-this-one checkbox
    ("Recommendation", "verdict"),
    ("Category", "category"),
    ("Domain", "domain"),
    ("Name", "name"),
    ("Expires", "expires"),
    ("Why we think so", "rationale"),
)

_VERDICT_COLORS = {
    Verdict.KEEP: QColor("#2e7d32"),  # green
    Verdict.DELETE: QColor("#c62828"),  # red
}

_VERDICT_LABELS = {
    Verdict.KEEP: "Keep",
    Verdict.DELETE: "Delete",
}


class CookiesModel(QAbstractTableModel):
    """A flat list of decisions, one per row.

    The first column is a checkbox driven by an internal ``selected``
    set. By default rows whose verdict is ``DELETE`` start checked, so a
    Grandma click on "Delete selected" already does the obvious thing.
    """

    def __init__(self, decisions: Sequence[Decision]) -> None:
        super().__init__()
        self._decisions: list[Decision] = list(decisions)
        self._selected: set[int] = {
            i for i, d in enumerate(self._decisions) if d.verdict is Verdict.DELETE
        }

    # --- Required overrides ------------------------------------------------

    def rowCount(self, parent: _Index | None = None) -> int:
        if parent is not None and parent.isValid():
            return 0
        return len(self._decisions)

    def columnCount(self, parent: _Index | None = None) -> int:
        if parent is not None and parent.isValid():
            return 0
        return len(_COLUMNS)

    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> object:
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal:
            return _COLUMNS[section][0]
        return section + 1

    def flags(self, index: _Index) -> Qt.ItemFlag:
        base = super().flags(index)
        if not index.isValid():
            return base
        if _COLUMNS[index.column()][1] == "checkbox":
            return base | Qt.ItemFlag.ItemIsUserCheckable
        return base

    def data(
        self,
        index: _Index,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> object:
        if not index.isValid():
            return None
        decision = self._decisions[index.row()]
        col_key = _COLUMNS[index.column()][1]

        if role == Qt.ItemDataRole.CheckStateRole and col_key == "checkbox":
            return (
                Qt.CheckState.Checked if index.row() in self._selected else Qt.CheckState.Unchecked
            )

        if role == Qt.ItemDataRole.ForegroundRole and col_key == "verdict":
            return QBrush(_VERDICT_COLORS[decision.verdict])

        if role == Qt.ItemDataRole.ToolTipRole and col_key == "rationale":
            return decision.rationale

        if role != Qt.ItemDataRole.DisplayRole:
            return None

        if col_key == "checkbox":
            return ""
        if col_key == "verdict":
            return _VERDICT_LABELS[decision.verdict]
        if col_key == "category":
            return decision.category.value.title()
        if col_key == "domain":
            return decision.cookie.domain
        if col_key == "name":
            return decision.cookie.name
        if col_key == "expires":
            if decision.cookie.is_session or decision.cookie.expires is None:
                return "session"
            return decision.cookie.expires.strftime("%Y-%m-%d")
        if col_key == "rationale":
            return decision.rationale
        return None

    def setData(
        self,
        index: _Index,
        value: object,
        role: int = Qt.ItemDataRole.EditRole,
    ) -> bool:
        if role != Qt.ItemDataRole.CheckStateRole:
            return False
        if _COLUMNS[index.column()][1] != "checkbox":
            return False
        checked = Qt.CheckState(cast("int", value)) == Qt.CheckState.Checked
        if checked:
            self._selected.add(index.row())
        else:
            self._selected.discard(index.row())
        self.dataChanged.emit(index, index, [Qt.ItemDataRole.CheckStateRole])
        return True

    # --- Helpers used by the window ----------------------------------------

    def decisions(self) -> Sequence[Decision]:
        return self._decisions

    def selected_decisions(self) -> list[Decision]:
        return [self._decisions[i] for i in sorted(self._selected)]

    def set_all_selected(self, *, selected: bool) -> None:
        self.beginResetModel()
        if selected:
            self._selected = set(range(len(self._decisions)))
        else:
            self._selected.clear()
        self.endResetModel()

    def select_default(self) -> None:
        """Re-apply the default selection (everything the policy says DELETE)."""
        self.beginResetModel()
        self._selected = {i for i, d in enumerate(self._decisions) if d.verdict is Verdict.DELETE}
        self.endResetModel()
