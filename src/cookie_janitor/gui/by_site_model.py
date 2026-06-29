"""Aggregated "by site" view of the same decisions.

This model does not own any cookie data. It wraps a ``CookiesModel`` and
groups the rows by cookie host. Selecting a site = ticking the
underlying CookiesModel rows for that host. Untick = the inverse.

Why a wrapper rather than a tree? A flat table is grep-able and sortable
and reuses our existing ``QTableView``. The number of sites is small
(low hundreds even for a heavy user) so a flat-list view is fine — a
``QTreeView`` would just add complexity for no real win.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import cast

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QPersistentModelIndex,
    Qt,
)
from PySide6.QtGui import QBrush, QColor

from cookie_janitor.model.cookie import Decision, Verdict

from .model import CookiesModel

_Index = QModelIndex | QPersistentModelIndex


# Column layout — keep this list as the single source of truth.
_COLUMNS: tuple[tuple[str, str], ...] = (
    ("", "checkbox"),  # tri-state: all/some/none of this site's cookies ticked
    ("Site", "host"),
    ("Cookies", "count"),
    ("Recommended", "recommended"),  # count whose verdict is DELETE
    ("Protected", "protected"),  # "Allow-list" if any cookie kept by user rule
    ("Notes", "notes"),
)

_PROTECTED_BRUSH = QBrush(QColor("#2e7d32"))
_DELETE_BRUSH = QBrush(QColor("#c62828"))


@dataclass(frozen=True, slots=True)
class SiteRow:
    """One row in the by-site view."""

    host: str
    rows: tuple[int, ...]  # indices into the underlying CookiesModel
    recommended_delete: int  # how many of those were classified DELETE
    on_allow_list: bool  # True iff at least one cookie was kept via user-keep-list:domain


class BySiteModel(QAbstractTableModel):
    """Read-only summary by host, plus a per-host checkbox.

    Toggling the checkbox calls back into the underlying
    ``CookiesModel.set_selected_for_rows`` so the *single* selection set
    drives both views and the eventual delete action. We listen to that
    model's ``dataChanged`` to redraw our own checkbox state when the
    user ticks individual rows in the "All cookies" tab.
    """

    def __init__(self, source: CookiesModel) -> None:
        super().__init__()
        self._source = source
        self._sites: list[SiteRow] = self._aggregate(source)
        source.dataChanged.connect(self._on_source_changed)
        source.modelReset.connect(self._on_source_reset)

    # --- aggregation -------------------------------------------------------

    @staticmethod
    def _aggregate(source: CookiesModel) -> list[SiteRow]:
        by_domain = source.decisions_by_domain()
        decs: Sequence[Decision] = source.decisions()
        out: list[SiteRow] = []
        for host, indices in by_domain.items():
            sub = [decs[i] for i in indices]
            recommended = sum(1 for d in sub if d.verdict is Verdict.DELETE)
            allow_listed = any(
                d.source == "user-keep-list:domain" for d in sub
            )
            out.append(
                SiteRow(
                    host=host,
                    rows=tuple(indices),
                    recommended_delete=recommended,
                    on_allow_list=allow_listed,
                )
            )
        # Stable, predictable order: most recommended deletes first, then
        # most cookies, then host name. Gives users the high-value sites
        # at the top without forcing them to click a header.
        out.sort(
            key=lambda s: (-s.recommended_delete, -len(s.rows), s.host),
        )
        return out

    def _on_source_changed(self, *_args: object) -> None:
        # Only the checkbox column needs refreshing for selection changes
        # — host counts don't change on tick. Cheap full-column refresh.
        if not self._sites:
            return
        top = self.index(0, 0)
        bottom = self.index(len(self._sites) - 1, 0)
        self.dataChanged.emit(top, bottom, [Qt.ItemDataRole.CheckStateRole])

    def _on_source_reset(self) -> None:
        self.beginResetModel()
        self._sites = self._aggregate(self._source)
        self.endResetModel()

    # --- Required overrides ------------------------------------------------

    def rowCount(self, parent: _Index | None = None) -> int:
        if parent is not None and parent.isValid():
            return 0
        return len(self._sites)

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
            site = self._sites[index.row()]
            if site.on_allow_list:
                # User-protected sites are uncheckable — the protection
                # is the whole point. The user can still toggle individual
                # rows in the "All cookies" tab if they really want to.
                return base
            return base | Qt.ItemFlag.ItemIsUserTristate | Qt.ItemFlag.ItemIsUserCheckable
        return base

    def data(
        self,
        index: _Index,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> object:
        if not index.isValid():
            return None
        site = self._sites[index.row()]
        col_key = _COLUMNS[index.column()][1]

        if role == Qt.ItemDataRole.CheckStateRole and col_key == "checkbox":
            if site.on_allow_list:
                # We render no checkbox on protected rows — return None.
                return None
            return self._check_state_for(site)

        if role == Qt.ItemDataRole.ForegroundRole:
            if col_key == "protected" and site.on_allow_list:
                return _PROTECTED_BRUSH
            if col_key == "recommended" and site.recommended_delete > 0:
                return _DELETE_BRUSH

        if role == Qt.ItemDataRole.ToolTipRole and col_key == "host":
            return (
                f"{len(site.rows)} cookies total; "
                f"{site.recommended_delete} recommended for deletion."
                + (" Protected by your allow list." if site.on_allow_list else "")
            )

        if role != Qt.ItemDataRole.DisplayRole:
            return None

        if col_key == "host":
            return site.host
        if col_key == "count":
            return len(site.rows)
        if col_key == "recommended":
            return site.recommended_delete
        if col_key == "protected":
            return "Allow-list" if site.on_allow_list else ""
        if col_key == "notes":
            return self._notes_for(site)
        if col_key == "checkbox":
            return ""
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
        site = self._sites[index.row()]
        if site.on_allow_list:
            return False
        # Qt sends PartiallyChecked when you click a tristate, but we treat
        # that as "user wants to commit one direction or the other". We
        # cycle: Unchecked → Checked → Unchecked. PartiallyChecked is
        # informational only (i.e. set by us, never by the user clicking).
        state = Qt.CheckState(cast("int", value))
        select = state == Qt.CheckState.Checked
        self._source.set_selected_for_rows(site.rows, selected=select)
        # Source emits dataChanged → our _on_source_changed refreshes our
        # column. No need to emit here.
        return True

    # --- Helpers used by the window ----------------------------------------

    def site_at(self, row: int) -> SiteRow | None:
        if 0 <= row < len(self._sites):
            return self._sites[row]
        return None

    def select_site_rows(self, row: int, *, selected: bool) -> None:
        """Tick / untick every cookie row for the site at ``row``."""
        site = self.site_at(row)
        if site is None or site.on_allow_list:
            return
        self._source.set_selected_for_rows(site.rows, selected=selected)

    def total_cookie_count(self) -> int:
        return sum(len(s.rows) for s in self._sites)

    def total_recommended(self) -> int:
        return sum(s.recommended_delete for s in self._sites)

    # --- Internals ---------------------------------------------------------

    def _check_state_for(self, site: SiteRow) -> Qt.CheckState:
        ticked = self._source.selected_rows()
        site_rows = set(site.rows)
        intersection = len(ticked & site_rows)
        if intersection == 0:
            return Qt.CheckState.Unchecked
        if intersection == len(site_rows):
            return Qt.CheckState.Checked
        return Qt.CheckState.PartiallyChecked

    @staticmethod
    def _notes_for(site: SiteRow) -> str:
        # A short, factual note. Helps a user scanning the column choose
        # whether to risk ticking the box.
        if site.on_allow_list:
            return "All cookies kept by your allow list."
        if site.recommended_delete == len(site.rows):
            return "Every cookie here is recommended for deletion."
        if site.recommended_delete == 0:
            return "Nothing recommended for deletion."
        return f"{site.recommended_delete} of {len(site.rows)} recommended for deletion."
