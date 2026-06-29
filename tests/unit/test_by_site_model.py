"""Headless tests for the by-site aggregation + selection wiring.

These tests construct a CookiesModel from synthetic decisions, wrap it
in a BySiteModel, and exercise the two-way link (toggling a site
selects its underlying rows; toggling individual rows updates the
site's tri-state).

We need a ``QCoreApplication`` for ``QAbstractTableModel`` signal
plumbing to work — pytest-qt is not installed in CI, so we set up an
``QGuiApplication`` once per session via a fixture below.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from PySide6.QtCore import QCoreApplication, Qt
from PySide6.QtWidgets import QApplication

from cookie_janitor.classify.cookie_db import CookieDatabase
from cookie_janitor.gui.by_site_model import BySiteModel
from cookie_janitor.gui.model import CookiesModel
from cookie_janitor.model.cookie import SameSite, make_cookie
from cookie_janitor.policy.decide import ClassifierMode, UserPolicy, decide


@pytest.fixture(scope="module", autouse=True)
def _qapp():
    """One QApplication per test module — Qt models need one."""
    app = QCoreApplication.instance() or QApplication([])
    yield app
    # Don't quit() — pytest may be running other Qt tests too.


def _cookie(name: str, host: str):
    return make_cookie(
        name=name,
        domain=host,
        path="/",
        expires=datetime.now(tz=UTC) + timedelta(days=30),
        secure=True,
        http_only=False,
        same_site=SameSite.LAX,
        is_host_only=False,
        value_bytes=b"v",
    )


def _build_model(
    cookie_specs: list[tuple[str, str]],
    *,
    mode: ClassifierMode = ClassifierMode.BALANCED,
    keep_domains: frozenset[str] = frozenset(),
) -> CookiesModel:
    cookies = [_cookie(name, host) for name, host in cookie_specs]
    policy = UserPolicy(keep_domains=keep_domains, mode=mode)
    decisions = [
        decide(c, policy=policy, cookie_db=CookieDatabase(by_exact_name={}, by_prefix={}))
        for c in cookies
    ]
    return CookiesModel(decisions)


# ---------------------------------------------------------------------------


def test_aggregates_by_host_and_counts_rows():
    src = _build_model(
        [
            ("a", "cnn.com"),
            ("b", "cnn.com"),
            ("c", ".cnn.com"),  # leading dot → same host
            ("d", "gmail.com"),
            ("e", "doubleclick.net"),
        ],
        mode=ClassifierMode.BALANCED,
    )
    site = BySiteModel(src)
    # 3 distinct hosts.
    assert site.rowCount() == 3

    by_host = {site.site_at(i).host: site.site_at(i) for i in range(site.rowCount())}  # type: ignore[union-attr]
    assert set(by_host) == {"cnn.com", "gmail.com", "doubleclick.net"}
    assert len(by_host["cnn.com"].rows) == 3


def test_sorted_by_recommended_delete_descending():
    # doubleclick.net is a tracker domain → all DELETE; gmail.com is
    # plain unknown → KEEP. Tracker should sort first.
    src = _build_model(
        [
            ("x", "gmail.com"),
            ("a", "doubleclick.net"),
            ("b", "doubleclick.net"),
        ],
        mode=ClassifierMode.BALANCED,
    )
    site = BySiteModel(src)
    first = site.site_at(0)
    assert first is not None
    assert first.host == "doubleclick.net"
    assert first.recommended_delete == 2


def test_protected_site_shows_on_allow_list_and_is_unticked():
    src = _build_model(
        [("a", "gmail.com")],
        keep_domains=frozenset({"gmail.com"}),
        mode=ClassifierMode.BALANCED,
    )
    site = BySiteModel(src)
    row = site.site_at(0)
    assert row is not None
    assert row.on_allow_list is True

    # Checkbox column returns None (no checkbox) for protected rows.
    idx = site.index(0, 0)
    assert site.data(idx, Qt.ItemDataRole.CheckStateRole) is None
    # Protected note rendered in the "Protected" column.
    protected_idx = site.index(0, 4)
    assert site.data(protected_idx, Qt.ItemDataRole.DisplayRole) == "Allow-list"


def test_toggling_site_checkbox_updates_underlying_selection():
    src = _build_model(
        [
            ("a", "cnn.com"),
            ("b", "cnn.com"),
            ("c", "gmail.com"),
        ],
        mode=ClassifierMode.BALANCED,
    )
    # Nothing pre-selected (all decisions are KEEP for these examples).
    src.set_all_selected(selected=False)
    site = BySiteModel(src)

    # Find the cnn.com row in the by-site model.
    cnn_row = next(
        i
        for i in range(site.rowCount())
        if (s := site.site_at(i)) is not None and s.host == "cnn.com"
    )
    cnn_site = site.site_at(cnn_row)
    assert cnn_site is not None

    # Tick it.
    idx = site.index(cnn_row, 0)
    ok = site.setData(idx, Qt.CheckState.Checked.value, Qt.ItemDataRole.CheckStateRole)
    assert ok is True

    # Both cnn cookies are now in the underlying selection set.
    assert set(cnn_site.rows).issubset(src.selected_rows())
    # The single gmail row is NOT selected.
    assert len(src.selected_rows()) == len(cnn_site.rows)


def test_partial_selection_renders_as_partiallychecked():
    src = _build_model(
        [
            ("a", "cnn.com"),
            ("b", "cnn.com"),
        ],
        mode=ClassifierMode.BALANCED,
    )
    src.set_all_selected(selected=False)
    site = BySiteModel(src)
    # Tick only the first underlying row.
    src.set_selected_for_rows([0], selected=True)
    idx = site.index(0, 0)
    state = site.data(idx, Qt.ItemDataRole.CheckStateRole)
    assert state == Qt.CheckState.PartiallyChecked


def test_select_site_rows_is_a_no_op_on_protected_site():
    src = _build_model(
        [("a", "gmail.com")],
        keep_domains=frozenset({"gmail.com"}),
    )
    src.set_all_selected(selected=False)
    site = BySiteModel(src)
    site.select_site_rows(0, selected=True)
    assert src.selected_rows() == frozenset()
