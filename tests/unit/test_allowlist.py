"""Tests for the persistent user allow-list."""

from __future__ import annotations

from pathlib import Path

import pytest

from cookie_janitor.policy.allowlist import (
    add_to_allowlist,
    load_allowlist,
    remove_from_allowlist,
    save_allowlist,
)


def test_load_missing_returns_empty(tmp_path: Path):
    assert load_allowlist(tmp_path / "nope.txt") == frozenset()


def test_save_and_load_roundtrip(tmp_path: Path):
    path = tmp_path / "allowlist.txt"
    save_allowlist(frozenset({"github.com", "accounts.google.com", "MyBank.example"}), path)
    assert load_allowlist(path) == frozenset(
        {"github.com", "accounts.google.com", "mybank.example"}
    )
    # Header comment is present.
    assert path.read_text().startswith("# Cookie Janitor")


def test_save_strips_leading_dot_and_lowercases(tmp_path: Path):
    path = tmp_path / "allowlist.txt"
    save_allowlist(frozenset({".GitHub.com", "FOO.example"}), path)
    assert load_allowlist(path) == frozenset({"github.com", "foo.example"})


def test_load_ignores_comments_and_blank_lines(tmp_path: Path):
    path = tmp_path / "allowlist.txt"
    path.write_text(
        "# this is a comment\n"
        "\n"
        "github.com\n"
        "  bank.example  # inline comment\n"
        "https://bad.example/path\n"  # malformed, dropped
        "user@host.example\n"  # malformed, dropped
        "ok.example\n"
    )
    assert load_allowlist(path) == frozenset({"github.com", "bank.example", "ok.example"})


def test_add_to_allowlist_creates_file(tmp_path: Path):
    path = tmp_path / "subdir" / "allowlist.txt"
    after = add_to_allowlist("github.com", path)
    assert "github.com" in after
    assert load_allowlist(path) == frozenset({"github.com"})


def test_add_rejects_garbage(tmp_path: Path):
    path = tmp_path / "allowlist.txt"
    with pytest.raises(ValueError):
        add_to_allowlist("https://x.example/path", path)


def test_remove_is_idempotent(tmp_path: Path):
    path = tmp_path / "allowlist.txt"
    add_to_allowlist("github.com", path)
    remove_from_allowlist("github.com", path)
    remove_from_allowlist("github.com", path)  # second remove is fine
    assert load_allowlist(path) == frozenset()


def test_save_is_atomic_no_partial_on_existing_file(tmp_path: Path):
    """Sanity: a successful save fully replaces the file contents.

    We can't easily induce a crash mid-write in a unit test, but we can
    verify the round-trip doesn't leak old entries.
    """
    path = tmp_path / "allowlist.txt"
    save_allowlist(frozenset({"first.example"}), path)
    save_allowlist(frozenset({"second.example"}), path)
    assert load_allowlist(path) == frozenset({"second.example"})
