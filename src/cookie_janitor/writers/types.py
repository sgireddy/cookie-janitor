"""Shared data types for writers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from cookie_janitor.model.cookie import Profile


@dataclass(frozen=True, slots=True)
class WriteResult:
    """Outcome of a write operation.

    All fields are present whether the operation succeeded or was a
    dry-run. ``backup_path`` is ``None`` on dry-runs.
    """

    profile: Profile
    requested_deletes: int
    actually_deleted: int
    backup_path: Path | None
    dry_run: bool
    timestamp: datetime
