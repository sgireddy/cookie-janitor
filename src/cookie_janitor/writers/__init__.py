"""Browser-specific cookie writers.

Writers must satisfy three invariants:

1. Operate on a private copy of the cookie store, then atomically
   replace the original via the safety primitives in
   ``cookie_janitor.safety.fs``. Never write to the original directly.
2. Always produce a verified backup of the original before performing
   the swap. The backup path is reported in the result so the user (or
   the ``restore`` command) can roll back.
3. Refuse to operate while the target browser is running.

The shared ``WriteResult`` dataclass describes what happened in
machine-readable form, and is what the CLI / GUI surfaces.
"""

from __future__ import annotations

from .types import WriteResult

__all__ = ["WriteResult"]
