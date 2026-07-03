"""cookie-janitor — transparent, user-controlled cookie management.

This package is the security-sensitive core. It is invoked by both the
CLI and the GUI sidecar (same binary, different entrypoints). It performs
no network I/O during cookie operations and never runs as root.
"""

from __future__ import annotations

__version__ = "0.6.4"
__all__ = ["__version__"]
