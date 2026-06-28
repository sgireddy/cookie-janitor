"""Refuse to run as a privileged user.

See SECURITY.md hardening guarantee #1 and AGENTS.md D8.

Cookie stores live under the user's home directory; running as root or
Administrator only widens the attack surface (BleachBit-style file-delete
privesc, CVE-2026-55567, would not have been possible if the tool refused
elevation).
"""

from __future__ import annotations

import os
import sys


class PrivilegedExecutionError(RuntimeError):
    """Raised when cookie-janitor is invoked with elevated privileges."""


def assert_not_privileged() -> None:
    """Raise ``PrivilegedExecutionError`` if running as root / Administrator.

    On POSIX, "privileged" means effective UID 0.

    On Windows, "privileged" means the process token is elevated. We use
    ``ctypes`` to call ``GetTokenInformation`` with ``TokenElevation``.
    If the lookup itself fails, we fail closed (raise) rather than
    silently allow execution.
    """
    if sys.platform == "win32":
        if _windows_is_elevated():
            raise PrivilegedExecutionError(
                "cookie-janitor refuses to run as Administrator. "
                "Cookie stores live in your own user profile and elevation "
                "is not required. Open a normal command prompt and try again."
            )
        return

    # POSIX: macOS, Linux, *BSD.
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise PrivilegedExecutionError(
            "cookie-janitor refuses to run as root. "
            "Cookie stores live in your home directory and root is not "
            "required. Re-run without sudo."
        )


def _windows_is_elevated() -> bool:  # pragma: no cover - exercised only on Windows
    """Return True if the current process token is elevated."""
    import ctypes
    from ctypes import wintypes

    TOKEN_QUERY = 0x0008
    TokenElevation = 20

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)  # type: ignore[attr-defined]
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]

    h_token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(h_token)
    ):
        # Fail closed: if we cannot determine elevation, refuse.
        raise PrivilegedExecutionError(
            "Could not determine process elevation state; refusing to continue."
        )
    try:
        elevation = wintypes.DWORD(0)
        size = wintypes.DWORD(0)
        if not advapi32.GetTokenInformation(
            h_token,
            TokenElevation,
            ctypes.byref(elevation),
            ctypes.sizeof(elevation),
            ctypes.byref(size),
        ):
            raise PrivilegedExecutionError("Could not query token elevation; refusing to continue.")
        return bool(elevation.value)
    finally:
        kernel32.CloseHandle(h_token)
