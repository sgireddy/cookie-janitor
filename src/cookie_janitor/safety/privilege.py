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
    """Return ``True`` if the current process token is elevated.

    Implementation notes
    --------------------
    We call ``OpenProcessToken`` + ``GetTokenInformation(TokenElevation)``
    via :mod:`ctypes`. **Setting ``argtypes`` and ``restype`` on every
    Win32 function used here is not optional on 64-bit Windows.**
    Without them ctypes assumes ``c_int`` (32-bit) for pointer-shaped
    return values, and the ``HANDLE`` returned by ``GetCurrentProcess``
    gets silently truncated to 32 bits before being passed on.
    ``OpenProcessToken`` then fails with ``ERROR_INVALID_HANDLE`` (6),
    which is what produced the:

        "Could not determine process elevation state; refusing to
         continue."

    error users saw on v0.6.2 the first time it launched on Windows.

    If the check itself fails, we still fail **closed** (raise), but we
    now include the concrete Windows error code in the message so the
    next diagnosis doesn't need a Python debugger.
    """
    import ctypes
    from ctypes import wintypes

    TOKEN_QUERY = 0x0008
    TokenElevation = 20

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)  # type: ignore[attr-defined]
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]

    # ---- explicit prototypes (see docstring) --------------------------
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE

    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,  # ProcessHandle
        wintypes.DWORD,  # DesiredAccess
        ctypes.POINTER(wintypes.HANDLE),  # TokenHandle (out)
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL

    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,  # TokenHandle
        ctypes.c_int,  # TokenInformationClass
        ctypes.c_void_p,  # TokenInformation (out)
        wintypes.DWORD,  # TokenInformationLength
        ctypes.POINTER(wintypes.DWORD),  # ReturnLength (out)
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    # -------------------------------------------------------------------

    h_token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(h_token)
    ):
        err = ctypes.get_last_error()  # type: ignore[attr-defined]
        raise PrivilegedExecutionError(
            f"Could not determine process elevation state "
            f"(OpenProcessToken failed, Windows error {err}); "
            f"refusing to continue."
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
            err = ctypes.get_last_error()  # type: ignore[attr-defined]
            raise PrivilegedExecutionError(
                f"Could not query token elevation "
                f"(GetTokenInformation failed, Windows error {err}); "
                f"refusing to continue."
            )
        return bool(elevation.value)
    finally:
        kernel32.CloseHandle(h_token)
