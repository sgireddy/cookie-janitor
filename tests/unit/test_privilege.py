import sys

import pytest

from cookie_janitor.safety import privilege as priv
from cookie_janitor.safety.privilege import (
    PrivilegedExecutionError,
    assert_not_privileged,
)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only test")
def test_refuses_to_run_as_root(monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 0)
    with pytest.raises(PrivilegedExecutionError, match="root"):
        assert_not_privileged()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only test")
def test_allows_normal_user(monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 1000)
    assert_not_privileged()  # should not raise


# ---------------------------------------------------------------------------
# Windows-path tests. We can't exercise the real ctypes calls on Linux CI,
# but we CAN pin the platform-dispatch and failure-propagation contract by
# monkeypatching ``sys.platform`` and stubbing ``_windows_is_elevated``.
#
# The bug this test file grew for: v0.6.2 on 64-bit Windows raised
# "Could not determine process elevation state; refusing to continue."
# even for a normal (non-elevated) user, because ``_windows_is_elevated``
# didn't set ``argtypes`` on the Win32 calls it used, causing ``HANDLE``
# truncation and an ``ERROR_INVALID_HANDLE`` from ``OpenProcessToken``.
# See _windows_is_elevated's docstring for detail.
# ---------------------------------------------------------------------------


def test_windows_elevated_raises(monkeypatch):
    """When elevation detection succeeds and reports ELEVATED, refuse."""
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(priv, "_windows_is_elevated", lambda: True)
    with pytest.raises(PrivilegedExecutionError, match="Administrator"):
        assert_not_privileged()


def test_windows_not_elevated_passes(monkeypatch):
    """When elevation detection succeeds and reports NOT ELEVATED, allow.

    This is the case the v0.6.2 bug broke: normal user account, no UAC
    prompt, but the app refused to run because the detection itself
    was silently failing.
    """
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(priv, "_windows_is_elevated", lambda: False)
    assert_not_privileged()  # must not raise


def test_windows_check_failure_propagates_with_error_code(monkeypatch):
    """When the ctypes plumbing itself fails, we fail closed AND the
    error message must include the concrete Windows error code so the
    user has something diagnosable to send us.
    """
    def _boom() -> bool:
        raise PrivilegedExecutionError(
            "Could not determine process elevation state "
            "(OpenProcessToken failed, Windows error 6); "
            "refusing to continue."
        )

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(priv, "_windows_is_elevated", _boom)
    with pytest.raises(PrivilegedExecutionError) as excinfo:
        assert_not_privileged()
    # The Windows error code MUST appear in the message. Without it we
    # can't tell ERROR_INVALID_HANDLE (6, our old bug) apart from
    # ERROR_ACCESS_DENIED (5) or anything else.
    assert "Windows error 6" in str(excinfo.value)


def test_windows_is_elevated_declares_ctypes_prototypes():
    """Regression test for the specific v0.6.2 bug.

    We can't call the real Win32 APIs from Linux CI, but we CAN
    verify that the source code of ``_windows_is_elevated`` sets
    ``argtypes`` and ``restype`` on every Win32 function it uses.
    Missing prototypes = 64-bit HANDLE truncation = the exact
    "OpenProcessToken failed, Windows error 6" bug that killed
    v0.6.2 on first launch.

    Yes, source-level assertions are brittle — but the alternative
    (waiting for a user report) is worse. If we ever refactor this
    module we WILL notice this test fail, and that's a moment to
    reason explicitly about whether prototypes are still needed.
    """
    import inspect

    src = inspect.getsource(priv._windows_is_elevated)

    required = [
        "OpenProcessToken.argtypes",
        "OpenProcessToken.restype",
        "GetTokenInformation.argtypes",
        "GetTokenInformation.restype",
        "GetCurrentProcess.restype",
        "CloseHandle.argtypes",
    ]
    missing = [name for name in required if name not in src]
    assert not missing, (
        f"_windows_is_elevated must set ctypes prototypes for "
        f"{missing}. Without them, HANDLE gets truncated to 32 bits "
        f"on 64-bit Windows and OpenProcessToken fails with "
        f"ERROR_INVALID_HANDLE. See the docstring."
    )
