import sys

import pytest

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
