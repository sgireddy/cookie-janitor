from __future__ import annotations

import contextlib
import logging
import sys

from cookie_janitor.safety.redact import (
    RedactingFormatter,
    default_log_file_path,
    install_redacting_root_logger,
    redact_value,
)


def test_redact_value_includes_length_and_prefix():
    out = redact_value(b"hello-world")
    assert "len=11" in out
    assert out.startswith("<redacted len=")


def test_redacting_formatter_strips_value_assignments():
    fmt = RedactingFormatter("%(message)s")
    record = logging.LogRecord(
        name="t",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg='reading cookie: name="SID" value="hunter2-bearer-token"',
        args=None,
        exc_info=None,
    )
    out = fmt.format(record)
    assert "hunter2-bearer-token" not in out
    assert "<redacted>" in out


def test_install_is_idempotent():
    install_redacting_root_logger()
    before = len(logging.getLogger().handlers)
    install_redacting_root_logger()
    after = len(logging.getLogger().handlers)
    assert before == after


# ---------------------------------------------------------------------------
# Regression tests for the "MSI installs but the app never opens" failure
# on Windows. Under Briefcase's pythonw.exe launcher, sys.stderr is None,
# and any logging.StreamHandler attached to it crashes the process on the
# first log call. See install_redacting_root_logger docstring for detail.
# ---------------------------------------------------------------------------


def _reset_root_logger():
    """Wipe root-logger state so each test starts from a clean slate."""
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
        with contextlib.suppress(Exception):
            h.close()
    root.setLevel(logging.WARNING)


def test_default_log_file_path_uses_platform_convention(monkeypatch, tmp_path):
    """The log-file location must match each OS's expectation.

    We can't just call the function three times — sys.platform is
    immutable per interpreter. Instead we set the right env vars and
    assert the SUFFIX matches for the current platform. The full
    per-platform behaviour is exercised in CI where all three OSes run.
    """
    path = default_log_file_path()
    assert path.name == "cookie-janitor.log"
    assert "cookie-janitor" in path.parts
    # Every platform we support must produce an absolute path — a
    # relative one would resolve against the CWD of whoever launched
    # the app, which is unpredictable and would land logs in random
    # spots on the filesystem.
    assert path.is_absolute()


def test_default_log_file_path_honours_xdg_state_home_on_posix(
    monkeypatch, tmp_path
):
    """On Linux, ``XDG_STATE_HOME`` overrides the fallback."""
    if sys.platform not in ("linux", "linux2"):
        # Other POSIXes (macOS/win) have their own conventions
        # tested at run-time on those OSes.
        return
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    path = default_log_file_path()
    assert str(path).startswith(str(tmp_path / "state"))
    assert path.name == "cookie-janitor.log"


def test_install_survives_when_stderr_is_none(monkeypatch, tmp_path):
    """The core Windows-pythonw regression test.

    Simulate ``pythonw.exe`` by setting ``sys.stderr = None`` and
    confirm that:

    1. ``install_redacting_root_logger`` doesn't raise.
    2. It does NOT attach a StreamHandler (which would crash on the
       first ``.emit()`` call).
    3. A subsequent ``log.warning(...)`` — the exact call chromium
       reader makes during startup profile discovery — also doesn't
       raise. This is the specific call that used to kill the packaged
       Windows GUI.
    """
    _reset_root_logger()
    monkeypatch.setattr(sys, "stderr", None)

    log_file = tmp_path / "cj" / "cookie-janitor.log"
    resolved = install_redacting_root_logger(log_file=log_file)
    assert resolved == log_file

    # No StreamHandler must be attached — the whole point of the fix.
    handlers = logging.getLogger().handlers
    assert not any(
        isinstance(h, logging.StreamHandler)
        and not isinstance(h, logging.FileHandler)
        for h in handlers
    )

    # And the previously-crashing log call now succeeds. If this
    # ever raises, the packaged Windows app is broken again.
    logging.getLogger("cookie_janitor.readers.chromium").warning(
        "Could not list %s: %s", "/fake/root", "some error"
    )

    # The file handler is RotatingFileHandler with delay=True, so the
    # file only exists once we've actually written to it. The warning
    # above should have triggered creation. Flush to be sure.
    for h in handlers:
        h.flush()
    assert log_file.exists(), "warning should have created the log file"

    contents = log_file.read_text(encoding="utf-8")
    assert "Could not list" in contents


def test_install_still_attaches_stream_handler_when_stderr_is_real(tmp_path):
    """The dev-mode path — running from source with a real terminal —
    must keep the stream handler so developers see live output.
    """
    _reset_root_logger()
    # sys.stderr is real in pytest by default.
    install_redacting_root_logger(log_file=tmp_path / "cj.log")
    stream_handlers = [
        h
        for h in logging.getLogger().handlers
        if isinstance(h, logging.StreamHandler)
        and not isinstance(h, logging.FileHandler)
    ]
    assert len(stream_handlers) == 1


def test_install_writes_to_the_configured_log_file(tmp_path):
    """End-to-end: a log message emitted after install lands in the
    file specified. This is the audit-trail guarantee.
    """
    _reset_root_logger()
    log_file = tmp_path / "audit" / "cookie-janitor.log"
    install_redacting_root_logger(log_file=log_file)

    logging.getLogger("test").info("hello world from cookie-janitor")

    for h in logging.getLogger().handlers:
        h.flush()

    assert log_file.exists()
    text = log_file.read_text(encoding="utf-8")
    assert "hello world from cookie-janitor" in text


def test_install_survives_when_log_directory_is_uncreatable(monkeypatch, tmp_path):
    """A read-only home / sandboxed process must not crash startup.

    The user still gets a working app (via NullHandler or the stderr
    handler if available); we just lose the file audit trail. Making
    this an OSError-swallow rather than a raise is deliberate — the
    priority is "app opens", not "logs land on disk".
    """
    _reset_root_logger()

    # Point the log file at a path where mkdir will fail.
    unwriteable = tmp_path / "readonly-file"
    unwriteable.write_text("i am a file, not a directory")
    log_file = unwriteable / "cannot" / "cookie-janitor.log"

    # Must not raise.
    resolved = install_redacting_root_logger(log_file=log_file)
    assert resolved is None  # signals "no file audit trail available"

    # And the app can still log — the call must NOT crash.
    logging.getLogger("test").warning("something bad happened")


def test_install_returns_none_when_stderr_none_and_file_fails(monkeypatch, tmp_path):
    """Belt-and-braces: when we can neither write the file NOR use
    stderr, we must still attach *something* (a NullHandler) so log
    calls remain no-ops rather than warnings.
    """
    _reset_root_logger()
    monkeypatch.setattr(sys, "stderr", None)

    unwriteable = tmp_path / "readonly-file"
    unwriteable.write_text("blocker")
    log_file = unwriteable / "nope" / "cookie-janitor.log"

    install_redacting_root_logger(log_file=log_file)

    handlers = logging.getLogger().handlers
    assert handlers, "root logger must have at least a NullHandler"
    # No live log calls should raise.
    logging.getLogger("test").error("still alive")
