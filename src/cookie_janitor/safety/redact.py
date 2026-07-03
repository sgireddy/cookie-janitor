"""Logging redaction for cookie-sensitive fields.

Hardening guarantee #11 (SECURITY.md): cookie values never appear in
logs. This module provides:

- ``RedactingFormatter``: a ``logging.Formatter`` that scrubs known
  sensitive structures from log records.
- ``redact_value(b)``: produce ``"<redacted len=N sha256=…8>"`` strings
  used everywhere we'd otherwise be tempted to log a cookie value.

We never include the raw value in any log message, so the redactor's job
is mostly defense-in-depth: if a future developer accidentally passes a
``Cookie``-like object with a value field, we still strip it.
"""

from __future__ import annotations

import contextlib
import hashlib
import logging
import os
import re
import sys
import traceback
from datetime import UTC, datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

# Match likely cookie-value occurrences in log strings: very conservative.
# We deliberately don't try to detect arbitrary secrets.
_KV_VALUE_RE = re.compile(
    r"(?P<key>(?:value|cookie_value|raw_value)\s*[:=]\s*)"
    r"(?P<quote>['\"]?)(?P<val>[^'\",\s]{6,})(?P=quote)",
    re.IGNORECASE,
)


def redact_value(value: bytes | str) -> str:
    """Return a redacted, length-and-fingerprint-only representation."""
    data = value.encode("utf-8", errors="replace") if isinstance(value, str) else value
    digest = hashlib.sha256(data).hexdigest()[:8]
    return f"<redacted len={len(data)} sha256={digest}>"


class RedactingFormatter(logging.Formatter):
    """A formatter that redacts cookie-value-shaped substrings in messages."""

    def format(self, record: logging.LogRecord) -> str:
        formatted = super().format(record)
        return _KV_VALUE_RE.sub(
            lambda m: f"{m.group('key')}{m.group('quote')}<redacted>{m.group('quote')}",
            formatted,
        )


def default_log_file_path() -> Path:
    """Return the best-effort per-user log-file path for this OS.

    Chosen locations mirror each platform's convention for "logs a
    desktop app writes":

    * **Windows** — ``%LOCALAPPDATA%\\cookie-janitor\\logs\\cookie-janitor.log``.
      ``LOCALAPPDATA`` is not part of a roaming profile, which is what
      we want: logs are diagnostic-only and shouldn't sync across
      machines.
    * **macOS** — ``~/Library/Logs/cookie-janitor/cookie-janitor.log``.
      Console.app surfaces this location automatically.
    * **Linux / other POSIX** — ``$XDG_STATE_HOME/cookie-janitor/cookie-janitor.log``
      (falling back to ``~/.local/state/cookie-janitor/…``). Per the
      XDG Base Directory spec, ``XDG_STATE_HOME`` is where "state data
      that should persist between (application) restarts" lives, and
      the spec explicitly names logs as an example.
    """
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA")
        root = Path(base) if base else Path.home() / "AppData" / "Local"
        return root / "cookie-janitor" / "logs" / "cookie-janitor.log"
    if sys.platform == "darwin":
        return (
            Path.home() / "Library" / "Logs" / "cookie-janitor" / "cookie-janitor.log"
        )
    xdg = os.environ.get("XDG_STATE_HOME")
    root = Path(xdg) if xdg else Path.home() / ".local" / "state"
    return root / "cookie-janitor" / "cookie-janitor.log"


def _install_last_resort_excepthook(log_path: Path) -> None:
    """Wire :data:`sys.excepthook` to persist tracebacks to the log file.

    Without this, an uncaught exception during startup under
    ``pythonw.exe`` (Briefcase's Windows launcher) produces the "app
    dies silently, nothing in Event Viewer" failure mode: pythonw has
    no console, so the default excepthook's traceback goes to a
    ``sys.stderr`` that is ``None`` and vanishes.

    We chain to the original hook so IDE and pytest integrations that
    replace ``sys.excepthook`` (e.g. debugger post-mortems) still work.
    """
    original = sys.excepthook

    def _hook(
        exc_type: type[BaseException],
        exc_value: BaseException,
        exc_tb: Any,
    ) -> None:
        try:
            with log_path.open("a", encoding="utf-8") as f:
                f.write(
                    f"\n=== UNCAUGHT EXCEPTION at "
                    f"{datetime.now(tz=UTC).isoformat()} ===\n"
                )
                traceback.print_exception(exc_type, exc_value, exc_tb, file=f)
        except OSError:
            # If we can't even write the traceback, we're already in
            # the failure mode this hook exists to escape. Fall
            # through to the original hook and let it try.
            pass
        original(exc_type, exc_value, exc_tb)

    sys.excepthook = _hook


def install_redacting_root_logger(
    level: int = logging.INFO,
    *,
    log_file: Path | None = None,
) -> Path | None:
    """Install redacting handlers on the root logger.

    Attaches, in order:

    1. A rotating **file handler** at :func:`default_log_file_path`
       (or ``log_file`` if given). This is the audit trail. It's the
       ONLY handler on Windows GUI builds because ``pythonw.exe``
       sets ``sys.stderr`` to ``None`` — attaching a
       :class:`~logging.StreamHandler` there and then emitting any
       record raises ``AttributeError`` in ``StreamHandler.emit`` and
       the process dies silently. That's the "MSI installs, app never
       launches" bug this function's second bullet point fixes.
    2. A **stream handler** on stderr, but only when
       ``sys.stderr is not None``. Developers running from source get
       coloured console output; the packaged GUI doesn't.
    3. A ``NullHandler`` as final fallback, so a locked-down system
       where we can neither write the log file nor emit to stderr
       still doesn't warn "no handlers".

    Also installs a :data:`sys.excepthook` that persists uncaught
    tracebacks to the log file, so a future silent-death regression is
    debuggable without a Windows debugger attached.

    Idempotent: if a handler with :class:`RedactingFormatter` is
    already installed, this is a no-op and the previously-configured
    log path (if any) is returned.

    Returns the resolved log-file path, or ``None`` if the file
    handler could not be created (read-only home, sandbox, etc.).
    """
    root = logging.getLogger()
    root.setLevel(level)

    for h in root.handlers:
        if isinstance(h.formatter, RedactingFormatter):
            return getattr(h, "_cookie_janitor_log_path", None)

    formatter = RedactingFormatter(
        fmt="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    resolved_path: Path | None = None
    target = log_file if log_file is not None else default_log_file_path()
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        # Best-effort private-mode on POSIX. Windows ignores the mode
        # bit; NTFS ACLs already keep %LOCALAPPDATA% private.
        if sys.platform != "win32":
            with contextlib.suppress(OSError):
                target.parent.chmod(0o700)
        # 1 MB x 3 rollovers = 4 MB ceiling. Enough for a week of
        # normal use; small enough to email if a user reports a bug.
        file_handler = RotatingFileHandler(
            target,
            maxBytes=1_000_000,
            backupCount=3,
            encoding="utf-8",
            delay=True,
        )
        file_handler.setFormatter(formatter)
        # Stash the path so the idempotency check can return it.
        file_handler._cookie_janitor_log_path = target  # type: ignore[attr-defined]
        root.addHandler(file_handler)
        resolved_path = target
    except OSError:
        # Can't create the log directory / file. Fall through — we'll
        # still try stderr, and worst case we install a NullHandler.
        # Do NOT crash startup over inability to log.
        pass

    if sys.stderr is not None:
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        root.addHandler(stream_handler)

    if not root.handlers:
        root.addHandler(logging.NullHandler())

    if resolved_path is not None:
        _install_last_resort_excepthook(resolved_path)

    return resolved_path


def _scrub_any(_obj: Any) -> Any:
    """Reserved for future Pydantic model log helpers."""
    return _obj
