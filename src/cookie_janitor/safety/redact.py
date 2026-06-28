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

import hashlib
import logging
import re
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


def install_redacting_root_logger(level: int = logging.INFO) -> None:
    """Install ``RedactingFormatter`` on the root logger.

    Idempotent: if a handler with this formatter is already installed,
    no-op. Call this once at process startup, in both the CLI and the
    GUI sidecar.
    """
    root = logging.getLogger()
    root.setLevel(level)
    for h in root.handlers:
        if isinstance(h.formatter, RedactingFormatter):
            return
    handler = logging.StreamHandler()
    handler.setFormatter(
        RedactingFormatter(
            fmt="%(asctime)s %(levelname)s %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
    )
    root.addHandler(handler)


def _scrub_any(_obj: Any) -> Any:
    """Reserved for future Pydantic model log helpers."""
    return _obj
