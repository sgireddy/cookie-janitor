import logging

from cookie_janitor.safety.redact import (
    RedactingFormatter,
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
