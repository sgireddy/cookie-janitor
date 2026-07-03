"""GUI entry point. Called by the briefcase-packaged macOS .app and
Windows .msi, and by ``cookie-janitor-gui`` from a pip install with
the ``[gui]`` extra.
"""

from __future__ import annotations

import logging
import sys

from PySide6.QtWidgets import QApplication, QMessageBox

from cookie_janitor.safety.privilege import (
    PrivilegedExecutionError,
    assert_not_privileged,
)
from cookie_janitor.safety.redact import install_redacting_root_logger

from .window import MainWindow

log = logging.getLogger(__name__)


def main() -> int:
    # Set up logging FIRST so anything that fails after this line is
    # captured to disk. Under pythonw.exe (Briefcase Windows GUI apps)
    # the file handler is our only diagnostic channel — sys.stderr is
    # None there. See install_redacting_root_logger's docstring.
    log_path = install_redacting_root_logger(level=logging.INFO)
    log.info("cookie-janitor starting; log file: %s", log_path)

    try:
        assert_not_privileged()
    except PrivilegedExecutionError as exc:
        # Log first (goes to file even under pythonw), then pop a Qt
        # dialog so a GUI user actually SEES the refusal. Falling
        # through to `print(..., file=sys.stderr)` would silently
        # disappear under pythonw.exe — exactly the failure mode this
        # commit exists to eliminate.
        log.error("refusing to run with elevated privileges: %s", exc)
        _app = QApplication.instance() or QApplication(sys.argv)
        QMessageBox.critical(
            None,
            "Cookie Janitor — elevated privileges refused",
            f"Cookie Janitor refuses to run as Administrator/root.\n\n{exc}",
        )
        # Also print, but only if stderr is a real stream; otherwise
        # skip to avoid the AttributeError-on-None-write trap.
        if sys.stderr is not None:
            print(
                f"cookie-janitor: refusing to run with elevated privileges: {exc}",
                file=sys.stderr,
            )
        return 2

    app = QApplication(sys.argv)
    app.setApplicationName("Cookie Janitor")
    app.setOrganizationDomain("cookie-janitor.local")
    app.setOrganizationName("Cookie Janitor")

    window = MainWindow()
    window.show()
    log.info("main window shown; entering Qt event loop")
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
