"""GUI entry point. Called by the briefcase-packaged macOS .app and by
``cookie-janitor-gui`` from a pip install with the ``[gui]`` extra.
"""

from __future__ import annotations

import logging
import sys

from PySide6.QtWidgets import QApplication

from cookie_janitor.safety.privilege import (
    PrivilegedExecutionError,
    assert_not_privileged,
)
from cookie_janitor.safety.redact import install_redacting_root_logger

from .window import MainWindow


def main() -> int:
    install_redacting_root_logger(level=logging.INFO)
    try:
        assert_not_privileged()
    except PrivilegedExecutionError as exc:
        # We can't pop a Qt dialog before QApplication; print and bail.
        print(f"cookie-janitor: refusing to run with elevated privileges: {exc}", file=sys.stderr)
        return 2

    app = QApplication(sys.argv)
    app.setApplicationName("Cookie Janitor")
    app.setOrganizationDomain("cookie-janitor.local")
    app.setOrganizationName("Cookie Janitor")

    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
