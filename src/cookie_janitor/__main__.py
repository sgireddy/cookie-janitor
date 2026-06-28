"""Package entry point for ``python -m cookie_janitor``.

The Briefcase-packaged macOS .app stub runs the bundled Python with
``python -m cookie_janitor``, which only works if the package exposes
a ``__main__`` module. Without this file the .app crashes at launch
with::

    No module named cookie_janitor.__main__;
    'cookie_janitor' is a package and cannot be directly executed

We delegate to the same ``gui.app:main`` entry point used by the
``cookie-janitor-gui`` console script so the .app and the
pip-installed CLI behave identically.
"""

from __future__ import annotations

from cookie_janitor.gui.app import main

raise SystemExit(main())
