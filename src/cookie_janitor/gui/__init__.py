"""Cookie Janitor desktop GUI.

A thin PySide6 layer over the existing classifier and writer. The GUI
deliberately does not own any logic — it asks the same `read_cookies`,
`decide`, `delete_cookies` functions the CLI uses. That way the
"transparent" claim holds: the GUI cannot hide a delete that the CLI
wouldn't perform.
"""

from __future__ import annotations
