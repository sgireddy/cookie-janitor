"""CLI entry point. Re-exports the ``app`` Typer instance for setuptools."""

from cookie_janitor.cli.main import app

__all__ = ["app"]
