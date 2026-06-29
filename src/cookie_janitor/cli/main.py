"""Typer CLI for cookie-janitor.

This is intentionally read-only / dry-run only in v1: it discovers
profiles, reads cookies, classifies them, and prints a clear table with
rationale. The destructive ``clean --apply`` path is added in a later
milestone, behind the safety primitives in ``cookie_janitor.safety``.
"""

from __future__ import annotations

import importlib.resources
import logging
import sys
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from cookie_janitor import __version__
from cookie_janitor.classify.cookie_db import CookieDatabase, load_database
from cookie_janitor.model.cookie import (
    BrowserKind,
    Decision,
    Profile,
    ScanResult,
    Verdict,
)
from cookie_janitor.policy.allowlist import load_allowlist
from cookie_janitor.policy.decide import ClassifierMode, UserPolicy, decide
from cookie_janitor.readers import discover_all_profiles, read_cookies
from cookie_janitor.safety.privilege import (
    PrivilegedExecutionError,
    assert_not_privileged,
)
from cookie_janitor.safety.process import BrowserRunningError
from cookie_janitor.safety.redact import install_redacting_root_logger

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help=(
        "cookie-janitor — see every cookie on your machine, why it's there, "
        "and decide what to keep. Dry-run only by default."
    ),
)

log = logging.getLogger("cookie_janitor.cli")


# --- Startup hooks -----------------------------------------------------------


def _preflight() -> None:
    """Run before every command. Order matters."""
    install_redacting_root_logger(level=logging.INFO)
    try:
        assert_not_privileged()
    except PrivilegedExecutionError as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(code=2) from exc


@app.callback()
def _main_callback() -> None:
    _preflight()


# --- Helpers -----------------------------------------------------------------


def _load_bundled_cookie_db() -> CookieDatabase:
    """Load the small bundled Open Cookie Database seed snapshot."""
    files = importlib.resources.files("cookie_janitor.data")
    seed = files / "cookie_db_seed.csv"
    with importlib.resources.as_file(seed) as path:
        # No hash check for the bundled snapshot: it's signed inside the
        # release artifact. External downloads via `update-lists` will
        # require a hash from the manifest.
        return load_database(path)


def _discover_all_profiles(browser: BrowserKind | None) -> list[Profile]:
    """Wrapper around the readers' dispatcher so the CLI keeps a single
    entry point (and so callers can be unit-tested with a stubbed
    dispatcher if needed in the future).
    """
    return discover_all_profiles(only=browser)


def _classify_profile(profile: Profile, policy: UserPolicy, db: CookieDatabase) -> ScanResult:
    cookies = read_cookies(profile)
    decisions: list[Decision] = [decide(c, policy=policy, cookie_db=db) for c in cookies]
    return ScanResult(profile=profile, decisions=tuple(decisions))


# --- Commands ----------------------------------------------------------------


@app.command()
def version() -> None:
    """Print the version and exit."""
    typer.echo(__version__)


@app.command()
def scan(
    browser: Annotated[
        BrowserKind | None,
        typer.Option(help="Limit to one browser family. Default: scan all supported."),
    ] = None,
) -> None:
    """List detected browser profiles, with cookie counts and run-state."""
    console = Console()
    profiles = _discover_all_profiles(browser)
    if not profiles:
        console.print(
            "[yellow]No profiles found.[/yellow] Either the browser is not "
            "installed for your user, or its profile dir is in a non-default "
            "location."
        )
        return

    table = Table(title="Detected browser profiles", show_lines=False)
    table.add_column("Browser")
    table.add_column("Vendor")
    table.add_column("Profile")
    table.add_column("Cookies path", overflow="fold")
    table.add_column("Running?")
    for p in profiles:
        table.add_row(
            p.browser.value,
            p.vendor,
            p.profile_name,
            str(p.cookies_db_path),
            "[red]yes[/red]" if p.is_running else "[green]no[/green]",
        )
    console.print(table)


@app.command(name="list")
def list_cookies(
    browser: Annotated[
        BrowserKind | None, typer.Option(help="Limit to one browser family.")
    ] = None,
    profile_name: Annotated[
        str | None,
        typer.Option("--profile", help="Limit to a specific profile name."),
    ] = None,
    show_value_hash: Annotated[
        bool,
        typer.Option(
            "--show-value-hash",
            help=(
                "Show the short value fingerprint column. Off by default. "
                "Even when on, raw values are never displayed."
            ),
        ),
    ] = False,
    mode: Annotated[
        ClassifierMode,
        typer.Option(
            "--mode",
            help=(
                "Classifier mode (a ladder, weakest to strongest). "
                "audit-only: never recommends deletion. "
                "conservative: only Open Cookie Database analytics/marketing. "
                "balanced (default): also tracker domains, subdomain labels, "
                "tracker cookie names. "
                "strict: also Open Cookie Database performance. "
                "aggressive: also long-lived non-auth and unknown. "
                "scorched-earth: everything except allow-list and "
                "__Host-/__Secure- prefixes."
            ),
        ),
    ] = ClassifierMode.BALANCED,
) -> None:
    """Show every cookie in every matching profile, with classification."""
    console = Console()
    profiles = _discover_all_profiles(browser)
    if profile_name:
        profiles = [p for p in profiles if p.profile_name == profile_name]
    if not profiles:
        console.print("[yellow]No profiles match.[/yellow]")
        return

    db = _load_bundled_cookie_db()
    policy = UserPolicy(keep_domains=load_allowlist(), mode=mode)

    for profile in profiles:
        if profile.is_running:
            console.print(
                f"[yellow]Skipping {profile.display}: browser is currently "
                f"running. Close it and re-run.[/yellow]"
            )
            continue
        try:
            result = _classify_profile(profile, policy, db)
        except BrowserRunningError as exc:
            console.print(f"[red]{exc}[/red]")
            continue
        _render_result(console, result, show_value_hash=show_value_hash)


def _render_result(console: Console, result: ScanResult, *, show_value_hash: bool) -> None:
    table = Table(
        title=f"Cookies in {result.profile.display}",
        show_lines=False,
        caption=(
            f"Total {len(result.decisions)} cookies — "
            f"would keep {result.counts_by_verdict[Verdict.KEEP]}, "
            f"would delete {result.counts_by_verdict[Verdict.DELETE]} "
            f"(dry-run; nothing has been changed)"
        ),
    )
    table.add_column("Verdict", no_wrap=True)
    table.add_column("Domain", overflow="fold")
    table.add_column("Name", overflow="fold")
    table.add_column("Category")
    table.add_column("Expiry")
    if show_value_hash:
        table.add_column("Value (sha256[:8] / len)")
    table.add_column("Why we think so", overflow="fold")

    # Sort: deletes first, then by domain.
    rows = sorted(
        result.decisions,
        key=lambda d: (d.verdict is not Verdict.DELETE, d.cookie.domain, d.cookie.name),
    )
    for d in rows:
        verdict_styled = (
            "[red]delete[/red]" if d.verdict is Verdict.DELETE else "[green]keep[/green]"
        )
        expiry = "session" if d.cookie.expires is None else d.cookie.expires.isoformat()
        row = [
            verdict_styled,
            d.cookie.domain,
            d.cookie.name,
            d.category.value,
            expiry,
        ]
        if show_value_hash:
            row.append(f"{d.cookie.value_sha256_prefix} / {d.cookie.value_length}")
        row.append(d.rationale)
        table.add_row(*row)
    console.print(table)


@app.command()
def restore(
    backup_path: Annotated[
        str,
        typer.Argument(
            help=(
                "Path to a previously-created backup of cookies.sqlite "
                "(printed by the GUI or by `clean --apply`)."
            ),
        ),
    ],
) -> None:
    """Atomically restore a profile's cookies from a backup file.

    The browser must not be running. The backup file must be a regular
    file you own. Path metadata in the backup file's directory is used
    to identify which profile to restore into.
    """
    from pathlib import Path as _Path

    from cookie_janitor.writers import restore_from_backup

    bp = _Path(backup_path).expanduser().resolve()
    if not bp.is_file():
        typer.echo(f"ERROR: not a regular file: {bp}", err=True)
        raise typer.Exit(code=2)

    # Backup layout: <root>/<browser>/<profile_name>/<ts>/cookies.sqlite.
    try:
        profile_name = bp.parent.parent.name
        browser_name = bp.parent.parent.parent.name
    except (AttributeError, IndexError):
        typer.echo(
            "ERROR: backup path doesn't look like a cookie-janitor backup tree",
            err=True,
        )
        raise typer.Exit(code=2) from None
    try:
        browser_kind = BrowserKind(browser_name)
    except ValueError:
        typer.echo(
            f"ERROR: backup path browser segment {browser_name!r} is not a"
            f" recognised browser family (expected one of:"
            f" {[b.value for b in BrowserKind]}).",
            err=True,
        )
        raise typer.Exit(code=2) from None

    profiles = discover_all_profiles(only=browser_kind)
    matches = [p for p in profiles if p.profile_name == profile_name]
    if not matches:
        typer.echo(
            f"ERROR: no {browser_kind.value} profile named {profile_name!r}"
            f" found on this machine",
            err=True,
        )
        raise typer.Exit(code=2)
    profile = matches[0]

    try:
        restore_from_backup(profile, bp)
    except (BrowserRunningError, RuntimeError) as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    typer.echo(f"Restored {profile.display} from {bp}")


def main() -> None:  # pragma: no cover - thin wrapper
    try:
        app()
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":  # pragma: no cover
    main()
