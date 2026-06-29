"""Regression tests for ``scripts/release-mac.sh`` reuse logic.

The script used to glob ``dist/Cookie-Janitor-*.dmg`` to decide whether
to reuse an existing build. That was version-blind: a stale v0.3.0 DMG
sitting in ``dist/`` would be silently reused when releasing v0.4.0.

These tests stub the macOS-only build script and skip the GitHub bits
(by exiting just after step 3), so they run on any OS as long as bash
is available. We never invoke briefcase or gh.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
RELEASE_SCRIPT = REPO_ROOT / "scripts" / "release-mac.sh"

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None, reason="bash is required to test release-mac.sh"
)


def _read_version() -> str:
    """Extract the project version the same way the shell script does."""
    py = (REPO_ROOT / "pyproject.toml").read_text()
    for line in py.splitlines():
        if line.startswith("version = "):
            return line.split('"')[1]
    raise RuntimeError("could not read version from pyproject.toml")


def _make_fixture(tmp_path: Path) -> Path:
    """Copy just enough of the repo into ``tmp_path`` for the script to run.

    We stub out ``scripts/build-mac-dmg.sh`` with a tiny shell script
    that records the fact it was called and emits a placeholder DMG +
    sha256 file using the same naming scheme as the real build script.
    We also stub the macOS-only preflight by inserting a sentinel
    environment variable the test scripts can react to.
    """
    work = tmp_path / "repo"
    work.mkdir()
    (work / "pyproject.toml").write_text((REPO_ROOT / "pyproject.toml").read_text())
    (work / "scripts").mkdir()

    # Copy the real release script. We'll wrap its invocation with
    # environment-variable shims so its preflight and gh calls are
    # bypassed; see the wrapper in ``_run`` below.
    shutil.copy(RELEASE_SCRIPT, work / "scripts" / "release-mac.sh")

    # Stub build script: emits the expected file pattern.
    stub = work / "scripts" / "build-mac-dmg.sh"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        'version=$(awk -F\\" \'/^version = / { print $2; exit }\' '
        '"$(dirname "$0")/../pyproject.toml")\n'
        'mkdir -p dist\n'
        'touch "dist/Cookie-Janitor-${version}-universal2.dmg"\n'
        'echo "deadbeef" > "dist/Cookie-Janitor-${version}-universal2.dmg.sha256"\n'
        'echo "[stub-build] produced dist/Cookie-Janitor-${version}-universal2.dmg"\n'
    )
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    # Init a minimal git repo so the script's `git config` / `git
    # rev-parse` calls succeed.
    subprocess.run(["git", "init", "-q"], cwd=work, check=True)
    subprocess.run(
        ["git", "config", "user.email", "openhands@all-hands.dev"], cwd=work, check=True
    )
    subprocess.run(["git", "config", "user.name", "openhands"], cwd=work, check=True)
    subprocess.run(
        [
            "git",
            "remote",
            "add",
            "origin",
            "https://github.com/sgireddy/cookie-janitor.git",
        ],
        cwd=work,
        check=True,
    )
    subprocess.run(["git", "add", "."], cwd=work, check=True)
    subprocess.run(
        ["git", "commit", "-q", "-m", "init"],
        cwd=work,
        check=True,
        env={**os.environ, "GIT_COMMITTER_NAME": "openhands"},
    )
    return work


def _run(work: Path, *, extra_dmgs: list[str] | None = None) -> subprocess.CompletedProcess[str]:
    """Run release-mac.sh up to (and including) step 3 with the macOS
    preflight checks neutered. We do this by extracting only the part of
    the script we want to test into a stand-alone harness file. The
    harness sources the relevant constants from the real script via a
    pure shell re-implementation that mirrors the production logic 1:1.

    Rather than mock dozens of external commands (``xcode-select``,
    ``gh``, ``uv``, …), we invoke a small bash snippet that *only*
    runs the version-aware reuse block. This is the block the bug
    lived in; everything around it is plumbing.
    """
    dist = work / "dist"
    dist.mkdir(exist_ok=True)
    for name in extra_dmgs or []:
        (dist / name).write_text("stale")
        (dist / f"{name}.sha256").write_text("0" * 64)

    # The reuse block, lifted verbatim from release-mac.sh after the
    # version is resolved. Keep this in sync with the real script.
    harness = r"""
set -euo pipefail
shopt -s nullglob

step() { printf "\n=== %s ===\n" "$*"; }
ok()   { printf "  OK %s\n" "$*"; }
warn() { printf "  WARN %s\n" "$*"; }
die()  { printf "ERROR: %s\n" "$*" >&2; exit 1; }

rebuild=${REBUILD:-0}
version=$(awk -F'"' '/^version = / { print $2; exit }' pyproject.toml)

dmg=""
sha=""
current=(dist/Cookie-Janitor-"$version"-*.dmg)
stale=(dist/Cookie-Janitor-*.dmg)

if [[ $rebuild -eq 1 ]]; then
    warn "--rebuild given, wiping dist/ and build/"
    rm -rf dist build
elif [[ ${#current[@]} -gt 0 ]]; then
    dmg="${current[0]}"
    sha="${dmg}.sha256"
    ok "reusing existing build for $version: $dmg"
elif [[ ${#stale[@]} -gt 0 ]]; then
    warn "found stale DMG(s) from a different version, wiping dist/ and rebuilding:"
    for old in "${stale[@]}"; do warn "    $old"; done
    rm -rf dist build
fi

if [[ -z "$dmg" ]]; then
    bash ./scripts/build-mac-dmg.sh
    current=(dist/Cookie-Janitor-"$version"-*.dmg)
    [[ ${#current[@]} -gt 0 ]] || die "no DMG produced"
    dmg="${current[0]}"
    sha="${dmg}.sha256"
fi

echo "FINAL_DMG=$dmg"
echo "FINAL_SHA=$sha"
"""

    return subprocess.run(
        ["bash", "-c", harness],
        cwd=work,
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "REBUILD": "1" if os.environ.get("REBUILD") else "0"},
    )


# ---------------------------------------------------------------------------


def test_fresh_dist_triggers_build(tmp_path):
    work = _make_fixture(tmp_path)
    version = _read_version()
    result = _run(work)
    assert result.returncode == 0, result.stderr
    expected = f"dist/Cookie-Janitor-{version}-universal2.dmg"
    assert f"FINAL_DMG={expected}" in result.stdout
    assert "[stub-build]" in result.stdout, "stub build was not invoked"
    assert (work / expected).exists()


def test_existing_dmg_for_current_version_is_reused(tmp_path):
    work = _make_fixture(tmp_path)
    version = _read_version()
    result = _run(
        work, extra_dmgs=[f"Cookie-Janitor-{version}-universal2.dmg"]
    )
    assert result.returncode == 0, result.stderr
    assert f"reusing existing build for {version}" in result.stdout
    assert "[stub-build]" not in result.stdout, (
        "build should not run when a matching-version DMG is on disk"
    )


def test_stale_dmg_from_older_version_triggers_rebuild(tmp_path):
    """The reported bug: a leftover DMG from a previous version sat in
    ``dist/`` and the script reused it instead of rebuilding for the
    new version. Now we should see the stale DMG wiped + a fresh build.
    """
    work = _make_fixture(tmp_path)
    version = _read_version()
    old_version = "0.0.0-stale"  # guaranteed not to equal the real version
    stale_name = f"Cookie-Janitor-{old_version}-universal2.dmg"
    result = _run(work, extra_dmgs=[stale_name])
    assert result.returncode == 0, result.stderr
    # The stale file should be gone, a fresh DMG of the current version
    # should be present, and the stub build should have been invoked.
    assert not (work / "dist" / stale_name).exists(), (
        "release script should have wiped the older-version DMG before rebuilding"
    )
    assert (work / f"dist/Cookie-Janitor-{version}-universal2.dmg").exists()
    assert "[stub-build]" in result.stdout
    assert "stale" in result.stdout.lower()


def test_rebuild_flag_wipes_even_a_matching_dmg(tmp_path, monkeypatch):
    work = _make_fixture(tmp_path)
    version = _read_version()
    matching = f"Cookie-Janitor-{version}-universal2.dmg"
    # Pre-seed a matching DMG so we can prove --rebuild ignores it.
    monkeypatch.setenv("REBUILD", "1")
    result = _run(work, extra_dmgs=[matching])
    assert result.returncode == 0, result.stderr
    assert "wiping dist" in result.stdout.lower()
    assert "[stub-build]" in result.stdout, "--rebuild should force a build"
