#!/usr/bin/env bash
# Build the Cookie Janitor macOS .app and .dmg locally.
#
# By default this produces a **universal2** DMG (`x86_64 + arm64` in one
# binary) so a single artefact runs on both Intel and Apple Silicon Macs.
# That is the recommended path for "I want an Intel build too" without
# owning an Intel Mac.
#
# Pass --native if you only want a DMG for your Mac's own architecture
# (faster build, smaller binary).
#
# Pass --identity "Developer ID Application: Your Name (TEAMID)" to sign
# with a real Apple Developer ID. Without it we ad-hoc sign and the user
# needs to right-click → Open the first time. We DO NOT support
# notarisation here — once you have an identity, run `notarytool` by hand
# (see docs/RELEASING.md, future TODO).
#
# Exit codes:
#   0  success — DMG at dist/Cookie-Janitor-<arch>.dmg with .sha256
#   1  preflight failed
#   2  build failed

set -euo pipefail

mode="universal2"
identity=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --native)    mode="native"; shift ;;
        --universal) mode="universal2"; shift ;;
        --identity)  identity="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "unknown flag: $1" >&2; exit 1 ;;
    esac
done

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

# Read the version up-front so the final DMG filename embeds it. This is
# important: scripts/release-mac.sh uses ``dist/Cookie-Janitor-${version}-*.dmg``
# to decide whether a usable build is already on disk. A version-less
# filename made it impossible to tell a stale v0.3.0 DMG apart from a
# fresh v0.4.0 one, so the reuse check fired against the old artefact
# and shipped the wrong DMG.
version="$(awk -F'"' '/^version = / { print $2; exit }' pyproject.toml)"
if [[ -z "$version" ]]; then
    echo "ERROR: could not read version from pyproject.toml" >&2
    exit 1
fi

# ---------------------------------------------------------------- preflight

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "ERROR: this script only runs on macOS." >&2
    exit 1
fi

if ! xcode-select -p > /dev/null 2>&1; then
    echo "ERROR: Xcode Command Line Tools not installed." >&2
    echo "  Run: xcode-select --install" >&2
    exit 1
fi

if ! command -v uv > /dev/null 2>&1; then
    echo "ERROR: uv not installed." >&2
    echo "  Run: curl -LsSf https://astral.sh/uv/install.sh | sh" >&2
    exit 1
fi

host_arch="$(uname -m)"   # arm64 on Apple Silicon, x86_64 on Intel
echo "Host architecture : $host_arch"
echo "Build mode        : $mode"
if [[ -n "$identity" ]]; then
    echo "Signing identity  : $identity"
else
    echo "Signing identity  : ad-hoc (Gatekeeper will warn on first open)"
fi

# ----------------------------------------------------------------- env setup

# Make sure the project + GUI extra are installed.
uv sync --extra gui

# Briefcase isn't a runtime dep; install it on demand into the project venv.
if ! uv run --no-sync briefcase --version > /dev/null 2>&1; then
    uv pip install "briefcase>=0.3.20"
fi

# ----------------------------------------------------------------- briefcase

# Clean any previous bundle so we never ship a stale .app.
rm -rf build/cookie_janitor dist

if [[ "$mode" == "universal2" ]]; then
    # Briefcase reads universal_build from pyproject; flip it on the
    # fly via env override so this script doesn't require a permanent
    # pyproject edit.
    export BRIEFCASE_MACOS_APP_UNIVERSAL_BUILD=true
    target_arch="universal2"
else
    export BRIEFCASE_MACOS_APP_UNIVERSAL_BUILD=false
    target_arch="$host_arch"
fi

# Step 1: create the .app skeleton from the template.
uv run briefcase create macOS app

# Step 2: compile the app.
uv run briefcase build macOS app

# Step 3: package into a .dmg. Pass identity through if supplied.
if [[ -n "$identity" ]]; then
    uv run briefcase package macOS app --identity "$identity"
else
    uv run briefcase package macOS app --adhoc-sign
fi

# ---------------------------------------------------------------- rename + sha

# Briefcase writes dist/Cookie Janitor-0.2.0.dmg (with a space). Rename
# to embed the version AND architecture so a glance at dist/ tells you
# what's in each file, and so release-mac.sh can match version-specific
# names without false positives from older builds. Keep this scheme in
# sync with release-mac.sh's reuse glob.
shopt -s nullglob
src_dmg=(dist/Cookie\ Janitor-*.dmg)
if [[ ${#src_dmg[@]} -eq 0 ]]; then
    echo "ERROR: no DMG produced under dist/" >&2
    exit 2
fi
final_dmg="dist/Cookie-Janitor-${version}-${target_arch}.dmg"
mv "${src_dmg[0]}" "$final_dmg"

shasum -a 256 "$final_dmg" | awk '{print $1}' > "${final_dmg}.sha256"

echo
echo "Built: $final_dmg"
echo "SHA-256: $(cat "${final_dmg}.sha256")"
echo
echo "Smoke test:"
echo "  open $final_dmg     # mounts the DMG"
echo "  # Then drag Cookie Janitor.app to /Applications."
echo "  # First launch: right-click the app -> Open (Gatekeeper warning)."
