#!/usr/bin/env bash
# scripts/release-mac.sh -- one-shot macOS release.
#
# What this script does, in order:
#   1. Sanity-check the environment (macOS, Xcode CLT, uv, gh).
#   2. Read the version from pyproject.toml.
#   3. Build the universal2 DMG via scripts/build-mac-dmg.sh
#      (skips this step if the DMG already exists and --rebuild was
#      not given).
#   4. Make sure a git tag matching the version exists locally and on
#      the remote.
#   5. Create (or update) a draft GitHub Release for that tag and
#      attach the DMG + .sha256.
#   6. Print the URL of the draft release for you to review and
#      publish from the web UI.
#
# Defaults: builds universal2, ad-hoc signed, draft release (so nothing
# becomes public until you click Publish in the GitHub UI).
#
# Flags:
#   --rebuild           Force a fresh build even if dist/*.dmg exists.
#   --native            Build only this Mac's architecture (faster,
#                       smaller, but no Intel support if built on M1+).
#   --publish           Publish the release immediately instead of
#                       leaving it as a draft. (Not recommended until
#                       you've smoke-tested the .app.)
#   --identity NAME     Pass a Developer ID identity to codesign with.
#                       Default is ad-hoc.
#   --tag vX.Y.Z        Use this tag instead of v<pyproject version>.
#   -h, --help          Print this help.
#
# Idempotency: re-running is safe. If the release already exists the
# assets are uploaded with --clobber. If the tag already points at HEAD
# it is left alone; if it points elsewhere the script refuses rather
# than rewrite history.

set -euo pipefail

rebuild=0
mode_flag=""
publish=0
identity=""
override_tag=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --rebuild)   rebuild=1; shift ;;
        --native)    mode_flag="--native"; shift ;;
        --publish)   publish=1; shift ;;
        --identity)  identity="$2"; shift 2 ;;
        --tag)       override_tag="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "unknown flag: $1" >&2; exit 1 ;;
    esac
done

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

# ----------------------------------------------------------- step 1: preflight

step() { printf "\n\033[1;36m=== %s ===\033[0m\n" "$*"; }
ok()   { printf "  \033[32m✓\033[0m %s\n" "$*"; }
warn() { printf "  \033[33m!\033[0m %s\n" "$*"; }
die()  { printf "\n\033[31mERROR:\033[0m %s\n" "$*" >&2; exit 1; }

step "Preflight"

[[ "$(uname -s)" == "Darwin" ]] || die "this script only runs on macOS."

if ! xcode-select -p > /dev/null 2>&1; then
    die "Xcode Command Line Tools not installed. Run: xcode-select --install"
fi
ok "Xcode Command Line Tools: $(xcode-select -p)"

# uv may have just been installed to ~/.local/bin and not be on PATH yet.
if ! command -v uv > /dev/null 2>&1; then
    if [[ -x "$HOME/.local/bin/uv" ]]; then
        export PATH="$HOME/.local/bin:$PATH"
        ok "added \$HOME/.local/bin to PATH for this run"
    else
        die "uv not installed. Run: curl -LsSf https://astral.sh/uv/install.sh | sh"
    fi
fi
ok "uv: $(uv --version)"

if ! command -v gh > /dev/null 2>&1; then
    die "GitHub CLI (gh) not installed. Run: brew install gh"
fi
if ! gh auth status > /dev/null 2>&1; then
    die "gh is not logged in. Run: gh auth login"
fi
ok "gh: $(gh --version | head -n1) ($(gh api user --jq .login))"

# Are we inside the right git repo?
remote_url="$(git config --get remote.origin.url || true)"
if [[ "$remote_url" != *"sgireddy/cookie-janitor"* ]]; then
    die "this script must run inside the sgireddy/cookie-janitor checkout (origin is '$remote_url')."
fi
ok "git remote: $remote_url"

# ----------------------------------------------------- step 2: read version

step "Resolve version + tag"

version="$(awk -F'"' '/^version = / { print $2; exit }' pyproject.toml)"
[[ -n "$version" ]] || die "could not read version from pyproject.toml"
tag="${override_tag:-v$version}"
ok "pyproject version: $version"
ok "release tag      : $tag"

# ----------------------------------------------------- step 3: build the DMG

step "Build DMG"

dmg=""
sha=""
shopt -s nullglob

# Match a DMG built for THIS version specifically. Earlier versions of
# this script globbed Cookie-Janitor-*.dmg which is version-blind and
# meant a stale v0.3.0 DMG sitting in dist/ would be silently reused
# when releasing v0.4.0 — the user had to delete the file by hand.
# The new build script writes Cookie-Janitor-${version}-${arch}.dmg so
# we can match on the version prefix and ignore older artefacts.
current=(dist/Cookie-Janitor-"$version"-*.dmg)
stale=(dist/Cookie-Janitor-*.dmg)

if [[ $rebuild -eq 1 ]]; then
    warn "--rebuild given, wiping dist/ and build/"
    rm -rf dist build/cookie_janitor
elif [[ ${#current[@]} -gt 0 ]]; then
    # Only reuse if the existing DMG is for THIS version.
    dmg="${current[0]}"
    sha="${dmg}.sha256"
    ok "reusing existing build for $version: $dmg"
    ok "(pass --rebuild to force a fresh build)"
elif [[ ${#stale[@]} -gt 0 ]]; then
    # Older-version DMGs in dist/. Wipe them so we don't ship the wrong
    # bits. This is the behavior change that fixes the reported bug.
    warn "found stale DMG(s) from a different version, wiping dist/ and rebuilding:"
    for old in "${stale[@]}"; do warn "    $old"; done
    rm -rf dist build/cookie_janitor
fi

if [[ -z "$dmg" ]]; then
    # macOS still ships Bash 3.2 where "${arr[@]}" on an empty array
    # trips `set -u` ("unbound variable"). The `${arr[@]+...}` form
    # expands to nothing if the array is empty and to the array
    # otherwise — safe on every Bash from 3.0 onward.
    build_args=()
    [[ -n "$mode_flag" ]] && build_args+=("$mode_flag")
    [[ -n "$identity"  ]] && build_args+=(--identity "$identity")
    bash "$repo_root/scripts/build-mac-dmg.sh" ${build_args[@]+"${build_args[@]}"}

    current=(dist/Cookie-Janitor-"$version"-*.dmg)
    if [[ ${#current[@]} -eq 0 ]]; then
        die "build finished but no DMG named Cookie-Janitor-${version}-*.dmg was produced under dist/. Check that pyproject.toml version matches what the build emitted."
    fi
    dmg="${current[0]}"
    sha="${dmg}.sha256"
fi

[[ -f "$sha" ]] || die "expected $sha next to $dmg, not found."
dmg_size="$(du -h "$dmg" | awk '{print $1}')"
dmg_hash="$(cat "$sha")"
ok "DMG : $dmg ($dmg_size)"
ok "sha256: $dmg_hash"

# ----------------------------------------------------- step 4: tag

step "Ensure git tag $tag exists and points at HEAD"

head_sha="$(git rev-parse HEAD)"

if git rev-parse --verify --quiet "refs/tags/$tag" > /dev/null; then
    tag_sha="$(git rev-list -n1 "$tag")"
    if [[ "$tag_sha" != "$head_sha" ]]; then
        die "tag $tag already points at $tag_sha but HEAD is $head_sha.
        Refusing to move the tag. Either check out the tagged commit,
        or delete the tag locally + on origin and re-run."
    fi
    ok "local tag $tag already at HEAD"
else
    git tag -a "$tag" -m "Cookie Janitor $version"
    ok "created local tag $tag at HEAD"
fi

# Push the tag if origin doesn't have it (or has it at a different sha).
remote_tag_sha="$(git ls-remote --tags origin "$tag" | awk '{print $1}')"
if [[ -z "$remote_tag_sha" ]]; then
    git push origin "$tag"
    ok "pushed tag $tag to origin"
elif [[ "$remote_tag_sha" != "$head_sha" ]]; then
    # ls-remote shows the tag object sha for annotated tags. Compare
    # the commit it points to instead.
    remote_commit="$(git ls-remote origin "refs/tags/$tag^{}" | awk '{print $1}')"
    if [[ -z "$remote_commit" ]]; then
        # Lightweight tag -- remote_tag_sha *is* the commit.
        remote_commit="$remote_tag_sha"
    fi
    if [[ "$remote_commit" != "$head_sha" ]]; then
        die "remote tag $tag points at $remote_commit, HEAD is $head_sha. Refusing to move it."
    fi
    ok "remote tag $tag already at HEAD"
else
    ok "remote tag $tag already at HEAD"
fi

# ----------------------------------------------- step 5: GitHub Release

step "Create or update GitHub Release $tag"

notes_file="$(mktemp -t cj-release-notes)"
trap 'rm -f "$notes_file"' EXIT
cat > "$notes_file" <<EOF
First desktop preview build.

## Download

- **$(basename "$dmg")** — universal2, runs on both Intel and Apple Silicon Macs.
- **$(basename "$sha")** — verify with \`shasum -a 256 $(basename "$dmg")\`.

Expected SHA-256: \`$dmg_hash\`

## First launch

This build is **ad-hoc signed**, not signed with an Apple Developer ID, so macOS Gatekeeper will warn the first time you open it. To get past:

1. Drag **Cookie Janitor.app** into /Applications.
2. **Right-click** the app in Finder → **Open**.
3. Click **Open** on the warning dialog. (Only needed once.)

## Highlights

- Firefox cookie reader, classifier, and writer with verified backup and atomic swap — your original cookie database is never edited in place.
- PySide6 desktop GUI: profile picker, color-coded recommendations, live search, plain-English rationale per cookie, dry-run by default.
- CLI: \`cookie-janitor scan\`, \`list\`, \`restore\`.
- Apache-2.0, zero telemetry, no auto-update, refuses to run as root.

Built locally from [\`$tag\`](https://github.com/sgireddy/cookie-janitor/tree/$tag) ($(git rev-parse --short HEAD)). Every line is auditable.
EOF

if gh release view "$tag" --repo sgireddy/cookie-janitor > /dev/null 2>&1; then
    ok "release $tag exists, updating notes + uploading assets (--clobber)"
    gh release edit "$tag" --repo sgireddy/cookie-janitor \
        --title "Cookie Janitor $version" \
        --notes-file "$notes_file"
    gh release upload "$tag" "$dmg" "$sha" \
        --repo sgireddy/cookie-janitor --clobber
else
    draft_flag="--draft"
    [[ $publish -eq 1 ]] && draft_flag=""
    gh release create "$tag" "$dmg" "$sha" \
        --repo sgireddy/cookie-janitor \
        --title "Cookie Janitor $version" \
        --notes-file "$notes_file" \
        $draft_flag
    if [[ $publish -eq 1 ]]; then
        ok "release $tag created and PUBLISHED"
    else
        ok "release $tag created as draft"
    fi
fi

if [[ $publish -eq 1 ]]; then
    # If it already existed as draft, flip it to published.
    gh release edit "$tag" --repo sgireddy/cookie-janitor --draft=false > /dev/null
    ok "release $tag is now public"
fi

# ----------------------------------------------- step 6: print result

step "Done"
url="$(gh release view "$tag" --repo sgireddy/cookie-janitor --json url --jq .url)"
echo
echo "  Release:  $url"
echo "  Asset:    $(basename "$dmg")  ($dmg_size)"
echo "  SHA-256:  $dmg_hash"
echo
if [[ $publish -eq 0 ]]; then
    echo "  Status:   DRAFT.  Review the page above, then click 'Publish release'."
    echo "            Or re-run this script with --publish."
else
    echo "  Status:   PUBLISHED."
fi
echo
