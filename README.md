# cookie-janitor

> A transparent, open-source helper that shows you every cookie on your machine,
> explains why it's there, and lets you decide what to keep — across browsers
> and operating systems.


## What it is

A cross-platform desktop tool that:

1. Discovers cookies stored by the browsers installed on your machine
   (Chromium-family, Firefox-family, and — on macOS — Safari).
2. Classifies each cookie using public, transparent data sources:
   the [Open Cookie Database](https://github.com/jkwakman/Open-Cookie-Database),
   [EasyPrivacy](https://easylist.to/), and the
   [Disconnect tracking protection list](https://github.com/disconnectme/disconnect-tracking-protection).
3. Shows you a clear, sortable grid: name, domain, category
   (Functional / Performance / Analytics / Marketing / Unknown), expiry,
   first-party vs third-party, and **a one-line rationale citing the source**.
4. Lets **you** decide what to keep or delete. Nothing is deleted without
   your explicit confirmation. Dry-run is the default.
5. **Explains itself.** In the GUI, Help → Cookies 101… opens a
   plain-English guide to what cookies are, which ones are safe to
   delete, and what Cookie Janitor is *not*. First-time users see a
   short teaser on launch. Full long-form doc at
   [`docs/COOKIES-101.md`](docs/COOKIES-101.md).

### Classifier modes

Six explicit choices on a single ladder, shown as radio buttons in the
GUI with an ⓘ icon next to each. Pick the one that matches your
tolerance for the "wait, did I just get logged out?" risk:

| Mode | What it deletes | Recommended for |
|---|---|---|
| **Audit only** | Nothing. Lists and classifies cookies but never pre-selects them for deletion. | Inspecting your jar without commitment. |
| **Conservative** | Only cookies the Open Cookie Database explicitly classifies as analytics/marketing. | Anyone who'd rather click "delete" manually than risk a logout. This was the 0.2.x behavior. |
| **Balanced** *(default)* | Conservative, plus: known third-party tracker domains (doubleclick.net, facebook.net, hotjar.com, …), tracking subdomain labels (`tracking.`, `analytics.`, `ads.`, …), and well-known tracker cookie names (`_ga`, `_fbp`, `MUID`, `visid_incap_*`, `*_tracking`, …). | Most users. Clears the obvious junk without touching anything that could plausibly be a session. |
| **Strict** | Balanced, plus: also deletes the Open Cookie Database's *Performance* category (CDN preferences, AB-test buckets, load-balancer affinity tokens). | Privacy-leaning users who don't need persisted UI prefs. |
| **Aggressive** | Strict, plus: long-lived (>6 months) non-HttpOnly cookies whose name doesn't look like auth, and unknown cookies in general. Auth-shape names (`session`, `sessionid`, `csrf`, `token`, `__Host-*`, `__Secure-*`, …) are still kept. | Users who want a clean jar and are happy to re-login to the occasional obscure site. |
| **Scorched earth** | Everything except cookies on your allow list and cookies whose name uses the `__Host-` / `__Secure-` security prefixes. | Starting over. Will log you out of almost every site that doesn't use modern security-prefix cookies. |

Set the mode via the radio buttons at the top of the GUI, or via the CLI:

```bash
cookie-janitor list --mode aggressive
```

### The "By site" tab

A second tab in the main window groups every cookie by host:

* Tick a row to mark **all** of that site's cookies for deletion. Use
  this for sites you don't have an account on — news sites, CDNs,
  anything you visit anonymously.
* Right-click any row → **Always keep cookies on `<host>`** to add it
  to your allow list. Allow-listed rows render in green and refuse to
  be ticked, so you can't accidentally nuke gmail.com.
* The "**Add selected site to allow list**" button does the same for
  multi-row selections.

Sites you never want touched, regardless of mode, go in your **allow
list** (File → Allow list… in the GUI, or edit
`~/Library/Application Support/Cookie Janitor/allowlist.txt` on macOS).
Allow-list matches always win.

## What it is not

- It is **not** an anti-virus, anti-malware, or "system optimizer." It only
  reads and (with your consent) edits cookie databases.
- It is **not** a browser extension. It works on the cookie store on disk,
  not through any browser API.
- It does **not** run as root or administrator. Cookie stores live in your
  user profile; elevation is unnecessary and would expand the attack surface.
- It does **not** phone home. Zero telemetry. Zero crash reporting to us.
- It is **not** available for iOS or Android. On those platforms, the OS
  sandbox prevents any app from reading another app's cookie store, by
  design. We will not pretend otherwise.

## Browser support

| Family | Read (scan + classify) | Delete | Notes |
|---|---|---|---|
| **Firefox-family** (Firefox, LibreWolf, Waterfox, Floorp, Zen) | ✅ | ✅ | Plain SQLite at `cookies.sqlite`; cookie values are unencrypted. |
| **Chromium-family** (Chrome, Edge, Brave, Vivaldi, Opera, Arc, Chromium) | ✅ | ✅ | Cookie values are encrypted (Keychain / DPAPI / libsecret). We don't decrypt them — the classifier only needs names, domains, expiries, and flags, all of which are stored in plaintext. The delete path doesn't need to decrypt either. |
| **Safari** (macOS only) | ✅ | ✅ | Reads and rewrites `Cookies.binarycookies` directly. Before writing we (a) refuse if Safari is running (it rewrites the whole file on quit and would clobber our changes), (b) refuse if *iCloud → Safari* is enabled — sync will resurrect deleted cookies within minutes — unless you set `COOKIE_JANITOR_ALLOW_SAFARI_SYNC=1` to acknowledge, and (c) take a timestamped backup next to the original. Requires **Full Disk Access** on the running app (macOS TCC); the GUI shows an actionable dialog if the OS blocks the read/write. |

The reader and writer dispatchers are at
[`src/cookie_janitor/readers/__init__.py`](src/cookie_janitor/readers/__init__.py)
and
[`src/cookie_janitor/writers/__init__.py`](src/cookie_janitor/writers/__init__.py).
Adding a new family is: one reader module + one writer module + one
``if`` branch in each dispatcher.

## How it stays trustworthy

- **Apache-2.0** licensed. Every line is auditable.
- **Reproducible builds** with SLSA provenance.
- **Signed releases** (Authenticode on Windows, Developer ID + notarization
  on macOS, cosign-signed artifacts on Linux).
- **Pinned dependencies with hashes.** No surprise updates.
- **Pinned filter-list snapshots.** Updating the bundled manifest is a
  deliberate release step, not a runtime decision.
- **Threat model** is published at [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
  and reviewed every release.
- **Security policy** at [`SECURITY.md`](SECURITY.md). Coordinated disclosure
  with a 90-day deadline.

## Project layout (planned)

```
cookie-janitor/
├── src/cookie_janitor/
│   ├── model/        # Cookie, Profile, Browser, Decision dataclasses
│   ├── readers/      # one module per browser family
│   ├── safety/       # symlink-safe IO, atomic writes, backups
│   ├── classify/     # Open Cookie DB + filter-list matchers + heuristics
│   ├── policy/       # turn classifications into KEEP / DELETE / ASK
│   ├── cli/          # Typer-based CLI
│   └── ipc/          # local JSON-RPC for the GUI sidecar
├── gui/              # Tauri 2 desktop shell (Rust + web UI)
├── data/             # vendored Open Cookie DB snapshot + manifest.json
├── docs/
│   ├── THREAT_MODEL.md
│   └── ARCHITECTURE.md
├── tests/
├── SECURITY.md
├── LICENSE
├── NOTICE
└── pyproject.toml
```

## Development

Requires Python 3.11+. We use [`uv`](https://docs.astral.sh/uv/) for
environment and dependency management.

```bash
uv sync                # install pinned deps from uv.lock
uv run cookie-janitor scan --browser firefox --dry-run
uv run pytest
```

### Running the GUI

```bash
uv sync --extra gui
uv run cookie-janitor-gui
```

### Building a macOS DMG locally

The published release ships a **universal2** DMG built on GitHub's
Apple Silicon runner (`macos-14`) that runs natively on both Intel
and Apple Silicon — you should not need a local build for
distribution. If you want to iterate on packaging changes without
waiting for CI, the same universal2 bundle is one script away:

```bash
./scripts/build-mac-dmg.sh                # universal2 (default)
./scripts/build-mac-dmg.sh --native       # only this Mac's architecture
./scripts/build-mac-dmg.sh --identity "Developer ID Application: …"
```

Output lands in `dist/Cookie-Janitor-<arch>.dmg` with a sibling
`.sha256`. First launch on an unsigned build needs a right-click → Open
to get past Gatekeeper.

### Building a Windows MSI locally

Windows MSIs are built **on Windows**. Briefcase wraps a native Python
interpreter and shells out to WiX (`candle.exe` / `light.exe`), so
cross-building from macOS or Linux is not possible. Options for a
maintainer without a dedicated Windows box: a Windows VM, a spare
laptop, a Windows EC2 spot instance (about $0.05/hour), or just push
a tag and let CI build it (see [_Cutting a release_](#cutting-a-release-via-ci-both-platforms) below).

#### One-time setup on the Windows machine

Run in an **elevated PowerShell** (needed for the `choco install`
step; nothing else in this workflow requires admin):

```powershell
# 1. Install Chocolatey if you don't already have it.
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# 2. Install the build prereqs.
choco install -y git uv wixtoolset gh
```

Close and reopen PowerShell so the new `PATH` takes effect, then (in a
**non-elevated** shell — we deliberately don't want admin for the
build itself):

```powershell
gh auth login                                    # once per machine
git clone https://github.com/sgireddy/cookie-janitor.git
cd cookie-janitor
```

Sanity-check that WiX is discoverable — this is the single most common
first-build failure:

```powershell
candle.exe -?                                    # should print version
light.exe  -?                                    # should print version
```

If either command isn't found, the chocolatey package didn't extend
`PATH` for the current session. Add it manually:

```powershell
$env:PATH += ";C:\Program Files (x86)\WiX Toolset v3.14\bin"
```

#### Building the MSI

```powershell
# Fastest path: build only, no GitHub interaction.
pwsh scripts\release-windows.ps1 -SkipRelease

# Force a fresh build even if dist\*.msi already exists.
pwsh scripts\release-windows.ps1 -SkipRelease -Rebuild
```

Output:

* `dist\Cookie-Janitor-x64.msi` — the installer.
* `dist\Cookie-Janitor-x64.msi.sha256` — matching hash in the same
  `<hash>  <filename>` format the macOS pipeline uses, so the same
  verify commands work on both platforms.

The MSI is a **per-user** installer (`system_installer = false` in
`pyproject.toml`): it installs to `%LOCALAPPDATA%\Programs\Cookie
Janitor\` and never prompts for UAC. Cookie Janitor only reads and
writes files under `%USERPROFILE%` at runtime, so forcing elevation
would be a lie.

#### Smoke-testing a fresh MSI

Do this in a scratch Windows account or VM whenever possible — the
whole point is to catch anything the build machine's environment might
have papered over.

1. Double-click the MSI. Installer runs to completion with **no UAC
   prompt**.
2. Launch **Cookie Janitor** from the Start Menu. Expect a one-time
   SmartScreen dialog ("Windows protected your PC") because the build
   is unsigned. Click **More info → Run anyway**.
3. The main window opens. The profile dropdown should list every
   Chrome, Edge, and Firefox profile installed on the machine.
4. Pick one obvious tracker cookie, click **Delete Selected**, confirm
   the dialog. Cookie Janitor writes a backup to
   `%LOCALAPPDATA%\cookie-janitor\backups\<timestamp>\` before
   touching anything.
5. Fully quit the affected browser and reopen it. The deleted cookie
   is gone; other cookies (Gmail, GitHub, etc.) still work.
6. If anything looks wrong: `cookie-janitor restore <backup-path>`
   reverts the file atomically. The backup pipeline is verified with
   SHA-256, so a corrupted backup won't overwrite the current file.

#### Troubleshooting

* **`briefcase: command not found`** — you're in a shell that opened
  before `uv` was installed. Re-open PowerShell.
* **`[WinError 32]` during briefcase build** — corporate antivirus is
  locking DLLs as briefcase writes them. Whitelist the repo directory
  in Defender / your endpoint protection tool and retry.
* **`candle.exe not found` mid-build even though it was on PATH
  earlier** — the `uv run` subshell inherits the parent PATH; if you
  set it via `$env:PATH += …` in the current session and then opened
  a new terminal tab, the new tab won't have it. Set the PATH in
  System Properties → Environment Variables for a persistent fix.
* **Briefcase downloads a huge template zip on every run** — that's
  the beeware app template; it's cached under
  `%LOCALAPPDATA%\BeeWare\`. Deleting that directory forces a
  fresh download, which is occasionally the fix if the template
  cache got corrupted mid-download.
* **MSI installs but the app fails to launch with `api-ms-win-crt-*.dll`
  missing** — the machine is missing the Visual C++ Redistributable
  that the bundled Python needs. Install
  [VC++ Redist 2015-2022](https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist).
  Old Windows 10 installs (< 1809) are the usual suspects.

#### Uninstalling

Settings → Apps → Installed apps → **Cookie Janitor** → Uninstall.
The uninstaller removes `%LOCALAPPDATA%\Programs\Cookie Janitor\`
but deliberately leaves backups under
`%LOCALAPPDATA%\cookie-janitor\backups\` alone, so a mis-click doesn't
wipe your safety net. Delete that directory manually if you want a
clean slate.

### Cutting a release via CI (both platforms)

This is the recommended path once a version is ready — one push
produces the DMG **and** the MSI in about 10 minutes with no local
build machines involved.

```bash
# Bump the version in pyproject.toml, commit, then:
git tag vX.Y.Z
git push origin main
git push origin vX.Y.Z
```

The `Release` workflow (`.github/workflows/release.yml`) fans out into
`build-macos` (Apple Silicon runner) and `build-windows`
(`windows-latest` runner) in parallel, then a `publish` job attaches
all four artefacts (`.dmg`, `.dmg.sha256`, `.msi`, `.msi.sha256`) to a
**draft** GitHub Release. Smoke-test the binaries, then click
_Publish_ in the GitHub UI.

If a single runner has a bad day (Windows runners in particular have
had outages), `fail-fast: false` means the other artefact still
builds. Delete the resulting incomplete draft release, re-trigger via
_Actions → Release → Run workflow_, and both artefacts land on the
same draft.

### Cutting a macOS release locally

`scripts/release-mac.sh` does the whole release flow end-to-end: it
preflight-checks the environment, runs `build-mac-dmg.sh` if no DMG
is on disk yet, makes sure the matching `vX.Y.Z` tag exists locally
and on origin, and creates (or updates) a **draft** GitHub Release
with the DMG + `.sha256` attached. Re-running is safe and idempotent.

```bash
chmod +x scripts/release-mac.sh
./scripts/release-mac.sh                    # draft release, ad-hoc signed
./scripts/release-mac.sh --rebuild          # force a fresh build first
./scripts/release-mac.sh --publish          # publish immediately (skip draft)
./scripts/release-mac.sh --identity "Developer ID Application: …"
```

The script reads the version from `pyproject.toml`, so to cut `v0.3.0`
you bump `version = "0.3.0"` in `pyproject.toml`, commit, then run
`./scripts/release-mac.sh`. Nothing else.

Prereqs: `xcode-select --install`, `uv`, and
[`gh`](https://cli.github.com/) authenticated as the release owner
(`gh auth login`).

### Cutting a Windows release locally

`scripts/release-windows.ps1` is the direct analogue of
`release-mac.sh`. It runs the same preflight → build → verify →
draft-release pipeline, but produces the MSI. Same idempotency —
re-running just re-uploads the artefact to the existing draft.

```powershell
pwsh scripts\release-windows.ps1                # build + draft release
pwsh scripts\release-windows.ps1 -Rebuild       # force a fresh build first
pwsh scripts\release-windows.ps1 -Publish       # publish immediately (skip draft)
pwsh scripts\release-windows.ps1 -SkipRelease   # build only, don't touch GitHub
pwsh scripts\release-windows.ps1 -Tag v0.6.1    # explicit tag override
```

To cut `v0.6.1` from a Windows machine: bump `version = "0.6.1"` in
`pyproject.toml`, commit, push, then run
`pwsh scripts\release-windows.ps1`. If the tag doesn't exist yet the
script creates it and pushes it to `origin` before creating the
release.

Prereqs: PowerShell 5.1+ (built into Windows) or PowerShell 7, `uv`,
WiX Toolset v3.x with `candle.exe` on `PATH`, and `gh` authenticated
as the release owner. See [_Building a Windows MSI locally_](#building-a-windows-msi-locally) above for the one-time
setup commands.

> **Choosing a route.** For a normal release, use the CI path — it's
> the least error-prone and produces both binaries. Use the local
> scripts when you're iterating on packaging, when the CI runners are
> unavailable, or when you want to sign an artefact with a certificate
> that isn't in repo secrets yet.

## Roadmap — known follow-up work

Post-v0.8.5 there are three known, scoped work items. They are
tracked in [`docs/HANDOFF.md`](docs/HANDOFF.md) with concrete
options, effort estimates, and mechanical checklists. Summary:

1. **Bundle size.** v0.8.5 ships a 513 MB universal2 DMG — half
   the bytes are Qt frameworks, doubled by dual-arch. A one-PR
   diet using briefcase's `cleanup_paths` plus swapping
   `PySide6` for `PySide6-Essentials` should get to ~250 MB.
   Details in HANDOFF § 1.
2. **Windows code signing + Winget listing.** Today's MSI is
   unsigned, so SmartScreen warns first-time users. Azure
   Trusted Signing (≈$10/mo, HSM-backed, no shipped hardware
   token) removes the warning and unlocks a Winget submission
   for one-line `winget install`. Details in HANDOFF § 3a/3b.
3. **Store presence.** Mac App Store is deliberately declined
   (see `AGENTS.md` decision D18 — sandbox forbids the tool's
   core function). Microsoft Store via MSIX is technically
   feasible after Windows signing lands. Details in HANDOFF § 2
   and § 3c.

Contributions welcome on any of these — open an issue first to
sync on approach.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) (to be written). All contributions
must pass `ruff`, `mypy --strict`, `pytest`, `bandit`, `pip-audit`, and
`semgrep` in CI. Security-sensitive changes require a second reviewer.

## License

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
