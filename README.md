# cookie-janitor

> A transparent, open-source helper that shows you every cookie on your machine,
> explains why it's there, and lets you decide what to keep — across browsers
> and operating systems.

**Status:** early development. Not yet ready for general use.

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

Hosted GitHub Actions Intel runners (`macos-13`) are saturated and being
retired, so the published release ships Apple Silicon only. To produce
an Intel-compatible DMG yourself, build a **universal2** bundle on any
Mac — the resulting `.app` runs on both Intel and Apple Silicon:

```bash
./scripts/build-mac-dmg.sh                # universal2 (default)
./scripts/build-mac-dmg.sh --native       # only this Mac's architecture
./scripts/build-mac-dmg.sh --identity "Developer ID Application: …"
```

Output lands in `dist/Cookie-Janitor-<arch>.dmg` with a sibling
`.sha256`. First launch on an unsigned build needs a right-click → Open
to get past Gatekeeper.

### Cutting a release (one command)

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

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) (to be written). All contributions
must pass `ruff`, `mypy --strict`, `pytest`, `bandit`, `pip-audit`, and
`semgrep` in CI. Security-sensitive changes require a second reviewer.

## License

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
