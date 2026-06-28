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

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) (to be written). All contributions
must pass `ruff`, `mypy --strict`, `pytest`, `bandit`, `pip-audit`, and
`semgrep` in CI. Security-sensitive changes require a second reviewer.

## License

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
