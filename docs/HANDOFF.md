# HANDOFF — future work

Written 2026-07-12 after shipping v0.8.5. Read this if you are
picking up cookie-janitor cold — as a new maintainer, a fresh AI
session, or the same maintainer six months from now who forgot
where they left off.

Companion to `AGENTS.md` (which captures locked *decisions*).
This file captures the open *work* — items that are known,
scoped, but deliberately not started.

## Current state

- **v0.8.5 is the latest release.** First DMG since v0.7.0 that
  genuinely runs on Intel Macs. See
  `docs/SIGNING-MACOS.md § History — the universal2 phantom` for
  the RCA of the six-release drought.
- Windows MSI (x64 + arm64) and macOS DMG (universal2) all ship
  from the same tag via `.github/workflows/release.yml`.
- All 8 macOS signing secrets are in place; Developer ID
  Application cert plus notarytool P8 key are both live. Cert
  expiry watch date is 2027-02-01.
- Team ID `5UN8LU48LQ`.
- Local build path on `mbp2019.local` (Intel Mac) works via
  `scripts/release-mac.sh`. Used to validate v0.8.5 before tag
  push. Keep it working — it is the fallback if GitHub Actions
  ever stops offering `macos-14`.

## Open work items

Three items the maintainer has flagged. Each is scoped, has
real numbers where possible, and is written so the next person
(or session) can pick it up without a background dump.

1. [Bundle size](#1-bundle-size) — 513 MB DMG is embarrassing
2. [Mac App Store](#2-mac-app-store-currently-declined-under-d18) — currently declined; captured tradeoffs if that ever reverses
3. [Windows Store / Winget](#3-windows-store--winget) — probable next distribution channel

---

## 1. Bundle size

### The current numbers (source: GitHub Releases API)

| Release | DMG | What it actually is |
|---|---|---|
| v0.6.0 (arm64) | 250 MB | arm64-thin |
| v0.7.0 → v0.8.0 | 250 MB | arm64-thin, mislabelled `-universal2` |
| **v0.8.5** | **513 MB** | genuinely universal2 (2× the code for 2× the arches) |
| v0.8.5 MSI (each) | 217 MB | Windows x64 or arm64 |

The v0.8.5 → v0.8.4 doubling is the honest cost of shipping a
real universal2 binary. It is not a regression; it is the size a
correct universal2 has always been. Prior "universal2" DMGs were
half the size because they were secretly single-arch.

### What is actually in 250 MB (one arch slice)

Rough breakdown of a thin `.app` bundle:

| Component | Size | Notes |
|---|---|---|
| PySide6 / Qt frameworks | 140–160 MB | QtCore, QtGui, QtWidgets, QtNetwork, QtDBus, QtQml, QtPrintSupport, QtOpenGL, plugins |
| `Python.framework` | 35–50 MB | Python 3.11 + full stdlib |
| PySide6 python bindings (`shiboken6`, `.pyi`, `.pyd`/`.so`) | 20–30 MB |  |
| pycryptodomex, browser_cookie3, psutil, lz4, pydantic, typer | 10–15 MB |  |
| Briefcase stub launcher | 3–5 MB |  |
| Cookie Janitor's own code | < 1 MB | (basically noise) |

**Qt dominates.** Any size project has to start there.

### Reduction ladder — cheap to expensive

#### Tier 1 — cleanup_paths in `pyproject.toml` (saves ~75 MB thin / ~150 MB universal2)

Briefcase supports a `cleanup_paths` list under the macOS section
that deletes specific paths from the built `.app` before
signing. Standard practice for Python-Qt apps. Candidates:

```toml
[tool.briefcase.app.cookie_janitor.macOS]
cleanup_paths = [
  # Qt IDE tools bundled by PySide6 that we never invoke
  "Contents/Resources/app_packages/PySide6/Assistant.app",
  "Contents/Resources/app_packages/PySide6/Designer.app",
  "Contents/Resources/app_packages/PySide6/Linguist.app",
  # Localised .qm files (Qt UI strings translated into ~35 languages)
  # We only render English strings; keep the framework but drop translations.
  "Contents/Resources/app_packages/PySide6/Qt/translations/*",
  # QML runtime — we render pure QtWidgets, no QML anywhere
  "Contents/Resources/app_packages/PySide6/Qt/qml",
  # Python stdlib bits we never import
  "Contents/Frameworks/Python.framework/Versions/*/lib/python*/test",
  "Contents/Frameworks/Python.framework/Versions/*/lib/python*/idlelib",
  "Contents/Frameworks/Python.framework/Versions/*/lib/python*/tkinter",
  "Contents/Frameworks/Python.framework/Versions/*/lib/python*/turtledemo",
  "Contents/Frameworks/Python.framework/Versions/*/lib/python*/ensurepip",
  # .dist-info leftovers from pip
  "Contents/Resources/app_packages/*.dist-info/RECORD",
]
```

**Verify each removal actually leaves the app launchable.** Add a
step to `.github/workflows/release.yml` that runs the app
briefly (see [size regression guardrail](#a-guardrail-against-size-regression) below).

For Windows the same table goes under
`[tool.briefcase.app.cookie_janitor.windows]` with the equivalent
`Contents/…` paths (Windows layout is flatter — see
`briefcase run windows` output for the actual directory names).

#### Tier 2 — `PySide6-Essentials` instead of `PySide6` (potentially saves 100+ MB)

PySide6 ships as several distributions on PyPI:

- `PySide6` — everything: WebEngine, Charts, DataVisualization, Quick3D, Multimedia.
- `PySide6-Essentials` — Core, Gui, Widgets, Network, DBus, PrintSupport, Xml, Concurrent. This is what a data-manipulation GUI app actually needs.
- `PySide6-Addons` — the rest, opt-in.

Change in `pyproject.toml`:

```diff
- "PySide6>=6.7,<7",
+ "PySide6-Essentials>=6.7,<7",
```

**Before doing this, grep the codebase** (`rg 'from PySide6\\.'`)
to confirm nothing imports from `QtWebEngine*`, `QtCharts`,
`QtDataVisualization`, `QtQuick3D`, or `QtMultimedia`. As of
v0.8.5 the app only imports Widgets, Gui, Core, Xml, Network — so
Essentials should be sufficient.

Trade-off: if any future feature ever needs WebEngine (e.g. an
embedded HTML rationale viewer), that reintroduces the full
PySide6 dependency and cancels this saving. Document the
implication in AGENTS.md if it happens.

#### Tier 3 — Qt plugin pruning (saves ~10 MB per arch)

`Contents/Resources/app_packages/PySide6/Qt/plugins/` ships every
platform plugin, image format, TLS backend, and style Qt knows
about. On macOS we need:

Keep: `platforms/libqcocoa.dylib`, `imageformats/libqjpeg.dylib`,
`imageformats/libqsvg.dylib`, `styles/libqmacstyle.dylib`,
`tls/libqopensslbackend.dylib` (only if HTTP is via QtNetwork —
we use `requests`, so **QtNetwork's TLS can go too**).

Drop: `platforms/libq{minimal,offscreen,vnc,linuxfb,eglfs}.dylib`,
`imageformats/libq{wbmp,webp,tga,tiff,ico}.dylib`,
`sqldrivers/*` (we ship no QtSql users),
`printsupport/*` (we don't print),
`iconengines/*`, `imageformats/libqicns.dylib` (unless the app
icon is icns and PySide6 needs it at runtime — verify).

Add these to `cleanup_paths` alongside the Tier 1 entries.

#### Tier 4 — Split thin/GUI + fat/CLI (major refactor)

Ship two distributions:

- **`cookie-janitor` CLI**: a ~20 MB DMG or an unpacked zip. No
  Qt. Pure typer/rich TUI. For power users and CI scripting.
- **`Cookie Janitor` GUI**: today's ~200 MB (post Tier 1+2) DMG.

Users who only want to review-and-delete via terminal never
download Qt.

Effort: 2–3 days. Requires splitting `pyproject.toml` into two
briefcase apps that share the same source tree (briefcase
supports this via multiple `[tool.briefcase.app.<name>]`
sections). Also doubles the release matrix — 2× DMG + 2× MSI.

**Only worth doing after Tier 1+2** — if a straightforward
`cleanup_paths` gets the GUI DMG under 250 MB, this is over-
engineering.

#### Tier 5 — Alternative packaging (weeks of work, unpredictable)

- **PyInstaller**: usually 100–150 MB smaller than Briefcase for
  Qt apps because it does dead-code elimination on Python
  modules. But it loses Briefcase's signing/notarization
  pipeline; we would re-implement it. Risk of undoing all the
  v0.8.1–v0.8.5 signing work.
- **Nuitka `--standalone --lto`**: compiles Python to C; often
  smaller and startup-faster. Works with Qt. Not tested against
  the signing pipeline. Prototype in a spike branch before
  committing.
- **Split into a Rust/Go/Swift host + Python worker**: previously
  considered as Tauri, reversed per D4 in AGENTS.md. Do not
  revisit without a compelling reason.

### Realistic target

**513 MB → 200–250 MB DMG** with Tier 1 + Tier 2 alone. That is a
week of focused work and one PR. Anything beyond that is
diminishing returns unless we also drop universal2 (option: ship
separate x86_64 and arm64 DMGs at ~120 MB each; requires either a
self-hosted Intel runner on `mbp2019` or the return of
`macos-13`, which GitHub retired in 2025 — see the runner comment
in `release.yml`).

### A guardrail against size regression

Once we do the size work, prevent future regression the same way
we now prevent the universal2 phantom: a CI step that fails if
the DMG grows unexpectedly.

Sketch (`.github/workflows/release.yml`, add after the universal2
assertion step):

```yaml
- name: Assert DMG size is within budget
  if: matrix.arch == 'universal2'
  run: |
    set -euo pipefail
    dmg="${{ steps.locate.outputs.dmg }}"
    bytes=$(stat -f %z "$dmg")
    mb=$(( bytes / 1048576 ))
    budget=280  # MB — reset after size work lands, then hold this line
    echo "DMG is ${mb} MB (budget: ${budget} MB)"
    if [ "$mb" -gt "$budget" ]; then
      echo "FAIL: DMG exceeds ${budget} MB budget" >&2
      exit 1
    fi
```

Set the budget just above the post-diet number so a future
"whoops I added PyQtWebEngine" PR fails CI loudly.

---

## 2. Mac App Store — currently declined under D18

**Read `AGENTS.md` decision D18 before doing anything here.**
The short version: the Mac App Store mandates the App Sandbox,
which forbids reading `~/Library/Application Support/{Google,
Firefox, ...}/`. That is Cookie Janitor's core function. Apple
has consistently rejected temporary-exception entitlements for
this pattern since ~2019.

This section captures **what would have to change** if the
maintainer ever reverses D18. Recording it here saves the future
person the day of research it took to write.

### Three paths, ranked by how much of the current product survives

#### Path A — full MAS reversal via NSOpenPanel + security-scoped bookmarks

- User opens Cookie Janitor.
- App shows: "To scan Chrome, click here to select Chrome's data
  folder." NSOpenPanel opens rooted at
  `~/Library/Application Support/Google/`.
- User picks the folder. macOS grants a security-scoped bookmark;
  the app persists it in `~/Library/Containers/dev.cookiejanitor.
  cookie_janitor/Data/Documents/bookmarks.plist`.
- Repeat for Firefox, Brave, Edge, Arc, Vivaldi, LibreWolf, ...
  — every browser, every profile within, one at a time, on
  first run. The user cannot "select all browsers" — sandbox
  demands each grant be individually confirmed.
- On subsequent runs the app resolves each bookmark to the
  current folder (bookmarks track renames; they don't survive
  Migration Assistant moves).

**UX verdict**: strictly worse than the current product for users
who install more than one browser. Same reasoning as Little
Snitch and BBEdit shipping outside MAS.

**Engineering cost**: 3–5 days. All new PyObjC code (Cocoa
NSOpenPanel + bookmark APIs) — briefcase doesn't help here. Plus
a fresh MAS App Review dance ($99/year for company, $19/year
individual).

Requires code changes:

- New module `src/cookie_janitor/macos_bookmarks.py` wrapping
  `Foundation.NSURL.URLByResolvingBookmarkData_options_
  relativeToURL_bookmarkDataIsStale_error_`. PyObjC is required
  (currently not a dep — that alone is +8 MB).
- Storage layer changes: `discover_browsers()` must know to
  attempt bookmark resolution before scanning system paths.
- GUI: an "Add browser…" button and a per-browser status row.
- CLI (`cookie-janitor scan`): what happens when the CLI runs in
  a sandboxed context and has no bookmarks? Fall back to
  system paths and let the read fail loudly? Or refuse to run
  outside the GUI? Decision needed.
- Entitlements: `com.apple.security.app-sandbox = true` plus
  `com.apple.security.files.user-selected.read-write` (the
  bookmark grant). Move the current signing config in
  `pyproject.toml`/`release.yml` to MAS-provisioned certs (Mac
  App Distribution + Mac Installer Distribution, not the current
  Developer ID Application).

#### Path B — companion "lite" app, MAS-listed, that links to the real thing

- Ship a second bundle: `Cookie Janitor Guide.app`. It contains
  no cookie code. It is a single-window app that shows the
  same rationale docs (`docs/COOKIES-101.md` rendered to HTML)
  and has one big button: **"Get Cookie Janitor from GitHub →"**
  which opens the browser to the Releases page.
- This companion clears sandbox trivially — it reads nothing
  outside its own bundle.
- MAS listing gives search discoverability ("cookie" in the App
  Store search returns Cookie Janitor Guide) while the real app
  stays direct-download.

**UX verdict**: fine, non-deceptive if the description clearly
says "companion / download link — not the app itself".

**Engineering cost**: 1–2 days. A separate briefcase app,
minimal dependencies, minimal code. Some MAS provisioning
paperwork.

**Value verdict**: unclear. Users who search the App Store for
cookie tools are not our target audience (they want a one-tap
install, not a "download from a GitHub link" hop). Probably not
worth the ongoing App Review maintenance burden.

#### Path C — petition Apple for an exception

Do not do this. Apple has said no to this exact use case for
seven years running. Wastes 6+ weeks of the maintainer's time
in App Review pingpong. Skip.

### Recommendation

**Do not reverse D18** unless a specific user need materializes
that only the App Store can serve (e.g. an enterprise MDM policy
that only allows App Store apps and a paying enterprise customer
asks for it). If that happens, do Path A. Do not do Path B just
for discoverability; SEO from the GitHub README + Homebrew Cask
delivers the same audience with zero App Review overhead.

### If we ever go for it — the mechanical checklist

Not for now, but for the future person opening this section:

1. Apple Developer Program membership: same one we already have,
   Team ID `5UN8LU48LQ`. Confirm still active.
2. **Mac App Distribution** certificate (distinct from the
   Developer ID Application cert we have today). Generate in
   Apple Developer Portal → Certificates → Mac App Distribution.
3. **Mac Installer Distribution** certificate. Same page.
4. Create an App ID with the correct bundle identifier
   (`dev.cookiejanitor.cookie_janitor`). Provisioning profile.
5. New target in `pyproject.toml`:
   ```toml
   [tool.briefcase.app.cookie_janitor.macOS.appstore]
   entitlement."com.apple.security.app-sandbox" = true
   entitlement."com.apple.security.files.user-selected.read-write" = true
   ```
6. Build with `briefcase package macOS --target=appstore` — a
   PR would need to add this as a matrix entry in `release.yml`.
7. Upload via `xcrun altool --upload-app` or Transporter.app to
   App Store Connect.
8. First submission goes through Apple's App Review (~1–3 days).
   Expect rejections on the first pass; iterate.

---

## 3. Windows Store / Winget

Fundamentally friendlier than MAS because Windows sandboxing is
less strict. Two channels, in effort order:

### 3a. Winget (recommended first; probably next release cycle)

Winget is the community app registry Microsoft ships with
Windows 11. Adding Cookie Janitor is a single PR to
[`microsoft/winget-pkgs`](https://github.com/microsoft/winget-pkgs).

**Effort**: half a day, per release.

**Prereqs**: the MSI must be publicly downloadable (it is — our
GitHub Releases assets are public) and have a stable SHA-256
(it does — we ship `.sha256` sidecars).

**Steps for the first submission**:

1. Install `wingetcreate` on a Windows box:
   `winget install Microsoft.WingetCreate`
2. `wingetcreate new` — the tool interactively asks for
   Publisher, PackageName, InstallerURL (paste the GitHub
   Releases MSI URL), and computes the SHA. It emits three YAML
   files under `manifests/s/sgireddy/CookieJanitor/<version>/`.
3. Publisher identity for a solo maintainer: `sgireddy` (same as
   the GitHub org). The community moderators will check that the
   installer's signing cert matches the publisher — since our
   MSI is unsigned today, the first submission may be rejected
   on that basis. If so, do 3b first.
4. `wingetcreate submit --token <PAT>` opens the PR against
   `microsoft/winget-pkgs`.
5. Moderator review, ~2–5 days. Address feedback. Merge.
6. Users then `winget install sgireddy.CookieJanitor`.

**For subsequent releases**: `wingetcreate update sgireddy.
CookieJanitor --urls <new-msi-url> --version <new-version>` —
another PR, moderators auto-fast-track updates for existing
packages.

**Automate it**: after the winget listing lands, add a step to
`release.yml`'s `publish` job that runs `wingetcreate update`
automatically on each release. Use a fine-grained PAT stored in
`WINGET_TOKEN` (secret needed) scoped to `microsoft/winget-pkgs`
fork.

**Signing prerequisite**: winget itself is happy with unsigned
MSIs, but moderators strongly prefer signed. Which brings us to…

### 3b. Windows code signing

We ship MSIs today with **no Authenticode signature**. Windows
SmartScreen shows "Windows protected your PC" the first ~few
thousand times an unsigned installer runs before it earns
reputation. That's a real UX papercut and blocks 3a moderator
approval.

**Certificate options**:

| Option | Cost | Trust | Effort |
|---|---|---|---|
| **Self-signed** | free | none — user gets scary warning | trivial |
| **DigiCert / Sectigo OV** ("Organization Validation") | $250–$500/yr | ~2 weeks of SmartScreen reputation building before "Run anyway" fades | 1 day (validation call) |
| **DigiCert EV** ("Extended Validation") | $500–$700/yr, needs a hardware token (HSM/YubiKey FIPS) mailed by the CA | Immediate SmartScreen trust | 3–5 days (paperwork + token shipping) |
| **Azure Trusted Signing** | ~$10/mo | Uses Azure-hosted HSM, no shipped hardware | 1–2 days setup |

**Recommendation**: **Azure Trusted Signing**. As of 2025 it's
Microsoft's own preferred path for solo devs — pay-as-you-go,
HSM-backed, no shipped-token logistics, integrates with GitHub
Actions via `Azure/trusted-signing-action`. Roughly $10/month
plus per-signature costs. Same trust level as EV. Documented at
<https://learn.microsoft.com/azure/trusted-signing/>.

**Concrete steps**:

1. Sign up for an Azure subscription if none exists.
2. Create a **Trusted Signing account** and **Identity
   Validation** (business or individual — individual is
   available and cheaper). Individual validation takes ~1–3
   business days.
3. Create a **Certificate Profile**. Note the account URI and
   profile name.
4. Store as GitHub Actions secrets:
   `AZURE_TRUSTED_SIGNING_ACCOUNT`,
   `AZURE_TRUSTED_SIGNING_PROFILE`,
   `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`,
   `AZURE_CLIENT_SECRET` (or use federated OIDC → no long-lived
   secret; preferred, matches our SLSA posture).
5. Add a signing step to `build-windows` in `release.yml`:

   ```yaml
   - name: Sign MSI with Azure Trusted Signing
     if: env.AZURE_TRUSTED_SIGNING_ACCOUNT != ''
     uses: azure/trusted-signing-action@<sha-pin>
     with:
       azure-tenant-id: ${{ secrets.AZURE_TENANT_ID }}
       azure-client-id: ${{ secrets.AZURE_CLIENT_ID }}
       # OIDC or federated auth — no client-secret needed
       endpoint: https://<region>.codesigning.azure.net
       trusted-signing-account-name: ${{ secrets.AZURE_TRUSTED_SIGNING_ACCOUNT }}
       certificate-profile-name: ${{ secrets.AZURE_TRUSTED_SIGNING_PROFILE }}
       files-folder: dist
       files-folder-filter: msi
   ```

   SHA-pin the action per AGENTS.md "Third-party GitHub Actions
   must be SHA-pinned" rule.
6. Same "if signing secrets are set, sign; otherwise skip" flow
   the macOS job uses — so PR builds without secrets still
   produce unsigned MSIs.
7. Re-generate the `.sha256` files **after** signing (signing
   changes the file hash).

Once 3b is in place, 3a becomes friction-free. Do them in this
order: 3b first (fixes the SmartScreen UX for everyone), then
3a (adds discoverability).

### 3c. Microsoft Store (MSIX) — the harder path

Different beast from Winget. Requires:

- **MSIX packages**, not MSI. Briefcase does not produce MSIX
  today (Windows template outputs WiX MSI). Options: pass the
  MSI through the `MSIX Packaging Tool` (a GUI conversion tool
  from Microsoft) or rewrite the packaging step to produce
  MSIX directly via a tool like [`makeappx.exe`](https://learn.microsoft.com/windows/msix/package/create-app-package-with-makeappx-tool).
- **Partner Center account**: $19 individual, $99 company,
  one-time.
- **Package identity** must match the one registered in Partner
  Center (publisher CN, package name, publisher display name).
- **Capabilities declaration** in the AppXManifest. Cookie
  Janitor needs `broadFileSystemAccess` — this is the capability
  that lets a Store-installed app read `%APPDATA%\Google\...`
  and `%LOCALAPPDATA%\Mozilla\...`. **It requires user consent
  via a Windows settings-page toggle** on first use. That is a
  friction point — some users won't figure out how to enable it.
- **Certification**: Microsoft's automated + manual review.
  Milder than Apple's App Review — usually clears in 48h. The
  gotchas are around telemetry (we have none, so no issue — see
  D6) and static analysis of the packaged binary.

**Effort**: 1–2 weeks for the first submission, single-day for
subsequent updates.

**Value verdict**: worth doing **after** 3a + 3b. Winget covers
most power users; MS Store gives us presence in the default
Windows 11 Store app for less-technical users.

**One trap**: the Store version and the direct-download MSI can
diverge in behaviour if they're not built from the exact same
sources. Automate the MSIX build in `release.yml` alongside the
MSI so they're always tag-locked together.

---

## Priorities the maintainer probably wants

If I had to sequence these, I'd do:

1. **Bundle size Tier 1 + Tier 2** — one PR, one week, gets the
   DMG under 250 MB and the MSI under 150 MB. Solves the most
   visible current pain point.
2. **Windows signing (3b)** — one week including Azure setup.
   Unlocks 3a AND removes the SmartScreen warning for direct
   downloaders. High leverage.
3. **Winget (3a)** — half a day after 3b. Immediate
   discoverability win.
4. **MS Store (3c)** — a month later, once 1–3 are stable.
5. **Mac App Store**: defer indefinitely. D18 stands.
6. **Bundle size Tier 3+4**: only if user feedback continues to
   flag size after Tier 1+2.

Each of these should be its own PR (small, reviewable).

## Contact-points for future sessions

- `AGENTS.md`: locked decisions and repo hygiene rules.
- `docs/SIGNING-MACOS.md`: everything about macOS signing +
  notarization + the universal2-phantom history section.
- `docs/SIGNING.md`: developer signed-commit setup.
- `docs/RULESETS.md`: branch protection ruleset JSON.
- `.github/workflows/release.yml`: the actual release pipeline.
  The universal2 assertion step (added after v0.8.4) is a
  useful template for future guardrails — copy its shape.
- `mbp2019.local`, user `reactivedev`, key
  `~/.ssh/cookie_janitor_mac`: the Intel Mac we validate
  releases on. Currently only used manually; consider promoting
  it to a self-hosted GitHub Actions runner if we ever need to
  build x86_64-only DMGs after `macos-13` retirement.
