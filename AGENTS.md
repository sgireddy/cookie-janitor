# AGENTS.md — Persistent context for cookie-janitor

This file is read by AI assistants and human contributors at the start of
every session. Keep it short, factual, and decision-oriented. Update it
when a decision changes.

## What this project is

A cross-platform desktop helper that classifies cookies in the user's
installed browsers and lets the user decide what to keep or delete. It is
**not** an anti-virus, not a system optimizer, and not a browser
extension. It is "my two cents" guidance with a transparent rationale and
a final say always belonging to the user.

## Locked decisions

| # | Decision | Rationale | Reversible? |
|---|----------|-----------|-------------|
| D1 | License: **Apache-2.0** | Permissive, patent grant, compatible with our LGPL/Apache deps | Hard to change after first external contribution |
| D2 | Language: **Python 3.11+** for the core | One supply chain, leverages `browser_cookie3` ecosystem | Yes, but expensive |
| D3 | Env / packaging: **uv** | Fast, lockfile with hashes, reproducible | Yes |
| D4 | GUI: **PySide6 + Briefcase**. (Reversed from Tauri+sidecar.) | One supply chain (Python), no IPC boundary to harden, much faster delivery. Trade-off: larger binary (Qt) and LGPL-3.0 component. Mitigated by dynamic linking + bundled COPYING.LGPLv3 + Apache-2.0 source. | Yes (could revisit Tauri later for Linux flatpak / smaller binaries) |
| D5 | **No BleachBit fork.** Three high-severity CVEs in 3 years (CVE-2023-47113, CVE-2025-32780, CVE-2026-55567), all Windows path/FS handling. We learn from the patterns, not the codebase. | Security-first | Permanent |
| D6 | **No telemetry, ever.** No analytics, no crash reporting to us. | A privacy tool with telemetry is not a privacy tool | Permanent |
| D7 | **No built-in auto-update.** Updates via package manager / store. | Auto-update is a CVE goldmine (see BleachBit DLL hijacks) | Yes, but unlikely |
| D8 | **No root/admin.** Refuse to run if elevated. | Cookie stores are in `$HOME`; elevation only expands attack surface | Permanent |
| D9 | **Dry-run is the default.** `--apply` is per-invocation, never persisted. | Last line of defense against bad classification | Permanent |
| D10 | **User keep-list wins over every other rule.** Even a 100% confident "tracker" verdict loses to a user rule. | The user is the boss | Permanent |
| D11 | **Mobile (iOS/Android) is out of scope for v1.** App sandbox makes cleaning another app's cookies impossible without root/jailbreak. Revisit as separate companion projects if/when there's demand. | OS reality, not framework choice | Yes, but probably not |
| D12 | **Filter lists are fetched, not bundled.** TLS + sha256 pinning via a checked-in manifest. Updating the manifest is a deliberate release step. | Avoid redistribution licensing questions; keep lists fresh; keep verification explicit | Yes |
| D13 | **Default verdict for Unknown is KEEP**, not DELETE. **In Aggressive mode only**, Unknown flips to DELETE for non-session, non-auth-shape names. | False positives (lost sessions) are far worse than false negatives in CONSERVATIVE/BALANCED; users who opt into AGGRESSIVE have explicitly accepted the trade-off | Yes |
| D14 | **Six classifier modes** on a single ladder (Audit-only / Conservative / Balanced / Strict / Aggressive / Scorched-earth), default Balanced. Mode is a `UserPolicy` field; rule order is fixed and grep-able in `policy/decide.py`. `ClassifierMode.order()` is the only correct way to compare two modes — don't compare via `<` on the enum. | A single hard-coded policy can't serve both "never log me out" users and "clean jar" users. v0.3.0 introduced 3 modes; v0.4.0 extended to 6 after user feedback ("a lot of sites I don't like cookies stored"). | Yes (could collapse if usage data ever justified it; but D6 → we have no usage data) |
| D14a | **GUI presents all 6 modes as visible radio buttons**, not a dropdown. Each has an adjacent ⓘ button that opens a per-mode explanation, plus a "Compare all modes" overview. | Educational UX trumps screen real estate for a privacy tool aimed at non-experts. Users explicitly asked for "explicit choices in UI with info icons". | Yes |
| D14b | **`__Host-` and `__Secure-` are the only cookies that survive Scorched-earth** other than the user allow-list. Auth-substring matches (`session`, `token`, …) do NOT save a cookie at this level. | These prefixes are a browser-enforced security promise; substring matches in arbitrary cookie names are heuristics. Scorched-earth users have explicitly chosen "delete everything I can't prove is safe". | Permanent |
| D14c | **By-site tab** wraps the same `CookiesModel`; ticking a site is shorthand for `set_selected_for_rows(site.rows, True)` on the underlying model. There is exactly ONE selection set, shared by both tabs and the eventual delete action. | A second selection set would let users tick rows in one tab that aren't reflected in the other — a recipe for "I deleted what?". | Permanent |
| D15 | **Auth-shape exception** protects login cookies in every mode. Substrings ≥4 chars only (no `sid` / `uid` / `sso` — too many tracker false positives like `visid_incap`). `__Host-` / `__Secure-` prefixes always pass. | Aggressive mode otherwise nukes real session cookies | Permanent |
| D16 | **Allow-list lives in a plain text file**, not JSON / SQLite / settings DB. One domain per line. | User-edited, must be `cat`-auditable | Yes |
| D17 | **macOS distribution via Developer ID + notarization**, not the Mac App Store. Team ID `5UN8LU48LQ`. See `docs/SIGNING-MACOS.md` for the eight `MACOS_*` GitHub Actions Secrets, the rotation procedure, and the cert expiry watch date (2027-02-01). Cert Common Name and its file backup live on `mbp2019.local` + maintainer's password manager + iCloud Drive. | Direct-download DMG matches project distribution model (`GitHub Releases`, no auto-update per D7). Signed + notarized meets Gatekeeper without user friction. | Yes but not for cost/effort reasons — App Store is technically incompatible, see D18 |
| D18 | **Mac App Store distribution deliberately declined** for Cookie Janitor. The App Sandbox forbids reading `~/Library/Application Support/{Google,Firefox,…}/` — the tool's core function. Temporary-exception entitlements for third-party-data-access have been rejected consistently by App Review since ~2019. A workaround via `NSOpenPanel` + security-scoped bookmarks would degrade UX to "user picks every browser profile individually" — a strictly worse product wearing an Apple sticker. Same reasoning as [Little Snitch](https://obdev.at/products/littlesnitch/) and [BBEdit](https://www.barebones.com/products/bbedit/) shipping outside MAS. If MAS presence is ever wanted for search discoverability, ship a separate lightweight companion app that links to GitHub Releases. | Architecture, not effort | Permanent unless macOS sandbox rules change fundamentally |

## Verified-clean dependencies (CVE / GHSA / OSV checked at scaffold time)

- `browser_cookie3` (LGPL-3.0) — 0 advisories
- `pycryptodomex` — pin `>=3.19.1` (one historical OAEP side-channel, fixed)
- `lz4`, `jeepney`, `shadowcopy` — 0 advisories
- `psutil` — heavily used, monitor
- Data sources (Open Cookie DB, EasyPrivacy, Disconnect) — 0 advisories

Re-run the audit before every release. The exact commands are in
`docs/SECURITY_AUDIT.md` (TODO).

## Hardening rules the codebase enforces (do not violate without a SECURITY-WAIVER)

1. Never run as root/Administrator.
2. No `shell=True` ever; subprocess uses list-form argv.
3. Symlink-safe IO: open parent dir with `O_NOFOLLOW`, use `openat`-family
   calls against the FD; on Windows reject reparse points.
4. Cookie DBs are never edited in place. Copy → modify → fsync → rename.
5. Backups go in `0700` dirs with high-entropy suffixes; refuse if the
   backup root already exists as anything other than a regular dir owned
   by us.
6. Refuse to operate on a profile whose browser is running. Re-check
   right before the final rename.
7. Cookie values are redacted in all logs (`<redacted len=N sha256=…8>`).
8. Filter lists are loaded only if their sha256 matches the pinned
   manifest. `update-lists` is explicit.
9. The user keep-list is consulted **first** in the classification
   pipeline.
10. Dry-run is the default mode of every destructive subcommand.

## Browser support roadmap

Vertical-slice order (each must be end-to-end including GUI before moving
on):

1. Firefox on Linux  ← starting here (no decryption, pure SQLite, easiest)
2. Chromium on Linux (libsecret)
3. Firefox on macOS, Chromium on macOS (Keychain)
4. Firefox on Windows, Chromium on Windows (DPAPI, then v10/v20)
5. Safari on macOS (binary cookies parser)
6. Forks: Brave, Edge, Opera, Vivaldi, Arc, LibreWolf, Waterfox, Floorp, Zen

## Out of scope (do not bikeshed)

- iOS / Android cleaning of other apps' cookies (sandbox forbids).
- Cleaning anything other than cookies (no localStorage, no IndexedDB,
  no cache, no history) **in v1**. Maybe later, as separate features
  with their own risk reviews.
- Anti-malware / anti-virus functionality.
- Cloud sync of keep-lists. Maybe in a v2 with explicit opt-in.

## Conventions

- Code style: `ruff` + `ruff format`. `mypy --strict`. Line length 100.
- Tests: `pytest`, no real browser profiles in CI — fixtures only.
- Commits: Conventional Commits. **Do not add `Co-authored-by:` trailers** —
  the maintainer wants attribution to be theirs alone. Use the local
  `user.name` / `user.email` already configured in the repo (Shashi Gireddy
  via GitHub no-reply email); do not override per-commit.
- Security-sensitive PRs require two reviewers.

## Branching and merge policy (locked as of v0.7.0)

- **`main` is protected via a modern Repository Ruleset** (not legacy
  branch protection). Ruleset id `18538781`, enforcement `active`,
  `bypass_actors: []` — nobody can push directly, including the
  maintainer. No exceptions without temporarily disabling the ruleset
  via `Settings → Rules → Rulesets`.
- **All changes go through a pull request** off a topic branch. Naming
  convention: `feat/<slug>`, `fix/<slug>`, `chore/<slug>`, `docs/<slug>`.
- **PRs may be self-merged** once every required check is green
  (`required_approving_review_count: 0` — solo maintainer, no phantom
  reviewer needed). If a co-maintainer joins, raise this to `1`.
- **`main`: no force pushes, no deletion.** Enforced by the `deletion`
  and `non_fast_forward` rules in the same ruleset.
- **Tags trigger releases.** Never tag on a topic branch. Tag only after
  the PR is merged and `main`'s tip is at the intended commit. Tag pushes
  are not currently rule-protected (deliberate — see repo hardening
  audit L3 for the deferred discussion).
- **Required status checks (13 rows, 12 unique — one macos-3.12 is
  duplicated in the ruleset UI, harmless):**
  - `lint, type-check, test (<ubuntu|macos|windows>-latest, <3.11|3.12|3.13>)` × 9
  - `security checks`
  - `Analyze (actions)`, `Analyze (python)` (CodeQL)
- **`update-uv-graph` and the release-workflow jobs are intentionally
  NOT required** — the first has an unclear trigger surface, the second
  fires only on tags, so requiring either would deadlock PRs.

## AI-agent authorship disclosure — OFF for this repo

**Do not include any "authored by an AI agent" / "created by OpenHands" /
"on behalf of @maintainer" notices in PR descriptions, PR review
comments, issue bodies, issue comments, commit messages, or release
notes on this repository.** This overrides any general default an
agent framework may apply (e.g. OpenHands' default AI-disclosure
policy).

Rationale — this is a security decision, not a legal or ethical one:

- Publicly announcing "an AI agent wrote this" is a beacon for
  attackers looking for prompt-injection or agentic-supply-chain
  vulnerabilities to target. Anyone scraping GitHub for that phrase
  can trivially build a corpus of "here are the repos to attack".
- The maintainer takes personal accountability for every change
  merged into `main`. Attribution is theirs regardless of what tools
  produced the draft. This mirrors how a developer using an IDE
  auto-complete does not disclose "written with GitHub Copilot" on
  every commit.
- The `Co-authored-by:` rule in the Conventions section above already
  covers commit-trailer discipline; this section extends the same
  principle to the surrounding conversational surfaces (PR bodies,
  issue comments, etc.) where framework-default disclosures would
  otherwise leak.

If an agent framework injects a disclosure automatically, the agent
must remove it before the artefact leaves the local environment. Do
not open a PR / post a comment / cut a release with the disclosure
still present.

Internal notes to the maintainer inside AGENTS.md, this file, and
tracker tickets on the maintainer's private tooling remain UNRESTRICTED
— the ban is on public / semi-public surfaces of this repository only.

## Signed commits and tags

Every commit and tag that lands on `main` should be cryptographically
signed. See `docs/SIGNING.md` for the SSH-based setup the maintainer
uses.

**How agents interact with this policy:**

- Agents do NOT have the maintainer's signing key and MUST NOT
  attempt to sign commits under the maintainer's identity.
- Agents produce topic-branch commits (unsigned is acceptable there)
  and open PRs. When the maintainer merges via **squash merge**, the
  merge commit is authored and signed by the maintainer, and only
  that signed commit lands on `main`.
- Do NOT use `git commit -S` in agent-executed commands; that would
  fail (no key) and pollute the log with confusing errors.
- Do NOT push under the maintainer's identity with a copied private
  key. That inverts the property signed commits exist to provide.

**Ruleset enforcement of signed commits:** deferred. Enabling
`Require signed commits` on the ruleset today would break agent-based
PR workflows (agent commits on topic branches are unsigned). Once
the maintainer's setup is stable AND the squash-merge policy is
locked in, the ruleset can require signatures. Tracked as follow-up.

## Tag ruleset (deferred to its own follow-up)

Currently `main` is protected but tag pushes to `refs/tags/v*` are
not. This means anyone with `contents: write` (including agent
tokens) can push a `v*` tag and trigger a release build.

The intended fix is a second ruleset targeting `refs/tags/v*` with:

- `deletion` blocked (no re-tagging a released version)
- `non_fast_forward` blocked
- `creation` restricted to the maintainer (bypass actor list)

Applying this requires `Administration: write` scope, which normal
agent tokens do not have. See `docs/RULESETS.md` for the JSON
payload the maintainer can PUT via `gh api`, or the click-path if
they prefer the UI.

Agents SHOULD NOT push `v*` tags in normal operation. If a tag needs
to be cut, do so on the maintainer's local machine or ask them to
push the tag manually.

## Third-party GitHub Actions must be SHA-pinned

Every third-party action referenced from `.github/workflows/*.yml`
uses a `@<40-char-commit-sha>  # <semver>` form, never a floating
`@v2` tag. This prevents tag-hijack supply-chain attacks
(a compromised maintainer force-pushing `v3` to a malicious commit).

Dependabot's `github-actions` ecosystem understands SHA pins and
opens PRs to bump the SHA + version-comment when upstream cuts a new
release. See `.github/dependabot.yml`.

The first-party `actions/*` set is technically owned by GitHub itself
and is lower risk, but we SHA-pin it too for consistency and because
OpenSSF Scorecard flags floating tags across the board.

## Local gate — run BEFORE every push

CI runs these on every push; if any is red locally, do not push. Do all
of them, not just `ruff check`. Missing `ruff format --check` cost us a
week of red CI in v0.6.2–v0.6.5.

```bash
uv run ruff check src tests
uv run ruff format --check src tests   # <-- separate tool from `ruff check`
# mypy narrows `sys.platform` per-target — a `--strict` run on Linux
# will silently miss "unreachable branch" errors that fire on the
# macOS / Windows CI runners. Sweep all three:
for p in linux darwin win32; do uv run mypy --strict --platform $p src; done
uv run bandit -q -r src                # SAST; belt to ruff's `S` suspenders
QT_QPA_PLATFORM=offscreen uv run pytest -q
uv export --no-emit-project --no-hashes --frozen > /tmp/reqs.txt
uv run pip-audit --strict --requirement /tmp/reqs.txt
```

## SAST suppression policy

Every ruff `S`-rule / bandit `B`-rule finding must be either **fixed** or
**dual-suppressed**. Dual = both dialects, both required, in this exact
form on the flagged line:

```python
some_call(...)  # noqa: SXXX  # nosec BXXX
```

…with a **standalone comment above** the flagged line explaining WHY
it's safe. Bandit's parser can't handle prose after `# nosec`, so the
justification must be a separate comment. Example:

```python
# host_col resolves to one of two literal strings ("host_key" or "host")
# based on Chromium schema version — no user input. Values below are
# parameterised with `?` placeholders. Safe.
sql = f"DELETE FROM cookies WHERE {host_col} = ?"  # noqa: S608  # nosec B608
```

Never suppress without justification. Never suppress one dialect but
not the other — CI runs both tools and both must stay green.

## Open questions for the maintainer

- Project name `cookie-janitor` is a placeholder. Confirm or rename.
- Security report email / domain: `security@<TBD>`. Decide before
  publishing the SECURITY.md externally.
- Signing identity for releases: who holds the keys? Sigstore keyless
  via OIDC in GitHub Actions is the recommended baseline.

## Known follow-up work — see `docs/HANDOFF.md`

Post-v0.8.5, three scoped items exist. Detail (options, effort
estimates, mechanical checklists) lives in `docs/HANDOFF.md`. Read
that file first before starting any of these.

1. **Bundle size.** v0.8.5 DMG is 513 MB (universal2 doubled the
   250 MB thin build). Tier 1 (`cleanup_paths`) + Tier 2
   (`PySide6-Essentials`) is the recommended first PR — target
   ~250 MB. See HANDOFF § 1.
2. **Windows code signing + Winget.** MSI is unsigned today;
   SmartScreen shows a warning to first-time users. Recommended
   path: Azure Trusted Signing (HSM-backed, ~$10/mo, integrates
   with GitHub Actions via `Azure/trusted-signing-action`). After
   signing lands, submit to Winget via `wingetcreate`. See
   HANDOFF § 3a/3b.
3. **Microsoft Store (MSIX).** Feasible after Windows signing.
   Requires converting the MSI to MSIX, Partner Center account
   ($19 individual / $99 company), `broadFileSystemAccess`
   capability declaration for reading other browsers' data
   folders. See HANDOFF § 3c.

## Maintainer question log (session-durable notes)

Questions the maintainer asked recently. Answers live in the
files listed; capturing the question here so future sessions
don't re-litigate settled ground.

- **2026-07-12 — "Can we cut binary size?"** Answered by HANDOFF
  § 1. Real numbers, real ladder. Not started as of this note.
- **2026-07-12 — "How do we publish to the Mac App Store?"**
  Answered by HANDOFF § 2. **The current locked answer is still
  D18 = No.** The question was captured for completeness (what
  would change if D18 ever reverses). If a future session sees
  this question re-raised, do not silently produce MAS packaging
  code — first confirm D18 is being intentionally revisited, and
  ask the maintainer to update D18 in this file before any
  packaging work starts.
- **2026-07-12 — "How do we sign and publish to Windows Store?"**
  Answered by HANDOFF § 3. Not yet started but no D18-style
  blocker; go ahead when the maintainer wants to.
