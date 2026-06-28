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
| D14 | **Three classifier modes** (Conservative / Balanced / Aggressive), default Balanced. Mode is a `UserPolicy` field; rule order is fixed and grep-able in `policy/decide.py`. | A single hard-coded policy can't serve both "never log me out" users and "clean jar" users. v0.3.0. | Yes (could collapse to one mode if telemetry showed everyone picks the same; but D6 → we have no telemetry) |
| D15 | **Auth-shape exception** protects login cookies in every mode. Substrings ≥4 chars only (no `sid` / `uid` / `sso` — too many tracker false positives like `visid_incap`). `__Host-` / `__Secure-` prefixes always pass. | Aggressive mode otherwise nukes real session cookies | Permanent |
| D16 | **Allow-list lives in a plain text file**, not JSON / SQLite / settings DB. One domain per line. | User-edited, must be `cat`-auditable | Yes |

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

## Open questions for the maintainer

- Project name `cookie-janitor` is a placeholder. Confirm or rename.
- Security report email / domain: `security@<TBD>`. Decide before
  publishing the SECURITY.md externally.
- Signing identity for releases: who holds the keys? Sigstore keyless
  via OIDC in GitHub Actions is the recommended baseline.
