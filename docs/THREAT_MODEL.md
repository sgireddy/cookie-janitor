# Threat Model

Living document. Reviewed at every release. Last updated alongside the
initial scaffolding.

## 1. What we are protecting

`cookie-janitor` operates on cookie databases stored in a user's home
directory. The assets are:

| # | Asset | Why it matters |
|---|-------|----------------|
| A1 | The user's **active login sessions** (the cookies we choose to keep) | Loss of availability = the user has to log in again. We must never accidentally delete a session the user wanted kept. |
| A2 | The **cookie databases themselves** (SQLite or binary files) | If we corrupt one, the browser may fail to start or lose all cookies. |
| A3 | **Cookie values in memory and on disk during processing** | They are bearer tokens. Leaking them to logs, temp files, or telemetry is an information-disclosure bug. |
| A4 | **Filter-list and Open-Cookie-DB snapshots** we rely on | If poisoned, an attacker can influence what we delete or keep. |
| A5 | The user's **trust** that this tool does what it says | Soft asset, but it's why this project exists. |

## 2. Who we defend against

| # | Actor | Capability | In scope? |
|---|-------|-----------|-----------|
| T1 | Local unprivileged process running as the same user | Can race file operations, plant symlinks/junctions inside the user's writable directories | ✅ Yes |
| T2 | Local unprivileged process running as a different user | Cannot read the user's home directory under default OS permissions | ⚠️ Limited — we still ensure backup dirs are mode `0700` |
| T3 | Network attacker against our filter-list / dataset downloads | Can MITM HTTP, swap hosts via DNS, or compromise an upstream mirror | ✅ Yes — TLS + hash pinning |
| T4 | Compromised upstream maintainer of a dependency | Can publish a malicious version | ⚠️ Mitigated by hash-pinned lockfile + dependabot review, not eliminated |
| T5 | Compromised upstream maintainer of a filter list / dataset | Can poison classification | ⚠️ Mitigated by shipping a pinned manifest, optional cross-checking between sources |
| T6 | Root / SYSTEM / Administrator on the local machine | Owns the machine | ❌ Out of scope — see SECURITY.md |
| T7 | Physical attacker with the machine unlocked | Can do anything the user can | ❌ Out of scope |
| T8 | Web attacker who has injected JS into a browser tab | Can already set/read cookies for the affected origin | ❌ Out of scope — they don't need us |

## 3. Trust boundaries

```
                 ┌────────────────────────────────────────────────┐
                 │ User                                           │
                 │  ┌──────────────────────────────────────────┐  │
                 │  │ cookie-janitor (Python core + GUI)       │  │
                 │  │   trust = same as user                   │  │
                 │  └────────────┬─────────────────────────────┘  │
                 │               │ FS calls under $HOME           │
                 │               ▼                                │
                 │  ┌──────────────────────────────────────────┐  │
                 │  │ Browser profile dirs (USER-WRITABLE)     │  │
                 │  │   - SQLite cookie DBs                    │  │
                 │  │   - any other process running as user    │  │
                 │  │     can plant symlinks/junctions here    │  │
                 │  └──────────────────────────────────────────┘  │
                 └────────────────────────────────────────────────┘
                              │
                              │ TLS + hash-pinned downloads
                              ▼
                ┌──────────────────────────────────────┐
                │ Upstream filter lists / datasets     │
                │   (semi-trusted — verified)          │
                └──────────────────────────────────────┘
```

The interesting boundary is the inner one: even though we run as the same
user as the cookie store, we treat the cookie store *path* as
attacker-influenceable, because any other process running as the user (e.g.
malware, a misbehaving extension that wrote files outside the sandbox, a
shared-machine roommate's leftover process) could have planted symlinks
there.

## 4. Concrete threats and our mitigations

### TH-1: Symlink / junction redirection to delete an arbitrary file

*Scenario.* A malicious local process replaces the cookie DB at
`~/.config/google-chrome/Default/Cookies` with a symlink to
`/etc/passwd` or `C:\Windows\System32\drivers\etc\hosts` between the time
we check the path and the time we open it.

*Reference.* This is exactly the class of bug behind BleachBit's
CVE-2026-55567 (CVSS 7.8).

*Mitigation.*
- Open the **parent directory** with `O_DIRECTORY | O_NOFOLLOW` (POSIX) /
  `FILE_FLAG_BACKUP_SEMANTICS` + reparse-point rejection (Windows).
- Use `openat` / `unlinkat` / `renameat` against the directory FD; never
  re-resolve the path.
- After opening the target file, `fstat` it and verify it is a regular
  file owned by the current user, with `st_nlink == 1` for files we will
  rename over.
- On Windows, after opening, query `FILE_ATTRIBUTE_REPARSE_POINT` and
  refuse if set.

### TH-2: Backup directory hijack

*Scenario.* Attacker pre-creates `~/.cache/cookie-janitor/backups/` as a
symlink to a sensitive location, hoping our backup write clobbers it.

*Mitigation.*
- We create the backup root with `mkdir(mode=0o700)` and refuse if it
  already exists as anything other than a regular directory owned by us
  with mode `0700`.
- Each backup goes in a fresh subdirectory whose name is a high-entropy
  random suffix.

### TH-3: TOCTOU on browser-running check

*Scenario.* We check that Chrome is not running, then start writing; Chrome
launches mid-write and corrupts its own SQLite store.

*Mitigation.*
- We acquire an exclusive SQLite lock on a *copy* of the DB, modify the
  copy, then `rename` over the original. Even if the browser starts mid-way,
  the worst case is the rename fails (file in use on Windows) and we report
  it cleanly.
- We re-check the running-processes set immediately before the `rename`.

### TH-4: Filter-list poisoning

*Scenario.* `easylist.to` or its CDN is compromised and serves a list that
marks `accounts.google.com` as a tracker.

*Mitigation.*
- We ship a **pinned manifest** with `sha256` of each list version we have
  reviewed. The runtime refuses to use lists whose hash isn't in the
  manifest.
- `cookie-janitor update-lists` is an explicit user action that produces a
  diff for the user to review before pinning a new manifest.
- The user's **keep-list always wins** over any filter-list verdict. Even
  if a list said "delete this", a user rule pinning `google.com` overrides.

### TH-5: Dependency confusion / supply-chain

*Scenario.* A malicious package with a typo-squatting name is pulled into
the build.

*Mitigation.*
- `uv.lock` with `--require-hashes` style hash pinning.
- `pip-audit`, `safety`, and `osv-scanner` run in CI on every PR.
- Dependabot/Renovate PRs require human review; no auto-merge.

### TH-6: Cookie value leakage via logs

*Scenario.* A debug log includes the literal value of a session cookie. It
gets emailed to support, posted to a GitHub issue, or sent to a crash
reporter.

*Mitigation.*
- A `RedactingFormatter` is installed at the root logger. Cookie value
  fields are replaced with `<redacted len=N sha256=…8>`.
- No crash reporter ships in the product.
- Tests assert that cookie values never appear in captured log output.

### TH-7: Accidental deletion of a session the user wanted kept

*Scenario.* Misclassification deletes the user's Gmail session.

*Mitigation.*
- Dry-run is the default. The GUI shows the full planned diff before
  apply.
- Every deletion creates an entry in the backup so `restore` brings it
  back.
- The user keep-list is matched **first**, before any list lookup, so
  user intent always wins.
- We default to `KEEP` for any cookie we cannot classify with high
  confidence (Unknown → keep). False positives are worse than false
  negatives in this tool.

### TH-8: Running as root / Administrator

*Scenario.* User invokes `sudo cookie-janitor` because "more permissions
must be better."

*Mitigation.*
- The CLI and GUI both refuse to start if `os.geteuid() == 0` or the
  Windows token is elevated, with a clear explanation.

## 5. Non-goals (explicit)

- We do not protect against malware that is already running with the same
  privileges as the user when our tool is not invoked.
- We do not protect cookies *while* the browser is using them.
- We do not protect against the user choosing to keep tracking cookies.
  Their machine, their call.
- We do not detect or remove malware, browser hijackers, or extensions.

## 6. Review process

This document is reviewed at every minor release. New threats discovered
in dependencies, in similar tools' CVEs, or in our own pentests are added
here with their mitigations before any code change ships.
