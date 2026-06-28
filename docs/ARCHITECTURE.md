# Architecture

## 1. High-level shape

```
┌───────────────────────────────────────────────────────────────────┐
│ GUI (Tauri 2 desktop shell)                                       │
│   - Rust core, web UI (TypeScript + a small framework)            │
│   - Sandboxed; only allowed to talk to the local Python sidecar   │
└──────────────────────────┬────────────────────────────────────────┘
                           │ JSON-RPC over a local Unix socket /
                           │ named pipe with a per-session token
                           ▼
┌───────────────────────────────────────────────────────────────────┐
│ Python core (`cookie_janitor`)                                    │
│                                                                   │
│  cli/  ◄─── same Python entry-point as the GUI sidecar            │
│                                                                   │
│  ipc/                       ── JSON-RPC server (GUI mode only)    │
│                                                                   │
│  model/   Cookie, Profile, Browser, Decision dataclasses          │
│                                                                   │
│  readers/ chromium.py  firefox.py  safari.py                      │
│              │            │           │                           │
│              ▼            ▼           ▼                           │
│            browser_cookie3 (decrypt) + our own SQLite writer      │
│                                                                   │
│  classify/  cookie_db.py  filter_lists.py  heuristics.py          │
│                                                                   │
│  policy/   decide.py  (KEEP / DELETE / ASK, with rationale)       │
│                                                                   │
│  safety/   process.py  fs.py  backup.py  redact.py                │
│                                                                   │
│  data/     pinned snapshot of Open Cookie DB                      │
│            manifest.json with sha256 of every consumed list       │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

The CLI and the GUI sidecar are the **same process binary** in different
modes. The GUI shell speaks JSON-RPC to that process over a local
socket/pipe; it never has direct file-system access to cookie stores.

## 2. Why this shape

- **One language for the security-critical parts.** All cookie operations
  are in Python. The Rust shell is purely UI plumbing. We don't want
  cookie-deletion logic split across two languages.
- **GUI on day 1, not Electron.** Tauri 2 ships a ~5 MB signed binary per
  OS, with a sandboxed renderer and an explicit capability allowlist.
  Electron's surface is too big for a security-first tool.
- **The GUI cannot do anything the CLI cannot.** Everything the user does
  in the GUI corresponds to a JSON-RPC call that maps to a CLI command.
  This makes the tool scriptable and auditable, and the GUI is just a
  view.

## 3. Core domain model

```python
# model/cookie.py
@dataclass(frozen=True, slots=True)
class Cookie:
    name: str
    domain: str            # ".example.com"  or  "example.com"
    path: str
    expires: datetime | None   # None = session cookie
    secure: bool
    http_only: bool
    same_site: Literal["strict", "lax", "none", "unspecified"]
    is_third_party: bool   # computed from browser's host_key + creation context
    value_sha256: str      # first 8 hex chars only, for logs; never the value
    value_length: int

@dataclass(frozen=True, slots=True)
class Profile:
    browser: BrowserKind   # CHROMIUM, FIREFOX, SAFARI, ...
    vendor: str            # "Google Chrome", "Brave", "Firefox", ...
    profile_name: str      # "Default", "Profile 1", ...
    cookies_db_path: Path
    is_running: bool
```

The actual cookie *value* is loaded only at write time, into a buffer
that is zeroized after use. It never crosses the JSON-RPC boundary.

## 4. Classification pipeline

For each `Cookie`, in order. First rule that fires wins.

1. **User keep-list** match (exact domain or domain suffix, or `name@domain`
   pattern) → `KEEP` with rationale `"matched user rule"`.
2. **Open Cookie Database** lookup by `(name, domain_suffix)` → `KEEP` /
   `DELETE` depending on category and user policy.
3. **Session-cookie heuristic**: `expires is None` and `http_only` and the
   domain matches a host the user has visited as first-party in the last
   N days → `KEEP` with rationale `"likely session cookie on a site you
   visit"`. (The "last N days" check uses the browser's *History* DB,
   read-only.)
4. **EasyPrivacy** domain match → `DELETE` with rationale `"domain on
   EasyPrivacy tracker list (snapshot YYYY-MM-DD)"`.
5. **Disconnect tracking** category match → `DELETE` with rationale
   citing the category (`Advertising`, `Analytics`, `Social`).
6. **Third-party + long expiry** (e.g. `> 30 days`) → `DELETE` with
   rationale `"third-party cookie with long expiry; not on any list, but
   matches the common tracker pattern"`. This is the most aggressive rule
   and is **off by default**; the user must opt in.
7. **Default** → `KEEP` with rationale `"unclassified; kept by default"`.

Every decision carries `rationale` and `source` fields so the GUI grid
can show *exactly* why a cookie was flagged. No "trust us" black boxes.

## 5. Reader / writer per browser family

| Family | Read | Write | Notes |
|--------|------|-------|-------|
| Chromium-based (Chrome, Chromium, Edge, Brave, Opera, Vivaldi, Arc) | `browser_cookie3` (locates profile, decrypts values via DPAPI / Keychain / libsecret) | Our own SQLite writer that opens a copy of `Cookies` and issues `DELETE FROM cookies WHERE …` | Schema shared across all Chromium forks; profile dirs differ. |
| Firefox-based (Firefox, LibreWolf, Waterfox, Floorp, Zen) | direct SQLite read of `cookies.sqlite` (no decryption needed) | direct SQLite writer | We do not need `browser_cookie3` for Firefox; it's pure SQLite. |
| Safari (macOS only) | parser for `Cookies.binarycookies` | rewrite the file from the surviving cookies | macOS-only; we ship the Safari module behind `sys.platform == "darwin"`. |

All writers go through `safety.fs.atomic_replace()` which:
1. Opens parent dir with `O_DIRECTORY | O_NOFOLLOW`.
2. Creates a temp file in the same dir.
3. Writes, `fsync`, closes.
4. Re-checks the running-browser set.
5. `renameat` over the original.

## 6. Filter-list pipeline

- A `manifest.json` in `data/` lists every consumed list with `url`,
  `sha256`, and `reviewed_at`.
- At install/runtime, lists are loaded from `~/.cache/cookie-janitor/lists/`
  if present and matching the manifest hash, otherwise downloaded over
  HTTPS and the hash verified before use.
- `cookie-janitor update-lists` downloads the latest, computes hashes,
  shows a diff, and writes a new `manifest.candidate.json` for the user
  to inspect before promoting.
- The user can run entirely offline by shipping the pinned snapshots
  alongside the install.

## 7. CLI surface (v1)

```
cookie-janitor scan                  # show all profiles + cookie counts
cookie-janitor list --profile <id>   # show all cookies, classified
cookie-janitor clean --profile <id>  # dry-run (default), prints diff
cookie-janitor clean --profile <id> --apply
cookie-janitor restore --backup <id>
cookie-janitor update-lists          # explicit, with diff and review
cookie-janitor gui                   # launches the Tauri shell, spawns
                                     # the sidecar with a fresh token
```

Every subcommand supports `--json` for machine-readable output, used by
the GUI and useful for power users.

## 8. GUI surface (v1)

A single window with:

- Left rail: detected browsers and profiles, with status (running/idle).
- Main grid: cookies in the selected profile. Columns: domain, name,
  category badge, expiry, first/third party, **rationale**, decision
  (`KEEP` / `DELETE`), and a checkbox.
- Top of grid: filter by category, search by domain.
- Bottom bar: "Dry-run preview" and "Apply changes". Apply is disabled
  until the user has reviewed the diff.
- Settings: user keep-list editor, filter-list manifest viewer with the
  pinned hashes shown, backup retention policy.

No modal dark patterns. No "Accept all" button. The default action is
always the non-destructive one.
