# Security Policy

`cookie-janitor` is a privacy tool. Its trustworthiness depends on us being
honest about what it does, careful about how it does it, and responsive when
things go wrong.

## Reporting a vulnerability

**Do not open a public GitHub issue for security reports.**
Use GitHub Security Advisories: https://github.com/sgireddy/cookie-janitor/security/advisories/new


## Supported versions

| Version | Supported       |
| ------- | --------------- |
| latest minor | ✅ security fixes |
| previous minor | ✅ security fixes (90 days after next minor) |
| anything older | ❌ |

We do not backport security fixes to releases older than the previous minor.

## What we consider in scope

- Any path that could let an attacker on the same machine **delete, modify,
  or read files outside the user's cookie stores**.
- Any **symlink, junction, hardlink, or TOCTOU** attack against our file
  operations.
- Any **dependency confusion**, **supply-chain**, or **filter-list
  poisoning** scenario that lets an attacker influence what we delete.
- **Privilege escalation**: we run as the unprivileged user. Any path that
  gains privileges is in scope.
- **Information disclosure**: leaking cookie values into logs, telemetry,
  crash dumps, or temp files with world-readable permissions.
- **Insecure defaults**: anything where the default behavior is more
  destructive or more permissive than documented.

## What we consider out of scope

- Attacks that require the attacker to already be root / SYSTEM /
  Administrator on the user's machine. At that point cookie-janitor is not
  the relevant defense.
- "Cookie X is a tracker but we classified it as Functional" — this is a
  data quality issue, not a vulnerability. Please open a regular issue
  against the upstream Open Cookie Database, EasyPrivacy, or Disconnect
  list, and a parallel issue here so we can adjust heuristics.
- Browsers' own bugs (e.g. Chrome leaks cookies via prefetch). Report to
  the browser vendor.
- Physical access to an unlocked machine.

## Hardening commitments

These are guarantees the codebase enforces; bugs that violate them are
in-scope security issues.

1. **Never runs as root / Administrator.** If invoked with elevated
   privileges, we refuse to continue and explain why.
2. **No shell invocation.** All subprocess calls use list-form `argv`.
3. **Symlink-safe IO.** Every file operation that touches paths under a
   user-writable directory uses `O_NOFOLLOW` semantics on POSIX and rejects
   reparse points on Windows. We open the parent directory and operate on
   file descriptors (`openat`, `unlinkat`), never on raw paths after
   resolution.
4. **Atomic edits.** Cookie databases are never modified in place. We copy,
   modify, `fsync`, and `rename` after re-checking the original's inode.
5. **Backups before any write.** Stored under a directory we create with
   mode `0700` and a path containing no user-controllable component.
   Backups are pruned on a clear policy (last N, configurable).
6. **No live writes to running browsers.** We detect running browser
   processes via `psutil` and refuse to operate on their profiles. Users
   are told which process to close.
7. **Dry-run by default.** `--apply` is required for any destructive
   action and is never persisted between invocations.
8. **No auto-update.** Updates come from your package manager / app store.
9. **No telemetry.** No analytics, no crash reporting to us, no usage
   pings, ever.
10. **Pinned dependencies and pinned filter lists.** Both have hashes in
    a manifest checked at install/runtime. Updating either is a deliberate
    release step.
11. **No network access during cookie operations.** Network is used only
    for the explicit `update-lists` command.
12. **Sensitive values never appear in logs.** Cookie values are redacted
    by default; only names, domains, and metadata are logged.
13. **Release binaries carry SLSA build provenance attestations.** Every
    DMG and MSI is signed via Sigstore keyless signing during the release
    workflow. Users can verify a downloaded installer was built from a
    specific commit by GitHub Actions in this repository with:

    ```sh
    gh attestation verify Cookie-Janitor-<arch>.<dmg|msi> \
      --repo sgireddy/cookie-janitor
    ```

    A failed verification is a supply-chain red flag: do not run the
    installer, open a security advisory instead.

Any code change that weakens or removes one of these guarantees requires
a `SECURITY-WAIVER:` line in the commit message and approval from two
maintainers.
