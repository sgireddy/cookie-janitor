# Signing and notarizing the macOS DMG

Cookie Janitor's macOS DMG is signed with a **Developer ID
Application** certificate and **notarized by Apple** on every tagged
release. This document is the reference for how it works, which
GitHub Actions Secrets are involved, and how to rotate the signing
material when the certificate expires.

For **git commit/tag signing** (a separate concern), see
[SIGNING.md](SIGNING.md).

## Why bother

Apple's Gatekeeper checks two things when a user opens an app
downloaded from the internet:

1. Is the app signed with a certificate Apple recognizes?
2. Has Apple's notarization service scanned this specific build and
   confirmed it's free of known malware signatures?

A signed **and** notarized DMG launches with no user warning at all
on macOS 13+. On Sequoia (macOS 15) it's the only route that works
for a downloaded app that isn't from the Mac App Store — ad-hoc
signed apps require increasingly awkward workarounds.

The alternative — ad-hoc signing — was fine on macOS 12 and earlier,
but on modern macOS the "right-click → Open" workaround is unreliable
and scary for users. Signing removes the friction entirely.

## The two credential types Apple uses

Apple splits the signing/notarization flow across two independent
credentials, each with its own lifecycle:

| Credential | Purpose | Type | Rotation cadence |
|---|---|---|---|
| **Developer ID Application** cert | Codesigns the `.app` bundle | X.509 cert + RSA private key, PKCS12 (`.p12`) file | 5 years (by Apple's issuance policy); currently expires 2027-02-01 due to the G1 CA sunset |
| **App Store Connect API key** | Authenticates with the notarization service | ECDSA P-256 private key, PKCS8 (`.p8`) file | No fixed expiry; rotate on demand |

The signing certificate is what the *end user's Mac* sees. The
notarization key is what the *build machine* uses to talk to Apple.
They serve completely different purposes and don't need to be
rotated together.

## GitHub Actions Secrets — the eight-secret set

All eight secrets live in the repository's **Actions Secrets** at
`Settings → Secrets and variables → Actions`. The workflow reads
them in `.github/workflows/release.yml`.

| Secret name | Sensitivity | Contents |
|---|---|---|
| `MACOS_CERTIFICATE_P12_BASE64` | 🔴 High | `base64` of the `.p12` file (contains the private signing key) |
| `MACOS_CERTIFICATE_PASSWORD` | 🔴 High | Password used when exporting the `.p12` from Keychain Access |
| `MACOS_KEYCHAIN_PASSWORD` | 🟡 Medium | Random password for the *ephemeral* keychain the workflow creates on each run — only meaningful during a single job |
| `MACOS_DEVELOPER_ID_APPLICATION` | 🟢 Low | The cert's Common Name (e.g. `Developer ID Application: Shashi Gireddy (5UN8LU48LQ)`) — used as `--identity` argument to briefcase |
| `MACOS_NOTARY_KEY_P8_BASE64` | 🔴 High | `base64` of the `.p8` App Store Connect API key |
| `MACOS_NOTARY_KEY_ID` | 🟢 Low | 10-char Key ID (shown in ASC Keys page) |
| `MACOS_NOTARY_ISSUER_ID` | 🟢 Low | UUID Issuer ID (shown at top of ASC Keys page) |
| `MACOS_TEAM_ID` | 🟢 Low | 10-char Apple Developer Team ID |

The **High**-sensitivity secrets grant the ability to sign code as
this project. Treat them like a code-signing HSM. The **Low**
secrets are identifiers, useless on their own.

## What the workflow does at run time

Simplified sequence inside the `build-macos` job when the secrets
are present:

1. **Decode and import the .p12** into a fresh, ephemeral keychain
   created just for this job. Set the key partition list so
   `codesign` can use the key without a GUI prompt. Prepend the
   ephemeral keychain to the search list. Delete the on-disk `.p12`
   immediately after import.
2. **Briefcase package** with `--identity "$MACOS_DEVELOPER_ID_APPLICATION" --no-notarize`.
   Briefcase signs the `.app` bundle and every nested Mach-O binary
   (Python framework, Qt frameworks, C extension modules) with the
   Developer ID cert, and enables the hardened runtime.

   The `--no-notarize` flag is deliberate: briefcase's built-in
   notarization looks up credentials via a stored keychain profile
   named `briefcase-macOS-<TEAM_ID>` that would require
   `xcrun notarytool store-credentials` to be run interactively on the
   build machine — impossible in CI. We hand off to our own step
   (below) which uses the `.p8` API key from secrets directly.
3. **Notarize the `.app` directly** via `xcrun notarytool submit --wait`
   with the `.app` zipped up (using `ditto -c -k --sequesterRsrc` to
   preserve symlinks and code-signing metadata). Apple's service
   takes 3–10 minutes typically. **Then `xcrun stapler staple` the
   `.app` in place** — the ticket is now embedded in the bundle.

   This step is critical. macOS 15+ Gatekeeper requires a stapled
   ticket on the `.app` itself when launching from a mounted DMG or
   after a copy to `/Applications`. Stapling only the DMG (as we did
   in v0.8.1 before this fix) causes Sequoia to show the
   "not supported on this Mac" error when it can't complete an
   online Gatekeeper query.
4. **Build a fresh DMG** containing the stapled `.app`.
   `hdiutil create -srcfolder` around a staging directory holding just
   the stapled `.app` and a symlink to `/Applications`. Discards
   briefcase's DMG entirely.

   An earlier v0.8.2 attempt tried to preserve briefcase's fancy DMG
   layout by `hdiutil convert`ing to `UDRW`, mounting, and swapping
   the `.app` inside. That failed with `cp: No space left on device`
   during the copy: `UDRW` conversion produces a read-write DMG whose
   filesystem has essentially zero free space, and HFS+/APFS journal
   + copy buffers need some. Building a fresh DMG from a staging
   directory on the runner's main disk sidesteps the problem.

   Trade-off: briefcase's DMG background image and window layout are
   lost. The DMG becomes a plain Finder icon view — `.app` on the
   left, `/Applications` symlink on the right, drag one to the other.
   Correctness before polish; polish is a nice-to-have to add back
   later.
5. **Sign the DMG** with our Developer ID cert
   (`codesign --sign "$MACOS_DEVELOPER_ID_APPLICATION" --timestamp`).
   `hdiutil create` produces unsigned DMGs, and `spctl -a -t install`
   requires the DMG bytes themselves to carry a Developer ID
   signature — a notarization ticket alone isn't enough for
   Gatekeeper's install policy. (This was the v0.8.3 failure:
   `dist/Cookie-Janitor-universal2.dmg: rejected — no usable
   signature`.) `--timestamp` requests Apple's trusted timestamp
   service so the signature remains verifiable after the cert
   expires. Signing MUST happen **before** the DMG's notarization
   round, otherwise the ticket wouldn't match the on-disk bytes.
6. **Notarize + staple the DMG.** Second `notarytool submit --wait`.
   Apple recognizes the enclosed `.app` is already notarized so this
   round is fast. Then `stapler staple` embeds the ticket in the DMG
   for offline verification of the mounted volume.
7. **Verify from both perspectives:**
   - `spctl -a -vvv -t install <dmg>` — the DMG passes Gatekeeper
     for installing.
   - `spctl -a -vvv -t exec <mounted-app>` — the `.app` passes
     Gatekeeper for executing.
   - `stapler validate` on both.
8. **Cleanup** — delete the ephemeral keychain and the decoded `.p8`.
   Runs even if signing failed.

When the secrets are **not** present (forks, PRs from third parties,
`workflow_dispatch` in an environment without secret access), the
workflow falls back to `briefcase package --adhoc-sign` and skips
notarization. This keeps the workflow usable for development builds.

## Verifying a signed release as a user

Any user can independently verify a downloaded DMG:

```sh
# Check the notarization ticket is stapled correctly
xcrun stapler validate Cookie-Janitor-universal2.dmg

# Confirm Gatekeeper accepts the DMG for installation
spctl -a -vvv -t install Cookie-Janitor-universal2.dmg

# Look at the signing cert (should match our published fingerprint)
codesign -dv --verbose=2 /Volumes/Cookie\ Janitor/Cookie\ Janitor.app
```

The `codesign -dv` output includes the `Authority` chain — the top
authority should be **`Apple Root CA`**, with the leaf reading
**`Developer ID Application: Shashi Gireddy (5UN8LU48LQ)`**. Team
identifier line should match `5UN8LU48LQ`.

## Rotating the signing certificate

The Developer ID Application cert expires 2027-02-01. When it does
(or if it's compromised and needs early rotation):

1. **On the release Mac** (`mbp2019.local` per project convention):
   open Xcode → Settings → Accounts → paid team → Manage
   Certificates → `+` → Developer ID Application. Xcode creates a
   fresh cert and installs it in the login keychain.
2. **Export as .p12**: Keychain Access → My Certificates →
   right-click the new cert → Export → format `.p12` → save with
   a strong random password (`openssl rand -base64 24`). Save the
   password in the maintainer's password manager.
3. **Base64-encode and update the two secrets**:
   ```sh
   base64 -i cj-signing-2027.p12 | tr -d '\n' \
     | gh secret set MACOS_CERTIFICATE_P12_BASE64 --repo sgireddy/cookie-janitor
   printf '%s' 'NEW_PASSWORD' \
     | gh secret set MACOS_CERTIFICATE_PASSWORD --repo sgireddy/cookie-janitor
   ```
4. **Update the cert's Common Name secret** if the new cert's parens
   differ (unlikely — the Team ID doesn't change on renewal):
   ```sh
   security find-certificate -c "Developer ID Application" \
     -p ~/Library/Keychains/login.keychain-db \
     | openssl x509 -noout -subject -nameopt sep_multiline \
     | awk -F'=' '/CN=/ {print $2}'
   ```
5. **Do NOT revoke the old cert** unless it's compromised. Apple
   allows up to 2 active Developer ID Application certs per team —
   keeping the old one active during transition means existing
   installations continue to verify against a still-valid cert.
6. **Delete the old .p12 file** from `~/Documents/` and any backup
   locations (password manager, iCloud) once the new cert is
   confirmed working via a successful test release.

## Rotating the App Store Connect API key

Independent of the signing cert. Rotate whenever a maintainer with
key access leaves the project, or on a general hygiene cadence
(annually is sensible).

1. Log into [App Store Connect](https://appstoreconnect.apple.com)
   as the account holder → Users and Access → Integrations → Team
   Keys → `+` to generate a new key.
2. Download the new `.p8` immediately (one-time download).
3. Note the new Key ID.
4. Update the three secrets:
   ```sh
   base64 -i AuthKey_NEW.p8 | tr -d '\n' \
     | gh secret set MACOS_NOTARY_KEY_P8_BASE64 --repo sgireddy/cookie-janitor
   gh secret set MACOS_NOTARY_KEY_ID --repo sgireddy/cookie-janitor \
     --body "NEW_KEY_ID"
   # Issuer ID is per-team and doesn't change
   ```
5. Revoke the old key from the same App Store Connect page after
   confirming the next release notarizes successfully.

## Where the master copies live

The .p12 and .p8 files are exported once on `mbp2019.local` at cert
creation time. After uploading to GitHub Actions Secrets:

- Backup copies live in the maintainer's password manager (as
  encrypted attachments) and in a personal iCloud Drive location.
- The on-disk files at `~/Documents/cj-signing.p12` and
  `~/Documents/AuthKey_*.p8` are securely deleted with `rm -P`
  after backup is confirmed.

The GitHub Actions Secret is the operational source of truth — the
backups exist purely for disaster recovery (if `mbp2019` and the
password manager both fail simultaneously).

## Why not Mac App Store?

Considered and declined. Cookie Janitor's core function — reading
and modifying other applications' cookie storage under
`~/Library/Application Support/` — is architecturally at odds with
the App Sandbox that Mac App Store submission requires. The tools
required to escape the sandbox (temporary-exception entitlements)
have been consistently rejected by App Review for third-party-data-
access use cases since ~2019.

Developer ID + notarization gives users the same "verified by Apple"
signal without the sandbox restriction. Distribution stays via
GitHub Releases.
