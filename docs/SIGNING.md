# Signing commits and tags

Every commit and tag in this repository should be cryptographically
signed by its author. GitHub shows signed commits with a green
**Verified** badge; unsigned commits show as **Unverified** or with
no badge at all.

Signed commits protect against a specific attack: a party with write
access to the repository (or a stolen GitHub token) pushing commits
that impersonate a maintainer's identity. The commit's `Author:`
field is not authenticated by Git alone — anyone can set it to any
name and email — but a signature can only be produced by whoever
holds the corresponding private key.

For a privacy tool distributed as binaries, "who wrote this line of
code" is a supply-chain question. Signed commits make the answer
verifiable.

## The recommended path: SSH-based signing

Git has supported SSH signing since version 2.34 (November 2021).
It is simpler than GPG:

- No separate keyring to manage.
- Your existing SSH auth key can double as a signing key (though a
  dedicated key is better hygiene).
- GitHub verifies SSH signatures natively — no third-party keyserver
  round-trip.

### One-time setup (per machine)

Assumes you already have an SSH key on the machine you commit from,
typically at `~/.ssh/id_ed25519` (or `id_rsa`). If not, generate one:

```sh
ssh-keygen -t ed25519 -C "commit-signing key for $(whoami)@$(hostname)"
```

Point Git at it:

```sh
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
git config --global tag.gpgsign true
```

Then upload the **public** key to GitHub as a **Signing Key** (this
is a distinct upload from an authentication SSH key, even if the key
file is the same):

1. Copy the public key to your clipboard:
   - macOS: `pbcopy < ~/.ssh/id_ed25519.pub`
   - Linux: `xclip -selection clipboard < ~/.ssh/id_ed25519.pub`
   - Windows (PowerShell): `Get-Content ~\.ssh\id_ed25519.pub | Set-Clipboard`
2. Open <https://github.com/settings/ssh/new>
3. Set **Key type** to **Signing Key** (default is Authentication).
4. Paste, name it something like `commit-signing / <hostname>`,
   click **Add SSH key**.

### Verifying it works

Make a signed commit locally:

```sh
git commit --allow-empty -m "test: verify signing setup"
git log --show-signature -1
```

The output should include:

```
Good "git" signature for <you>@<yourdomain> with ED25519 key SHA256:…
```

Push it to a topic branch and check the GitHub UI — the commit should
render with a green **Verified** badge next to the commit hash.

### Signing tags for releases

Tags for releases must also be signed. `git tag -a v0.8.0 -m "..."`
uses your default signing config, so once `tag.gpgsign = true` is
set globally, every annotated tag is signed automatically:

```sh
git tag -a v0.8.0 -m "Cookie Janitor 0.8.0"
git tag --verify v0.8.0     # should say: Good signature ...
```

Do not push lightweight tags (`git tag v0.8.0` without `-a`) — they
carry no signature.

## The alternative: GPG

If you have an existing GPG identity you want to keep using, that
also works. GitHub supports both. The setup steps are analogous but
involve a separate keyring, and revocation is more involved. Prefer
SSH unless you have a specific reason to stay on GPG.

Reference: <https://docs.github.com/en/authentication/managing-commit-signature-verification/telling-git-about-your-signing-key>

## Verifying someone else's signed commit

If you receive a PR from a contributor, you can verify their signature
matches an SSH key GitHub associates with their account:

- The commit renders with a **Verified** badge in the GitHub UI.
- Locally, after fetching: `git log --show-signature <commit>` shows
  the key fingerprint.
- The fingerprint should be listed at
  `https://github.com/<user>.gpg` (GPG keys) or
  `https://github.com/<user>.keys` (SSH keys) — GitHub exposes both
  publicly.

## What we enforce, and what we do not

We do **not** currently block unsigned commits at the ruleset level.
Doing so before the maintainer's signing setup is complete would
create a chicken-and-egg problem: the ruleset change itself would
have to be pushed as an unsigned commit.

Once the maintainer's signing setup is verified (a Verified commit
lands on `main`), the ruleset can be updated to require signed
commits via:

- `Settings → Rules → Rulesets → main → Rules → Require signed commits`

At that point every future push must be signed to be merged.

## What if my agent / CI / bot cannot sign?

Signed commits do not work well for automated commits made by
third-party agents that do not have access to the maintainer's
private key. Two acceptable patterns:

1. **The agent opens a PR; the maintainer squash-merges it.** The
   squash-merge commit is authored by the maintainer under the
   maintainer's key and is therefore signed. The agent's individual
   commits on the topic branch may be unsigned; only what lands on
   `main` needs to be verified.

2. **The agent uses its own signing key.** Some frameworks (Renovate,
   Dependabot) sign commits with a bot identity. If we add such a
   bot, we add its key here and configure the ruleset to accept it.

Do not attempt to make an unattended agent commit under the
maintainer's identity by copying their private key into CI. That
inverts the security property signed commits exist to provide.
