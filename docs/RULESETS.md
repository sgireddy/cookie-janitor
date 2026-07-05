# Repository rulesets

`cookie-janitor` uses [GitHub Repository Rulesets] for branch and tag
protection instead of the older Branch Protection API. Rulesets are
the modern replacement; they support tags natively, allow bypass
lists, and can be edited transactionally in the UI.

[GitHub Repository Rulesets]: https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets

This document is the canonical description of what rulesets should
exist on the repo. If the live configuration drifts from this file,
that is a bug in one of the two — fix and reconcile.

## Ruleset 1 — `main` branch protection

**Status:** Live. Ruleset id `18538781` (query with
`gh api repos/sgireddy/cookie-janitor/rulesets`).

**Target:** `~DEFAULT_BRANCH` (i.e. `main`)

**Enforcement:** `active`. Bypass actors: none — nobody can push
directly to `main`, including the maintainer. To make an emergency
change, temporarily set enforcement to `evaluate` or `disabled`,
push, and set it back.

**Rules:**

| Rule | Setting | Rationale |
|---|---|---|
| `deletion` | blocked | `main` can never be deleted |
| `non_fast_forward` | blocked | No force pushes; history is append-only |
| `pull_request` | required | Required approvals: 0 (solo maintainer). `required_review_thread_resolution: True`, `dismiss_stale_reviews_on_push: True` |
| `required_status_checks` | required | `strict_required_status_checks_policy: True` (branches must be up-to-date). 12 required checks (see below) |
| `code_scanning` | CodeQL | Blocks merge on high-severity findings |
| `code_quality` | severity=errors | Blocks merge on quality errors |

**Required status checks (12):**

- `lint, type-check, test (<ubuntu-latest|macos-latest|windows-latest>, <3.11|3.12|3.13>)` — 9 cells
- `security checks`
- `Analyze (actions)`, `Analyze (python)` — CodeQL

## Ruleset 2 — `v*` tag protection *(intended, not yet live)*

**Status:** Not yet applied. Requires a token with
`Administration: write` scope to install; the standard agent
$GITHUB_TOKEN does not have this. Maintainer applies via UI or
CLI (payload below).

**Rationale:** Today, anyone with `contents: write` on the repo
(including short-lived agent tokens) can push a tag matching `v*`
and trigger the release workflow, which builds and drafts a
GitHub Release. The release is created as a draft — so it is not
immediately visible — but the workflow itself runs, consumes CI
minutes, and populates a draft that the maintainer may then
publish without realising a bot triggered the build.

A tag ruleset closes this by requiring tags to be created by the
maintainer, and by blocking tag deletion so a released version's
provenance chain can never be silently rewritten.

**Target:** `refs/tags/v*` (or the equivalent glob in Rulesets UI)

**Enforcement:** `active`

**Bypass actors:** `sgireddy` (the maintainer) as `Repository role: Admin`.

### Applying via `gh api` (recommended for reproducibility)

```sh
cat > /tmp/tag-ruleset.json <<'EOF'
{
  "name": "v-tags",
  "target": "tag",
  "enforcement": "active",
  "conditions": {
    "ref_name": {
      "include": ["refs/tags/v*"],
      "exclude": []
    }
  },
  "bypass_actors": [
    {
      "actor_id": 5,
      "actor_type": "RepositoryRole",
      "bypass_mode": "always"
    }
  ],
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "creation" }
  ]
}
EOF

gh api --method POST \
  repos/sgireddy/cookie-janitor/rulesets \
  --input /tmp/tag-ruleset.json
```

**Notes:**

- `actor_id: 5` is the `Admin` repository role. To find role ids for
  a specific repo: `gh api repos/sgireddy/cookie-janitor/rulesets/rule-suites`
  or check the Rulesets UI which lets you pick actors by name.
- The `creation` rule combined with the empty non-admin bypass list
  means only admins can create new `v*` tags — normal push access is
  not enough.
- If you later want to allow a bot (e.g. release-please) to cut
  tags, add its actor to `bypass_actors`.

### Applying via UI

1. `Settings → Rules → Rulesets → New ruleset → New tag ruleset`
2. **Ruleset name:** `v-tags`
3. **Enforcement status:** Active
4. **Bypass list:** add `Repository admin` role, mode `Always`
5. **Target tags:**
   - Include by pattern: `v*`
6. **Rules:** tick:
   - Restrict deletions
   - Block force pushes
   - Restrict creations
7. **Create**

### Post-application verification

```sh
gh api repos/sgireddy/cookie-janitor/rulesets | \
  jq '.[] | {id, name, target, enforcement}'
```

Expected output includes:

```json
{ "id": 18538781, "name": "main",   "target": "branch", "enforcement": "active" }
{ "id": <new>,    "name": "v-tags", "target": "tag",    "enforcement": "active" }
```

Then attempt a test tag push with a non-admin token:

```sh
git tag test-tag-ruleset
git push origin test-tag-ruleset
# expected: rejected due to rule violations
git tag -d test-tag-ruleset  # local cleanup
```

## Ruleset drift detection

If someone edits a ruleset via the UI and forgets to update this
document, the two go out of sync. Options:

1. **Manual:** run `gh api repos/sgireddy/cookie-janitor/rulesets`
   periodically and compare to this file.
2. **Automated:** a `chore/ruleset-drift-check` CI job that fetches
   the live rulesets and diffs against a committed JSON snapshot,
   failing if they disagree. Not implemented today; tracked as a
   possible follow-up.
