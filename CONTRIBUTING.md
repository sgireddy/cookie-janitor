# Contributing

Thanks for considering a contribution.

## Before you start

- Read [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). Most design
  arguments in this project resolve to "what does the threat model say."
- Read [`AGENTS.md`](AGENTS.md) for the locked decisions. If you want
  to change one, open an issue first.
- For security-sensitive bugs, follow [`SECURITY.md`](SECURITY.md) —
  please do not open a public issue.

## Development setup

```bash
uv sync --extra dev
uv run pytest
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy --strict src
uv run bandit -q -r src
uv run pip-audit
```

All of these run in CI on every PR.

## Pull request checklist

- [ ] Tests added or updated for any behavior change.
- [ ] No new dependency without a CVE / GHSA / OSV check and a one-line
      justification in the PR description.
- [ ] If you touched anything in `safety/`, add or update a regression
      test in `tests/unit/test_fs_safety.py` (or peer).
- [ ] If you weakened or removed a hardening guarantee, include a
      `SECURITY-WAIVER:` line in the commit message and tag two
      reviewers.

## Commit messages

Conventional Commits, e.g.:

```
feat(readers): add LibreWolf profile discovery on Linux
fix(safety): reject hardlinked target in atomic_replace
docs: clarify session-cookie heuristic in ARCHITECTURE.md
```

If your work was generated or assisted by OpenHands, include:

```
Co-authored-by: openhands <openhands@all-hands.dev>
```
