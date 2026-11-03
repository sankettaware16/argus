## Summary

<!-- What does this PR change, and why? Link the related issue: Fixes #NN -->

## Type of change

- [ ] Bug fix
- [ ] New feature (intake, evidence pack, assessment, web, installer)
- [ ] SIEM gateway / request templates
- [ ] Database migration
- [ ] Documentation
- [ ] CI / repository housekeeping

## Checklist

- [ ] `uv run ruff check . && uv run ruff format --check . && uv run mypy` are clean
- [ ] `uv run pytest -q` passes (unit + integration; the network guard keeps tests on the loopback)
- [ ] New SIEM requests go through the gateway, with a template and tests
- [ ] Migrations GRANT the runtime role exactly what it needs (`argus.db.roles.RUNTIME_GRANTS`)
- [ ] No real data anywhere (IPs, hostnames, usernames, organisation names, keys are placeholders)
- [ ] `CHANGELOG.md` updated under `[Unreleased]` (for user-visible changes)
