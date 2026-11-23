# Contributing to ARGUS

Thank you for helping improve ARGUS. Bug fixes, evidence packs, documentation,
and features are all welcome. Ecosystem-wide guidelines live in
[tlsoc — CONTRIBUTING](https://github.com/sankettaware16/tlsoc); this file covers
what is specific to ARGUS.

## Ground rules

- Be respectful — participation is governed by the
  [Code of Conduct](CODE_OF_CONDUCT.md).
- **Never include real data** in issues, commits, fixtures or tests: no real IP
  addresses, hostnames, organisation names, usernames, e-mail addresses, alert
  bodies or API keys. Use the documentation ranges (`192.0.2.0/24`,
  `198.51.100.0/24`, `203.0.113.0/24`), `example.org`, and the made-up test site
  in `tests/fixtures/site.yaml`.
- Security vulnerabilities go through [SECURITY.md](SECURITY.md), never public
  issues.
- Contributions are accepted under the [Apache-2.0 license](LICENSE).

## How this repository is made

ARGUS is developed in a private repository that also holds its first installation's
configuration, working notes and incident records. This repository is an export of it: the
same code, tests and documentation without that installation's files, checked by a sweep for
its names and addresses before every push. That is why the history here is short and its
commits are large.

- Comments and tests cite design decisions by number (`D-123`).
  [docs/decisions.md](docs/decisions.md) lists what each one decided; the full entries stay
  with the working notes. Other labels (`Q-A5`, `AR8`, `P4-F`) name the work item a piece
  was built under.
- A few tests check the code against files of the private repository (its runbooks, its
  release tooling). They are skipped here, and say so.
- A pull request is reviewed here and applied to both repositories.
- A release is a tag (`vX.Y.Z`), a GitHub release and a dated section of
  [CHANGELOG.md](CHANGELOG.md), made only after that build was installed from scratch and
  tried. Between releases `main` reports a development version (`X.Y.Z.dev0`).

## Development setup

```bash
git clone https://github.com/sankettaware16/argus.git && cd argus
uv sync                                  # Python 3.12 and every dependency
cp .env.example .env && chmod 600 .env   # then set the two database passwords
docker compose up -d db                  # PostgreSQL on 127.0.0.1:55432
uv run argus db bootstrap && uv run argus db upgrade
```

The full guide — test profiles, markers, the network guard, the local Kibana
tier — is [docs/development.md](docs/development.md).

## Before you open a pull request

```bash
uv run ruff check . && uv run ruff format --check . && uv run mypy
uv run pytest -q                         # unit + integration (Docker PostgreSQL)
```

- **Tests never leave the loopback.** The suite's network guard refuses every
  non-loopback connection; tests run against a made-up site and local fakes.
  Never add a test that needs a real SIEM.
- **Typed and formatted:** `mypy --strict`, `ruff` (line length 100), pydantic v2
  models at component boundaries, UTC timezone-aware datetimes only.
- **Generic code:** nothing specific to one organisation in `src/` — a site's
  values belong in `config/site.yaml` (written by `argus discover`) or
  `config/local.yaml`. That includes words: a sentence, a label or a prompt says
  "your network" through the site's own word (`argus.site.say`, `lib/site.ts`),
  never "campus" or "the office". The suite's made-up site is a university, so
  `tests/unit/site/test_organisation_words.py` and
  `frontend/tests/site-words.test.tsx` check the words on a second site.
- **Database changes** come as an Alembic migration
  (`uv run alembic revision --autogenerate -m "..."`) that GRANTs the runtime
  role exactly what it needs and lists the table in
  `argus.db.roles.RUNTIME_GRANTS` (`argus doctor` checks it).
- **The SIEM's safety first:** every request goes through the gateway
  (`src/argus/gateway/`) with its budget, health states and quiet hours. A
  change that adds a request type adds a template and its tests.
- Update [CHANGELOG.md](CHANGELOG.md) under `[Unreleased]` for user-visible
  changes.

## Reporting bugs and proposing features

Use the issue templates. For a bug, include `uv run argus doctor` output and the
relevant `journalctl --user -u argus-<service>` lines — **sanitized**.
