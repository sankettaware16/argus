# Development and Testing

How to work on ARGUS itself: the toolchain, the test suite and its profiles, the local services
tests use, and how a change gets in. For contributing rules and the review process see
[CONTRIBUTING.md](../CONTRIBUTING.md).

**Contents**

- [Set up](#set-up)
- [The test suite](#the-test-suite)
- [The network guard](#the-network-guard)
- [The made-up test site](#the-made-up-test-site)
- [Static checks](#static-checks)
- [The local Kibana tier](#the-local-kibana-tier)
- [Database migrations](#database-migrations)
- [The web app](#the-web-app)
- [Conventions](#conventions)
- [Contribution workflow](#contribution-workflow)

---

## Set up

You need git, Docker with compose v2, and uv ([install.md](install.md#2-prepare-the-machine)).
Python 3.12 comes with uv.

```bash
git clone https://github.com/sankettaware16/argus.git
cd argus
uv sync                         # the package and the dev tools (pytest, hypothesis, mypy, ruff, ...)
uv run argus --help
```

**A database for the integration tests.** The tests use the compose `db` service with the
owner's credentials from `.env`; each integration test creates its own throwaway database
(`argus_test_<time>_<random>`) and never touches the `argus` database.

```bash
cp .env.example .env && chmod 600 .env
# replace the placeholder passwords with random ones
sed -i "s/^ARGUS_DATABASE__OWNER_PASSWORD=.*/ARGUS_DATABASE__OWNER_PASSWORD=$(openssl rand -hex 24)/" .env
sed -i "s/^ARGUS_DATABASE__PASSWORD=.*/ARGUS_DATABASE__PASSWORD=$(openssl rand -hex 24)/" .env
sed -i "s/^REPLICA_ELASTIC_PASSWORD=.*/REPLICA_ELASTIC_PASSWORD=$(openssl rand -hex 24)/" .env
docker compose up -d db
uv run argus db bootstrap       # ARGUS's roles (idempotent)
```

(A full `uv run argus init` on a development machine works too, but needs a SIEM to talk to.)

## The test suite

```bash
uv run pytest -q                              # fast: unit + integration (a few minutes)
uv run pytest -q -m unit                      # pure tests only, no Docker
uv run pytest -q tests/unit/gateway           # one area
HYPOTHESIS_PROFILE=ci uv run pytest -q        # ci: 1,000 examples per property
scripts/gate.sh                               # gate: everything a release checks (below)
```

| Profile | How | Hypothesis examples | Use |
|---|---|---|---|
| **fast** | `uv run pytest -q` (profile `dev`) | 100 | after every change |
| **ci** | `HYPOTHESIS_PROFILE=ci uv run pytest -q` | 1,000 | before a pull request; CI |
| **gate** | `scripts/gate.sh` (`--mutation` adds mutation testing) | 10,000, no deadline | before a release |

`scripts/gate.sh` runs ruff, the format check, mypy, `pip-audit` of the locked dependencies, the
full suite with the `gate` profile and every log line captured, a secret scan of that output,
coverage, and (once `frontend/` has its toolchain) the frontend's checks. Its results go to
`data/gate/<UTC time>/summary.txt`. Heavy steps run through `scripts/heavy.sh`, which caps their
memory.

**Markers** (`--strict-markers`: a test with an unknown marker fails):

| Marker | Needs | Notes |
|---|---|---|
| `unit` | nothing | pure tests, no external services |
| `integration` | Docker PostgreSQL | its own throwaway database per test |
| `kibana` | the local Kibana tier, or nothing | contract tests against a real Kibana 8.19.12 Basic; **replayed from strict cassettes** when the tier does not answer, so they run everywhere |
| `live` | `--run-live` | read-only checks against a real SIEM; none ship in this repository |

Property-based tests use [Hypothesis](https://hypothesis.readthedocs.io/); the profile comes
from `HYPOTHESIS_PROFILE` (`dev` when unset; any other name stops the run).

## The network guard

The suite **never leaves the machine**. `tests/_guard/argus_netguard.py` is loaded into pytest and
into every Python process a test starts, and while it is active:

- sockets may reach only loopback addresses and Unix sockets; any other connection (TCP, UDP,
  asyncio) is refused before it is made;
- PostgreSQL connections are checked before libpq opens its own socket: the server must be on
  this machine, and the database must not be a protected one;
- a child process whose command line names a configured production host is not started;
- the hosts it refuses also come from the configuration: every host in `config/local.yaml`, and
  `siem.url` / `kibana.url` from `.env` and the environment.

The guard cannot be switched off from inside a test. Its own tests are in `tests/_guard/`.

## The made-up test site

Tests do not run against your site. `tests/conftest.py` activates `tests/fixtures/site.yaml`, a
complete, made-up organisation ("Example University", short name ACME, space `acme-soc`, log
families `acme-logs-<source>-*`, incident prefix `ACME-IR`, a mirror and a lookup threat-intel
source, a +05:30 time zone so hand-written times keep their meaning), with its made-up SIEM in
`tests/fixtures/local.yaml`. Your own `config/site.yaml`, `config/local.yaml` and `.env` do not
change what the tests see.

## Static checks

```bash
uv run ruff check .             # lint (pycodestyle, pyflakes, bugbear, bandit, ...)
uv run ruff format --check .    # formatting (100 columns)
uv run mypy                     # mypy --strict over src/, with the pydantic plugin
```

All three must be clean. `uv run ruff format .` fixes formatting.

## The local Kibana tier

For work on the Kibana lane, a local Elasticsearch and Kibana 8.19.12 (Basic licence, security
and HTTPS on, seeded like a real site) run as two compose services under the `kibana` profile, on
the loopback only (Elasticsearch `127.0.0.1:59210`, Kibana `127.0.0.1:55610`). They need about
3 GB of memory. `scripts/kibana_tier.py` is the only way to manage them (it never touches the
`db` service):

```bash
uv run python scripts/kibana_tier.py init       # the CA, certificates and passwords (outside the checkout)
scripts/heavy.sh --label kibana-tier uv run python scripts/kibana_tier.py up --hold &
uv run python scripts/kibana_tier.py seed       # the space, roles, users, keys, a rule
uv run python scripts/kibana_tier.py status
uv run pytest -q -m kibana                      # the contract tests, live against the tier
uv run python scripts/kibana_tier.py down       # stop (keeps the data)
uv run python scripts/kibana_tier.py reset --yes   # remove its containers and volumes
```

Its secrets live in `~/.local/share/argus-kibana-tier` (`KIBANA_TIER_DIR`), so every checkout
uses the same tier. Without the tier, the `kibana` tests replay their recorded cassettes.

## Database migrations

Alembic migrations live in `src/argus/db/migrations/versions/`.

```bash
uv run alembic revision --autogenerate --rev-id 0065 -m "what it adds"
uv run argus db upgrade
uv run argus db check           # the database is at head and matches the models
uv run argus db downgrade --yes -- -1
```

Rules:

- ARGUS runs as a runtime role that owns nothing. **Every migration that adds a table grants
  `argus_runtime` exactly what it needs** (no default privileges) and adds the table to
  `argus.db.roles.RUNTIME_GRANTS`, which `argus doctor` checks.
- Every migration has a working downgrade; the integration suite upgrades and downgrades.
- Tables that must not change (the audit trail) are protected by triggers, not by convention.

## The web app

The React app (`frontend/`) is built into `src/argus/web/spa/`, and **the build is committed**, so
an installation needs no Node. Rebuild it only when you change `frontend/`:

- Node **24** and npm **11** at `~/.local/opt/node24` (ARGUS never uses the system's Node; doctor
  reads the toolchain from there):

  ```bash
  mkdir -p ~/.local/opt && cd ~/.local/opt
  curl -fsSLO https://nodejs.org/dist/latest-v24.x/SHASUMS256.txt
  # download the linux-x64 tarball named in SHASUMS256.txt, check it with sha256sum -c, then:
  tar -xf node-v24.*-linux-x64.tar.xz && mv node-v24.*-linux-x64 node24
  export PATH=$HOME/.local/opt/node24/bin:$PATH
  ```

- Then, in `frontend/`:

  ```bash
  npm ci
  npm run typecheck && npm run lint && npm test
  npm run build                                  # writes ../src/argus/web/spa
  uv run python ../scripts/frontend_build.py manifest   # records what the build came from
  ```

`argus doctor` fails `frontend build` when the committed build is not the build of the current
`frontend/` sources. The app's rules (a strict CSP with Trusted Types, untrusted text only through
`UntrustedText`, every change shown before it is sent) are in [frontend/README.md](../frontend/README.md).
The API the app uses is `docs/api/openapi-v1.json`; `npm run client` regenerates the typed client
from it.

## Conventions

- Python 3.12, async I/O, fully typed (`mypy --strict`), pydantic v2 models at component
  boundaries, UTC timezone-aware datetimes only.
- Settings: every new setting has a default, a bound and a docstring in
  `src/argus/config/settings.py`; unknown names are errors. Secrets are `SecretStr` and never
  logged.
- Nothing new talks to the SIEM except through the gateway, with a template and a purpose; nothing
  new talks to a model except through the LLM gateway and the privacy layer.
- Messages a person reads say what happened and the fix, in plain words, and never print a
  secret or a value from a log.
- Comments are sparse and say why.

## Contribution workflow

1. Open an issue first for anything larger than a fix, so the approach can be agreed.
2. Branch from `main`; keep a change focused.
3. Write the tests with the change (unit, and integration where the database is involved;
   properties with Hypothesis where an input space is large).
4. Run the fast suite and the static checks; for a change to the gateway, the privacy layer or
   the database, also the `ci` profile.
5. Open a pull request describing what changed and why, and how it was tested.

See [CONTRIBUTING.md](../CONTRIBUTING.md), the [Code of Conduct](../CODE_OF_CONDUCT.md), and
report vulnerabilities privately per [SECURITY.md](../SECURITY.md).
