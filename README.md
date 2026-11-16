<h1 align="center">ARGUS</h1>

<p align="center">
  <b>AI-Guided Investigation &amp; Evidence Orchestration System</b><br/>
  An always-on first-line SOC analyst for Elastic SIEM: it takes in every alert, groups and
  investigates them, and leaves people a short, explained, reviewed queue.
</p>

<p align="center">
  <a href="https://github.com/sankettaware16/tlsoc"><img src="https://img.shields.io/badge/TLSOC-Ecosystem-4a6edb" alt="TLSOC Ecosystem"/></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="License: Apache-2.0"/></a>
  <img src="https://img.shields.io/badge/python-3.12-3776AB?logo=python&logoColor=white" alt="Python 3.12"/>
  <img src="https://img.shields.io/badge/Elastic-8.x%20%7C%209.x-005571?logo=elastic&logoColor=white" alt="Elastic 8.x | 9.x"/>
  <img src="https://img.shields.io/badge/PostgreSQL-17-4169E1?logo=postgresql&logoColor=white" alt="PostgreSQL 17"/>
  <img src="https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=black" alt="React 19"/>
  <img src="https://img.shields.io/badge/AI-optional%2C%20free%20tiers%20first-6b7280" alt="AI optional, free tiers first"/>
</p>

<p align="center">
  <a href="#getting-started">Getting Started</a> •
  <a href="docs/features.md">Features</a> •
  <a href="docs/architecture.md">Architecture</a> •
  <a href="docs/install.md">Installation</a> •
  <a href="docs/llm.md">AI Providers</a> •
  <a href="docs/costs.md">Costs</a> •
  <a href="docs/case-team.md">Case Team</a> •
  <a href="#tlsoc-ecosystem">Ecosystem</a>
</p>

---

## Overview

Many security teams cannot watch their SIEM around the clock. Alerts pile up between reviews, and
one incident shows up as dozens of separate alerts. **ARGUS** sits on top of an existing Elastic
SIEM (Elasticsearch and Kibana Security, any licence, Basic included) and **owns every alert**:

1. it takes in each Security alert within a minute, and never loses one;
2. it groups duplicates into **investigations** and alike investigations into **patterns**;
3. it gathers the evidence an analyst would look for, from your own logs, into a **dossier** in
   which every fact names its source and the query behind it;
4. it **proposes an outcome**: a deterministic decision engine learned from your reviewers' own
   verdicts, and optionally an **AI investigator** behind a privacy layer, for what the engine
   cannot decide;
5. it **suggests cases** across investigations and writes each case's **incident report** (a page,
   a PDF and CSVs);
6. it leaves people a calm **Inbox** to confirm or correct, and, when you switch it on, posts the
   confirmed incident to **Kibana Cases** as a team of seven named Kibana users.

ARGUS reads your SIEM with a **read-only key**, through a gateway that holds it to a daily load
budget and backs off when the cluster is busy. It writes nothing to the SIEM unless you switch a
write on yourself, and nothing is closed without a person. It runs with **no AI at all**; with
AI keys it uses **free providers first** and caps paid use per day and per month.

![The ARGUS Inbox: what needs a person today, in order](docs/images/screenshots/inbox.png)

## Screenshots

<table>
  <tr>
    <td width="50%"><img src="docs/images/screenshots/investigation.png" alt="An investigation: the verdict, the facts behind it and every check ARGUS made"/><br/><sub><b>Investigation</b>: the verdict in a few lines, every fact with its query</sub></td>
    <td width="50%"><img src="docs/images/screenshots/case.png" alt="A case: summary, incident report, timeline, evidence and actions"/><br/><sub><b>Case</b>: one real problem across hosts, rules and days</sub></td>
  </tr>
  <tr>
    <td width="50%"><img src="docs/images/screenshots/dashboard.png" alt="The dashboard: alerts, investigations and incidents at a glance"/><br/><sub><b>Dashboard</b>: alerts, investigations and incidents at a glance</sub></td>
    <td width="50%"><img src="docs/images/screenshots/incident-report.png" alt="Page 1 of a generated incident report PDF"/><br/><sub><b>Incident report</b>: written by code, every number from a cited fact</sub></td>
  </tr>
  <tr>
    <td width="50%"><img src="docs/images/screenshots/inbox-dark.png" alt="The Inbox in dark mode"/><br/><sub><b>Dark mode</b>: follows the system setting</sub></td>
    <td width="50%"><img src="docs/images/screenshots/proposals.png" alt="Proposals grouped by what decided them, with an audit sample"/><br/><sub><b>Proposals</b>: confirm a whole group after checking its sample</sub></td>
  </tr>
</table>

The screenshots show a demo installation on made-up data. More in the
[Web UI guide](docs/web-ui-guide.md).

## Key Features

- **Owns every alert** — takes in every Security alert of a Kibana space every minute, backfills
  a configurable history (`history.window`, 5 days by default), reconciles hourly so nothing is
  lost between reviews, and quarantines (never drops) an alert it cannot read.
- **Incidents, not alerts** — an incident engine scores every alert group and evidence fact on the
  campus side (device, account, site), links them across rules, days and log families by shared
  hosts, accounts, flagged or rare indicators and campaigns (never through hubs such as NAT,
  proxies or resolvers), and puts in front of a person only what crosses a lane (decisive, burst,
  slow, campaign, exposure). Each incident carries a priority (P1–P4), a certainty word, a "why"
  line whose points add up, what was checked, and the benign explanations it ruled out; plain
  internet scanning goes to a "handled by ARGUS" digest. A campus site that really served a file
  is verified by a capped checking lane before anyone reads "served".
- **Groups before people look** — one investigation per rule, actor and day; alike investigations
  form patterns a reviewer decides at once. Thousands of alerts become hundreds of decisions.
- **Deterministic evidence** — bounded, read-only questions to your proxy, web, DNS and sign-in
  logs, your threat-intel indices and the host's history, chosen by each log family's role. A
  missing log is *unknown*, never *clean*.
- **Proposes, with reasons** — a decision engine learned from your reviewers' verdicts proposes
  outcomes where they agree; a **safety floor** in code never lets "benign" through while a danger
  sign is present or unknown.
- **An optional AI investigator** — a lead agent with web, proxy and threat-intel specialists
  reads a **pseudonymised** dossier, may run a fixed list of read-only checks, and answers with a
  verdict, hypotheses and cited facts; code checks every citation. One run per **pattern**, not
  per alert.
- **An analyst's queue modelled on the big SOC tools** — four pages (Today · Incidents · Search ·
  Reports): incident cards and a queue with a preview pane, a sticky decision bar (confirm, not an
  incident with a reason, merge, "I'm checking"), entity pages for devices, accounts, sites and
  outside addresses, keyboard shortcuts, light and dark, phone layouts. Titles say what happened,
  to what, how sure ARGUS is and what came of it; a checker refuses any claim without a fact.
- **Cases and incident reports** — suggested cases (campaigns, a host flagged by several rules,
  actors on the same rare targets), a case lifecycle with two-person closures, known infections
  that stop re-raising what an owner was already told, and an incident report as a page, a PDF
  with a one-page dashboard, and CSVs.
- **A Kibana case team** — when you switch it on, ARGUS posts a person-confirmed incident to
  Kibana Cases as **seven Kibana users** (lead, evidence, visualiser, intel, responder, hunter,
  reporter), each owning its part, with the files in the Files tab and live charts of the alerts.
  It creates those users and keys itself, with one command.
- **Protects the SIEM** — every request goes through the Elastic Gateway: a budget in server time
  (60 minutes a day by default; one site measures 6–9), health states that slow ARGUS down and
  then stop it, quiet hours, an overload breaker, kill switches and a ledger of every request.
- **Cost-first AI** — no keys means $0; free tiers (Groq, OpenRouter, Google Gemini) first; paid
  fallbacks (OpenAI, then Anthropic) only when no free provider can answer, within daily and
  monthly caps overall and per provider. Measured: about **$0.60 to $1.20 a day**.
- **Run from the browser** — one command installs it (`./install.sh`); a first-time setup in the
  app connects your SIEM; **Settings** holds every setting with its help (each change checked,
  applied by `argus-admin` within seconds, and rolled back by itself if a service does not come
  back; keys sealed and never shown again); **Users and roles** gives people a role and a
  one-time link to set their own password. Anything that would write to your SIEM needs an
  administrator's password and a typed confirmation.
- **Operable** — `argus doctor` checks every part with the fix for each problem, verified
  backups with a weekly restore drill, a retention purge, systemd units rendered for your machine.

The full catalogue: [docs/features.md](docs/features.md).

## Architecture

```mermaid
flowchart LR
  A["Kibana Security alerts"] --> G{{"Elastic Gateway<br/>read-only · budget ·<br/>health · quiet hours"}}
  L["Your log indices<br/>+ threat intel"] --> G
  G --> C["Collector<br/>every minute"]
  C --> GR["Grouping<br/>investigations, patterns"]
  GR --> W["Worker<br/>evidence packs → dossier"]
  W -. "bounded queries" .-> G
  W --> AS["Assessment<br/>decision engine + floor,<br/>optional AI investigator"]
  AS -. "pseudonymised" .-> LLM{{"LLM gateway<br/>free first, capped"}}
  AS --> CS["Cases<br/>incident reports"]
  CS --> UI["Inbox<br/>reviewers decide"]
  UI -- "verdicts teach the engine" --> AS
  CS -. "case team (off by default)" .-> KC["Kibana Cases"]
  DB[("PostgreSQL")] --- C & W & AS & UI
```

Every arrow into the SIEM goes through the Elastic Gateway; every arrow to a model goes through
the LLM gateway and its privacy layer. Full diagrams (the gateway, health states, the privacy
layer, the database, the services): [docs/architecture.md](docs/architecture.md).

## Getting Started

### Prerequisites

| | Required | Notes |
|---|---|---|
| A Linux machine with systemd | yes | 2 vCPU / 4 GB RAM / 50 GB SSD at least; 4 vCPU / 8 GB / 100 GB recommended; ARGUS uses about 1.2 GB of memory |
| Docker Engine with compose v2, git, [uv](https://docs.astral.sh/uv/) | yes | uv fetches Python 3.12 itself; Node.js is not needed |
| Elasticsearch and Kibana **8.x or 9.x** with Kibana Security, over HTTPS | yes | any licence, Basic included |
| Someone who can create an API key in it, for five minutes | yes | the exact read-only request: [docs/install.md](docs/install.md#32-the-api-keys-argus-asks-for) |
| LLM keys (Groq, OpenRouter, Gemini free; OpenAI paid) | no | without them ARGUS investigates deterministically |

### Install: one command, then the browser

```bash
git clone https://github.com/sankettaware16/argus.git
cd argus
./install.sh
```

`./install.sh` installs ARGUS's packages, starts PostgreSQL in Docker with new passwords, makes the
web's certificate and starts two services: the web app and `argus-admin`, which applies the
changes people make in the app. It asks one question (the address people open ARGUS at) and ends
with a one-time link for the first administrator:

```
    https://192.0.2.10:8765/welcome?token=…
```

Open it, choose a password, sign in, and press **Start the setup** on Today. Four short steps
ask for your organisation (name, domains, networks, time zone), Elasticsearch's address (ARGUS
shows the certificate it presents, for you to compare and trust) and a **read-only API key**, and
optionally Kibana. ARGUS then discovers your log families, Kibana space and threat-intel sources
(metadata only), writes its configuration and starts every service. The first alerts arrive in
minutes. Lost the link? Run `./install.sh` again.

The whole path, including how to make the read-only key and how to install from the terminal
alone (`uv run argus init`, interactive or with an answers file):
[docs/install.md](docs/install.md).

### Run it from the app

| To… | Go to |
|---|---|
| Change a setting: the SIEM, Kibana, outside lookups (VirusTotal, Shodan, Censys), notices, retention, backups, sign-in, the incident engine | **More → Administration → Settings** |
| Add people, give them a role (Viewer, Analyst, Lead, Administrator), reset a password | **More → Administration → Users and roles** |
| See whether data is arriving | **More → System health** |
| Work incidents | **Today**, **Incidents**, **Search**, **Reports** ([guide](docs/web-ui-guide.md)) |

A few jobs stay on the server on purpose: upgrading ([docs/upgrading.md](docs/upgrading.md)),
the AI providers' keys (below), importing the asset map file, restoring a backup, and recovery
when the web itself is down (`uv run argus doctor`).

### AI keys (optional)

ARGUS works without any model. To let its AI investigator help, put the keys in a private file
and give its path in `config/llm.local.yaml`:

```bash
install -m 600 /dev/null ~/llm-keys.env          # then paste NAME=value lines into it:
# GROQ_API_KEY=...  OPENROUTER_API_KEY=...  GEMINI_API_KEY=...  OPENAI_API_KEY=...  ANTHROPIC_API_KEY=...
uv run argus assets import asset_map.yaml        # your networks: needed before any key
uv run argus init                                # step 7: give ~/llm-keys.env
uv run argus llm probe && uv run argus llm ping
```

Where to get each key, step by step: [docs/llm.md](docs/llm.md#3-getting-each-key-step-by-step).

## Usage

People use ARGUS from the browser; the command line is for the server-side jobs above and for
recovery.

| # | Interface | For | Needs a terminal? |
|---|---|---|---|
| 1 | **The web app** (`argus-web`, [guide](docs/web-ui-guide.md)) | everyone: incidents, cases, reports, approvals; administrators: settings, users and roles | no |
| 2 | **Kibana** ([integration](docs/kibana.md)) | the read-back of cases; the case team's posts (off by default) | no |
| 3 | **Command line** (`uv run argus ...`) | the server: install, upgrade, backups, recovery, kill switches | yes |

| Service | What it does |
|---|---|
| `argus-collector` | probes the SIEM's health and takes in new alerts every minute, reconciles hourly |
| `argus-worker` | gathers the evidence and writes a dossier for each queued investigation |
| `argus-assess` | proposes outcomes (decision engine, then the optional AI investigator), suggests cases, writes incident reports and the weekly tuning report |
| `argus-web` | the web app and its API, over HTTPS on the address set at install (or `127.0.0.1:8765`) |
| `argus-admin` | applies the settings and first-time setup people do in the app; never reachable from the network |

For the server (every command has `--help`; day-to-day operation:
[docs/operations.md](docs/operations.md)):

```bash
uv run argus doctor                  # every part, offline, with the fix for each problem
uv run argus admin status            # the latest changes made in the app, and what became of each
uv run argus siem status             # the SIEM's health state, kill switches, today's budget
uv run argus siem stop --reason "…"  # stop every request to the SIEM at once
uv run argus backup check            # a dump and a verified restore of it
uv run argus break-glass --help      # a view-and-review account for when ELK sign-in is down
```

## Cost

The machine is the only fixed cost. Language models are optional, free tiers come first, and the
paid fallback is capped. Measured on one production installation (a university SIEM, about
12,000 alerts a day) over 14 days:

| | Calls | Cost |
|---|---:|---:|
| Free providers (Gemini 2,428 · OpenRouter 462 · Groq 252) | 3,142 | **$0.00** |
| Paid fallback (OpenAI) | 1,957 | $8.47 |
| **Total** | **5,099** | **$8.47 — about $0.60 a day** |

On its busiest days the paid fallback spent $1.10–$1.20 and stopped: the investigator may use 80 %
of the $1.50 daily cap. Why it stays cheap:

- **Deterministic code decides most of the work**: grouping, evidence, the decision engine, case
  suggestions and reports use no model.
- **One model run per pattern, not per alert.**
- **Free providers first**: 62 % of all calls cost nothing.
- **Small models by default**, medium only for items with a danger sign.
- **Hard caps**: $1.50 a day and $40 a month by default (and optionally per provider), shared out by priority, reserved before
  each call.
- **No keys, no calls: $0.** ARGUS still investigates every alert.

Prices, the budget's rules and how to choose your caps: [docs/costs.md](docs/costs.md).

## AI Providers

| Order | Provider | Cost | Key | Used for |
|---|---|---|---|---|
| 1 | [Groq](https://console.groq.com/keys) | free tier | `GROQ_API_KEY` | small calls (`gpt-oss-20b`, `gpt-oss-120b`) |
| 2 | [OpenRouter](https://openrouter.ai/settings/keys) | free models (`:free`) | `OPENROUTER_API_KEY` | any call, when its free models answer |
| 3 | [Google Gemini](https://aistudio.google.com/apikey) | free tier | `GEMINI_API_KEY` | any call (`gemini-3.5-flash-lite`) |
| 4 | [OpenAI](https://platform.openai.com/api-keys) | **paid**, prepaid credit | `OPENAI_API_KEY` | only when no free provider can answer, within the caps (`gpt-5.4-nano`, `gpt-5.4-mini`) |
| 5 | [Anthropic](https://console.anthropic.com/settings/keys) | **paid**, prepaid credit | `ANTHROPIC_API_KEY` | after OpenAI, within its own caps (`claude-haiku-5-5`, `claude-sonnet-5-5`; spoken through its own Messages API) |
| – | your own OpenAI-compatible server | your hardware | `LOCAL_LLM_API_KEY` | optional; shipped disabled |

The keys live in one `NAME=value` file (mode 600) outside the checkout, which `argus init` records
in `config/llm.local.yaml`. Before any text leaves, the **privacy layer** replaces your internal
addresses, host names, user names and domains with per-item pseudonyms, withholds every field the
data policy does not allow, and a validator checks the exact bytes. Sign-in user names and
reviewers' notes are never sent. Every provider, key and rule: [docs/llm.md](docs/llm.md); the
agents and how to change them: [docs/agents.md](docs/agents.md).

## The Case Team

ARGUS can post a confirmed incident into **Kibana Cases** as a team of seven Kibana users, so the
case's timeline shows who said what:

| Kibana user | Owns |
|---|---|
| `argus-lead` | opens the case, attaches and tags its alerts, gives the verdict last |
| `argus-evidence` | the evidence with hypotheses, the affected devices |
| `argus-visualiser` | "Incident at a glance": numbers and live Kibana charts (optional) |
| `argus-intel` | threat intel, when there is an outside answer |
| `argus-responder` | recommended actions, each with its owner |
| `argus-hunter` | KQL and ES\|QL queries to check it yourself |
| `argus-reporter` | the incident PDF, the dashboard PDF and two CSVs in the Files tab |

```bash
uv run argus case team provision                               # the plan: two roles, seven users, seven keys
uv run argus case team provision --apply --admin-user elastic  # create them (the password is asked once)
uv run argus case team preview 1 --text --requests             # exactly what would be posted
```

Posting is **off** until you switch it on; the first case waits for a person's approval of its
exact plan in the Inbox, and people answer in Kibana with a `Verdict:` comment that ARGUS reads
back. The guide: [docs/case-team.md](docs/case-team.md).

## Tech Stack

| Layer | Technology |
|---|---|
| Language and runs | Python 3.12 (typed, `mypy --strict`), [uv](https://docs.astral.sh/uv/) with a locked environment |
| API and web server | FastAPI, uvicorn, Jinja2 |
| Database | PostgreSQL 17 (Docker, pinned by digest), SQLAlchemy 2 async, psycopg 3, Alembic migrations |
| Settings and contracts | pydantic v2, pydantic-settings |
| Investigation graphs | LangGraph with Postgres checkpoints (deterministic: no model inside) |
| HTTP and logging | httpx with pinned TLS, structlog with secret redaction |
| Command line | typer |
| Reports | reportlab (PDFs), CSV |
| Security | argon2-cffi, cryptography |
| Web app | React 19, TypeScript, Vite, TanStack Router and Query, Base UI, Tailwind CSS 4 |
| Running | systemd user units, Docker compose v2 |
| Testing | pytest, Hypothesis, schemathesis, Vitest, MSW, Playwright, Stryker; a local Elasticsearch and Kibana 8.19 tier |

Details: [docs/architecture.md](docs/architecture.md#tech-stack).

## Repository Structure

```
├── src/argus/            # The package
│   ├── gateway/          #   the Elastic Gateway (budget, health, breaker, lanes, validator, Kibana lane)
│   ├── collector/        #   alerts in, backfill, reconciliation
│   ├── grouping/         #   alerts into investigations
│   ├── context/          #   evidence packs and the LangGraph evidence graph
│   ├── assess/           #   the decision engine, proposals, patterns
│   ├── agent/            #   the AI investigator: loader, registry, tool catalogue
│   ├── llm/              #   the LLM gateway, budgets and the privacy layer
│   ├── cases/            #   suggested cases, the lifecycle, known infections, the watch
│   ├── incident/         #   incident reports, the PDF, the dashboard, the CSVs
│   ├── caseteam/         #   the Kibana case team
│   ├── web/              #   the Inbox and its API (the built app in web/spa/)
│   ├── install/          #   argus init
│   ├── ops/              #   backups, purge, units, doctor checks
│   └── db/migrations/    #   Alembic migrations
├── config/               # argus.yaml (defaults), llm.yaml, the data policy, agents/*.md, actions.yaml
├── deploy/systemd/       # Unit templates, rendered per installation by `argus units install`
├── frontend/             # The React app's sources (its build is committed)
├── docs/                 # Documentation (see below); api/openapi-v1.json
├── scripts/              # Developer tools: the gate, the local Kibana tier, builds
├── tests/                # unit/, integration/, kibana/: on a made-up site, never a real SIEM
├── docker-compose.yml    # PostgreSQL (and the optional local Kibana tier for tests)
└── .env.example          # The names of the secrets (argus init writes the real .env)
```

## Documentation

| Document | Contents |
|---|---|
| [Installation](docs/install.md) | `./install.sh` and the first-time setup in the browser; then the full reference: requirements, Docker and uv per distribution, the SIEM's API keys, installing from the terminal (`argus init`, scripted), TLS, verification |
| [Features](docs/features.md) | Everything ARGUS can do, area by area, with what is on and off by default |
| [Configuration](docs/configuration.md) | Where every value lives, the files and their precedence, the site, every section of `config/argus.yaml`, the load budget |
| [Architecture](docs/architecture.md) | The pipeline, the Elastic Gateway, the privacy layer, the database, the services, the tech stack |
| [AI providers and keys](docs/llm.md) | Each provider, how to get its key, where it goes, the routing rules, the caps, the privacy layer, the asset map |
| [Costs](docs/costs.md) | Measured spending, model prices, the budget's rules, choosing caps |
| [The investigation agents](docs/agents.md) | The investigator and its specialists, their tools, how to change or add one |
| [The case team](docs/case-team.md) | The seven Kibana users, provisioning, switching posting on, the canary, the read-back |
| [Operations](docs/operations.md) | Services and timers, `argus doctor`, logs, backups, retention, kill switches, key rotation, certificates |
| [Web UI Guide](docs/web-ui-guide.md) | Sign-in, every page, approvals, Settings, Users and roles, ELK sign-in |
| [Reviewers' guide](docs/guide-ta-ra.md) | One page for the people who review alerts every day |
| [Kibana integration](docs/kibana.md) | The reader key, the read-back, the self-test, write classes (off by default) |
| [Upgrading](docs/upgrading.md) | A verified backup, migrate, reinstall the units, restart; rolling back |
| [Troubleshooting](docs/troubleshooting.md) | Real messages and their fixes |
| [Development & Testing](docs/development.md) | The test profiles, the network guard, the Kibana tier, migrations, the web app |
| [Roadmap](docs/roadmap.md) | What exists, what is off by default, what is planned |

## TLSOC Ecosystem

ARGUS is one component of the TLSOC Ecosystem, an open-source security operations platform:

| Repository | Purpose |
|---|---|
| [TLSOC Ecosystem](https://github.com/sankettaware16/tlsoc) | Ecosystem home: documentation, architecture, roadmap |
| [foss-soc-engine](https://github.com/sankettaware16/foss-soc-engine) | Log parsing and ECS normalisation engine |
| [TLSOCDockerDeploy](https://github.com/sankettaware16/TLSOCDockerDeploy) | TLS-secured core stack: Kafka, Logstash, Elasticsearch, Kibana |
| [TLSOC-Dashboards](https://github.com/sankettaware16/TLSOC-Dashboards) | SOC platform: a fork of OpenSearch Dashboards |
| [tlsoc-reporting-framework](https://github.com/sankettaware16/tlsoc-reporting-framework) | Declarative executive reporting (HTML/PDF) |
| **argus** (this repository) | The always-on first-line analyst for Elastic SIEM |

ARGUS needs none of the others: it works with any Elastic SIEM.

## Roadmap

Highlights; the full list is in [docs/roadmap.md](docs/roadmap.md):

- The deterministic investigation wave and the daily case watch switched on after their load is
  measured.
- Alert status write-back to Kibana in real use, after its canary.
- A local model for helper tasks, each task only after its evaluation against the gold set.

## Contributing

Bug reports, fixes, documentation and features are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md)
and [docs/development.md](docs/development.md). Every change runs the test suite on a made-up
site; the suite never leaves the machine. Please follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md), never in a public
issue.

## License

Free and open-source software under the [Apache License 2.0](LICENSE).

---

<p align="center">
  Part of the <a href="https://github.com/sankettaware16/tlsoc">TLSOC Ecosystem</a>
</p>

<p align="center">
  <a href="https://github.com/sankettaware16/tlsoc">Ecosystem</a> •
  <a href="https://github.com/sankettaware16/foss-soc-engine">Engine</a> •
  <a href="https://github.com/sankettaware16/TLSOCDockerDeploy">Deploy</a> •
  <a href="https://github.com/sankettaware16/TLSOC-Dashboards">Dashboards</a> •
  <a href="https://github.com/sankettaware16/tlsoc-reporting-framework">Reporting</a> •
  <a href="https://github.com/sankettaware16/argus">ARGUS</a>
</p>
