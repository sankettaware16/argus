# Changelog

All notable changes to ARGUS are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this repository adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **One command, then the browser:** `./install.sh` installs the packages, the database, the
  web's certificate and two services, and prints a one-time link (72 hours) for the first
  administrator. Running it again prints a new link if the first one was never used.
- **First-time setup in the app:** your organisation, Elasticsearch (its certificate shown to
  compare and trust, a read-only key) and optionally Kibana; ARGUS then discovers your log
  families, writes its configuration and starts every service.
- **Settings in the app:** every setting with its help, grouped by subject. A change is checked
  again and applied by a new service, `argus-admin`, which restarts only the services that read
  it and puts the old configuration back if one does not come back. Keys are sealed for
  `argus-admin` alone and never shown again. A key or an address needs the administrator's
  password again; anything that writes to the SIEM also needs a typed confirmation. The SIEM load
  budget is shown, not editable. App-made changes land in `config/admin.yaml` unless the setting
  already lives in another file.
- **Users and roles in the app:** Viewer, Analyst, Lead and Administrator, or a custom set of
  capabilities; a new person or a forgotten password gets a one-time link to choose a password
  (`/welcome`); switch an account off, end its sessions. The database itself checks the
  administrator's session and recent password confirmation for each of these.
- **AI and agents in the app:** each AI provider's keys (added in the app, sealed, written to
  the keys file by `argus-admin`; a new installation gets `local/llm-keys.env`), its on/off switch,
  a Test (its model list, no prompt), its own and the overall monthly and daily spending limits,
  each AI task's calls a day, providers and model size, and **Stop all AI calls**. The agents
  are listed with what each does, its model size, tools, triggers, version and whether it runs.
  App-made changes land in `config/llm.admin.yaml`.
- **Threat intel in the app:** VirusTotal, Shodan and Censys keys added and tested (one lookup of
  a public test address, counted under each free plan's limits), with each plan's limits and use.
- **Costs and usage:** the AI's spend a day by provider for 31 days and by task this month
  against the caps; each threat-intel source's lookups a day against its daily limit.
- **More in Settings:** check the SIEM's and each Kibana key's connection and privileges, upload
  the asset map (imported and the services restarted), and the history of the last fifty changes.
- **Everyone is told** when the first-time setup is still pending.
- New screenshots of the current app, made from synthetic demo data.

### Removed

- **The classic server-rendered pages.** Every address they had (links in Kibana cases
  included) leads to the same thing in the app; their forms answer 410. `web.classic` is accepted
  and ignored, with a note from `argus doctor`.

## [0.2.0] — 2026-11-07

### Added

- **An incident engine:** every alert group and evidence fact becomes a scored observation on a
  campus device, account or site; observations add up per object (each source once per window,
  noisy sources scaled down, stages counted so one rule cannot fake progression); five lanes
  decide what a person sees; a linker joins objects across rules, days and log families into one
  incident (hubs never link, size caps, a reason sentence per link); a lifecycle re-queues only on
  a material change; priority P1–P4 with a "why" line, checks and ruled-out explanations; a
  capacity governor; a "handled by ARGUS" digest. Runs in shadow until `risk.present` is on, from
  its own timer (`argus-risk.timer`), and replays over stored history (`argus risk`).
- **Exposure checks:** for inbound attacks the campus site is the thing at risk; a capped checking
  lane (10 minutes of SIEM time a day, normal health only) verifies whether a probe was really
  served or answered by a not-found page.
- **The analyst UI, rebuilt:** Today · Incidents · Search · Reports, a queue with a preview pane, a
  sticky decision bar (confirm, not an incident with a reason, merge, hold), entity pages,
  keyboard shortcuts, the incident's glance charts on its own page.
- **Accurate titles:** certainty, activity, target, actors, place and outcome, each from a fact; a
  checker refuses a title with an unbacked claim.
- **Anthropic** as a paid provider through its own Messages API (structured outputs, refusals and
  credit limits handled), and per-provider daily and monthly caps.

### Changed

- Paid providers: OpenAI first, then Anthropic; an OpenAI-compatible 404 raises a model alarm.
- The Visualiser's charts: empty days drawn as gaps, one source for every count, one living glance
  comment edited in place.

### Fixed

- A suspected case can be confirmed, dismissed or merged in the web (no command line needed).
- `argus init` repairs the case team's database login; doctor reports a failed enabled timer.

## [0.1.0] — 2026-11-03

First public release.

### Added

- **Always-on alert intake** from Kibana's Security app (detection alerts of one
  space), stored durably with an idempotent cursor: nothing is lost between
  reviews.
- **Grouping and investigation:** repeated alerts become one investigation;
  evidence packs ask the log indices bounded, read-only questions and write a
  dossier with every source named.
- **Deterministic assessment** of every investigation, with an optional LLM
  agent (Groq, OpenRouter, Gemini, OpenAI; free providers first, daily and
  monthly caps) for what rules cannot decide. Internal names and addresses are
  pseudonymised before any cloud call; without model keys ARGUS runs fully
  deterministically.
- **A web Inbox** for reviewers: cases, investigations, evidence, approvals,
  daily and weekly reports.
- **SIEM protection:** every read goes through a gateway with a daily load
  budget, health states (slow down, then stop, when the cluster is busy),
  quiet hours, kill switches and a circuit breaker. Kibana writes are off until
  an operator switches them on.
- **`argus init`:** a one-command installer (prerequisites, `.env` with
  generated passwords, PostgreSQL in Docker, certificate trust, read-only key
  checks, organisation and discovery, systemd user units, doctor), interactive
  or scripted with `--answers`.
- **`argus discover`:** proposes the site's log families, threat-intel sources
  and Kibana space from read-only metadata requests.
- **`argus doctor`:** a health check of every part, each problem with its fix.
- **Backups:** `argus backup dump|drill|check|list|prune` with restore drills
  that compare every table's fingerprint.
