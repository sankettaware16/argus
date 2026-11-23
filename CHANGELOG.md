# Changelog

All notable changes to ARGUS are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this repository adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

Versions 0.3.0, 0.3.1 and 0.3.2 were published on 17 November 2026 and withdrawn the same day:
the first-time setup failed on a self-managed Elastic stack. Their changes are listed here, and
the next release is 0.4.0. Until it is tagged, `main` reports `0.4.0.dev0`.

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
- **The first-time setup can make ARGUS's own access:** an Elastic administrator's login, used
  once and never stored, makes ARGUS's read-only Elasticsearch and Kibana keys and, if ticked,
  ARGUS's Kibana case team; the setup also takes the AI and threat-intel keys and the asset map.
  Pasting read-only keys by hand stays possible.
- **A new look for the welcome, sign-in and first-time setup pages,** one question per screen.
- **Costs and usage is live:** 7 or 31 days, tooltips and keyboard reading, providers shown or
  hidden from the legend, a trend against the previous week, the month's projection against the
  cap, a refresh every minute.
- **Services and timers** switched on or off, and services restarted, from System health.
- **ARGUS's team** (the investigation agents and the Kibana case team) shown as the default pack.
- **[docs/compatibility.md](docs/compatibility.md):** ARGUS works with any Elastic SIEM on its own,
  any licence including the free Basic, measured on Basic and on a trial licence.
- New screenshots of the current app, made from synthetic demo data.

- **Alerts** (the menu's third entry): every alert group, newest first, with the incident it
  belongs to; the ones in an incident and the ones in none are one click apart, and the
  list narrows to one rule. An alert group's page leads back to its incident.
- **Dashboards**: four ready-made boards. *Security overview*: the alerts over time, how far
  ARGUS narrows them down, the most active devices and outside addresses, what waits for a
  person, and the **response times** (mean time to detect, to a person's first decision and to
  close; the share decided and closed within targets by priority; what is past its time now).
  *Detections*: every rule that fired, the loud ones that never found anything, the ones that
  did. *ARGUS operations*: what it takes in and handles alone. *Costs* (administrators): the
  AI's spend against its caps and where the month is heading, by day, provider and task, and
  the threat-intel lookups against their limits. Charts are read by pointing, with the arrow
  keys or as a table; most figures open the list behind them.
- **Response-time targets** as settings (`sla.triage_p1` … `sla.resolve_p4`, Settings ›
  Response times): how long a person has to decide and to close an incident, by priority.
- `GET /api/v1/performance`, and `incident=in|none` and each row's incident on
  `GET /api/v1/investigations`.
- **Who used a device, on the incident itself:** the Overview and Entities tabs name the
  accounts that signed in from each of your devices in the incident, from the sign-in logs ARGUS
  already reads.
- **Your own account directory (optional):** name a provider in `directory.provider` and ARGUS
  asks your organisation's own system who an account belongs to (the name, the kind of account,
  the department): a card on the incident and on the account's page, and an *Account look-up*
  page. The answer is shown only to people who may see account names, kept in memory for
  `directory.cache_window`, and never stored, reported or sent to a model. ARGUS ships the
  hook and no provider; without one the feature is off.
- **A person's decision reaches Kibana's alerts by itself** (off by default): a dismissed
  possible incident closes its alerts; with `writeback.own_accounts` a review made in one of
  ARGUS's own accounts needs no operator; with `writeback.auto`, `argus-writeback.timer` plans
  and sends every 10 minutes, once a person has made the first run at a terminal
  ([runbook](docs/runbooks/writeback.md)).

### Changed

- **The menu** shows what is used: Today, Incidents, Alerts, Dashboards, Search, Reports, then
  the work, health and administration pages, each with a glyph; More holds only what is opened
  rarely. Costs and usage is the dashboards' Costs board (`/costs` leads there).
- **No word of the first installation in what ARGUS says.** The incident pages ("Your side",
  or your own word: "Plant side"), the evidence sentences, the action catalogue and the AI
  agents' instructions now take every word about your organisation from your settings
  (`site.own_network_noun`, `site.organisation.kind`, `site.organisation.reviewers`). The agents
  no longer tell a model it reads "a university network": they say what kind of organisation
  yours is. New agent versions: coordinator@5, specialist@2 and @3, responder@2, reporter@2.
- **Renamed, the older names still read:** a self-hosted model's `trust: campus` is
  `trust: self_hosted`; `campus_domains` and `campus_replacement` in
  `config/llm_data_policy.yaml` and `config/fixtures.yaml` are `own_domains` and
  `own_replacement`. A file that has both the new and the older name is refused.
- **Renamed, not compatible:** the block list's API fields and CSV columns
  `first_seen_on_campus` and `campus_devices` are `first_seen_on_own_network` and
  `own_devices`. The role "Analyst (TA/RA)" is "Analyst".
- `docs/guide-ta-ra.md` is `docs/guide-reviewers.md`.
- CI runs the integration suite on PostgreSQL, the Kibana contract tests, the frontend's
  types, lint, tests and build, and a dependency audit on every push; mutation testing on request.
- `docs/decisions.md` lists every design decision the code and the tests cite by number.
- Own domains refuse a public suffix (`in`, `ac.in`, `co.uk`): each entry is a whole domain and
  covers its subdomains.

### Fixed

- The times on an entity's page and in the CISO draft were labelled "IST" whatever the site's
  time zone; they carry the site's label now.
- The comparison arms of the model evaluation recognised one of your public addresses only on a
  site whose word for its network was "campus".

- **Running `./install.sh` again after `git pull` now restarts the web and `argus-admin`,** so they
  run the new code at once (before, they kept the version they started with until a reboot).
- **A CA certificate on the ARGUS server:** when Elastic runs on the same machine, the setup takes
  the path of its CA file (for example `/opt/<stack>/certs/ca/ca.crt`) beside an upload or pasted
  text.
- **`./install.sh` asks nothing and needs no preparation:** it installs uv itself when it is
  missing, says exactly how to fix a missing Docker or a missing `docker` group, keeps the
  services running after logout where the machine allows it, makes the web's certificate for this
  machine's address, and ends with the one-time link. It no longer asks for a first account (the
  link makes the administrator) or points at commands outside the checkout.
- **The first-time setup opens by itself** after the first sign-in; the header shows "Setting up"
  instead of a red problem until the SIEM is connected.
- **A SIEM that sends only its own certificate** (common on self-managed Elastic): the setup
  recognises it, asks for the CA certificate as an upload or pasted text, and trusts that CA.
- **An address typed with a trailing slash** (`https://host:9200/`) is accepted.
- "Back to fix" after a failed setup opens the chapter the error is about.

### Removed

- **The classic server-rendered pages.** Every address they had (links in Kibana cases
  included) leads to the same thing in the app; their forms answer 410. `web.classic` is accepted
  and ignored, with a note from `argus doctor`.

## [0.2.0] — 2026-11-07

### Added

- **An incident engine:** every alert group and evidence fact becomes a scored observation on a
  device, account or site of your own; observations add up per object (each source once per window,
  noisy sources scaled down, stages counted so one rule cannot fake progression); five lanes
  decide what a person sees; a linker joins objects across rules, days and log families into one
  incident (hubs never link, size caps, a reason sentence per link); a lifecycle re-queues only on
  a material change; priority P1–P4 with a "why" line, checks and ruled-out explanations; a
  capacity governor; a "handled by ARGUS" digest. Runs in shadow until `risk.present` is on, from
  its own timer (`argus-risk.timer`), and replays over stored history (`argus risk`).
- **Exposure checks:** for inbound attacks your own site is the thing at risk; a capped checking
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
