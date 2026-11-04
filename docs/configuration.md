# Configuration

Reference for every file ARGUS reads, the order in which they win, and the settings an operator
is likely to change. The authoritative list, with every bound, is the settings code:
[`src/argus/config/settings.py`](../src/argus/config/settings.py) and
[`src/argus/site.py`](../src/argus/site.py) (each setting has a docstring).

**Contents**

- [Where every value lives](#where-every-value-lives): one table, value by value
- [The files](#the-files)
- [Precedence](#precedence)
- [Environment variables](#environment-variables)
- [Inspecting and validating](#inspecting-and-validating)
- [The site (`config/site.yaml`)](#the-site-configsiteyaml)
- [`config/argus.yaml`, section by section](#configargusyaml-section-by-section)
- [The load budget and health states](#the-load-budget)
- [Kibana and its write classes](#kibana-and-its-write-classes)
- [The web](#the-web)
- [Units](#units)
- [The case team (`case_team`)](#the-case-team-case_team)
- [The LLM gateway (`config/llm.yaml`)](#the-llm-gateway-configllmyaml)
- [Other sections](#other-sections)

---

## Where every value lives

Every value an operator gives ARGUS, where it goes, who puts it there, and whether ARGUS needs it.
**Secrets** go only in `.env`, the LLM keys file, or a credential folder, never in YAML.

| Value | Setting or name | File | Set by | Required? |
|---|---|---|---|---|
| Database passwords (owner, runtime, web) | `ARGUS_DATABASE__OWNER_PASSWORD`, `ARGUS_DATABASE__PASSWORD`, `ARGUS_DATABASE__API_PASSWORD` | `.env` | `argus init` (generated) | yes |
| Database host, port, name, users | `ARGUS_DATABASE__HOST`, `__PORT`, `__NAME`, `__USER`, `__OWNER_USER` | `.env` | `argus init` | yes |
| Elasticsearch's address | `siem.url` | `config/local.yaml` | `argus init` step 4 | yes |
| The SIEM's pinned CA | `siem.ca_file` (`data/certs/siem-ca.crt`) | `config/local.yaml`; the certificate in `data/certs/` | `argus init` step 4 | yes |
| The read-only Elasticsearch key | `ARGUS_SIEM__API_KEY` | `.env` | `argus init` step 5 | yes |
| Its expiry date | `siem.api_key_expires` | `config/local.yaml` | `argus init` step 5 | recommended (doctor warns 30 days ahead) |
| Kibana's address and CA | `kibana.url`, `kibana.ca_file`, `kibana.enabled` | `config/local.yaml` | `argus init` step 4 | optional |
| Kibana's reader key, its expiry | `ARGUS_KIBANA__READER_API_KEY`; `kibana.reader_api_key_expires` | `.env`; `config/local.yaml` | `argus init` step 5 | optional |
| Organisation, team name, kind | `site.organisation.name`, `.short_name`, `.kind` | `config/site.yaml` | `argus init` step 6 | yes |
| Own domains | `site.own_domains` | `config/site.yaml` | `argus init` step 6 | yes (at least one) |
| Own public networks | `site.own_networks` | `config/site.yaml` | `argus init` step 6 | optional |
| Time zone and its label | `site.timezone`, `site.timezone_label` | `config/site.yaml` | `argus init` step 6 | yes (choose once) |
| Incident id prefix | `site.incident_id_prefix` | `config/site.yaml` | `argus init` step 6 | yes |
| Log families, space, threat-intel sources, versions | `site.families`, `site.space`, `site.ti_sources`, `site.kibana_features` | `config/site.yaml` | `argus discover` (init step 6), you | yes (families, space) |
| Quiet hours | `site.quiet_hours` | `config/site.yaml` | you | optional (00:00–01:30 UTC) |
| History depth | `history.window` | `config/local.yaml` | you | optional (`5d`) |
| The LLM keys file's path | `keys_file` | `config/llm.local.yaml` | `argus init` step 7 | optional |
| The model keys | `GROQ_API_KEY`, `OPENROUTER_API_KEY`, `GEMINI_API_KEY`, `OPENAI_API_KEY`, ... | your keys file (mode 600) | you ([llm.md](llm.md#4-where-the-keys-go)) | optional |
| Cost caps | `daily_cap_usd`, `monthly_cap_usd`, `shares`, `margin` | `config/llm.yaml` | you, in a local commit | optional ($1.50 / $40) |
| The asset map | `assets.map_path` (`data/assets/asset_map.yaml`) | the map itself | `argus assets import` | required before any model or outside key |
| Outside threat-intel keys | `ARGUS_OUTSIDE__VIRUSTOTAL_API_KEY`, `..._SHODAN_API_KEY`, `..._CENSYS_API_KEY` | `.env` | you | optional |
| Your DNS resolvers | `campaigns.resolvers` | `config/local.yaml` | you | recommended |
| The services to run | `units.run` | `config/local.yaml` | `argus init --start`, you | yes, once started |
| The web on the network | `units.web.host`, `tls_cert`, `tls_key`, `allowed_hosts`, `allowed_networks`, `public_url` | `config/local.yaml` | you | optional (loopback by default) |
| The address in permanent links | `web.public_url` | `config/local.yaml` | you | needed by notices and the case team |
| The approval key | `web.approval_key_file` (`data/keys/approval-signing.key`) | `config/local.yaml`; the key in `data/keys/` | `argus approvals keygen`, you | needed to record approvals |
| ELK sign-in | `web.elk_signin`, `web.secret_file` | `config/local.yaml`; `data/keys/web-secret` | `argus sessions keygen`, you | optional |
| E-mail notices | `ARGUS_NOTICES__ENABLED`, `__RELAY_HOST`, `__RELAY_FROM`, `__RECIPIENTS`, `__WEB_URL`, `__USER`, `__PASSWORD` | `.env` | you | optional |
| The case team's keys | `case_team.<agent>_api_key` | `local/creds-writer/case_team.<agent>_api_key` (credential files, mode 600) | `argus case team provision` | only for the case team |
| The case team's switches | `ARGUS_KIBANA__WRITE_CLASSES=WC`, `ARGUS_CASE_TEAM__POST=true` | `local/argus-writer.env` | you | only for the case team |
| The writer's database login | `database.writer_password` | `local/creds-writer/database.writer_password` | you | only for Kibana writes |

## The files

| File | Tracked in git | Who writes it | What it holds |
|---|---|---|---|
| `config/argus.yaml` | yes | the project | Neutral defaults, with comments. **Leave it as shipped**: put your changes in `config/local.yaml`, so `git pull` never conflicts. |
| `config/site.yaml` | no | `argus init` / `argus discover --write` | The `site` section only: your organisation and its Elastic (log families, space, threat intel, time zone, domains, networks, quiet hours). |
| `config/local.yaml` | no | `argus init`, then you | This installation's own values: the SIEM's and Kibana's addresses and CA files, the keys' expiry dates, `units`, and any setting you change. Any section may be in it. |
| `config/llm.yaml` | yes | the project | The LLM providers, their models, limits and the cost caps ([llm.md](llm.md)). |
| `config/llm.local.yaml` | no | `argus init` | Laid over `llm.yaml`; may set `keys_file` only. |
| `config/llm_data_policy.yaml` | yes | the project | What a model may see of a dossier ([llm.md](llm.md#9-the-privacy-layer)). |
| `config/grouping.yaml` | yes | you, rarely | The group-key fields of rules that declare none ([architecture.md](architecture.md#2-group)). |
| `.env` | no | `argus init` | **Secrets only**: database passwords, the API keys. Mode 600. Shared with docker compose. |

Never put a secret in a YAML file: secrets are `.env` (or the environment) only.

## Precedence

Highest first:

1. Values a command passes itself (overrides)
2. A systemd credential directory (`CREDENTIALS_DIRECTORY`), secret settings only
3. The process environment (`ARGUS_...` variables)
4. `.env`
5. `config/local.yaml`
6. `config/argus.yaml` (or the file `--config` / `ARGUS_CONFIG` names)
7. `config/site.yaml` (the `site` section only)
8. The defaults in code

`config/local.yaml` and `config/site.yaml` are read from the folder of the config file in use.
Sections merge key by key: a `local.yaml` that sets `siem: {url: ...}` keeps `siem.budget` from
the files below it.

**Unknown names are errors**, in every file and in the environment: a misspelled setting stops
ARGUS with the setting's name and where it was set, instead of being ignored.

```
invalid configuration (config/argus.yaml, environment and .env):
  - siem.budjet: unknown setting (check the spelling); did you mean budget? [local.yaml line 4]
```

## Environment variables

Every setting can be set as `ARGUS_<SECTION>__<KEY>`, with `__` for each level of nesting:

```bash
ARGUS_HISTORY__WINDOW=7d
ARGUS_SIEM__BUDGET__TOOK_PER_DAY_MS=1800000
ARGUS_WEB__PORT=8766
ARGUS_WEB__ALLOWED_HOSTS=argus.example.org,argus          # lists: comma-separated
ARGUS_SITE__OWN_DOMAINS=example.org,example.net
```

The database connection lives only in `.env` (docker compose reads the same file):
`ARGUS_DATABASE__HOST`, `__PORT`, `__NAME`, `__USER`, `__PASSWORD`, `__OWNER_USER`,
`__OWNER_PASSWORD`, `__API_PASSWORD`. Three compose variables without the `ARGUS_` prefix may
also be in `.env`: `COMPOSE_PROJECT_NAME`, `COMPOSE_DB_CONTAINER` (see
[install.md](install.md#10-a-second-argus-on-the-same-machine)) and `REPLICA_ELASTIC_PASSWORD`.

The secrets ARGUS reads:

| Variable | What |
|---|---|
| `ARGUS_DATABASE__OWNER_PASSWORD` | The schema owner (migrations, backups, purge, resuming a kill switch) |
| `ARGUS_DATABASE__PASSWORD` | The runtime login every service uses |
| `ARGUS_DATABASE__API_PASSWORD` | The web's own login (`web.database_role: api`) |
| `ARGUS_SIEM__API_KEY` | The read-only Elasticsearch key |
| `ARGUS_KIBANA__READER_API_KEY` | Kibana's Cases-read key |
| `ARGUS_OUTSIDE__VIRUSTOTAL_API_KEY`, `..._SHODAN_API_KEY`, `..._CENSYS_API_KEY` | Optional outside threat intel ([below](#outside)) |
| `ARGUS_NOTICES__PASSWORD` | Optional: the e-mail relay's login ([below](#notices)) |

The LLM providers' keys are not settings: they live in the keys file named by
`config/llm.local.yaml` ([llm.md](llm.md)).

## Inspecting and validating

```bash
uv run argus config show          # the effective configuration, secrets masked
uv run argus config validate      # exit 2 if invalid, with every problem listed
uv run argus doctor               # the configuration plus every other part
```

Restart the services after a change (`systemctl --user restart argus-collector argus-worker
argus-web argus-assess`): each reads its settings when it starts.

---

## The site (`config/site.yaml`)

Everything about your organisation's Elastic that is not code. `argus discover` proposes it;
you may edit it by hand.

```yaml
site:
  space: security                       # the Kibana space of the Security alerts
  # alerts_index: .alerts-security.alerts-{space}    # the default
  elastic_versions: ">=8.0,<10"
  kibana_versions: ">=8.0,<10"
  log_patterns: [logs-*]                # optional: one wider pattern the key is granted
  families:
    - name: proxy
      role: proxy
      pattern: logs-squid-*             # ends in '*': daily indices <prefix>YYYY.MM.DD
      fields:
        url: url.original.keyword
    - name: dns
      role: dns
      pattern: logs-dns-*
    - name: nginx
      role: web
      pattern: logs-nginx-*
      fields:
        domain: url.domain.keyword
    - name: sso
      role: auth
      pattern: logs-sso-*
      watch: false                      # read, but not watched by the health probe
  ti_sources:
    - {index: logs-ti_*, schema: ecs, mode: lookup}
  own_domains: [example.org, example.net]
  own_networks: [192.0.2.0/24]
  own_network_noun: your network
  timezone: Europe/Berlin
  timezone_label: CET
  incident_id_prefix: SOC-IR
  quiet_hours: {start: "00:00", end: "01:30"}
  organisation:
    name: Example Corp
    short_name: Example SOC
    kind: company
    units: department, team or lab
    reviewers: analysts
```

| Setting | Default | Meaning |
|---|---|---|
| `families` | none | The log indices ARGUS may read. Each has a `role` (`proxy`, `web`, `dns`, `auth`, `mail`, `other`: the evidence modules pick their family by role), a `pattern` (ending in `*`: daily indices `<prefix>YYYY.MM.DD`; without `*`: one data stream or alias), an optional `name` (the source key in stored evidence; default the role), `time_field` (default `@timestamp`), `fields` (the field names the evidence queries use, by field role, where they differ from ECS), `watch` (false: read, but not watched by the health probe and freshness), `types` (a field's mapping type where it is not the role's default) and `ignore_above` (keyword fields' limit, default 256). |
| `space` | `default` | The Kibana space that holds the Security alerts (lowercase letters, digits, `_`, `-`). |
| `alerts_index` | `.alerts-security.alerts-{space}` | The space's alerts alias. |
| `log_patterns` | each family's own pattern | The patterns the self-test and the `see_logs` capability check `read` on. Give one wider pattern when that is what the key is granted. |
| `ti_sources` | none | Up to 8 threat-intel sources, each `{index, schema, mode}`. `schema: ecs` is ECS `threat.indicator.*` (what Elastic's Threat Intel integration writes); `schema: ioc` is `ioc_type` / `ioc_value` / `intel_source` rows. `mode: mirror` reads the whole (small) index into ARGUS's store every 6 hours; `mode: lookup` asks for the values an investigation needs, cached for a day. None: threat intel is off and ARGUS says so wherever it reports intel. |
| `elastic_versions`, `kibana_versions` | `>=8.0,<10` | The versions ARGUS runs against / writes to (comparators joined by commas: `>=8.0,<10`, `==8.19.12`, `*`). The self-test refuses others. Pin Kibana to the version its writes were tested on. |
| `kibana_features` | `{security: siemV2, cases: securitySolutionCasesV3}` | Kibana's Security and Cases feature ids (they change between versions); discovery reads them. |
| `own_domains` | none | Domain suffixes that are the organisation's own. The privacy layer pseudonymises them; case titles recognise them. **At least one** before any model is used. |
| `own_networks` | none | The organisation's public networks (CIDR). Private ranges are always its own. |
| `own_network_noun` | `your network` | The word for your network in the pages' sentences (`the plant`, `campus`). |
| `timezone` | `UTC` | The IANA zone people read times and days in. **Also the zone of the investigation day**: investigation ids depend on it. Choose it before the first alert is stored; changing it later starts new investigations at the new day boundary. |
| `timezone_label` | none | How a time in that zone is labelled (`CET`). Left out: the offset (`UTC+01:00`). |
| `incident_id_prefix` | `IR` | Incident case ids are `<prefix>-YYYY-MMDD-NN` (capital letters, digits, `-`; at most 16 characters). |
| `quiet_hours` | `00:00`–`01:30` | A daily UTC window in which ARGUS asks the SIEM for nothing optional (the time your cluster creates the day's indices and deletes old ones). Write the times in quotes (`"22:00"`). `start` equal to `end` is no window; a window may cross midnight. |
| `organisation` | | `name` (default "your organisation"), `short_name` (the security team; page header and PDF footer; default `SOC`), `kind` (a lower-case noun; default `organisation`), `units` (who an owner may be told through; default "department, team or lab"), `reviewers` (who reads the reports; default "analysts"). |

Field roles a family's `fields` may name: **proxy** `client_ip server_ip server_port bytes url
method status_code action`; **web** `client_ip domain url_path method status_code bytes
user_agent`; **dns** `client_ip client_ip_alt query_name query_type response_code`; **auth**
`client_ip user_name action outcome user_agent`. A role left out uses its ECS name; a text field
with a keyword sub-field is written with the suffix (`url.domain.keyword`).

After editing the site, check it and narrow the key to it:

```bash
uv run argus config validate
uv run argus siem selftest            # the key must read every family and source
uv run argus init --force-key         # prints the exact key for the new site, asks for it
```

---

## `config/argus.yaml`, section by section

The values below are the shipped ones (`config/argus.yaml`), which in a few places differ from
the code's own defaults. Set any of them in `config/local.yaml`.

### environment

`environment: dev` — one of `dev`, `test`, `prod`; shown by doctor.

### history

| Setting | Shipped | Range | Meaning |
|---|---|---|---|
| `history.window` | `5d` | `1h`–`365d` | **The single knob for history depth**: how far back the collector backfills, and how far back each investigation looks at an entity's history. Keep it at or below your SIEM's log retention (its ILM policy). |

Durations are written `30s`, `15m`, `36h`, `5d`.

### memory

| Setting | Shipped | Meaning |
|---|---|---|
| `memory.window` | `90d` | How long ARGUS keeps alerts, investigations and their history locally. Older ones are removed by the retention purge unless held. Never shorter than `history.window` in effect. |

### retention

What the purge removes, and when ([operations.md](operations.md#retention-and-the-purge)):

| Setting | Shipped | Meaning |
|---|---|---|
| `retention.raw_source` | `30d` | An alert's raw `_source` (its normalized form stays until `memory.window`) |
| `retention.evidence` | `90d` | Evidence snapshots (log rows a query returned), from the investigation's newest review |
| `retention.quarantine` | `30d` | A quarantined alert's raw `_source` |
| `retention.app_logs` | `14d` | ARGUS's own logs: they go to the systemd journal; this is reported, the journal's own settings enforce it |
| `retention.scheduled` | `false` | Whether the scheduled purge (`argus-purge.timer`) may delete. Off until you decide. |

Each period is at least `history.window` in effect.

### database

`pool_size` (5), `max_overflow` (5), `connect_timeout` (5s), `statement_timeout` (30s). The
connection itself is `.env` only ([above](#environment-variables)).

### logging

`level` (`INFO`; `DEBUG`, `WARNING`, `ERROR`), `format` (`console` for people, `json` for log
shippers). Logs go to stdout and so to the systemd journal; secrets are redacted.

### assets

`assets.map_path` (default `data/assets/asset_map.yaml`): where `argus assets import` installs
your asset map ([llm.md](llm.md#10-the-asset-map)). `assets.campus_prefixes` is the older name of
`site.own_networks`; set the latter.

### siem

Set in `config/local.yaml` by `argus init`:

| Setting | Meaning |
|---|---|
| `siem.url` | Elasticsearch's address, `https://host[:port]` (no default: ARGUS sends nothing without one) |
| `siem.ca_file` | The pinned CA (default `data/certs/siem-ca.crt`) |
| `siem.api_key_expires` | The key's expiry date; doctor warns 30 days ahead |
| `siem.budget.*` | [The load budget](#the-load-budget) |
| `siem.health.*` | [The health thresholds](#health-states) |
| `siem.lanes.*` | Per-lane allowances (advanced) |

The key itself is `ARGUS_SIEM__API_KEY` in `.env`.

### reference and enrichment

| Setting | Shipped | Meaning |
|---|---|---|
| `reference.ti_sync` | `true` | Sync the site's `mirror` threat-intel sources every 6 hours; `lookup` sources are asked as investigations need them |
| `enrichment.log_queries` | `true` | The web follow-up search: did an attacker get a successful answer afterwards |
| `enrichment.proxy_aggregations` | `true` | The proxy aggregations: what a host reached, and whether it repeats like a beacon |
| `enrichment.templates` | none | Further evidence templates, each switched on only after its first run passed within its limit (`argus worker template-check`) |

### investigation

`investigation.wave` (`false`): the deterministic wave. For an undecided investigation with a gap
a query could close, ARGUS asks the ranked checks (through the investigation lane: 400 ms a
minute, 6 minutes a day, NORMAL health only) before any model is asked. Its caps:
`wave_per_day` (120), `item_requests` (4), `item_heavy` (2), `item_server_ms` (4000). A person's
**Check more** in the web runs regardless.

### freshness

`freshness.mode` (`off`): watermarks of each log source, so that "nothing found" can be told from
"the logs were not there yet". `shadow` records readings without using them; `on` needs measured
`freshness.margins` per source. Leave it `off` unless you are measuring.

### cases and campaigns

| Setting | Shipped | Meaning |
|---|---|---|
| `cases.suggest` | `true` | Every 15 minutes `argus assess run` suggests cases from evidence across investigations (a campaign of devices reaching one flagged destination, a host flagged by several rules or on several days). A person confirms or dismisses each; ARGUS opens nothing. |
| `cases.offers_per_hour` | `30` | Offers of a new device's investigations to an open case, per hour |
| `cases.retitle` | `true` | Keep suggested case titles up to date with their evidence |
| `cases.watch` | `off` | The daily still-active watch of open true-positive cases: `local` (ARGUS's own alerts only) or `on` (also the proxy logs). See [the case-watch runbook](runbooks/case-watch.md). |
| `campaigns.resolvers` | `[]` | **Set this** to your recursive DNS resolvers' addresses (or networks). A resolver asks for every name its users ask for, so it would join unrelated campaigns. |

### notified

How a case whose owner was told is tracked quietly: `renotify_days` (7), `network_days` (21),
`quiet_days` (14), `active_days` (3), `move_gap` (2h), `move_window` (72h), `move_similarity`
(0.8), `volume_factor` (10), `managed_types` (asset-map `site.type` values of machines you
manage), `reopen_days` (30), `per_pass` (500). See the comments in `config/argus.yaml`.

### incident

ARGUS writes an incident report for each suggested or open case (summary, verdict, timeline,
actors, assets, evidence with the query behind each line, indicators, actions) from its own
database, as a page, a PDF and two CSVs.

| Setting | Shipped | Meaning |
|---|---|---|
| `incident.enabled` | `true` | Write the reports |
| `incident.per_pass` / `look` | `5` / `40` | Reports written / cases examined per assessment pass |
| `incident.min_interval` | `30m` | No case is rewritten sooner than this |
| `incident.prose` | `false` | Let a model word the summary from verified facts (needs an LLM key) |
| `incident.kibana_url` | `kibana.url` | The address people open Kibana at, for the evidence links |
| `incident.data_views` | none | `source=data-view-id` pairs, so a source's links open as KQL in that data view (others use ES|QL links) |

### signins

`signins.enabled` (`true`): who was behind an internal address. ARGUS reads the site's `auth`
family's sign-in logs for the addresses of its investigations (a few requests a pass) and keeps
the accounts per address and day (180 days). Usernames are shown only to people who may see logs
and are never sent to a model. Without an `auth` family it does nothing. See
[the sign-ins runbook](runbooks/signins.md).

### outside

Optional outside threat intel for **public** addresses and names only: VirusTotal (reputation),
Shodan and Censys (what a public server is). A source without a key is off; keys go in `.env`.
The rate limits default to below the free plans (`virustotal_per_minute` 3, `virustotal_per_day`
400, `shodan_per_day` 200, `censys_per_day` 10, `censys_per_month` 50; results cached 7 days, "no
record" 1 day). With no Shodan key, Shodan's free InternetDB is used (`shodan_internetdb: true`).
**An outside key needs an asset map imported first**, like a model key
([llm.md](llm.md#10-the-asset-map)).

### notices

E-mail notices that carry a link, a severity and a count (never a name). Off
(`notices.enabled: false`). The relay and recipients go in `.env`:
`ARGUS_NOTICES__ENABLED`, `ARGUS_NOTICES__RELAY_HOST`, `ARGUS_NOTICES__RELAY_PORT` (25),
`ARGUS_NOTICES__RELAY_FROM`, `ARGUS_NOTICES__RECIPIENTS` (comma-separated),
`ARGUS_NOTICES__WEB_URL`, and `ARGUS_NOTICES__USER` / `ARGUS_NOTICES__PASSWORD` if the relay needs
a login. See [the notices runbook](runbooks/notices.md).

### backup

| Setting | Default | Meaning |
|---|---|---|
| `backup.dir` | `data/backups` | Where dumps go (mode 700; one folder per kind) |
| `backup.keep_nightly` | 7 | Nightly dumps kept |
| `backup.keep_verified` | 4 | Dumps a restore drill proved, kept besides |
| `backup.keep_migration` / `keep_manual` | 5 / 5 | |
| `backup.max_age` | `35d` | No dump older than this is kept (except the newest one a drill restored) |
| `backup.before_migration` | `false` | `argus db upgrade` / `downgrade` dump the database first and stop if that fails. Turn it on in `.env` (`ARGUS_BACKUP__BEFORE_MIGRATION=true`). |
| `backup.tools` | `image` | `pg_dump` runs in a throwaway container of the pinned PostgreSQL image (needs Docker) |

---

## The load budget

ARGUS's load on the SIEM is a budget of **Elasticsearch server time** (the `took` of every
answer), not a count of requests:

| Setting | Default | Meaning |
|---|---|---|
| `siem.budget.took_per_day_ms` | `3600000` (60 min) | Server time a day, all of ARGUS |
| `siem.budget.took_per_minute_ms` | `3000` | Server time a minute |
| `siem.budget.burst_ms` | `3000` | What may be spent at once |
| `siem.budget.concurrency` | `2` | Requests in flight at once, probes included |
| `siem.budget.heavy_concurrency` | `1` | Heavy queries (aggregations) at once |
| `siem.budget.heavy_per_minute` / `heavy_per_day` | `6` / `2000` | |
| `siem.budget.probes_per_minute` | `12` | Health probes |

The ceiling is split into **lanes**, each with its own allowance, so a slow Kibana call never
delays the collector:

| Lane | What | a minute | a day |
|---|---|---|---|
| collector | collect, backfill, reconcile, evidence | 1,800 ms | 40 min |
| investigation | the wave, Check more | 400 ms | 6 min |
| freshness | freshness readings | 100 ms | 3 min |
| kibana_read | the read-back, Kibana self-tests | 200 ms | 4 min |
| kibana_write | Kibana writes (off) | 200 ms | 3 min |
| identity | ELK sign-in checks | 300 ms | 2 min |
| measurement | reserved | 0 | 2 min |

A smaller ceiling scales the lanes with it. To halve ARGUS's daily load:

```yaml
# config/local.yaml
siem:
  budget:
    took_per_day_ms: 1800000
```

`uv run argus siem status` shows today's spending and the last requests. When a budget is spent, work waits (`skipped_budget`) and resumes as the bucket refills.

### Health states

Once a minute the collector probes the SIEM (`GET _nodes/_local/stats`: disk, heap, load,
search queue and rejections, circuit breakers; and index blocks and ingest lag of the watched
families). The result is one of four states:

| State | Entered when (defaults) | What ARGUS may do | Budget |
|---|---|---|---|
| **NORMAL** | nothing below | everything | all |
| **CAUTION** | disk ≥ 85 %, heap > 85 %, 1-minute load > 16, a search queue | collection, evidence, freshness, Kibana reads; **no** backfill, reconcile, investigation wave, discovery or write | half |
| **DEGRADED** | disk ≥ 90 %, search rejections or breaker trips rising, a failed probe, two or more late log sources, rules not running; also **never probed** or no probe for 3 minutes | collection, freshness, Kibana reads, probes | a tenth |
| **STOP** | disk ≥ 95 %, a 401/403, a blocked target index, no probe for 15 minutes, the global kill switch | probes only (and ELK sign-in checks) | none |

States are left with hysteresis (5 points below a threshold, or 3 clean probes), and after
DEGRADED or STOP the budget comes back slowly: a quarter for 20 minutes, half until 40 minutes,
then all of it. The thresholds:

| Setting | Default |
|---|---|
| `siem.health.disk_caution` / `disk_degraded` / `disk_stop` | 85 / 90 / 95 (%) |
| `siem.health.heap_caution` | 85 (%) |
| `siem.health.load_caution` | 16.0 (1-minute load; set it to about your nodes' core count) |
| `siem.health.ingest_lag_degraded` | `15m` |

---

## Kibana and its write classes

| Setting | Default | Meaning |
|---|---|---|
| `kibana.enabled` | `false` | Nothing is sent to Kibana while false. `argus init` sets it to `true` in `local.yaml` when you give a Kibana key. |
| `kibana.url` | none | Kibana's address (`local.yaml`) |
| `kibana.ca_file` | `data/certs/siem-ca.crt` | The pinned CA Kibana's certificate must chain to |
| `kibana.base_path` | empty | Kibana's `server.basePath`, if set (`/kibana`) |
| `kibana.timeout` | `15s` | |
| `kibana.reader_api_key_expires` | none | The reader key's expiry; doctor warns 30 days ahead |
| `kibana.sync.enabled` | `true` (shipped) | The read-back of cases, where `kibana.enabled` is true |
| `kibana.sync.normal` / `caution` / `degraded` | `10m` / `20m` / `1h` | How often the read-back polls in each health state (never in STOP) |
| `kibana.write_classes` | none | **The write classes switched on.** Empty: ARGUS writes nothing. |
| `kibana.write_window` | `02:30`–`17:30` | UTC hours in which writes may happen; never inside the quiet hours |
| `kibana.service_user` | `argus` | The ELK user that owns ARGUS's writer keys |

The write classes, all off by default:

| Class | What it writes |
|---|---|
| `WC` | The case team: posts a person-confirmed incident case to Kibana, step by step, each step by its own Kibana user (also needs `case_team.post: true` and the team's keys) |
| `WA` | Alert status: after people's reviewed verdicts, closes or acknowledges those alerts (also `writeback.enabled`) |
| `W1`, `W2`, `W3` | The earlier case writer's create / update / approved-closure classes |

Every write class also needs its own key held only by the writer's environment (never `.env`;
doctor fails if a write key is found in a shared place) and a person present at its first run.
See [kibana.md](kibana.md).

---

## The web

| Setting | Default | Meaning |
|---|---|---|
| `web.host` | `127.0.0.1` | Anything else needs `tls_cert`, `tls_key`, `allowed_hosts` and `allowed_networks` |
| `web.port` | `8765` | |
| `web.tls_cert`, `web.tls_key` | none | Both or neither |
| `web.allowed_hosts` | none | Host names browsers use, besides the loopback |
| `web.allowed_networks` | none | Client networks allowed, besides the loopback |
| `web.public_url` | none | The address in permanent links (`https://argus.example.org:8765`) |
| `web.tls_pin_sha256` | none | SHA-256 of the served certificate (DER, lowercase hex); doctor fails if it changes |
| `web.session_idle` / `session_absolute` | `30m` / `8h` | A session ends after this long without a request of the person's, and this long after sign-in |
| `web.database_role` | `app` | `api`: the web logs in with its own database login (`argus init` sets this) |
| `web.approval_key_file` | none | The key that signs approvals ([web-ui-guide.md](web-ui-guide.md#approvals)) |
| `web.elk_signin` | `false` | People sign in with their own ELK accounts ([web-ui-guide.md](web-ui-guide.md#sign-in-with-elk-accounts)) |
| `web.secret_file` | none | The web's own secret (needed for ELK sign-in) |
| `web.classic` | `primary` | The web unit sets `fallback`: people land on the app at `/app` |

The web service gets its network settings from `units.web` (next section); the others may go in
the `web` section of `local.yaml`.

## Units

`units` in `config/local.yaml` says how `argus units install` renders the systemd units:

| Setting | Default | Meaning |
|---|---|---|
| `units.root` | this checkout | The checkout the units run (absolute) |
| `units.uv` | the uv running the command | The uv the units start ARGUS with (absolute) |
| `units.run` | the four services | The units this installation runs. Doctor warns while none of them is started yet and fails while some run and a listed one is not enabled. `argus init --start` writes it: the four services, the Kibana read-back when Kibana is set up, the backup timers unless declined, and whatever it listed already. |
| `units.web.host`, `tls_cert`, `tls_key`, `allowed_hosts`, `allowed_networks`, `public_url`, `approval_key_file`, `database_role` | none | Rendered into the web unit's environment; a value left out drops its line |
| `units.web.classic` | `fallback` | |

After changing `units`: `uv run argus units install --apply --reload`, then restart the changed
service ([operations.md](operations.md#services-and-timers)).

## The case team (`case_team`)

The seven Kibana users that post incident cases ([case-team.md](case-team.md)). Off by default:

| Setting | Default | Meaning |
|---|---|---|
| `case_team.post` | `false` | Nothing is written while false (dry runs still show everything) |
| `case_team.auto` | `false` (shipped) | ARGUS's own true positive may open a case; off: only a person's Confirm |
| `case_team.auto_min_confidence` | `0.8` | |
| `case_team.per_day` | `5` | Cases opened a day, in the site's time zone |
| `case_team.canary` | `1` | The first N cases need a person's approval of that case |
| `case_team.max_alerts` / `alerts_per_call` / `alert_pause` | `500` / `100` / `3s` | Alerts attached per case, per call, and the gap between calls |
| `case_team.min_update_gap` | `6h` | At most one "Update" round in this time |
| `case_team.look` | `40` | Cases examined in one pass |
| `case_team.lead_api_key`, `evidence_api_key`, `intel_api_key`, `responder_api_key`, `hunter_api_key`, `reporter_api_key`, `visualiser_api_key` | none | The team's keys: credential files only (`local/creds-writer/`), never `.env` or YAML |
| `case_team.keys_expire` | none | Their common expiry; `argus case team provision` writes it |

## The LLM gateway (`config/llm.yaml`)

Not part of the settings above: its own file, laid under `config/llm.local.yaml`
([llm.md](llm.md), [costs.md](costs.md)).

| Key | Shipped | Meaning |
|---|---|---|
| `keys_file` | `null` | The keys file; set it in `config/llm.local.yaml` (the only key that file may set) |
| `monthly_cap_usd` / `daily_cap_usd` | `40.0` / `1.50` | Paid spending caps (UTC month, UTC day) |
| `margin` | `0.8` | The share of each provider's published rate limits ARGUS uses |
| `shares` | `{high: 1.0, normal: 0.8, low: 0.5}` | The share of each day limit and of both caps a priority may use |
| `evaluation` | `window_utc: ["17:30", "00:00"]`, `calls_per_day: 150` | When evaluation runs may call models, and how many a night per provider |
| `providers[]` | groq, openrouter, gemini, openai, local (disabled) | Tried in this order. Each: `name`, `base_url`, `keys` (key names), `models` (`small`, `medium`, `large`: `name`, `limits`, `input_per_m`, `output_per_m`, `extra`), `limits` (`rpm`, `rpd`, `tpm`, `tpd`), `timeout_s`, `max_tokens_field`, and optionally `enabled`, `trust` (`cloud` or `campus`), `ca_file`, `concurrency`, `tasks`, `probe`, `slow_s`, `schema_output` |

## Other sections

`identity` (ELK sign-in timeouts and refused accounts), `writeback` (the alert status write-back,
off), `soak` and `custody` (used by the project's own production checks) are documented in
`settings.py`. Leave them as shipped unless a guide tells you otherwise.
