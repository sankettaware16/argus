# Kibana Integration

ARGUS reads Kibana's **Security alerts** through Elasticsearch (that needs only the Elasticsearch
key). Kibana itself is optional; with its address and a reader key ARGUS also:

- learns Kibana's version, spaces and feature ids during discovery;
- **reads back the Kibana cases** that hold ARGUS's alerts, and what people did to them;
- links every evidence line of an incident report to Kibana Discover (no request: a link a
  signed-in person opens).

**Writing** to Kibana (posting incident cases, closing alerts after reviews) exists, but every
write class is **off** by default and needs its own key, its own environment and a person present
for its first run.

**Contents**

- [The reader key](#the-reader-key)
- [The self-test](#the-self-test)
- [The read-back](#the-read-back)
- [Writes: off by default](#writes-off-by-default)
- [The case team](#the-case-team)
- [Stopping and resuming Kibana work](#stopping-and-resuming-kibana-work)
- [Settings](#settings)

---

## The reader key

`argus init` asks for it at step 5, after printing the Dev Tools request
([install.md](install.md#32-the-api-keys-argus-asks-for)): an Elasticsearch API key with one
Kibana application privilege, **Cases read** in your space
(`feature_securitySolutionCasesV3.read` on `space:<space>` for Kibana 8.19). It is stored in `.env`
as `ARGUS_KIBANA__READER_API_KEY`, and `kibana.enabled: true`, `kibana.url` and
`kibana.reader_api_key_expires` go to `config/local.yaml`.

To add Kibana later, run `uv run argus init` again and give Kibana's address and key; to replace
the key, `uv run argus init --force-key`.

Kibana is reached over HTTPS with the same pinned CA as Elasticsearch when that CA verifies it,
or its own pin (`kibana.ca_file`). If Kibana is served under a path (`server.basePath`), set
`kibana.base_path` (`/kibana`).

## The self-test

```bash
uv run argus kibana selftest              # the reader key (default)
uv run argus kibana selftest --dry-run    # print the two requests, send nothing
```

It reads Kibana's status (version) with the key, then asks Elasticsearch what the key holds: the
privileges it **must** hold, and those it must **not** (the alert updates, `deleteCase`,
`createConfiguration`, `pushCase`, `assignCase`, `api:rac`):

```
Kibana 8.19.12; the reader key:
  as it must be
```

or, for a key that lacks or exceeds its profile,

```
Kibana 8.19.12; the reader key:
  PROBLEM: lacks ...
```

with exit code 1. `--key cases` and `--key alerts` check the writer keys, once you have them.

## The read-back

`argus kibana sync` reads, read-only, the Kibana cases that hold ARGUS's alerts (found through the
alerts' `kibana.alert.case_ids`), their status and comments, and the status changes of those
alerts. Findings (a case people closed in Kibana, a case deleted there, a comment that gives a
verdict) appear on the investigation's and case's pages ("the Kibana mirror"). A comment
`Verdict: true positive` or `Verdict: false positive: <reason>` written in a Kibana case ARGUS
posted is read as a person's verdict.

It polls every 10 minutes when the SIEM is NORMAL, 20 in CAUTION, hourly in DEGRADED, never in
STOP, inside the Kibana read lane's budget (200 ms of server time a minute, 4 minutes a day).

```bash
uv run argus kibana sync once --dry-run   # the requests of one cycle, none sent
uv run argus kibana sync once             # one cycle now
uv run argus kibana sync status           # the read-back's state, open findings, paused cases
uv run argus kibana sync report           # cycles complete, staleness, the read load
```

**As a service.** `argus init --start` starts `argus-kibana-sync.service` whenever Kibana is set
up (its key given at step 5), and lists it in `units.run`. Its unit reads two extra files from
the checkout, an environment file and a credential folder, for installations that keep the
reader key apart from `.env`; init makes both, empty, so the key stays in `.env`
(`local/creds-sync/`, mode 700, and `local/argus-kibana-read.env`, mode 600). To check it:

```bash
systemctl --user status argus-kibana-sync --no-pager
journalctl --user -u argus-kibana-sync -f
uv run argus kibana sync status
```

The web's status bar shows **Kibana sync** from the newest recorded cycle: *in sync* (complete,
within the last 90 minutes), *partly read*, *failing*, *late* (none for 90 minutes), or *not
running yet* before the first cycle. Hover over it for the time and outcome; *System → Health*
has the same in a row.

While `kibana.enabled` or `kibana.sync.enabled` is false, `kibana sync run` says so and exits 0
(the unit stays stopped rather than restarting).

## Writes: off by default

`kibana.write_classes` is empty: ARGUS writes nothing to Kibana or Elasticsearch. The classes
that exist:

| Class | What it writes | Its runbook |
|---|---|---|
| `WC` | **The case team**: posts a person-confirmed incident case, each part by its own Kibana user (opening and verdict, evidence, intel, recommended actions, hunting queries, the report files), so the case's timeline shows who said what | [case-team.md](case-team.md), [the runbook](runbooks/kibana-case-team.md) |
| `WA` | **Alert status**: after people's reviewed verdicts, closes (benign, policy, false positive) or acknowledges (true positive, follow-up) those alerts, a few a minute | `writeback.*` settings |
| `W1`, `W2`, `W3` | The earlier case writer's create, update and approved-closure classes | [kibana-cases.md](runbooks/kibana-cases.md) |

Every class needs, all together:

1. **Its own key with write privileges**, held only by the writer's own environment, never in
   `.env`, a YAML file or a shared unit. `argus doctor` fails (`write keys`) when it finds a write
   key in a shared place.
2. Its name in `kibana.write_classes` **in that same environment**, and, for the case team,
   `case_team.post: true` and the team's keys (`case_team.<user>_api_key`).
3. A **person present for its first run** (a canary), which runs at a terminal with the class
   name typed; a class ramps up only after clean runs whose every write was read back.
4. The **write window** (`kibana.write_window`, default 02:30–17:30 UTC; never the quiet hours)
   and NORMAL health.

What ARGUS never does in Kibana: edit or disable a rule, delete a case or an alert, write to a
case it did not create, or send text from a log or a model unescaped. Case closures are always a
person's request **and** another person's approval in ARGUS.

**Read the runbook of a class completely before switching it on.** The runbooks were written for
the project's first deployment: their local times, its credential layout (`local/...`, a root
"custody" layout with `argus-owner`) and its incident ids are that site's; the commands and
settings are ARGUS's own.

Useful read-only commands while preparing a class:

```bash
uv run argus kibana selftest --key cases     # the writer key's privileges
uv run argus kibana plan --class W1          # what a run would take up and what stops it (database only)
uv run argus kibana diff --class W1          # each waiting row planned against the case as it is now
uv run argus kibana state                    # stopped or not, paused classes, today's writes
```

## The case team

The write class most installations will want first. ARGUS posts a person-confirmed incident case
as **seven Kibana users**, each owning one part of the case, so the case's timeline in Kibana
reads like a team's work:

| User | Posts |
|---|---|
| `argus-lead` | opens the case, attaches and tags its alerts, writes the verdict last |
| `argus-evidence` | the evidence with its hypotheses, the affected devices |
| `argus-visualiser` (optional) | "Incident at a glance": a numbers row and live Kibana charts of the case's alerts |
| `argus-intel` | threat intel, when there is an outside answer |
| `argus-responder` | recommended actions |
| `argus-hunter` | KQL and ES\|QL queries to check it yourself |
| `argus-reporter` | the incident PDF, the dashboard PDF and two CSVs in the Files tab |

ARGUS creates the users, two roles and one API key each with one command, run once with an
Elasticsearch administrator's login (held in memory for that run only):

```bash
uv run argus case team provision                              # the plan; nothing is sent
uv run argus case team provision --apply --admin-user elastic # create; the password is asked
```

The keys land in `local/creds-writer/case_team.<agent>_api_key` (mode 600). Posting stays off
until you switch it on, preview the first case, and a person approves it in the Inbox. The full
guide: [case-team.md](case-team.md).

## Stopping and resuming Kibana work

```bash
uv run argus siem stop --component kibana --reason "..."   # all Kibana reads
uv run argus siem stop --component cases --reason "..."    # Kibana writes
uv run argus kibana state
```

ARGUS stops all Kibana work by itself on a **401** and pauses one write class on a **403** or an
answer it did not expect; a person lifts it after reading why (as the database owner, whose
password is in `.env` on a standard install):

```bash
uv run argus kibana resume --reason "reader key renewed"
uv run argus kibana resume --class WC --reason "..."
```

The last resort is always the key: invalidate it in Kibana (Stack Management → API keys).

## Settings

| Setting | Default | Meaning |
|---|---|---|
| `kibana.enabled` | `false` (`true` after init with a key) | Nothing is sent to Kibana while false |
| `kibana.url` | none | `https://host:5601` |
| `kibana.ca_file` | `data/certs/siem-ca.crt` | The pinned CA |
| `kibana.base_path` | empty | Kibana's `server.basePath` |
| `kibana.timeout` | `15s` | One request |
| `kibana.reader_api_key_expires` | none | Doctor warns 30 days ahead |
| `kibana.sync.enabled` | `true` (shipped) | The read-back runs where `kibana.enabled` is true |
| `kibana.sync.normal` / `caution` / `degraded` | `10m` / `20m` / `1h` | Poll interval by health |
| `kibana.sync.team_cases` | `true` | Also read back the case team's cases |
| `kibana.write_classes` | none | The write classes switched on |
| `kibana.write_window` | `02:30`–`17:30` UTC | When writes may happen |
| `kibana.service_user` | `argus` | The ELK user that owns ARGUS's writer keys |
| `case_team.*` | `post: false` | The case team ([case-team.md](case-team.md#11-settings)) |
| `incident.kibana_url` | `kibana.url` | The address in the report's Discover links |
| `incident.data_views` | none | `source=data-view-id` pairs for KQL links |
| `site.kibana_versions` | `>=8.0,<10` | Versions ARGUS writes to |
| `site.kibana_features` | read by discovery | Kibana's Security and Cases feature ids |

More in [configuration.md](configuration.md#kibana-and-its-write-classes).
