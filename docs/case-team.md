# The Case Team

ARGUS can post its incident cases into **Kibana Cases**, where your security team already works,
as a **team of seven Kibana users**. Each user owns one part of the case: the lead opens it and
gives the verdict, the evidence user writes the evidence, the reporter uploads the PDF and CSVs,
and so on. The case's timeline in Kibana then reads like a team's work: who said what, in order,
and every part can be traced to the ARGUS user that wrote it.

Posting is **off by default**. This page explains what the team posts, how to create its seven
users with one command, how to switch posting on safely (a dry run, a person's approval of the
first case, then a timer), how people answer in Kibana, and how to stop it. The operator's
step-by-step runbook, with every detail of pacing and recovery, is
[runbooks/kibana-case-team.md](runbooks/kibana-case-team.md).

**Contents**

1. [The seven users and what each posts](#1-the-seven-users-and-what-each-posts)
2. [A posted case, step by step](#2-a-posted-case-step-by-step)
3. [When a case is posted](#3-when-a-case-is-posted)
4. [Creating the team: `argus case team provision`](#4-creating-the-team-argus-case-team-provision)
5. [Switching posting on](#5-switching-posting-on)
6. [The canary: a person approves the first case](#6-the-canary-a-person-approves-the-first-case)
7. [After the first case: updates, corrections, Sync alerts](#7-after-the-first-case)
8. [People answer in Kibana: `Verdict:` comments and the read-back](#8-people-answer-in-kibana)
9. [Limits, pacing and recovery](#9-limits-pacing-and-recovery)
10. [Stopping it](#10-stopping-it)
11. [Settings](#11-settings)
12. [Developer guide: adding a member to the team](#12-developer-guide-adding-a-member-to-the-team)

---

## 1. The seven users and what each posts

| Kibana user | Full name | Owns | Posts | Key setting |
|---|---|---|---|---|
| `argus-lead` | ARGUS · Lead | the case and its alerts | **opens** the case (incident ID, title, severity, `key:value` tags, description), **attaches** the case's alerts and **tags** them, writes the **verdict comment last**, and later the notes after a person's verdict | `case_team.lead_api_key` |
| `argus-evidence` | ARGUS · Evidence | the evidence | **Evidence** (every line with the query behind it, and the hypotheses), **Affected devices**, and the accounts that signed in from them where sign-ins are known | `case_team.evidence_api_key` |
| `argus-visualiser` | ARGUS · Visualiser | the glance (**optional**) | **Incident at a glance**, right after the evidence: the severity, the call and whose it is, still active or quiet, the dwell; a numbers row (alerts, actors, targets, indicators on your threat lists, first and last alert, rules); what is new since the last version; and up to four **live Kibana charts** of the case's tagged alerts (a short list where a chart would hold one bar or a field the alerts lack). **One living comment**: later rounds edit it in place | `case_team.visualiser_api_key` |
| `argus-intel` | ARGUS · Intel | threat intel | **Threat intel**, only when the report holds an outside answer (VirusTotal, Shodan, Censys); nothing to add is not posted | `case_team.intel_api_key` |
| `argus-responder` | ARGUS · Responder | the actions | **Recommended actions**: each with its owner, status and the condition to close | `case_team.responder_api_key` |
| `argus-hunter` | ARGUS · Hunter | the queries | **Queries to check it yourself**: KQL and ES\|QL in code blocks, the time range, a Discover link (code only) | `case_team.hunter_api_key` |
| `argus-reporter` | ARGUS · Reporter | the files | uploads the **incident report PDF**, the one-page **dashboard PDF** and two **CSVs** (indicators, affected devices) to the case's Files tab, then a comment listing them | `case_team.reporter_api_key` |

Only `argus-lead` opens a case or touches alerts, and only `argus-reporter` uploads files: the
Kibana lane's request validator and the database both enforce it. The visualiser is optional:
without its key its step is skipped (reason `no visualiser key`) and nothing else changes.

The case's **tags**: the incident ID (`<prefix>-YYYY-MMDD-NN`), `incident`, the verdict, a
category, the zone, MITRE techniques, up to three indicators, the status and
`source:argus-lead`. Each attached **alert** is tagged with the incident ID and
`incident:<verdict>`, which is also what the visualiser's charts filter on.

## 2. A posted case, step by step

The order is fixed (`src/argus/caseteam/model.py`, `ORDER`):

1. `argus-lead` **opens** the case: title, severity, tags and the description (the summary, the
   verdict with its confidence, a facts table, and what is not part of the incident).
2. `argus-lead` **attaches** the alerts, newest first, 100 a call (at most `max_alerts`, 500),
   and **tags** them.
3. `argus-evidence`: **Evidence** with the hypotheses (split into "Evidence (2 of 3)" ... when
   long; a table row or a query is never cut).
4. `argus-visualiser`: **Incident at a glance** (if its key is installed), the one comment ARGUS
   later edits in place (section 7).
5. `argus-evidence`: **Affected devices**.
6. `argus-intel`: **Threat intel** (only if there is an outside answer).
7. `argus-responder`: **Recommended actions**.
8. `argus-hunter`: **Queries**.
9. `argus-reporter`: four **files**, then the comment listing them.
10. `argus-lead`: the **verdict**, last. It ends:
    `ARGUS's verdict: true positive (0.8). ... Confirm or reject in a comment.`

Every word is rendered by code from the stored incident report: counts, times and lists come
from ARGUS's database, values from logs are written in code spans, and a **guardian** reads each
finished comment the way Kibana's Markdown reader would and refuses (holds for a person) any text
in which something could act: a link ARGUS did not build, an `@mention`, HTML, an unclosed code
span, a broken table. No model writes any of it.

## 3. When a case is posted

One pure rule (`src/argus/caseteam/policy.py`), the same in the preview, the API and the poster:

1. **`case_team.post: false` stops everything.** The whole rendering still runs as a dry run:
   `argus case team preview <n>` and the case page show exactly what would be sent.
2. With it on, a case is opened when **(a)** a person **confirmed** its report in ARGUS **as a
   true positive, on the newest report version** (a benign or inconclusive confirm never opens
   one; a report that changed since needs a new confirm), or **(b)** with `case_team.auto: true`,
   ARGUS's own verdict is a true positive of at least `auto_min_confidence` (0.8) and the case is
   suggested or open. A person's rejection stops both.
3. At most **`per_day`** cases a day (in the site's time zone).
4. **The canary:** the first `canary` cases (1) wait for a person's approval of that case.
5. A case already in Kibana is **never opened again**: a newer report version is posted as
   "Update" comments by the owning users, only what changed, never a delete.
6. A Kibana case that already carries the incident ID (one made by hand) is never duplicated:
   ARGUS holds the post for a person.
7. A sequence that was started is finished, whatever the caps say: half a case is worse than an
   extra one.

Recommended for a first deployment: `auto: false`, so only a person's Confirm opens a case.

## 4. Creating the team: `argus case team provision`

ARGUS creates its own seven users, their two roles and one API key each, in one command run by
someone with an Elasticsearch administrator login. Nothing is created until you add `--apply`.

```
uv run argus case team provision [--apply] [--admin-user NAME] [--credentials DIR]
                                 [--without-visualiser] [--expiration DAYS] [-c CONFIG]
```

| Option | Meaning |
|---|---|
| *(none)* | **The plan only** (the default): prints what would be created and where each key would be written; sends nothing |
| `--apply` | Create or update the roles and users and grant the keys |
| `--admin-user NAME` | The administrator's user name (the password is always asked, hidden) |
| `--credentials DIR` | Where the keys are written (default `local/creds-writer`, the writer's credential folder) |
| `--without-visualiser` | Six users: leave out the optional `argus-visualiser` |
| `--expiration DAYS` | The keys' lifetime (default 365 days) |
| `-c`, `--config` | Another config file than `config/argus.yaml` |

**What it creates:**

| | Privileges |
|---|---|
| role **`argus_case_lead`** | Kibana **Cases: all** and **Security: read**, in the site's space only; `read`, `write` and `maintenance` on that space's alerts indices, so it can attach and tag alerts |
| role **`argus_case_commenter`** | Kibana **Cases: all** and **Security: read**, in the space; `read` on the alerts |
| user `argus-lead` | the lead role |
| users `argus-evidence`, `argus-intel`, `argus-responder`, `argus-hunter`, `argus-reporter`, `argus-visualiser` | the commenter role |

Each user has the full name `ARGUS · Lead`, `ARGUS · Evidence`, ... and the metadata
`argus_service: true`, and gets **one API key** (365 days by default).

**Step 1: read the plan.**

```bash
uv run argus case team provision
```

It prints the two roles it will create or update, the users, the key per user and the file each
key will be written to. Nothing is sent.

**Step 2: apply it** (outside the site's quiet hours):

```bash
uv run argus case team provision --apply --admin-user elastic
```

It asks **once** for the administrator's password: a superuser such as `elastic`, or any user
holding the `manage_security` cluster privilege (it must be able to create roles, users and API
keys). Then it:

1. checks the login and its privileges, and refuses during the site's quiet hours;
2. creates or updates the two roles;
3. creates each missing user with a **random password nobody ever sees**;
4. grants each user one API key (Elasticsearch's grant API, with that user's password);
5. writes each key to `<credentials>/case_team.<agent>_api_key` (mode 600), e.g.
   `local/creds-writer/case_team.lead_api_key`;
6. checks that each key authenticates as its own user;
7. records the keys' expiry in `config/local.yaml` (`case_team.keys_expire`).

**The administrator's login is held in memory for this run only**: never stored, printed, logged
or sent anywhere but to the SIEM.

**It is idempotent.** Run it again at any time: a user whose key file exists is kept; a user that
exists without a key file gets a new random password and a new key. To re-key one agent (a lost
or leaked key, or before expiry), delete its key file and run it again; then invalidate the old
key in Kibana (Stack Management → API keys).

Posting **stays off** after provisioning: the keys only sit in the writer's credential folder.

## 5. Switching posting on

Do this with the person who will approve the first case, inside the write window
(`kibana.write_window`, 02:30–17:30 UTC by default) and with the SIEM NORMAL.

**Prerequisites** (once):

- Kibana is configured and its reader key works: `uv run argus kibana selftest`.
- The web has an approval key ([web-ui-guide.md](web-ui-guide.md#approvals)) and an address for
  links in the case: in `config/local.yaml`,

  ```yaml
  web:
    public_url: https://argus.example.org:8765
  ```

- An approver: an Inbox account with `approve` **and** `see_logs` (an approver must be able to read
  every word that will be posted).

**1. The writer's database login.** Posts are recorded by the writer's own database login
(`argus_writer_app`), never the services' shared one. Give it a password in the writer's
credential folder and let bootstrap create it:

```bash
cd ~/argus
umask 077
openssl rand -hex 32 > local/creds-writer/database.writer_password
CREDENTIALS_DIRECTORY="$PWD/local/creds-writer" uv run argus db bootstrap
```

`argus init` does the same whenever the login does not log in with that file (a new database, a
copy of the folder from another machine), and leaves it alone when it does.

**2. The approval key, for the writer.** The writer verifies the canary's approval with the same
key the web signs with:

```bash
install -m 600 data/keys/approval-signing.key local/creds-writer/approval-signing.key
```

**3. The writer's switches**, in their own file (never `.env`, which every process loads):

```bash
install -m 600 /dev/null local/argus-writer.env
cat >> local/argus-writer.env <<'EOF'
ARGUS_KIBANA__ENABLED=true
ARGUS_KIBANA__WRITE_CLASSES=WC
ARGUS_CASE_TEAM__POST=true
ARGUS_CASE_TEAM__AUTO=false
EOF
```

`local/creds-writer/` now holds the team's keys, `database.writer_password` and
`approval-signing.key`, all mode 600. The case-team unit (`argus-case-team.service`) loads exactly
these two places: `EnvironmentFile=local/argus-writer.env` and
`CREDENTIALS_DIRECTORY=local/creds-writer`. `argus doctor` fails (`write keys`) if a team key is
ever found in `.env`, a YAML file, a unit file or a process's environment.

**4. See what is missing.** In a shell with the writer's view of the settings:

```bash
( set -a; . local/argus-writer.env; set +a
  export CREDENTIALS_DIRECTORY="$PWD/local/creds-writer"
  uv run argus case team run 1 )
```

Run before everything is in place, it prints each missing piece and sends nothing, for example
`cannot post: WC is not switched on at this host (kibana.write_classes)`,
`cannot post: no key is installed for argus-hunter`,
`cannot post: web.public_url is not set: the link to ARGUS in a case would not open`, or
`cannot post: no approval key is configured: the canary's approval cannot be checked`.

**5. Preview the first case** (nothing is written):

```bash
uv run argus case team preview 1 --text --requests
```

**6. Approve it** in the Inbox ([section 6](#6-the-canary-a-person-approves-the-first-case)).

**7. Post it, with a person at the terminal:**

```bash
( set -a; . local/argus-writer.env; set +a
  export CREDENTIALS_DIRECTORY="$PWD/local/creds-writer"
  uv run argus case team run 1 )
# This writes to Kibana on the SIEM as the six case team users (class WC).
# Type WC to confirm: WC
```

Check the case in Kibana's own UI: the title, tags, description, the attached alerts, the Files
tab, and who wrote each comment.

**8. Then the timer**, which posts the cases that qualify every 3 minutes, paced by the Kibana
write lane:

```bash
systemctl --user enable --now argus-case-team.timer
```

and add `argus-case-team.timer` to `units.run` in `config/local.yaml`, so `argus doctor` checks it
stays enabled. Also run the read-back (`argus-kibana-sync`, [kibana.md](kibana.md#the-read-back)):
it is how ARGUS learns what people do to the team's cases.

## 6. The canary: a person approves the first case

The first `case_team.canary` cases (1 by default) are posted only after a person approves **that
case's plan**:

- On the case page in the Inbox, the **Kibana case preview** section shows the plan: every step
  with its author, every comment word for word, every request (a file as its name, size and hash),
  and the plan's hash. The same is `argus case team preview <n> --text --requests` and
  `GET /api/v1/cases/{id}/team`.
- The approver needs `approve` and `see_logs` and re-types their password (a step-up within the
  last 5 minutes). Approving sends `{"plan_hash": ...}` to `POST /api/v1/cases/{id}/team/approve`.
- The approval is **signed** with the approval key, expires with the write window it was given for
  (at most 72 hours) and binds **exactly that plan**: a new report version, a new alert or a
  changed text is a new plan and needs a new approval.
- The poster checks the signature, the hash, the expiry and that the approver's account is still
  active before its first request.

## 7. After the first case

**Updates.** When a case's report gets a newer version, the next round (at most one every
`min_update_gap`, 6 hours) posts **only what changed**, as "Update" comments by the owning users.
A file is uploaded again only if its bytes changed, under a versioned name (`..._v2`). Nothing is
ever deleted.

**The glance is one living comment.** It is the one exception to "Update" comments: when the
glance changed, the round **edits** the visualiser's comment in place (one `PATCH`, read first, as
every edit is) and the comment says what is new since the version before ("New since report
version 2: 40 more alerts, 1 more rule"). So a long case holds one glance, always the newest. A
glance a person changed or removed in Kibana is left alone from then on, and the run says so.

**Corrections in place.** A retitle in ARGUS edits the Kibana title in the next round. The
description and the comments are rewritten only when a person asks:

```bash
uv run argus case team refresh <n>            # dry run: what would change
uv run argus case team refresh <n> --apply    # plan the edits (the next run sends them)
```

Every edit reads Kibana first: if a **person** changed that text in Kibana, ARGUS leaves it
(`a person changed it in Kibana, so ARGUS leaves it`). A refresh also corrects the glance (a chart
whose form Kibana did not draw, for one); it never posts a first glance, which the next round does.
Without the visualiser's key a refresh leaves the glance out and goes on.

**Sync alerts.** A Kibana case's *Sync alerts* setting is the team's; ARGUS never changes it. With
it on, Kibana sets every attached alert's status to the case's status, so the lead reads the case
before every attach: on an **open** case, alerts a person had already closed are left out (so they
are not reopened) and the run says how many; on a case **in progress or closed**, attaching is
skipped altogether (it would change the alerts' status). Skipped alerts are tried again in a
later round. Tagging is unaffected: a tag changes no status.

## 8. People answer in Kibana

**A person's verdict.** The lead's last comment asks people to *Confirm or reject in a comment*.
A team member writes, from their own Kibana account, at the start of a comment:

```
Verdict: true positive
Verdict: false positive: the vendor's backup agent, confirmed with the owner
```

ARGUS reads it after each Kibana sync cycle (or now: `uv run argus case team sync`) and records it
as that person's review, through the same path as Confirm and Reject in the Inbox, if:

- the author's Kibana name is the ELK name of exactly one enabled ARGUS person (otherwise kept as
  `unmatched` and read again later);
- that person holds `review` in ARGUS (a comment-only Kibana account is `refused`);
- the comment was not edited by someone else.

The lead then writes a short note saying what happened. **ARGUS closes nothing**: closing stays a
person's request and another person's approval in ARGUS.

**The read-back.** `argus-kibana-sync` reads the team's cases as well
(`kibana.sync.team_cases: true`). Within one cycle (10 minutes when the SIEM is NORMAL) ARGUS knows
when a person edits, comments on, closes, reopens or deletes a team case, and shows it on the
ARGUS case's page and in `argus case team status`. A case deleted in Kibana is left alone from
then on.

## 9. Limits, pacing and recovery

Every request goes through the Kibana write lane of the Elastic Gateway: class `WC`, the lane's
budget of Kibana server time, the health states, the write window, the breaker and the ledger.

| Limit | Value |
|---|---|
| Cases opened a day | `case_team.per_day` (5) |
| Alerts per case / per call | `max_alerts` (500) / `alerts_per_call` (100), `alert_pause` (3 s) between calls |
| Case writes | 40 a run, 200 a day |
| Alert changes (all write classes) | 2,000 a day |
| Write lane | a 60 s burst of server time while NORMAL, then 200 ms a minute; 3 minutes a day: a case of about 45 s posts in one or two runs, and about 4 such cases fit in a day |

**Crashes and timeouts.** Every request is a stored step. A step left in doubt is **looked for in
Kibana before anything is sent again** (a comment by its text and author, the case by its
incident tag, alerts by the case's count, a file by the case's user actions), at 2, 5, 15 and 30
minutes. Found: verified. Not found after four looks: it waits for a person:

```bash
uv run argus case team status 1              # the posts and the state of every step
uv run argus case team resend <step-id>      # send it once more
uv run argus case team skip <step-id> --reason "done by hand in Kibana"
```

ARGUS stops all Kibana work on a **401** and pauses class `WC` on a **403** or an answer it did
not expect; `uv run argus kibana resume --class WC --reason "..."` lifts the pause after a person
has read why.

## 10. Stopping it

From gentlest to strongest:

1. `ARGUS_CASE_TEAM__POST=false` in `local/argus-writer.env` (the next run sends nothing: each run
   refuses before it logs in; doctor notes it and fails nothing).
2. `systemctl --user disable --now argus-case-team.timer`.
3. `uv run argus siem stop --component cases --reason "..."` (every Kibana write, at once).
4. Invalidate the team's keys in Kibana (Stack Management → API keys), or disable the users.

## 11. Settings

`case_team:` in `config/argus.yaml` (defaults) or `config/local.yaml`; the switches that turn
writing on belong in the writer's own `local/argus-writer.env`:

| Setting | Default | Meaning |
|---|---|---|
| `case_team.post` | `false` | Nothing is written while false; the dry run shows everything |
| `case_team.auto` | `true` in code, **`false` shipped** | ARGUS's own true positive may open a case; off: only a person's Confirm |
| `case_team.auto_min_confidence` | `0.8` | The confidence from which ARGUS's own true positive opens a case |
| `case_team.per_day` | `5` | Cases opened a day (a person's confirmation counts too) |
| `case_team.canary` | `1` | The first N cases need a person's approval of that case |
| `case_team.max_alerts` | `500` | Alerts attached and tagged on one case (newest first; at most 1,000) |
| `case_team.alerts_per_call` | `100` | Alerts in one attach or tag call (at most 100) |
| `case_team.alert_pause` | `3s` | The least time between two alert calls |
| `case_team.min_update_gap` | `6h` | At most one "Update" round in this time |
| `case_team.look` | `40` | Cases examined in one pass |
| `case_team.<agent>_api_key` | none | The seven keys (`lead`, `evidence`, `intel`, `responder`, `hunter`, `reporter`, `visualiser`): credential files only |
| `case_team.keys_expire` | none | The keys' common expiry; written by `provision` |
| `kibana.write_classes` | none | Must hold `WC`, in the writer's environment only |
| `kibana.write_window` | 02:30–17:30 UTC | When writes may happen |
| `kibana.sync.team_cases` | `true` | The read-back also reads the team's cases |

## 12. Developer guide: adding a member to the team

The roster is **fixed in code**, deliberately: every author is checked by the request validator,
the database and the read-back, so a new member is a code change with tests, not a setting.
To add an eighth member (say `argus-forensics`):

1. **The author.** Add it to `Author` in `src/argus/caseteam/model.py` (the value is the Kibana
   user name), place it in `ORDER`, and map the part it owns in `PART_AUTHOR`.
2. **Its part.** Write a pure renderer for its comment in `src/argus/caseteam/render.py` (from the
   stored `incident-report@1` only; build table rows with `row()`, values with `val()`), add it to
   `parts_of`, and make sure the guardian (`guard.py`) accepts what it produces.
3. **Its steps.** Add its step to `first_plan` and `update_plan` (and `refresh_plan` if its comment
   can be corrected) in `src/argus/caseteam/plan.py`, in its place in the order.
4. **Its key.** Add `case_team.<name>_api_key` to `CaseTeamSettings` in
   `src/argus/config/settings.py` and to `_by_user()` (which also feeds the read-back's list of
   team users), and the same name to `WRITE_KEYS` in `src/argus/ops/checks.py`, so doctor keeps it
   out of shared places. If posting must not start without it, add it to `TEAM` in
   `src/argus/caseteam/service.py`; leave it out for an optional member (as the visualiser is).
5. **The other places that name the team.** The Kibana lane's own list of team users
   (`src/argus/gateway/kibana/models.py`; `validator.py` says which author may use which
   template), the web API's (`src/argus/web/v1/team_models.py`) and the database model's
   (`src/argus/db/models.py`): each must know the new name.
6. **The database.** `case_team_steps.author` is checked by a constraint: add a migration that
   accepts the new value (as migration 0062 did for the visualiser).
7. **Provisioning.** Add it to the `provision` roster with the role it needs (the commenter role
   unless it touches alerts or files).
8. **Tests.** Unit tests for the renderer and the plan order (`tests/unit/caseteam/`), the guardian
   on its output, and the integration tests for posting (`tests/integration/caseteam/`).

The **investigation** agents (the AI investigator and its specialists) are a different thing:
model prompts in `config/agents/*.md`, described in [agents.md](agents.md).
