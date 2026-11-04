# Operations

Day-to-day running of an ARGUS installation: the services and timers, health checks, logs,
backups, retention, the kill switches, key rotation and certificates. Every command is run from
the checkout as the user that owns the installation.

**Contents**

- [Services and timers](#services-and-timers)
- [`argus doctor`](#argus-doctor)
- [Status at a glance](#status-at-a-glance)
- [Logs](#logs)
- [Backups](#backups)
- [Retention and the purge](#retention-and-the-purge)
- [Kill switches](#kill-switches)
- [Rotating the API keys](#rotating-the-api-keys)
- [Certificates and the TLS pin](#certificates-and-the-tls-pin)
- [Health states and quiet hours](#health-states-and-quiet-hours)
- [Users and sessions](#users-and-sessions)
- [A daily and weekly routine](#a-daily-and-weekly-routine)

---

## Services and timers

The unit files in `deploy/systemd/` are **templates**. `argus units install` renders them for
this installation (the checkout, the uv, the web's settings from `units` in
`config/local.yaml`) and writes them to `~/.config/systemd/user/`. New units are installed
**disabled**: each is switched on on purpose.

| Unit | Kind | Runs | Default |
|---|---|---|---|
| `argus-collector.service` | service | the collector: health probe and new alerts every minute, workflow states every 15 min, reconciliation hourly, backfill | on (`--start`) |
| `argus-worker.service` | service | evidence and dossiers for queued investigations | on |
| `argus-assess.service` | service | proposals, case suggestions, incident reports, the AI investigator (with keys), weekly tuning | on |
| `argus-web.service` | service | the Inbox, over HTTPS on the address `argus init` set up, or on `127.0.0.1:8765` | on |
| `argus-backup.timer` | timer | `argus backup dump --kind nightly`, daily 21:30 UTC | on with `--start`, unless declined |
| `argus-backup-drill.timer` | timer | `argus backup drill --latest`, Sundays 22:00 UTC | on with `--start`, unless declined |
| `argus-report-daily.timer` | timer | `argus report daily`, 02:15 UTC | off |
| `argus-report-weekly.timer` | timer | `argus report weekly`, Mondays 02:20 UTC | off |
| `argus-purge.timer` | timer | `argus purge run --apply --scheduled`, 23:00 UTC | off (needs `retention.scheduled`) |
| `argus-notices.timer` | timer | `argus notices run`, every 10 minutes | off (needs notices configured) |
| `argus-kibana-sync.service` | service | the read-back of Kibana cases ([kibana.md](kibana.md#the-read-back)) | on with `--start` when Kibana is set up |
| `argus-case-team.timer` | timer | the case team's posts to Kibana (a write) | off |
| `argus-writer.service` | service | Kibana writes from the outbox (a write) | off |

(`argus-soak-*` units also ship; they belong to the project's own release checks and stay off.)

**`units.run` is the list of what this installation runs.** Doctor fails while a listed unit is
not enabled, warns when an unlisted optional unit is enabled, and fails when a unit that waits for
its own step (purge, notices, reports, writer) is enabled without being listed. So switching a
unit on is two changes:

```yaml
# config/local.yaml
units:
  run:
    - argus-collector.service
    - argus-worker.service
    - argus-web.service
    - argus-assess.service
    - argus-backup.timer
    - argus-backup-drill.timer
```

```bash
systemctl --user enable --now argus-backup.timer argus-backup-drill.timer
systemctl --user list-timers 'argus-*'
uv run argus doctor
```

List the **timer**, not its service: a timer's service is started by the timer and never enabled
itself.

**Look at a rendered unit, and reinstall after a change**

```bash
uv run argus units show argus-web.service      # one unit as this installation renders it
uv run argus units install                     # what would change: a diff per unit (dry run)
uv run argus units install --apply --reload    # write the changed units, then daemon-reload
systemctl --user restart argus-web             # restart a changed service
```

Never edit the installed copies or add drop-ins: doctor compares the installed units with their
rendering byte for byte and fails on a difference or a drop-in. Change `units` in
`config/local.yaml` (or the template in `deploy/systemd/`) and install again.

**Start, stop, restart**

```bash
systemctl --user start  argus-collector argus-worker argus-web argus-assess
systemctl --user stop   argus-collector argus-worker argus-web argus-assess
systemctl --user restart argus-assess
systemctl --user status 'argus-*' --no-pager
```

Services restart on failure on their own (after 10–30 s). The database container restarts with
Docker (`restart: unless-stopped`); until it is up a service's start fails and is retried.

**Keep the collector running.** It is the one that probes the SIEM's health. Without a fresh
probe every other service treats the SIEM as DEGRADED after 3 minutes and as STOP after 15, and
their SIEM work waits.

## `argus doctor`

```bash
uv run argus doctor
```

Read-only health checks of every part. It sends **no request** to the SIEM, Kibana or any LLM
provider (those have their own live checks: `argus siem selftest`, `argus kibana selftest`,
`argus llm probe`).

| Label | Meaning |
|---|---|
| `PASS` | Fine. |
| `WARN` | Works, but needs a person soon or is a choice not made yet: a key or certificate expiring within 30 days, no nightly dump yet, the approval key not set, an optional unit enabled but not listed. |
| `FAIL` | Broken, or unsafe: the database unreachable or not at the latest migration, an installed unit that differs from its rendering, a listed unit not enabled, an expired key or CA, a write key in a shared place, a web certificate that no longer matches its pin, an invalid asset map. |

Exit code 1 if any check fails, else 0. What it covers: configuration, the database (roles,
grants, migrations, time zone), the site, the SIEM's address, pinned CA and key (presence and
expiry), Kibana's key, write keys, the asset map, the LLM configuration and keys, the privacy
domains, the agents' files, the web certificate, the systemd units, whether the running services
run the deployed code, backups and restore drills, the committed web build, notices, and the
freshness of stored data.

Run it after every change and after every upgrade. Typical warnings on a fresh install are listed
in [troubleshooting.md](troubleshooting.md#doctor-on-a-fresh-install).

## Status at a glance

None of these sends a request to the SIEM:

```bash
uv run argus siem status          # kill switches, health state, breaker, today's budget, last requests
uv run argus collect status       # alerts and investigations stored, the backfill
uv run argus worker status        # the job queue, dossiers, checkpoints
uv run argus assess status        # assessments by assessor, proposals by outcome
uv run argus llm status           # the LLM kill switch, cost against the caps, cool-downs
uv run argus kibana state         # Kibana work stopped or not, paused classes, today's writes
uv run argus kibana sync status   # the read-back's state and findings
uv run argus backup list          # dumps kept and the last drills
uv run argus assets status        # the asset map's size and hash
uv run argus db current           # the database's migration revision
```

Live checks (small and read-only):

```bash
uv run argus siem probe           # one health probe (two tiny requests); stores the new state
uv run argus siem selftest        # probe, TLS pin, server version, the key's privileges
uv run argus kibana selftest      # Kibana's version and the reader key's privileges
uv run argus llm probe            # each enabled LLM provider: up, down, unauthorized, ...
```

## Logs

Every service logs to the systemd journal of your user:

```bash
journalctl --user -u argus-collector -f                     # follow one service
journalctl --user -u 'argus-*' --since '1 hour ago'         # all of ARGUS
journalctl --user -u argus-worker -p warning --since today  # warnings and errors only
journalctl --user -u argus-backup --since '2 days ago'      # what the last dumps said
```

Secrets are redacted before anything is logged. `logging.format: json` makes the lines
machine-readable for a log shipper.

If `journalctl --user` shows nothing, journald keeps no persistent storage on this machine (so it
does not split per-user journals). Turn it on:

```bash
sudo mkdir -p /var/log/journal
sudo systemctl restart systemd-journald
```

How long the journal is kept is the journal's own setting (`SystemMaxUse=` / `MaxRetentionSec=`
in `/etc/systemd/journald.conf`); `retention.app_logs` (14 days) is what ARGUS recommends.

## Backups

The database holds everything ARGUS knows that the SIEM does not: reviews, verdicts, cases,
approvals, the audit trail. Back it up.

```bash
uv run argus backup dump              # a manual dump now (the services keep running)
uv run argus backup drill             # restore the newest nightly dump into a scratch database and compare
uv run argus backup check             # a dump, then a restore drill of that very dump
uv run argus backup list              # what is kept, and the last drills
uv run argus backup prune             # what retention would remove; --apply removes it
```

- A dump is a consistent snapshot (`pg_dump --format=custom`) with a manifest: per-table
  fingerprints, size, SHA-256 and the migration revision. A **drill** restores it into a scratch
  database and compares every table's fingerprint with the manifest, then drops the scratch
  database. A dump no drill has restored is not yet a backup you know works.
- Dumps go to `data/backups/<kind>/argus-<UTC time>.dump` with a `.json` manifest beside it
  (folders mode 700, files 600). Kinds: `nightly`, `manual`, `migration`.
- What is kept: 7 nightly, 4 drill-verified, 5 migration and 5 manual dumps, none older than 35
  days except the newest one a drill restored (`backup.*`, [configuration.md](configuration.md#backup)).
  Every dump prunes afterwards.
- `pg_dump` runs in a throwaway container of the pinned PostgreSQL image, so backups need Docker
  and the owner's password in `.env`.

**Enable the schedule** (the nightly dump at 21:30 UTC and the weekly drill on Sundays at 22:00
UTC): add both timers to `units.run` and enable them, as in
[Services and timers](#services-and-timers). Doctor then fails when the newest nightly dump is
too old (`argus-backup.service did not run or failed`) or the last drill did not pass.

**Copy dumps off the machine.** A dump on the same disk does not survive the disk. Copy them to
another host, encrypted, for example nightly after the dump:

```bash
# each night, e.g. from cron at 22:30 UTC, after the dump:
rsync -a --chmod=D700,F600 ~/argus/data/backups/ backup@vault.example.org:argus-backups/
```

Dumps hold personal data (alerts, addresses, usernames) and are not encrypted by ARGUS; encrypt
them at rest at the destination, and keep the destination's retention no longer than your
policy allows (the purge's work is undone by a dump that is kept for ever).

**Restoring** is plain PostgreSQL (ARGUS has no restore command: the drill only restores into a
scratch database). See [upgrading.md](upgrading.md#rolling-back).

## Retention and the purge

ARGUS keeps personal data only as long as configured ([configuration.md](configuration.md#retention)):
raw alert sources 30 days, evidence snapshots 90 days after the newest review, investigations 90
days (`memory.window`). Open cases, pending approvals and the gold set are held. Audit events and
case records are never purged.

The purge is **off until you decide**; it cannot be undone except from a backup.

```bash
uv run argus purge plan                               # what would go, per class and table (read only)
uv run argus purge plan --output data/purge/plan.json # ... saved for review
uv run argus backup check                             # a fresh, verified backup first
uv run argus purge run --apply --expect data/purge/plan.json   # the reviewed purge
```

To purge every night afterwards, set `retention.scheduled: true` in `config/local.yaml`, add
`argus-purge.timer` to `units.run`, and enable it (it runs at 23:00 UTC, after the nightly dump).
Details: [the retention runbook](runbooks/retention.md).

## Kill switches

Each stops ARGUS's requests at once, without stopping a service:

```bash
# the SIEM: everything, or one component
uv run argus siem stop --reason "cluster maintenance"
uv run argus siem stop --component investigation --reason "too many wave queries"
uv run argus siem resume --reason "maintenance over"
uv run argus siem resume --component investigation --reason "..."

# the LLM gateway: no call to any model (assessments wait; nothing is lost)
uv run argus llm stop --reason "..."
uv run argus llm resume --reason "..."
```

SIEM components: `global`, `collector`, `enrichment`, `kibana`, `writeback`, `investigation`,
`freshness`, `cases`, `identity`. Health probes keep running under a stop, so ARGUS still knows
the SIEM's state. A **stop** may be thrown by anyone who can run ARGUS (and by the services
themselves); a **resume** needs the database owner's password (`ARGUS_DATABASE__OWNER_PASSWORD`,
in `.env` on a standard install). Every stop and resume is in the audit trail with its reason.

Kibana stops by itself on a 401 (all Kibana work) or pauses one write class on a 403; a person
lifts it after reading why:

```bash
uv run argus kibana state
uv run argus kibana resume --reason "key renewed"            # Kibana work
uv run argus kibana resume --class WC --reason "..."         # one write class
```

The last-resort stop is the key itself: invalidate it in Kibana (Stack Management → API keys).

## Rotating the API keys

The keys expire after 90 days; `argus doctor` warns 30 days ahead (`siem.api_key_expires`,
`kibana.reader_api_key_expires`). To rotate:

1. Make a new key with the **exact** request for your site (`argus init` prints it at step 6; it
   is also printed when you run `--force-key`).
2. Give it to ARGUS:

   ```bash
   uv run argus init --force-key
   ```

   Init prints the requests, asks for the new keys, checks them read-only and stores them in
   `.env`.
3. Record the new expiry dates in `config/local.yaml` (an interactive rerun keeps the old dates):

   ```yaml
   siem:
     api_key_expires: 2027-05-01
   kibana:
     reader_api_key_expires: 2027-05-01
   ```

4. Restart the services (each reads the key when it starts) and check:

   ```bash
   systemctl --user restart argus-collector argus-worker argus-web argus-assess
   uv run argus siem selftest && uv run argus kibana selftest && uv run argus doctor
   ```

5. Invalidate the **old** key by its id (both keys share the name `argus-reader`, so invalidating
   by name would also kill the new one). In Kibana Dev Tools:

   ```
   GET /_security/api_key?name=argus-reader
   DELETE /_security/api_key
   { "ids": ["<the old key's id>"] }
   ```

With a scripted install, put the new key in the file `siem.api_key_file` names and rerun
`argus init --force-key --answers answers.yaml` with the new `api_key_expires`.

## Certificates and the TLS pin

ARGUS trusts exactly one pinned CA file per service (`siem.ca_file`, `kibana.ca_file`) and checks
the host name on every connection. Doctor warns 30 days before the pinned CA expires and fails
once it has.

When the SIEM's CA is renewed (or the server moves to a certificate from another CA):

```bash
uv run argus init --force-trust     # pins the CA again (file, chain or system), checks a handshake
systemctl --user restart argus-collector argus-worker argus-web argus-assess
uv run argus siem selftest
```

A renewed **server** certificate from the same CA needs nothing: the pin is the CA.

The web's own certificate: if `web.tls_pin_sha256` is set, doctor fails when the served
certificate no longer matches it. After installing a new web certificate, update the pin
(`openssl x509 -in <cert> -outform der | sha256sum`) and restart `argus-web`.

## Health states and quiet hours

ARGUS's SIEM work follows the cluster's health (probed every minute by the collector):
**NORMAL** (everything), **CAUTION** (half the budget; no backfill, reconciliation, investigation
wave or discovery), **DEGRADED** (a tenth; collection, freshness and Kibana reads only), **STOP**
(probes only). Thresholds and details: [configuration.md](configuration.md#health-states).

```bash
uv run argus siem status
```

shows the state, why (`disk_caution`, `search_rejections`, `probe_stale`, `auth_failed`, ...) and
since when. After DEGRADED or STOP the budget comes back over 40 minutes.

**Quiet hours** (`site.quiet_hours`, default 00:00–01:30 UTC): the time your cluster creates the
day's indices and deletes old ones. ARGUS asks nothing optional then: discovery and the
freshness readings wait (`... waits for the end of the quiet hours (01:30 UTC)`), and so do the
investigation wave, the extra evidence templates, the case watch and the sign-in lookups
(`signins: waiting for the end of the quiet hours (01:30 UTC)`); Kibana writes never fall in
them. Collecting new alerts goes on. Set the window to your cluster's own maintenance time in
`config/site.yaml`.

## Users and sessions

```bash
uv run argus user add bob --name "Bob Example"
uv run argus user grant bob manage_cases
uv run argus user revoke bob manage_cases
uv run argus user disable bob            # their sessions stop at once
uv run argus user list
uv run argus sessions end-all            # end every open session (e.g. after a suspected compromise)
```

See [web-ui-guide.md](web-ui-guide.md#users-and-capabilities).

## A daily and weekly routine

**Daily (2 minutes):**

```bash
uv run argus doctor | grep -v '^PASS'     # anything not PASS
uv run argus siem status | head -20
```

**Weekly:**

- `uv run argus backup list`: a nightly dump every day, a drill this week.
- Copy dumps off the machine (if not automated).
- `uv run argus llm status`: what the models cost this month.
- Read the weekly report and the tuning report in the Inbox (*AI & reports*).
- Check `git log` of the upstream repository for a new release ([upgrading.md](upgrading.md)).
