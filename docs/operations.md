# Operations

Day-to-day running of an ARGUS installation. **Most of it is done in the web app** by an
administrator: settings, people, keys, and checking that data arrives. The server is for the few
jobs the app does not do (upgrades, restoring a backup, the AI providers' keys, the asset map
file) and for recovery when the web itself is down. Server commands are run from the checkout as
the user that owns the installation.

**Contents**

- [In the app](#in-the-app)
- [What stays on the server](#what-stays-on-the-server)
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

## In the app

Install with `./install.sh` and finish the first-time setup in the browser
([install.md](install.md#install-in-two-steps)). After that, an administrator does the routine
work here:

| To… | In the app |
|---|---|
| Change a setting: the SIEM's address or key, Kibana, outside lookups (VirusTotal, Shodan, Censys), notices, retention periods, backup counts, sign-in, the incident engine, logging | **More → Administration → Settings** ([configuration.md](configuration.md#changing-a-setting-in-the-app)) |
| Add a person, change a role, send a new password link, switch an account off, end someone's sessions | **More → Administration → Users and roles** ([web-ui-guide.md](web-ui-guide.md#users-and-capabilities)) |
| See whether alerts are arriving, the SIEM's state, the Kibana read-back, any coverage gaps | **More → System health**, and the status in the page header |
| See what the AI investigator did and what it cost | **More → ARGUS quality** |
| Connect ARGUS to its SIEM for the first time | the **Finish the first-time setup** card on **Today** (or `/app/setup`) |

How a change in **Settings** is made:

- Every setting is shown with its help and its current value, grouped in sections. Settings that
  are fixed on purpose (the SIEM load budget and its lanes, the web's own address and certificate)
  are shown read-only.
- Three levels of care. Most changes need only an administrator. Keys, addresses, sign-in and
  allowed hosts need your password confirmed again within the last five minutes. Anything that
  lets ARGUS **write to the SIEM** (Kibana case posting, write classes, write-back) also asks you
  to type *let ARGUS write to the SIEM*.
- The service `argus-admin` checks each change again, writes it to the file where that setting
  lives, restarts only the services that read it and reports back on the page within seconds. If a
  restarted service does not come back, it puts the previous files back and the change shows as
  **rolled back**.
- A key you paste is sealed the moment it reaches ARGUS; only `argus-admin` can open it. It is
  never shown again, only replaced.
- Every save is in the audit trail. On the server, `uv run argus admin status` lists the latest
  changes with who made them, when, and what became of each, and when `argus-admin` was last seen.

If `argus-admin` is not running, the Settings page says so and saved changes wait until it runs.

## What stays on the server

A short list, by design:

- **Upgrading** to a new version: [upgrading.md](upgrading.md).
- **The AI providers' keys and cost caps**: `config/llm.local.yaml` and its keys file
  ([llm.md](llm.md)). They are not in Settings yet.
- **The asset map file**: copy it to the server and import it with `uv run argus assets import`
  ([llm.md](llm.md#10-the-asset-map)). Settings holds only its path.
- **Switching an optional timer on or off** (the purge, notices, the daily and weekly reports, the
  Kibana writer): `units.run` and `systemctl` ([below](#services-and-timers)).
- **Backups by hand and restoring one**, and the purge: [below](#backups).
- **The kill switches**: [below](#kill-switches).
- **The approval signing key** and the ELK sign-in secret
  ([web-ui-guide.md](web-ui-guide.md#approvals)).
- **The emergency (break-glass) account**: `uv run argus break-glass`.
- **Custody and other `sudo` steps** (lingering, journald storage, the hardened layout).
- **Uninstalling.**
- **Recovery when the web itself is down**: `uv run argus doctor`,
  `systemctl --user status 'argus-*'`, `journalctl --user -u argus-admin`, and
  [troubleshooting.md](troubleshooting.md).

The rest of this page is the reference for those server jobs.

## Services and timers

The unit files in `deploy/systemd/` are **templates**. `argus units install` renders them for
this installation (the checkout, the uv, the web's settings from `units` in
`config/local.yaml`) and writes them to `~/.config/systemd/user/`. `./install.sh` and the
first-time setup install and start what a new installation runs; anything else is switched on
on purpose.

| Unit | Kind | Runs | Default |
|---|---|---|---|
| `argus-web.service` | service | the web app, over HTTPS on the address given at install, or on `127.0.0.1:8765` | on (from the install) |
| `argus-admin.service` | service | applies the settings changed in the app, and runs the first-time setup | on (from the install) |
| `argus-collector.service` | service | the collector: health probe and new alerts every minute, workflow states every 15 min, reconciliation hourly, backfill | on (after the setup) |
| `argus-worker.service` | service | evidence and dossiers for queued investigations | on (after the setup) |
| `argus-assess.service` | service | proposals, case suggestions, incident reports, the AI investigator (with keys), weekly tuning | on (after the setup) |
| `argus-kibana-sync.service` | service | the read-back of Kibana cases ([kibana.md](kibana.md#the-read-back)) | on when Kibana is set up |
| `argus-backup.timer` | timer | `argus backup dump --kind nightly`, daily 21:30 UTC | on, unless declined |
| `argus-backup-drill.timer` | timer | `argus backup drill --latest`, Sundays 22:00 UTC | on, unless declined |
| `argus-risk.timer` | timer | `argus risk run --once`, the incident engine's pass, every 10 minutes | off (listed when you choose it) |
| `argus-risk-check.timer` | timer | `argus risk check --once`, the incident engine's targeted checks, every 10 minutes | off (listed when you choose it) |
| `argus-report-daily.timer` | timer | `argus report daily`, 02:15 UTC | off |
| `argus-report-weekly.timer` | timer | `argus report weekly`, Mondays 02:20 UTC | off |
| `argus-purge.timer` | timer | `argus purge run --apply --scheduled`, 23:00 UTC | off (needs `retention.scheduled`) |
| `argus-notices.timer` | timer | `argus notices run`, every 10 minutes | off (needs notices configured) |
| `argus-case-team.timer` | timer | the case team's posts to Kibana (a write) | off |
| `argus-writer.service` | service | Kibana writes from the outbox (a write) | off |

(`argus-soak-*` units also ship; they belong to the project's own release checks and stay off.)

**`units.run` is the list of what this installation runs.** It is a server file setting, not in
the app. Doctor fails while a listed unit is not enabled, warns when an unlisted optional unit is
enabled, and fails when a unit that waits for its own step (purge, notices, reports, writer) is
enabled without being listed. So switching a unit on is two changes:

```yaml
# config/local.yaml
units:
  run:
    - argus-web.service
    - argus-admin.service
    - argus-collector.service
    - argus-worker.service
    - argus-assess.service
    - argus-backup.timer
    - argus-backup-drill.timer
    - argus-report-daily.timer        # the new one
```

```bash
systemctl --user enable --now argus-report-daily.timer
systemctl --user list-timers 'argus-*'
uv run argus doctor
```

List the **timer**, not its service: a timer's service is started by the timer and never enabled
itself. A setting such as `notices.enabled` or `retention.scheduled` can be changed in Settings;
the timer that acts on it is still switched on here.

**Look at a rendered unit, and reinstall after a change**

```bash
uv run argus units show argus-web.service      # one unit as this installation renders it
uv run argus units install                     # what would change: a diff per unit (dry run)
uv run argus units install --apply --reload    # write the changed units, then daemon-reload
systemctl --user restart argus-web             # restart a changed service
```

Never edit the installed copies or add drop-ins: doctor compares the installed units with their
rendering byte for byte and fails on a difference or a drop-in. Change `units` in
`config/local.yaml` (or the template in `deploy/systemd/`) and install again. (A change in
Settings that the web unit is rendered with, such as the allowed hosts, is rendered by
`argus-admin` itself.)

**Start, stop, restart**

```bash
systemctl --user start  argus-collector argus-worker argus-web argus-assess argus-admin
systemctl --user stop   argus-collector argus-worker argus-web argus-assess argus-admin
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

Read-only health checks of every part, run on the server. It is the first thing to run when the
app itself does not open. It sends **no request** to the SIEM, Kibana or any LLM provider (those
have their own live checks: `argus siem selftest`, `argus kibana selftest`, `argus llm probe`).

| Label | Meaning |
|---|---|
| `PASS` | Fine. |
| `WARN` | Works, but needs a person soon or is a choice not made yet: a key or certificate expiring within 30 days, no nightly dump yet, the approval key not set, an optional unit enabled but not listed, an old `web.classic` setting still in a file. |
| `FAIL` | Broken, or unsafe: the database unreachable or not at the latest migration, an installed unit that differs from its rendering, a listed unit not enabled, an expired key or CA, a write key in a shared place, a web certificate that no longer matches its pin, an invalid asset map. |

Exit code 1 if any check fails, else 0. What it covers: configuration, the database (roles,
grants, migrations, time zone), the site, the SIEM's address, pinned CA and key (presence and
expiry), Kibana's key, write keys, the asset map, the LLM configuration and keys, the privacy
domains, the agents' files, the web certificate, the systemd units, whether the running services
run the deployed code, backups and restore drills, the committed web build, notices, and the
freshness of stored data.

Run it after every upgrade and after any change made on the server. Typical warnings on a fresh
install are listed in [troubleshooting.md](troubleshooting.md#doctor-on-a-fresh-install).

## Status at a glance

In the app, **System health** shows the SIEM's state and why, how far alerts have been collected
and history loaded, what is stored and waiting, the Kibana read-back and any coverage gaps. The
status in the page header opens to the same, and to the AI cost for an administrator.

On the server, more detail. None of these sends a request to the SIEM:

```bash
uv run argus siem status          # kill switches, health state, breaker, today's budget per lane, last requests
uv run argus collect status       # alerts and investigations stored, the backfill
uv run argus worker status        # the job queue, dossiers, checkpoints
uv run argus assess status        # assessments by assessor, proposals by outcome
uv run argus llm status           # the LLM kill switch, cost against the caps, cool-downs
uv run argus kibana state         # Kibana work stopped or not, paused classes, today's writes
uv run argus kibana sync status   # the read-back's state and findings
uv run argus backup list          # dumps kept and the last drills
uv run argus assets status        # the asset map's size and hash
uv run argus admin status         # argus-admin's heartbeat and the latest changes made in the app
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
journalctl --user -u argus-admin -n 50                      # what the last setting changes and the setup did
journalctl --user -u argus-backup --since '2 days ago'      # what the last dumps said
```

Secrets are redacted before anything is logged. The log level and format are in **Settings →
Logging**; `json` makes the lines machine-readable for a log shipper.

If `journalctl --user` shows nothing, journald keeps no persistent storage on this machine (so it
does not split per-user journals). Turn it on (an administrator, with `sudo`):

```bash
sudo mkdir -p /var/log/journal
sudo systemctl restart systemd-journald
```

How long the journal is kept is the journal's own setting (`SystemMaxUse=` / `MaxRetentionSec=`
in `/etc/systemd/journald.conf`); `retention.app_logs` (14 days) is what ARGUS recommends.

## Backups

The database holds everything ARGUS knows that the SIEM does not: reviews, verdicts, cases,
approvals, the audit trail. Back it up.

The nightly dump and the weekly restore drill run by themselves once their timers are on (the
install turns them on unless you declined). **Settings → Backups** holds how many dumps are kept,
their folder, and whether a dump is taken before every migration. Everything else is on the
server:

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

**The schedule** (the nightly dump at 21:30 UTC and the weekly drill on Sundays at 22:00 UTC): if
you declined it at install, add both timers to `units.run` and enable them, as in
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

**Restoring** is plain PostgreSQL, on the server (ARGUS has no restore command: the drill only
restores into a scratch database). See [upgrading.md](upgrading.md#rolling-back).

## Retention and the purge

ARGUS keeps personal data only as long as configured ([configuration.md](configuration.md#retention)):
raw alert sources 30 days, evidence snapshots 90 days after the newest review, investigations 90
days (`memory.window`). Open cases, pending approvals and the gold set are held. Audit events and
case records are never purged. The periods are in **Settings → Retention** (`memory.window` is a
file setting).

The purge is **off until you decide**; it cannot be undone except from a backup. It is run on the
server:

```bash
uv run argus purge plan                               # what would go, per class and table (read only)
uv run argus purge plan --output data/purge/plan.json # ... saved for review
uv run argus backup check                             # a fresh, verified backup first
uv run argus purge run --apply --expect data/purge/plan.json   # the reviewed purge
```

To purge every night afterwards, switch on `retention.scheduled` in **Settings → Retention**, then add `argus-purge.timer` to `units.run` and enable it (it runs at
23:00 UTC, after the nightly dump). Details: [the retention runbook](runbooks/retention.md).

## Kill switches

Server only. Each stops ARGUS's requests at once, without stopping a service:

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
the SIEM's state (System health shows it). A **stop** may be thrown by anyone who can run ARGUS
(and by the services themselves); a **resume** needs the database owner's password
(`ARGUS_DATABASE__OWNER_PASSWORD`, in `.env` on a standard install). Every stop and resume is in
the audit trail with its reason.

Kibana stops by itself on a 401 (all Kibana work) or pauses one write class on a 403; a person
lifts it after reading why:

```bash
uv run argus kibana state
uv run argus kibana resume --reason "key renewed"            # Kibana work
uv run argus kibana resume --class WC --reason "..."         # one write class
```

The last-resort stop is the key itself: invalidate it in Kibana (Stack Management → API keys).

## Rotating the API keys

The keys expire after 90 days; doctor warns 30 days ahead (`siem.api_key_expires`,
`kibana.reader_api_key_expires`). To rotate:

1. Make a new key with the **exact** request for your site ([install.md](install.md#32-the-api-keys-argus-asks-for)
   has it; `argus init --force-key` also prints it for your site).
2. **In the app:** Settings → **SIEM** → paste the new key into *API key* and set *API key
   expires*; save. (For Kibana's reader key: Settings → **Kibana** → *Reader API key*.) Confirm your password when
   asked. `argus-admin` restarts the services that read the key; if one does not come back, the
   old key is put back and the change shows as rolled back.
3. **Check:** System health shows the SIEM as reachable, checked within the last minutes. The
   app stores the key without testing its privileges, so on the server run the full check:

   ```bash
   uv run argus siem selftest && uv run argus kibana selftest
   ```

4. Invalidate the **old** key by its id (both keys share the name `argus-reader`, so invalidating
   by name would also kill the new one). In Kibana Dev Tools:

   ```
   GET /_security/api_key?name=argus-reader
   DELETE /_security/api_key
   { "ids": ["<the old key's id>"] }
   ```

**From the server instead** (or when the web is down): `uv run argus init --force-key` prints
the requests, asks for the new keys, checks them read-only and stores them in `.env`. Record the
new expiry dates in Settings (or in `config/local.yaml`), then restart the services
(`systemctl --user restart argus-collector argus-worker argus-web argus-assess`) and run the
self-tests above. With a scripted install, put the new key in the file `siem.api_key_file` names
and rerun `argus init --force-key --answers answers.yaml` with the new `api_key_expires`.

## Certificates and the TLS pin

ARGUS trusts exactly one pinned CA file per service (`siem.ca_file`, `kibana.ca_file`) and checks
the host name on every connection. Doctor warns 30 days before the pinned CA expires and fails
once it has.

When the SIEM's CA is renewed (or the server moves to a certificate from another CA), pin it
again on the server; it checks a handshake before it keeps anything:

```bash
uv run argus init --force-trust     # pins the CA again (file, chain or system), checks a handshake
systemctl --user restart argus-collector argus-worker argus-web argus-assess
uv run argus siem selftest
```

A renewed **server** certificate from the same CA needs nothing: the pin is the CA.

The web's own certificate: if `web.tls_pin_sha256` is set, doctor fails when the served
certificate no longer matches it. After installing a new web certificate, update the pin
(`openssl x509 -in <cert> -outform der | sha256sum`) in `config/local.yaml` and restart
`argus-web`.

## Health states and quiet hours

ARGUS's SIEM work follows the cluster's health (probed every minute by the collector):
**NORMAL** (everything), **CAUTION** (half the budget; no backfill, reconciliation, investigation
wave or discovery), **DEGRADED** (a tenth; collection, freshness and Kibana reads only), **STOP**
(probes only). Thresholds and details: [configuration.md](configuration.md#health-states).

**System health** in the app shows the state and its reasons (`disk_caution`,
`search_rejections`, `probe_stale`, `auth_failed`, ...) and when it was last checked; on the
server, `uv run argus siem status` adds since when, the breaker and each lane's spending. After
DEGRADED or STOP the budget comes back over 40 minutes.

**Quiet hours** (`site.quiet_hours`, default 00:00–01:30 UTC): the time your cluster creates the
day's indices and deletes old ones. ARGUS asks nothing optional then: discovery and the
freshness readings wait (`... waits for the end of the quiet hours (01:30 UTC)`), and so do the
investigation wave, the extra evidence templates, the case watch and the sign-in lookups
(`signins: waiting for the end of the quiet hours (01:30 UTC)`); Kibana writes never fall in
them. Collecting new alerts goes on. Set the window to your cluster's own maintenance time in
**Settings → Organisation and data sources** (`site.quiet_hours`; the Settings search box finds a setting by its name).

## Users and sessions

People are managed in **More → Administration → Users and roles**: add a person (they get a
one-time link to set their own password), change a role, send a new password link, switch an
account off or on, end one person's sessions. See
[web-ui-guide.md](web-ui-guide.md#users-and-capabilities).

From the server, for recovery or scripting:

```bash
uv run argus user list
uv run argus user add bob --name "Bob Example"
uv run argus user grant bob manage_cases
uv run argus user revoke bob manage_cases
uv run argus user disable bob            # their sessions stop at once
uv run argus sessions end-all            # end every open session (e.g. after a suspected compromise)
```

Ending **every** session at once is only on the server.

## A daily and weekly routine

**Daily (2 minutes), in the app:** System health (or the status in the header) says the SIEM is
reachable and alerts arrive; Today is where the reviewers start.

**Weekly:**

- In the app: the weekly report and the rule tuning report (**Reports**, **More → Rule
  tuning**); the AI's cost this month (**More → ARGUS quality**).
- On the server: `uv run argus doctor | grep -v '^PASS'` (anything not PASS) and
  `uv run argus backup list` (a nightly dump every day, a drill this week).
- Copy dumps off the machine (if not automated).
- Check the upstream repository for a new release ([upgrading.md](upgrading.md)).
