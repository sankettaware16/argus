# Runbook: the retention purge (Q-A4, D-028)

For the operator of the ARGUS machine. The purge removes the personal data ARGUS keeps once it
is older than its period. It is local only: nothing here sends a request to the SIEM. **A purge
cannot be undone** except by restoring a backup, so the first production purge and its schedule
are two separate approvals of the user's (D-109, DQ27).

## 1. What goes, and when

| Class | Setting (default) | What the purge does |
|---|---|---|
| `raw_source` | `retention.raw_source` (30d) | empties a normalized alert's raw `_source` (`{}`, `raw_purged_at`); its normalized form stays |
| `quarantine` | `retention.quarantine` (30d) | empties a quarantined alert's raw `_source` |
| `evidence` | `retention.evidence` (90d) | empties the evidence snapshots of an investigation whose newest decision is a review of its current version older than the period (a follow-up, or a version changed since the review, keeps them); what was asked, its status, counts and hash stay |
| `memory` | `memory.window` (90d) | removes an investigation whole (alerts, entity index, dossiers, signals, evidence, reviews, assessments, jobs, write-back rows, the local model's shadow answers) once its day, every alert and every review are past the window and no work on it is unfinished (a job or assessment waiting or running, a write-back planned or paused: the plan counts these as "waiting"); recounts the entity index; removes expired alerts in no investigation, threat-intel answers and weekly tuning reports (they name dominant values) older than the window |
| `app_logs` | `retention.app_logs` (14d) | not the database: ARGUS logs to the systemd journal, which only root can trim (section 4) |

- An alert's age is the earlier of when the SIEM wrote it (`detected_at`) and when ARGUS stored it.
- **No period is shorter than `history.window` in effect.** The collector may read such an alert
  again; the plan says "(history.window: never shorter)" where that applies.
- **Holds** keep everything of an investigation: the gold set; an active member of a case that
  is not closed; a case (or merge target) with an approval request that has not expired. The
  investigation a held one continues keeps its row (its raw data and snapshots still go), so
  the held investigation's link to it stays.
- **Never purged in Phase 3:** the audit trail, the case records (cases, events, members,
  notes, openings, approvals, the outbox, the action ledger), and **entity notes** (what people
  wrote about a host or user on purpose, append-only; kept like a case's notes, even after the
  entity's investigations are gone). An investigation a case record names keeps its rows (only
  its raw data and snapshots go, once no hold applies). Every plan prints this list.
- Once purged, a value never comes back or misleads: the collector keeps an emptied raw
  `_source` empty; a purged snapshot is never reused, and its task is never asked of the SIEM
  again (recorded as not checked: "its log rows were deleted after ARGUS's retention period");
  `argus worker rederive` skips the investigation, and the worker finishes any job of it as
  skipped, keeping the stored dossier; its report is shown as stored ("the log rows behind its
  evidence were deleted after ARGUS's retention period, so its findings are shown as they were
  stored").
- **Backups** still hold purged rows until they are pruned. No dump older than `backup.max_age`
  (35 days) is kept, whatever its kind (the nightly prune after each dump removes it); the one
  exception is the newest dump a drill restored, so that there is always one to restore from.
  So purged data lives on disk at most about 35 days after the purge, while the nightly dumps
  and weekly drills run (doctor warns when the drill is older than 8 days).

## 2. Who may do what

The purge logs in as the owner (like `argus db`) and runs every statement after
`SET LOCAL ROLE argus_purge`. `argus db bootstrap` makes `argus_purge` (no login, a member of
nothing); migration 0030 grants it exactly `argus.db.roles.PURGE_GRANTS`. It cannot touch the
audit trail or the case records, disable a trigger or change `session_replication_role`. Each
run checks the role first and refuses to run if it holds more or less than that.

## 3. Commands

```
uv run argus purge plan                          # the counts now, per class and table (read only)
uv run argus purge plan --output data/purge/plan.json   # ... and saved for the run
uv run argus purge run                           # the same dry run
uv run argus backup check                        # a dump and a restore drill of it
uv run argus purge run --apply --expect data/purge/plan.json   # the reviewed purge
```

`--apply` needs either `--expect PLAN` or `--scheduled`:

- `--expect PLAN`: the run counts again **at the plan's own time** and refuses unless every
  count equals the plan's (a hold that changed, a row that arrived, other periods: make a new
  plan). It also needs a restore drill that passed within the last 24 hours.
- `--scheduled` (what `argus-purge.timer` runs, daily at 04:30 IST after the nightly dump):
  refused while `retention.scheduled` is off; refused unless the periods configured now are
  exactly those of the last reviewed purge (`--expect`) that succeeded, so a changed period
  (or a typo in `.env`) never deletes unreviewed: run a reviewed plan with the new periods
  first; and refused unless the last drill passed within 8 days. A drill record dated in the
  future (more than 5 minutes ahead) proves nothing.

After deleting, the run compares what it did with its own counts, and checks **row by row**
that every row held before the run and still held after it is as it was: the held
investigations and their `continues` links, their alerts' raw data, their snapshots ("every
count as planned; the held rows are untouched"). Rows ARGUS adds to a held investigation
meanwhile (a new alert, a new member) are not a change. It exits 1 otherwise, naming what
changed. Every `--apply` (done, failed or refused, a usage error included) is an audit event
`purge.run` with the counts. Each batch commits on its own: a run that stops leaves what it
did done, and the next one goes on.

Under the custody layout (Q-A5) the units are `deploy/custody/units/argus-purge.service` and
`.timer`: root runs it with the owner's credential, like the backups
(`sudo systemctl enable --now argus-purge.timer` once the schedule is approved).

## 4. Production steps (the user's, D-109)

1. Checkpoint: `uv run argus db bootstrap` (makes `argus_purge`), then `uv run argus db
   upgrade` (0030; it refuses without the role).
2. The first purge: `uv run argus purge plan --output data/purge/plan.json`; review the counts
   (the oldest raw `_source` turns 30 days in early November, the oldest alerts reach
   `memory.window` in early January); `uv run argus backup check`; then
   `uv run argus purge run --apply --expect data/purge/plan.json`. Check the output says every
   count as planned, then spot-check a held investigation in the Inbox.
3. The schedule, as its own approval, after step 2 succeeded (the schedule continues its
   periods): `ARGUS_RETENTION__SCHEDULED=true` in production's `.env` (or `argus.env` under
   custody), `deploy/systemd/install.sh --apply --reload`, `systemctl --user enable --now
   argus-purge.timer` (under custody: `sudo systemctl enable --now argus-purge.timer`), and
   `argus-purge.timer` added to `units.run` in `config/local.yaml` (D-295) and changed from
   `off` to `run` in `argus.ops.custody.UNITS`. It relies on the weekly drill (`argus-backup-drill.timer`).
4. App logs, as root: a journald drop-in, for example
   `/etc/systemd/journald.conf.d/argus-retention.conf` with `[Journal]` and
   `MaxRetentionSec=14day`, then `systemctl restart systemd-journald`. It applies to the whole
   machine's journal, not only ARGUS's; the user decides (or folds it into Q-A5's root script).
