# Upgrading

How to move an installation to a newer version of ARGUS, and back if something goes wrong. The
whole procedure takes about ten minutes; ARGUS stops taking in alerts only while the services
restart (a minute), and the collector's reconciliation and backfill catch up on anything that
arrived meanwhile.

**The strategy in one line:** read the release notes → a verified backup → pull → migrate →
reinstall the units → restart → doctor → timers back on. Keep the dump until the new version has
run for a few days.

---

## 0. Before you start

```bash
cd ~/argus
git status --short          # your checkout should have no local changes to tracked files
git describe --tags         # the version you run now: note it for a rollback
uv run argus doctor         # start from a clean state: fix any FAIL first
uv run argus db current     # the database's migration revision now
```

Your own files (`.env`, `config/local.yaml`, `config/site.yaml`, `config/llm.local.yaml`,
`data/`) are not tracked by git, so a pull never touches them. If you edited a tracked file (for
example `config/llm.yaml`), commit it on a local branch first or `git stash` it.

Read the release notes ([CHANGELOG.md](../CHANGELOG.md)) for the new version: a new setting, a
change to the key's role, or a step to take by hand is announced there.

Avoid 00:00–01:30 UTC (the SIEM's quiet hours) so the first minutes after the restart are not
also the hours in which ARGUS waits.

## 1. Stop the timers

A oneshot timer that fires during the upgrade would run half-updated code:

```bash
systemctl --user list-timers 'argus-*'
systemctl --user stop 'argus-*.timer'
```

(`stop` only pauses them; they stay enabled.)

## 2. A verified backup

```bash
uv run argus backup check
```

`backup check` takes a dump and restores that very dump into a scratch database, comparing every
table's fingerprint: a backup known to restore. It ends with the dump's path; note it. The
services keep running.

(To make `argus db upgrade` always dump first by itself, set
`ARGUS_BACKUP__BEFORE_MIGRATION=true` in `.env`. It is off by default.)

## 3. Get the new version

```bash
git fetch --tags
git checkout v0.2.0         # the release tag you are moving to (or: git pull on main)
uv sync                     # the locked dependencies of that version
uv run argus --version
```

## 4. Migrate the database

```bash
uv run argus db upgrade     # applies every migration up to head
uv run argus db check       # exit 0: the database is at head and matches the code
```

Migrations run as the schema owner and may take a while on a large database. If the release
notes say "stop the services first", stop them before this step
(`systemctl --user stop argus-collector argus-worker argus-web argus-assess`); step 6 starts them
again.

If `argus db bootstrap` is named in the release notes (a new database role or grant), run it
before the upgrade: `uv run argus db bootstrap`.

## 5. Reinstall the units

The unit templates may have changed. See what would change, then write it:

```bash
uv run argus units install                  # a diff per unit (dry run)
uv run argus units install --apply --reload
```

## 6. Restart the services

```bash
systemctl --user restart argus-collector argus-worker argus-web argus-assess
# and any optional service you run, e.g.:
systemctl --user restart argus-kibana-sync
systemctl --user status 'argus-*' --no-pager
```

## 7. Check

```bash
uv run argus doctor
uv run argus siem selftest
journalctl --user -u 'argus-*' --since '5 minutes ago' -p warning --no-pager
```

Doctor's `services run the deployed code` line warns if a service still runs code from before the
pull (restart it). Open the Inbox: if the browser shows an old page, reload it (the app reloads
itself on its next navigation when its build changed).

## 8. Timers back on

```bash
systemctl --user start $(systemctl --user list-unit-files 'argus-*.timer' --state=enabled --no-legend | awk '{print $1}')
systemctl --user list-timers 'argus-*'
```

Keep the dump from step 2 until the new version has run for a few days (`backup.keep_manual`
keeps the last 5 manual dumps).

---

## Rolling back

If the new version misbehaves:

### A. Code only (no migration ran, or the migrations are backwards compatible)

```bash
systemctl --user stop 'argus-*.timer'
git checkout v0.1.0            # the version noted in step 0
uv sync
uv run argus units install --apply --reload
systemctl --user restart argus-collector argus-worker argus-web argus-assess
uv run argus doctor
```

If doctor says the database is ahead of the code (`migrations`), go on with B or C.

### B. Downgrade the migrations

Each migration has a downgrade. Run it **with the new code still checked out** (it holds the
downgrade steps), down to the revision you noted in step 0:

```bash
systemctl --user stop argus-collector argus-worker argus-web argus-assess
uv run argus db downgrade --yes <revision from step 0>
git checkout v0.1.0 && uv sync
uv run argus units install --apply --reload
systemctl --user start argus-collector argus-worker argus-web argus-assess
uv run argus doctor
```

A downgrade can drop tables or columns the new version added, and their data with them.

### C. Restore the dump

ARGUS has no restore command for the live database (the drill only restores into a scratch
database). Restoring is plain PostgreSQL, run inside the database container. This **replaces the
whole database** with the dump: everything ARGUS took in since the dump is gone from ARGUS (the
collector backfills alerts from the SIEM again, within `history.window`; reviews made since are
lost).

```bash
cd ~/argus
systemctl --user stop 'argus-*.timer'
systemctl --user stop argus-collector argus-worker argus-web argus-assess argus-kibana-sync

uv run argus backup list                 # pick the dump, e.g. from step 2
DUMP=data/backups/manual/argus-20270115T093000123456Z.dump

set -a; . ./.env; set +a                 # the owner's name and the database name
CONTAINER=${COMPOSE_DB_CONTAINER:-argus-db}
docker exec "$CONTAINER" psql -U "$ARGUS_DATABASE__OWNER_USER" -d postgres \
  -c "DROP DATABASE \"$ARGUS_DATABASE__NAME\" WITH (FORCE)" \
  -c "CREATE DATABASE \"$ARGUS_DATABASE__NAME\""
docker exec -i "$CONTAINER" pg_restore -U "$ARGUS_DATABASE__OWNER_USER" \
  -d "$ARGUS_DATABASE__NAME" --no-owner --exit-on-error < "$DUMP"

git checkout v0.1.0 && uv sync           # the code that matches the dump's revision
uv run argus db bootstrap                # the roles' passwords and grants
uv run argus db check
uv run argus units install --apply --reload
systemctl --user start argus-collector argus-worker argus-web argus-assess
uv run argus doctor
```

The dump's manifest (`.json` beside it) names the migration revision it was taken at: check out
the release whose head is that revision.

Practise this once on a spare machine before you need it.
