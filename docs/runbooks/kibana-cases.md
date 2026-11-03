# Runbook: the case writer (Q-D4)

> **Retired for incident cases (D-271, 2026-10-30):** the case team (AR8–AR10,
> [kibana-case-team.md](kibana-case-team.md)) is the one way ARGUS writes cases — it opens a case
> on a person's confirm and corrects it in place. W1 (create) and W2 (update) have no canary, no
> ramp and no cases-writer key to mint; W3 (close) stays a person's action. The text below stays
> as the description of the retired classes and of the renderer the team shares
> (`argus.writer.render`); WA (alert status write-back) is in [writeback.md](writeback.md).

`argus-writer` is the one process that sends ARGUS's case writes to Kibana: it drains the outbox
(`kibana_outbox`) class by class through the Kibana lane (the gateway's `kibana_write` lane: its own budget, D-235).
Plan §7.1; code in `src/argus/writer/`. **Every class is off** (`kibana.write_classes` empty, the
unit disabled); nothing here has been sent to the SIEM (D-109).

| Class | What it writes | Ramp unit |
|---|---|---|
| W1 | create a case, its opening comment, representative alerts (first and latest of each investigation, with their concrete index; 5 alerts per case at the canary, up to 200 after) | a case |
| W2 | status, severity and ARGUS's own tags of an existing case, each with its comment; the approved undo of such a write | a change |
| W3 | an approved closure: status `closed` and the reason tags, then the closing comment naming the approver | a closure |

What it never does: delete, touch assignees, observables, custom fields or `settings` after the
create (Sync alerts is off at the create and is never sent again), write to a case ARGUS did not
make, send text from a log, a model or a person's comment. Text is built by `writer/render.py`
only: values fenced and defanged, names escaped, ARGUS's own link the only link.

## The sending rules

- The case is read again first, and again after any wait for a gap between writes (a minute
  between alert calls is long enough for a person to switch Sync alerts on). A PATCH sends its
  latest version, **keeps every tag a person added**, leaves a severity a person edited alone
  and never reverts a status a person changed. An edit the read-back has not polled yet is
  caught by comparing with what ARGUS has seen or set (the row's before-image, the mirror's last
  poll, the latest write it read back): a severity outside those stays as the person left it, and
  a tag of ARGUS's own kind (`argus:owner:...`, `argus:state:...`) that a person added or removed
  holds the write until the poll has seen it (the poll then pauses the case for a person).
- Sync alerts on in Kibana: nothing is sent for a status change or an attach, and the case gets a
  finding ("Needs attention"). A case whose changes ARGUS paused (a person edited ARGUS's tags)
  is not written to either.
- `sending` is committed at the last step before the request leaves, and the request goes once.
  Nothing is retried. A 409 is "not changed": the row goes to `conflict` for a person.
- A write whose outcome is unknown (timeout, reset, 5xx, a 2xx answer that cannot be read or is
  not what the write should have produced, a connection that was never made) is **ambiguous**
  and is looked for at 2, 5, 15 and 30 minutes (a create by its `argus:case:<uuid>` tag and
  `reporters=argus`, each match made by `argus` with the payload; a change by reading the case
  and planning again; a comment by the newest comments; an attachment by the alerts'
  `case_ids`). One match makes it
  verified. If the fourth finds nothing while Kibana answers, the row reads `resend? ...`:
  `argus kibana plan --class W1` lists it, and it needs a person's approval (kind `resend`,
  bound to that write and that send; the person who asked cannot approve, under another account
  either) before it is sent once more. A lost opening comment, attachment or compensating write
  is closed as `lost` and not sent again. A refused connection takes the same road (no write
  is sent twice without a person), and the run stops there; a mismatching or unreadable 2xx
  answer also pauses the class and raises a finding, while the looks adopt the case that landed.
  A look that cannot be made (Kibana down) is postponed and does not count.
- Every write is read back. A mismatch pauses the class, the row goes to `conflict`, the case
  gets a finding. A timeout is charged to the Kibana write lane in full (15 s of a 200 ms-a-minute
  lane): after one, the lane is in debt for about 75 minutes, so the next write waits.
- Limits: a case write every 3 s (waited out), 10 a run, 50 a day; alert calls of at most 5
  alerts, 60 s apart (a terminal run waits it out, the service comes back in 10 minutes), each
  alert on fewer than 10 cases before and `case_ids` read back after, at most 200 per case,
  1,000 alert changes a day; only in the write window (02:30-17:30 UTC), never 00:00-01:30, only
  in NORMAL health.

## Emergency stop

Any of these stops the next request; none needs the others.

```bash
uv run argus siem stop --component cases --reason "..."     # the kill switch (services may stop, only the owner resumes)
sudo systemctl stop argus-writer                              # the service (custody layout)
uv run argus kibana state                                     # what is stopped or paused, today's counts
```

A 401 from Kibana stops all Kibana work; a 403 or a wrong answer pauses that class. The owner
lifts them (`sudo argus-owner kibana resume --reason "..." [--class W1]`) after reading why.
The last stop is the key: invalidate the cases writer key in Kibana (Stack Management, API keys).
**Writer keys die with their switch:** when a class is switched off for good, invalidate the key.

## What W1 cannot undo, and how a person deletes a case

ARGUS never deletes anything in Kibana. A created case, comment or attachment can be answered
only by closing the case as `created_in_error` (an approved W3 closure with a correcting comment).
A person who may delete cases deletes one in Kibana: Security, Cases, tick the case, Delete. The
alerts lose the case id, ARGUS sees "Deleted in Kibana" within a cycle and a person recreates the
case or closes it in ARGUS. W2 and W3 are undone by an approved compensating write: ask for it in
ARGUS (it binds `argus kibana compensate --outbox N`'s payload), the writer sends it once, reads
it back and adds a correcting comment; the comment the earlier write added stays.

## Commands (in the writer's account: `sudo argus-owner --as writer ...`)

```bash
uv run argus kibana plan --class W1       # what waits and what stops it (the database only)
uv run argus kibana diff --class W1       # each row planned against Kibana now (reads only)
uv run argus kibana run --class W1        # one run at the ramp step; the class name is typed
uv run argus kibana ramp --class W1 --checked-in-kibana   # raise the step when the runs allow it
uv run argus kibana skip --outbox N --reason "..."        # a person drops a write that cannot go on (see below)
uv run argus kibana compensate --outbox N                 # the undo payload an approval binds
uv run argus writer run                                   # the service (scheduled classes only)
```

`skip` is for a write that cannot or should not go on (`conflict`, `paused`, in doubt): it is never
sent after that, and the case's later rows go on. Skip a create that reached Kibana only if the
case should stay without a Kibana id: its later changes wait for a verified create.

A canary and a ramp step are a person's, at a terminal, in the live slot (Tue and Thu
20:30-22:00 IST; the window is 08:00-23:00 IST). The ramp: a class starts at 1 unit a run; it
moves to 5 and then to 10 only after at least 3 runs on 3 days (or 5 working days after a clean
run), every write read back as sent, no reconciliation alarm since the step began, and your check
of the cases in Kibana. Classes go in order: W2 after W1's canary and one more run, W3 after W2's.
After the ramp a class may run on a schedule you switch on (`kibana.writer.scheduled`, every
`kibana.writer.interval`, at most 10 minutes, at the ramp step). **The service is never a class's
first writer:** it runs a class only after a clean canary run at a terminal (it sent, every
write read back, nothing stopped it) and a ramp step above 1; `kibana plan` says so. Outside the
write window a scheduled pass reads nothing. Only a run that sent something and read all of it
back counts for the ramp and the class order; nothing is raised while a finding of the writer
(a case that landed twice, an unexpected answer) waits for a person, the class is paused in the
lane, or one of its writes is in doubt, in conflict or paused. The runs, ramp steps and skips
record the person who ran `sudo argus-owner` (`SUDO_USER`), not the service account.

## Settings (`ARGUS_KIBANA__...`, in the writer's own credentials)

`ENABLED=true`, `WRITE_CLASSES=W1` (a class by name), `CASES_WRITER_API_KEY` and its
`..._EXPIRES` (30 days; a run is refused without an expiry or after it), `WRITER__SCHEDULED`,
`WRITER__INTERVAL`, `WRITER__APPROVAL_KEYS` (else the credential `approval-signing.key`);
`ARGUS_WEB__PUBLIC_URL` (ARGUS's link in every case); `ARGUS_DATABASE__WRITER_PASSWORD` (the
writer's own database login, made by `argus db bootstrap`: a member of `argus_writer` alone,
with exactly its grants; `argus doctor` checks every table).

**Credentials.** `argus-writer.service` names only what the cases schedule needs
(`database.writer_password`, `approval-signing.key`, `siem.api_key`, `kibana.reader_api_key`,
`kibana.cases_writer_api_key`): a missing file fails `LoadCredential=` and the whole unit. The keys
minted at later canaries (`siem.writer_api_key` for R17's write-back,
`kibana.alert_writer_api_key` for Q-D5) are optional: `argus-owner --as writer` loads them when
they exist, and the unit that uses a key names it once it exists. Each class is gated on its own
key being installed with a recorded unexpired expiry (`gate_problems`).

## Production steps for the first canary (the user, with the lead)

1. Checkpoint: `scripts/backup_check.sh`; put the writer's database password in
   `/etc/argus/credentials/database.writer_password` (root, 0600), then `sudo argus-owner db
   bootstrap` and `sudo argus-owner db upgrade` (migrations 0037 and 0038); `uv run argus doctor`
   ("writer login" passes: exactly the writer's grants, a member of `argus_writer` alone). If a
   0037-only database had made the login a member of `argus_runtime`, bootstrap takes it out
   (and says so).
2. The approval key for the writer (`approval-signing.key`, Q-C3 step 2) and
   `web.public_url` set (DQ29).
3. Mint the cases writer key (Q-A0 ER8) with a 30-day expiry; install it and its expiry; run
   `sudo argus-owner --as writer kibana selftest --key cases`.
4. `ARGUS_KIBANA__ENABLED=true` and `ARGUS_KIBANA__WRITE_CLASSES=W1` in the writer's environment.
5. In the live slot: `kibana plan --class W1`, `kibana diff --class W1` (read the dry-run), then
   `kibana run --class W1` (type `W1`): the PS1Bot case, its opening comment and at most 5 alerts.
   Check the case in Kibana's UI (title, description, tags, comment, alerts, Sync alerts off) and
   `uv run argus kibana sync status` (no unexplained action). Run it again: it writes nothing.
6. W2 after W1's canary and one more run: `WRITE_CLASSES=W1,W2`, one change, you present. W3 on a
   real closable case, or the declared test case closed `created_in_error`: one approved
   closure, then a second run that writes nothing. Costs recorded each time (round trip, heap,
   search queue; stop at a p95 above 2 s).
