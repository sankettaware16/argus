# The still-active watch and case membership (Q-C2)

Once a day ARGUS asks of every open true-positive case: is it still active? It looks at its own
alerts first (local, nothing sent to the SIEM), then at the proxy logs for the case's addresses.
"Contained" needs positive evidence; activity after containment or closure is never silent
(plan §5 Q-C2, §7.1; DQ13 as D-110 answered it: 72 hours, a person confirms, the watch lasts 14
days after closure). **Off in production** (`cases.watch: "off"`) until the lead switches it on;
the proxy part is a new kind of read on the SIEM and follows Q-F4's first runs.

## What it does

A **watched case** is a confirmed one that is not closed, or one closed as
`remediated_verified` or `remediated_unverified` within the last 14 days (activity after a
benign, accepted or attempt closure is expected, so those are not watched). One run, in order:

1. **Membership.** An investigation that alerted after the case's reference time (its opening;
   its containment; its closure) joins the case when it strongly matches the case's actors or
   indicators and no other case matches as well:
   - an internal host, account or attacker address in common is an *actor* match; a C2 or other
     indicator address or name in common is a *c2* or *indicator* match (actor first);
   - a match through **shared infrastructure** is only *suggested*, never joined: an address in a
     content-delivery or cloud network or a name on one of their services
     (`config/shared_infrastructure.yaml`, a seed list: add the ranges your providers publish),
     and, outside the list, any value that appears in 50 or more investigations within
     `history.window` (the prevalence gate's own limit; such a value is not even suggested);
   - two or more cases matching equally is **ambiguous**: it joins none and is suggested to all
     (`argus case suggestions`; join one by hand with `argus case link`, or dismiss it). **A tie
     opens at most one case**: a person's verdict opens one on its own merits; a later
     investigation that ties the same cases (or the case the tie opened) opens none and is
     suggested to each, and the opener's report says why. ARGUS's own proposals never open a case
     on a tie;
   - an investigation a person judged benign or a false positive is not activity, **while that
     review is current** (its version is the investigation's): new alerts after the review make
     it count again;
   - a join through a C2 also adds the investigation's own actors as indicators (the second and
     third PS1Bot hosts), nothing more.
   **Activity is a wider question than joining.** An investigation counts as activity of a case
   when it strongly matches the case's keys (or is of one of the case's own hosts or accounts),
   **whether or not it belongs to a case** (this one, another, a suspected, dismissed or closed
   one); only investigations in no case join. The case's own hosts and accounts always count,
   even when one appears in 50 or more investigations (its alerts are the case's activity; such
   an investigation is still not joined or suggested). **Any other key of the case (a C2 or
   indicator) found in 50 or more investigations makes the case "cannot tell: too common"**: its
   alerts rows are *unverified* with that reason and it is never called quiet.
   An open or assigned case is linked; a **contained** case returns to **open** automatically
   (event `new_activity`, a W2 state tag and comment through the outbox, the case shows "New
   activity after containment"); activity **after a closure** opens a **suspected** case that
   follows the closed one (`cause: watch`), never a reopen; later activity joins that case.
2. **ARGUS's own alerts**, per finished UTC day: *active* (the case's investigations, or ones that
   strongly match it, alerted), *quiet* (none, and the collector read past the day with no
   coverage gap) or *unverified* (a gap, or a key too common to search; final). A day the
   collector has not yet read past is *not checked* until it has. Today is recorded only if
   active. An open case is looked at on its last 7 finished days; a **contained** or
   **closed** one on every day since its containment or closure (up to 14 days), however long
   the watch was down.
3. **The proxy logs** (`cases.watch: on`): per address of the case (a public `c2` or `indicator`
   address) and finished day not yet decided, one `proxy.contact` request with the case's internal
   hosts watched (at most 10 a request), window 01:40-22:59 UTC (one daily index; Q-F1's readings
   stop at 00:00 and resume at 01:30, so an earlier start has no anchor). A day the alerts already
   show active is not asked. When contact is seen, one `proxy.pair` request reads its rhythm. A
   zero is *quiet* only when Q-F1 verifies it (`freshness.mode: "on"`); otherwise *unverified*
   with the reason.
   - **The cap** (`watch.cap_for`): a case may ask **one question a day for each of its
     checkable subjects** (a destination address, times its groups of 10 watched hosts) **and two
     spare, at least 6 and at most 20** (every answer that was sent counts, a failed
     `proxy.pair` included). A case with 8 addresses may ask 10 a day: it asks the 8 that are
     open, and the two spare clear a question that had to be asked again the next day (or a
     backlog, two questions a run faster than the days arrive); with 4 addresses the cap is 6.
     Questions go **the oldest unanswered (day, address) first**. **Above 20 subjects a day
     stays incomplete** (20 are asked, the rest wait) and the verdict says "N of M checks
     answered; this case has more addresses than the watch asks in a day": a person decides with
     that in view. With 19 subjects there is one spare question and with 20 none: there a
     question that failed and is asked again takes a place of the next day's, so the newest day
     waits one question until a day needs fewer (the verdict shows "N of M").
     The cap counts *questions*; the lane's ledger counts every attempt (the gateway retries a
     502 or 503 once, and each row of the ledger has its attempts), and the lane's own limits
     charge every one. What is cut off, or refused (a switch, STOP, the quiet hours, CAUTION or
     worse, the lane's budget), stays **not checked: <reason>** and is asked again at the next
     run; asking stops at the first refusal of the SIEM's state. An answer that cannot be read
     (a field of the wrong kind, a negative or absurd count) is **not checked: malformed
     answer**, never quiet.
   - **The lane:** `Purpose.INVESTIGATE`: the investigation lane (400 ms of server time a
     minute, 6 minutes and 300 heavy requests a day), NORMAL health only, the `investigation`
     kill switch, plus `proxy.contact`'s own prevalence gate and 90 s a day (Q-F4). The template
     must be in `enrichment.templates` (its first run passed).
4. **Reactions** to contact seen in the logs after containment or closure with no investigation
   to carry it: a contained case returns to open; a closed one gets a note once (its attention
   reads "Activity after closure, seen in the proxy logs").

A **quiet window** ("72 hours" means **three whole UTC days**: the three days before today) is
the last three whole UTC days, each with a *quiet* alerts answer and a *quiet* answer for every
address that can be checked in the logs, no activity since, and nothing arrived late (the live
database is read again at the moment). **The verdict says exactly what was read**: "alerts, and
the proxy logs 01:40-22:59 UTC on each of the 3 days; the nightly seam and today are covered by
alerts only", or, for a case with no address that can be checked in the logs (a host-only case,
a domain C2), "alerts only: no address of this case can be checked in the proxy logs". The
nightly seam (22:59 to 01:40 UTC, one daily index) and today are not read in the logs; ARGUS's
own alerts cover them, so a beacon that runs only in the seam and is in no alert is not seen.
While answers are missing the verdict says "N of M checks answered". Without Q-F1 on nothing is
verified. A case that is **contained** is only proposed for `remediated_verified` once the window
ends after the containment (a case contained a moment ago waits for the next day).
`argus case contain` asks the watch itself (a caller never supplies the window);
`argus approvals propose` uses it for `remediated_verified`.

**How fast activity shows.** ARGUS's own alerts: at the next daily run (within 24 hours). A beacon
seen only in the proxy logs: a day is asked after it ends and its log window starts at 01:40, so
it is flagged within about 28 hours (a beacon that resumes at 23:30 is in the next day's window
and flagged at the run after that day). A second run within the day would be needed for 24 hours.

## Commands

```bash
uv run argus case watch run --dry-run     # read and plan only; nothing changed, nothing asked
uv run argus case watch run               # the daily run (once a day, after 01:30 UTC)
uv run argus case watch run --local-only  # ARGUS's own alerts only, whatever cases.watch says
uv run argus case watch status <case>     # when the watch last ran, the last days' answers, followers, the verdict
uv run argus case contain <case> --as <user> --attest "what you know"
uv run argus case suggestions [--dismiss <id> --as <user>]
uv run argus case split <case> --investigation <id> [--investigation <id> ...] \
    (--title "..." [--severity S] | --into <case>) --reason "..." --as <user> [--version N]
```

`status` and the run report say "not checked: <reason>" for every question left open, within a day
of the day it concerns when the run is daily. `status` also shows **when the watch last ran** and
how long ago; `argus doctor` warns when `cases.watch` is not `off` and no run was recorded in the
last 36 hours (the daily run is not happening, and "not checked within 24 hours" depends on it).
`argus doctor` also checks that `config/shared_infrastructure.yaml` loads. One run at a time (a
session lock on a connection of its own, idle rather than in a transaction, so the engine's 60 s
limit cannot end it): a second returns "another run of the watch is in progress". One case's
unexpected failure is a `problem:` line (exit 1) and the other cases and the audit row go on.

`config/shared_infrastructure.yaml` is found next to the code (the repo's `config/`), whatever
directory the command runs in; a missing, invalid or **empty** list (no network and no domain) is
an error line and exit 1, not a traceback: without it the content-delivery rule would silently
not apply.

## Splitting a case (D-211)

A suggested case can group two devices that turn out to be separate problems (case 6: the Amadey
host whose owner was told, and a second device nobody had reviewed). Record the owner's notice on
a case that holds only the notified device, because the notice makes the case "known": its
fingerprint absorbs that device's alerts silently, and the second device must not be absorbed with
them. `argus case split` moves the chosen investigations out of a case (suspected, open, assigned
or contained; at least one investigation stays: moving all of them is a merge) into a **new case**
you open for them (`--title`, `--severity`, owner ARGUS, opened by you like `argus case open`) or
into **an existing case that is not closed** (`--into`), in one step, with a reason. Then record
the notice on the case that holds the notified device.

What goes with the investigations: the **actor** rows only they carried (the device: an address,
host or account that no investigation left behind involves). The **C2 and indicator rows stay**
on the case (the server both devices reached is a fact of both) and are copied to the other case
when a moved investigation involves them. If a device's row cannot be separated because an
investigation that stays involves it too, the command says so and leaves it; `argus case show`
lists the rows of each case afterwards. Nothing is deleted: the history of both cases says what
moved and why, and an investigation moved by mistake can be moved back the same way. A third
device that later reaches the shared server matches both cases equally and is *suggested* to both
instead of joined. A case that is already notified may split (the notice stays with it, and the
command says what the known pass had decided about the moved investigations, which stays as it
is). Needs migration 0055 (`argus db upgrade`) first.

## Settings

| Setting | Default | Meaning |
|---|---|---|
| `cases.watch` | `"off"` | `off`: nothing runs. `local`: ARGUS's own alerts only (no request reaches the SIEM). `on`: also the proxy logs |

The service is not a unit: schedule `argus case watch run` once a day yourself (for example at
03:30 UTC, 09:00 IST).

## Emergency stop

- `cases.watch: "off"` (or `local`) in `config/argus.yaml`; takes effect at the next run.
- `uv run argus siem stop --component investigation` stops the watch's proxy questions (and the
  rest of the investigation lane) at once; they are recorded as not checked with the reason.

## Production steps (the lead, in this order)

1. After the merge into `main`: `scripts/backup_check.sh`, `uv run argus db upgrade` (migration
   0041, which follows Q-F3's 0040), `uv run argus doctor`.
2. Nothing else is needed for `local`: set `cases.watch: "local"`, restart nothing (the run is a
   command), `uv run argus case watch run --dry-run`, read it, then run it once by hand and read
   `argus case watch status` for the PS1Bot case. Journal it. It reads the database only.
3. Q-F4's first runs first (`docs/runbooks/phase3-production-steps.md` step 23: `proxy.contact`,
   then `proxy.pair`), each within its limit and switched on in `enrichment.templates`.
4. The first proxy day: `cases.watch: "on"` for one run, at a terminal, in NORMAL health between
   01:30 and 23:59 UTC; journal the new kind of read (each case: at most its cap, 6 to 20,
   1 per address and day; the PS1Bot case asks 1 a day). Read the ledger rows
   (`purpose = 'investigate'`, template `proxy.contact`, `took`) and the rows in
   `case_watch_checks`. A case not yet watched has up to 7 finished days open: the first run
   asks the oldest ones up to its cap (6 for a case of up to 6 addresses) and the next days' runs
   the rest.
5. Schedule the daily run. `contained` and `remediated_verified` stay out of reach until Q-F1 is
   `on` (step 25) and `freshness.margins` are set.
