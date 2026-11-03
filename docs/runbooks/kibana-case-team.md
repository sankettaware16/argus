# Runbook: the case team (AR8)

Seven Kibana users (six, and from AR10 a seventh, optional one) post one incident case, the way `SOC-IR-2026-1027-01` was made by hand
(the incident case: one case per incident ID): ARGUS renders its stored incident report
(AR7, `incident-report@1`) into the case, each part posted by the user that owns it, so the case's
timeline shows who said what (D-157, D-158, D-195). Code in `src/argus/caseteam/`; the lane's part
(class `WC`, five templates, the file upload) in `src/argus/gateway/kibana/`.

**Today (2026-10-30, D-214): live on this host, person-confirmed cases only.** `argus-case-team.timer`
runs `case team run --unattended` 10 minutes after each run, with `local/argus-writer.env` (0600: the
switches, the six keys, the reader key, the writer's database login; never `.env`) and the approval
key as its credential; `argus-kibana-sync` reads back with the reader key only
(`local/argus-kibana-read.env`), the team's cases too (below). `case_team.auto: false`: ARGUS's own verdict never opens a case, a
person's Confirm of a true positive does. The first case (the canary, case 1) waits for the user's
Confirm and approval in `/app`. Stop: `ARGUS_CASE_TEAM__POST=false` in `local/argus-writer.env`, or
`systemctl --user disable --now argus-case-team.timer`.

| Kibana user | Posts | Key setting (`ARGUS_CASE_TEAM__...`) |
|---|---|---|
| `argus-lead` | opens the case (ID, title, severity, `key:value` tags, description), attaches and tags the alerts, the verdict comment **last**, later the note after a person's verdict | `LEAD_API_KEY` |
| `argus-evidence` | Evidence with its hypotheses; Affected devices | `EVIDENCE_API_KEY` |
| `argus-visualiser` | **Incident at a glance** (AR10, D-250): a numbers row and live Kibana charts of the case's alerts, right after the Evidence comment. **Optional**: without its key the step is skipped (reason "no visualiser key"), nothing else changes | `VISUALISER_API_KEY` |
| `argus-intel` | Threat intel, only when the report holds an outside answer (nothing to add is not posted) | `INTEL_API_KEY` |
| `argus-responder` | Recommended actions: owner, status, the condition to close | `RESPONDER_API_KEY` |
| `argus-hunter` | Queries to check it yourself: KQL / ES\|QL in code blocks, the time range, a Discover link; code only | `HUNTER_API_KEY` |
| `argus-reporter` | the PDF, the one-page dashboard PDF (AR10) and the two CSVs in the Files tab, then the comment listing them | `REPORTER_API_KEY` |

The order is fixed: lead opens, the alerts (100 a call, D-235), evidence, the visualiser's glance,
devices (campus devices, or for outside addresses the campus targets and the outside actors:
D-240), intel if needed, responder, hunter, reporter's four files and its comment, the lead's
verdict last. It ends: **"ARGUS's verdict: true positive (0.8). ... Confirm or reject in a
comment."** Only `argus-lead` opens a case or touches alerts, only `argus-reporter` uploads a file
(the validator and the database both keep that).

## Settings (`case_team:` in `config/argus.yaml`; keys only in the writer's credentials)

| Setting | Default | Meaning |
|---|---|---|
| `post` | `false` | **nothing is written to the SIEM while false**; the dry run still shows everything |
| `auto` | `true` (`false` here, D-214) | ARGUS's own true positive may open a case; off: only a person's confirm |
| `auto_min_confidence` | `0.8` | ARGUS's own true positive opens a case from this confidence |
| `per_day` | `5` | cases opened a day (IST); a person's confirmation counts too |
| `canary` | `1` | the first N cases need a person's approval of that case |
| `max_alerts` | `500` | alerts attached and tagged on one case (newest first; at most 1,000; the hand-made case held 317) |
| `alerts_per_call` | `100` | alerts in one attach or tag call (at most 100; the hand-made case did 100, D-235) |
| `alert_pause` | `3s` | the least between two alert calls (1 s at the least): a courtesy gap; the write lane's bucket paces the server time (D-242) |
| `min_update_gap` | `6h` | at most one "Update" round in this time |
| `<user>_api_key`, `keys_expire` | none | the seven keys (SecretStr) and their common expiry |
| `kibana.write_classes` | none | needs `WC`, which needs the first six keys (else the host refuses to start); `visualiser_api_key` is optional |

The keys follow every write key's rule: not in `.env`, YAML or a shared unit (`argus doctor`
checks); the writer's root-owned credentials (`case_team.<user>_api_key` files, optional ones of
`argus-owner --as writer`). `WC` goes into the writer's environment only, never the shared `.env`.

## Speed: a case posts in one go, once (D-235, D-242, D-243)

Alerts are attached and tagged 100 a call. The `kibana_write` lane's bucket holds **60 s of server
time at once while the SIEM is NORMAL** (`siem.lanes.kibana_write.burst_ms`, default 60,000); at
CAUTION, DEGRADED, or in the slow start after a recovery its capacity is a minute's share (200 ms)
times the scale again, so a cluster that is not healthy sees no burst. A person-confirmed case of about
45 s of Kibana server time (a file upload costs ~3 s; case 1 took 43.6 s in 32 writes) posts in one run
or two (the timer runs every 3 minutes). A run keeps sending while the lane admits: the 3 s gaps
between case writes and between alert calls are waited out, a step the lane cannot admit within
5 minutes ends the run, and the next run goes on.

**What the burst is worth, as it is (D-243).** It is a *reserve*, not a rate: after it the lane refills
**200 ms a minute (12 s an hour)**. A case of 45 s leaves 15 s; the next case is 30 s short, which the
refill gives in 2.5 hours (3.75 hours after an empty bucket): in steady state about **one 45 s case
every 4 hours**. The day's share is unchanged (3 minutes), so **at most 4 such cases a day** (the old
"4 to 6" was wrong); a 500-alert case also meets the 2,000 alert-mutation cap. After any use, and after
any CAUTION blip (a full bucket is cut to a minute's share at the next roll), the burst is rebuilt only
by the refill: five hours from 200 ms.

**At the deploy of this version, once: top the stored bucket up.** The bucket the old code left in the
database holds 200 ms, so without this the first case after the deploy, and case 1's refresh (8 to 10
edits), would wait about 7 minutes for each edit:

```bash
uv run argus siem probe                    # if the last probe is old (the fill needs a fresh NORMAL)
uv run argus siem lanes fill kibana_write  # a person at a terminal; type the lane's name to confirm
```

It sets that lane's stored bucket to its capacity (60 s). Refused unless the SIEM's stored health is NORMAL
at full scale, for the collector, for a closed lane, and over a debt (a slow call's cost is real). It
writes ARGUS's database only (nothing goes to the SIEM or Kibana) and is kept in the audit trail with who,
when, what the bucket held and holds. It does not change the day's share or any other lane.

## Correcting a posted case in place (D-236, D-241)

Posted cases are corrected, not re-posted. Three step kinds edit what ARGUS wrote: `retitle` and
`redescribe` (`argus-lead`, `PATCH api/cases` with the case's version) and `edit_comment` (the user who
wrote the comment, `PATCH api/cases/{id}/comments` with the comment's version); class WC, ledgered, the
answer checked. Each is **read first**: if Kibana already reads as wanted the step is only recorded; if
Kibana still holds what ARGUS last wrote, one PATCH goes against the version just read (a 409 reads
again and tries once more); if it holds something else, **a person changed it and ARGUS leaves it**
(the step is `skipped` with that reason, `case team status` shows it, the run says so). A title a
person changed is never edited again.

- **A retitle in ARGUS** (D-230) edits the Kibana title by itself, as the first step of the next update
  round; it does not wait for the update gap.
- **The description and the comments** are rewritten only on a person's decision:
  ```bash
  uv run argus case team refresh <n>                           # dry run: what would change
  sudo argus-owner --as writer case team refresh <n> --apply   # plan it (type REFRESH)
  ```
  `--apply` plans the edits in ARGUS's database and writes nothing to Kibana; the timer's next run
  sends them (a refresh is finished before anything else is planned). Refused while any step is open or
  the case is not in Kibana. The files, the verdict and the lead's notes are left alone; the newest
  report's other new lines, files and verdict still follow in the usual update round.
- **After the deploy of this version** every report is rewritten once (`incident-writer@3`), so a case
  already in Kibana (case 1) has a new report version and an update round is due. To correct it in
  place instead of as "Update" comments, run the refresh (dry run, then `--apply`) before the timer's
  next run, or stop the timer (`ARGUS_CASE_TEAM__POST=false`) until it is planned. Do it **only after
  case 1's report is at `incident-writer@3`** (a dry run before that says "nothing differs"), after the
  lane's top-up (see Speed), and know that **the refresh does not touch the files**: the new PDF, the
  dashboard and the CSVs still go in the usual update round. A refresh that has to add a comment (a part
  that now needs one more) is still no update round: it does not move the report version or the round's
  time, so the files, the verdict and new alerts follow as usual (D-247).
- Not verified against a live Kibana: the PATCH shapes are the lead's reading of Kibana 8.19's OpenAPI.
  The first refresh is checked in Kibana's own UI (title, description, the comments' "edited" marks).

## Sync alerts on (D-272, D-288)

A person's Sync alerts setting is theirs; ARGUS never switches it back (D-270). With it on, Kibana
sets each attached alert's workflow status to the case's status. The poster therefore reads the case
once before every `attach` step. **Sync alerts off:** nothing changes. **On, and the case is open:**
the only harm is re-opening an alert a person had closed, so the alerts ARGUS records as not open
(`alert_records.workflow_status`) are left out of the call; the step records them in its
`kibana_ids` (`left_out`), the run's note says "N closed alerts left unattached: Sync alerts is on",
and the totals the case is expected to hold drop by that number for this step and every later attach
of the generation (the answer check and the look after a doubt use the lowered total). A call whose
alerts are all closed is skipped. **On, and the case is in progress or closed:** every attach would
change the alerts' status, so each is `skipped` with "Sync alerts is on and the case is not open: the
attach would change the alerts' status" (`argus case team status` shows it; the run goes on). A skipped
or left-out alert is not counted as attached, so the next update round tries it again (it attaches
once Sync alerts is off or the alert is open again). The tag step is unchanged: a tag changes no
alert's status.

## Text in Kibana (D-237, D-240, D-244, D-246)

Kibana 8.19's Markdown is remark-parse 8 (EUI), **not CommonMark**. It honours a backslash only before
``\ ` * _ { } [ ] ( ) # + - . ! > ~ |``; ARGUS escapes exactly those and nothing else (no `\,` or `\:`
shows), writes `&` and `<` as entities, and puts any word that could act without a backslash (a URL,
`www.`, an e-mail, `@name`, `javascript:`, a `/path`) in a code span. Addresses, domains, URLs and
paths are written plain in code spans (not defanged); fenced words that touch are **one** span. A
colon cannot be escaped, so a value such as `:smile:` may show as an emoji.

What the reader does that CommonMark does not, and what ARGUS does about it (the guardian refuses a
text that breaks any of these, so a step is held rather than sent wrong):

- **No fence inside bold.** Kibana ends `**bold**` at the next raw `**`, even inside a code span, so
  headings are `**E1 · title** — values` with the values (in code spans) after the bold.
- **A pipe in a table cell.** Kibana ends a cell at every pipe no backslash protects, inside a code span
  too. A pipe in a *value* in a cell is written as the look-alike `∣` (U+2223), never a backslash;
  every row of every table is built by `row()`, and the guardian counts the cells of each row against
  the header's.
- **No language tag on a code fence** (a tag Prism does not know may make EUI throw).
- A line of `=` signs alone is written in a code span (the underline of a heading).
- **Values from the logs reach the case.** The case team never hides log-derived values: served paths,
  the values a check asked about and indicators are in the comments for everyone who can read the case
  (as the facts from the logs already were, D-216).

The same texts are read by Kibana's own reader in `tests/unit/caseteam/test_kibana_parser.py` where
its packages are installed (`tests/kibana_markdown/README.md`; otherwise the tests skip and say so).
## The glance and the dashboard (AR10, D-250 to D-252)

**The comment "Incident at a glance"** (`argus-visualiser`) has a plain **numbers row** (alerts, actors,
targets, indicators on the local threat lists, first and last alert in IST, rules), which always renders,
and up to four **live Kibana charts** (`!{lens{...}}` blocks, each on its own line): alerts over time stacked
by rule, the top actors, the targets (campus sites or the servers reached) and a table of the rules. Every
chart is over the alerts tagged with the incident ID only (a phrase filter on `kibana.alert.workflow_tags`
over `.alerts-security.alerts-<space>`, as a self-contained ad hoc data view; the time range runs from the
first alert minus 1 hour to the last plus 1 hour). No name of a person is in it. If Kibana does not draw a
chart the numbers row and the dashboard file say the same. A later round says it again, as "Update:
Incident at a glance", only when it changed; a case posted before AR10 gets it in its next round.
`argus case team preview <n> --text` shows it, blocks and all.

**The dashboard**: the same four panels drawn by code (reportlab) on one page, as the incident PDF's second
part and as its own file `<incident-id>_dashboard.pdf` in the Files tab (the reporter uploads it second, and
the files comment lists it).

**The seventh user's key.** The user is made by a person (`uv run python deploy/elk/make_case_team_user.py
visualiser`: the reporter's role, one 365-day key) and its key goes to `local/creds-writer/case_team.visualiser_api_key`
(a credential file, 0600; in the custody layout the writer's `case_team.visualiser_api_key`, loaded by
`argus-owner --as writer` when present: no unit file names it until the key exists, since a missing
`LoadCredential=` file fails a unit). **Without the key nothing breaks**: the step is `skipped` with the
reason "no visualiser key" (`argus case team preview` says it as a note on a host that holds the keys),
the other comments and files are posted as ever, and a round does not plan the glance. When the key is
installed the next round posts it. Migration 0062 lets the database accept the new author.

## When a case is posted (D-195)

1. `case_team.post: false` stops everything. 2. With it on, a case is opened when **(a)** a person
confirmed its report in ARGUS **as a true positive, on the newest report version** (a benign or
inconclusive confirm never opens one; a report that changed since needs a new confirm: D-207), or **(b)** ARGUS's verdict (a person's, a proposal or the case's:
not a reading) is a true positive of at least `auto_min_confidence` and the case is suggested or
open (`suspected`, `open`, `assigned`); a person's rejection stops both. At most `per_day`.
3. **The canary**: the first `canary` cases wait for a person's approval of that case. 4. A case
already in Kibana is **never opened again**: a newer report version is posted as "Update" comments
by the owning user, only what changed, never a delete (an edit only as described under "Correcting a
posted case in place"); a file is uploaded again only if
its bytes changed, as `<ID>_..._vN`. A **notified** case (AR4b) that has not changed since the notice
is never posted again; one that did change is a new comment on its Kibana case. 5. A Kibana case
that already carries the incident ID (the hand-made one!) is never duplicated: the lead's own
earlier create is adopted, anyone else's holds the post for a person.

## Seeing what would be sent (nothing is written)

```bash
uv run argus case team preview <n>               # the decision, the steps by author, the plan hash
uv run argus case team preview <n> --text --requests   # every comment in full, every request
uv run argus case team status [<n>]
```
The same is `GET /api/v1/cases/{id}/team` and the **Kibana case preview** section of the case page
in `/app` (without log access the words are hidden: they say what the logs said).

## The canary: what the approval shows

The approver (capabilities `approve` **and `see_logs`**: an approver must be able to read every word;
a password re-typed in the last 5 minutes) sees the plan: each
step with its author, each comment word for word, each request (a file as name, size and hash), and
the plan's hash. The button posts `{"plan_hash": ...}` to `POST /api/v1/cases/{id}/team/approve`.
The approval is signed (the closures' approval key), expires with the write window it was given
for (at most 72 h) and binds **exactly that plan**: a new report version, a new alert or a changed
text needs a new approval. The writer checks the signature, the hash, the expiry and that the
approver's account is still active before its first request. It sends nothing itself.

## Recovery, in doubt, and the person's decisions

Every request is a row (`case_team_steps`): its text, payload, hash, author, the Kibana ids that
came back. `sending` is committed at the last step before the request leaves. After a crash or a
timeout the step is **looked for in Kibana before anything is sent again** (a comment by its text
and author; the case by its incident tag; the alerts by the case's count; a file by the case's user
actions), at 2, 5, 15 and 30 minutes; found: verified; not found after four looks: `resend`, and
nothing else is sent until a person decides:
```bash
sudo argus-owner --as writer case team resend <step-id>        # send it once more
sudo argus-owner --as writer case team skip <step-id> --reason "done by hand"
```
`skip` is **refused while the Kibana case does not exist** (nothing after the step could be sent).

**A Kibana case already carries the incident ID (the hand-made `SOC-IR-2026-1027-01`):** ARGUS
never writes into a case it did not make; it holds the post (the create is `held`, nothing is sent).
Either leave it held (the hand-made case is the record), or have the team rename the hand-made
case's incident tag in Kibana and then `resend` the create (`case team status <n>` shows its
step id): the create looks for the incident ID again, finds none and makes ARGUS's own case. Do not
`skip` it, and ARGUS does not continue a case made by hand (D-206).
A tag call in doubt is sent again by itself (tags are added to a set). One step in doubt holds
the steps after it. **One run at a time:** `run`, a pass and the looks for steps in doubt take the
same lock; a second run does nothing while the first goes on, and a run is bounded by the lane's
cap of case writes whatever cases it takes (the next run goes on, a started sequence first).

**A tag call that tagged fewer alerts than it named is not a failure** (D-210): alerts the index
lifecycle removed are left out of every later plan and said on the case once by the lead; a version
conflict (a rule rewriting the alert) is tried once more after about 10 minutes, and if it comes back the
alerts are said as attached without the tag. Neither holds the case or pauses class `WC`; a failure
report or a timeout in the answer does. A Kibana timeout puts the write lane in debt for about 75 minutes (the lane's
rule), so a run after one waits.

## The read-back of the team's cases (P4-B1, D-270)

`argus-kibana-sync` reads the team's cases as it reads `argus`'s: every find of a cycle (the change
poll, the open and in-progress listings, the closed probe) names the service user **and the seven
team users** as `reporters` (repeated key, one request; `kibana.sync.team_cases`, on by default; the
names come from settings, the sync unit holds no team key). So within one cycle (10 minutes in NORMAL)
ARGUS knows when a person **edits** a team case's title or description (`person_edited`, kept in the
mirror's `unmanaged`, never overwritten: D-241), **comments** or tags it, **closes** or **reopens** it
(`closed_in_kibana`, `reopened_in_kibana`: items for a person in ARGUS, never reverted) or **deletes**
it. A deletion is confirmed by `cases.get` (404), recorded on the ARGUS case (`kibana_mirror.deleted_at`,
finding `deleted_in_kibana`) and shown by `argus case team status` ("read back: DELETED in Kibana") and
the case page's Kibana section; **the poster then leaves the case alone** (no update, no new case; a
direct `case team run <n>` is the lead's to check against `case team status` first).

What ARGUS did itself is explained, per user, by the steps in `case_team_steps` that left (open ->
create, comments and files -> comment, attach, retitle -> title, redescribe -> description, comment
edit -> comment update); an action by any of the seven that no step accounts for is
`unexplained_argus_action` (an alarm: W1-W3 and WA pause; **the case team's own class WC does not**,
D-270 open point), and a team case with no post or no sent open step is `unexplained_argus_case`.
Alerts' status changes on a team case are not diffed (people triage them). Extra cost: no request more
per cycle; two user-action pages per team case read again (about 8 s a day of the Kibana lane's 4
minutes at 40 changed team cases a day) and one `cases.get` per deletion.

## A person's `Verdict:` comment

`Verdict: true positive` or `Verdict: false positive: <reason>`, from a person's own account, at
the start of a comment. After every complete Kibana sync cycle ARGUS lists the lead's cases once and
reads the comments of those that **changed** (`argus case team sync` does it now); the author must be the
ELK name of one enabled ARGUS person (else it is kept as `unmatched`, and read again when such a person
appears), that person must **hold `review`** in ARGUS (their stored capabilities, or in ELK mode the
snapshot of their ELK session; a comment-only Kibana account is `refused` with its reason), and a
comment by any of the six users or `argus` is never a verdict. A comment **edited by someone other than
its author** is refused; an author's edit is their newest verdict. It becomes the label through AR7's
Confirm / Reject path (`incident.review.decide`), once per comment text; two people who disagree are both
recorded and the lead says so. The lead then writes **a note that says what happened** (recorded as a
label on N investigations, or "Kept: an earlier review by X stands", or no new label) and, for a benign
verdict, that a person may close the case in ARGUS. **ARGUS proposes nothing and closes nothing; closing
stays a person's approval (W3).** `argus case team sync` prints how many comments became `recorded`, `refused`, `unmatched`,
`ignored` or `needs_reason`; the table `case_team_seen` holds each one with its reason.

## Stopping it

`case_team.post: false` (next pass), `uv run argus siem stop --component cases`, `sudo systemctl stop`
of whatever runs `case team run`, `argus kibana state` (class `WC`: paused or not), and last the
six keys (invalidate by id in Kibana). The lane's budget, health states, window (02:30-17:30 UTC),
caps (WC: 40 case writes a run, 200 a day, apart from W1-W3's; alerts 100 a call, 3 s apart,
2,000 alert mutations a day with the other classes') and breakers apply to every request. A 403 or a wrong answer pauses class `WC`.

## Deploying it

Local (no SIEM): merge (0062 follows 0061); `uv run argus db upgrade` on the local database; `uv run pytest -q
tests/integration/caseteam`; `argus case team preview <n>`; the web shows the preview already.

**This version (AR9 review fixes, D-243 to D-248):** no migration. After the deploy and before the
first post or refresh: `argus siem probe`, then `argus siem lanes fill kibana_write` (Speed, above).

**The first live post needs the user's approval** (D-109, D-157): (1) the owner runs `sudo
argus-owner db upgrade` (migration 0053 and its grants; the writer's login exists); (2) the six keys
from `local/argus-case-team.env` go to the writer's credentials (`case_team.lead_api_key`, ...),
`ARGUS_CASE_TEAM__KEYS_EXPIRE=<date>`; (3) `web.public_url`, the approval key (`approval-signing.key`);
(4) in the writer's environment only: `ARGUS_KIBANA__ENABLED=true`, `ARGUS_KIBANA__WRITE_CLASSES=WC`,
`ARGUS_CASE_TEAM__POST=true`, and the Kibana reader key; `uv run argus case team run 1` prints
what stops it, if anything; (5) `uv run argus case team preview <n> --text --requests`, with the
user, and the user approves **that case** on its page; (6) in the live slot (08:00-23:00 IST), a
person at the terminal: `sudo argus-owner --as writer case team run <n>` and type `WC`; the case
is checked in Kibana's own UI (title, tags, description, the alerts, the Files tab, who wrote each
comment). The route for files and for alert tags, and the shape of Kibana's answers to them, have
**not** been seen against a real Kibana yet (the local tier could not start in the build): this
first case is where they are verified. Then the timer (`case team run --unattended`) may follow.
