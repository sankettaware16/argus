# ARGUS — one-page guide for the TA/RA

**The short version.** ARGUS reads every alert from the SIEM (the SIEM), groups related alerts
into one *investigation* per rule, key and day, checks the rule's own steps, and writes a short
**dossier** for each. You open the app (at `/app`), look at what needs you, and decide. ARGUS
never decides for you and never edits a rule.

**Stop at any certificate warning.** ARGUS asks for your password. If your browser shows *any*
warning about the site's certificate (untrusted, expired, wrong name, "your connection is not
private"), **stop**: do not click through, do not type your password, close the tab and tell an
ARGUS admin. A warning is never "just the first time".

## What ARGUS does in Kibana
- **Today it changes nothing in Kibana.** You decide in ARGUS; a verdict or a closed case here
  does not show in Kibana.
- **Writing to Kibana ships switched off.** Your project owner switches it on one kind at a time
  (cases first, then alert status), each after a trial with a person watching. When a kind is
  on, ARGUS does only this, and the case or alert page says what it wrote:
  - **Cases:** creates a Kibana case for a confirmed ARGUS case, with a title, tags, a first
    comment and representative alerts, and keeps its severity, tags and comments up to date.
    When a person takes, assigns, releases or contains a case, ARGUS also changes the Kibana
    case's status and its tags (the owner and "contained" are tags), and when a person
    **reopens** a closed case it reopens the Kibana case; each change adds a comment saying
    what changed. Every comment links back to ARGUS, where the decisions are made.
  - **Closing a case** is never done by one person: someone requests it with a reason, and a
    **second person with the "approver" right** sees the exact changes and approves. A closure
    for a real incident (*fixed but not verified*, *risk accepted*) needs **two different
    approvers**. Only then is the case closed in Kibana, with the reason as a tag and a comment
    that names the approver. **If alert-status writing is on too, an approved closure also
    closes the case's alerts in Kibana**, for every reason except *duplicate* and *opened in
    error* (those say nothing about the alerts). Approving a closure is therefore also closing
    those alerts.
  - **Alert status:** after your *reviewed* verdicts (benign, policy, false positive) ARGUS may
    mark those alerts closed in Kibana, and acknowledge the ones you called true positive or
    follow-up. It does this slowly (a few alerts a minute), reads back what it did, and stops
    at once if anything looks wrong.
  - It never edits a rule and never deletes a case, and it writes nothing that is not listed
    here.
- What a person wrote in Kibana (a case comment) is shown in ARGUS as text. ARGUS takes no
  instruction from it.

## Open it and sign in
- **Open** the address your admin gave you, from a computer on the campus subnet. Once your
  admin has made the app the main entrance (a separate step), any old address you have
  bookmarked leads to the same page in the app. Until then old addresses open the older
  pages, as before.
- **Sign in** with your **ELK (Kibana) username and password**, the same ones you use in
  Kibana. Until the cutover reaches you, your ARGUS reviewer account (ask for one:
  `argus user add <name>`) still works; the sign-in page is the same.
- **Your ELK account replaces it.** Your old reviews, notes and place in the lists stay with you:
  the admin links the two accounts first. ARGUS keeps no separate password for you; change yours
  in Kibana (user menu, Edit profile). What you can do in ARGUS follows your ELK roles.
- **Your first ELK sign-in should show no warning**: no certificate warning, and no banner at
  the top of the page saying that ARGUS cannot confirm your access or that this is an
  emergency session. If you see one, stop and tell the admin before you go on.
- **If ELK cannot be reached,** you can still read and review (reviews are kept here and not
  sent to Kibana until ELK is back); changes that need ELK wait. A banner at the top says so
  while it lasts (the app looks again each minute). If you cannot sign in at all,
  ask the admin for the emergency sign-in (view and review only, one-time, switched on at the
  ARGUS machine).
- **Failed logins:** a wrong password makes the next tries wait a little (1, 2, then 4
  seconds); after 5 within 15 minutes, logins for that name pause. Every failure gets the same
  answer, so a typo in the name looks like a typo in the password.
- **Sessions** end after 30 minutes without a page of yours (the status bar's refreshes do not
  count) and 8 hours after signing in whatever you do. A change sent after that asks you to
  sign in again and is not saved: copy a long note before you step away.
- **Step-up.** Approving a closure asks for your password again, to confirm it is you.
- **Browsers.** ARGUS is tested in **Chromium (Chrome, Edge) and Firefox**, current versions.
  Other browsers may work; if something looks wrong in one, try one of these and tell an admin.
- **The menu** is on the left (behind *Menu* on a phone): *Home*, *Dashboard*, *Review*,
  *Cases*, *Browse*, *AI & reports*, *System*. The *Glossary* explains every page and word.
  *Your access* (a server page) says what your account may do and why; open it when a button
  is greyed out or a change is refused.

## Daily routine (10–20 minutes)
1. **Home** shows what needs you today: investigations that need attention, your cases, and
   closures waiting for a decision. Each tile is a link to its list.
2. **Needs attention** (*Review*). Start here: severe investigations, threat-list hits, and ones
   that changed after someone reviewed them. On the list, `j`/`k` or the arrows move, `Enter`
   opens, `Esc` goes back, `?` lists the keys.
3. **Open one.** The strip under the title holds the key facts. The tabs:
   - **Overview:** the verdict in a few lines, the reasons to look, what ARGUS found;
   - **Report:** every fact, with the request it came from;
   - **AI assessment:** what the decision engine and the AI investigator propose, with the
     facts they quote;
   - **What ARGUS checked:** the rule's own steps, answered or waiting;
   - **Alerts:** the alerts with the columns you choose; the raw alert on demand;
   - **History:** reviews and changes.
4. **Decide** at the top of the page. When ARGUS makes a call and it is right, **Accept ARGUS's
   call** (key `C`) is one click. Otherwise choose one of the five decisions (keys `1` to `5`),
   add a short note if useful, then **Save decision**. **Come back to it** keeps the alert group
   in Needs attention as a follow-up; *Can't tell yet* ticks it for you. If someone else got there
   first, nothing is saved and you see what changed: read it again.

| Decision (key) | Use it when | Example |
|---|---|---|
| **Real: act on it** (1) | Real, and someone must act; it may open or join an incident | A lab PC beacons to an IP on a threat list |
| **Real but harmless** (2) | It happened, but no action is needed: an attempt that failed, or expected activity | An internet scanner got only 403/404 answers |
| **Allowed by policy** (3) | Allowed by campus policy | An approved vulnerability scan by the IT team |
| **Wrong alert** (4) | The rule's claim is wrong | An "executable download" alert for Windows Update |
| **Can't tell yet** (5) | You cannot tell yet | Not enough data: it stays for a follow-up |

5. **Patterns.** Many alike? Check the "In common" values, then decide for the whole group.
6. **Browse** (*By rule*, *By host or IP*), **Not reviewed**, **Reviewed**, **All**: to find
   something again. **Health** says whether data is arriving; a gap means *unknown*, never
   *clean*.

Every change **ARGUS composes for you** shows **the exact request it will send** first:
accepting a proposal, asking the AI investigator, deciding a group of alike investigations,
confirming proposals, a case action (take, assign, release, contain, reopen, request closure,
merge, check more) and an approval. Read it, then confirm. What you write yourself is saved
from its own form without that step: your decision (**Save decision**, **Add note only**), a
gold-set answer, and notes on cases and addresses. The exact request is one click away in every
confirm dialog (**Show the exact request**). A message says what
happened, and a failed change is never retried by itself.

## ARGUS's proposals
Each investigation has an **AI assessment** tab. Two assessors fill it:
- **The decision engine** proposes an outcome only when people's past verdicts on the same
  kind of alert agree: at least 5 of them, 95% alike, none older than 30 days.
- **The AI investigator** looks at what the engine leaves open. It reads the dossier with
  every campus name and address hidden, may ask the SIEM for more evidence (a fixed list of
  read-only checks), and must quote the facts behind its answer. Whether it is ready, off or
  refused (its instruction files must match the versions written into ARGUS's code) is not
  shown in the app yet: ask an ARGUS admin. **Metrics** shows what it has done.
  **Ask the AI investigator now** works on any investigation.

Neither may propose a harmless outcome while a danger sign is present or unknown (the "floor").
Then **Accept ARGUS's call** at the top of the page if it is right; if it is wrong, choose the
right decision there, and your decision teaches the engine. The AI assessment tab only reads. **No proposal** means ARGUS could not decide; the
tab says why.

**Proposals** (about 10 minutes a week). Proposals are grouped by what decided them. Open the
**audit sample** of a group (picked at random each day); if those are right, **Confirm all**.
Only the listed ones are confirmed; anything that changed meanwhile is skipped. A group that
ARGUS calls *Real: act on it* is never confirmed together: a real attack starts an incident, so
each one is decided on its own page.

**Tuning** (weekly). Per rule: how often it fires, how often a run hit its alert limit (alerts
were lost), your verdicts, and suggested changes. A suggestion is kept only with evidence (an
exception needs at least 3 of your benign or false-positive verdicts on that value and no true
positive). Apply what you agree with in Kibana yourself.

**The AI cost bar** (top of every page) shows what the paid AI provider has cost this month
against the monthly cap (`monthly_cap_usd` in `config/llm.yaml`). It turns amber at the
`margin` share of it (80 % by default): from then on normal work uses only the free providers. **Metrics** has the details and says if the kill switch has stopped the AI.

## Cases
A **case** is one problem across days, hosts and rules: alert groups ARGUS links by the same
actor, indicator or command-and-control address. An **incident** is a case a person confirmed; a
**possible incident** is one ARGUS thinks may be an incident, waiting for a person. **Cases**
opens on **Needs a decision**; the other tabs are Mine, Open, Owner told, Closed and All, and the
*Next step* column says what each case asks for. A case page reads in this order: (for a possible
incident) the decision, summary, report, what's new, timeline, evidence, hypotheses, unknowns,
actions, members, the Kibana mirror, notes, history.
- **Is this an incident?** On a possible incident the decision is at the top: **Confirm as
  incident** (it becomes an open incident and waits for someone who may open it in Kibana, as
  every confirmed case does), **Not an incident…** with a reason (expected activity; a scan or
  attempt where nothing happened; allowed by policy; the rule was wrong; a duplicate of another
  case, which is merged into it), or **Merge into…** another case. Owner, containment and
  closure become available once it is confirmed.
- **Take, Assign, Release, Contain** change who owns the case and its state.
- **Request closure** needs a reason; a second person approves it in **Approvals** after
  confirming their password (a real-incident closure needs two different approvers).
  **Merge** works the same way. **Reopen** brings a closed case back: it needs a reason but
  no approval. A button that is greyed out says why.
- **Check more** asks the SIEM one approved question about one host or address. It is queued
  under your name, its cost is shown first, and its answer is recorded.
- **Notes** are for people only; they are never sent to a model.
- **Approvals** shows each request with its exact changes and the alerts before and after. A
  group of alike closures is approved by a sample first, then the rest, at most 20 at a time.
- **Report** (right after the summary) is the incident report ARGUS writes for each suggested or
  open case, the one the team used to write by hand: what happened, ARGUS's verdict, the
  timeline, who did what, what was affected, the evidence, what was ruled out, the indicators and
  the actions with their owners. **Every evidence line has the exact query behind it and a link
  that opens it in Kibana Discover** (read-only, a new tab): check any line in one click. **Confirm
  the verdict** if it is right; **Reject with a reason** if it is wrong (say what it is instead
  and why: the reason is saved with the label ARGUS learns from). Neither closes the case:
  closing stays a request and an approval. The PDF and the two CSVs (indicators, affected
  devices) are in the Report section; ARGUS writes a new version when the case changes and keeps
  the old ones.
- **Kibana case preview** (next) is what ARGUS would write to the incident case in Kibana for
  this case: step by step, each by its own Kibana user (`argus-lead` opens the case and gives the
  verdict last, `argus-evidence`, `argus-visualiser` (the "Incident at a glance" comment: numbers and live
  charts of the case's alerts), `argus-intel`, `argus-responder`, `argus-hunter`,
  `argus-reporter`), every comment word for word. **Posting is off until the team switches it
  on**, so for now it only shows; looking at it writes nothing. For the first case an approver
  reads the steps and approves exactly them. Once a case is in Kibana, comment
  `Verdict: true positive` or `Verdict: false positive: <your reason>` from your own account:
  ARGUS reads it, saves it as the label it learns from and proposes the closure; closing stays an
  approval.

## Reports
**Reports** has a daily and a weekly report: what waits for a person, what happened, what went
wrong. Every figure says how it was counted. Download one as text or JSON.

## The gold set (about 80 alerts, 2–3 sittings)
An **answer key**: real alerts with the correct outcome written by a person, used to check how
often ARGUS and the AI are right. ARGUS pre-fills each with a suggestion, the reason and the
evidence; you **confirm or correct** in the *Gold set: your answer* box on the investigation
(the *Gold set* page lists them). Think hard only where you disagree: the key must be your own
judgement.

## Rules of thumb
- A successful answer (2xx) after an attack, a threat-list hit, or a regular beacon: never
  benign without a look.
- "Could not be told" means unknown, not safe. "At least" means the real number may be higher.
- A note helps the next person: one line on why.

## If the app does not work
Reload the page first: usually ARGUS was updated a moment ago and the page needs the new files.
If it still does not work, tell an ARGUS admin what you were doing and what the page said.
Old links (in Kibana cases, notices and bookmarks) open the same thing in the app.

## What happens before we call ARGUS ready to roll out
| Step | Who | Status |
|---|---|---|
| Phase 1: collect, group, investigate, Inbox, 72 h soak | ARGUS | done 2026-10-16 |
| Phase 2: privacy layer, gold set, decision engine, AI investigator, cost caps | ARGUS, you approved | done |
| Phase 3: the app, cases, approvals, reports, ELK sign-in | ARGUS, you approve each part | built part by part |
| Writing to Kibana, one kind at a time | your go, with a person watching | off until you switch it on |
| The 7-day soak of the app, with drills | ARGUS | after the writes are on |

**Ready** means: the soak passed with no lost or duplicated alert, the gold-set scores meet the
plan's targets, no real attack was missed, and you have used it for a week and trust it.
