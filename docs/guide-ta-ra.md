# ARGUS — one-page guide for the TA/RA

**The short version.** ARGUS reads every alert from the SIEM, groups related alerts into
*alert groups* (one per rule, key and day), checks the rule's own steps and the logs, and raises an
**incident** when something across those groups looks like a real problem. You open the app (at
`/app`), look at what needs you on **Today**, and decide. ARGUS never confirms an incident for
you and never edits a rule.

**Stop at any certificate warning.** ARGUS asks for your password. If your browser shows *any*
warning about the site's certificate (untrusted, expired, wrong name, "your connection is not
private"), **stop**: do not click through, do not type your password, close the tab and tell an
ARGUS admin. A warning is never "just the first time".

## What ARGUS does in Kibana
- **Today it changes nothing in Kibana.** You decide in ARGUS; a verdict or a closed case here
  does not show in Kibana.
- **Writing to Kibana ships switched off.** An ARGUS administrator switches it on one kind at a
  time in Settings (cases first, then alert status), each after a trial with a person watching. When a kind is
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
- **Open** the address your admin gave you, from a network ARGUS allows. Any old address you
  have bookmarked, and every link in a Kibana case or a notice, leads to the same thing in the app.
- **Your account.** An ARGUS administrator adds you in *Users and roles* and sends you a
  one-time link (valid 72 hours). Open it and choose your own password; nobody else sees it.
  Forgot it? Ask for a new password link. Most reviewers get the **Analyst (TA/RA)** role.
- **If your ARGUS uses ELK sign-in,** sign in with your **ELK (Kibana) username and password**
  instead, the same ones you use in Kibana. Your old reviews, notes and place in the lists stay
  with you: the admin links the two accounts first. ARGUS then keeps no separate password for
  you; change yours in Kibana (user menu, Edit profile). What you can do in ARGUS follows your
  ELK roles.
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
- **Step-up.** Approving a closure asks for your password again, to confirm it is you
  (*Confirm your password* opens a new tab).
- **Settings and people** are for administrators only; you do not need them for reviewing.
- **Browsers.** ARGUS is tested in **Chromium (Chrome, Edge) and Firefox**, current versions.
  Other browsers may work; if something looks wrong in one, try one of these and tell an admin.
- **The menu** is on the left (on a phone, a bar at the bottom): *Today*, *Incidents*,
  *Search*, *Reports*, and under *More*: *Overview*, *Approvals*, *Rule tuning*, *ARGUS
  quality*, *System health*, *Help & glossary*, and the queues *Patterns* and *Proposals*.
  *Help & glossary* explains every page and word. *Your access* (a server page) says what your
  account may do and why; open it when a button is greyed out or a change is refused.

## Daily routine (10–20 minutes)

1. **Today.** Start here. **Needs you** lists the possible incidents waiting for a person,
   sorted by priority. Below it: **Just decided** (what you decided this session, with **Undo**
   for a closure), **New activity** on incidents you know, **Waiting for your approval** (for
   approvers), **ARGUS is unsure about these**, and **Handled by ARGUS**, with a short
   **Spot-check** of what it closed on its own: read a few, it takes seconds each. Each card has
   the decision buttons and an **Open →** link.
2. **Incidents** is the full queue, in tabs: **Needs you**, **Mine**, **Open**, **Owner told**,
   **Closed**, **All**, with filters. On a wide screen, clicking a row opens a **preview** beside
   the list (what happened, why, what was checked, the campus side and the other side) with the
   same decision buttons; `Enter` or `o` opens the full page. Select rows with `x` to close
   several possible incidents with one reason (**Not an incident ▾**), **Merge into one…**, or
   **Review together**. There is no bulk confirm: **Confirm incidents one at a time.**
3. **An incident's page.** The **decision bar** stays at the top while you scroll (at the bottom
   on a phone). Under it, the tabs: **Overview** (what happened, why ARGUS raised it, what was
   seen, what ARGUS checked, other explanations, related incidents, next steps), **Story** (who
   talked to what, and the timeline), **Evidence** (with **Ask ARGUS to check something else**),
   **Entities**, **Alert groups**, **Report**, **Activity** (the log, notes, owner and
   containment). **More about this incident** has **Copy link**, **Download the report (PDF)**
   and **Everything on one page**. If the incident changes while you read, a strip says so:
   **Show what changed**.
4. **Decide** in the bar. On a possible incident:
   - **Confirm incident…** opens a dialog that says what happens and anything **Still open —
     read before you confirm**, with **Take it myself** and an optional note. The button then
     reads **Confirm incident** (or **Confirm anyway** when something is still open).
   - **Not an incident ▾** opens the reasons, each with its letter key:

| Reason (key) | Use it when |
|---|---|
| **Expected activity** (`e`) | It happened and it is normal here (a scheduled scan, a nightly backup) |
| **Scan or attempt: no sign it worked** (`s`) | Someone probed or tried; nothing answered or changed. Not offered when something answered: check first |
| **Allowed by policy** (`p`) | Risky but allowed here (a sanctioned remote-access tool) |
| **Wrong rule** (`w`) | The rule fired on something that was not an attack |
| **Duplicate of…** (`u`) | Another incident covers it: name it, and this one is merged into it |

   Then a short sheet with an optional note and **Close it**. A closure can be undone for a few
   seconds (**Undo**), and from Today's **Just decided** for the rest of your session.
   - **Merge into…** moves it into another incident.

   On a confirmed incident the bar offers what fits its state: **Take it**, **Assign ▾**, and
   under **More ▾**: **Send to Kibana…**, **Report to the CISO…**, **Mark contained**, **Record
   that the owner was told…**, **Request closure**, **Release**, **Merge into…**. A closed one
   offers **Reopen**. A greyed-out button says why. If someone else decided first, nothing is
   sent and you see what changed.

**Keys** (anywhere, while you are not typing): `j`/`k` next and previous card or row, `Enter` or
`o` open, `Esc` close a pane or menu, `c` **Confirm incident…**, `d` **Not an incident…** (then
the reason's letter), `x` select a row, `/` search, `?` the list of keys, `g` then `t`, `i`, `s`
or `r` to go to Today, Incidents, Search or Reports. Nothing is sent on one key: `c` and `d` only
open the dialog or menu.

**Search** takes an address, a host, an account, a domain, a rule, an incident number (`#31`) or
an IR number. It lists the matching incidents and alert groups, and **Open its page** leads to
the **entity page** of a device, an account, a site or an outside address: what ARGUS knows about it, the
incidents whose title names it, and its alert groups of the last 5 days. Clicking an entity chip on an
incident opens a short panel with **Open full page**. **▸ Advanced: alert-group
filters** opens the older alert-group lists (Needs attention, by rule, by host or IP).

**Alert groups** are the building blocks under incidents. Their pages (linked from an
incident's **Alert groups** tab, from Search and from some Today cards) keep the older layout:
tabs **Overview**, **Report**, **AI assessment**, **What ARGUS checked**, **Alerts**, **History**,
and **Your decision** with five outcomes (keys `1`–`5`): **Real: open an incident…**, **Real but
harmless**, **Allowed by policy**, **Wrong alert**, **Can't tell yet**; then **Save decision**.
**Come back to it** keeps it in Needs attention for a follow-up; **Accept ARGUS's call** (key
`C`) takes ARGUS's proposal in one click; `N` goes to the next one. Marking one real opens a
possible incident, or adds it to the incident that holds its activity.

Every change **ARGUS composes for you** shows **the exact request it will send** first, one click
away (**Show the exact request**). What you write yourself (a note, a decision) is saved from its
own form. A failed change says why and is never retried by itself.

## ARGUS's proposals

- **On an incident,** ARGUS's call is the first line of the decision bar, and the Overview says
  **Why ARGUS raised it** (with its priority out of 100) and what it checked. An incident ARGUS's
  AI raised says so (**Raised by ARGUS's AI**).
- **On an alert group,** the **AI assessment** tab shows what the decision engine (your team's
  past verdicts on the same kind of alert: at least 5, 95% alike, none older than 30 days) and
  the AI investigator propose, with the facts they quote. **Ask the AI investigator now** works
  on any alert group.
- Neither may propose a harmless outcome while a danger sign is present or unknown (the
  "floor"). If ARGUS is wrong, decide otherwise: your decision teaches the engine.

**More → More queues** holds two older queues, still useful:

- **Proposals** (about 10 minutes a week): alert-group outcomes ARGUS proposes, grouped by what
  decided them. Open the **Audit sample** of a group; if those are right, **Confirm all**. Only
  the listed ones are confirmed, and nothing is closed in Kibana.
- **Patterns**: alike alert groups, to decide in one go after checking what they have **In
  common**.

**Rule tuning** (weekly, under More). Per rule: how often it fires, how often a run hit its alert
limit, your verdicts, and suggested changes, each kept only with evidence. Apply what you agree
with in Kibana yourself.

**What the AI costs** is in **More → ARGUS quality** (Metrics), which also says if the AI has
been stopped. Past 80 % of the monthly cap (by default), normal work uses only the free
providers.

## Cases

An **incident** is a case a person confirmed; a **possible incident** waits for a person. Once
confirmed:

- **Take it**, **Assign ▾**, **Release**, **Mark contained** change who owns it and its state.
- **Request closure** needs a reason; a second person approves it in **Approvals** after
  confirming their password (a real-incident closure needs two different approvers). A confirmed
  incident's merge works the same way. **Reopen** brings a closed incident back: it needs a reason
  but no approval.
- **Ask ARGUS to check something else** (Evidence tab) asks the SIEM one approved, read-only
  question about one host or address. Its cost is shown first, and its answer is recorded.
- **Notes** (Activity tab, **Add a note to this incident**) are for people only; they are never
  sent to a model or to Kibana.
- **Record that the owner was told…** moves it to **Owner told**: ARGUS then watches it quietly
  and raises only something new.
- **Report** tab: the incident report ARGUS writes (what happened, the verdict, timeline, who did
  what, what was affected, the evidence, what was ruled out, indicators, actions). For a
  confirmed incident it opens with the **analyst brief**: what is happening, a summary, why it
  is judged real, the impact and the numbered steps asked for, each with who takes it and by
  when. ARGUS's AI writes the brief from the report's facts and ARGUS checks every sentence
  against them (**The facts it rests on** lists them); it may still be wrong, so read the
  evidence before you send it on. **Report to the CISO…** builds its mail from the brief. **Every
  evidence line has the exact query behind it and a link that opens it in Kibana Discover.**
  **Confirm the verdict** if it is right; **Reject with a reason…** if it is wrong. Neither closes
  the incident. The PDF and the two CSVs are there too, and a new version is written when the
  incident changes.
- **Kibana case preview** (Report tab) is exactly what ARGUS would write to the case in Kibana,
  step by step, each step by its own Kibana user. **Send to Kibana…** posts it, once the team has
  switched posting on. Once a case is in Kibana, comment `Verdict: true positive` or
  `Verdict: false positive: <your reason>` from your own account: ARGUS reads it and proposes the
  closure; closing stays an approval.
- **Approvals** (under More) shows each request with its exact changes. Approving or rejecting
  needs your password again (**Confirm it is you**).

## Reports
**Reports** has a daily and a weekly report: what waits for a person, what happened, what went
wrong. Every figure says how it was counted. Download one as text or JSON.

## The gold set (about 80 alerts, 2–3 sittings)
An **answer key**: real alerts with the correct outcome written by a person, used to check how
often ARGUS and the AI are right. ARGUS pre-fills each with a suggestion, the reason and the
evidence; you **confirm or correct** in the *Gold set: your answer* box on the investigation
(*ARGUS quality*, Gold set tab, lists them). Think hard only where you disagree: the key must be your own
judgement.

## Rules of thumb
- A successful answer (2xx) after an attack, a threat-list hit, or a regular beacon: never
  benign without a look.
- "Could not be told" means unknown, not safe. "At least" means the real number may be higher.
- A note helps the next person: one line on why.

## If the app does not work
Reload the page first: usually ARGUS was updated a moment ago and the page needs the new files.
If a page says it could not load, use its **Try again**; nothing was changed. If it still does
not work, tell an ARGUS admin what you were doing and what the page said. Old links (in Kibana
cases, notices and bookmarks) open the same thing in the app.

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
