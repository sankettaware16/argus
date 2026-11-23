# Notices (Q-H4)

ARGUS can send a short e-mail when something needs a person: a confirmed case that is still
active, a closure nobody has decided, an internal host that reached a known-bad address, or ARGUS
not seeing everything for an hour. The e-mail carries **a link, a severity and a count, and
nothing else**: no host, address, user or rule name (plan §5 Q-H4, §7.7; DQ26 as D-110 answered
it). **Off until you approve the organisation's network mail relay and name the recipients.** It is the fix for
what happened with PS1Bot: its hosts kept beaconing for 10 days after their verdicts and nobody
was told.

Until you switch it on, `argus notices run` still works out and remembers what would be worth a
notice, prints it and says **"not switched on, by your choice"**; nothing leaves the machine.

## What is worth a notice

All five are worked out from ARGUS's own database (never from the SIEM), every 10 minutes
(`argus-notices.timer`), so a flag reaches a person within the hour (success rule 18: the watch's
flag, plus at most one pass).

| Kind | When | Severity | The count is |
|---|---|---|---|
| A confirmed case is still active | an open, assigned or contained case where the watch (Q-C2) found its host active on one of the last 3 days, after the verdict or the containment (a `new_activity` event counts too) | the case's; at least *high* if it had been contained | days of activity since |
| Activity after a case was closed | a case closed as fixed has an `activity_after_closure` event in the last 3 days (the link leads to the follower case when there is one) | the case's, at least *high* | times noted |
| A closure is waiting | a closure request nobody has decided for more than 12 hours that has not expired | *medium*; *high* in its last 12 hours | hours waiting |
| An internal host reached a known-bad address | an unreviewed investigation with alerts in the last day whose newest dossier lists an indicator a feed marks high-confidence ("high", or a score of 75 to 100), and whose actor is an internal host | *high*; *critical* for a critical alert | high-confidence indicators |
| ARGUS cannot watch everything | the SIEM's health memory DEGRADED or STOP (also a probe silent for 15 minutes), the Kibana lane stopped or a write class paused, the daily watch on and not run for 36 hours, or ARGUS's own collector lag (once it has lasted an hour: one closed sooner whose hours reconciliation found complete was only lateness, "collected late", D-321), an open breaker or a stalled log source | STOP and collector lag *high*, the rest *medium* | hours so far |

A request for a closure lives to the end of the next Kibana write window (15 to 39 hours, plan
§7.1), so it is noticed after 12 hours (`WAITING` in `argus.notices.triggers`; the plan's "over 24
hours" never held for a request made in the evening, UTC): at least 3 hours before it expires.

## The rules

- **One notice for each thing** until it is resolved or its severity rises (a higher severity is
  a new notice; a lower one never is). What was resolved and comes back is a new notice.
- **A reminder at most once a day** ("Still waiting: ...") for what waits for a person (an active
  case, activity after closure, a closure). Never for an event or an outage.
- **An outage** is told once, when it has lasted an hour, and once more when it ends. Nothing in
  between.
- **At most 10 e-mails an hour in all.** When more are due, the most urgent go out one by one and
  the last e-mail says "N more notices", with a link to the Inbox. The hour's count is read from
  the audit trail (`notice.sent`, `notice.folded`), so a restart cannot forget it. What the hour
  cannot take waits for the next pass; nothing is lost.
- A message that could not be sent is not marked: the next pass sends it. A crash between the
  send and the mark can send one twice, never none.

## What an e-mail looks like

```
Subject: [ARGUS High] A confirmed case is still active

A case that was confirmed as a real incident is still showing activity.

Severity: High
Activity seen on 2 days since the verdict or containment.

Open it in ARGUS:
https://argus.example.org/go/case/6f1c...

This is an automatic notice from ARGUS. It names nothing on purpose: ...
```

The link opens the case (or the investigation, or the Health page for an outage) for people who
are signed in and may see it. The subject and body are built from fixed text and numbers; the
sender and recipients are checked to be one plain address each (no line break, comma, name or
quote), so nothing in the data can add a header or a recipient. The only values in the message
are the severity, the count and the web address you configure.

## Switching it on (your steps)

1. **Ask your IT team for a mail relay** that accepts mail from this machine: host, port (25, 587),
   whether it offers STARTTLS (use it if so), the From address it will accept for ARGUS (for
   example `argus@<your domain>`), and whether it needs a login (most internal relays accept by
   network address).
2. **Choose the recipients** (up to 20, one address each).
3. Put the settings in production's own `.env` (never in `config/argus.yaml`: every checkout loads
   it). Under custody they go in `/etc/argus/argus.env`:
   ```
   ARGUS_NOTICES__RELAY_HOST=mail.example.org
   ARGUS_NOTICES__RELAY_PORT=587
   ARGUS_NOTICES__RELAY_STARTTLS=true
   ARGUS_NOTICES__RELAY_FROM=argus@example.org
   ARGUS_NOTICES__RECIPIENTS=ta@example.org,ra@example.org
   ARGUS_NOTICES__WEB_URL=https://argus.example.org      # or web.public_url
   ARGUS_NOTICES__ENABLED=true
   ```
   A relay that needs a login: `ARGUS_NOTICES__USER` and `ARGUS_NOTICES__PASSWORD` (the password
   is a secret: `.env` only; a login is allowed only with STARTTLS or to the loopback). Under
   custody the password is the credential `notices.password` in `/etc/argus/credentials/`; the
   unit names it with a `LoadCredential=notices.password:...` line at this step (it is optional
   and not loaded until then, so nothing fails without it).
4. `uv run argus doctor`: the `notices` line must be PASS or a WARN you understand (no recipient,
   links that point to the loopback, no pass yet).
5. **Send yourself the test message:** `uv run argus notices test --to you@example.org`. It is
   refused while `enabled` is false. It travels the same path as a real notice and is audited
   (`notice.test`). If it does not arrive, read the error (the relay's reply is not shown, only
   the kind of failure), check the relay with your IT team, and do not go on.
6. `uv run argus notices run --dry-run`: what would go out, nothing stored or sent. Then
   `uv run argus notices run` once by hand.
7. **Enable the timer** (it is off until now): `systemctl --user enable --now argus-notices.timer`
   (shared layout), or under custody after `deploy/custody/install.sh` has copied the units:
   `sudo systemctl enable --now argus-notices.timer`. Check with `argus notices status` and
   `systemctl --user list-timers argus-notices.timer`.

## Looking and stopping

- `uv run argus notices status`: whether notices are on and why not, who gets them, the link
  address, when a pass last ran, how many things are live and told for each kind, and the e-mails
  of the last hour (of 10) and day.
- `argus doctor` warns when notices are on and no recipient is named, when no pass ran in the last
  hour (is the timer enabled?), when the relay failed lately, and when links point to the loopback.
- **To stop:** set `ARGUS_NOTICES__ENABLED=false` (the next pass stops sending; the table is kept)
  and/or `systemctl --user disable --now argus-notices.timer`. Switching off and on again sends
  what is still due, not what is old: an outage that ended more than a day ago is not announced.
- The table `notices` holds a kind, an opaque subject (a case's or investigation's id), the
  severity, the count, when it was first and last seen and when it ended, and the last notice that
  went out. It holds no host, address or name and is never purged. Every e-mail is in the audit
  trail as `notice.sent` (or `notice.folded` for "N more") by `system`, with the kind, severity,
  count and number of recipients; a failure is `notice.send_failed`.

## Limits and honest gaps

- **A case that keeps beaconing is found by the still-active watch** (`cases.watch: local` or
  `on`, runbook `case-watch.md`). With the watch off, a case is told as active only when an
  investigation joins it or reopens it (`new_activity`). `argus doctor` warns about it.
- The threat-intel trigger reads the confidence the dossier stored from the feeds ("high", or a
  score of 75 to 100). A feed that writes confidence another way never triggers it; check what
  yours writes with `SELECT confidence, count(*) FROM ti_indicators GROUP BY 1` (local table).
  A live lookup's matches (`ti.listed_remote`) carry no confidence in the dossier and are not used.
- A beacon seen in the proxy logs only is flagged by the watch within about 28 hours (a day is
  read after it ends); the notice follows the flag within 10 minutes.
- SMTP over implicit TLS (port 465) is not supported; use STARTTLS (587) or a plain relay inside
  the internal network.
- The relay's certificate is checked against the system's CAs; a relay with a private CA needs
  that CA installed on the machine.
