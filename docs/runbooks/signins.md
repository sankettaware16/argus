# Runbook: who was behind an address (AR6)

The security team often finds the person behind an infected internal address from the SSO sign-in logs. ARGUS
does it for every investigation and case: it reads the SSO sign-ins of the internal addresses it
holds, keeps the accounts per address and UTC day (the logs last five days at the SIEM; ARGUS keeps
180), and shows the probable user(s) on the investigation and case pages, on the case timeline, in
the incident report (PDF, an accounts CSV) and in the Kibana case. Decisions: D-216 to D-220, and the
review's fixes D-222 to D-227. Code in `src/argus/signins/`.

**Today: off.** `signins.enabled` is false and nothing has been sent to the SIEM. The code, the
tables (migration 0056) and the pages are in; with the switch off every page and report is exactly
what it was (the pages show a card that says ARGUS is not reading the sign-in logs yet).

## What a person reads

Always with the wording: **"Probable user, from SSO sign-ins on this address — a lead, not proof:
addresses can be reassigned."** For each internal device of the investigation or case, one of (a
**device** is an internal address on the **source side** of the alerts, read from the grouping key:
the infected host, not an own server that an outside scanner only probed, D-226):

| State | Meaning |
|---|---|
| Probable user (`likely`) | exactly one account had successful sign-ins in the alerts' window (first alert minus 2 h to last alert plus 2 h), no day was a shared one, and every day was read completely |
| Possible users (`possible`) | two or three accounts; listed by successful sign-ins, then by nearness to the alerts. When single accounts differ from day to day it says the address **changed hands** ("used by X on 26 Oct and by Y on 28 Oct") |
| Shared address (`shared`) | a day with four accounts or more (or more than ARGUS lists, or that many different accounts over the window): a lab or a NAT. **Only a count; no one is guessed** |
| No sign-in seen (`none_seen`) | every day was read completely and no account had a successful sign-in in the window (accounts with only failed sign-ins are listed apart) |
| Not known (`unknown`) | a day was not looked up yet, the lookup was incomplete, it was made before the window ended, some sign-ins had **no account name** ("N sign-in events without an account name", D-223), or the logs are no longer kept; the line says which, and lists what was seen so far |

An account counts only if it had an event in an hour the window touches (the hourly buckets).
Whether a sign-in succeeded is known for the day, not for the hour. Accounts with only failed
sign-ins do not make an address "shared" (D-227). A device is read over the alerts of **its own**
investigations, never the whole case's span (D-226).

## Privacy

Account names are personal data. They are shown **only to an account with `see_logs`**; everyone else
gets the state and the count ("2 accounts signed in from this address — hidden: needs log access") and
no name in any field. The accounts CSV and the PDF need `see_logs`. **No model ever sees a name**
(cloud or local): the report's accounts are facts read from the logs with no safe form, the guarded
prose never reads them, and tests hold the model side of the code away from the package and its tables.
The pass logs counts only. Fixtures use synthetic names. `scripts/privacy_sweep.py` fails if a stored
name appears in any rendered model request (run it at each gate).

The Kibana case receives the accounts (the "Accounts affected" comment by `argus-evidence`, the
accounts CSV): the security team's escalation always has an "accounts affected" table, and Kibana's own
access decides who reads the case.

## Turning it on (the lead, with the user)

1. Deploy, then `uv run argus db upgrade` (migrations 0056 and 0057), then the web, the terminal and
   the writer.
   The sign-in family (role `auth`, `watch: false`) is in `site.families`; the reader's key reads its pattern.
2. See the plan without sending anything: `uv run argus signins run --dry-run`. It reads ARGUS's own
   database, prints how many address-days are wanted and each request it would send (day, how many
   addresses, the index), and validates each against the gateway's contract.
3. Not between 00:00 and 01:30 UTC. One request by hand, with the user watching the SIEM:
   `uv run argus signins run --max-requests 1` after setting `signins.enabled: true` (or
   `ARGUS_SIGNINS__ENABLED=true`). Read its server time in the ledger (`siem_requests`,
   template `signins.day`): a request is a `terms` filter on `source.ip` and the action allowlist inside
   one day's index, `size` 0, with a 30 s timeout. Its cost on the SIEM is **not measured yet**.
4. If the time is acceptable, leave it on: `argus assess run` then makes the pass every cycle (at most
   `max_requests_per_pass` = 6 requests of up to 200 addresses, at least 3 s apart, NORMAL health only,
   the investigation lane's budget).
5. **Backfill** the retained days: `uv run argus signins run --backfill --max-requests 60`. It lifts the
   per-pass cap up to the number given (at most 500), keeps the 3 s gap, and waits for the investigation
   lane's budget instead of stopping. About 14 requests cover the 2,800 address-days of the five retained
   days; the rest are the current day's refreshes. Run it in a quiet hour: the wave and "Check more" share
   the lane.
6. Look: `uv run argus signins show --case 11` (or `--investigation ID`, `--address IP`). It prints names
   on the operator's terminal and says so.

## Settings (`signins:` in `config/argus.yaml`)

| Setting | Default | Meaning |
|---|---|---|
| `enabled` | `false` | the pass sends nothing while false |
| `actions` | the browser and interactive sign-in events | `user_login_success`, `user_password_auth_success`, `user_prompt_challenge_success`, `user_authorize`, `user_saml_authorize`, `user_session_switch`, `user_access_token_auth`, `user_login_fail`, `user_authorize_fail`. The LDAP proxy's actions (95% of the data, 18 servers with 400 to 2,000 users each), `client_*`, mail, SMS and `user_logout` never identify a device's user |
| `pad_hours` | `2` | sign-ins from this long before the first alert to this long after the last |
| `shared_accounts` | `4` | an address with this many accounts on a day is shared |
| `batch` | `200` | addresses in one request (one daily index, at most 200) |
| `max_requests_per_pass` | `6` | requests a pass may send |
| `gap` | `3s` | the least between two requests (not below 3 s) |
| `current_day_every` | `1h` | a day not over is looked up again no sooner |
| `retention_days` | `5` | days of SSO logs the cluster keeps, today included; an older day is "logs no longer kept" |
| `keep_days` | `180` | how long ARGUS keeps what it read (pruned at every pass, with the switch off too, D-227) |
| `final_after` | `3h` | a finished day is final once looked up this long after its end; a day looked up sooner is looked up once more then (15 minutes to 24 hours, D-224) |

## What the pass does, and does not

- Plans from ARGUS's own database: the internal IPv4 addresses on the **source side** of the grouping
  keys of the investigations active in the retained days (`store.source_devices`; a destination is
  not a device, D-226). Members of a case that is not closed first, then raised or high and
  critical, then the rest, newest first. Only one pass runs at a time (a database lock, D-222): the
  assessment loop and `argus signins run --backfill` do not both plan the same batches.
- A day that is over (plus the 15-minute ingest margin) is looked up; it is **final** only when the
  lookup was made `final_after` (3 h) after its end, so a day looked up sooner is looked up once more
  (D-224). The current day is looked up when it has not been, or an hour after the last lookup if that
  did not read as far as the window needs. A lookup is dated by how far its request read, not by when
  it was answered. An incomplete lookup is retried after 30 minutes; a missing index of a day that
  should still exist (`index_missing`) and an answer the database refused (`store_failed`) after 6 hours;
  an answer refused 3 times in a row is left alone and said; a day older than the logs are kept is
  never asked again.
- A timed-out or shard-failed answer is **incomplete, never "none seen"**. An answer that is not exactly
  the template's shape is stored as incomplete (`bad_answer`) and said. **Either one ends the pass**
  (D-222): one request shows a mismatch with the contract, six would only repeat it. Sign-in events with
  no account name make the lookup incomplete (`unnamed_events`, D-223).
- Text from the logs (account names, browser strings) is made storable before it is kept (NUL, lone
  surrogates and control characters become U+FFFD; names cut to 256). If the database still refuses an
  answer, it is stored address by address and only the address it cannot take waits (D-222).
- It stops at the first refusal (kill switch `investigation`, the SIEM not NORMAL, the lane's debt, the
  breaker) and leaves the rest for the next pass. It never reads two days in one request.
- A sign-in that lands in the neighbouring day's index (ingest delay near UTC midnight) is missed; the
  request is one index by rule.
- `keep_days` governs the two sign-in tables only. Account names are also in the stored incident reports
  (append-only), in a posted Kibana case and in backups (D-227).

## When something looks wrong

| Sign | Cause and what to do |
|---|---|
| every device "Not known: not looked up yet" | the pass is off or has not reached them: `argus signins run --dry-run` shows what is waiting |
| "the lookup was incomplete" for a day | the SIEM answered partially; ARGUS retries after 30 minutes; if it persists, the request is too heavy: lower `batch` |
| "the sign-in logs are no longer kept" | the day is older than `retention_days`; nothing can be done for it |
| "the lookup was incomplete" and `index_missing` in `show --address` | the day's index is not there though it should be (a shipper outage or a late ILM); ARGUS asks again every 6 hours |
| a "bad answer" line in the pass | the SIEM's answer changed shape (a mapping change): a surprise, not a failure to ignore; the parser refuses rather than guesses |
| "could not be stored 3 times and are left alone" | the database refused the rows of an address-day three times (`argus signins show --address IP` prints the tries); look at the database log for the cause; the rest of the batch is stored |
| "another pass is running" | the lock is held by another process (the assessment loop or a backfill); it is given back when that pass ends |
| "N sign-in events without an account name" | the logs hold sign-ins whose `user.name` is missing or too long; the day stays "not known" with the named accounts as "so far" |
| a very high server time | lower `batch`; the lane's debt rule already slows the pass |
| a name that should not be seen | check the account's `see_logs`; the server sends none otherwise (`hidden`) |

Tests: `tests/unit/signins/` (template, parse, attribution properties, plan, browser words, privacy
guards, the review's pure parts), `tests/integration/signins/test_review.py` and
`test_devices_window.py` (the review's fixes), `tests/integration/caseteam/test_confirm_core.py`, `tests/integration/signins/` (migration, store, the pass end to end, privacy against the
database), `tests/integration/web/test_signins*_ar6.py` (the API shown and hidden), `tests/unit/incident/
test_accounts.py`, `tests/unit/caseteam/test_accounts.py`, `frontend/tests/signins-*.test.tsx` and the
live test `tests/live/test_signins_live.py` (one address, one finished day, one request; run only with
`--run-live` inside a live session).
