# Runbook: write-back (R17 v2, Q-D5) — people's decisions into Kibana's alerts

Design: D-061 to D-063, plan §5 Q-D5 and §7.10, DQ8 and DQ11 (D-110). Code: `src/argus/writeback.py`
(plan, diff), `writeback_sender.py` (the sender), `writeback_cli.py`. **Off.** Nothing has been
written to the SIEM (D-109): the first run is the user's, with them present.

## What it writes (DQ11 (a): alert status only)

| Decision | Kibana alert status |
|---|---|
| a person's review as benign, policy or false positive (`benign_expected`, `benign_policy`, `rule_false_positive`) | **closed** |
| a person's review as true positive, or a follow-up | **acknowledged** |
| inconclusive, a note | nothing |
| an approved case closure (not `duplicate`, not `created_in_error`) | its alerts **closed** |
| a benign verdict (or closure) that rests on Q-F1's "nothing found" | **waits** until `writeback.f1_audited: true` (your decision after the audit) |

Only alerts the reviewer saw (linked before the review) whose status differs. A newer decision on
the same investigation supersedes an older row not sent yet, and the sender checks that again
before each batch (also a case reopened). Alert tags (WT, D-004) are not written.

## Who may reach Kibana

- A review made under an ELK check that showed the alert-status privileges (`review`, the
  capability map) in a verified session: yes, by the default plan.
- An earlier review by a person (local mode, an unverified session): only in a **terminal run whose
  operator signs in with their own ELK account** (`--operator NAME`, the password read with
  `getpass`, checked live through the identity lane, and the check must show `review`). Plan them
  first with `uv run argus writeback plan --older`; `diff` lists them under `needs_operator`.
- Break-glass and service accounts: never. The ARGUS service user cannot be the operator.

## Local, no request

```
uv run argus writeback plan [--older]   # new decisions and closures -> planned changes
uv run argus writeback diff             # per status: items and alerts left; needs_operator; held
```

## A real run (in the writer's account; it holds the alert writer's key)

Conditions, each refused with its own reason: `writeback.enabled: true`; `kibana.enabled`;
`WA` in `kibana.write_classes`; `kibana.alert_writer_api_key` installed with a recorded expiry;
a person at a terminal who types `WA`.

```
sudo argus-owner --as writer writeback run [--operator NAME] [--limit N]
```

For each batch the sender, in this order: waits out the gap since the last alert call (at least
60 s, shared with W1's attaches); checks the kill switch, the SIEM NORMAL (disk under 85 %, no index
block), Kibana's breaker and the write window; reads the alerts (`alerts.mget`): one already at the
status, or gone, is counted without a request, the rest have their **previous status kept** on the
row; sends one status call of at most `writeback.batch` alerts (5 until production numbers, at most
100); checks the update_by_query body Kibana answers with; reads the alerts back; moves the row
(`sent_count`, `written_count`) with an audit row. It holds the case writer's lock, so a W1 attach
and a status call never go at once.

Everything that decides whether a row may go out (a newer review or a reopened case; an operator
check older than 30 minutes; the audit of Q-F1; the review's author and its ELK check) is read
from its sources, not from the row, and is read again, with the alerts' statuses, at the last
step before the request leaves. A change found there sends nothing: the row is skipped, left
waiting, or the batch is planned anew. A row whose alerts cannot be read waits for the next run;
the run goes on to the next row.

- The first run writes at most **5 alerts**, then stops. Check them in Kibana. A second run writes
  0 once everything planned is done.
- Later runs write up to `writeback.run_limit` alerts (a call a minute: 50 alerts take 10 minutes).
- The daily alert-mutation cap (1,000 a day, shared with attaches) and the window (02:30-17:30 UTC,
  never 00:00-01:30) are the lane's.

### When it stops

Any error ends the run; nothing is retried (a **429 never**). The row is `paused`; the next run
reads the alerts first, so an alert that landed late is counted, never written twice.

| What you see | What it means | What to do |
|---|---|---|
| `Kibana's answer: ...` (the class WA is paused) | the answer's body was not a clean report: failures (a flood-stage block comes as `cluster_block_exception` in a 200), conflicts, `timed_out`, an id Kibana did not find (a 200 with total 0), fewer or more alerts than named | read why (`uv run argus kibana state`), check the alerts in Kibana, then `sudo argus-owner kibana resume --reason "..." --class WA` |
| `read-back: n of m alerts do not show ...` (WA paused) | Kibana said yes, Elasticsearch shows otherwise | same |
| `Kibana did not answer ...; the read-back shows it landed` / `n of m alerts show the new status` | a timeout or a 5xx: the read-back decides; what landed is counted | nothing; run again later (a timeout is charged to the lane for about an hour) |
| `the SIEM is caution (disk_caution)`, `stop (index_blocked)` | disk at 85 % or more, or a block: write-back is off | wait for the SIEM; nothing was written |
| `stopped by the kill switch` | `argus siem stop --component writeback` | `argus siem resume --component writeback` |
| `the alert writer key failed its self-test` | the key holds more than update on the alerts (`delete`, `all`, `manage`, `create_index`) or too little | mint it again (ER9b); nothing was sent |
| `row N needs an operator ...` / `waits for the audit of Q-F1` | left on purpose | `--operator NAME`; `writeback.f1_audited` |

Stop at once: `uv run argus siem stop --component writeback`.

## Enabling (your decisions, each step)

1. The alert writer key (ER9b, `elk_mint_writer`), installed in the writer's credentials with its
   expiry; `uv run argus kibana selftest --key alerts` (from the writer's account).
2. `kibana.write_classes: [WA]` and `writeback.enabled: true`.
3. `plan`, `diff`; then the first run with you present (at most 5 alerts); check them in Kibana;
   a second run writes 0.
4. Then `writeback.batch` (5 until production numbers, at most 100 by your decision) and the
   schedule are yours (DQ8); no schedule exists yet.
