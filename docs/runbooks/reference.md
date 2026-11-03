# Runbook: reference data (R9) — rules registry and threat intelligence

For the operator of the ARGUS machine. Design: D-057.

## Rules registry (automatic, no SIEM request)
Every alert carries its rule's definition, so ARGUS builds the registry from the alerts it
stores. The collector refreshes it every 15 minutes; by hand:
```
uv run argus rules refresh     # catch up (short batches)
uv run argus rules list        # name, type, revision, schedule, alerts, truncated runs
```
**Truncated runs**: an execution that produced as many alerts as the rule's `max_signals`
(100 by default) may have had more matches that Kibana dropped. Each one is a closed
`truncated_execution` coverage gap; investigations of that rule and time show it. Raising a
rule's `max_signals` in Kibana is the SIEM admin's decision.

**Execution status** (rules that stopped running, or report gaps) needs Kibana's rules
API. The reader key has no Kibana privileges, so the registry says `execution unknown`
until a key with Kibana read for the site's space is approved and configured.

## Threat intelligence
- A mirrored source (`mode: mirror` in `site.ti_sources`) is copied into Postgres every 6 hours.
- A looked-up source (`mode: lookup`, a large index) is asked in batches of up to 100 exact values;
  answers (misses too) are kept 24 hours.
- A source is **stale** when its newest indicator is older than 7 days. A miss in a stale
  source is reported as "no match (stale source)", never as clean.

```
uv run argus ti status                 # freshness of each source, mirror size
uv run argus ti lookup 77.221.155.150  # what ARGUS knows (local; remote too when sync is on)
```

### First live check (needs you; once)
The TI templates passed the local Elasticsearch tier. Their first run on the SIEM is a
human-issued live-test session (D-056): 6 small read-only requests.
```
uv run argus live start --max-requests 20 --minutes 10   # confirm at the prompt
export ARGUS_LIVE_SESSION=<the id it prints>
uv run argus ti check --session $ARGUS_LIVE_SESSION      # ends with LIVE CHECK PASSED/FAILED
uv run argus live stop $ARGUS_LIVE_SESSION
```
Avoid 00:00–01:30 UTC. If it passes, switch the sync on in `config/argus.yaml`:
```
reference:
  ti_sync: true
```
and restart the collector (`systemctl --user restart argus-collector`). Then
`uv run argus ti sync` once, and `uv run argus ti status` shows the mirror.

### Second check: the log templates (needs you; once each, D-069)
Web follow-up (a search): inside a live-test session, 15 minutes of nginx, at most 10 rows.
```
uv run argus live start --max-requests 10 --minutes 10   # confirm at the prompt
uv run argus worker live-check --session <the id it prints>   # LIVE CHECK PASSED/FAILED
uv run argus live stop <the id>
```
Proxy aggregations: live tests never aggregate, so this is a one-off job you confirm
(2 aggregations over one hour of squid, under the normal budget):
```
uv run argus worker proxy-check        # type the word it shows; LIVE CHECK PASSED/FAILED
```
Run both between 02:15 and 23:14 UTC (07:45 to 04:44 IST). The lead then switches on
`enrichment.log_queries` (web) and `enrichment.proxy_aggregations` (proxy) and restarts the
worker.

## Knowledge store
`config/knowledge.yaml` holds seeds (empty in Phase 1). `uv run argus knowledge load` adds
new ones; existing items are never overwritten. A `benign_pattern` must have `expires_at`.
