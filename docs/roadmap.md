# Roadmap

What ARGUS does today, what is built but switched off, and what is planned. No dates: items move
when they are measured and ready.

## Current

Shipped, running in production at its first site:

- **Collection** of every Security alert of one Kibana space, with backfill of `history.window`,
  hourly reconciliation and quarantine of unreadable alerts.
- **Grouping** into investigations (rule, actor, day), patterns of alike investigations, and case
  suggestions across investigations.
- **Deterministic investigation**: evidence packs for proxy, web, DNS, threat-intel and sign-in
  logs, the entity's history, dossiers with every fact's source and query.
- **The Elastic Gateway**: a server-time budget split into lanes, health states, quiet hours, an
  overload breaker, kill switches, a query-contract validator and a ledger of every request.
- **Assessment**: the decision engine learned from people's verdicts; the optional AI
  investigator behind a privacy layer and an LLM gateway (free providers first, cost caps);
  guardian checks and the safety floor.
- **The Inbox**: review queues, investigations, cases, two-person approvals, incident reports
  (page, PDF, CSVs), daily and weekly reports, rule-tuning reports, the gold set and metrics.
- **Kibana read-back** of the cases holding ARGUS's alerts.
- **Operations**: `argus init` (interactive or scripted), `argus doctor`, rendered systemd units,
  verified backups, the retention purge.
- **Discovery** of a new site's log families, space and threat-intel sources from metadata only.

## Built, off by default

Each needs a decision and a person present for its first run at a new site:

- **Kibana case team**: posting a person-confirmed incident case to Kibana, step by step.
- **Alert status write-back**: closing or acknowledging alerts after reviewed verdicts.
- **Sign-in with ELK accounts**, capabilities derived from the account's own privileges, and the
  emergency account.
- **The deterministic investigation wave** and the daily **case watch**.
- **Freshness readings** ("nothing found, logs complete to <time>" instead of "could not tell").
- **E-mail notices** carrying a link, a severity and a count.
- **Outside threat intel** (VirusTotal, Shodan, Censys) with your own free keys.

## Planned

- Switch the investigation wave on, measure a day of its load from the ledger, then the case
  watch; off again on any CAUTION that ARGUS causes.
- The alert status write-back in real use, after its canary.
- A local model for helper tasks, each task only after its evaluation against the gold set.

## Known gaps

- The Kibana read-back unit expects two files under `local/` (the first site's layout); a
  standard install creates them by hand ([kibana.md](kibana.md#the-read-back)).
- The root-owned hardening layout the first site runs (service accounts, credentials outside the
  checkout) is not documented for other installations yet.
- Some runbooks under `docs/runbooks/` still carry the first site's local times and file layout.

Ideas and requests: open an issue on <https://github.com/sankettaware16/argus>.
