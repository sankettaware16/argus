# Compatibility: which Elastic ARGUS works with

ARGUS stands on its own. It needs **one Elastic SIEM** (Elasticsearch and Kibana with the Security
app) and nothing else: no other component of the TLSOC Ecosystem, no particular log pipeline, no particular
licence. A company, a university or a lab that already runs Elastic as its SIEM installs ARGUS
with `./install.sh`, connects it in the browser, and it starts working the alerts Kibana Security
already raises.

## What ARGUS needs from Elastic

| | Needed | Why |
|---|---|---|
| Elasticsearch and Kibana **8.x or 9.x** | yes | ARGUS reads the Security alerts index and Kibana's Cases API |
| **Security on** (the default since 8.0), over **HTTPS** | yes | ARGUS uses API keys and checks the certificate it is given |
| Kibana **Security** with **detection rules** that raise alerts | yes | the alerts are what ARGUS triages; without rules there is nothing to do |
| Your logs in Elasticsearch (any index names, ECS fields preferred) | yes | the evidence ARGUS asks for; discovery finds the families itself |
| Kibana Cases | optional | the read-back of cases, and the case team's posts when you switch them on |
| Threat-intel indices | optional | discovery finds them; ARGUS checks indicators against them |

## Licences

Everything ARGUS needs is in the free **Basic** licence, and it uses no paid feature: a paid
level changes nothing for it.

| Licence | ARGUS reads (alerts, logs, threat intel, cases) | Kibana cases written by ARGUS's team |
|---|---|---|
| **Basic** (free) | yes | yes |
| Gold, **Platinum**, **Enterprise**, **Trial** | yes | yes |
| Expired or invalid | yes | **no** (ARGUS refuses every write and says why) |

ARGUS reads the licence itself (`GET /_license`, in discovery and before any write) and adapts;
you never set it.

## How it was tested

`scripts/licence_matrix.py` runs what a new installation does against a local Elasticsearch and
Kibana (`scripts/kibana_tier.py`: security on, HTTPS with its own CA), first on the licence the
cluster has, then on a trial licence (every paid feature), then back to Basic:

| Step | Basic | Trial (all paid features) |
|---|---|---|
| An administrator's login makes ARGUS's read-only Elasticsearch key (the setup's "Let ARGUS create its own access") | ✓ | ✓ |
| … and its read-only Kibana key | ✓ | ✓ |
| The key holds `monitor` and read on the Security alerts | ✓ | ✓ |
| The key holds no write or administration privilege | ✓ | ✓ |
| The key reads the Security alerts | ✓ | ✓ |
| The Kibana key reads cases | ✓ | ✓ |
| ARGUS's Kibana case team made (two roles, seven users, a key each) | ✓ | ✓ |
| ARGUS reads writes as allowed | yes | yes |

Measured on Elasticsearch and Kibana 8.19.12 (17 November 2026). The contract tests in
`tests/kibana/` (reads, case writes, alert status, the writer) also run against the same local
cluster on Basic. To measure your own version:

```bash
uv run python scripts/kibana_tier.py init
scripts/heavy.sh --label kibana-tier uv run python scripts/kibana_tier.py up --hold &
uv run python scripts/kibana_tier.py seed
uv run python scripts/licence_matrix.py
```

## Where Elastic runs

| Deployment | Status |
|---|---|
| Self-managed (Docker, packages, VMs), single node or cluster | supported, tested |
| Elastic Cloud Hosted | expected to work (the same APIs and API keys); not measured yet |
| Elastic Cloud Serverless | not supported yet (different privileges and no licence API) |
| OpenSearch, OpenSearch Dashboards | not supported: ARGUS reads the alerts of Kibana's Security app |

## On its own, or in the TLSOC ecosystem

ARGUS is also one component of the TLSOC ecosystem (log parsing, a TLS-secured Elastic stack,
dashboards, reporting). It uses none of them: they help build an Elastic SIEM, and ARGUS works
with any Elastic SIEM, built with them or not.
