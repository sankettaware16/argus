# Runbook: `argus discover` — propose the `site` section from an Elastic (P4-D1, D-282, D-283)

ARGUS is one code base for many sites; what differs between them is the `site` section of the
settings (D-280): which indices hold which logs, what their fields are called, the Kibana space,
the versions and licence ARGUS may write against. `argus discover` reads a few things from the
Elastic ARGUS is pointed at and **proposes** that section, with the evidence for each part. It
reads names and mappings, never a document, and it writes nothing to the SIEM; with `--write` it
saves the proposal as `config/site.yaml` on this machine.

## Before you run it

- The SIEM address, its CA and a read key are set (`siem.url`, `siem.ca_file`,
  `ARGUS_SIEM__API_KEY` in `.env`). The key is the read-only one: `monitor`, `read` and
  `view_index_metadata` on the indices. With `read_ilm` the retention is read from ILM too; without
  it the command says so and judges retention from the dated indices.
- For Kibana's version, spaces and feature ids: `kibana.enabled` and the reader key
  (`ARGUS_KIBANA__READER_API_KEY`). Without them the command says what it did not read and still
  proposes the Elasticsearch part (`--no-kibana` skips Kibana on purpose).
- The database is up (`uv run argus doctor`): every request is ledgered like the others.
- The SIEM is **NORMAL** and it is not 00:00-01:30 UTC (the command refuses otherwise, and every
  request asks again, so a long run does not drift into those hours). "NORMAL" is the health the
  collector's last probe left, if that is less than 90 seconds old; otherwise the command takes one
  probe itself (node stats and, for the families the site already names, their index blocks) and
  uses it for this run only. **It never saves a probe or a health state:** the stored memory is
  the collector's, and a `STOP` for blocked indices or a `DEGRADED` for late sources is not
  cleared or set by a discovery. A site that names no family yet is judged by the node stats.
- It remembers **no failure** either: a 401 or 403 on one of its reads (a key without a
  privilege, a `site.space` that is wrong) is a warning in its output and a row in the request
  ledger, and does not put ARGUS's access in STOP or stop the Kibana lane (which only
  `argus kibana resume` could lift). It does respect a stop that is already there: a stopped
  Kibana lane or the global kill switch stop its reads.

## Run it

```bash
uv run argus discover --dry-run          # the requests, none sent
uv run argus discover                    # the proposal and the evidence
uv run argus discover --write            # also writes config/site.yaml (never over a file)
uv run argus discover --write --force    # replace an existing config/site.yaml
```

`--max-mappings N` (default 12) is how many candidate families have their mapping read; the ones
with the most telling names come first, the rest are judged by their names alone and the report
says how many.

## What it reads, and what it costs

All are `GET` except one `_has_privileges` `POST`; each is a light template through the Elastic
Gateway (the kill switches, the NORMAL-only health rule, the enrichment lane and budget (D-321), the
ledger with component `discover`) or the Kibana lane (reader key). About 8 requests plus one per
examined family, a few hundred milliseconds of server time in all.

| Read | Why | Cap |
|---|---|---|
| `GET /` | Elasticsearch's version | version number only |
| `GET /_license` | level and status: writes need an active licence | type, status |
| `GET /_resolve/index/*` | indices, aliases and data streams (names only) | 5,000 of each, 200 backing indices a stream; the cut is said |
| `GET /_resolve/index/.alerts-security.alerts-*` (hidden included) | which spaces have a Security alerts index | same |
| Kibana `api/status`, `api/spaces/space`, `api/features` | Kibana's version, the spaces, the Security and Cases feature ids | ids and names only |
| `GET <newest index>/_mapping/field/<fields>` | how the well-known fields are mapped (type, `.keyword`) | one day's index, stream backing index or alias (never a system index), at most 80 allowlisted fields |
| `POST /_security/user/_has_privileges` (`monitor`, `read_ilm`) | whether ILM may be read | — |
| `GET /_ilm/policy` (only when `read_ilm` is held) | each policy's delete age and what uses it | 5,000 names |

It never searches, never reads a document and never aggregates. A key without a privilege one of
these needs is answered 401 or 403: the read becomes a warning (`auth_failed`, `kibana_forbidden`)
and the command goes on. ILM is still asked for only after `_has_privileges` says the key holds
it. The Kibana reads go to `/s/<site.space>/api/...`: with a wrong space they fail as warnings and
the space is then proposed from the Security alerts aliases alone.

## Reading the proposal

```
Log families proposed: 4
  web [web] corp-logs-nginx-* - high confidence (16 points, daily)
      the name has nginx (4 points)
      the mapping has http.request.method, ..., url.path, user_agent.original (12 points)
      event time: @timestamp (@timestamp is mapped as date)
      kept: 3 days from 2026.10.28 to 2026.10.30
```

- **Role** (proxy, web, dns, auth, mail) is decided by points: words in the index or data stream
  name (`nginx` 4 points, `dns` 3, `sso` 3) and well-known fields in the mapping (`url.path`,
  `dns.question.name`, `user.name`). A role is proposed with 4 points, or on a name that alone
  gives 3 (a mapping read later can add to a proposal and never removes one). **High** confidence
  needs the name and the mapping to agree; **medium** is a good score; **low** is a product name
  alone or a score that only just reached the minimum. "also looks like web (7 points): check it"
  names a rival role within one point. A mapping answer that names none of the fields asked about
  counts as not read (the family is judged by its name and says so).
- **Pattern**: `prefix-*` is daily indices `<prefix>YYYY.MM.DD`; a name without `*` is one data
  stream or alias, named as it is in a request. A family is never a hidden or system index.
- **fields**: only what differs from the ECS names. A text field with a keyword sub-field that the
  evidence modules query (a URL, a domain, a DNS name, an account name) is written with
  `.keyword`. A note says when a queried field is text without a keyword (it cannot be queried),
  or is not mapped.
- **auth** families are `watch: false`: read for sign-ins, not watched by the health probe and the
  freshness lane.
- **Space**: the Kibana space that has a `.alerts-security.alerts-<space>` index; with two, the
  first is proposed and the warning names both (ARGUS reads one space). A space id is lowercase
  letters, digits, `_` and `-`; an alias with another suffix is left out and said.
- **Looked like no log role**: candidates that scored nothing. Check this list: a family you expect
  may be there if its name and fields are unusual; add it to `site.yaml` by hand.
- **Names left out**: Elasticsearch allows names a family pattern does not (`@`, `=`, an accented
  letter) and a dated index whose date is none (`x-2026.13.45`). They are not proposed; one warning
  names the first five.
- **Suggestion: history.window**: no deeper than the shortest retention found. It is not part of
  the `site` section; set `history.window` yourself.

Everything the SIEM supplies (index names, versions, aliases) is cleaned of control characters
before it is printed or put in a comment, and the YAML is loaded back and compared with the
proposal before it is shown or written: if it does not load back as the proposal, nothing is
shown as YAML and nothing is written.

## After it

1. Read `config/site.yaml`; edit what is wrong (the evidence is in its comments). It is ignored by
   the repository: it belongs to this installation. `--write --force` writes a temporary file in
   `config/` and renames it, so a failed write leaves the old file whole.
2. `uv run argus doctor` loads it and names the families (the `site` line). `config/site.yaml` is
   read beside `config/argus.yaml`, below it in priority; it may hold only the `site` section. An
   installer that cannot write a file sets the whole section as one JSON value,
   `ARGUS_SITE='{"space": "soc", "families": [...]}'`; a list of families is not a setting of its
   own (`ARGUS_SITE__FAMILIES` is refused).
3. The family names are the **source keys** in stored evidence and readings (`proxy`, `web`,
   `dns`, `auth`, `mail` by default). Choose them before ARGUS has stored anything: renaming one
   later orphans what was stored under the old key.
4. Ask the organisation for the words discovery cannot guess and put them in the section
   (`config/argus.yaml`'s `site:` comments say each): `timezone` (and `timezone_label`),
   `incident_id_prefix`, `own_networks` and `own_domains`, `own_network_noun`, `organisation`
   (its name and its security team's), `quiet_hours`. They are all read (D-284); `argus doctor`
   prints the zone, the incident ID form and how many own networks and domains the site has.
   **The zone and the prefix are chosen once**: every investigation id depends on the zone (the
   day an investigation covers), so changing it later starts new investigations at the new day
   boundary; the prefix is on every incident ID already sent. A family's mapping facts, if the
   defaults (ECS fields as a Logstash pipeline maps them: text with a `.keyword` sub-field, `ip`,
   `long`, `integer`) are wrong, are `types` (a field path to a mapping type, for example
   `url.original: keyword` for an Elastic Agent) and `ignore_above` (default 256).
5. The privilege checks (`argus gateway selftest`, the `see_logs` capability) ask `read` on each
   family's own pattern, and on the `site.ti_indices` it names (none by default). If the key is
   granted one wider pattern instead, give it as `site.log_patterns` (a site's `corp-logs-*`, say).

## Two families of one role

`argus discover` may propose two families of one role (two proxies, two web servers); the second
gets a product word or `<role>_2` as its name. The evidence then reads the family **the rule
reads**: a rule's index entry that names one (`corp-b-squid-*`, its dataset, or its name as a
whole word) or that only its pattern covers (`corp-b-*`); a rule that names none of them reads the
first and logs a warning (`argus.site`). The request carries the family's name in its `source`
parameter whenever the site has two or more of the role, so the stored evidence says which log
was read; a one-family site's requests are unchanged. The live check and the first run's
measurement take the family from the alert's rule too (D-284). Still the **first** family of the
role: the sign-ins (one auth family a day) and the case watch's contact and pair checks (a case
has no rule of its own; reading every family needs a family column in their tables).

A rule's index entries are lower-cased and matched by dataset or by whole word: a bare `squid`,
`*squid*` or `my-squid-logs` names the `squid` family, `corp-logs-squidguard-*` does not, and
an entry broader than a family (`corp-logs-*`) names none (it reads them all).

## Versions

`site.elastic_versions` and `site.kibana_versions` are comma-joined comparators (`>=8.0,<10`,
`==8.19.12`, `*`) over numbers, compared number by number: a version is up to three ASCII numbers
without leading zeros (`9` is 9.0.0, `==8.19` is 8.19.0); `8.19.12.1`, `8.19.012` and
`8.19.12abc` are no version and are never allowed. A pre-release or snapshot (`8.19.12-SNAPSHOT`)
counts as its numbers but is never equal to the release and never on a bound: `>=9.0.0` does not
allow `9.0.0-rc1`.

## Logs that are not there

A data stream or alias the site names that Elasticsearch does not have answers `source_missing`
(never created, renamed, mistyped), not `source_expired` (ILM deleted a day of a daily family): the
evidence is "asked again", never "the logs are no longer kept". A search of a data stream must
carry a range on the family's time field in its filter (all the shipped templates do), since the
name spans every backing index.

## What it will not do

Change anything in the SIEM, read a log, guess a resolver (D-174), or pick the organisation's
networks and domains (`site.own_networks`, `site.own_domains`): those are asked of a person.
