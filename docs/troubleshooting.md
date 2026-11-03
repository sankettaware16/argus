# Troubleshooting

Real messages ARGUS prints, what they mean, and the fix. Search this page for the words you see.

**First steps for any problem**

```bash
uv run argus doctor                     # every part, offline; FAIL lines first
uv run argus siem status                # health state, kill switches, breaker, today's budget
journalctl --user -u 'argus-*' --since '1 hour ago' -p warning --no-pager
uv run argus config validate            # the configuration, every problem listed
```

**Contents**

- [`argus init`](#argus-init)
- [Certificates and TLS](#certificates-and-tls)
- [The API key](#the-api-key)
- [The SIEM: quiet hours, deferred, budget, stopped](#the-siem-quiet-hours-deferred-budget-stopped)
- [Nothing arrives](#nothing-arrives)
- [Models and the asset map](#models-and-the-asset-map)
- [Kibana](#kibana)
- [The services and units](#the-services-and-units)
- [Doctor on a fresh install](#doctor-on-a-fresh-install)
- [Configuration errors](#configuration-errors)

---

## `argus init`

| Message | Fix |
|---|---|
| `MISSING: uv is not on PATH: https://docs.astral.sh/uv/getting-started/` | Install uv ([install.md](install.md#22-uv-and-python-312)) and open a new shell. |
| `MISSING: docker-compose.yml is not here: run argus init in the checkout` | `cd` into the ARGUS checkout first. |
| `MISSING: docker is not installed: https://docs.docker.com/engine/install/` | Install Docker Engine ([install.md](install.md#21-docker-engine-and-the-compose-v2-plugin)). |
| `MISSING: docker compose v2 is missing: install the compose plugin (...)` | Install `docker-compose-plugin`. The old `docker-compose` v1 does not count. |
| `MISSING: the Docker daemon cannot be reached: start it (systemctl start docker), or add yourself to the docker group and log in again` | `sudo systemctl enable --now docker`; `sudo usermod -aG docker $USER`, then log out and in. |
| `MISSING: port 55432 is in use by another program: set ARGUS_DATABASE__PORT in .env to a free port and run argus init again` | Another program listens there (`ss -ltnp 'sport = :55432'`). Put e.g. `ARGUS_DATABASE__PORT=55433` in `.env`. |
| `MISSING: the database container argus-db belongs to another ARGUS checkout (...); this one would take it over. Set COMPOSE_PROJECT_NAME, COMPOSE_DB_CONTAINER and ARGUS_DATABASE__PORT ...` | A second installation on this machine: give this checkout its own three values in its `.env` ([install.md](install.md#10-a-second-argus-on-the-same-machine)). |
| `MISSING: 1.4 GiB free in ...: ARGUS needs at least 2 GiB (its database grows)` | Free disk space, or move the checkout and Docker's data to a bigger disk. |
| `argus-db is not healthy after 120 s: docker logs argus-db` | Read `docker logs argus-db`. Common: a volume from an earlier install with another owner password (`docker compose down -v` deletes it and **its data**). |
| `warn: ARGUS_DATABASE__OWNER_PASSWORD, ... still hold .env.example's placeholder: change them` | `.env` was copied from `.env.example`. Change the passwords before ARGUS holds real data (in `.env` and, for an existing database, with `ALTER ROLE`), then `argus db bootstrap`. |
| `` `argus db bootstrap` failed (the error is above) `` | Usually the owner password in `.env` does not match the database's (an old volume). |
| `siem.url: must be https://host[:port] with no path, user or query` | Give `https://siem.example.org:9200`; ARGUS never uses plain HTTP. |
| `answers.yaml does not answer siem.url (...)` | A scripted install lacks an answer: add it ([install.md](install.md#5-scripted-install-argus-init---answers)). Exit code 2. |
| `answers.yaml gives siem.api_key itself: a key never goes in the answers file; name a file (siem.api_key_file) or an environment variable (siem.api_key_env) instead` | Put the key in a mode-600 file and name it. |
| `siem.api_key_file: ... is readable by others (chmod 600)` | `chmod 600` the key file. |
| `the SIEM key does not look like an API key's encoded form` | Paste the `encoded` value of the answer, not `id` or `api_key`. |
| `nothing written: run argus init again to answer differently, or write config/site.yaml yourself (argus discover --write) and run argus init again` | You declined discovery's proposal. |
| `uv is not on PATH: set units.uv in config/local.yaml` | Set `units: {uv: /home/argus/.local/bin/uv}` (absolute). |
| `warn: systemd did not reload (no user systemd here?)` | No user systemd session (e.g. `su` into the account). Log in as the user (SSH) or `sudo machinectl shell argus@`, then `systemctl --user daemon-reload`. |
| `init: set up, but doctor found a failure (above): fix it and run argus init again (it keeps everything that is done)` | Read doctor's FAIL lines above that message. |

## Certificates and TLS

| Message | Meaning and fix |
|---|---|
| `no TLS handshake with https://...: ...` | The address is wrong, the port closed, or a firewall in between. `curl -vk https://siem.example.org:9200` from the ARGUS machine. |
| `data/certs/siem-ca.crt no longer verifies https://... (...): run `argus init --force-trust` to pin the CA again` | The SIEM's certificate now comes from another CA (renewed or replaced). Check the new CA's fingerprint with its administrator, then `argus init --force-trust`. |
| `siem.fingerprint does not match the CA https://... presents (..., SHA-256 ...): nothing is trusted` | The fingerprint in your answers file is not the one the server shows. Do not "fix" it by copying the shown one: confirm with the SIEM's administrator first (a mismatch can be an interception). |
| `the presented CA was not confirmed: nothing is trusted` | You answered no to the fingerprint question. |
| `the presented CA ... does not verify https://... (...); if the server does not send its root CA, give the CA file instead (trust: file)` | The server sends only its own certificate or an intermediate. Use `trust: file` with the CA file. |
| `https://... does not verify against the system's CA bundle: ...` | `trust: system` is only for certificates from a public CA. Use `chain` or `file`. |
| `Hostname mismatch, certificate is not valid for ...` (in the reason) | The certificate does not name the host you gave. Use the name it was issued for (`openssl s_client -connect host:9200 </dev/null 2>/dev/null \| openssl x509 -noout -ext subjectAltName`), or reissue it. ARGUS never turns the host-name check off. |
| doctor `FAIL the SIEM CA ... expired on ...: renew the pin` | The pinned CA expired: the SIEM's administrator renews it, then `argus init --force-trust`. Doctor warns 30 days ahead. |
| doctor `FAIL web certificate pin` | The web serves another certificate than `web.tls_pin_sha256` says: update the pin after a deliberate renewal; otherwise find out why. |

## The API key

`argus init` and `argus siem selftest` check the key with Elasticsearch's `_authenticate` and
`_has_privileges` (read-only):

| Message | Fix |
|---|---|
| `the SIEM key is not what ARGUS needs: lacks read on logs-* (make one with the request above: argus init --force-key)` | The key was made with another role. Make a new key with init's exact request and `argus init --force-key`. |
| `... holds write on ...` / `holds cluster privilege manage` | The key can write: ARGUS refuses it. Make it with the request init prints (the role inline limits the key, whatever its creator may do). |
| `the key does not authenticate as an API key` / `problem: not authenticated with an API key` | The value is not an API key (a password, a service token). |
| `problem: lacks cluster privilege monitor` | The health probe needs `monitor`. |
| `problem: server version 7.17.x is not >=8.0,<10` | ARGUS supports Elasticsearch 8.x and 9.x (`site.elastic_versions`). |
| `the SIEM self-test failed: ... (the key needs the exact role below: argus init --force-key)` | After discovery the key must read every family and threat-intel source of the site; the exact role follows the message. |
| doctor `the SIEM key ... expires ...` | Rotate it ([operations.md](operations.md#rotating-the-api-keys)). |
| Collector logs a 401/403 and `siem status` shows STOP with `auth_failed` | The key expired or was invalidated. Rotate it, restart the services. |

`argus siem selftest` prints `selftest passed: TLS pinned, server 8.19, read-only API key` when
everything holds. (The version in that line is fixed text: the version check itself compares your
server's real version with `site.elastic_versions`.)

## The SIEM: quiet hours, deferred, budget, stopped

None of these is an error: they are the gateway protecting the SIEM. Work waits and resumes by
itself.

| Message | Meaning |
|---|---|
| `the list of indices could not be read: nothing is proposed (the SIEM's quiet hours, 00:00-01:30 UTC: ARGUS asks it nothing optional now; run this again after 01:30 UTC)` | Discovery (or `argus init`'s step 6) ran in the quiet hours. Run it again after the window. |
| `discover waits for the end of the quiet hours (01:30 UTC)`, `freshness waits for ...` | The same, for discovery and the freshness readings. |
| `signins: waiting for the end of the quiet hours (01:30 UTC)` | The sign-in lookups wait for the window's end. |
| `the SIEM is caution: discover waits` (`deferred`) | This kind of work is not allowed in the current health state ([configuration.md](configuration.md#health-states)). Discovery, backfill, reconciliation and the investigation wave need NORMAL. |
| `the SIEM is degraded: no budget for ...` | DEGRADED leaves a tenth of the budget to collection. Also seen **before the first health probe**: ARGUS treats a SIEM it has never probed as DEGRADED. Start the collector (it probes every minute) or run `argus siem probe`. |
| `the SIEM is in STOP` / `log reads wait: the SIEM is in STOP or ARGUS is stopped` | Health is STOP (disk ≥ 95 %, a 401/403, a blocked index, or no probe for 15 minutes: is the collector running?) or a kill switch is thrown. `argus siem status` says which. |
| `stopped by the operator's kill switch` | Someone ran `argus siem stop`. `argus siem resume --reason "..."` (needs the owner password in `.env`). |
| `the daily budget is spent`, `the heavy_daily budget is spent`, `the investigation lane's daily budget is spent` (`skipped_budget`) | The day's or minute's server-time allowance is used up; work resumes as the bucket refills. If it happens daily, look at what spends it (`argus siem status`) before raising `siem.budget.took_per_day_ms`. |
| `the SIEM reported overload; requests pause until the breaker closes` | The SIEM answered 429 or tripped a circuit breaker: ARGUS pauses for 5, 15, then 60 minutes. |
| `error: resuming needs the database owner (Q-A5): ...` | Run the resume where `ARGUS_DATABASE__OWNER_PASSWORD` is set (in `.env` on a standard install). |
| `source_expired: ...` / `source_not_ready: ...` | A daily index a query needed was deleted by ILM, or not created yet: the evidence says "could not tell", never "clean". Keep `history.window` within your log retention. |

## Nothing arrives

1. `systemctl --user status argus-collector`: running? If it restarts in a loop, read
   `journalctl --user -u argus-collector -n 100`.
2. `uv run argus siem status`: NORMAL? kill switches? budget?
3. `uv run argus collect status`: what the store holds, the backfill's progress.
4. The space: `site.space` must be the Kibana space whose rules produce the alerts
   (`.alerts-security.alerts-<space>`). Check in Kibana's Security app which space you are in.
5. The key: `uv run argus siem selftest`.
6. Do the rules fire at all? In Kibana: Security → Alerts, in that space.

The collector's first run backfills `history.window` newest hours first; a large SIEM's first
days take a while within the budget.

## Models and the asset map

| Message | Fix |
|---|---|
| `agent: off (no model key)` (in the assessment service's log) | No LLM keys: expected without keys. Add keys ([llm.md](llm.md)). |
| `no asset map imported: the privacy layer needs it before any model or outside service is asked (`argus assets import FILE`)` | You added a model key or an outside threat-intel key without an asset map. Import one ([llm.md](llm.md#10-the-asset-map)), then restart `argus-assess`. Or remove the key. |
| doctor `PASS assets no asset map imported (asset context is unknown)` | Fine without model keys: ARGUS runs without asset context. |
| doctor `FAIL privacy domains no domain of the organisation is listed ...` | Set `site.own_domains` (at least one) in `config/site.yaml`. |
| `llm.keys_file: ... is readable by others (chmod 600)` | `chmod 600` the keys file. |
| `warn: ... holds no key config/llm.yaml names (...)` | The file's names are not the providers' key names (`GROQ_API_KEY`, ...). |
| `argus llm probe` says `unauthorized` | The provider refused the key. |
| The cost bar is amber / calls stop | The daily or monthly cap is reached; free providers continue where they can. `argus llm status`. |

## Kibana

| Message | Fix |
|---|---|
| `Kibana key: not checked now (its lane is paced; discovery spent this minute's share): check it later with `argus kibana selftest`` | Not an error: run `uv run argus kibana selftest` a minute later. |
| `Kibana's key is not what ARGUS needs: ...` | Make the key with init's printed request (Cases **read** in the space, nothing more), `argus init --force-key`. |
| `PROBLEM: holds ...` from `argus kibana selftest` | The key holds a write privilege it must not: make a narrower key. |
| `kibana.url is not configured (kibana: url: in the settings file)` | Kibana is enabled without an address: rerun `argus init` with Kibana's address, or set `kibana.enabled: false`. |
| `argus-kibana-sync` fails at start: `Failed to load environment files` or `the credential directory ... does not exist` | The shipped unit expects `local/argus-kibana-read.env` and `local/creds-sync/`: create them ([kibana.md](kibana.md#the-read-back)). |
| `argus kibana state` shows `STOPPED` | Kibana answered 401: renew the key, then `argus kibana resume --reason "..."`. |

## The services and units

| Message | Fix |
|---|---|
| doctor `FAIL unit argus-web.service the installed copy differs from its rendered template (argus units install)` | You changed `units`, pulled a new version, or edited the installed file: `argus units install --apply --reload`, restart that service. |
| doctor `FAIL unit ... not installed: run argus units install --apply` | Install the units. |
| doctor `FAIL unit ... installed but not enabled` | A unit listed in `units.run` is not enabled: `systemctl --user enable --now <unit>`, or remove it from `units.run`. |
| doctor `WARN unit ... enabled, but units.run does not list it (...): add it there (config/local.yaml) so doctor watches it` | Add the unit to `units.run`. |
| doctor `FAIL unit ... enabled before its production step (...)` | A unit that waits for its own decision (purge, notices, reports, writer) is enabled but not in `units.run`. Add it to `units.run` if you meant it, else disable it. |
| doctor `FAIL unit ... a drop-in changes it: ...` | Remove the drop-in; change `units` or the template instead. |
| doctor `WARN services run the deployed code ... restart them` | The code changed after the services started: restart them. |
| The services stop when you log out | `sudo loginctl enable-linger $USER`. |
| `journalctl --user` shows nothing | Turn on persistent journald storage ([operations.md](operations.md#logs)). |
| The web exits: `the web app listens on the loopback only unless it has TLS (tls_cert, tls_key), allowed_hosts and allowed_networks (D-104); ...` | Complete `units.web` ([install.md](install.md#73-open-it-on-the-network-tls)) or return to the loopback. |

## Doctor on a fresh install

These are **expected** on a new installation and do not make doctor exit 1:

| Line | Why, and when it goes away |
|---|---|
| `WARN backups no dump in data/backups yet: the nightly dump starts when argus-backup.timer is enabled (a production step)` | Enable the backup timers ([operations.md](operations.md#backups)). |
| `WARN restore drill never run: ...` | Goes with the first drill (`argus backup drill`, or the weekly timer). |
| `WARN unit argus-backup.timer not enabled yet (...): a production step` | The same. |
| `WARN approval signing key (web) web.approval_key_file is not set: ...` | Make the key when you want two-person approvals ([web-ui-guide.md](web-ui-guide.md#approvals)). |
| `WARN node toolchain no Node at ... (the system Node is never used): the frontend cannot be built on this machine` | Only developers who rebuild the web app need Node ([development.md](development.md#the-web-app)). |
| `WARN custody not installed: ...` | A root-owned hardening layout used by the project's own production; not needed for a standard installation. |
| `WARN agents since approval cannot tell: ...` | The checkout has no approval tags for the AI investigator's instruction files (a release clone). Informational. |
| `PASS assets no asset map imported (asset context is unknown)` | Fine until you add model keys. |
| `PASS threat intel no source in site.ti_sources: threat ...` | No threat-intel source was discovered or configured. |

Anything that is `FAIL` on a fresh install is a real problem: read its line, fix, rerun doctor.

## Configuration errors

ARGUS refuses to start on any unknown or invalid setting and lists every problem with where it
was set:

```
invalid configuration (/home/argus/argus/config/argus.yaml, environment and /home/argus/argus/.env):
  - siem.budjet: unknown setting (check the spelling); did you mean budget? [local.yaml line 4]
```

- `unknown setting; nested settings are written as an indented section, not with dots`: write
  `siem:` / `  url: ...`, not `siem.url: ...`.
- `site.yaml holds the 'site' section only, not ...`: move other sections to `config/local.yaml`.
- `quiet_hours ... write the time in quotes, as "22:00"`: YAML reads `22:00` unquoted as a number.
- `kibana.write_window: must not reach into the quiet hours (...)`: the write window and the
  quiet hours overlap.
- `freshness.mode on needs the derived margins (freshness.margins)`: leave freshness `off` or
  `shadow`.

`uv run argus config validate` prints the same list without starting anything.
