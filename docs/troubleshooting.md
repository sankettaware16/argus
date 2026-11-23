# Troubleshooting

Real messages ARGUS prints, what they mean, and the fix. Search this page for the words you see.

**First steps for any problem**

1. **In the app:** More → **System health** (is the SIEM reachable, are alerts arriving, any
   gaps), and the status in the page header. An administrator's **Settings** page says when
   `argus-admin` is not running and shows what became of each change.
2. **On the server**, when the app does not open or does not say enough:

```bash
uv run argus doctor                     # every part, offline; FAIL lines first
systemctl --user status 'argus-*' --no-pager
uv run argus siem status                # health state, kill switches, breaker, today's budget
journalctl --user -u 'argus-*' --since '1 hour ago' -p warning --no-pager
uv run argus config validate            # the configuration, every problem listed
```

**Contents**

- [Settings and the first-time setup](#settings-and-the-first-time-setup)
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

## Settings and the first-time setup

| What you see | Meaning and fix |
|---|---|
| *argus-admin is not running: changes you save wait until it runs* (Settings), *the setup starts when it runs* (setup) | The service that applies changes is down. On the server: `systemctl --user status argus-admin`, `journalctl --user -u argus-admin -n 50`, `systemctl --user restart argus-admin`. `uv run argus admin status` shows when it was last seen. |
| *argus-admin is not running here, so a key cannot be saved yet* | Keys are sealed for `argus-admin`, so a key can be saved only while it runs. Start it as above, then save again. |
| A change shows **rolled back** | A restarted service did not come back with the new value; the previous files were put back and the services restarted with them. Read why: `journalctl --user -u <the service named> -n 30`. |
| A change shows **refused** | `argus-admin` checked the value again and did not accept it (the reason is on the line), or the installation uses the custody layout, where settings are the custodian's (the head of [deploy/custody/install.sh](../deploy/custody/install.sh) says how it is laid out). |
| *Confirm your password again (within five minutes) to change this* | Keys, addresses, sign-in and allowed hosts need your password again: *Confirm your password* (a new tab), then save again. Your edits are kept. |
| *Type "let ARGUS write to the SIEM" to save this change* | The change lets ARGUS write to the SIEM; type the words exactly. |
| A setting says *Set in the files (argus.yaml / local.yaml) … It is not changed here* | It is changed on the server on purpose (the load budget, the web's own address and certificate, ...): [configuration.md](configuration.md#changing-a-setting-in-the-app). |
| A value in Settings has no effect | The same setting is also set in the process environment (an `ARGUS_...` variable in a unit), which wins over every file. `uv run argus config show` shows the value in effect. |
| *The setup did not finish* | Its output names the problem (the messages are the same as `argus init`'s, below). Your answers are kept: *Back to fix*, then run it again. The full log: `journalctl --user -u argus-admin -n 200`. |
| No *Finish the first-time setup* card on Today | It shows only to administrators, and only until ARGUS has its SIEM address and key. Open `/app/setup` directly to run it again (it replaces the connection; to change one value, use Settings). |
| The one-time link says it has expired or was used | First administrator: rerun `./install.sh` on the server; it keeps everything and prints a new link (the old one stops working). Anyone else: an administrator makes a *New password link* in Users and roles. |

## `argus init`

`./install.sh` runs `argus init`, and the first-time setup in the app runs the rest of it with
your answers, so these messages may appear in the terminal or in the setup's output.

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
| `not taken: this is the "api_key" or "id" of the answer: paste the value of "encoded" (the longest one)` | Kibana's answer has three strings; only `encoded` (about 80 characters) is the key. Init asks again. In an answers file the run stops (exit 2): put the `encoded` value in the key file. |
| `not taken: siem.api_key_expires: '...' is not a date` | Give `YYYY-MM-DD`, the `expiration` number from Kibana's answer (`1801550534086`), or `90d`. |
| `not taken: the two passwords differ` / `a password has 10 to 256 characters` | Type the web password again, the same twice, 10 characters or more. |
| `cannot read the CA's key ... run argus init as an account that can read it, or answer none for a self-signed certificate` | The CA's key is root's: have an administrator sign the web's certificate ([install.md](install.md#13-argus-on-the-siems-own-machine)), put it at `data/tls/argus.crt` and `.key`, and rerun init (it keeps it). |
| `... is not the key of ...` | The CA certificate and key you gave do not belong together. |
| `moved: config/local.yaml named /old/path (another checkout); N paths now name this one` | Not an error: the copied settings now name this checkout. |
| `warn: the services stop when argus logs out and do not start after a reboot: an administrator runs sudo loginctl enable-linger argus once` | Run that line from your administrator account (not as `argus`: it has no sudo). |
| `[sudo] password for argus:` and nothing works | The `argus` account has no password and no sudo, by design. Run `sudo` lines from your own account (`exit`, then `ssh you@host`). |
| `nothing written: run argus init again to answer differently, or write config/site.yaml yourself (argus discover --write) and run argus init again` | You declined discovery's proposal. |
| `uv is not on PATH: set units.uv in config/local.yaml` | Set `units: {uv: /home/argus/.local/bin/uv}` (absolute). |
| `warn: systemd did not reload (no user systemd here?)` | No user systemd session (e.g. `su` into the account). Log in as the user (SSH) or `sudo machinectl shell argus@`, then `systemctl --user daemon-reload`. |
| `init: set up, but doctor found a failure (above): fix it and run argus init again (it keeps everything that is done)` | Read doctor's FAIL lines above that message. |
| `the case team's login: repaired from local/creds-writer/database.writer_password (...)` | Not an error: the case team's database login did not log in with its credential (a new database, or a credential copied from another machine), and init set it from the file. `kept` on the next run. |
| `warn: the case team is set to run (...), but its database login has no password: ...` | The case team's timer is listed in `units.run` or enabled while posting is on, and `local/creds-writer/database.writer_password` is missing. Make it (`umask 077; openssl rand -hex 32 > local/creds-writer/database.writer_password`) and rerun `argus init`, which makes the login; or stop the case team, either way: `ARGUS_CASE_TEAM__POST=false` in `local/argus-writer.env`, or `systemctl --user disable --now argus-case-team.timer` and remove it from `units.run`. Init and doctor count both as off. |
| `warn: local/creds-writer/database.writer_password is empty` (or `is not UTF-8 text`, `is not a regular file`) | The case team cannot start with that file. Write the password again as above (one line) and rerun `argus init`. |
| `warn: the case team's login: argus_writer_app ..., even after argus db bootstrap set it from ...` | The login still does not work: read doctor's `writer login` line; the database's own log (`docker logs argus-db`) says why it refused. |

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
| `the SIEM key is not what ARGUS needs: lacks read on logs-* (make one with the request above: argus init --force-key)` | The key was made with another role. Make a new key with init's exact request, then paste it in Settings → SIEM (or `argus init --force-key` on the server). |
| `... holds write on ...` / `holds cluster privilege manage` | The key can write: ARGUS refuses it. Make it with the request init prints (the role inline limits the key, whatever its creator may do). |
| `the key does not authenticate as an API key` / `problem: not authenticated with an API key` | The value is not an API key (a password, a service token). |
| `problem: lacks cluster privilege monitor` | The health probe needs `monitor`. |
| `problem: server version 7.17.x is not >=8.0,<10` | ARGUS supports Elasticsearch 8.x and 9.x (`site.elastic_versions`). |
| `the SIEM self-test failed: ... (the key needs the exact role below: argus init --force-key)` | After discovery the key must read every family and threat-intel source of the site; the exact role follows the message. |
| doctor `the SIEM key ... expires ...` | Rotate it ([operations.md](operations.md#rotating-the-api-keys)). |
| Collector logs a 401/403 and System health (or `siem status`) shows STOP with `auth_failed` | The key expired or was invalidated. Replace it in Settings → SIEM; the services that read it restart by themselves. |

A key pasted in Settings is stored without this privilege check; run `uv run argus siem
selftest` on the server after a new key. It prints
`selftest passed: TLS pinned, server 8.19, read-only API key` when everything holds. (The version in that line is fixed text: the version check itself compares your
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

1. Was the first-time setup finished? Until it is, only the web and `argus-admin` run, and Today
   shows administrators the setup card.
2. More → **System health**: the SIEM's state, *Alerts collected up to*, *History loaded back to*.
3. On the server, `systemctl --user status argus-collector`: running? If it restarts in a loop,
   read `journalctl --user -u argus-collector -n 100`.
4. `uv run argus siem status`: NORMAL? kill switches? budget?
5. The space: `site.space` (Settings → Organisation and data sources) must be the Kibana space
   whose rules produce the alerts (`.alerts-security.alerts-<space>`). Check in Kibana's Security
   app which space you are in.
6. The key: `uv run argus siem selftest`.
7. Do the rules fire at all? In Kibana: Security → Alerts, in that space.

The collector's first run backfills `history.window` newest hours first; a large SIEM's first
days take a while within the budget.

## Models and the asset map

| Message | Fix |
|---|---|
| `agent: off (no model key)` (in the assessment service's log) | No LLM keys: expected without keys. Add keys on the server ([llm.md](llm.md)); they are not in Settings. |
| `no asset map imported: the privacy layer needs it before any model or outside service is asked (`argus assets import FILE`)` | You added a model key or an outside threat-intel key without an asset map. Import one ([llm.md](llm.md#10-the-asset-map)), then restart `argus-assess`. Or remove the key. |
| doctor `PASS assets no asset map imported (asset context is unknown)` | Fine without model keys: ARGUS runs without asset context. |
| doctor `FAIL privacy domains no domain of the organisation is listed ...` | Add at least one own domain in Settings → Organisation and data sources (`site.own_domains`). |
| `llm.keys_file: ... is readable by others (chmod 600)` | `chmod 600` the keys file. |
| `warn: ... holds no key config/llm.yaml names (...)` | The file's names are not the providers' key names (`GROQ_API_KEY`, ...). |
| `argus llm probe` says `unauthorized` | The provider refused the key. |
| The cost bar is amber / calls stop | The daily or monthly cap is reached; free providers continue where they can. `argus llm status`. |

## Kibana

| Message | Fix |
|---|---|
| `Kibana key: not checked now (its lane is paced; discovery spent this minute's share): check it later with `argus kibana selftest`` | Not an error: run `uv run argus kibana selftest` a minute later. |
| `Kibana's key is not what ARGUS needs: ...` | Make the key with init's printed request (Cases **read** in the space, nothing more), then replace it in Settings → Kibana (or `argus init --force-key`). |
| `Kibana answered as to someone who is not signed in: it did not accept the key` | The key in `.env` is wrong (often the `api_key` field). Check it: `curl --cacert data/certs/siem-ca.crt -H "Authorization: ApiKey <key>" https://<siem>:9200/_security/_authenticate` names `argus-kibana-reader` for a good key. Then `argus init --force-key`. |
| The status bar says **Kibana sync: not running yet** | No read-back cycle is recorded yet. Check `systemctl --user status argus-kibana-sync` and `uv run argus kibana sync status`. The first cycle runs within minutes of the unit starting; while `kibana.enabled` or `kibana.sync.enabled` is false the unit says so and exits. |
| **Kibana sync: late** or **failing** | Its newest cycle is over 90 minutes old, or failed: `journalctl --user -u argus-kibana-sync -n 50`; the SIEM in STOP pauses it on purpose. |
| `PROBLEM: holds ...` from `argus kibana selftest` | The key holds a write privilege it must not: make a narrower key. |
| `kibana.url is not configured (kibana: url: in the settings file)` | Kibana is enabled without an address: give Kibana's address in Settings → Kibana, or switch `kibana.enabled` off there. |
| `argus-kibana-sync` fails at start: `Failed to load environment files` or `the credential directory ... does not exist` | The unit reads `local/argus-kibana-read.env` and `local/creds-sync/`: rerun `argus init` (it makes both when Kibana is set up). |
| `argus kibana state` shows `STOPPED` | Kibana answered 401: renew the key (Settings → Kibana), then on the server `argus kibana resume --reason "..."`. |

## The services and units

| Message | Fix |
|---|---|
| doctor `FAIL unit argus-web.service the installed copy differs from its rendered template (argus units install)` | You changed `units`, pulled a new version, or edited the installed file: `argus units install --apply --reload`, restart that service. |
| doctor `FAIL unit ... not installed: run argus units install --apply` | Install the units. |
| doctor `WARN unit ... installed, not started yet (argus init --start)` | Nothing runs yet: finish the first-time setup in the app, or `uv run argus init --start` on a terminal install. |
| doctor `FAIL unit ... installed but not enabled` | Some units run, and this one, listed in `units.run`, does not: `uv run argus init --start`, or `systemctl --user enable --now <unit>`, or remove it from `units.run`. |
| doctor `WARN unit ... enabled, but units.run does not list it (...): add it there (config/local.yaml) so doctor watches it` | Add the unit to `units.run`. |
| doctor `FAIL unit ... enabled before its production step (...)` | A unit that waits for its own decision (purge, notices, reports, writer) is enabled but not in `units.run`. Add it to `units.run` if you meant it, else disable it. |
| doctor `FAIL unit ... a drop-in changes it: ...` | Remove the drop-in; change `units` or the template instead. |
| doctor `WARN services run the deployed code ... restart them` | The code changed after the services started: restart them. |
| doctor `FAIL unit argus-case-team.service its last run failed (exit-code, exit status 1, at ...) and argus-case-team.timer keeps starting it` | An enabled timer's service failed its last run (the timer starts it again and again). `journalctl --user -u argus-case-team.service -n 30` says why. `password authentication failed for user "argus_writer_app"`: run `uv run argus init` (it sets the login from `local/creds-writer/database.writer_password`). `cannot post: ...` (exit status 2) while posting is on: the line names what is missing (a key, `kibana.enabled`, the expiry, ...); fix that. With posting off (`ARGUS_CASE_TEAM__POST=false`, the documented stop) each run refuses by choice: doctor says `argus-case-team.service refuses its runs: posting is off (...)` in its `service units` line and fails nothing. The line goes with the next run that succeeds. The same holds for any other timer (backups, samples). |
| doctor `FAIL unit argus-....service failed (...): it is not running` | An enabled service stopped with an error and systemd gave up restarting it: `journalctl --user -u <unit> -n 30`, fix the cause, `systemctl --user restart <unit>`. |
| doctor `FAIL writer login argus_writer_app: the case team is set to run (...), but its login has no password` | Put the password in `local/creds-writer/database.writer_password` (mode 600) and run `uv run argus init`, or stop the case team (above). |
| doctor `FAIL writer login argus_writer_app: ... password authentication failed ... run argus init` | The case team's login is missing or has another password than its credential file: `uv run argus init`. Then the case team's next run succeeds. |
| doctor `WARN writer login ... the case team is off, and its login does not log in with ...` | Not a failure while the case team is off; `argus init` repairs the login before you switch it on. |
| The services stop when you log out | `sudo loginctl enable-linger $USER`. |
| `journalctl --user` shows nothing | Turn on persistent journald storage ([operations.md](operations.md#logs)). |
| The web exits: `the web app listens on the loopback only unless it has TLS (tls_cert, tls_key), allowed_hosts and allowed_networks; ...` | Rerun `./install.sh` and give the address, or complete `units.web` by hand ([install.md](install.md#73-your-own-certificate-and-the-firewall)). |
| `units.web: public_url's host must be the loopback or one of allowed_hosts` | The address in `public_url` and `allowed_hosts` disagree (often after a move): rerun `./install.sh` and give the address; it writes both. |
| The web page says **ARGUS cannot reach its database** | The web logs in with its own login (`units.web.database_role: api`) and that login does not exist or has another password: rerun `argus init` (it makes it from `ARGUS_DATABASE__API_PASSWORD` or the web's credentials folder), then `systemctl --user restart argus-web`. `journalctl --user -u argus-web -n 30` shows the database's answer. |
| The browser warns about the certificate | Self-signed: import the certificate (or your CA) into the browsers, or use your own certificate ([install.md](install.md#73-your-own-certificate-and-the-firewall)). Never type a password past a warning you did not expect. |

## Doctor on a fresh install

These are **expected** on a new installation and do not make doctor exit 1:

| Line | Why, and when it goes away |
|---|---|
| `WARN backups no dump in data/backups yet: ...` | The first nightly dump runs at 21:30 UTC (the setup enables the timer); `argus backup dump` makes one now. |
| `WARN restore drill never run: ...` | Goes with the first drill (`argus backup drill`, or the weekly timer). |
| `WARN unit argus-backup.timer not enabled yet (...): a production step` | You declined the backups at init: `systemctl --user enable --now argus-backup.timer argus-backup-drill.timer` and add both to `units.run`. |
| `WARN service units ... none started yet: argus init --start starts them` | The first-time setup has not run yet: finish it in the app (it starts them). On a terminal install where you answered no to starting: `uv run argus init --start`. |
| `WARN classic setting web.classic ... is no longer used: remove it` | An older `config/local.yaml` still names the classic pages, which are gone: delete the line. |
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
