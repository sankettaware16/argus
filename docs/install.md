# Installing ARGUS

From a bare Linux machine to ARGUS taking in your SIEM's alerts, in two steps: one command on the
server, then the rest in your browser. After that, people use and run ARGUS from the web app:
settings, users and roles included.

ARGUS reads your Elastic SIEM with a **read-only API key** and writes nothing to it unless an
administrator switches a write on. Everything it keeps (alerts, investigations, cases, reviews)
lives in its own PostgreSQL database on this machine.

> **Upgrading an existing installation?** Follow [upgrading.md](upgrading.md) instead.

## Install in two steps

### What you need

- **A Linux machine** (4 cores, 8 GB of memory and 100 GB of disk recommended; section 1)
  with **Docker and its compose plugin**, **[uv](https://docs.astral.sh/uv/)** and **git**
  (section 2 shows how to install them). Run ARGUS from an ordinary account, for example `argus`,
  that is in the `docker` group.
- **From the SIEM:** Elasticsearch's address, and **a read-only API key** for ARGUS. Section 3.2
  has the exact request an Elastic administrator runs to make it. Optionally, Kibana's address
  and a read-only Kibana key, if you want ARGUS to read Kibana cases.
- About 15 minutes.

### Step 1: on the server

```bash
git clone <ARGUS's repository> argus && cd argus
./install.sh
```

`./install.sh` installs ARGUS's Python packages, creates the database (in Docker) with new
passwords of its own, makes the web's certificate and starts two services: the web app and
`argus-admin`, which applies the changes people make in the app. It asks one question, the
address people will open ARGUS at (this machine's IP address or name; leave it empty to keep the
web on this machine only and reach it through an SSH tunnel, section 7.2). It ends with a
one-time link for the first administrator:

```
init: done. Open this link within 72 hours to set admin's password and finish the setup
in the browser:

    https://192.0.2.10:8765/welcome?token=…
```

Lost the link, or it ran out? Run `./install.sh` again: it keeps everything already done and
prints a new one (the old link stops working).

### Step 2: in the browser

1. **Open the link** and choose a password for the account `admin` (10 characters or more).
   Your browser warns about the certificate the first time: ARGUS made it itself
   (section 7.3 shows how to use your own).
2. **Sign in.** Today shows a card, **Finish the first-time setup**: press **Start the setup**.
3. **Answer the four steps:**
   - **Your organisation:** its name, the security team's name, your own domains and networks
     (so ARGUS can tell inside from outside), the time zone, and the prefix of incident ids.
   - **The SIEM:** Elasticsearch's address. ARGUS reads the certificate the SIEM presents and
     shows it; compare its fingerprint with the one your Elastic administrator gives you, then
     trust it by its certificate authority or pin it. Paste the read-only API key and when it
     expires. The log index patterns are optional: ARGUS finds the log families itself.
   - **Kibana (optional):** its address, its certificate, a read-only key and the Kibana space
     with the Security alerts (found by itself when left empty). Without a key, Kibana stays off;
     you can add it later in Settings.
   - **Review and run:** check the summary, confirm your password, and press the button.
4. **Watch it finish.** `argus-admin` checks the SIEM with your answers, discovers which logs
   and Kibana space your SIEM has, writes the configuration, and starts every service. The page
   shows its progress. The first alerts arrive in the Inbox within minutes.

Keys you paste are sealed as soon as they leave the browser: only `argus-admin` can open them,
and the app can never show them again, only replace them.

### After the setup: everything is in the app

| To… | Go to |
|---|---|
| Change any setting (the SIEM, Kibana, outside lookups such as VirusTotal, notices, retention, backups, sign-in, the incident engine…) | **More → Administration → Settings** |
| Add people, give them a role, reset a password, switch an account off | **More → Administration → Users and roles** |
| See whether data is arriving, and any gaps | **More → System health** |
| Work alerts and incidents | **Today**, **Incidents**, **Search** ([web-ui-guide.md](web-ui-guide.md)) |

**Settings** shows every setting with its help and its current value, grouped by subject. A
change is checked, written and applied by `argus-admin` within seconds, and only the services that
read it restart. If a service does not come back, the old configuration is put back by itself and
the change is marked *rolled back*. Changing a key or an address asks for your password again;
anything that would let ARGUS **write to your SIEM** (Kibana cases, write-back) also asks you to
type a confirmation. The limits on ARGUS's load on the SIEM are shown, not editable.

**Users and roles** offers four roles (Viewer, Analyst, Lead, Administrator) or a custom set of
capabilities ([web-ui-guide.md](web-ui-guide.md#users-and-capabilities)). A new person gets a
one-time link, valid 72 hours, to choose their own password; nobody else ever sees it. People can
also sign in with their ELK accounts (Settings → Sign-in through ELK); their roles then come from
ELK.

### What still happens on the server

A few things are deliberately not in the app, either because they replace the app itself or
because they need this machine's files:

- **Upgrading ARGUS** to a new version: [upgrading.md](upgrading.md).
- **The AI providers' keys and daily caps** (optional): `config/llm.local.yaml` and its keys
  file ([llm.md](llm.md)). ARGUS works without them.
- **The asset map file** (which devices and networks belong to whom): copy it to the server and
  import it with `uv run argus assets` ([configuration.md](configuration.md)); its path is a
  setting in the app.
- **Restoring a backup** (the nightly dumps and the weekly drill run by themselves):
  [operations.md](operations.md).
- **Recovery when the web itself is down:** `uv run argus doctor`,
  `systemctl --user status 'argus-*'`, and [troubleshooting.md](troubleshooting.md).
- **The break-glass account** (view and review only) for when ELK sign-in is down:
  `uv run argus break-glass`.

## The complete reference, and installing from the terminal

The numbered sections below explain every step in depth, for administrators who want to know
exactly what is installed where, and for installing without a browser: `argus init` asks the
same questions in the terminal, or reads them from an answers file (section 5).

**Contents**

0. [Clean setup from zero](#0-clean-setup-from-zero): the whole terminal path on one page, every
   value and the file it lands in
1. [Requirements](#1-requirements)
2. [Prepare the machine](#2-prepare-the-machine): Docker and compose v2, uv, git
3. [Prepare the SIEM side](#3-prepare-the-siem-side): what to have ready, the API keys
4. [Run `argus init`](#4-run-argus-init): the ten steps, one by one
5. [Scripted install: `argus init --answers`](#5-scripted-install-argus-init---answers)
6. [Start the services](#6-start-the-services)
7. [More people, and opening the app](#7-more-people-and-opening-the-app)
8. [Verify the installation](#8-verify-the-installation)
9. [Rerunning `argus init`](#9-rerunning-argus-init)
10. [A second ARGUS on the same machine](#10-a-second-argus-on-the-same-machine)
11. [Writes stay off](#11-writes-stay-off)
12. [Uninstalling](#12-uninstalling)
13. [ARGUS on the SIEM's own machine](#13-argus-on-the-siems-own-machine)
14. [Moving ARGUS to another machine](#14-moving-argus-to-another-machine)
15. [Mistakes people make, and what init does about them](#15-mistakes-people-make-and-what-init-does-about-them)

---

## 0. Clean setup from zero

The whole path from a fresh Linux machine to a working ARGUS, in order. Each step says what you
type, what you need ready, and **which file each value lands in**. The numbered sections below
explain every step in depth; this one is the map. Allow about an hour, most of it waiting for an
administrator to run two Kibana requests.

**Two people, two accounts.** Some steps need `sudo` (installing Docker, creating the account,
opening a firewall port). Those run from **your own administrator account**. Everything else runs
as the account ARGUS lives in, `argus`, which has **no password and no sudo** on purpose: the
account that runs ARGUS cannot make itself root. You reach it with `sudo -iu argus` or with an
SSH key; typing a password for `argus` never works, whatever you type.

**Required:** a Linux machine, Docker, uv, git, your SIEM's address and CA, one read-only API
key, at least one of your own domains, your time zone. **Optional:** Kibana's reader key, LLM
keys, an asset map, outside threat-intel keys, TLS for the web, the case team.

### Step A. The machine (5 minutes)

A Linux host with systemd: 2 vCPU / 4 GB RAM / 50 GB SSD at least, 4 vCPU / 8 GB / 100 GB
recommended, Ubuntu 24.04 LTS preferred ([section 1](#1-requirements)). It must reach
Elasticsearch (`:9200`) and optionally Kibana (`:5601`) over HTTPS. It may be the SIEM's own
machine ([section 13](#13-argus-on-the-siems-own-machine)). As your administrator account, create
the account ARGUS will run as:

```bash
sudo useradd -m -s /bin/bash argus     # no password: nobody signs in to it with one
sudo loginctl enable-linger argus      # its services run at boot and while nobody is logged in
# optional, to reach it over SSH from your own computer (paste your public key):
sudo install -d -m 700 -o argus -g argus /home/argus/.ssh
echo 'ssh-ed25519 AAAA... you@laptop' | sudo tee /home/argus/.ssh/authorized_keys > /dev/null
sudo chown argus:argus /home/argus/.ssh/authorized_keys && sudo chmod 600 /home/argus/.ssh/authorized_keys
```

### Step B. Prerequisites (10 minutes)

Docker Engine with the compose v2 plugin, uv (it fetches Python 3.12 itself), git and openssl.
On Ubuntu ([section 2](#2-prepare-the-machine) has Debian, RHEL and Fedora):

```bash
# Docker (as an administrator), from docker.com's repository
sudo apt-get update && sudo apt-get install -y ca-certificates curl git openssl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update && sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker argus          # ARGUS's account may use Docker without sudo

# uv (as the argus user, in a new login so the docker group applies)
sudo -iu argus
curl -LsSf https://astral.sh/uv/install.sh | sh && source "$HOME/.local/bin/env"

docker compose version && uv --version      # both answer: ready
```

Node.js is **not** needed: the web app's build is in the repository.

### Step C. Get ARGUS (2 minutes)

```bash
git clone https://github.com/sankettaware16/argus.git ~/argus
cd ~/argus
uv sync
```

Every command from here on runs in `~/argus` as `uv run argus ...`.

### Step D. What to have ready from the SIEM side

| You need | Example | Lands in |
|---|---|---|
| Elasticsearch's address | `https://siem.example.org:9200` | `config/local.yaml` (`siem.url`) |
| How to trust its certificate: the CA file, or its SHA-256 fingerprint | `B7:53:57:21:...` | the CA is pinned to `data/certs/siem-ca.crt`; the path in `config/local.yaml` (`siem.ca_file`) |
| Kibana's address (optional) | `https://siem.example.org:5601` | `config/local.yaml` (`kibana.url`, `kibana.enabled`) |
| The index patterns of your logs | `logs-*` | the starting key's role (and later `config/site.yaml`) |
| Your organisation's name, its own domains (at least one), public networks, time zone, a case-id prefix | `Example Corp`, `example.org`, `192.0.2.0/24`, `Europe/Berlin`, `SOC-IR` | `config/site.yaml` (`site.*`) |
| An administrator in Kibana for 5 minutes | | runs the two Dev Tools requests `argus init` prints |
| The address people will open ARGUS at: this machine's IP or name | `192.168.10.20`, `argus.example.org` | `config/local.yaml` (`units.web.*`) |
| Optional: your organisation's CA certificate and key, so browsers trust the web without a warning | `ca.crt`, `ca.key` | signs `data/tls/argus.crt`; the CA's key is read once and never copied |
| A sign-in name and password for yourself in the web | `alex` | the database (users) |

### Step E. Run `argus init` (15–30 minutes)

```bash
uv run argus init
```

It asks its questions in ten steps and stops with a one-line fix whenever something is missing;
rerun it and it keeps what is done. A wrong answer at the terminal (a key or a date it cannot
use) is explained and asked again. Avoid 00:00–01:30 UTC (the SIEM's quiet hours: discovery
waits). What each step writes:

| Init step | You give | It writes |
|---|---|---|
| 1. prerequisites | nothing | nothing |
| 2. `.env` | nothing: passwords are generated | **`.env`** (mode 600): `ARGUS_DATABASE__OWNER_PASSWORD`, `ARGUS_DATABASE__PASSWORD`, `ARGUS_DATABASE__API_PASSWORD`, the database names and port |
| 3. the database | nothing | the Docker container `argus-db` (PostgreSQL 17 on `127.0.0.1:55432`), its volume `argus-pgdata`, the roles and the schema |
| 4. addresses and trust | the SIEM's and Kibana's addresses; `file`, `chain` or `system` | `config/local.yaml` (`siem.url`, `siem.ca_file`, `kibana.url`, `kibana.ca_file`); `data/certs/siem-ca.crt` (and `kibana-ca.crt`) |
| 5. the read-only keys | the log patterns; then the **`encoded`** value of each key an administrator creates from the request init prints ([section 3.2](#32-the-api-keys-argus-asks-for)); when each expires: the date, the `expiration` number from the same answer, or `90d` | **`.env`**: `ARGUS_SIEM__API_KEY`, `ARGUS_KIBANA__READER_API_KEY`; `config/local.yaml`: `siem.api_key_expires`, `kibana.reader_api_key_expires`, `kibana.enabled` |
| 6. the organisation and discovery | name, team name, domains, networks, time zone, case-id prefix; the Kibana space; accept the proposal | **`config/site.yaml`** (families, space, threat-intel sources, versions, the organisation) |
| 7. the LLM keys (optional) | the path of your keys file, or `none` | **`config/llm.local.yaml`** (`keys_file`) |
| 8. the web | the address people open it at (or `none`: this machine only); optionally your CA's certificate and key; the networks allowed; your sign-in name and password | `data/tls/argus.crt` and `argus.key` (mode 600); `config/local.yaml` (`units.web.*`, `web.tls_pin_sha256`); your account in the database |
| 9. the services | install the units? start them? the nightly backup? | `~/.config/systemd/user/argus-*.{service,timer}`; `config/local.yaml` (`units`); with Kibana, `local/creds-sync/` and `local/argus-kibana-read.env` for the read-back |
| 10. doctor | nothing | nothing: init's exit code is doctor's |

For automation, the same answers in a YAML file: `uv run argus init --answers answers.yaml`
([section 5](#5-scripted-install-argus-init---answers)).

### Step F. LLM keys (optional, 10 minutes)

Skip this and ARGUS investigates deterministically at $0. To add the AI investigator: get one or
more keys (Groq, OpenRouter and Gemini are free; OpenAI is the paid fallback), put them in a file
outside the checkout, and import an asset map first:

```bash
mkdir -p -m 700 ~/secrets
install -m 600 /dev/null ~/secrets/llm-keys.env
nano ~/secrets/llm-keys.env           # GROQ_API_KEY=..., OPENROUTER_API_KEY=..., GEMINI_API_KEY=..., ANTHROPIC_API_KEY=..., OPENAI_API_KEY=...
uv run argus assets import ~/secrets/asset_map.yaml
uv run argus init                     # step 7: give ~/secrets/llm-keys.env
uv run argus llm probe && uv run argus llm ping
```

Where each key comes from, step by step, and when the paid one is used: [llm.md](llm.md). What it
costs: [costs.md](costs.md).

### Step G. Start the services

Answer **yes** to *Start ARGUS's services now?*, or run init again with `--start`:

```bash
uv run argus init --start
systemctl --user status 'argus-*' --no-pager
```

It starts every service this installation runs: the collector, the worker, the assessments and
the web; with Kibana, the read-back of cases (`argus-kibana-sync`); and, unless you say no, the
nightly database backup and the weekly restore drill. It ends with the address to open:

```
init: done; ARGUS is running. Open https://192.168.10.20:8765/ and sign in
```

If it warns that the services stop when `argus` logs out, run the `loginctl` line from Step A.

### Step H. Sign in

Open the address init printed and sign in with the name and password you gave at step 8. With a
self-signed certificate the browser warns once: check that the warning names the address you
typed, then continue (or import your CA into the browser so it never warns). If you answered
`none` at step 8, the web stays on this machine: from your own computer run
`ssh -L 8765:127.0.0.1:8765 argus@<this machine>` and open <http://127.0.0.1:8765/>.

More people: `uv run argus user add alice --name "Alice Example"`, then
`uv run argus user grant alice manage_cases` ([section 7.1](#71-more-people)). To let approvals
be recorded, make the approval key once:

```bash
mkdir -p -m 700 data/keys
uv run argus approvals keygen data/keys/approval-signing.key
```

and set `units.web.approval_key_file` to its full path in `config/local.yaml`, then
`uv run argus units install --apply --reload && systemctl --user restart argus-web`.

### Step I. Optional extras

| Extra | What to do | Lands in |
|---|---|---|
| Outside threat intel | free VirusTotal, Shodan, Censys keys ([llm.md](llm.md#36-other-optional-keys-outside-threat-intel)) | `.env`: `ARGUS_OUTSIDE__VIRUSTOTAL_API_KEY`, `..._SHODAN_API_KEY`, `..._CENSYS_API_KEY` |
| Your DNS resolvers | so they never join unrelated campaigns | `config/local.yaml`: `campaigns.resolvers` |
| Daily and weekly reports | `systemctl --user enable --now argus-report-daily.timer argus-report-weekly.timer`, and add both to `units.run` | `units.run` |
| The case team in Kibana | `uv run argus case team provision`, then switch posting on ([case-team.md](case-team.md)) | `local/creds-writer/`, `local/argus-writer.env`, `config/local.yaml` |
| The exact, narrower SIEM key | the role init printed after discovery; `uv run argus init --force-key` | `.env` |

### Step J. Verify

```bash
uv run argus doctor                 # 0 FAIL; a fresh install shows a few expected warnings
uv run argus siem selftest          # the TLS pin, the version and the key's privileges (5 small requests)
uv run argus collect status         # alerts arriving within a minute or two
uv run argus worker status          # dossiers being written
```

In the Inbox, *Review → Not reviewed* fills as the worker writes dossiers; the backfill of
`history.window` (5 days) follows over minutes to hours, within the load budget. The status bar
at the top shows the AI spend, the SIEM's state and **Kibana sync** (the read-back's newest
cycle: *in sync*, *partly read*, *failing*, *late*, or *not running yet* before its first
cycle); *System → Health* has the details.

### Where every value lives

| File | Holds | Written by | Tracked by git |
|---|---|---|---|
| `.env` | **secrets**: database passwords, `ARGUS_SIEM__API_KEY`, `ARGUS_KIBANA__READER_API_KEY`, outside keys, notice relay login | `argus init`, you | no (mode 600) |
| `config/local.yaml` | this installation: addresses, CA files, key expiry dates, `units`, the web, any setting you change | `argus init`, you | no |
| `config/site.yaml` | your organisation and its Elastic: families, space, threat intel, domains, networks, time zone | `argus init` / `argus discover --write`, you | no |
| `config/llm.local.yaml` | the path of your LLM keys file | `argus init` | no |
| your LLM keys file (e.g. `~/secrets/llm-keys.env`) | the model keys, `NAME=value` | you | outside the checkout (mode 600) |
| `data/certs/` | the pinned CA certificates | `argus init` | no |
| `data/tls/argus.crt`, `argus.key` | the web's certificate and key (mode 600) | `argus init` (or you) | no |
| `local/creds-sync/`, `local/argus-kibana-read.env` | the read-back's own credentials and switches (empty by default: its key stays in `.env`) | `argus init` | no |
| `data/assets/asset_map.yaml` | your imported asset map | `argus assets import` | no (mode 600) |
| `data/keys/` | the approval key, the web's secret | `argus approvals keygen`, `argus sessions keygen` | no (mode 600) |
| `local/creds-writer/`, `local/argus-writer.env` | the case team's keys and the writer's switches | `argus case team provision`, you | no (mode 600) |
| `config/argus.yaml`, `config/llm.yaml` | shipped defaults: leave them as shipped, override in `local.yaml` | the project | yes |

Precedence and every setting: [configuration.md](configuration.md).

---

## 1. Requirements

### The ARGUS machine

| | Minimum | Recommended |
|---|---|---|
| CPU | 2 vCPU | 4 vCPU |
| Memory | 4 GB | 8 GB |
| Disk | 50 GB SSD | 100 GB SSD |
| OS | Linux with systemd (Ubuntu 22.04+, Debian 12+, RHEL 9+, Fedora 40+) | Ubuntu 24.04 LTS |

What one production installation measured (about 12,000 alerts a day, five services):

- **Memory:** about 1.2 GB in all (the services about 850 MB, PostgreSQL about 270 MB). The
  units cap the collector and the worker at 2 GB each, the web and the assessments at 1 GB.
- **CPU:** well under one core on average (about 1–2 % of a core); short bursts while it
  investigates.
- **Disk:** the database grows by about **180 MB a day** before the retention purge starts
  removing old data (90 days by default, see [configuration.md](configuration.md#retention)).
  Backups need room as well: a week of nightly dumps plus the verified ones is several times the
  database's compressed size. `argus init` refuses to start with less than 2 GiB free and warns
  below 10 GiB.

Network: the machine reaches Elasticsearch (usually `:9200`) and, optionally, Kibana (usually
`:5601`) over **HTTPS**. Reviewers reach the web Inbox on port `8765` (loopback by default; see
[section 7](#7-more-people-and-opening-the-app)). PostgreSQL listens on
`127.0.0.1:55432` only.

### The SIEM

- **Elasticsearch and Kibana 8.x or 9.x**, any licence (Basic is enough), with Kibana's
  **Security** app producing detection alerts.
- Reachable over HTTPS from the ARGUS machine. ARGUS never talks plain HTTP to the SIEM.
- Someone who can create API keys in it (an administrator, for a few minutes).

### ARGUS's load on the SIEM

ARGUS treats your SIEM as production. Every request goes through its Elastic Gateway, which
counts the **server time** Elasticsearch spends answering (the `took` of every response) against
a daily budget:

- **60 minutes of server time a day** by default (`siem.budget.took_per_day_ms`), 3 seconds a
  minute, at most 2 requests at once and one heavy query at a time.
- In practice ARGUS uses far less: one production installation spends **6–9 minutes a day**
  (6,000–9,000 small requests).
- When the cluster is busy (disk, heap, load, search rejections, late ingest) ARGUS slows down,
  then stops, on its own. See [architecture.md](architecture.md#the-elastic-gateway).

### Optional

- API keys for LLM providers (free tiers work). Without them ARGUS still takes in, groups and
  investigates every alert deterministically. See [llm.md](llm.md).
- An asset map of your internal networks. See [llm.md](llm.md#10-the-asset-map).

---

## 2. Prepare the machine

ARGUS runs as an **ordinary user** (not root): its services are systemd *user* units and its
database is a Docker container. Pick the account that will own the installation and run
everything below as that user (`sudo` only where shown).

### 2.1 Docker Engine and the compose v2 plugin

ARGUS needs `docker compose` (v2, the plugin), not the old `docker-compose` v1.

**Ubuntu**

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

**Debian**: the same, with `debian` in place of `ubuntu` in both URLs.

**RHEL 9 / Rocky / Alma**

```bash
sudo dnf -y install dnf-plugins-core
sudo dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo
sudo dnf -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

**Fedora**

```bash
sudo dnf -y install dnf-plugins-core
sudo dnf config-manager addrepo --from-repofile=https://download.docker.com/linux/fedora/docker-ce.repo
sudo dnf -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

Then, on every distribution: start the daemon and let your user run `docker` without `sudo`.

```bash
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"
# log out and back in (or: newgrp docker) so the new group applies
```

**Verify**

```bash
docker compose version          # Docker Compose version v2.x
docker info --format '{{.ServerVersion}}'   # prints the engine version, no permission error
```

The full, current instructions are on <https://docs.docker.com/engine/install/>.

### 2.2 uv (and Python 3.12)

[uv](https://docs.astral.sh/uv/) runs ARGUS and fetches the Python it needs (3.12) by itself:
you do not install Python separately.

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
# open a new shell, or:
source "$HOME/.local/bin/env"
```

**Verify**

```bash
uv --version                    # uv 0.x.y
which uv                        # e.g. /home/argus/.local/bin/uv (the units record this path)
```

### 2.3 git and the small tools

```bash
# Ubuntu / Debian
sudo apt-get install -y git openssl
# RHEL / Fedora
sudo dnf -y install git openssl
```

`openssl` is only for checking a certificate fingerprint by hand. **Node.js is not needed**: the
web app's build is committed in the repository.

### 2.4 Get ARGUS

```bash
git clone https://github.com/sankettaware16/argus.git
cd argus
uv sync                         # installs the locked dependencies into .venv
uv run argus --version
```

Every `argus` command below is run **from this checkout**, as `uv run argus ...`.

---

## 3. Prepare the SIEM side

### 3.1 What to have ready

| You need | Example | Notes |
|---|---|---|
| Elasticsearch's address | `https://siem.example.org:9200` | `https://host[:port]`, no path |
| Kibana's address (optional) | `https://siem.example.org:5601` | needed for the read-back of cases and for Kibana's version and spaces; ARGUS works without it |
| How to trust their certificate | the CA file, or its SHA-256 fingerprint | see [step 4](#step-4-the-siem-and-kibana-addresses-and-trust) |
| The index patterns of your logs | `logs-*` | what the starting key may read; discovery looks inside these |
| Your organisation's domains | `example.org` | at least one; the privacy layer replaces them |
| Its public networks (optional) | `192.0.2.0/24` | private ranges always count as yours |
| The time zone reviewers read times in | `Europe/Berlin` | choose it once: investigation days follow it |
| A prefix for incident case ids | `SOC-IR` | capital letters, digits, `-`; at most 16 characters |
| An administrator in Kibana for 5 minutes | | to run two Dev Tools requests that `argus init` prints |

**The CA fingerprint.** Elasticsearch 8 with its automatic security setup has its CA at
`config/certs/http_ca.crt` (package installs: `/etc/elasticsearch/certs/http_ca.crt`). Its
administrator can read the fingerprint with:

```bash
openssl x509 -noout -fingerprint -sha256 -in /etc/elasticsearch/certs/http_ca.crt
# sha256 Fingerprint=B7:53:57:21:...:78:D0
```

### 3.2 The API keys ARGUS asks for

`argus init` **creates nothing on your SIEM**: no user, no role, no key. When it reaches the keys
it prints a request for Kibana's **Dev Tools** console. An administrator pastes it, runs it, and
copies the `encoded` value from the answer: that string is the key, which you paste into
`argus init` (it is not shown as you type). Each key expires in **90 days**; `argus doctor`
warns 30 days before.

**The Elasticsearch key (`argus-reader`).** Before discovery ARGUS does not know your space or
log families yet, so the **starting** key reads the Security alerts of every space and the log
patterns you name (default `logs-*`):

```
POST /_security/api_key
{
  "name": "argus-reader",
  "expiration": "90d",
  "role_descriptors": {
    "argus_reader": {
      "cluster": [
        "monitor"
      ],
      "indices": [
        {
          "names": [
            ".alerts-security.alerts-*",
            ".internal.alerts-security.alerts-*",
            "logs-*"
          ],
          "privileges": [
            "read",
            "view_index_metadata"
          ],
          "allow_restricted_indices": false
        }
      ]
    }
  },
  "metadata": {
    "application": "argus",
    "purpose": "read-only first-line analyst: alerts, logs, threat intel, node health"
  }
}
```

Why each privilege:

| Privilege | What ARGUS does with it |
|---|---|
| cluster `monitor` | The health probe (node statistics: disk, heap, load, search queue and rejections, circuit breakers), the server's version and licence. This is how ARGUS knows to slow down or stop when the cluster is busy. |
| `read` on the alerts indices | Takes in the Security alerts of your space (the space's alias and its backing indices). |
| `read` on the log patterns | The evidence: bounded, read-only searches and aggregations about the hosts and addresses in an investigation. |
| `read` on threat-intel indices (after discovery) | Looks up indicators in the threat-intel sources discovery found. |
| `view_index_metadata` | Index names, aliases and field mappings: discovery reads these (never a document) to propose your log families; the probe checks index blocks. |
| `allow_restricted_indices: false` | Never Elasticsearch's own system indices. |

The key holds **no write privilege**: `argus init` checks with `_has_privileges` that it holds
what it needs and none of the write privileges, and stops if it does.

**After discovery** init prints the **exact** role for your site: the space's alerts alias
(`.alerts-security.alerts-<space>`) and its backing indices
(`.internal.alerts-security.alerts-<space>-*`), your log families' patterns and the threat-intel
sources, and nothing else. Replace the starting key with it when convenient
(`argus init --force-key`, [section 9](#9-rerunning-argus-init)). Both are read-only.

Optional: `read_ilm` (cluster) lets discovery read your retention from ILM; without it, it judges
retention from the dated index names and says so.

**The Kibana key (`argus-kibana-reader`, optional).** Read access to Kibana **Cases** in the
space, for the read-back of cases (what people did to the Kibana cases holding ARGUS's alerts).
Before discovery it is granted in every space; the exact one names your space:

```
POST /_security/api_key
{
  "name": "argus-kibana-reader",
  "expiration": "90d",
  "role_descriptors": {
    "argus_kibana_reader": {
      "cluster": [],
      "indices": [],
      "applications": [
        {
          "application": "kibana-.kibana",
          "privileges": [
            "feature_securitySolutionCasesV3.read"
          ],
          "resources": [
            "space:security"
          ]
        }
      ]
    }
  },
  "metadata": {
    "application": "argus",
    "purpose": "Kibana Cases read in space security (read-back)"
  }
}
```

(`securitySolutionCasesV3` is Kibana 8.19's Cases feature id; discovery reads the right id from
your Kibana and init prints the request with it.) Skip this key and ARGUS runs without Kibana:
press Enter at the prompt, or answer `none` in an answers file.

**Copy the request from `argus init`'s own output**, not from this page: init prints it for your
log patterns, your space and your Kibana's feature id.

---

## 4. Run `argus init`

```bash
cd ~/argus
uv run argus init
```

> **Not between 00:00 and 01:30 UTC.** That is the SIEM's default *quiet hours* window (when
> Elasticsearch creates the day's indices and deletes old ones): ARGUS asks nothing optional of
> the SIEM then, so discovery cannot run. Init stops with
> `the list of indices could not be read: nothing is proposed (the SIEM's quiet hours,
> 00:00-01:30 UTC: ARGUS asks it nothing optional now; run this again after 01:30 UTC)`.
> Rerun it afterwards: everything done so far is kept.

Init asks its questions in ten numbered steps. Whenever something is missing it stops with a
one-line fix; fix it and run `argus init` again: what is done is kept ("kept"), only what is
missing is done. Enter keeps the value shown in brackets. A value it cannot use (a key in the
wrong form, a date it cannot read, a password typed differently twice) is explained with
`not taken: ...` and asked again.

### Step 1: prerequisites

```
1. prerequisites
   ok: Python 3.12.x
   ok: uv /home/argus/.local/bin/uv
   ok: docker compose 2.x.y
   ok: port 55432 is free for PostgreSQL
   ok: 84.2 GiB free in /home/argus/argus
```

What it checks: uv on `PATH`; `docker-compose.yml` and `config/argus.yaml` in the current folder
(run init in the checkout); Docker installed, compose v2, the daemon reachable; that the database
container name is not used by **another** ARGUS checkout; the PostgreSQL port free (or already
ARGUS's own database); free disk (fails below 2 GiB, warns below 10 GiB). Each missing item
names its fix, e.g.
`MISSING: docker compose v2 is missing: install the compose plugin (https://docs.docker.com/compose/install/linux/)`.

When `config/local.yaml` came from another machine (a copied checkout, a moved installation),
its paths name that machine's folder. Init rewrites every path under the old `units.root` to this
checkout, and a `units.uv` that does not exist here to this machine's uv:

```
   moved: config/local.yaml named /home/someone/argus (another checkout); 4 paths now name this one (units.root, ...)
```

### Step 2: `.env` (the database passwords)

```
2. .env (the database passwords; never shown)
   written: ARGUS_DATABASE__OWNER_USER, ARGUS_DATABASE__USER, ... (mode 600)
```

Init creates `.env` (mode 600) with the database's names and new random passwords for:
the schema owner (the container's superuser; only `argus db ...` and backups log in as it),
ARGUS's runtime login (`argus_app`: every service), and the web's own login (`argus_api`, used
only by the web). It never prints a secret and never overwrites a value already in `.env`. When
the web's password lives in the web unit's credentials folder instead (`units.web.credentials`,
holding `database.api_password`), step 3 makes the web's login from there.
(`REPLICA_ELASTIC_PASSWORD` is also written: `docker-compose.yml` names it for an optional
development service, and compose refuses to read the file without it.)

### Step 3: the database

```
3. the database
   docker compose: db is up
   healthy
```

`docker compose up -d db` starts PostgreSQL 17 (an image pinned by digest) bound to
`127.0.0.1:55432`, with its data in the Docker volume `argus-pgdata`. Init waits up to two
minutes for it to be healthy, then creates ARGUS's roles (`argus db bootstrap`) and the schema
(`argus db upgrade`). With `--no-compose`, init uses a PostgreSQL that is already running, the
one `.env` names.

### Step 4: the SIEM and Kibana: addresses and trust

```
4. the SIEM and Kibana: addresses and trust
The SIEM's Elasticsearch address (https://host:9200): https://siem.example.org:9200
How should ARGUS trust https://siem.example.org:9200's certificate? ... (file, chain, system) [chain]:
```

ARGUS pins **one CA certificate file** (`data/certs/siem-ca.crt`) and always checks the host
name. Choose how that file is made:

| Way | When | What happens |
|---|---|---|
| `file` | You have the CA certificate (Elastic's `http_ca.crt`, your company CA) | Init copies it to `data/certs/` and checks a real handshake against it. |
| `chain` | You have the CA's fingerprint, not the file | Init shows each certificate the server presents (subject, issuer, expiry, SHA-256) and asks you to confirm the fingerprint of the one at the top of the chain. Only that one is pinned. Compare it with the fingerprint your administrator gave you ([3.1](#31-what-to-have-ready)). |
| `system` | The SIEM has a certificate from a public CA | The root CA from the system's bundle that verifies the server is pinned (just that root, not the whole bundle). |

```
   presented: siem.example.org (issued by Elasticsearch security auto-configuration HTTP CA, until 2028-05-01) SHA-256 4F:...
   presented: Elasticsearch security auto-configuration HTTP CA (issued by Elasticsearch security auto-configuration HTTP CA, until 2029-04-30) SHA-256 B7:53:...
Trust Elasticsearch security auto-configuration HTTP CA with SHA-256 B7:53:...? Compare it with the fingerprint your SIEM's administrator gives you [y/N]: y
   SIEM https://siem.example.org:9200: pinned the presented CA ... at data/certs/siem-ca.crt
```

Then Kibana's address (`none` to skip). When the SIEM's CA also verifies Kibana, init offers
`same` (one pin for both); otherwise Kibana gets its own pin (`data/certs/kibana-ca.crt`) the same
three ways. The addresses and pins are written to `config/local.yaml`.

If the server does not send its root CA, `chain` cannot pin it: init says so and you use `file`.

### Step 5: the read-only keys

```
5. the read-only keys (init creates no user, role or key on the SIEM)
The index patterns of your logs, for the key's starting role (comma-separated) [logs-*]:
   The key ARGUS needs (read-only; narrowed after discovery):

      POST /_security/api_key
      { ... }

      In Kibana: Dev Tools (Console), paste the request, run it as an administrator, and copy
      "encoded" from the answer: that is the key. It expires in 90 days (note the date).
Paste the SIEM key (not shown):
   SIEM key: stored in .env (ARGUS_SIEM__API_KEY)
When does the SIEM key expire: YYYY-MM-DD, "expiration" from the answer, or 90d (none to skip) [none]: 90d
```

Kibana's answer to the request looks like this; **only `encoded` is the key**:

```
{
  "id": "aB3d...Pq2R",                 <- not the key
  "name": "argus-reader",
  "expiration": 1801550534086,         <- paste this at the expiry question, or type 90d
  "api_key": "Q7mZ...8sYe",             <- not the key either (22 characters)
  "encoded": "YUIzZEVm...OHNZZQ=="     <- the key: about 80 characters
}
```

Init refuses the `api_key` or `id` value with `not taken: this is the "api_key" or "id" of the
answer: paste the value of "encoded"` and asks again. A line copied whole
(`"encoded": "czhD...",`) is fine: init strips the name, the quotes and the comma. **Never share
a screenshot of this answer**: if one leaks, invalidate that key in Kibana (Stack Management → API
keys) and make a new one.

The same follows for Kibana's key if you gave Kibana's address (Enter skips it: Kibana stays
off). Init then checks the key read-only through ARGUS's gateway: it must authenticate as an
**API key**, hold `monitor` and `read` on the indices, and hold no write privilege:

```
   SIEM key: an API key, read-only, reads .alerts-security.alerts-*, .internal.alerts-security.alerts-*, logs-*
```

Record the expiry dates: `argus doctor` warns 30 days before a key expires (it never asks the
SIEM for them).

### Step 6: the organisation and discovery (`config/site.yaml`)

```
6. the organisation and its Elastic (config/site.yaml)
The organisation's name: Example Corp
The security team's name (the page header): Example SOC
What kind of organisation it is (a lower-case noun) [organisation]: company
The organisation's own domains (at least one; the privacy layer replaces them) (comma-separated) [none]: example.org, example.net
Its public networks (CIDR) (comma-separated) [none]: 192.0.2.0/24
The time zone people read times in (IANA: Europe/Berlin) [UTC]: Europe/Berlin
How a time in it is labelled (CET) (none to skip) [none]: CET
The prefix of incident case ids (capital letters: SOC-IR) [IR]: SOC-IR
   discovering (a few read-only requests to the SIEM and Kibana) ...
```

Each answer is checked as the site settings check it; a wrong one is refused with the reason and
asked again. Notes:

- **Own domains**: at least one. Before any text goes to a cloud model, the privacy layer
  replaces these domains (and their subdomains) with tokens ([llm.md](llm.md#9-the-privacy-layer)).
- **Time zone**: the zone of the *investigation day* as well as of the pages; investigation ids
  depend on it. Choose it once, before the first alert is stored.

**Discovery** (`argus discover`) then sends a few read-only metadata requests (about eight plus
one per examined family; a few hundred milliseconds of server time): the server version and
licence, the list of indices, aliases and data streams (names only), which spaces have Security
alerts, Kibana's version, spaces and feature ids, and the field mappings of the most likely log
indices. It never reads a document. It needs the SIEM to be **NORMAL** and outside the quiet
hours. It prints its proposal with a confidence and the evidence for each family, then asks for
the Kibana space that holds your Security alerts:

```
The Kibana space that holds the Security alerts (default, security) [security]: security
   config/site.yaml will be:
      site:
        space: security
        families:
          - name: nginx
            role: web
            pattern: logs-nginx.access-*
        ...
Write it to config/site.yaml? [Y/n]:
```

Read the proposal: each **family** is a set of log indices with a **role** (`proxy`, `web`,
`dns`, `auth`, `mail` or `other`) that tells ARGUS's evidence modules what they hold. You can
edit `config/site.yaml` later ([configuration.md](configuration.md#the-site-configsiteyaml)) and
rerun discovery with `argus init --force-site` or `argus discover --write --force`.

With the site written, init runs the full SIEM self-test and Kibana's reader self-test, and
prints the **exact** keys for your site:

```
   SIEM self-test: passed (https://siem.example.org:9200)
   Kibana key: Cases read in the space, no write

   The exact keys for this site (narrower than a starting key; replace the
   keys with these when convenient, then argus init --force-key):
```

If Kibana's lane has already spent this minute's share on discovery, init says
`Kibana key: not checked now (its lane is paced; discovery spent this minute's share): check it
later with `argus kibana selftest`` and goes on. If Kibana does not accept the key, init says so
in words: `Kibana answered as to someone who is not signed in: it did not accept the key. Paste
the value of "encoded" ...`; run `argus init --force-key` with the right value.

### Step 7: the LLM providers' keys (optional)

```
7. the LLM providers' keys (optional)
The providers' keys file (NAME=value lines, mode 600) (none to skip) [none]:
   no model: the investigation agent, the tuning suggestions and the incident prose are off;
   ARGUS takes in and investigates every alert deterministically (llm.local.yaml adds keys)
```

Give the path of a file of `NAME=value` lines (mode 600) holding your providers' keys, or
`none`. The names and the file format are in [llm.md](llm.md). Init records the path in
`config/llm.local.yaml`; the keys stay in your file. **Before you add a model key, import an
asset map** ([llm.md](llm.md#10-the-asset-map)): with a model key and no map, the assessment
service refuses to start, because the privacy layer could not recognise your asset names.

### Step 8: the web

```
8. the web: where people open it, its certificate, the first person
The address people open ARGUS at: this machine's IP or name (none: this machine only, reached with ssh -L) (none to skip) [192.168.10.20]:
Your organisation's CA certificate, to sign the web's certificate so browsers trust it (none: a self-signed one, which browsers warn about once) (none to skip) [none]:
The networks people open it from (CIDR; others are refused) (comma-separated) [192.168.0.0/16]:
   certificate: made data/tls/argus.crt for 192.168.10.20, signed by itself (self-signed)
   https://192.168.10.20:8765: written units.web.host, units.web.tls_cert, ..., web.tls_pin_sha256
Your sign-in name for the web (lowercase; none: add people later with argus user add) (none to skip): alex
Your name as ARGUS shows it [alex]: Alex Example
A password for alex (10 or more characters):
The same password again:
   alex: created, with every capability (argus user grant changes it)
```

- **The address** is offered from the route to your SIEM (this machine's address on that
  network). Answer `none` to keep the web on `127.0.0.1` only, reached through an SSH tunnel.
- **The certificate** names that address (and `localhost`). Give your organisation's CA
  certificate and its private key to have it signed by that CA: browsers that already trust the
  CA (as they do for Kibana, when Kibana's certificate comes from it) show no warning. The CA's
  key is read once to sign and never copied. Init must be able to read it; if only root can, have
  an administrator sign it instead ([section 13](#13-argus-on-the-siems-own-machine)) and put the
  two files at `data/tls/argus.crt` and `data/tls/argus.key`: init keeps a certificate that
  already names the address. Without a CA, the certificate is self-signed.
- **The allowlists and the pin** are written together (`units.web.host`, `tls_cert`, `tls_key`,
  `allowed_hosts`, `allowed_networks`, `public_url`, and `web.tls_pin_sha256` for doctor), so the
  web's own checks pass the first time. When the address changes (a moved installation), the old
  one is replaced everywhere, including the case team's links in `local/argus-writer.env`.
- **The first person** gets every capability. Init asks only while the web has no account.

Open the port in the machine's firewall for those networks if one is active
(`sudo ufw status`; [section 7.3](#73-your-own-certificate-and-the-firewall)).

### Step 9: the services

```
9. the services (systemd user units)
Install the systemd user units? [Y/n]:
Start ARGUS's services now? [y/N]: y
Back up ARGUS's database every night (and check a restore every week)? [Y/n]:
   24 new, 0 changed, 0 kept (/home/argus/.config/systemd/user)
   started: argus-collector.service, argus-worker.service, argus-web.service, argus-assess.service, argus-kibana-sync.service, argus-backup.timer, argus-backup-drill.timer
```

Init renders the unit templates in `deploy/systemd/` for this checkout and this uv, and writes
them to `~/.config/systemd/user/`. Answering yes starts **every unit this installation runs**:
the four services, every unit already listed in `units.run`, the Kibana read-back when Kibana is
set up (init makes the two files its unit reads), and the backups unless you decline them. They
are recorded in `units.run`. Answer no and nothing starts: the units stay installed and
disabled, doctor says *installed, not started yet* as a warning, and `argus init --start` starts
them later ([section 6](#6-start-the-services)).

If lingering is off for the account, init says so with the one command an administrator runs
(`sudo loginctl enable-linger argus`); without it the services stop when the account logs out
and wait for a login after a reboot.

### Step 10: `argus doctor`

Init ends with `argus doctor` and **its exit code is doctor's**: 0 when no check fails.

```
init: done; ARGUS is running. Open https://192.168.10.20:8765/ and sign in
```

Warnings are expected on a fresh install: no backup yet, the approval key not set, no Node
toolchain, `custody: not installed`, threat-intel feeds not synced yet. See
[troubleshooting.md](troubleshooting.md#doctor-on-a-fresh-install).

### The files init writes

| File | Holds | Mode |
|---|---|---|
| `.env` | Secrets only: the database passwords, `ARGUS_SIEM__API_KEY`, `ARGUS_KIBANA__READER_API_KEY` | 600 |
| `config/local.yaml` | This installation: the SIEM's and Kibana's addresses and CA files, the keys' expiry dates, `kibana.enabled`, `web.database_role`, `units` | 644 |
| `config/site.yaml` | Your organisation and its Elastic: families, space, threat intel, time zone, domains, networks | 644 |
| `config/llm.local.yaml` | The path of your LLM keys file (relative to the checkout when it is inside it, or `keys_file: null`) | 644 |
| `data/certs/siem-ca.crt` (and `kibana-ca.crt`) | The pinned CA certificates | 644 |
| `data/tls/argus.crt`, `data/tls/argus.key` | The web's certificate and key | 644, 600 |
| `local/creds-sync/`, `local/argus-kibana-read.env` | The read-back unit's credentials folder and switches, empty | 700, 600 |

None of them is tracked by git. They are yours to edit; `argus doctor` checks them all, and a
rerun of init keeps what is there. When init changes a value in `config/local.yaml` it edits that
line in place: your comments and layout stay.

---

## 5. Scripted install: `argus init --answers`

For automation (Ansible, a golden image, CI), give init a YAML file that answers every question:
it never prompts.

```bash
uv run argus init --answers answers.yaml
```

Rules:

- A question the file does not answer stops init with the answer's name and exit code 2, e.g.
  `answers.yaml does not answer siem.url (the SIEM's Elasticsearch address, https://host:9200)`.
- An unknown answer name is refused (exit 2).
- **A key is never written in the file**: name a file holding it (`api_key_file`, which must be
  mode 600) or an environment variable (`api_key_env`). A file that gives `siem.api_key` itself
  is refused.
- On a rerun every answer that is already done may be left out: what exists is kept.

A complete example:

```yaml
database:
  compose: true                      # false: use the PostgreSQL that .env names
siem:
  url: https://siem.example.org:9200
  trust: chain                       # file | chain | system
  fingerprint: "B7:53:57:21:...:78:D0"   # trust: chain; a mismatch stops init, nothing is trusted
  # ca_file: /path/to/http_ca.crt    # trust: file
  log_patterns: [logs-*]             # the starting key's log patterns
  api_key_file: /home/argus/secrets/argus-reader.key   # mode 600; or api_key_env: ARGUS_READER_KEY
  api_key_expires: 2027-02-01        # or the answer's "expiration" (1801550534086), or 90d
kibana:
  url: https://siem.example.org:5601     # or none
  trust: same                            # same | file | chain | system
  api_key_env: ARGUS_KIBANA_KEY          # or api_key_file; api_key_file: none keeps Kibana off
  api_key_expires: 2027-02-01
organisation:
  name: Example Corp
  short_name: Example SOC
  kind: company                          # optional; default organisation
  own_domains: [example.org, example.net]
  own_networks: [192.0.2.0/24]
  timezone: Europe/Berlin
  timezone_label: CET                    # optional
  incident_id_prefix: SOC-IR
  space: security                        # the Kibana space of the Security alerts
discovery:
  accept: true                           # write the proposal to config/site.yaml
llm:
  keys_file: none                        # or /home/argus/secrets/llm-keys.env
web:
  address: 192.168.10.20                   # left out: the web stays on 127.0.0.1
  # ca_cert: /etc/pki/org-ca.crt         # with ca_key: signed by your CA; left out: self-signed
  # ca_key: /etc/pki/org-ca.key
  networks: [10.0.0.0/8]                 # left out: the private range the address is in
  person: alex                           # left out: nobody is made (argus user add later)
  person_name: Alex Example
  person_password_file: /home/argus/secrets/alex.pw   # mode 600; or person_password_env
units:
  install: true
  start: false
  backups: true                          # with start: the nightly backup and the weekly drill
```

Every answer:

| Answer | Meaning |
|---|---|
| `database.compose` | `true`: start the database with docker compose; `false`: use a PostgreSQL that is already running (the `.env` names it) |
| `siem.url` | The SIEM's Elasticsearch address, `https://host:9200` |
| `siem.trust` | How the SIEM's certificate is trusted: `file`, `chain` or `system` |
| `siem.ca_file` | The SIEM's CA certificate file (`siem.trust: file`) |
| `siem.fingerprint` | The SHA-256 fingerprint of the CA the SIEM presents (`siem.trust: chain`); case and separators do not matter |
| `siem.api_key_file` | A file holding the read-only API key (the `encoded` form), mode 600 |
| `siem.api_key_env` | An environment variable holding the read-only API key |
| `siem.api_key_expires` | When the key expires: `YYYY-MM-DD`, the answer's `expiration` (milliseconds), or a number of days (`90d`) |
| `siem.log_patterns` | The index patterns of the logs, for the starting role (default `logs-*`) |
| `kibana.url` | Kibana's address, `https://host:5601`, or `none` |
| `kibana.trust` | `same` (the SIEM's CA), `file`, `chain` or `system`; asked only when the SIEM's CA does not verify Kibana, or offered as `same` when it does |
| `kibana.ca_file` | Kibana's CA certificate file (`kibana.trust: file`) |
| `kibana.fingerprint` | The SHA-256 fingerprint of the CA Kibana presents (`kibana.trust: chain`) |
| `kibana.api_key_file` | A file holding Kibana's read-only API key, or `none` |
| `kibana.api_key_env` | An environment variable holding Kibana's read-only API key |
| `kibana.api_key_expires` | When Kibana's key expires, as for the SIEM's |
| `organisation.name` | The organisation's name |
| `organisation.short_name` | The security team's name (page header, PDF footer) |
| `organisation.kind` | What kind of organisation it is, a lower-case noun (default `organisation`) |
| `organisation.own_domains` | The organisation's own domains (at least one) |
| `organisation.own_networks` | The organisation's public networks, CIDR (may be empty) |
| `organisation.timezone` | The zone people read times in, an IANA name (`Europe/Berlin`) |
| `organisation.timezone_label` | How a time in that zone is labelled (`CET`), or `none` |
| `organisation.incident_id_prefix` | The prefix of incident case ids (`SOC-IR`) |
| `organisation.space` | The Kibana space that holds the Security alerts (must be one discovery found) |
| `discovery.accept` | `true`: write what discovery proposes to `config/site.yaml` |
| `llm.keys_file` | The LLM providers' keys file, or `none` (every LLM feature off) |
| `web.address` | The address people open the web at (this machine's IP or name); left out, the web stays on the loopback |
| `web.ca_cert`, `web.ca_key` | A CA certificate and its private key to sign the web's certificate; left out, it is self-signed |
| `web.networks` | The networks people open the web from (CIDR); default: the private range the address is in |
| `web.person`, `web.person_name` | The first person's sign-in name and display name; left out, nobody is made |
| `web.person_password_file` / `_env` | The first person's password, from a file (mode 600) or an environment variable; never in the answers file |
| `units.install` | `true`: install the systemd user units |
| `units.start` | `true`: enable and start every unit this installation runs |
| `units.backups` | With `units.start`: `true` (default) adds the nightly backup and the weekly restore drill |

Lists may also be written as one comma-separated string (`own_domains: example.org, example.net`).

Exit codes: **0** done and doctor shows no failure; **1** a step stopped, or doctor found a
failure; **2** an answer or the usage is wrong.

---

## 6. Start the services

ARGUS runs as four long-running services (systemd **user** units of your account), plus the
Kibana read-back when Kibana is set up and the backup timers:

| Unit | What it does |
|---|---|
| `argus-collector.service` | Probes the SIEM's health and polls for new alerts every minute, refreshes workflow states every 15 minutes, reconciles hourly, backfills `history.window` |
| `argus-worker.service` | Gathers the evidence and writes a dossier for each queued investigation |
| `argus-assess.service` | Proposes outcomes (decision engine, then the optional AI investigator), suggests cases, writes incident reports |
| `argus-web.service` | The Inbox and its API, on `127.0.0.1:8765` or the address of step 8 |
| `argus-kibana-sync.service` | With Kibana: reads back what people did to the Kibana cases holding ARGUS's alerts, every 10 to 60 minutes |
| `argus-backup.timer`, `argus-backup-drill.timer` | The nightly database dump (21:30 UTC) and the weekly restore drill (Sundays) |

Start them:

```bash
uv run argus init --start
```

`argus init --start` records them in `units.run` in `config/local.yaml`; doctor then checks that
each of them is installed and enabled. If you start units by hand
(`systemctl --user enable --now ...`), add them there yourself:

```yaml
# config/local.yaml
units:
  run: [argus-collector.service, argus-worker.service, argus-web.service, argus-assess.service]
```

**Keep them running while you are logged out.** User units stop when your last session ends
unless lingering is on (init warns when it is off; an administrator turns it on once):

```bash
sudo loginctl enable-linger "$USER"
loginctl show-user "$USER" --property=Linger     # Linger=yes
```

**Verify**

```bash
systemctl --user status 'argus-*' --no-pager
journalctl --user -u argus-collector -n 50 --no-pager
```

The other timers (reports, purge, notices) are installed but not enabled: switch them on as
described in [operations.md](operations.md#services-and-timers).

---

## 7. More people, and opening the app

### 7.1 More people

Add people in the app: **More → Administration → Users and roles → Add a person** gives them a role and
a one-time link to set their own password. From the terminal, the same is possible (useful when
you installed without a browser; `argus init` made the first account at step 8):

```bash
uv run argus user add alice --name "Alice Example"
# the password is asked twice (never on the command line)
```

Without `--capability`, an account can **view**, **see logs**, **review** and **answer gold-set
items**. Give an administrator more:

```bash
uv run argus user grant alice manage_cases reopen approve admin
uv run argus user list
```

The eight capabilities and what they allow are in
[web-ui-guide.md](web-ui-guide.md#users-and-capabilities).

### 7.2 Open it

With an address at step 8, open `https://<address>:8765/` (init prints it at the end). Without
one, the web listens on **`127.0.0.1:8765` only**; from your own computer, forward the port over
SSH:

```bash
ssh -L 8765:127.0.0.1:8765 argus@argus-host.example.org
```

and open <http://127.0.0.1:8765/> in your browser. Sign in with the account you created; you
land on the app at `/app`.

### 7.3 Your own certificate, and the firewall

Init's step 8 sets all of this up. This section is for doing it by hand: a certificate from
elsewhere (a public CA, your PKI team), or a change later.

To serve the Inbox to reviewers directly, the web needs **all of**: a TLS certificate and key, the
host names browsers use (`allowed_hosts`), and the client networks allowed (`allowed_networks`).
ARGUS refuses to listen on anything but the loopback without them, and refuses a `public_url`
whose host is not in `allowed_hosts`.

The web unit takes these from `units.web` in `config/local.yaml`:

```yaml
# config/local.yaml
units:
  web:
    host: 0.0.0.0                                   # listen on every address
    tls_cert: /home/argus/argus/data/tls/web.crt    # absolute paths
    tls_key: /home/argus/argus/data/tls/web.key     # mode 600
    allowed_hosts: [argus.example.org]              # the names in the browser's address bar
    allowed_networks: [192.0.2.0/24]                # clients allowed besides this machine
    public_url: https://argus.example.org:8765      # optional: the address in permanent links
```

Then render the unit again and restart the web:

```bash
uv run argus units install            # shows the diff
uv run argus units install --apply --reload
systemctl --user restart argus-web
```

Open the port in the host firewall for the allowed networks only:

```bash
# Ubuntu / Debian (ufw)
sudo ufw allow from 192.0.2.0/24 to any port 8765 proto tcp
# RHEL / Fedora (firewalld)
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.0.2.0/24" port port="8765" protocol="tcp" accept'
sudo firewall-cmd --reload
```

Use a certificate your reviewers' browsers trust (your organisation's CA, or a public one).
**A reviewer must never type a password past a certificate warning.** Optionally pin the served
certificate so `argus doctor` fails if it ever changes:

```bash
openssl x509 -in data/tls/web.crt -outform der | sha256sum     # lowercase hex
```

```yaml
# config/local.yaml
web:
  tls_pin_sha256: <the 64 hex digits>
```

---

## 8. Verify the installation

**Doctor: every part, offline.** It sends no request to the SIEM.

```bash
uv run argus doctor
```

```
PASS  config                 environment=dev history.window=5d
PASS  database               ...
PASS  site                   3 log families (nginx, dns, proxy); space security; zone Europe/Berlin; incident IDs SOC-IR-YYYY-MMDD-NN; 1 own networks, 2 own domains
PASS  the SIEM CA            Elasticsearch security auto-configuration HTTP CA, valid until 2029-04-30 (1274 days)
PASS  the SIEM key           configured (`argus siem selftest` checks it)
WARN  backups                no dump in data/backups yet: ...
...
```

Exit code 0 means no FAIL. What each line means: [operations.md](operations.md#argus-doctor).

**The SIEM, live** (five small requests):

```bash
uv run argus siem selftest
uv run argus siem status            # health state, kill switches, today's budget (no request)
uv run argus kibana selftest        # if Kibana is configured
```

**The first alerts.** Within a minute or two of starting the collector:

```bash
journalctl --user -u argus-collector -f
uv run argus collect status         # what the store holds
uv run argus worker status          # the queue and the dossiers
uv run argus assess status          # assessments and proposals
```

The collector also backfills `history.window` (5 days by default), newest hours first, so older
alerts arrive over the following minutes to hours, within the budget.

**Two things that look like a stall but are not:**

- **Before the first health probe** ARGUS does not trust the SIEM's health ("unknown is not
  healthy"): it treats it as **DEGRADED** and only collects, at a tenth of the budget. The
  collector probes once a minute, so this lasts about a minute after it first starts. If the
  collector is not running, every other service's SIEM work degrades after 3 minutes and stops
  after 15: keep the collector running.
- **During the quiet hours** (default 00:00–01:30 UTC) discovery, the freshness readings and
  the other optional reads wait (`... waits for the end of the quiet hours (01:30 UTC)`).
  Collecting new alerts goes on.

**The Inbox:** sign in, open *Review → Not reviewed*: the first investigations are there once
the worker has written their dossiers.

---

## 9. Rerunning `argus init`

`argus init` is safe to run again at any time: it keeps what exists, says "kept", and repairs
only what is missing or wrong. Nothing is overwritten without a flag or an explicit answer:

| Flag | What it redoes |
|---|---|
| `--force-trust` | Pins the SIEM's and Kibana's CA again (a renewed certificate) |
| `--force-key` | Asks for new keys and replaces them in `.env` (a rotated or narrowed key) |
| `--force-site` | Runs discovery again and rewrites `config/site.yaml` |
| `--start` | Enables and starts every unit this installation runs |
| `--no-compose` | Uses a PostgreSQL that is already running (the one `.env` names) |
| `--answers FILE` | Answers from a YAML file; never prompts |
| `--config FILE` | Another config file than `config/argus.yaml` |

---

## 10. A second ARGUS on the same machine

`docker-compose.yml` names its project `argus` and the database container `argus-db`. A second
checkout on the same machine would otherwise take over the first one's database container.
`argus init` refuses that:

```
MISSING: the database container argus-db belongs to another ARGUS checkout (/home/argus/argus);
this one would take it over. Set COMPOSE_PROJECT_NAME, COMPOSE_DB_CONTAINER and
ARGUS_DATABASE__PORT in this checkout's .env to new values and run argus init again
```

Before the second checkout's first `argus init`, give it its own names in its `.env`:

```bash
cd ~/argus-staging
cat >> .env <<'EOF'
COMPOSE_PROJECT_NAME=argus-staging
COMPOSE_DB_CONTAINER=argus-staging-db
ARGUS_DATABASE__PORT=55433
EOF
chmod 600 .env
uv run argus init
```

Init then adds the passwords and keeps these three values. Also:

- **The systemd units have fixed names** (`argus-collector.service`, ...) in your user's unit
  folder, so two installations cannot both install units under **one** Linux account. Run the
  second one under another account, or answer *no* to installing the units (`units.install:
  false`) and run its commands by hand.
- **The web port**: give the second web another port in its `config/local.yaml`
  (`web: {port: 8766}`).
- **The SIEM's budget is per installation**: two installations both spend up to their own
  `siem.budget`. Lower it in the second one if both point at the same SIEM
  ([configuration.md](configuration.md#the-load-budget)).

---

## 11. Writes stay off

ARGUS writes nothing to the SIEM or Kibana by default (`kibana.write_classes` is empty). Init
says so:

```
   Kibana writes stay off (kibana.write_classes is empty, D-109): ARGUS reads cases back and
   writes nothing until a person names a write class, gives the writer its own key and is there
   for its first write (docs/install.md)
```

Each write (posting incident cases to Kibana, closing alerts after reviews) needs its own key with
write privileges, held only by the writer's own environment (never `.env`), a class named in
`kibana.write_classes`, and a person present for its first write. Read
[kibana.md](kibana.md#writes-off-by-default) before switching one on.

---

## 12. Uninstalling

```bash
cd ~/argus
systemctl --user disable --now 'argus-*.service' 'argus-*.timer'
rm -f ~/.config/systemd/user/argus-*.service ~/.config/systemd/user/argus-*.timer
systemctl --user daemon-reload
docker compose down -v      # removes the database container AND its volume: all ARGUS data
```

Without `-v`, `docker compose down` keeps the database volume for a later install. Backups in
`data/backups/` are removed with the checkout; copy them elsewhere first if you want to keep
them.

Then, in Kibana (Stack Management → API keys), invalidate the keys `argus-reader` and
`argus-kibana-reader`, and remove the checkout:

```bash
cd ~ && rm -rf ~/argus
sudo loginctl disable-linger "$USER"     # if nothing else of yours needs it
```

---

## 13. ARGUS on the SIEM's own machine

ARGUS can run on the machine that runs Elasticsearch and Kibana. It is the simplest place: no
second machine, the SIEM is local, and its outage stops ARGUS too, so nothing raises a false
alarm. It is also production, so keep ARGUS small beside it:

- **Its own account**, as in [Step A](#step-a-the-machine-5-minutes): `argus` with no password
  and no sudo. Membership of the `docker` group is root-equivalent on the host; if that is too
  much, use the custody layout ([architecture.md](architecture.md)).
- **Disk.** On one disk shared with Elasticsearch, ARGUS's database (a few GB after weeks) and
  its backups eat into Elasticsearch's watermark headroom. Keep `retention` and `backup.keep_*`
  modest, and copy the nightly dumps off the machine ([operations.md](operations.md#backups)):
  a disk failure would otherwise take the SIEM and ARGUS together.
- **CPU and memory.** The units already cap memory (512 MB to 2 GB each) and run the batch work
  at a lower priority. To give Elasticsearch priority, add a drop-in per unit, for example
  `~/.config/systemd/user/argus-worker.service.d/caps.conf` with
  `[Service]` / `CPUQuota=50%` / `CPUWeight=20` / `IOWeight=10`. (Doctor reports a drop-in as a
  change to the unit; that is expected here.)
- **The web's certificate from the SIEM's CA.** Kibana's browsers already trust the CA that
  signed Kibana's certificate, so a web certificate from the same CA raises no warning. If the
  CA's key is readable only by root, an administrator signs it (the key never leaves its folder):

  ```bash
  # as your administrator account; CA = the folder holding the SIEM's ca.crt and ca.key
  D=$(mktemp -d) && cd "$D" && umask 077
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj "/CN=ARGUS web" -keyout argus.key -out argus.csr
  printf 'subjectAltName=IP:192.168.10.20,IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n' > argus.ext
  sudo openssl x509 -req -in argus.csr -days 825 -sha256 -extfile argus.ext \
    -CA "$CA/ca.crt" -CAkey "$CA/ca.key" -set_serial 0x$(openssl rand -hex 16) -out argus.crt
  openssl verify -CAfile "$CA/ca.crt" argus.crt          # argus.crt: OK
  sudo install -o argus -g argus -m 600 argus.key /home/argus/argus/data/tls/argus.key
  sudo install -o argus -g argus -m 644 argus.crt /home/argus/argus/data/tls/argus.crt
  cd / && rm -rf "$D"
  ```

  Then run `argus init` as `argus`: step 8 keeps a certificate that already names the address.
  Check the CA's key file while you are there: it should be readable by root only
  (`-rw-------`); if every account can read it, any of them can make certificates the SIEM's
  users will trust.

---

## 14. Moving ARGUS to another machine

Two ways, chosen before you start:

- **Fresh**: the new machine starts with an empty database and reads back `history.window` of
  alerts (5 days) on its first start. Past reviews, cases and the spending ledger stay with the
  old machine's last dump.
- **Carry the history**: restore the old machine's last dump on the new one
  ([operations.md](operations.md#backups)), in a window where the old one is stopped.

Either way:

1. **Install the new machine** (Steps A to C). Clone the same repository and commit the old one
   runs.
2. **Copy what is not in git**, with `scp` or `rsync` straight between the machines, never
   through chat or a ticket, keeping the modes: `.env` (secrets), your LLM keys file,
   `data/assets/` (the asset map), `data/certs/` (the pinned CAs), and `local/` (the case team's
   keys and switches, the web's and the read-back's credentials). Leave out `data/tls/`: the
   certificate names the old address.
3. **Run `argus init` without `--start`.** It rewrites the old checkout's paths in
   `config/local.yaml` to this one, keeps the copied keys, asks the new web address and makes a
   certificate for it, and updates the case team's links. Doctor then shows the services as
   *installed, not started yet*.
4. **Switch over in one short window.** On the old machine:
   `systemctl --user disable --now 'argus-*.timer' 'argus-*.service'`, then
   `uv run argus backup dump` for a last copy of its history. On the new one, at once:
   `uv run argus init --start`. Never run both at the same time: they would post twice to the
   same Kibana cases and spend the SIEM's budget twice.
5. **Check** `uv run argus doctor`, the Inbox, and *System → Health* (alerts arriving, the
   Kibana read-back's first cycle within the hour).

---

## 15. Mistakes people make, and what init does about them

Seen in real installations; each is now caught or done for you:

| What happened | What init does now |
|---|---|
| The `"api_key"` field (22 characters) or the `"id"` was pasted instead of `"encoded"` | Refuses it with `not taken: this is the "api_key" or "id" of the answer: paste the value of "encoded"`, and asks again |
| The `"expiration"` number (`1801550534086`) was pasted at the expiry question, and init ended | Takes it (and `90d`, and a date); a value it cannot read is asked again |
| Kibana answered "not signed in" to a wrong key and init printed a traceback | Says in words that Kibana did not accept the key |
| `config/local.yaml` copied from another machine still named that machine's folders and web address | Rewrites the old folder's paths; step 8 replaces the old address, certificate and pin together |
| `sed` on `config/local.yaml` missed values because init had rewritten its layout | Init edits values in place; comments and layout stay. You never need `sed` |
| The web said "cannot reach its database": its own login was never made | Makes the web's login from the web unit's credentials folder |
| A new database never got the case team's login although its credential was copied over; the case team failed every run and doctor said PASS | Sets the case team's login from `local/creds-writer/database.writer_password` when it does not log in with it; doctor fails a case team set to run whose login does not work, and an enabled timer whose last run failed |
| `--start` started four services; the read-back, the case team and backups stayed off, and doctor failed | Starts every unit the installation runs, and the backups unless declined |
| Answering *no* to starting made doctor print FAIL and init say "fix it" | *installed, not started yet* is a warning; init says how to start |
| `sudo` was typed in the `argus` account and asked for a password that does not exist | The guide says which steps run as your administrator account; init prints the one `sudo` line linger needs |
| A browser warned about the web's certificate | Step 8 signs it with your CA when you give one |
| The status bar always said "Kibana sync: not set up yet" | It shows the read-back's newest cycle |
