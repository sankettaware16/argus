# AI Providers and Keys

ARGUS works **without any language model**. With none it still takes in, groups and
investigates every alert, the decision engine proposes outcomes where your reviewers' past
verdicts support them, and everything else waits for a person. Model keys are optional and add
the AI investigator and two smaller helpers. This guide covers which providers ARGUS uses, how to
get each key step by step, where to put it, when the paid one is used, and how spending is
capped. The money side, with measured numbers, is in [costs.md](costs.md).

**Contents**

1. [What a model adds](#1-what-a-model-adds)
2. [The providers at a glance](#2-the-providers-at-a-glance)
3. [Getting each key, step by step](#3-getting-each-key-step-by-step)
4. [Where the keys go](#4-where-the-keys-go)
5. [Before you add a key: own domains and the asset map](#5-before-you-add-a-key)
6. [Turning it on and checking it](#6-turning-it-on-and-checking-it)
7. [Which provider answers: the routing rules](#7-which-provider-answers-the-routing-rules)
8. [Budget and caps](#8-budget-and-caps)
9. [The privacy layer](#9-the-privacy-layer)
10. [The asset map](#10-the-asset-map)
11. [Commands](#11-commands)
12. [An optional local model](#12-an-optional-local-model)
13. [Running with no keys](#13-running-with-no-keys)

---

## 1. What a model adds

| Feature | What the model does | Without a model |
|---|---|---|
| **The AI investigator** | Takes the investigations the decision engine cannot decide, **once per pattern** a day (alike investigations share one run), reads the pseudonymised dossier, consults web, proxy and threat-intel specialists, may ask a fixed list of read-only SIEM checks, and proposes a verdict with the facts it relied on ([agents.md](agents.md)) | Those investigations wait for a person (`agent: off (no model key)`) |
| **"Ask the AI investigator now"** | The same, on a reviewer's request, for one investigation | The button is not offered |
| **Tuning suggestions** | Drafts the weekly per-rule suggestions to make noisy rules quieter | The weekly tuning report is built with its numbers, without suggestions |
| **Incident prose** (`incident.prose`, off by default) | Rewords an incident report's summary from verified facts, adding none | The summary stays deterministic |

Every model answer passes **guardian checks in code**: each quoted fact must be in the evidence,
a benign answer must rest on ARGUS's own findings, and no "benign" is proposed while a danger
sign is present or unknown (the safety floor). An answer that cannot be a proposal is still
shown to reviewers as ARGUS's reading, with the reason.

## 2. The providers at a glance

ARGUS talks to every provider through the same OpenAI-compatible chat API, so no provider SDK is
installed. The four cloud providers below are the ones ARGUS ships with and has run in
production; they are tried **in this order**, free tiers first and the paid one last:

| Order | Provider | Cost | Key name(s) in the keys file | Models ARGUS uses (small / medium) | Limits ARGUS keeps to (from `config/llm.yaml`) |
|---|---|---|---|---|---|
| 1 | **Groq** | free tier | `GROQ_API_KEY` (and `GROQ_API_KEY_2`) | `openai/gpt-oss-20b` / `openai/gpt-oss-120b` | 30 requests and 8,000 tokens a minute, 1,000 requests and 200,000 tokens a day, per model; one quota per Groq organisation |
| 2 | **OpenRouter** | free models (`:free`) | `OPENROUTER_API_KEY` | `minimax/minimax-m3.1-flash:free` / `nvidia/nemotron-3-ultra-550b-a55b:free` | 20 a minute, 50 a day for the whole account |
| 3 | **Google Gemini** | free tier | `GEMINI_API_KEY` | `gemini-3.5-flash-lite` (both tiers) | 10 a minute, 500 a day, 250,000 tokens a minute |
| 4 | **OpenAI** | **paid** (prepaid credit) | `OPENAI_API_KEY` | `gpt-5.4-nano` / `gpt-5.4-mini` | 500 a minute, 200,000 tokens a minute; **your daily and monthly caps** ([costs.md](costs.md)) |
| – | **Your own model** (optional) | your hardware | `LOCAL_LLM_API_KEY` | any OpenAI-compatible server | shipped disabled ([section 12](#12-an-optional-local-model)) |

- **One key is enough.** A provider without a key is skipped. More providers mean fewer waits
  when a free tier's limit is reached.
- **Why this order.** Free first, so the paid key pays only for what the free tiers cannot
  answer. Gemini is the last of the free ones because prompts sent on its free tier may be used
  to improve Google's products. Groq is first but serves mostly small calls: its 8,000 tokens a
  minute is below the investigator's larger prompts, which ARGUS then refuses locally without
  sending anything.
- **Data terms.** Only pseudonymised, validated text is ever sent ([section 9](#9-the-privacy-layer)),
  but it is still your security data: read each provider's data-use terms before you add its key.
  Free tiers and free models may keep or use prompts; OpenAI's API does not train on API data by
  default.
- **Limits change.** Providers change their free limits and model names. The table is what ARGUS
  is configured with; check your own account's limits page and adjust `config/llm.yaml` if yours
  differ.

## 3. Getting each key, step by step

Create the keys in your organisation's name (a shared security-team account), not a person's,
so a key outlives a staff change. Every key is shown **once** when created: paste it straight
into the keys file ([section 4](#4-where-the-keys-go)), never into a chat, a ticket or a shell
command.

### 3.1 Groq (free)

1. Open <https://console.groq.com> and sign up (an e-mail address, or a Google or GitHub account).
2. Open **API Keys**: <https://console.groq.com/keys>.
3. Create an API key, name it after its use (`argus`), and copy it.
4. Optional: read your organisation's limits at <https://console.groq.com/settings/limits>. Groq
   counts limits **per organisation**, not per key: a second key (`GROQ_API_KEY_2`) of the same
   organisation adds no capacity; it only lets you rotate one key while the other works.

Free plan: no payment details are needed. The limits ARGUS keeps to are in the table above.

### 3.2 OpenRouter (free models)

1. Open <https://openrouter.ai> and sign up.
2. Open **Settings → Keys**: <https://openrouter.ai/settings/keys>, create a key (name it
   `argus`), and copy it. You may give the key a credit limit of 0: ARGUS only uses models whose
   names end in `:free`, which cost nothing.
3. Limits for free models (OpenRouter's documentation): **20 requests a minute**; **50 requests a
   day** while the account has bought fewer than 10 credits, **1,000 a day** once it has bought
   at least 10. ARGUS ships with 50 a day; if you buy credits, raise `limits.rpd` of the
   `openrouter` provider in `config/llm.yaml`.

Free models are served by volunteers' and vendors' capacity and are often busy: in production
only 130 of 462 calls came back usable. ARGUS moves on to the next provider when one does not
answer; it costs nothing.

### 3.3 Google Gemini (free tier)

1. Open Google AI Studio at <https://aistudio.google.com/apikey> and sign in with a Google
   account; accept the terms. New users get a default Google Cloud project.
2. Create an API key (in that project, or one you import).
3. If the key is listed as unrestricted, restrict it to the Gemini API (Google's documentation
   describes this on the same page).
4. Copy the key.

The free tier needs no billing account. Its prompts may be used to improve Google's products,
which is why ARGUS asks Gemini last of the free providers. Do **not** enable billing on that
project unless you mean to pay: ARGUS does not price Gemini, so its paid use would not count
against ARGUS's caps.

### 3.4 OpenAI (paid fallback)

1. Open <https://platform.openai.com> and sign up, or sign in to your organisation.
2. **Add credit first.** In the organisation's **Billing** settings add a payment method and buy
   **prepaid credit** (OpenAI's help centre gives $5 as the minimum purchase). Turn
   **auto-recharge off** unless you want it: then the credit you bought is a hard ceiling of its
   own, besides ARGUS's caps. Credit expires after a year.
3. Optional but recommended: set a monthly budget or usage limit in the organisation's limits
   settings, below ARGUS's monthly cap, as an independent second stop.
4. Open **API keys**: <https://platform.openai.com/api-keys>, create a new secret key for the
   project you bought credit for, name it `argus`, and copy it.

When is it used? Only when no free provider can answer a call ([section 7](#7-which-provider-answers-the-routing-rules)),
and only within your caps ([section 8](#8-budget-and-caps)). If the credit runs out OpenAI
refuses with `insufficient_quota`; ARGUS then pauses OpenAI for six hours and goes on with the
free providers.

### 3.5 Other optional keys (outside threat intel)

Not model keys, but the same idea: free personal keys that add outside reputation lookups for
**public** addresses and names. They go in `.env`, not in the LLM keys file:

| Source | What ARGUS asks | Where to get the key | `.env` name |
|---|---|---|---|
| VirusTotal | how many engines flag an outside address or domain | a free VirusTotal account: the API key in your account's settings | `ARGUS_OUTSIDE__VIRUSTOTAL_API_KEY` |
| Shodan | what a public server is: ports, software, known CVEs | a Shodan account: the API key on your account page (without a key ARGUS uses Shodan's free InternetDB) | `ARGUS_OUTSIDE__SHODAN_API_KEY` |
| Censys | the same, as a second source | a Censys Platform **personal access token** (the old API id and secret no longer work) | `ARGUS_OUTSIDE__CENSYS_API_KEY` |

ARGUS keeps below each free plan by default (VirusTotal 3 a minute and 400 a day, Shodan 200 a
day, Censys 10 a day and 50 a month) and caches answers for 7 days. Like a model key, an outside
key needs the asset map first ([section 5](#5-before-you-add-a-key)).

## 4. Where the keys go

**One file, `NAME=value` lines, mode 600, outside the checkout:**

```bash
mkdir -p -m 700 ~/secrets
cat > ~/secrets/llm-keys.env <<'EOF'
GROQ_API_KEY=gsk_...
OPENROUTER_API_KEY=sk-or-v1-...
GEMINI_API_KEY=AIza...
OPENAI_API_KEY=sk-proj-...
EOF
chmod 600 ~/secrets/llm-keys.env
```

Better still, open the file in an editor and paste each key, so no key passes through your shell
history. Format rules (`src/argus/llm/providers.py`):

- One `NAME=value` per line; spaces around `=` and quotes around the value are removed; blank
  lines and every other line are ignored.
- Only the names `config/llm.yaml` lists are read: `GROQ_API_KEY`, `GROQ_API_KEY_2`,
  `OPENROUTER_API_KEY`, `GEMINI_API_KEY`, `OPENAI_API_KEY`, `LOCAL_LLM_API_KEY`. A name left out,
  or with an empty value, leaves its provider out.
- Each value is registered for log redaction when it is read and is never printed.

**How ARGUS finds the file.** `argus init` asks for its path at step 7:

```
7. the LLM providers' keys (optional)
The providers' keys file (NAME=value lines, mode 600) (none to skip) [none]: /home/argus/secrets/llm-keys.env
   keys for groq, openrouter, gemini, openai: written config/llm.local.yaml
```

Init refuses a file that does not exist or that others can read
(`llm.keys_file: ... is readable by others (chmod 600)`), and records the path in
**`config/llm.local.yaml`** (not tracked by git), which is laid over `config/llm.yaml` and may set
`keys_file` only:

```yaml
# config/llm.local.yaml
keys_file: /home/argus/secrets/llm-keys.env
```

`keys_file: null` means no keys: every model feature is off, cleanly. In a scripted install the
answer is `llm.keys_file` ([install.md](install.md#5-scripted-install-argus-init---answers)).
To add or change keys later, edit the keys file (or rerun `uv run argus init` to point at another
one) and restart the assessments.

| Where | What |
|---|---|
| `~/secrets/llm-keys.env` (your choice of path) | the model keys, `NAME=value`, mode 600 |
| `config/llm.local.yaml` | the path of that file (`keys_file`), written by `argus init` |
| `config/llm.yaml` | providers, order, models, limits, prices, caps (tracked; non-secret) |
| `.env` | outside threat-intel keys (`ARGUS_OUTSIDE__*`), never model keys |

## 5. Before you add a key

Two things must be in place, or ARGUS refuses to send anything to a model:

1. **At least one own domain** (`site.own_domains`, asked by `argus init`). The privacy layer
   replaces your domains with tokens; with none it builds no request, and `argus doctor` fails
   `privacy domains` while a provider is enabled.
2. **An asset map**, imported ([section 10](#10-the-asset-map)). Without one ARGUS cannot
   recognise your internal asset names in text. With no model key and no outside key, ARGUS runs
   without a map; **with a key and no map, the assessment service stops** with:

   ```
   no asset map imported: the privacy layer needs it before any model or outside service is asked (`argus assets import FILE`)
   ```

## 6. Turning it on and checking it

```bash
# 1. the asset map
uv run argus assets import ~/secrets/asset_map.yaml
# 2. the keys file (init asks at step 7; or edit config/llm.local.yaml)
uv run argus init
# 3. is each provider up, and does it accept the key? (no prompt and no data are sent)
uv run argus llm probe
# 4. one tiny call through the whole gateway with a fixed test text: who answered, what it cost
uv run argus llm ping
# 5. the assessments pick the keys up when they start
systemctl --user restart argus-assess
uv run argus doctor
```

`argus llm probe` prints one state per provider: `up`, `down`, `loading`, `unauthorized` (the key
is wrong), `tls_failed` or `model_mismatch` (the model name is not offered).

`argus-assess.service` already runs with the investigator and the weekly tuning switched on
(`argus assess run --every 120 --agent --agent-per-day 400 --agent-batch 3 --tuning`): with keys
present they simply start working, and the patterns waiting for the agent are picked up on the
next pass. For model-worded incident summaries also set `incident.prose: true` in
`config/local.yaml`.

**Verify:**

```bash
journalctl --user -u argus-assess -n 50 --no-pager     # no more "agent: off (no model key)"
uv run argus llm status                                # today's use per provider, cost this month
```

In the Inbox, the **Metrics** page shows what the AI did, and each investigation's **AI
assessment** tab shows the answer and the facts it quoted.

## 7. Which provider answers: the routing rules

Every model call goes through the LLM gateway (`src/argus/llm/gateway.py`). For each call:

1. **The privacy check first.** The request must pass the egress validator, and then the exact
   bytes for each provider must pass it again. A refused request is never sent anywhere.
2. **Providers in file order:** Groq → OpenRouter → Gemini → OpenAI. A provider is **skipped
   without a request** when:
   - it is disabled, has no key, or has no model for the call's tier;
   - the task is not on its allowlist (`tasks`), or its answer for this item was unusable before;
   - the call is too large for its token limits;
   - it is over its minute or day limit (at the margin and the priority's share), cooling down
     after a `429` (for the `Retry-After` it asked, at most a day), or its breaker is open after
     server errors or timeouts (5, then 15, then 60 minutes);
   - its key or certificate was refused (paused for an hour, with an alarm in `argus llm status`);
   - for the paid provider: the call would pass the **daily or monthly cost cap**.
3. **On a failure at one provider** (a timeout, a server error, an answer cut off or malformed)
   ARGUS goes on to the next one within the same call.
4. **The paid provider is reached only when every free provider was skipped or failed.**
5. **When none can take the call now**, the item is deferred to the earliest time one could (never
   more than an hour for a provider that is off or misconfigured) and stays queued. Nothing is
   lost and nothing is marked done without an answer.

**Model tiers.** The investigator asks for the **small** tier, and for the **medium** tier only
when the item has a danger sign (a threat-list hit, success after an attack, beaconing, a rare
destination, ...) or untrusted text had to be cut. The specialists, tuning and helpers use small.
The large tier is configured but the investigator never uses it.

Every attempt is recorded in the ledger (`llm_calls`): provider, model, tier, purpose, tokens,
cost, latency, outcome and the request's hash, never its content.

## 8. Budget and caps

The full explanation, with measured numbers, is in [costs.md](costs.md#how-the-budget-works). In
short, from `config/llm.yaml`:

| Setting | Shipped | Meaning |
|---|---|---|
| `daily_cap_usd` | 1.50 | Paid spending a UTC day, all providers: a backlog cannot spend the month in a day |
| `monthly_cap_usd` | 40.0 | Paid spending a UTC month |
| `shares` | high 1.0, normal 0.8, low 0.5 | The share of each cap and each day limit a priority may use: the investigator (normal) stops at $1.20 a day and $32 a month |
| `margin` | 0.8 | The share of each provider's published rate limits ARGUS uses |
| `evaluation` | 17:30–24:00 UTC, 150 calls a night per provider | Evaluation runs (`argus gold ...`) go at low priority, overnight only |

- Each call is reserved at an upper-bound cost before it is sent and settled with the
  provider's own token counts after; a call whose estimate alone exceeds a cap is never sent.
- Past a cap the paid provider is skipped until the next UTC day or month; the free providers go
  on.
- **No keys means no model calls at all: $0.**
- `argus llm stop` stops every call at once (assessments wait, nothing is lost); `argus llm
  reconcile` sets the month's spending to the ledger's settled costs.

To change a cap, edit `config/llm.yaml` (a tracked file: keep your change in a local commit) and
restart `argus-assess`. To make paid use impossible, give no `OPENAI_API_KEY`.

## 9. The privacy layer

Before any text leaves for a cloud model:

1. **Default deny.** `config/llm_data_policy.yaml` lists, field by field, what a model may see of
   a dossier and how (`send`, `number`, `ip`, `domain`, `url`, `host`, `user`, `drop`). A field
   not listed is withheld, and the item says how many were.
2. **Pseudonyms.** Private addresses, your own networks and every address in the asset map
   become `IP_n`; host names `HOST_n`; user names `USER_n`; your own domains (and their
   subdomains) `SITE_n`; each in a space of its own per item (`I2.IP_1`). Public addresses and
   outside domains stay as they are: they are the evidence. The raw log line is never sent.
3. **Shaping.** Counts are rounded (exact below 100), times made relative, untrusted text
   (URLs, user agents, rule text) cleaned of anything shaped like a pseudonym and capped at 300
   characters; at most 5 top values a field and 10 entities a kind.
4. **The egress validator** checks the exact text, byte by byte, before it is sent.
5. **Re-identification** of an answer happens only in memory, for that one item; an answer that
   names another item's pseudonym is refused. The pseudonym map is never stored.

User names from the sign-in logs are never sent to a model at all. What a reviewer writes in a
note is never sent either.

Your own domains come from `site.own_domains`; `campus_domains` in `config/llm_data_policy.yaml`
adds more. The asset map's generalisations (`site.type`, `site.zone`) may be sent, never its
names.

## 10. The asset map

A YAML file describing your internal networks. ARGUS uses it to label addresses in the Inbox
("a lab machine in building B") and, for the privacy layer, to recognise every internal address
and asset name.

```yaml
# asset_map.yaml (keep it outside the checkout; it describes your network)
defaults:
  site.organization: Example Corp
networks:
  - name: office-lan
    range: 10.10.0.0/16
    fields: {site.zone: office, site.type: workstation}
  - name: lab-a
    ranges: [10.20.1.0/24, 10.20.2.0/24]
    fields: {site.zone: building-a, site.type: lab}
  - name: dmz
    range: 192.0.2.0/26
    fields: {site.zone: dmz, site.type: server}
  - name: mail-relay
    range: 192.0.2.25          # a bare address is a /32
    fields: {site.zone: dmz, site.type: server}
```

- Top level: `defaults` (fields applied to every entry) and `networks` (a non-empty list) only.
- Each entry: `name`, `range` or `ranges` (IPv4 or IPv6 CIDR; up to 256 per entry), and
  `fields` named `site.<name>`. Nested networks are fine: the most specific match wins.
- `site.type` values feed `notified.managed_types` (which machines you manage).
- No anchors, aliases or duplicate keys; at most 100,000 entries and 16 MB.

```bash
uv run argus assets import ~/secrets/asset_map.yaml   # validates, audits, installs (mode 600)
uv run argus assets status                            # its size and hash (never its content)
```

Error messages name entries by number, never by value. The installed copy is
`data/assets/asset_map.yaml` (`assets.map_path`). Import it again after every change, then restart
the services.

## 11. Commands

```bash
uv run argus llm status        # kill switch, cost against the caps, today's use, cool-downs, breakers
uv run argus llm probe         # each enabled provider: up, down, loading, unauthorized, tls_failed, model_mismatch
uv run argus llm probe --provider groq
uv run argus llm ping          # one tiny call with a fixed test text: which provider answered, what it cost
uv run argus llm ping --provider gemini --tier small
uv run argus llm stop --reason "..."      # no call to any model until resumed
uv run argus llm resume --reason "..."
uv run argus llm reconcile     # set this month's spending to the ledger's settled costs
```

## 12. An optional local model

`config/llm.yaml` also holds a `local` provider entry, **disabled**, for an OpenAI-compatible
server you run yourself (for example `llama-server` from llama.cpp) behind TLS, reached at
`base_url`, trusted through its own certificate (`ca_file`) and keyed with `LOCAL_LLM_API_KEY`.
Its `trust: campus` marks it as on your own network. As shipped it is limited to the evaluation
and ping tasks (`tasks: [evaluate, ping]`): a local model is used for real work only after it has
been evaluated against the gold set for a task, and its model licence is recorded
(`licence:`). Enabling it means editing `config/llm.yaml` (`enabled`, `base_url`, `ca_file`, the
model names, `context_tokens`, the measured `read_tps` / `write_tps` speeds); `argus doctor` then
checks its certificate and `argus llm probe --provider local` whether it answers. A local model
costs no money; on a CPU it takes 30 seconds to a few minutes a call, so ARGUS sizes each call's
deadline from its measured speed.

## 13. Running with no keys

`keys_file: null` (the default) is a supported installation:

- `argus assess run --agent` says `agent: off (no model key)` and leaves the patterns queued: add
  keys later and they are picked up on the next pass.
- The weekly tuning report is built with its numbers but without suggestions.
- Incident summaries stay deterministic.
- Doctor's `llm keys` line says `none (keys_file: null): no model is called; ARGUS investigates
  deterministically`; with a keys file it checks the file is mode 600.
- **No model call is ever made, and the model cost is $0.**
