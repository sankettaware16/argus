# Costs

What ARGUS costs to run, where the money goes, how the caps stop it, and what one production
installation really spent. In short: **the machine is the only fixed cost; model calls are
optional, the free providers come first, and paid use is capped per day and per month.**

**Contents**

- [The three kinds of cost](#the-three-kinds-of-cost)
- [Measured: 14 days of one production installation](#measured-14-days-of-one-production-installation)
- [Model prices](#model-prices)
- [Why ARGUS is cheap to run](#why-argus-is-cheap-to-run)
- [How the budget works](#how-the-budget-works)
- [What happens at a cap](#what-happens-at-a-cap)
- [Watching and controlling spend](#watching-and-controlling-spend)
- [Choosing your caps](#choosing-your-caps)

---

## The three kinds of cost

| Cost | What | Typical |
|---|---|---|
| **The machine** | One Linux host: 2–4 vCPU, 4–8 GB RAM, 50–100 GB SSD. ARGUS itself uses about 1.2 GB of memory and well under one core on average ([install.md](install.md#1-requirements)). | whatever a small VM costs you |
| **Load on your SIEM** | Not money, but production capacity: a budget of Elasticsearch **server time**, 60 minutes a day by default; one installation spends 6–9 minutes a day ([configuration.md](configuration.md#the-load-budget)). | a few minutes of server time a day |
| **Language models** | Optional. Free tiers (Groq, OpenRouter's free models, Google Gemini) first; paid fallbacks (OpenAI, then Anthropic) only when no free provider can answer, within hard caps. | **$0** with no keys or free keys only; about **$0.60 a day** measured with the paid fallback |

Everything else is free and open source: ARGUS (Apache-2.0), PostgreSQL, Python, the web app.
The optional outside threat-intel sources (VirusTotal, Shodan, Censys) are used within their
**free** plans by default ([features.md](features.md#outside-threat-intel)).

---

## Measured: 14 days of one production installation

One university SIEM (about 12,000 alerts a day), the 14 days to 3 November 2026, with every
provider configured (three free, one paid) and the shipped caps ($1.50 a day, $40 a month):

| | Calls | Cost |
|---|---:|---:|
| **All model calls** | **5,099** | **$8.47** |
| Free providers | 3,142 (62 %) | $0.00 |
| &nbsp;&nbsp;Google Gemini (free tier) | 2,428 | $0.00 |
| &nbsp;&nbsp;OpenRouter (`:free` models) | 462, of which 130 answered | $0.00 |
| &nbsp;&nbsp;Groq (free tier) | 252 | $0.00 |
| Paid fallback: OpenAI | 1,957 (38 %) | $8.47 |

- **About $0.60 a day on average** ($8.47 over 14 days), about **$0.0043 per paid call**.
- **On the days the paid fallback was needed most** it spent **$1.10–$1.20** and then stopped:
  the investigator's calls run at *normal* priority, which may use **80 %** of the $1.50 daily cap
  ($1.20). Past that, work waited for the free providers or for the next day ([below](#what-happens-at-a-cap)).
- **All-time: $13.27 over 18 days**, including the first days' one-off evaluation runs and a
  backlog after an outage.
- **Free models are flaky.** Of 462 calls to OpenRouter's free models only 130 came back with a
  usable answer (busy upstreams, timeouts, malformed answers). ARGUS simply moves on to the next
  provider: an unusable answer costs nothing and loses nothing.

A projection from these numbers: **about $18 a month**, never more than the caps allow
($32 a month for the investigator's normal-priority work, $40 for everything).

---

## Model prices

Prices are set per model in [`config/llm.yaml`](../config/llm.yaml) (`input_per_m`,
`output_per_m`: US dollars per million tokens). ARGUS uses them to estimate and cap spending;
your provider's invoice is the truth, and `argus llm reconcile` sets ARGUS's month to the costs it
has settled.

| Provider | Tier | Model (shipped) | Input / 1M tokens | Output / 1M tokens | Used for |
|---|---|---|---:|---:|---|
| Groq | small, medium | `openai/gpt-oss-20b`, `openai/gpt-oss-120b` | free tier | free tier | small calls (its 8,000 tokens a minute is too small for the investigator's larger prompts) |
| OpenRouter | small, medium | `minimax/minimax-m3.1-flash:free`, `nvidia/nemotron-3-ultra-550b-a55b:free` | $0 | $0 | any call, when its free models answer |
| Google Gemini | small, medium | `gemini-3.5-flash-lite` | free tier | free tier | any call |
| Anthropic | small | `claude-haiku-5-5` | $0.10 | $0.50 | routine items (prompts under 100,000 tokens; ARGUS's always are) |
| Anthropic | medium | `claude-sonnet-5-5` | $2.00 | $10.00 | items with a danger sign, or long text |
| Anthropic | large | `claude-opus-5-5` | $4.00 | $20.00 | **not used by the investigator** (configured) |
| OpenAI | small | `gpt-5.4-nano` | $0.20 | $1.25 | routine items |
| OpenAI | medium | `gpt-5.4-mini` | $0.75 | $4.50 | items with a danger sign, or long text |
| OpenAI | large | `gpt-5.5` | $5.00 | $30.00 | **not used by the investigator** (configured, priced high on purpose so a cap errs safe) |

The shipped prices were taken from third-party trackers in October 2026: check them against your
provider's price page and edit `config/llm.yaml` if they differ (it is a tracked file: keep the
change in a local commit). The free tiers have **limits**, not prices; ARGUS keeps to them
([llm.md](llm.md#2-the-providers-at-a-glance)).

---

## Why ARGUS is cheap to run

1. **Deterministic code decides most of the work.** Collecting, grouping, the evidence packs,
   the dossiers, case suggestions, incident reports (page, PDF, CSV) and the daily and weekly
   reports are code, not model calls. The **decision engine** proposes outcomes from your
   reviewers' own past verdicts without any model.
2. **One model run per pattern, not per alert.** Alike investigations (same rule, same
   evidence shape, same day) form a **pattern**; the AI investigator reads one member and its
   reading is shown on the rest. Thousands of alerts become hundreds of investigations, and
   those become a few hundred runs a day at most (`--agent-per-day 400`, the shipped service).
3. **Free providers first.** Every call tries Groq, OpenRouter's free models and Gemini before
   the paid providers. In production 62 % of all calls were free.
4. **Small models by default.** The investigator uses the small tier unless the item has a
   danger sign or text had to be cut; the large tier is never used by it (it was 65 % of the
   spend for answers the medium tier also gave).
5. **Hard caps.** A daily cap ($1.50) so a backlog cannot spend the month in a day, a monthly
   cap ($40), and per-priority shares of both. A call is reserved at an upper-bound estimate
   *before* it is sent, so the caps are never overshot by more than the estimate's rounding.
6. **It works with no keys at all.** No keys means no model calls and $0: ARGUS still takes in,
   groups and investigates every alert, and proposes outcomes where people's verdicts support
   them. Models only take what the engine cannot decide.

---

## How the budget works

All of it is in `config/llm.yaml`:

```yaml
monthly_cap_usd: 40.0                      # paid spending a month, all providers
daily_cap_usd: 1.50                        # paid spending a day (UTC day)
margin: 0.8                                # the share of each provider's published rate limits ARGUS uses
shares: {high: 1.0, normal: 0.8, low: 0.5} # of each day limit and of both cost caps
```

**Priorities and their shares.** Every call has a priority, and a priority may use only its
share of each cap:

| Priority | Who uses it | Daily cap (of $1.50) | Monthly cap (of $40) |
|---|---|---:|---:|
| `high` | `argus llm ping` (a connection test) | $1.50 | $40.00 |
| `normal` | **the AI investigator** (coordinator and specialists), incident prose | **$1.20** | **$32.00** |
| `low` | the weekly tuning suggestions; evaluation runs (overnight only) | $0.75 | $20.00 |

So the investigator stops at about 80 % of the daily cap, which is exactly what production
showed ($1.10–$1.20 on its busiest days), and leaves the rest for higher-priority work.

**Reserve, then settle.** Before a call, ARGUS reserves an upper bound of its cost (every byte of
the request counted as one token, plus the answer's full allowance) in the day's and the month's
spending. When the answer comes, the reservation is replaced by the provider's own token counts.
A call whose estimate alone is above a cap is never sent.

**Shared by every process.** The budget state lives in PostgreSQL, so the assessment service, the
web's "Ask the AI investigator now" and the command line all spend from one budget.

**Rate limits use the margin.** For each provider and model ARGUS uses `margin` (80 %) of the
published per-minute limits, and `margin × share` of the per-day limits. Example: Gemini's
configured 500 requests a day give the investigator (normal priority) 500 × 0.8 × 0.8 = 320 a day.

**Windows are UTC.** The day is the UTC day, the month the UTC calendar month.

## What happens at a cap

- **The paid providers are skipped, the free ones go on.** The overall caps count OpenAI's and
  Anthropic's spending together; each paid provider may also have its own caps
  (`config/llm.local.yaml`, `provider_caps`). Past one provider's own cap the next paid one is
  asked; past the overall daily share neither is asked again until the next UTC day (past the
  monthly share, until the next month); the free providers keep answering within their own limits.
- **Nothing is lost.** When no provider can take a call now, the item is **deferred** to the
  earliest time one could (at most an hour for a provider that is off or misconfigured) and stays
  in the queue. It is never marked done without an answer.
- **People are not blocked.** Investigations waiting for a model are still in the Inbox with
  their full evidence; a reviewer can decide them at any time.
- **Out of prepaid credit.** If OpenAI itself refuses for lack of credit (`insufficient_quota`),
  or Anthropic does (`402`, a credit balance too low, or its spend limit reached), ARGUS pauses
  that provider for six hours and uses the others.

## Watching and controlling spend

```bash
uv run argus llm status          # kill switch, this month's and today's cost against the caps,
                                 # today's use per provider and limit, cool-downs, breakers
uv run argus llm stop --reason "budget review"     # no call to any model until resumed
uv run argus llm resume --reason "reviewed"
uv run argus llm reconcile       # set this month's spending to the ledger's settled costs
```

- The **cost bar** at the top of every Inbox page shows this month's and today's paid spending.
- The **Metrics** page shows calls, answers and cost per provider.
- Every call is in the ledger (`llm_calls`): provider, model, tokens, cost, latency, outcome and
  the request's hash, **never its content**.

## Choosing your caps

| You want | Do |
|---|---|
| **$0, always** | Give no `OPENAI_API_KEY` and no `ANTHROPIC_API_KEY` (free keys only), or no keys at all. |
| Free first, a small paid safety net | Keep the shipped caps, or lower them: `daily_cap_usd: 0.50`, `monthly_cap_usd: 15`. |
| More AI coverage on a busy SIEM | Raise `daily_cap_usd` first (it is the one that binds), then `monthly_cap_usd`. |
| A second, independent limit | Set a monthly budget or usage limit in your OpenAI account and a monthly spend limit in your Anthropic Console as well, and use prepaid credit with auto-recharge off. |

Edit `config/llm.yaml`, then restart the assessments: `systemctl --user restart argus-assess`.
