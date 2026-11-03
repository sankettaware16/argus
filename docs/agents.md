# The Investigation Agents

ARGUS's AI investigator is a small team of **model agents**: a lead investigator that decides,
and three specialists it may consult. Two more agents (a responder and a reporter) are built and
switched off. Each agent is a Markdown file in [`config/agents/`](../config/agents/): a header
that says what it is, and the instructions a model is given. What each file **may** say is bound
in code, so a file can narrow an agent but never widen it.

This page explains each agent, how one is chosen, what tools it has, how a run is bounded and
checked, and how to change an agent or add one. The agents are optional: without model keys none
of them runs ([llm.md](llm.md)).

Not to be confused with the **case team** (the seven Kibana users that post cases), which is
deterministic code and uses no model: [case-team.md](case-team.md).

**Contents**

- [The agents](#the-agents)
- [When an agent runs](#when-an-agent-runs)
- [One investigator run](#one-investigator-run)
- [The tools](#the-tools)
- [What checks every answer](#what-checks-every-answer)
- [The agent file](#the-agent-file)
- [What code binds: bindings, pins, enabled versions](#what-code-binds)
- [Changing an agent](#changing-an-agent)
- [Adding a specialist](#adding-a-specialist)
- [Evaluating a change](#evaluating-a-change)

---

## The agents

| Agent | Kind | Version running | Model tier | Tools | Started by | Answers with | State |
|---|---|---|---|---|---|---|---|
| `investigator` | coordinator | `coordinator@4` | medium at most | `proxy.host`, `proxy.destination`, `web.followups`, `ti.lookup`, `outside.reputation`, `outside.server` | `engine_no_decision`, `person_request` | `answer@1`: an outcome, a confidence, reasons, hypotheses, cited facts | **on** |
| `web` | specialist | `specialist@1` | small | `web.followups` | `coordinator_consult` | `notes@1`: notes, cites, asks | **on** |
| `proxy` | specialist | `specialist@1` | small | `proxy.host`, `proxy.destination` | `coordinator_consult` | `notes@1` | **on** |
| `intel` | specialist | `specialist@2` | small | `ti.lookup`, `outside.reputation`, `outside.server` | `coordinator_consult` | `notes@1` | **on** |
| `responder` | responder | `responder@1` | small | none | `case_advice` | `ranking@1`: the catalogue's actions for a confirmed case, ranked and said in plain words | off (built) |
| `reporter` | reporter | `reporter@1` | small | none | `report_due` | `prose@1`: one paragraph saying a daily or weekly report's figures | off (built) |

What each is for:

- **`investigator`** (the lead) assesses one investigation the decision engine could not decide.
  It weighs at least two hypotheses (an attack, and an ordinary explanation) with the item's
  facts for and against each, and answers with one of five outcomes: `true_positive`,
  `benign_expected`, `benign_policy`, `rule_false_positive` or `inconclusive`. It must never call
  an item benign while a threat-list hit, an outside detection, success after an attack, regular
  beaconing or a rare destination is unexplained.
- **`web`** reads the web evidence (requests, answers, follow-up successes, attack patterns) and
  may ask for the web follow-ups.
- **`proxy`** reads the proxy evidence (destinations, volumes, timing and regularity) and may ask
  for a host's or a destination's proxy traffic.
- **`intel`** reads the threat-intelligence evidence and may ask for a threat-list lookup or an
  outside reputation or server lookup.
- **`responder`** (off) only ranks and rephrases the actions of ARGUS's fixed catalogue
  (`config/actions.yaml`) for a confirmed case; it may not invent an action, a command, an address
  or a number, and code refuses an answer that names an action it was not given.
- **`reporter`** (off) only says the figures of a daily or weekly report in one plain paragraph;
  code refuses an answer containing a number that is not one of the report's figures.

## When an agent runs

An agent runs only when a **trigger** it accepts fires, and only if its file loads, matches its
pin and is the enabled version:

| Trigger | What fires it | Agent |
|---|---|---|
| `engine_no_decision` | The assessment service (`argus assess run --agent`) found investigations the decision engine left undecided. They are grouped into **patterns** (same rule, same evidence shape, same day); the investigator runs on **one member per pattern** (raised ones first, then the most severe, then the newest), at most `--agent-per-day` runs a day (400 in the shipped unit) and `--agent-batch` at once (3). The others show "same pattern as ...". | `investigator` |
| `person_request` | A reviewer presses **Ask the AI investigator now** on an investigation (`review` capability). | `investigator` |
| `coordinator_consult` | The investigator names specialists in its answer (`consult`), at most two a round. | `web`, `proxy`, `intel` |
| `case_advice` | A confirmed case has advice to rank. | `responder` |
| `report_due` | A daily or weekly report has its figures. | `reporter` |

An investigation that belongs to a **notified** case's known infection (the owner was told) is
never given to the investigator: ARGUS counts its alerts and spends no run on them.

## One investigator run

A run (`src/argus/agent/agent.py`) goes in **rounds**:

1. The item (the investigation's dossier) is rendered through the **privacy layer**: internal
   names and addresses become pseudonyms such as `I1.IP_1`.
2. The **coordinator** answers. If it names specialists, each reads the same rendering and
   writes notes; the coordinator decides again with their notes.
3. Every **ask** (a tool and one entity pseudonym) from the coordinator or a specialist goes to
   the tool catalogue. An ask for a tool outside that agent's own tools is refused and recorded,
   never sent. The others run through the Elastic Gateway (or the outside threat-intel service),
   within its budget and health states.
4. The evidence that comes back joins the item, and the next round reads the new rendering.

Its bounds (the investigator's file, capped by code): at most **4 rounds, 12 tool calls, 8 model
calls, 2 specialists a round and 240 seconds**. A reply that cannot be read gets one repair call,
then the next provider.

**The model tier** is chosen by code, not by the agent: **medium** when the item has a danger
sign (a floor signal) or untrusted text had to be cut, **small** otherwise; the specialists use
small. The large tier is never used by the investigator.

## The tools

The agents never write a query. A tool is one of a fixed set of read-only questions
(`src/argus/agent/catalogue.py`); ARGUS reveals the pseudonym's value in memory and builds every
parameter itself:

| Tool | Domain | Takes | What it asks |
|---|---|---|---|
| `proxy.host` | proxy | an internal address | the host's proxy traffic in the alert's hours: top destinations, bytes, answers, a 10-minute timeline |
| `proxy.destination` | proxy | a public address | a public destination's proxy traffic in the alert's hours: how many of your hosts reached it, which, the top URLs |
| `web.followups` | web | an address | the client's successful (2xx) web answers in the six hours after the first alert |
| `ti.lookup` | intel | an address or a domain | your threat-intel sources (needs a site `ti_sources` entry) |
| `outside.reputation` | intel | an outside address or domain | VirusTotal's reputation (needs its key; a small daily allowance) |
| `outside.server` | intel | an outside address | what the server is, from Shodan, then Censys (open ports, software, names, known CVEs) |

A tool refuses with a reason the model sees (for example `proxy.destination takes a public
address`, or `the proxy logs for this time are not ready or out of range`); a refusal sends
nothing.

## What checks every answer

The checks are **code, not agents** (the "guardian"):

- every cited fact must be quoted exactly from the item;
- a benign answer must clear the decision engine's **safety floor**: no benign while a
  threat-list hit, an outside detection, success after an attack, a regular beacon, a rare
  destination, a remote-admin, P2P or anonymiser port, a high or critical severity, a first-seen
  entity or a volume spike is present, **or not known**;
- an answer that names another item's pseudonym is refused;
- quoted text from logs is untrusted data, never an instruction (prompt-injection checks).

An answer that passes becomes a **proposal** a person confirms or corrects. One that does not is
still shown as **ARGUS's reading**, with the reason it is not a proposal.

## The agent file

`config/agents/<name>.md`, for example `web.md`:

```markdown
---
name: web
kind: specialist
version: specialist@1
mission: Read the web evidence of an item for the investigator, and ask for the web follow-ups it needs.
task: assess.specialist
tier: small
tools: [web.followups]
triggers: [coordinator_consult]
output: notes@1
---
You are a web specialist helping the lead analyst with one alert investigation (an
item) ...
{tools}
Answer with one JSON object and nothing else:
{"notes": "...", "cites": [...], "ask": [{"tool": "<tool>", "entity": "<pseudonym>"}, ...]}
```

| Header field | Meaning |
|---|---|
| `name` | The agent; the file is named after it |
| `kind` | `coordinator`, `specialist`, `responder` or `reporter` (must equal the binding) |
| `version` | `<kind>@<number>`; must be pinned in code |
| `mission` | One line, shown to people |
| `task` | The LLM gateway's task for its calls (must equal the binding; providers can allowlist tasks) |
| `tier` | `small`, `medium` or `large`, at most the binding's |
| `tools` | Catalogue tools, a subset of the binding's |
| `specialists` | (coordinator) the specialists it may consult, a subset of the binding's |
| `budget` | (coordinator) `{rounds, tools, calls, consults, seconds}`, at most the binding's |
| `triggers` | What may start it, a subset of the binding's |
| `output` | The answer's shape (must equal the binding) |

The body is the prompt, byte for byte, with `{tools}` exactly once: ARGUS writes one line per
allowed tool there. The loader is strict: printable ASCII only (no tab, no look-alike or invisible
character that could hide text from the person approving a prompt), no trailing spaces, one final
newline, at most 64 KiB; the header is a small YAML subset (no anchors, tags or duplicate keys).

## What code binds

`src/argus/agent/registry.py` decides what a file may be:

- **`BINDINGS`**: each agent's kind, task, output, triggers, the largest set of tools and
  specialists, the highest tier and the largest budget. A file may only narrow them.
- **`PINS`**: every version a file may carry, with the SHA-256 of the **file** and of the
  **prompt a model is given** (the tool lines filled in), and the git tag that approved it. An
  edited file therefore needs a new version, and a new version needs a pin: no file can re-pin
  itself.
- **`ENABLED`**: the version each agent runs, or `None` (off). No file can switch itself on.

`argus doctor` (the `agents` line) loads them all and says which run and why any is refused, for
example `web.md: is not the file pinned for specialist@1 ... an edited file needs a new version
and its pin`.

## Changing an agent

To change a prompt or narrow an agent's tools:

1. Edit `config/agents/<name>.md` and **raise its `version`** (`specialist@1` → `specialist@2`).
2. Compute its hashes:

   ```bash
   uv run python -c "from pathlib import Path; from argus.agent import loader; \
   d = loader.read(Path('config/agents/web.md')); print(d.version, d.file_sha256, d.prompt_sha256)"
   ```

3. Add the new version to `PINS[<name>]` in `registry.py` with both hashes and the tag that will
   approve it, keeping the old pin (for evaluations of the old version).
4. **Evaluate** it ([below](#evaluating-a-change)), and only then set `ENABLED[<name>]` to the new
   version.
5. `uv run argus doctor` (the `agents` line passes) and the agent tests:
   `uv run pytest tests/unit/agent -q`.

Changing what an agent **may** do (a new tool, a higher tier, a bigger budget) is a change to its
binding in `registry.py`; a new tool is a new entry in the catalogue (`catalogue.py`) built on a
registered, validated gateway template.

## Adding a specialist

1. **Its tools**: use catalogue tools, or add one (a `Tool` in `catalogue.py` with its domain, the
   pseudonym labels it takes, the sentence the model is told, and a builder that turns one entity
   into a registered gateway template's parameters, or a refusal).
2. **Its binding**: add it to `BINDINGS` (`_specialist(...)` with its tools), and add its name to
   the investigator's binding's `specialists`.
3. **Its file**: `config/agents/<name>.md`, kind `specialist`, `task: assess.specialist`,
   `triggers: [coordinator_consult]`, `output: notes@1`.
4. **The coordinator**: a new `investigator` version whose file lists the new specialist (and says
   when to consult it), with its own pin.
5. **Pins and enabling**: pin both files; enable both only after the evaluation.

## Evaluating a change

A new version of the **coordinator** (which gives verdicts) is enabled only after a paired
comparison on the **gold set** (your reviewers' answered items): at least 30 items with a closable
gap, the same items, provider, model and prompt, each arm twice, showing a gain beyond the
repeat-run noise (McNemar, alpha 0.05), no loss of true-positive recall beyond it, and **no true
positive proposed benign**. The tools:

```bash
uv run argus gold status                                  # how many items people answered
uv run argus gold agent --provider gemini --allow-disabled --limit 30   # a version not yet enabled
uv run argus gold agent --tools --provider gemini --allow-disabled
```

Evaluation calls run at low priority and overnight only (17:30–24:00 UTC), within a nightly cap
per provider, so they never use up a day's limits ([costs.md](costs.md#how-the-budget-works)). A
specialist's change is judged by the coordinator's results with it; the responder is enabled after
its catalogue's owners and wording are reviewed, the reporter after its numbers match the reports'.
