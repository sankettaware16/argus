"""What each agent may be, bound in code (Q-H1, plan §7.6, D-105).

An agent is a Markdown file in ``config/agents/`` (its header and its instructions); what the
file may say is decided here, never by the file:

* ``BINDINGS``: each agent's name is bound to its kind, model task, output, triggers and the
  largest sets of tools and specialists it may have, the highest model tier and the largest
  budget. A file may only narrow them; a kind, task or output change is refused.
* ``PINS``: each version a file may carry, with the SHA-256 of the file and of the
  instructions it gives a model (its tools' lines filled in), and the git tag that approves it
  (``q-<id>-approved``: doctor compares the files with the nearest such tag). An edited file
  therefore needs a new version, and a new version needs a pin here: no file can re-pin itself.
* ``ENABLED``: the version each agent runs, or None: the agent is off (built so, like Q-H2's
  responder until its owners and wording are reviewed). No file can switch itself on. A new
  version of a verdict agent (a coordinator) is enabled only under plan §7.6's rule: a paired
  comparison on at least 30 gold items with a closable gap (same items, provider, model and
  prompt, each arm twice) that shows a gain beyond the repeat-run noise (McNemar, alpha 0.05),
  no loss of true-positive recall beyond it and no true positive proposed benign; then a
  DECISIONS entry. The responder goes on after the user's review of its owners and wording;
  the reporter after its numbers match SQL.
* ``GOLD_RUNS``: the evaluation signatures (``argus.evaluation.agent_eval.signature``) of the
  enabled agent@1, without and with tools: the ids its gold verdicts are kept under. The
  loaded files must give exactly these, so a change to anything a verdict depends on is seen
  here before any gold result is reused for it.

Guardian stays code (D-105): the cite checks, the floor, the injection checks and the
validator are not agents.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

from argus.llm.providers import Tier


class Kind(StrEnum):
    COORDINATOR = "coordinator"  # decides; may consult specialists; has the run's budget
    SPECIALIST = "specialist"  # reads one domain for the coordinator; consults no one
    RESPONDER = "responder"  # ranks and phrases catalogue actions for a case (Q-H2); no tools
    REPORTER = "reporter"  # says a report's figures in one paragraph (Q-H3); no tools


class Trigger(StrEnum):
    ENGINE_NO_DECISION = "engine_no_decision"  # the decision engine found no decision (P3)
    PERSON_REQUEST = "person_request"  # "Ask the AI investigator now" (D-095)
    COORDINATOR_CONSULT = "coordinator_consult"  # the coordinator asked for this specialist
    CASE_ADVICE = "case_advice"  # a confirmed case has advice to rank and phrase (Q-H2)
    REPORT_DUE = "report_due"  # a daily or weekly report has its figures (Q-H3)


TIERS = (Tier.SMALL, Tier.MEDIUM, Tier.LARGE)  # in order: a file may name its cap or below


@dataclass(frozen=True)
class Limits:
    """One run's bounds. Its fields are part of the evaluation signature (``asdict``): adding,
    renaming or retyping one changes every gold run id."""

    rounds: int = 4
    tools: int = 12
    calls: int = 8
    consults: int = 2  # specialists per round
    seconds: float = 240.0


@dataclass(frozen=True)
class Binding:
    kind: Kind
    task: str  # the model gateway's task for its calls (Q-G1 routes by it)
    output: str  # the shape of its answers
    triggers: frozenset[Trigger]  # what may start it
    tools: frozenset[str]  # the largest set of catalogue tools it may ask for
    tier: Tier  # the highest model tier (D-098: the investigator never uses large)
    specialists: frozenset[str] = frozenset()  # the largest set it may consult
    budget: Limits | None = None  # a coordinator's largest budget for one run


def _specialist(*tools: str) -> Binding:
    return Binding(
        kind=Kind.SPECIALIST,
        task="assess.specialist",
        output="notes@1",
        triggers=frozenset({Trigger.COORDINATOR_CONSULT}),
        tools=frozenset(tools),
        tier=Tier.SMALL,
    )


BINDINGS: Mapping[str, Binding] = MappingProxyType(
    {
        "investigator": Binding(
            kind=Kind.COORDINATOR,
            task="assess.coordinator",
            output="answer@1",
            triggers=frozenset({Trigger.ENGINE_NO_DECISION, Trigger.PERSON_REQUEST}),
            tools=frozenset(
                {
                    "proxy.host",
                    "proxy.destination",
                    "web.followups",
                    "ti.lookup",
                    "outside.reputation",
                    "outside.server",
                }
            ),
            tier=Tier.MEDIUM,
            specialists=frozenset({"web", "proxy", "intel"}),
            budget=Limits(rounds=4, tools=12, calls=8, consults=2, seconds=240.0),
        ),
        "web": _specialist("web.followups"),
        "proxy": _specialist("proxy.host", "proxy.destination"),
        "intel": _specialist("ti.lookup", "outside.reputation", "outside.server"),
        # Q-H2: the responder only ranks and phrases the catalogue's actions for a case
        # (argus.responder.ranking checks its answer); it asks for nothing and is built off
        "responder": Binding(
            kind=Kind.RESPONDER,
            task="respond.rank",
            output="ranking@1",
            triggers=frozenset({Trigger.CASE_ADVICE}),
            tools=frozenset(),
            tier=Tier.SMALL,
        ),
        # Q-H3: the reporter only says the report's figures in one paragraph
        # (argus.reporter.prose checks its answer: a number that is not in the input refuses
        # it); it asks for nothing and is built off
        "reporter": Binding(
            kind=Kind.REPORTER,
            task="report.prose",
            output="prose@1",
            triggers=frozenset({Trigger.REPORT_DUE}),
            tools=frozenset(),
            tier=Tier.SMALL,
        ),
    }
)
COORDINATOR = "investigator"  # agent@1's coordinator: the others are its specialists


@dataclass(frozen=True)
class Pin:
    file_sha256: str  # the whole file, byte for byte
    prompt_sha256: str  # the instructions a model is given, with its tools' lines in
    approved: str  # the git tag that approves this version: its file is as at that tag


PINS: Mapping[str, Mapping[str, Pin]] = MappingProxyType(
    {
        "investigator": MappingProxyType(
            {
                "coordinator@3": Pin(
                    "f212ab8f9becad42891ee21c02c726e47ed589de8f22cbb8ea34337f9cce6944",
                    "3dc2a7dacec401ea018fafd8681dde3cfd03d7e5050fbe6f01dc37a9f7d5f60e",
                    "q-h1-approved",  # D-095 (its hypotheses), P6 (p6-approved); ported
                ),
                # AR3 (D-165): the two outside.* tools; the lead creates the tag when approving it
                "coordinator@4": Pin(
                    "95984877dfc72d7143ed0b4d061cf85a9703888dd16a2b6f33e063ce13a3a033",
                    "a90ac7cfa898b66969540f802a9f85b34dc71da315b59f867f0ab47136c66be7",
                    "ar3-approved",
                ),
                # D-338: the same instructions, with the site's words where the file named a
                # university; on a university site a model reads coordinator@4's text
                "coordinator@5": Pin(
                    "10b3fa550014434a9759ba455cd34ab1b03d1be1fdc50cbeee782400ec56627d",
                    "1927384dc5aecf6b11e8a93e9f89297d5a5b342f23fa8724c4bfd684a24cb0b8",
                    "site-words-approved",
                ),
            }
        ),
        "web": MappingProxyType(
            {
                "specialist@1": Pin(
                    "46214a567149398de6733da0327c0bb6386bb74ae1f6d15bd13422ecc3a274e0",
                    "7eefa6e9e46ce34d0d6a9f4546b0f5922bc360b77c9612782743cf3ba72b0652",
                    "q-h1-approved",  # P6 (p6-approved); ported byte for byte
                ),
                "specialist@2": Pin(
                    "6ded3f2d23ee09e6dcf092270d22f8185d12df65b4ea2e4d8877f164ae3190c6",
                    "f10c7d8de1005c9868628dd0581d8534c7ebd3904a4c3e2122dabe6541f4de26",
                    "site-words-approved",  # D-338: the site's words
                ),
            }
        ),
        "proxy": MappingProxyType(
            {
                "specialist@1": Pin(
                    "db82b7b83bdd798729696e5f063550e747f41349d2b9ccdc0b8dadf391648405",
                    "1c8349d40ec3b272c2b7c5ffa86b384a7b9fc9afd7ed0c1f1f27a703754ab09c",
                    "q-h1-approved",  # P6 (p6-approved); ported byte for byte
                ),
                "specialist@2": Pin(
                    "cdc5736888edea2a3e937dc219bb8c3dd81b0fdf4198b1d9e08686246114db50",
                    "aa65088513f6654e1376570b7aad6b7059256c66e56a8e44bf8a08add3ca6afa",
                    "site-words-approved",  # D-338: the site's words
                ),
            }
        ),
        "intel": MappingProxyType(
            {
                "specialist@1": Pin(
                    "b55297118175c0b234845e0d315d82410a9b98e447fd15e473a04b99a4401bb6",
                    "2ef7c0ca67a3752d468105787ecf3247bcfde94535243245a667b749df551e1e",
                    "q-h1-approved",  # P6 (p6-approved); ported byte for byte
                ),
                "specialist@2": Pin(
                    "39a376b99537259edcb1104e63fc8ef51295808060ab38ba8a340fccf49e9f34",
                    "f38633018afcb2ef9882eea65ad8120016a8cef082ef9ef33a87705fe2ef9a3a",
                    "ar3-approved",  # AR3 (D-165): the same two tools
                ),
                "specialist@3": Pin(
                    "2aeac339b2224cfe761837c247765eb908decdba92af574fefb82aa3ab67c5b1",
                    "b9d9471eeb1e64a27e1cd3e8e22ef9c7f68a5f9e4fcc1a0814df5e63eb000093",
                    "site-words-approved",  # D-338: the site's words
                ),
            }
        ),
        "responder": MappingProxyType(
            {
                "responder@1": Pin(
                    "f35476f48738d2996144683e8db89383d05ff4fbde84b36fb1e90f25b61981d7",
                    "586538632ff9b0277692b6378ac473ff4d1d9774f9aa0583f1b8b22a0e5e22f3",
                    "q-h2-approved",  # Q-H2: new; the lead creates the tag when approving it
                ),
                "responder@2": Pin(
                    "8e0aa91adbdb4df334b73ea73f272bfcf567341b42c4d7cbbb2a95775323c82d",
                    "251aa3145f5d4423237e4a40fbd6ce328003a6fd1849c5f3331b9dfb6f260dc9",
                    "site-words-approved",  # D-338: the site's words
                ),
            }
        ),
        "reporter": MappingProxyType(
            {
                "reporter@1": Pin(
                    "4a661f6d183d12724703b92e38a38b26375b5df7ccd5e3ef95abead7acd618f1",
                    "7ef9b1982cc97b9fed43a63161c28a2b079fb26beb5072c5296db055adc115bc",
                    "q-h3-approved",  # Q-H3: new; the lead creates the tag when approving it
                ),
                "reporter@2": Pin(
                    "c50334baeaa39474df23b62574c33edb2cb952ed9c5dcab151be4a0884068e46",
                    "3da9564cf361586df44b87e73898060ad8e0c48fd99ec2ef470e7eb9a56b469b",
                    "site-words-approved",  # D-338: the site's words
                ),
            }
        ),
    }
)

ENABLED: Mapping[str, str | None] = MappingProxyType(
    {
        "investigator": "coordinator@5",
        "web": "specialist@2",
        "proxy": "specialist@2",
        "intel": "specialist@3",
        "responder": None,  # off until the user has reviewed the catalogue's owners and wording
        "reporter": None,  # off until the user has read two reports and asks for the prose
    }
)

GOLD_RUNS: Mapping[str, str] = MappingProxyType(
    # D-338: coordinator@5 and its specialists give a model coordinator@4's text on the site the
    # gold items come from, so the verdicts kept under 98aa90f205fd and 0232557c5055 stand for it
    {"no_tools": "8962e42b9863", "tools": "bf01507f7984"}
)
