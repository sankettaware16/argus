"""Q-H1's proof that moving agent@1's prompts into ``config/agents/*.md`` changed nothing it
should not: the parity cassettes recorded on the pre-port code (``parity.BASE``) are replayed
strictly through the ported agent and the real LLM gateway. A request whose bytes changed has
no recorded answer and stops the run (``CassetteMiss``); so does any request the pre-port
code did not make.

What may differ, and only that: each check in the reviewer's report now names the agent that
asked for it; an answer that is no proposal now leaves ARGUS's reading beside it (AR1: the
report's ``reading``, which the pre-port code did not store); and an ask for a tool outside the
asking agent's own set, which the pre-port code ran, is refused, so those runs are identical up
to the refusal and end there."""

from __future__ import annotations

import json
from typing import Any

import pytest

from argus.agent import loader
from argus.agent.registry import GOLD_RUNS
from argus.evaluation import agent_eval
from argus.llm.wire import CassetteMiss, LlmCassette
from tests.unit.agent import parity

MANIFEST: dict[str, Any] = json.loads(parity.MANIFEST.read_text(encoding="utf-8"))
SCENARIOS = {s.name: s for s in parity.scenarios()}
IN_SET = sorted(n for n, s in MANIFEST["scenarios"].items() if not s["outside"])
OUTSIDE = sorted(n for n, s in MANIFEST["scenarios"].items() if s["outside"])


def cassette(name: str) -> LlmCassette:
    return LlmCassette(parity.HERE / "cassettes" / f"{name}.json")  # replay: strict


def without_agents(report: dict[str, Any]) -> dict[str, Any]:
    checks = [{k: v for k, v in c.items() if k != "agent"} for c in report["checks"]]
    return {**{k: v for k, v in report.items() if k != "reading"}, "checks": checks}


def test_the_recording_covers_every_scenario_from_the_pre_port_code() -> None:
    assert MANIFEST["base"] == parity.BASE
    assert set(MANIFEST["scenarios"]) == set(SCENARIOS)
    assert MANIFEST["versions"] == {"coordinator": "coordinator@3", "specialist": "specialist@1"}
    assert len(IN_SET) == 13
    assert len(OUTSIDE) == 2
    for name, recorded in MANIFEST["scenarios"].items():
        assert recorded["outside"] == SCENARIOS[name].outside
        entries = json.loads((parity.HERE / "cassettes" / f"{name}.json").read_text())["entries"]
        assert set(entries) == set(recorded["keys"])  # one answer per request, no other


@pytest.mark.parametrize("name", IN_SET)
async def test_a_recorded_run_replays_byte_for_byte(name: str) -> None:
    recorded = MANIFEST["scenarios"][name]
    got = await parity.run(SCENARIOS[name], cassette(name))
    assert got.keys == recorded["keys"]  # the same requests, in the same order
    assert got.calls == recorded["calls"]  # system prompt, item, model and answer cap
    assert got.tasks == recorded["tasks"]  # what the SIEM is asked
    assert got.verdict == recorded["verdict"]
    assert without_agents(got.report) == recorded["report"]
    for check in got.report["checks"]:
        assert check["agent"] in parity.frozen().by_name


def test_one_scenario_was_rekeyed_for_the_outside_tools() -> None:
    """AR3 (D-165) added two tools, so the catalogue's refusal of an unknown tool ("tools: ...")
    lists two more names. The scenario that quotes it in the history was recorded again with the
    same scripted answers; its first call, the one before any history, is as it was."""
    assert MANIFEST["rekeyed"]["refusals_in_the_history"].startswith("AR3 (D-165)")
    got = MANIFEST["scenarios"]["refusals_in_the_history"]
    assert len(got["keys"]) == 2


def test_the_scenarios_naming_a_threat_intel_source_were_rekeyed_for_the_suites_site() -> None:
    """D-294: the suite runs on its made-up site, whose lookup source a request names ("On
    acme-threat-intel: ..."); those scenarios' answers are the recorded ones under the new
    request keys (release/map_test_site.py --parity, private), and nothing else changed."""
    rekeyed = {n for n, note in MANIFEST["rekeyed"].items() if "D-294" in note}
    assert rekeyed == {
        "a_tool_and_its_evidence",
        "every_round_used",
        "evidence_already_held",
        "narrower_limits",
        "refusals_in_the_history",
        "specialists_asking_in_their_own_set",
        "web_specialist_asks_its_tool",
    }
    assert set(MANIFEST["rekeyed"]) == rekeyed


def test_the_prompts_are_byte_identical() -> None:
    agents = parity.frozen()
    assert {name: d.prompt for name, d in agents.by_name.items()} == MANIFEST["base_prompts"]
    for text in MANIFEST["prompts"].values():  # every system prompt a recorded run sent
        assert any(text.startswith(d.prompt) for d in agents.by_name.values())


def test_the_gold_run_ids_of_the_recorded_agents_are_unchanged() -> None:
    agents = parity.frozen()
    budget = agents.coordinator.budget
    assert budget is not None
    got = {"no_tools": agent_eval.signature_of(agents, budget, False),
           "tools": agent_eval.signature_of(agents, budget, True)}  # fmt: skip
    assert got == MANIFEST["signatures"]
    assert got == {"no_tools": "adf1ebf5f7ce", "tools": "872a71a7fe93"}
    assert got != dict(GOLD_RUNS)  # AR3's agents (D-165) have their own ids


@pytest.mark.parametrize("name", OUTSIDE)
async def test_an_ask_outside_its_agents_set_ran_before_and_is_refused_now(name: str) -> None:
    recorded = MANIFEST["scenarios"][name]
    assert [t["template"] for t in recorded["tasks"]] == ["proxy.host"]  # it reached the SIEM
    got = await parity.run(SCENARIOS[name], cassette(name))
    assert got.tasks == []  # it no longer does
    assert got.keys == recorded["keys"][:3]  # identical up to the refusal, and nothing after
    assert got.calls == recorded["calls"][:3]
    (check,) = got.report["checks"]
    who = {"outside_intel_asks_a_proxy_tool": "intel",
           "outside_an_injected_ask_obeyed_by_a_specialist": "web"}[name]  # fmt: skip
    assert check == {"tool": "proxy.host", "value": "10.20.3.4",
                     "result": f"refused: the {who} specialist may not use proxy.host",
                     "agent": who}  # fmt: skip
    assert got.verdict["reasons"][-1].endswith("tools: none")


async def test_a_changed_prompt_misses_the_cassette(monkeypatch: pytest.MonkeyPatch) -> None:
    """The replay is strict: one byte more in the investigator's instructions is a request
    the pre-port code never made."""
    agents = parity.frozen()
    lead = agents.coordinator
    import dataclasses

    changed = dataclasses.replace(lead, prompt=lead.prompt + " ")
    edited = loader.Agents({**agents.by_name, lead.name: changed})

    def make(*a: Any, **kw: Any) -> Any:
        return parity.Agent(*a, agents=edited, **kw)

    with pytest.raises(CassetteMiss):
        await parity.run(SCENARIOS["a_plain_answer"], cassette("a_plain_answer"), make)
