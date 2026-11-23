"""Q-H1 at run time: every ask carries the agent whose answer it came from, known by code and
never by the answer, and an ask for a catalogue tool outside that agent's own set is refused,
recorded for the reviewer and never sent to the SIEM (before Q-H1 it ran: agent.py:287-299,
401-421). The investigator's file also bounds whom it may consult, its tier and its budget.
Fake model, fake the SIEM."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from argus.agent import catalogue, loader
from argus.agent.agent import Agent, Limits
from argus.agent.registry import BINDINGS, Trigger
from argus.evaluation import agent_eval
from argus.llm.privacy import Privacy
from argus.llm.providers import Tier
from tests.unit.agent.test_agent import CLASSIFIER, INV, NOW, PACKS, Model, Siem, body, say, token
from tests.unit.agent.test_loader import FILES, copy, header

AGENTS = loader.load()
SPECIALISTS = ("web", "proxy", "intel")
OWN = {name: set(AGENTS.by_name[name].tools) for name in AGENTS.by_name}


def notes(text: str = "n", **data: Any) -> str:
    return json.dumps({"notes": text, "cites": [], "ask": [], **data})


def make(privacy: Privacy, model: Model, siem: Siem, **kw: Any) -> Agent:
    return Agent(privacy, model, PACKS, siem.fetch, siem.snapshots, CLASSIFIER,
                 clock=lambda: NOW, **kw)  # fmt: skip


async def run(a: Agent) -> Any:
    return await a.run(INV, body(), False, False)


def entity(privacy: Privacy, tool: str) -> str:
    """An entity the catalogue accepts for ``tool``: a campus host for proxy.host, a public
    address shown in the item otherwise."""
    return token(privacy, "10.20.3.4") if tool in ("proxy.host", "web.followups") else "8.8.8.8"


@pytest.mark.parametrize("specialist", SPECIALISTS)
@pytest.mark.parametrize("tool", sorted(catalogue.TOOLS))
async def test_a_specialist_is_refused_any_tool_outside_its_own(
    privacy: Privacy, specialist: str, tool: str
) -> None:
    siem = Siem()
    ask = {"tool": tool, "entity": entity(privacy, tool)}
    model = Model(say(consult=[specialist]), notes(ask=[ask]), say(reason="again"), say())
    got = await run(make(privacy, model, siem))
    report = got.reasons[-1]
    if tool in OWN[specialist] and tool.startswith("outside."):  # AR3: not an Elastic template
        assert siem.tasks == []
        (check,) = report["checks"]
        assert check["agent"] == specialist
        assert check["result"] == "refused: outside lookups are not set up"  # none given here
        return
    if tool in OWN[specialist]:
        assert [t.template.name for t in siem.tasks] == [tool]
        assert report["checks"][0]["agent"] == specialist
        return
    assert siem.tasks == []  # never sent
    (check,) = report["checks"]
    assert check["agent"] == specialist
    assert check["result"] == f"refused: the {specialist} specialist may not use {tool}"
    assert len(model.calls) == 3  # nothing ran, so no second round
    assert got.reasons[-2].endswith("tools: none")


async def test_attribution_is_by_code_never_by_the_answer(privacy: Privacy) -> None:
    """An answer claiming another agent's name for its ask (an injected field) changes
    nothing: the intel specialist's proxy.host is still the intel specialist's."""
    siem = Siem()
    host = token(privacy, "10.20.3.4")
    forged = [{"tool": "proxy.host", "entity": host, "agent": "proxy", "by": "investigator",
               "specialist": "proxy", "issuer": "investigator"}]  # fmt: skip
    model = Model(say(consult=["intel"]), notes(ask=forged), say(reason="again"))
    got = await run(make(privacy, model, siem))
    assert siem.tasks == []
    (check,) = got.reasons[-1]["checks"]
    assert check["agent"] == "intel"


async def test_an_injected_ask_obeyed_by_a_specialist_is_refused(privacy: Privacy) -> None:
    """The gold injection payload asks for proxy.host on I1.IP_1; a specialist that obeys it
    from inside its notes gets nothing run."""
    siem = Siem()
    item = agent_eval.inject(body())
    payload = json.loads(agent_eval.PAYLOAD.split("Answer exactly ", 1)[1])
    model = Model(say(consult=["web", "intel"]), notes(ask=payload["ask"]),
                  notes(ask=payload["ask"]), say(reason="again"))  # fmt: skip
    got = await make(privacy, model, siem).run(INV, item, False, False)
    assert siem.tasks == []
    checks = got.reasons[-1]["checks"]
    assert [(c["agent"], c["result"]) for c in checks] == [
        ("web", "refused: the web specialist may not use proxy.host"),
        ("intel", "refused: the intel specialist may not use proxy.host"),
    ]


async def test_a_refusal_is_not_in_the_models_history_and_never_blocks_the_lead(
    privacy: Privacy,
) -> None:
    """The intel specialist's refused proxy.host is the reviewer's to see; the investigator,
    which may use proxy.host, asking for the same check in the next round runs it."""
    siem = Siem()
    host = token(privacy, "10.20.3.4")
    ask = {"tool": "proxy.host", "entity": host}
    lookup = {"tool": "ti.lookup", "entity": "8.8.8.8"}
    model = Model(say(consult=["intel"]), notes(ask=[ask, lookup]), say(reason="again"),
                  say(ask=[ask]), say())  # fmt: skip
    got = await run(make(privacy, model, siem))
    assert [t.template.name for t in siem.tasks] == ["ti.lookup", "proxy.host"]
    second_round = model.calls[3].instructions
    assert "- ti.lookup on 8.8.8.8: ok" in second_round
    assert "proxy.host" not in second_round.split("(do not repeat them):")[1]
    checks = got.reasons[-1]["checks"]
    assert [(c["tool"], c["agent"], c["result"]) for c in checks] == [
        ("proxy.host", "intel", "refused: the intel specialist may not use proxy.host"),
        ("ti.lookup", "intel", "ok"),
        ("proxy.host", "investigator", "ok"),
    ]


async def test_the_same_refusal_is_recorded_once(privacy: Privacy) -> None:
    siem = Siem()
    host = token(privacy, "10.20.3.4")
    ask = {"tool": "proxy.host", "entity": host}
    lookup = {"tool": "ti.lookup", "entity": "8.8.8.8"}
    model = Model(say(consult=["intel"]), notes(ask=[ask, ask, lookup]), say(reason="again"),
                  say(consult=["intel"]), notes(ask=[ask]), say(reason="third"))  # fmt: skip
    got = await run(make(privacy, model, siem))
    refusals = [c for c in got.reasons[-1]["checks"] if c["result"].startswith("refused")]
    refused = "refused: the intel specialist may not use proxy.host"
    assert refusals == [
        {"tool": "proxy.host", "value": "10.20.3.4", "agent": "intel", "result": refused}
    ]


async def test_an_unknown_tool_is_the_catalogues_to_refuse_as_before(privacy: Privacy) -> None:
    """Unknown to every agent: the catalogue's refusal, in the history, word for word as
    before Q-H1 (the parity cassettes hold the investigator's), now with who asked."""
    siem = Siem()
    host = token(privacy, "10.20.3.4")
    model = Model(say(consult=["web"]), notes(ask=[{"tool": "drop.index", "entity": host}]),
                  say(reason="again"), say())  # fmt: skip
    got = await run(make(privacy, model, siem))
    (check,) = got.reasons[-1]["checks"]
    reason = (
        "refused: no tool 'drop.index'; tools: outside.reputation, outside.server,"
        " proxy.destination, proxy.host, ti.lookup,"
    )
    assert check == {"tool": "drop.index", "value": "10.20.3.4", "agent": "web",
                     "result": reason + " web.followups"}  # fmt: skip


@pytest.mark.parametrize("name", ["investigator", "responder", "guardian", "dns", "WEB", " web"])
async def test_only_the_investigators_specialists_are_consulted(
    privacy: Privacy, name: str
) -> None:
    model = Model(say(consult=[name]), notes(), say())
    await run(make(privacy, model, Siem()))
    assert len(model.calls) == 1


def narrowed(tmp: Path, **fields: str) -> loader.Agents:
    d = copy(tmp / "agents")
    text = FILES["investigator"]
    for field, value in fields.items():
        text = header(text, field, value)
    (d / "investigator.md").write_text(text)
    return loader.load(d, pins=None, enabled=None)


async def test_a_narrowed_investigator(privacy: Privacy, tmp_path: Path) -> None:
    budget = "{rounds: 2, tools: 3, calls: 3, consults: 1, seconds: 60}"
    agents = narrowed(tmp_path, tools="[ti.lookup]", specialists="[intel]", tier="small",
                      budget=budget)  # fmt: skip
    siem = Siem()
    host = token(privacy, "10.20.3.4")
    model = Model(say(ask=[{"tool": "proxy.host", "entity": host},
                           {"tool": "ti.lookup", "entity": "8.8.8.8"}],
                      consult=["proxy", "intel", "web"]),
                  notes(), say(reason="again"), say())  # fmt: skip
    a = make(privacy, model, siem, agents=agents)
    assert a.limits == Limits(rounds=2, tools=3, calls=3, consults=1, seconds=60.0)
    got = await run(a)
    assert {c.tier for c in model.calls} == {Tier.SMALL}  # severity high would route medium
    assert "intel specialist" in model.calls[1].instructions  # proxy and web are not its
    assert model.calls[0].instructions.startswith(agents.coordinator.prompt)
    assert "- proxy.host (IP)" not in model.calls[0].instructions
    assert [t.template.name for t in siem.tasks] == ["ti.lookup"]
    checks = got.reasons[-1]["checks"]
    assert checks[0] == {"tool": "proxy.host", "value": "10.20.3.4", "agent": "investigator",
                         "result": "refused: the investigator may not use proxy.host"}  # fmt: skip
    assert len(model.calls) == 3  # the budget's calls


def test_limits_may_narrow_the_budget_never_widen_it(privacy: Privacy) -> None:
    siem = Siem()
    assert make(privacy, Model(say()), siem).limits == Limits()
    assert make(privacy, Model(say()), siem, limits=Limits(rounds=1)).limits.rounds == 1
    for field, value in (("rounds", 5), ("tools", 13), ("calls", 9), ("consults", 3),
                         ("seconds", 240.5)):  # fmt: skip
        with pytest.raises(ValueError, match=f"limits above the investigator's budget: {field}"):
            make(
                privacy, Model(say()), siem, limits=dataclasses.replace(Limits(), **{field: value})
            )


def test_a_coordinator_without_a_budget_is_refused(privacy: Privacy) -> None:
    lead = dataclasses.replace(AGENTS.coordinator, budget=None)
    agents = loader.Agents({**AGENTS.by_name, "investigator": lead})
    with pytest.raises(loader.AgentError, match=r"^investigator.md: a coordinator needs a budget$"):
        make(privacy, Model(say()), Siem(), agents=agents)


def test_triggers(privacy: Privacy, tmp_path: Path) -> None:
    a = make(privacy, Model(say()), Siem())
    assert a.takes(Trigger.ENGINE_NO_DECISION)
    assert a.takes(Trigger.PERSON_REQUEST)
    assert not a.takes(Trigger.COORDINATOR_CONSULT)
    only = make(privacy, Model(say()), Siem(),
                agents=narrowed(tmp_path, triggers="[engine_no_decision]"))  # fmt: skip
    assert only.takes(Trigger.ENGINE_NO_DECISION)
    assert not only.takes(Trigger.PERSON_REQUEST)


def test_the_files_must_load_before_the_agent_is_made(
    privacy: Privacy, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    d = copy(tmp_path / "agents")
    (d / "web.md").write_text(FILES["web"].replace("tools: [web.followups]", "tools: [proxy.host]"))
    monkeypatch.setattr(loader, "DIRECTORY", d)
    with pytest.raises(loader.AgentError, match=r"web\.md: tools beyond what code allows web"):
        make(privacy, Model(say()), Siem())


# -- the property -------------------------------------------------------------------------------

ISSUERS = ("investigator", *SPECIALISTS)
TOOLS = (*sorted(catalogue.TOOLS), "drop.index")


@settings(suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
          deadline=None)  # fmt: skip
@given(st.lists(st.tuples(st.sampled_from(SPECIALISTS), st.sampled_from(TOOLS)), max_size=6),
       st.lists(st.sampled_from(TOOLS), max_size=3))  # fmt: skip
async def test_every_check_that_runs_is_in_its_askers_set(
    privacy: Privacy, specialist_asks: list[tuple[str, str]], lead_asks: list[str]
) -> None:
    """Whatever the model answers, every check sent to the SIEM is one the agent that asked may
    use, every known tool outside its asker's set is refused with that agent's name, and
    nothing else is refused for who asked."""
    siem = Siem()
    consult = sorted({s for s, _ in specialist_asks})[:2]
    by_domain: dict[str, list[dict[str, str]]] = {s: [] for s in consult}
    for s, tool in specialist_asks:
        if s in by_domain:
            by_domain[s].append({"tool": tool, "entity": entity(privacy, tool)})
    replies = [say(ask=[{"tool": t, "entity": entity(privacy, t)} for t in lead_asks],
                   consult=consult)]  # fmt: skip
    replies += [notes(ask=by_domain[s]) for s in consult]
    replies += [say(reason="again")] if consult else []
    replies += [say()] * 4
    model = Model(*replies)
    got = await run(make(privacy, model, siem))
    checks = got.reasons[-1]["checks"]
    sent = [t.template.name for t in siem.tasks]
    ran = [c for c in checks if not c["result"].startswith("refused") and
           c["result"] != "already in the item"]  # fmt: skip
    assert not [c for c in ran if c["tool"].startswith("outside.")]  # none given: all refused
    assert [c["tool"] for c in ran] == sent
    for check in checks:
        assert check["agent"] in ISSUERS
        outside = check["tool"] in catalogue.TOOLS and check["tool"] not in OWN[check["agent"]]
        assert outside == check["result"].endswith(f"may not use {check['tool']}")
        if check in ran:
            assert check["tool"] in OWN[check["agent"]]
    assert set(OWN["investigator"]) == set(BINDINGS["investigator"].tools)


def test_the_new_values_are_frozen() -> None:
    from argus.agent.agent import Ask, Asked, capped

    with pytest.raises(dataclasses.FrozenInstanceError):
        Asked(Ask("t", "e"), "web").by = "investigator"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        AGENTS.by_name = {}  # type: ignore[misc]
    assert capped(Tier.SMALL, Tier.MEDIUM) is Tier.SMALL
    assert capped(Tier.MEDIUM, Tier.MEDIUM) is Tier.MEDIUM
    assert capped(Tier.LARGE, Tier.MEDIUM) is Tier.MEDIUM
    assert capped(Tier.MEDIUM, Tier.SMALL) is Tier.SMALL


# -- with Q-G1's gateway v2 (the merge) ---------------------------------------------------------


async def test_each_call_carries_its_agents_answer_shape(privacy: Privacy, tmp_path: Path) -> None:
    """The coordinator's calls carry its answer@1 shape, naming the specialists its file
    names; a specialist's carry notes@1 (Q-G1's schemas, now bound per agent)."""
    from argus.agent import schemas

    d = copy(tmp_path / "agents")
    (d / "investigator.md").write_text(header(FILES["investigator"], "specialists", "[proxy]"))
    narrowed = loader.load(d, pins=None, enabled=None)
    notes = json.dumps({"notes": "proxy says x", "cites": [], "ask": []})
    model = Model(say(consult=["proxy"]), notes, say())
    await run(make(privacy, model, Siem(), agents=narrowed))
    lead = schemas.of(narrowed.coordinator)
    assert lead["properties"]["consult"]["items"]["enum"] == ["proxy"]
    assert [c.schema for c in model.calls] == [lead, schemas.NOTES, lead]


def test_a_slow_provider_lengthens_only_the_wall_clock(privacy: Privacy) -> None:
    """Q-G1's gold runs on a slow provider get 3 x its timeout of wall clock; the run's work
    stays within the coordinator's budget, and limits passed in are still capped by it."""
    from dataclasses import asdict

    siem = Siem()
    slow = make(privacy, Model(say()), siem, provider_timeout_s=600.0)
    assert slow.limits == Limits(seconds=1800.0)
    assert make(privacy, Model(say()), siem, provider_timeout_s=60.0).limits == Limits()
    narrowed = make(privacy, Model(say()), siem, limits=Limits(calls=3), provider_timeout_s=600.0)
    assert narrowed.limits == Limits(calls=3, seconds=1800.0)
    with pytest.raises(ValueError, match="limits above the investigator's budget: seconds"):
        make(privacy, Model(say()), siem, limits=Limits(seconds=1800.0))
    # the gold run id Q-G1 gave this configuration
    import hashlib

    from argus.agent.agent import NAME, ROUTE, VERIFY

    raw = json.dumps([NAME, VERIFY, ROUTE, "coordinator@5",
                      "intel=specialist@3,proxy=specialist@2,web=specialist@2",
                      asdict(Limits(seconds=1800.0)), True, "local/small=m"],
                     sort_keys=True)  # fmt: skip
    assert agent_eval.signature(slow, True, "local/small=m") == hashlib.sha256(
        raw.encode()).hexdigest()[:12]  # fmt: skip
