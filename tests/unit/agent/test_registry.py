"""Q-H1: what code binds each agent to, which versions it pins and which it runs. These are
the approval's own values, held here on purpose: changing one is a change a reviewer must
see, so each assertion says what the change needs."""

from __future__ import annotations

import dataclasses
import re

import pytest

from argus.agent import catalogue, drift
from argus.agent.registry import (
    BINDINGS,
    COORDINATOR,
    ENABLED,
    GOLD_RUNS,
    PINS,
    TIERS,
    Binding,
    Kind,
    Limits,
    Pin,
    Trigger,
)
from argus.llm.providers import Tier

SPECIALISTS = ("web", "proxy", "intel")


def test_the_investigator_is_bound_to_what_agent_1_did_before_q_h1() -> None:
    assert COORDINATOR == "investigator"
    assert BINDINGS["investigator"] == Binding(
        kind=Kind.COORDINATOR,
        task="assess.coordinator",
        output="answer@1",
        triggers=frozenset({Trigger.ENGINE_NO_DECISION, Trigger.PERSON_REQUEST}),
        tools=frozenset(catalogue.TOOLS),
        tier=Tier.MEDIUM,  # D-098: never the large model
        specialists=frozenset(SPECIALISTS),
        budget=Limits(rounds=4, tools=12, calls=8, consults=2, seconds=240.0),
    )


@pytest.mark.parametrize("name", SPECIALISTS)
def test_each_specialist_is_bound_to_its_own_domains_tools(name: str) -> None:
    domain = frozenset(t.name for t in catalogue.TOOLS.values() if t.domain == name)
    assert BINDINGS[name] == Binding(
        kind=Kind.SPECIALIST,
        task="assess.specialist",
        output="notes@1",
        triggers=frozenset({Trigger.COORDINATOR_CONSULT}),
        tools=domain,
        tier=Tier.SMALL,
    )
    assert domain  # every specialist has at least one tool
    assert BINDINGS[name].specialists == frozenset()
    assert BINDINGS[name].budget is None


def test_the_responder_is_bound_to_ranking_and_phrasing_the_catalogue_with_no_tools() -> None:
    """Q-H2: it asks for nothing, answers a ranking of catalogue ids with a sentence each, and
    code keeps it off until the owners and wording are reviewed."""
    assert BINDINGS["responder"] == Binding(
        kind=Kind.RESPONDER,
        task="respond.rank",
        output="ranking@1",
        triggers=frozenset({Trigger.CASE_ADVICE}),
        tools=frozenset(),
        tier=Tier.SMALL,
    )
    assert ENABLED["responder"] is None


def test_the_reporter_is_bound_to_saying_the_figures_in_one_paragraph_with_no_tools() -> None:
    """Q-H3: it asks for nothing, answers one paragraph that argus.reporter.prose checks number
    by number, and code keeps it off until the user has read two reports."""
    assert BINDINGS["reporter"] == Binding(
        kind=Kind.REPORTER,
        task="report.prose",
        output="prose@1",
        triggers=frozenset({Trigger.REPORT_DUE}),
        tools=frozenset(),
        tier=Tier.SMALL,
    )
    assert ENABLED["reporter"] is None


def test_names_fit_what_reads_them() -> None:
    assert set(BINDINGS) == {COORDINATOR, *SPECIALISTS, "responder", "reporter"}
    for name in BINDINGS:
        assert re.fullmatch(r"[a-z]+", name)
    for name in BINDINGS[COORDINATOR].specialists:
        assert BINDINGS[name].kind is Kind.SPECIALIST
        assert len(name) <= 10  # agent.parse keeps a consult's first 10 characters
    for binding in BINDINGS.values():
        assert binding.tools <= set(catalogue.TOOLS)
        assert (binding.budget is None) == (binding.kind is not Kind.COORDINATOR)


def test_the_enums_and_tiers() -> None:
    assert [k.value for k in Kind] == ["coordinator", "specialist", "responder", "reporter"]
    assert [t.value for t in Trigger] == [
        "engine_no_decision", "person_request", "coordinator_consult", "case_advice", "report_due",
    ]  # fmt: skip
    assert TIERS == (Tier.SMALL, Tier.MEDIUM, Tier.LARGE)


def test_limits_are_part_of_every_gold_run_id() -> None:
    """``asdict(Limits())`` is in the evaluation signature: a field added, renamed or retyped
    changes every gold run id, so GOLD_RUNS must change with it (after a gold run)."""
    assert [(f.name, f.type) for f in dataclasses.fields(Limits)] == [
        ("rounds", "int"), ("tools", "int"), ("calls", "int"), ("consults", "int"),
        ("seconds", "float"),
    ]  # fmt: skip
    assert dataclasses.asdict(Limits()) == {"rounds": 4, "tools": 12, "calls": 8, "consults": 2,
                                            "seconds": 240.0}  # fmt: skip
    with pytest.raises(dataclasses.FrozenInstanceError):
        Limits().rounds = 5  # type: ignore[misc]


def test_every_bound_agent_has_pins_and_one_enabled_pinned_version_or_is_off() -> None:
    assert set(PINS) == set(BINDINGS) == set(ENABLED)
    for name, versions in PINS.items():
        assert versions
        for version, pin in versions.items():
            assert re.fullmatch(rf"{BINDINGS[name].kind}@[1-9][0-9]*", version)
            assert re.fullmatch(r"[0-9a-f]{64}", pin.file_sha256)
            assert re.fullmatch(r"[0-9a-f]{64}", pin.prompt_sha256)
        assert ENABLED[name] is None or ENABLED[name] in versions


def test_each_pin_names_the_tag_that_approves_it() -> None:
    """Doctor compares the files with the nearest of these tags (``argus.agent.drift``): a
    new version's pin names its own component's approval tag, which the lead creates when
    approving it, never an existing one."""
    tags = {pin.approved for versions in PINS.values() for pin in versions.values()}
    # Q-H1's files, Q-H2's responder, Q-H3's reporter, AR3's outside tools (D-165) and the
    # site's words in every file (D-338)
    assert tags == {
        "q-h1-approved", "q-h2-approved", "q-h3-approved", "ar3-approved", "site-words-approved",
    }  # fmt: skip
    for tag in tags:
        assert drift.TAG.fullmatch(tag)
        assert re.fullmatch(r"(?:q-[a-z][0-9]+|ar[0-9]+|site-words)-approved", tag)
    assert drift.approvals() == tags


def test_the_enabled_versions_are_the_approved_ones() -> None:
    """Switching an agent to another version is a decision, never a file's: a verdict agent
    (a coordinator) needs plan §7.6's paired comparison on >= 30 gold items with a closable
    gap (McNemar alpha 0.05, no loss of true-positive recall, 0 true positives proposed
    benign) and a DECISIONS entry; then this test changes with it, naming the entry."""
    assert dict(ENABLED) == {
        # D-165: coordinator@3 (D-095, P6) + the outside tools; D-338: the same instructions
        # with the site's words, which on the gold items' site read as coordinator@4 did
        "investigator": "coordinator@5",
        "web": "specialist@2",
        "proxy": "specialist@2",
        "intel": "specialist@3",  # D-165: the same two tools; D-338
        "responder": None,  # Q-H2: off until the user reviews the owners and the wording
        "reporter": None,  # Q-H3: off until the user has read two reports and asks for prose
    }
    assert dict(GOLD_RUNS) == {"no_tools": "8962e42b9863", "tools": "bf01507f7984"}


def test_the_tables_are_read_only() -> None:
    pin = Pin("a" * 64, "b" * 64, "x")
    with pytest.raises(TypeError):
        BINDINGS["dns"] = BINDINGS["web"]  # type: ignore[index]
    with pytest.raises(TypeError):
        PINS["investigator"]["coordinator@5"] = pin  # type: ignore[index]
    with pytest.raises(TypeError):
        PINS["dns"] = {}  # type: ignore[index]
    with pytest.raises(TypeError):
        ENABLED["investigator"] = "coordinator@4"  # type: ignore[index]
    with pytest.raises(TypeError):
        GOLD_RUNS["tools"] = "x"  # type: ignore[index]
    with pytest.raises(dataclasses.FrozenInstanceError):
        pin.approved = "y"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        BINDINGS["web"].tier = Tier.LARGE  # type: ignore[misc]
