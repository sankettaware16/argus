"""The agents' answer shapes (Q-G1's json_schema, strict, D-112) after Q-H1 moved the prompts
into config/agents/: each shape is bound to an agent's output, a coordinator's names the
specialists its file names, and agent@1's are exactly the ones Q-G1 sent."""

from __future__ import annotations

from dataclasses import replace

import pytest

from argus.agent import loader, schemas
from argus.agent.registry import BINDINGS
from argus.llm.prompts import OUTCOMES, strict_object, strings

AGENTS = loader.load()


def q_g1_coordinator() -> dict[str, object]:
    """Q-G1's COORDINATOR_SCHEMA as it was written in prompts.py (df6de7f..e96378d)."""
    ask = {"type": "array", "maxItems": 6,
           "items": strict_object(tool={"type": "string"}, entity={"type": "string"})}  # fmt: skip
    return strict_object(
        outcome={"type": "string", "enum": list(OUTCOMES)},
        confidence={"type": "number"},
        reason={"type": "string"},
        hypotheses={"type": "array", "maxItems": 4,
                    "items": strict_object(name={"type": "string"},
                                           **{"for": strings(4), "against": strings(4)})},
        cites=strings(12),
        consult={"type": "array", "maxItems": 3,
                 "items": {"type": "string", "enum": ["web", "proxy", "intel"]}},
        ask=ask,
    )  # fmt: skip


def test_agent_1s_shapes_are_q_g1s() -> None:
    assert schemas.of(AGENTS.coordinator) == q_g1_coordinator() == schemas.COORDINATOR_SCHEMA
    ask = q_g1_coordinator()["properties"]["ask"]  # type: ignore[index]
    notes = strict_object(notes={"type": "string"}, cites=strings(12), ask=ask)
    for name in ("web", "proxy", "intel"):
        assert schemas.of(AGENTS.by_name[name]) == notes == schemas.SPECIALIST_SCHEMA


def test_every_bound_output_has_a_shape() -> None:
    assert {b.output for b in BINDINGS.values()} <= set(schemas.SHAPES)
    for definition in AGENTS.by_name.values():
        assert schemas.of(definition)["additionalProperties"] is False


def test_a_coordinator_consults_only_the_specialists_its_file_names() -> None:
    narrowed = replace(AGENTS.coordinator, specialists=("proxy", "web"))
    consult = schemas.of(narrowed)["properties"]["consult"]
    assert consult["items"]["enum"] == ["proxy", "web"]
    alone = schemas.of(replace(AGENTS.coordinator, specialists=()))["properties"]["consult"]
    assert alone == {"type": "array", "maxItems": 0, "items": {"type": "string"}}


def test_an_output_without_a_shape_is_refused() -> None:
    other = replace(AGENTS.by_name["web"], output="report@1")
    with pytest.raises(ValueError, match=r"^web: no answer shape for the output 'report@1'$"):
        schemas.of(other)


def test_a_shape_is_a_copy() -> None:
    got = schemas.of(AGENTS.by_name["web"])
    got["x"] = 1
    assert "x" not in schemas.of(AGENTS.by_name["web"])
    assert "x" not in schemas.NOTES
