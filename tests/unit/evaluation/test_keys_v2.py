"""Evaluation keys carry the provider and the model (Q-G1): another model is asked again, the
same one is read from the cache; the agent's limits follow the provider's timeout."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus.agent.agent import DEFAULT_LIMITS, Limits, limits_for
from argus.evaluation import agent_eval, comparison
from argus.llm.privacy import Privacy
from argus.llm.providers import Tier
from tests.unit.evaluation.test_agent_eval import CASES as AGENT_CASES
from tests.unit.evaluation.test_agent_eval import Engine, FakeAgent
from tests.unit.evaluation.test_comparison import CASES, Model

pytestmark = pytest.mark.unit


async def test_a_comparison_asks_again_for_another_model(privacy: Privacy, tmp_path: Path) -> None:
    path = tmp_path / "answers.json"
    first = await comparison.run(CASES, privacy, Model(), path, ("A-fake",),
                                 model="openai/gpt-5.4-nano")  # fmt: skip
    assert first.calls == 2
    same = await comparison.run(CASES, privacy, Model(), path, ("A-fake",),
                                model="openai/gpt-5.4-nano")  # fmt: skip
    assert same.calls == 0
    other = await comparison.run(CASES, privacy, Model(), path, ("A-fake",),
                                 model="local/cyber-prime-1.2")  # fmt: skip
    assert other.calls == 2


def test_the_comparison_key_names_the_model() -> None:
    case = CASES[0]
    key = comparison._key("B", case, "text", "assess@1", Tier.SMALL, "local/cp")
    assert key.split("|")[:5] == ["B", str(case.investigation_id), "assess@1", "small", "local/cp"]
    bare = comparison._key("B", case, "text", "assess@1", Tier.SMALL)
    assert bare.count("|") == 4  # the Phase 2 form, without a pinned model


async def test_agent_verdicts_are_keyed_by_the_models(tmp_path: Path) -> None:
    out = tmp_path / "v.json"
    await agent_eval.evaluate(Engine(), AGENT_CASES[:1], FakeAgent(["true_positive"]), out,  # type: ignore[arg-type]
                              False, models="openai/small=gpt-5.4-nano")  # fmt: skip
    again = FakeAgent(["true_positive"])
    await agent_eval.evaluate(Engine(), AGENT_CASES[:1], again, out, False,  # type: ignore[arg-type]
                              models="openai/small=gpt-5.4-nano")  # fmt: skip
    assert again.seen == []  # from the cache
    other = FakeAgent(["benign_expected"])
    found, _ = await agent_eval.evaluate(Engine(), AGENT_CASES[:1], other, out, False,  # type: ignore[arg-type]
                                         models="local/small=cyber-prime-1.2")  # fmt: skip
    assert other.seen == [AGENT_CASES[0].investigation_id]
    assert found[str(AGENT_CASES[0].investigation_id)]["outcome"] == "benign_expected"
    a = FakeAgent([])
    assert agent_eval.signature(a, False) == agent_eval.signature(a, False, "")
    assert agent_eval.signature(a, False, "x") != agent_eval.signature(a, False, "y")


def test_the_agents_wall_clock_follows_the_provider() -> None:
    assert limits_for(60.0) == DEFAULT_LIMITS
    assert limits_for(80.0).seconds == 240.0
    assert limits_for(600.0) == Limits(seconds=1800.0)
    assert limits_for(600.0, Limits(calls=3)).calls == 3
