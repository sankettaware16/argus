"""ARGUS's prompts and how answers are read (P5)."""

from __future__ import annotations

import dataclasses
import hashlib
import json

import pytest

from argus.llm import egress, prompts
from argus.llm.detect import OwnSpace
from argus.llm.privacy import template_words


def test_the_prompt_passes_the_validator_and_asks_for_json(ours: OwnSpace) -> None:
    for text in prompts.PROMPTS.values():
        assert egress.check(text, ours, ordinary=template_words()).allowed
        assert "JSON" in text
        for outcome in prompts.OUTCOMES:
            assert outcome in text


def answer(**over: object) -> str:
    data = {"outcome": "true_positive", "confidence": 0.8, "reason": "beacon", "missing": []}
    data.update(over)
    return json.dumps(data)


def test_a_good_answer() -> None:
    got = prompts.parse(answer(missing=["dns logs"]))
    assert got == prompts.Assessment("true_positive", 0.8, "beacon", ("dns logs",))
    assert not got.asks_withheld
    assert prompts.parse("  " + answer(outcome=" Benign_Expected ") + "\n").outcome == (
        "benign_expected"
    )


def test_a_wrapped_answer_is_read() -> None:
    assert prompts.parse("Here:\n```json\n" + answer() + "\n```").outcome == "true_positive"
    assert prompts.parse("Here: {not json}").outcome is None


@pytest.mark.parametrize(
    "text",
    ["", "no", "[1, 2]", '"x"', answer(outcome="malicious"), answer(outcome=3),
     answer(outcome=None)],
)  # fmt: skip
def test_an_unusable_answer(text: str) -> None:
    assert prompts.parse(text).outcome is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [(0, 0.0), (1, 1.0), (0.5, 0.5), (1.01, None), (-0.1, None), (True, None), ("0.5", None)],
)
def test_confidence_only_between_0_and_1(value: object, expected: float | None) -> None:
    assert prompts.parse(answer(confidence=value)).confidence == expected


def test_reason_and_missing_are_capped_and_typed() -> None:
    got = prompts.parse(answer(reason="x" * 5000, missing=["y" * 900] * 30))
    assert len(got.reason) == 2000
    assert len(got.missing) == 20
    assert all(len(m) == 500 for m in got.missing)
    assert prompts.parse(answer(reason=5, missing="dns")).reason == ""
    assert prompts.parse(answer(missing="dns")).missing == ()
    assert prompts.parse(answer(missing=[1])).missing == ("1",)


@pytest.mark.parametrize(
    "missing",
    ["the real IP address", "actual hostname of I1.HOST_1", "unmask the user",
     "de-anonymized logs", "the original value", "true identity"],
)  # fmt: skip
def test_asking_for_what_was_withheld(missing: str) -> None:
    assert prompts.parse(answer(missing=[missing])).asks_withheld
    assert prompts.parse(answer(reason=f"need {missing}")).asks_withheld


def test_ordinary_requests_are_not_asking_for_withheld_data() -> None:
    for missing in ("dns logs for the hour", "firewall answers", "the asset's owner"):
        assert not prompts.parse(answer(missing=[missing])).asks_withheld


def test_a_prompt_version_names_one_text() -> None:
    # a changed text is a new version (a new name): recorded answers stay tied to their text
    digests = {name: hashlib.sha256(text.encode()).hexdigest()
               for name, text in prompts.PROMPTS.items()}  # fmt: skip
    assert digests == {
        "assess@1": "1bded78bc1252a1c309d4eb7d7e2fed39b51a571b65649b541d52d86502166cb"
    }
    assert prompts.ASSESS_V1 == "assess@1"


def test_an_assessment_is_immutable_and_an_unusable_one_is_empty() -> None:
    got = prompts.parse("no")
    assert got == prompts.Assessment(None, None, "", ())
    with pytest.raises(dataclasses.FrozenInstanceError):
        got.reason = "x"  # type: ignore[misc]
