"""A person's ``Verdict:`` comment (AR8): what counts as one, in the forms a person writes it."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.caseteam import verdicts

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "text",
    [
        "Verdict: true positive",
        "verdict: True Positive",
        "  VERDICT:   true   positive  ",
        "**Verdict:** true positive",
        "__Verdict:__ true positive",
        "Verdict: true-positive",
        "Verdict: true_positive",
        "Verdict: true positive\n\nChecked with the owner.",
        "Verdict: true positive.",
    ],
)
def test_a_true_positive_in_the_forms_people_write_it(text: str) -> None:
    assert verdicts.parse(text) == verdicts.Parsed("true_positive", None)


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        (
            "Verdict: false positive: it is the department's backup tool",
            "it is the department's backup tool",
        ),
        ("verdict: False Positive:   backup   tool  ", "backup tool"),
        ("**Verdict:** false positive: vendor confirmed", "vendor confirmed"),
        ("Verdict: false positive: line one\nline two", "line one line two"),
        ("Verdict: false-positive: scanner", "scanner"),
    ],
)
def test_a_false_positive_carries_its_reason(text: str, reason: str) -> None:
    assert verdicts.parse(text) == verdicts.Parsed("rule_false_positive", reason)


@pytest.mark.parametrize(
    "text", ["Verdict: false positive", "Verdict: false positive:", "Verdict: false positive: ab"]
)
def test_a_false_positive_without_a_reason_has_none(text: str) -> None:
    assert verdicts.parse(text) == verdicts.Parsed("rule_false_positive", None)


@pytest.mark.parametrize(
    "text",
    [
        "",
        "true positive",
        "I think the verdict: true positive",  # not at the start
        "Verdict true positive",
        "Verdict: probably a true positive",
        "Verdict: benign",
        "verdicts: true positive",
        "Verdict: true positives are rare",  # a word boundary, not the start of one
        "> Verdict: true positive",
        "ARGUS's verdict: true positive (0.8).",
    ],
)
def test_what_is_not_a_verdict_comment(text: str) -> None:
    assert verdicts.parse(text) is None


def test_the_reason_is_cleaned_and_cut() -> None:
    found = verdicts.parse("Verdict: false positive: " + "x‮y " * 3000)
    assert found is not None
    assert found.reason is not None
    assert "‮" not in found.reason
    assert len(found.reason) <= 4000


@given(st.text(max_size=300))
def test_parse_never_raises_and_a_true_positive_never_carries_a_reason(text: str) -> None:
    found = verdicts.parse(text)
    if found is not None and found.outcome == "true_positive":
        assert found.reason is None


@given(
    st.sampled_from(["", " ", "  ", "\t"]),
    st.sampled_from(["", "**", "__"]),
    st.sampled_from(["true", "TRUE", "True"]),
    st.sampled_from([" ", "-", "_", "  "]),
)
def test_spacing_and_bold_do_not_change_a_true_positive(
    lead: str, bold: str, word: str, joiner: str
) -> None:
    text = f"{lead}{bold}Verdict:{bold} {word}{joiner}positive"
    assert verdicts.parse(text) == verdicts.Parsed("true_positive", None)
