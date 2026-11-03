"""Q-B3 review findings that need no database (R3-8, R3-9): each test carries its finding number.

The first two are the reviewer's repros (they failed on the reviewed tree); the rest are the
fixer's."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest

from argus.cases.model import NO_QUIET_WINDOW
from argus.web import casepages
from argus.web.capabilities import Capability
from tests.unit.web.test_casepages import a_case, reviewer

pytestmark = pytest.mark.unit
ROOT = Path(__file__).resolve().parents[3]


def test_r3_8_the_contract_does_not_promise_text_the_server_refuses() -> None:
    """A note, an attestation, a reopen reason and a closure note are `minLength 1, no NUL` in the
    OpenAPI; the server strips them and answers 422 to words that are only spaces. So Schemathesis's
    schema-valid data meets 422 on these (decision 18 exempts three other operations for the same
    reason): the pattern must exclude them, or the operations be exempt."""
    spec = json.loads((ROOT / "docs" / "api" / "openapi-v1.json").read_text())
    schemas = spec["components"]["schemas"]
    for name, field in (
        ("NoteCreateIn", "body"),
        ("ContainIn", "attestation"),
        ("ReopenIn", "reason"),
    ):
        prop = schemas[name]["properties"][field]
        pattern = prop.get("pattern")
        assert pattern is not None
        assert re.search(pattern, " \n ") is None, f"{name}.{field} accepts a text of only spaces"


def test_r3_9_a_refusal_a_person_reads_has_no_component_codes_or_identifiers() -> None:
    now = datetime(2026, 10, 26, 6, 0, tzinfo=UTC)
    me = reviewer(Capability.VIEW, Capability.REVIEW, Capability.MANAGE_CASES, Capability.REOPEN)
    case = a_case("open")
    choices = casepages.closure_choices(case, me, NO_QUIET_WINDOW, now)
    actions = casepages.case_actions(case, me, NO_QUIET_WINDOW, choices, 1, now)
    words = [c.why_not for c in choices if c.why_not] + [a.why_not for a in actions if a.why_not]
    assert words
    for said in words:
        assert re.search(r"\(Q-[A-Z]\d\)", said) is None, said  # a build component's code
        assert re.search(r"\b[A-Za-z]+_[a-z_]+\b", said) is None, said  # a stored identifier


# -------------------------------------------------------- R3-8, more: what the contract says
def test_r3_8_the_pattern_is_exactly_what_the_server_calls_blank() -> None:
    """The class of characters the pattern refuses to stand alone is the code points Python's
    ``str.strip()`` removes (that is how the server judges a text blank)."""
    from argus.web.v1.models import WORDS

    for number in range(0x110000):
        c = chr(number)
        if number == 0 or 0xD800 <= number <= 0xDFFF:
            continue
        assert (re.search(WORDS, c) is None) == c.isspace(), hex(number)
    assert re.search(WORDS, "\n\nhello " + chr(0xA0)) is not None
    assert re.search(WORDS, " \t\x1f" + chr(0x3000) + chr(0x2028)) is None
    assert re.search(WORDS, "a\x00") is None  # no NUL anywhere


def test_r3_8_every_field_a_person_must_fill_with_words_refuses_blank_text() -> None:
    from pydantic import ValidationError

    from argus.web.v1 import case_models as m

    for model, field, extra in (
        (m.NoteCreateIn, "body", {}),
        (m.EntityNoteIn, "body", {"kind": "ip", "value": "10.0.0.1"}),
        (m.ContainIn, "attestation", {"expected_version": 1}),
        (m.ReopenIn, "reason", {"expected_version": 1}),
    ):
        for blank in (" ", "\n \t", chr(0x3000), "\x1f"):
            with pytest.raises(ValidationError):
                model(**{**extra, field: blank})
        assert model(**{**extra, field: " a "})


def test_r3_8_the_schemathesis_run_allows_a_server_error_only_where_the_contract_names_one() -> (
    None
):
    source = (ROOT / "tests" / "integration" / "web" / "test_v1_external.py").read_text()
    config = source[source.index('CONFIG = """') : source.index("async def test_schemathesis")]
    before_operations = config.split("[[operations]]")[0]
    assert "not_a_server_error" not in before_operations  # no 503 for every operation
    allowed = re.findall(
        r'include-name = "([^"]+)"\n\n\[operations\.checks\.not_a_server_error\]\n'
        r"expected-statuses = \[([^\]]*)\]",
        config,
    )
    assert sorted(name for name, statuses in allowed if '"503"' in statuses) == [
        "POST /api/v1/approvals/group",
        "POST /api/v1/approvals/{request_id}/decision",
        "POST /api/v1/investigations/{investigation_id}/assess",
    ]
    for operation in ("assign", "notes"):  # the 422s of an unknown person and of too many notes
        assert f"POST /api/v1/cases/{{case_id}}/{operation}" in config
    assert "POST /api/v1/entity-notes" in config


# -------------------------------------------------------- R3-9, more: words, no codes
def test_r3_9_a_reason_that_needs_a_quiet_window_says_so_in_words() -> None:
    now = datetime(2026, 10, 26, 6, 0, tzinfo=UTC)
    me = reviewer(Capability.VIEW, Capability.REVIEW, Capability.MANAGE_CASES, Capability.REOPEN)
    case = a_case("open")
    choices = {c.reason: c for c in casepages.closure_choices(case, me, NO_QUIET_WINDOW, now)}
    for reason, label in (("remediated_verified", "Fixed, and shown quiet"),
                          ("attempt_no_impact", "An attempt that did not work")):  # fmt: skip
        said = choices[reason].why_not
        assert said is not None
        assert said.startswith(
            f"“{label}” needs ARGUS to have shown the case quiet for 72 hours"
        ), said
        assert said.endswith("so nothing can be shown quiet."), said
    actions = {
        a.action: a
        for a in casepages.case_actions(case, me, NO_QUIET_WINDOW, list(choices.values()), 1, now)
    }
    contain = actions["contain"].why_not
    assert contain is not None
    assert contain.startswith(
        "ARGUS has not shown the case quiet for 72 hours, so it cannot be confirmed contained yet:"
    )


def test_r3_9_the_watchs_own_reasons_lose_only_the_component_codes() -> None:
    from argus.cases import watch

    assert "Q-F1" not in casepages.window_words(watch.NOT_ON)
    assert casepages.window_words("ARGUS's own alerts show activity today") == (
        "ARGUS's own alerts show activity today"
    )
    assert casepages.window_words("x (Q-C2) y") == "x y"
    assert casepages.window_words(NO_QUIET_WINDOW.reason) == (
        "the still-active watch is not running here, so nothing can be shown quiet"
    )
