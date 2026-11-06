"""P4-F Track 2A: the decision bar of a possible incident and the plain words of the pages, as
pure functions. The bar is the case machine's own answer: whatever the case and the account, a
part is offered exactly when the command it sends would be accepted, and never on a case that is
not suspected. The plain words of a measure keep its order (more bytes never read smaller, a more
regular rhythm never scores lower) and never reach what a model is sent."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import get_args

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.cases.machine import CaseRefused, Confirm, Dismiss, decide
from argus.cases.model import DISMISS_REASONS, STATES, Case
from argus.context import display
from argus.web import auth, casepages
from argus.web.capabilities import Capability
from argus.web.v1 import case_models

pytestmark = pytest.mark.unit
NOW = datetime(2026, 11, 6, 9, 0, tzinfo=UTC)
CAPABILITIES = st.frozensets(st.sampled_from(list(Capability)))


def case_in(state: str, opened: bool) -> Case:
    return Case(
        id=uuid.UUID(int=7), number=7, title="t", state=state, severity="high",  # type: ignore[arg-type]
        version=3, cause="raised", opened_at=NOW if opened else None,
        closed_at=NOW if state == "closed" else None,
        closure_reason="benign_expected" if state == "closed" else None,
    )  # fmt: skip


def person(capabilities: frozenset[Capability]) -> auth.Reviewer:
    return auth.Reviewer(user_id=5, username="p", display_name="P", csrf_token="t",
                         previous_seen_at=None, capabilities=capabilities)  # fmt: skip


def accepted(case: Case, command: object, me: auth.Reviewer) -> bool:
    try:
        decide(case, command, casepages.actor_of(me), NOW)  # type: ignore[arg-type]
    except CaseRefused:
        return False
    return True


def test_the_contract_names_the_reasons_a_dismissal_takes() -> None:
    assert set(get_args(case_models.DismissReason)) == DISMISS_REASONS
    bar = [reason for reason, _, _ in casepages.DISMISS_CHOICES]
    assert bar == ["benign_expected", "attempt_no_impact", "benign_policy",
                   "rule_false_positive", "duplicate"]  # fmt: skip
    assert set(bar) <= DISMISS_REASONS
    assert "attempt_no_impact" in DISMISS_REASONS  # "a scan or attempt: nothing happened"


@given(
    state=st.sampled_from(STATES),
    opened=st.booleans(),
    capabilities=CAPABILITIES,
    others=st.integers(0, 3),
    posted=st.none() | st.just("ACME-IR-2026-1106-02"),
)
def test_the_bar_is_the_machines_answer(
    state: str, opened: bool, capabilities: frozenset[Capability], others: int, posted: str | None
) -> None:
    case = case_in(state, opened and state != "suspected")
    me = person(capabilities)
    bar = casepages.decision_bar(case, me, others, NOW, posted)
    if state != "suspected":
        assert bar is None
        return
    assert bar is not None
    manage = Capability.MANAGE_CASES in capabilities
    assert bar.confirm.enabled == (manage and accepted(case, Confirm(), me))
    dismiss = Dismiss("benign_expected", posted=posted)
    assert bar.dismiss.enabled == (manage and accepted(case, dismiss, me))
    # a dismissal needs both: the route's capability and the machine's (review); and a case the
    # case team posted to Kibana is never dismissed (its Kibana case would stay open)
    assert bar.dismiss.enabled == (manage and Capability.REVIEW in capabilities and posted is None)
    if manage and Capability.REVIEW in capabilities and posted is not None:
        assert bar.dismiss.why_not is not None
        assert posted in bar.dismiss.why_not
    assert bar.merge.enabled == (manage and others > 0)
    for part in (bar.confirm, bar.dismiss, bar.merge):
        assert (part.why_not is None) == part.enabled
        assert part.why_not is None or "argus case" not in part.why_not
    assert [r.reason for r in bar.reasons] == [r for r, _, _ in casepages.DISMISS_CHOICES]
    assert all("{" not in r.meaning for r in bar.reasons)


UNITS = {"byte": 0, "bytes": 0, "KB": 1, "MB": 2, "GB": 3, "TB": 4}


@given(st.floats(min_value=0, max_value=2**60), st.floats(min_value=0, max_value=2**60))
def test_more_bytes_never_read_as_a_smaller_unit(a: float, b: float) -> None:
    small, large = sorted((a, b))
    said = display.size(large)
    assert UNITS[display.size(small).rsplit(" ", 1)[1]] <= UNITS[said.rsplit(" ", 1)[1]]
    assert "e+" not in said
    assert len(said) <= 16


def test_bytes_read_as_people_say_them() -> None:
    assert display.size(66803186.0) == "64 MB"
    assert display.size(0) == "0 bytes"
    assert display.size(1) == "1 byte"
    assert display.size(1023) == "1,023 bytes"
    assert display.size(1024) == "1.0 KB"
    assert display.size(5 * 1024**3) == "5.0 GB"


@given(st.floats(min_value=0, max_value=50), st.floats(min_value=0, max_value=50))
def test_a_steadier_rhythm_never_scores_lower(a: float, b: float) -> None:
    steady, loose = sorted((a, b))
    assert 0 <= display.regular_score(loose) <= display.regular_score(steady) <= 100
    for beacon in (True, False):
        words = display.timing(steady, beacon=beacon)
        assert words.endswith(f"({display.regular_score(steady)}/100)")
        assert ("beacon" in words) == (beacon and steady < display.BEACON)


def test_the_pages_say_timing_in_words_and_a_model_gets_its_old_sentence() -> None:
    signal = {"name": "proxy.regularity", "status": "known", "value": 0.02}
    assert display.sentence(signal, plain=True) == "Timing: very regular, like a beacon (98/100)"
    assert display.sentence(signal) == "Traffic regularity: 0.02 (0 = perfectly regular)"
    sized = {"name": "proxy.bytes", "status": "known", "value": 66803186.0}
    assert display.sentence(sized, plain=True) == "Received through the proxy: 64 MB"
    assert display.sentence(sized) == "Bytes received: 66803186.0 bytes received through the proxy"
    # a value a model's cleaning made text is shown as it is, under the old label
    cleaned = {"name": "proxy.bytes", "status": "known", "value": "~67,000,000"}
    assert display.sentence(cleaned, plain=True) == display.sentence(cleaned)
    for odd in (True, None, float("nan"), -5):
        weird = {"name": "proxy.bytes", "status": "known", "value": odd}
        assert "MB" not in display.sentence(weird, plain=True)


def test_every_plain_entry_is_complete() -> None:
    entries = display.registry()
    plain = {name: e for name, e in entries.items() if e.plain or e.plain_label}
    assert set(plain) == {"alerts.cadence_cv", "proxy.bytes", "proxy.regularity"}
    assert all(e.plain and e.plain_label for e in plain.values())
