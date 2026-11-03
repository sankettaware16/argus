"""Q-A1: the ``/api/v1`` views read years of stored JSON (dossiers, the investigator's runs,
tuning reports): whatever shape a stored value has, they answer a valid model, never a 500."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.agent import reading as readings
from argus.web import assessed
from argus.web.v1 import models as m
from argus.web.v1 import routes as v1_routes
from argus.web.v1 import views

pytestmark = pytest.mark.unit
T = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)
SCALARS = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(-(2**70), 2**70),
    st.floats(allow_nan=True, allow_infinity=True),
    st.text(max_size=20),
)
JSON = st.recursive(SCALARS, lambda inner: st.one_of(
    st.lists(inner, max_size=4), st.dictionaries(st.text(max_size=12), inner, max_size=4)),
    max_leaves=25)  # fmt: skip
KEYS = st.sampled_from(["report", "steps", "summary", "shown", "fields", "context", "pack",
                        "ips", "web", "decoded_paths", "related", "investigation_id", "status",
                        "top", "distinct", "from", "number", "text", "sentence", "has_note",
                        "complete", "alerts_read", "class", "asset", "shared", "answer",
                        "hypotheses", "for", "against", "cites", "checks", "specialists",
                        "rounds", "calls", "models", "cost_usd", "seconds", "labels",
                        "suggestions", "evidence", "dropped", "outcome", "confidence", "reading",
                        "kind", "checked", "blocked", "explanation"])  # fmt: skip
# JSON whose keys are mostly the ones the views read, so they meet every odd type
SHAPED = st.recursive(
    SCALARS,
    lambda inner: st.one_of(st.lists(inner, max_size=4), st.dictionaries(KEYS, inner, max_size=6)),
    max_leaves=40,
)


@given(SHAPED, SHAPED, SHAPED, SHAPED, SHAPED)
def test_a_dossier_of_any_shape_gives_a_valid_view(
    body: Any, report: Any, fields: Any, ips: Any, related: Any
) -> None:
    found = {"version": 1, "pack": "generic@12", "status": "evidence_ready",
             "partial_reason": None, "created_at": T, "body": body, "report": report,
             "fields": fields, "ips": ips, "related": related, "sentences": related}  # fmt: skip
    got = views.dossier(found)
    assert got is not None
    m.DossierOut.model_validate(got.model_dump())  # it serializes and validates again


@given(SHAPED)
def test_a_run_of_any_shape_gives_a_valid_view(report: Any) -> None:
    got = views.run(report)
    if not isinstance(report, dict):
        assert got is None
    else:
        assert got is not None
        m.RunOut.model_validate(got.model_dump())


@given(SHAPED)
def test_a_reading_of_any_stored_shape_gives_a_valid_view(report: Any) -> None:
    for hidden in (False, True):
        got = views.reading(readings.of(report), hide_logs=hidden)
        if got is not None:
            m.ReadingOut.model_validate(got.model_dump())


def stored(**reading: Any) -> dict[str, Any]:
    return {
        "answer": {"outcome": "benign_expected", "confidence": 0.8, "explanation": "campus scan",
                   "cites": ["severity high", "made up"]},
        "reading": {"kind": "floor", "checked": [True, False],
                    "blocked": ["severity high", "regular like a beacon"], **reading},
    }  # fmt: skip


def test_a_reading_is_shown_in_plain_words_and_hidden_without_log_access() -> None:
    got = views.reading(readings.of(stored()))
    assert got is not None
    assert got.kind == "floor"
    assert got.outcome == "benign_expected"
    assert got.confidence == 0.8
    assert got.headline == (
        "ARGUS's reading: benign, expected activity (80%) \u2014 not proposed because a safety"
        " check needs a person: the severity is high; it repeats regularly, like a beacon"
    )
    assert got.reason == "campus scan"
    assert [(f.text, f.checked) for f in got.facts] == [("severity high", True),
                                                        ("made up", False)]  # fmt: skip
    hidden = views.reading(readings.of(stored()), hide_logs=True)
    assert hidden is not None
    assert hidden.reason == "Hidden: needs log access in ELK."
    assert hidden.facts == []  # not even how many quotes there were, or which were found
    assert "beacon" not in hidden.why  # what the logs said stays hidden
    assert hidden.why.endswith("the severity is high; what the logs say is hidden (it needs log"
                               " access in ELK)")  # fmt: skip
    assert views.reading(None) is None


def test_an_assessment_carries_its_reading_only_when_it_has_one() -> None:
    def detail(report: Any, status: str = "no_decision") -> assessed.Detail:
        return assessed.Detail(1, "agent@1", "the AI investigator", status, None, None, "-",
                               ("r",), report, T, None, readings.of(report))  # fmt: skip

    shown = views.assessment(detail(stored()))
    assert shown is not None
    assert shown.reading is not None
    assert (shown.status, shown.outcome, shown.confidence) == ("no_decision", None, None)
    bare = views.assessment(detail({"answer": {"outcome": "true_positive"}}))
    assert bare is not None
    assert bare.reading is None
    nothing = views.assessment(detail(None))
    assert nothing is not None
    assert nothing.reading is None


@given(SHAPED, SHAPED, SHAPED, JSON)
def test_a_tuning_report_of_any_shape_gives_a_valid_view(
    report: Any, suggestions: Any, dropped: Any, cost: Any
) -> None:
    row = {"rule": "r", "week_end": T, "report": report, "suggestions": suggestions,
           "dropped": dropped, "model": cost, "cost_usd": cost, "created_at": T}  # fmt: skip
    (got,) = views.tuning([row])
    m.TuningReportOut.model_validate(got.model_dump())


@given(st.lists(SHAPED, max_size=4))
def test_alert_rows_of_any_shape_give_a_valid_view(entities: list[Any]) -> None:
    row = {"alert_id": "a", "detected_at": T, "event_time": None, "status": "normalized",
           "workflow_status": None, "duplicate_of": None, "late_arrival": False,
           "severity": entities[0] if entities else None, "entities": entities,
           "cols": {"x": entities}}  # fmt: skip
    got = views.alerts([row], 1, ["x"])
    m.AlertsOut.model_validate(got.model_dump())


def test_assessments_and_verdicts_with_unknown_states_are_left_out() -> None:
    detail = assessed.Detail(1, "agent@1", "the AI investigator", "exploded", None, None, "-",
                             (), None, T, None)  # fmt: skip
    assert views.assessment(detail) is None
    assert views.ai_verdict({"status": "exploded"}) is None
    assert views.ai_verdict(None) is None
    ok = views.ai_verdict({"status": "proposed", "outcome": "guilty", "confidence": "high",
                           "assessor": "engine@1", "source": "the decision engine"})  # fmt: skip
    assert ok is not None
    assert (ok.outcome, ok.confidence) == (None, None)


def test_numbers_that_json_cannot_hold_are_left_out() -> None:
    run = views.run({"cost_usd": float("nan"), "seconds": float("inf"), "rounds": True,
                     "calls": 2.9, "models": ["m", 3, None, {"x": 1}]})  # fmt: skip
    assert run is not None
    assert (run.cost_usd, run.seconds, run.rounds, run.calls) == (None, None, None, 2)
    assert run.models == ["m", "3"]


def test_the_investigator_name_matches_the_agent() -> None:
    from argus.agent.agent import NAME

    assert v1_routes.AGENT == NAME


def test_related_entries_without_a_valid_id_are_dropped() -> None:
    inv = uuid.uuid4()
    got = views.dossier({"version": 1, "pack": "p", "status": "s", "partial_reason": None,
                         "created_at": T, "body": {}, "report": {}, "fields": {}, "ips": {},
                         "sentences": [], "related": [{"investigation_id": str(inv)},
                                                      {"investigation_id": 7}, "x"]})  # fmt: skip
    assert got is not None
    assert [r.investigation_id for r in got.related] == [inv]
