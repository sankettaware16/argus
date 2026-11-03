"""Q-B3: how the case routes turn what the case machine and the approval functions refuse into
answers, and the one live check a group of decisions shares."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest

from argus.cases.approvals import ApprovalError
from argus.cases.desk import Refused
from argus.cases.identity import FakeIdentityProvider, LocalIdentityProvider
from argus.cases.machine import CaseRefused
from argus.cases.model import REASONS, REQUEST_REASONS
from argus.web import auth
from argus.web.capabilities import Capability
from argus.web.v1 import case_models, case_routes

pytestmark = pytest.mark.unit


def test_the_contract_names_the_reasons_a_person_may_ask_a_closure_for() -> None:
    from typing import get_args

    # a schema that offered "duplicate" would promise a request the machine always refuses
    assert set(get_args(case_models.RequestedReason)) == REQUEST_REASONS
    assert set(get_args(case_models.ClosureReason)) == set(REASONS)
    assert set(REASONS) - REQUEST_REASONS == {"duplicate"}


@pytest.mark.parametrize(
    ("code", "status", "answer"),
    [
        ("forbidden", 403, "forbidden"),
        ("conflict", 409, "conflict"),
        ("invalid", 422, "invalid"),
        ("unavailable", 409, "not_ready"),
        ("not_found", 404, "not_found"),
    ],
)
def test_each_refusal_of_the_case_machine_has_its_status_and_code(
    code: Any, status: int, answer: str
) -> None:
    refusal = case_routes.case_refusal(CaseRefused(code, "cannot take a closed case"), "take")
    assert (refusal.status, refusal.code) == (status, answer)
    assert refusal.detail == "Only an open or assigned case can be taken; this one is closed."


@pytest.mark.parametrize(
    ("status", "code", "answer"),
    [
        (401, None, (401, "unauthenticated")),
        (403, "step_up_required", (403, "step_up_required")),
        (403, None, (403, "forbidden")),
        (404, None, (404, "not_found")),
        (409, None, (409, "conflict")),
        (410, None, (409, "conflict")),  # an approval that ran out is a conflict with the clock
        (422, None, (422, "invalid")),
        (503, None, (503, "unavailable")),
        (418, None, (409, "conflict")),  # anything the database adds is a conflict, never a 500
    ],
)
def test_each_refusal_of_the_approval_functions_has_its_status_and_code(
    status: int, code: str | None, answer: tuple[int, str]
) -> None:
    refusal = case_routes.approval_refusal(ApprovalError(status, "the words", code))
    assert (refusal.status, refusal.code) == answer
    assert refusal.detail == "The words."


def test_a_refused_identity_check_is_an_answer_not_a_raised_refusal() -> None:
    """The record of the denial must be committed with the request, so it is returned."""
    answer = case_routes.refused_answer(Refused(403, "your account was refused: sign in again"))
    assert answer.status_code == 403
    assert json.loads(bytes(answer.body)) == {
        "detail": "Your account was refused: sign in again.",
        "code": "forbidden",
    }


async def test_a_group_of_decisions_asks_the_provider_once_for_each_purpose() -> None:
    async def now(conn: Any) -> datetime:
        return datetime(2026, 10, 26, tzinfo=UTC)

    fake = FakeIdentityProvider(clock=now)
    fake.allow(7, frozenset({"approve"}))
    once = case_routes.OneCheck(fake)
    first = await once.check(None, 7, purpose="approval")  # type: ignore[arg-type]
    for _ in range(5):
        assert await once.check(None, 7, purpose="approval") is first  # type: ignore[arg-type]
    await once.check(None, 7, purpose="request")  # type: ignore[arg-type]
    await once.check(None, 8, purpose="approval")  # type: ignore[arg-type]
    assert fake.calls == [(7, "approval"), (7, "request"), (8, "approval")]
    assert once.name == "fake"


def reviewer(mode: str) -> auth.Reviewer:
    return auth.Reviewer(
        user_id=3,
        username="u",
        display_name="U",
        csrf_token="t",
        previous_seen_at=None,
        capabilities=frozenset({Capability.VIEW}),
        mode=mode,
    )


def test_an_elk_session_is_checked_in_elk_and_a_local_one_locally() -> None:
    elk = object()
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(elk=elk)))
    assert case_routes.provider_for(request, reviewer("elk"), "tok").name == "elk"  # type: ignore[arg-type]
    assert isinstance(
        case_routes.provider_for(request, reviewer("local"), "tok"), LocalIdentityProvider
    )  # type: ignore[arg-type]
    plain = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(elk=None)))
    assert isinstance(
        case_routes.provider_for(plain, reviewer("elk"), "tok"), LocalIdentityProvider
    )  # type: ignore[arg-type]
