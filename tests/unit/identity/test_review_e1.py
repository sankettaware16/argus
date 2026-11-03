"""Q-E1's independent review (docs/gates/q-e1.md): one regression test per finding fixed.
Each failed on the reviewed code."""

from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import SecretStr

from argus.gateway.lanes import Lane
from argus.gateway.transport import WireResponse
from argus.identity.lane import (
    IdentityDeniedError,
    IdentityRefusedError,
    IdentityUnavailableError,
    Kind,
    read_identity,
)
from argus.identity.names import Credential
from argus.identity.transport import Route
from tests.unit.identity.test_lane import (
    DENIED,
    ME,
    SECRET,
    answer,
    fails,
    make,
    privileges_body,
    whoami_body,
)

pytestmark = pytest.mark.unit


async def test_e1_1_two_back_to_back_signins_leave_the_rechecks_their_server_time() -> None:
    """E1-1 (major): the kept share covered request starts only; the 50 ms floor per call
    spent the lane's whole minute on two sign-ins, so a re-check was "busy"."""
    lane, transport, store, clock = make()
    spec = store.lane_plan.spec(Lane.IDENTITY)
    assert (spec.per_minute_requests, spec.per_minute_ms) == (6, 300)  # D-130
    for _ in range(2):
        await lane.check(ME, deadline=clock.now + timedelta(seconds=5))
    assert len(transport.calls) == 4
    clock.advance(timedelta(seconds=1))
    access = await lane.verify(ME, deadline=clock.now + timedelta(seconds=6), kind=Kind.RECHECK)
    assert access.username == "devuser"
    assert len(transport.calls) == 5


async def test_e1_1_a_signin_waits_for_the_rechecks_server_time_not_only_their_starts() -> None:
    """With the minute's server time nearly spent, a sign-in waits for the refill rather than
    take what the re-checks need; a re-check does not."""
    lane, transport, _store, clock = make()
    transport.on(Route.WHOAMI, answer(whoami_body(), elapsed_ms=120))  # 120 ms charged each
    transport.on(Route.VERIFY, answer(privileges_body(), elapsed_ms=120))
    await lane.check(ME, deadline=clock.now + timedelta(seconds=5))  # 240 of 300 ms
    error = await fails(lane.whoami(ME, deadline=clock.now + timedelta(seconds=2)))
    assert error.reason == "busy"  # 60 ms left: under the 100 ms kept plus its own 50
    await lane.whoami(ME, deadline=clock.now + timedelta(seconds=2), kind=Kind.RECHECK)
    assert len(transport.calls) == 3


async def test_e1_3_a_401_or_403_that_is_not_elasticsearchs_is_unavailable() -> None:
    """E1-3: a proxy's or firewall's refusal (an HTML page, another error type) never counts
    towards the throttle."""
    for status, body in (
        (403, b"<html>forbidden</html>"),
        (401, b""),
        (403, b'{"error": {"type": "x"}}'),
    ):
        lane, transport, _store, clock = make()
        transport.on(Route.WHOAMI, lambda b=body, s=status: _raw(b, s))
        error = await fails(lane.whoami(ME, deadline=clock.now + timedelta(seconds=5)))
        assert isinstance(error, IdentityUnavailableError), (status, body)
        assert error.reason == "not_elasticsearch"
        assert not error.counts
    lane, transport, _store, clock = make()
    transport.on(Route.WHOAMI, answer(DENIED, 403))
    error = await fails(lane.whoami(ME, deadline=clock.now + timedelta(seconds=5)))
    assert isinstance(error, IdentityDeniedError)
    assert error.counts


def _raw(body: bytes, status: int) -> WireResponse:
    return WireResponse(status, body, 20.0)


async def test_e1_5_a_partial_privileges_answer_is_unavailable_not_a_superuser_refusal() -> None:
    """E1-5: a truncated ``_has_privileges`` answer for the right name is no verdict."""
    lane, transport, _store, clock = make()
    transport.on(Route.VERIFY, answer({"username": "devuser"}))
    error = await fails(lane.verify(ME, deadline=clock.now + timedelta(seconds=5)))
    assert isinstance(error, IdentityUnavailableError)
    assert error.reason == "answer_incomplete"
    partial = privileges_body()
    del partial["cluster"]["all"]
    transport.on(Route.VERIFY, answer(partial))
    error = await fails(lane.verify(ME, deadline=clock.now + timedelta(seconds=5)))
    assert error.reason == "answer_incomplete"
    with pytest.raises(IdentityUnavailableError, match="answer_incomplete"):
        read_identity(whoami_body(enabled=None), "devuser")
    with pytest.raises(IdentityRefusedError, match="disabled"):
        read_identity(whoami_body(enabled=False), "devuser")


@pytest.mark.parametrize("flag", [0, 0.0, False, None, "", "false", 1, True])
def test_e1_6_any_argus_service_metadata_is_a_service_account(flag: object) -> None:
    """E1-6: ``0`` and ``0.0`` were let in (``0 in (None, False)``); the plan says no such
    metadata at all."""
    with pytest.raises(IdentityRefusedError, match="service_account"):
        read_identity(whoami_body(metadata={"argus_uid": whoami_body()["metadata"]["argus_uid"],
                                            "argus_service": flag}), "devuser")  # fmt: skip


async def test_e1_7_a_password_that_cannot_encode_is_refused_before_any_request() -> None:
    """E1-7: a lone surrogate crashed the lane after admission with the credential in the
    exception's ``object``; now it is a refusal with 0 requests and 0 ledger rows."""
    lane, transport, store, clock = make()
    bad = Credential("devuser", SecretStr(SECRET + "\ud800"))
    for call in (lane.whoami, lane.verify, lane.check):
        error = await fails(call(bad, deadline=clock.now + timedelta(seconds=5)))
        assert isinstance(error, IdentityRefusedError)
        assert error.reason == "not_a_password"
    assert transport.calls == []
    assert store.ledger == []


async def test_e1_8_a_signins_whoami_leaves_a_start_for_its_own_verify() -> None:
    """E1-8: a whoami could take the last sign-in start and its verify was then "busy"
    after the password had been checked. The whoami now leaves one more start."""
    lane, transport, _store, clock = make()
    for _ in range(3):
        await lane.whoami(ME, deadline=clock.now + timedelta(seconds=5))  # 3 whoamis fit
    error = await fails(lane.whoami(ME, deadline=clock.now + timedelta(seconds=5)))
    assert error.reason == "busy"  # a 4th sign-in's whoami does not
    await lane.verify(ME, deadline=clock.now + timedelta(seconds=5))  # a verify still goes
    assert len(transport.calls) == 4
