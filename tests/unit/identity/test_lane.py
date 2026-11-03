"""The identity lane (Q-E1, plan §5 and §7.2) on a scripted transport: refusals with 0
requests; a 403 is a denial, a 401 only after the security-index check, anything else
"unavailable"; its own gate, never the SIEM's health; the lane's switch, budget and the share
kept for re-checks; the ledger; no password anywhere."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import traceback
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import SecretStr

from argus.gateway.errors import ResponseError, TimedOutError, TransportFailedError
from argus.gateway.gateway import LaneGate
from argus.gateway.health import HealthMemory, HealthState
from argus.gateway.lanes import Lane
from argus.gateway.state import MemoryStore
from argus.gateway.transport import WireResponse
from argus.identity import capmap
from argus.identity.lane import (
    INDEX_CHECK_FRESH,
    KEPT_FOR_RECHECKS,
    AdminAccounts,
    IdentityDeniedError,
    IdentityError,
    IdentityLane,
    IdentityRefusedError,
    IdentityUnavailableError,
    Kind,
    read_identity,
)
from argus.identity.names import Credential, NamePolicy
from argus.identity.reach import COOLDOWNS, Signal
from argus.identity.transport import IdentityRequest, Route, authorization
from argus.web.capabilities import Capability
from tests.unit.gateway.fakes import FakeClock

T0 = datetime(2026, 10, 23, 10, 0, tzinfo=UTC)
SECRET = "correct-horse-battery-staple"
UID = "5f0c8c3e-1b8f-4a8e-9f5e-2b1d3c4e5f60"
ME = Credential("devuser", SecretStr(SECRET))
T = capmap.Targets()
# Elasticsearch's own 401/403 body: only this counts as a denial (review E1-3)
DENIED: dict[str, Any] = {
    "error": {"type": "security_exception", "reason": "unable to authenticate"}
}


def whoami_body(username: str = "devuser", **over: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "username": username,
        "roles": ["acme_view"],
        "full_name": "Devuser",
        "email": "devuser@acme.invalid",
        "metadata": {"argus_uid": UID},
        "enabled": True,
        "authentication_realm": {"name": "native1", "type": "native"},
        "lookup_realm": {"name": "native1", "type": "native"},
        "authentication_type": "realm",
    }
    body.update(over)
    return body


def privileges_body(
    username: str = "devuser", kibana: tuple[str, ...] = ("login:", "ui:siemV2/show"),
    alerts: tuple[str, ...] = ("read",), logs: tuple[str, ...] = (),
    argus: tuple[str, ...] = (), cluster: tuple[str, ...] = (),
) -> dict[str, Any]:  # fmt: skip
    request = capmap.request_body(T)
    index: dict[str, Any] = {}
    for entry in request["index"]:
        held = logs if entry["names"] == list(T.log_patterns) else alerts
        for name in entry["names"]:
            index[name] = {p: p in held for p in entry["privileges"]}
    kib, arg = request["application"]
    return {
        "username": username,
        "has_all_requested": False,
        "cluster": {c: c in cluster for c in request["cluster"]},
        "index": index,
        "application": {
            capmap.KIBANA_APP: {T.resource: {p: p in kibana for p in kib["privileges"]}},
            capmap.ARGUS_APP: {"*": {p: p in argus for p in arg["privileges"]}},
        },
    }


def answer(body: Any, status: int = 200, elapsed_ms: float = 20.0) -> WireResponse:
    return WireResponse(status, json.dumps(body).encode(), elapsed_ms)


Reply = WireResponse | Exception | Callable[[], WireResponse]


@dataclass
class ScriptedIdentity:
    """Answers each route from its own list (the last one repeats); records every call."""

    clock: FakeClock
    replies: dict[Route, list[Reply]] = field(default_factory=dict)
    calls: list[tuple[Route, IdentityRequest, str]] = field(default_factory=list)
    latency: timedelta = timedelta(milliseconds=20)

    def on(self, route: Route, *replies: Reply) -> ScriptedIdentity:
        self.replies[route] = list(replies)
        return self

    async def send(self, request: IdentityRequest, auth: SecretStr) -> WireResponse:
        self.calls.append((request.route, request, auth.get_secret_value()))
        self.clock.advance(self.latency)
        replies = self.replies.get(request.route) or [answer({}, 500)]
        reply = replies.pop(0) if len(replies) > 1 else replies[0]
        if isinstance(reply, Exception):
            raise reply
        if callable(reply):
            return reply()
        return reply


@dataclass
class IndexCheck:
    results: list[bool | None] = field(default_factory=lambda: [True])
    calls: int = 0

    async def __call__(self, deadline: datetime) -> bool | None:
        self.calls += 1
        return self.results.pop(0) if len(self.results) > 1 else self.results[0]


def make(
    index: IndexCheck | None = None, *, admin: AdminAccounts = AdminAccounts.REFUSE,
    memory: HealthMemory | None = None, names: NamePolicy | None = None,
    store: MemoryStore | None = None,
) -> tuple[IdentityLane, ScriptedIdentity, MemoryStore, FakeClock]:  # fmt: skip
    clock = FakeClock(T0)
    store = store or MemoryStore(memory=memory or HealthMemory(probed_at=T0))
    transport = ScriptedIdentity(clock)
    transport.on(Route.WHOAMI, answer(whoami_body()))
    transport.on(Route.VERIFY, answer(privileges_body()))
    lane = IdentityLane(
        transport, store, LaneGate(store, clock=clock, sleep=clock.sleep), names=names,
        index_check=index or IndexCheck(), admin_accounts=admin, clock=clock,
    )  # fmt: skip
    return lane, transport, store, clock


def soon(clock: FakeClock, seconds: float = 30) -> datetime:
    return clock.now + timedelta(seconds=seconds)


async def fails(coro: Any) -> IdentityError:
    with pytest.raises(IdentityError) as caught:
        await coro
    return caught.value


# --------------------------------------------------------------------------- the good path


async def test_a_good_check() -> None:
    lane, transport, store, clock = make()
    checked = await lane.check(ME, deadline=soon(clock))
    assert checked.identity.username == "devuser"
    assert checked.identity.argus_uid == UID
    assert checked.identity.full_name == "Devuser"
    assert checked.identity.email == "devuser@acme.invalid"
    assert checked.access.capabilities == frozenset({Capability.VIEW})
    assert checked.access.map_version == capmap.MAP_VERSION
    assert checked.access.custody
    assert checked.access.checked_at == clock.now
    assert [route for route, _r, _a in transport.calls] == [Route.WHOAMI, Route.VERIFY]
    whoami, verify = transport.calls
    assert whoami[1].body is None
    assert json.loads(verify[1].body or b"") == capmap.request_body(T)
    assert whoami[2] == verify[2] == authorization(ME).get_secret_value()
    assert [e.template for e in store.ledger] == ["identity.whoami", "identity.verify"]


async def test_each_call_gets_the_header_of_its_own_credential() -> None:
    lane, transport, _store, clock = make()
    other = Credential("someone", SecretStr("another-long-password"))
    transport.on(Route.WHOAMI, answer(whoami_body()), answer(whoami_body("someone")))
    await lane.whoami(ME, deadline=soon(clock))
    await lane.whoami(other, deadline=soon(clock))
    assert [a for _route, _r, a in transport.calls] == [
        authorization(ME).get_secret_value(), authorization(other).get_secret_value()
    ]  # fmt: skip


async def test_the_request_timeout_is_the_lanes_and_never_past_the_deadline() -> None:
    lane, transport, _store, clock = make()
    await lane.whoami(ME, deadline=soon(clock, 60))
    await lane.whoami(ME, deadline=soon(clock, 2))
    assert [r.timeout_s for _route, r, _a in transport.calls] == [5.0, pytest.approx(2.0)]


async def test_a_lane_with_a_shorter_timeout() -> None:
    clock = FakeClock(T0)
    store = MemoryStore(memory=HealthMemory(probed_at=T0))
    transport = ScriptedIdentity(clock).on(Route.WHOAMI, answer(whoami_body()))
    lane = IdentityLane(transport, store, LaneGate(store, clock=clock, sleep=clock.sleep),
                        timeout_s=3, clock=clock)  # fmt: skip
    await lane.whoami(ME, deadline=soon(clock))
    assert transport.calls[0][1].timeout_s == 3
    for bad in (0, 5.5, -1):
        with pytest.raises(ValueError, match="at most"):
            IdentityLane(transport, store, LaneGate(store), timeout_s=bad)


# --------------------------------------------------------------------------- refusals


@pytest.mark.parametrize(
    ("credential", "reason"),
    [
        (Credential("elastic", SecretStr(SECRET)), "reserved_name"),
        (Credential("Kibana_System", SecretStr(SECRET)), "reserved_name"),
        (Credential("argus", SecretStr(SECRET)), "service_name"),
        (Credential("argus-canary", SecretStr(SECRET)), "service_name"),
        (Credential("san:ket", SecretStr(SECRET)), "not_a_name"),
        (Credential("sankét", SecretStr(SECRET)), "not_a_name"),
        (Credential("devuser", SecretStr("123456789")), "short_password"),
    ],
)
async def test_refused_before_any_request(credential: Credential, reason: str) -> None:
    lane, transport, store, clock = make(names=NamePolicy.of(["argus-canary"]))
    for call in (lane.whoami, lane.verify, lane.check):
        error = await fails(call(credential, deadline=soon(clock)))
        assert isinstance(error, IdentityRefusedError)
        assert error.reason == reason
        assert not error.counts
    assert transport.calls == []
    assert store.ledger == []
    assert store.lanes.bucket(Lane.IDENTITY).leases == ()
    assert store.lanes.starts.get(Lane.IDENTITY, ()) == ()


async def test_only_a_credential() -> None:
    lane, _transport, _store, clock = make()
    with pytest.raises(TypeError):
        await lane.whoami(("devuser", SECRET), deadline=soon(clock))  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("over", "reason"),
    [
        ({"authentication_realm": {"name": "file1", "type": "file"}}, "not_native"),
        ({"authentication_realm": {"name": "reserved", "type": "reserved"}}, "not_native"),
        ({"lookup_realm": {"name": "file1", "type": "file"}}, "not_native"),
        ({"authentication_type": "api_key"}, "not_a_password"),
        ({"authentication_type": "token"}, "not_a_password"),
        ({"enabled": False}, "disabled"),
        ({"metadata": {"argus_uid": UID, "argus_service": True}}, "service_account"),
        ({"metadata": {"argus_uid": UID, "argus_service": "yes"}}, "service_account"),
        ({"metadata": {"argus_uid": UID, "argus_service": False}}, "service_account"),
        ({"metadata": {"argus_uid": UID, "argus_service": 0}}, "service_account"),
        ({"metadata": {"argus_uid": UID, "argus_service": 0.0}}, "service_account"),
        ({"metadata": {"argus_uid": UID, "argus_service": None}}, "service_account"),
        ({"metadata": {}}, "no_argus_uid"),
        ({"metadata": None}, "no_argus_uid"),
        ({"metadata": {"argus_uid": "not-a-uuid"}}, "no_argus_uid"),
        ({"metadata": {"argus_uid": UID.replace("-", "")}}, "no_argus_uid"),
        ({"metadata": {"argus_uid": 7}}, "no_argus_uid"),
    ],
)
def test_whoami_is_read_strictly(over: dict[str, Any], reason: str) -> None:
    with pytest.raises(IdentityRefusedError) as refused:
        read_identity(whoami_body(**over), "devuser")
    assert refused.value.reason == reason


@pytest.mark.parametrize(
    "over",
    [
        {"lookup_realm": None},
        {"authentication_realm": None},
        {"authentication_realm": "native"},
        {"authentication_type": None},
        {"enabled": "true"},
        {"enabled": None},
        {"enabled": 1},
    ],
)
def test_a_whoami_answer_missing_a_field_is_incomplete_not_a_verdict(over: dict[str, Any]) -> None:
    """Review E1-5: what the answer does not state is unavailable, never a refusal."""
    with pytest.raises(IdentityUnavailableError, match="answer_incomplete"):
        read_identity(whoami_body(**over), "devuser")


def test_whoami_for_another_name_is_not_an_answer() -> None:
    bodies: list[Any] = [
        whoami_body("Devuser"),
        whoami_body("devuser2"),
        [],
        None,
        {"username": None},
    ]
    for body in bodies:
        with pytest.raises(IdentityUnavailableError, match="answer_mismatch"):
            read_identity(body, "devuser")


def test_whoami_keeps_what_it_needs() -> None:
    upper = UID.upper()
    got = read_identity(whoami_body(full_name="", email=None, metadata={"argus_uid": upper}),
                        "devuser")  # fmt: skip
    assert got.argus_uid == UID  # one form
    assert (got.full_name, got.email, got.realm) == (None, None, "native")
    long = read_identity(whoami_body(full_name="x" * 1000), "devuser")
    assert long.full_name == "x" * 256


@pytest.mark.parametrize(
    ("body", "reason", "kind"),
    [
        (privileges_body(cluster=("all",)), "superuser", IdentityRefusedError),
        (privileges_body(cluster=("all", "manage_security")), "superuser", IdentityRefusedError),
        (privileges_body(cluster=("manage_security",)), "admin_account", IdentityRefusedError),
        (privileges_body(cluster=("grant_api_key",)), "admin_account", IdentityRefusedError),
        (privileges_body(kibana=("login:",)), "no_access", IdentityRefusedError),
        (privileges_body(alerts=()), "no_access", IdentityRefusedError),
        (privileges_body(username="someone-else"), "answer_mismatch", IdentityUnavailableError),
        ({"cluster": {}}, "answer_mismatch", IdentityUnavailableError),
    ],
)
async def test_verify_refusals(body: Any, reason: str, kind: type[IdentityError]) -> None:
    lane, transport, _store, clock = make()
    transport.on(Route.VERIFY, answer(body))
    error = await fails(lane.verify(ME, deadline=soon(clock)))
    assert type(error) is kind
    assert error.reason == reason
    assert not error.counts


async def test_admin_accounts_without_custody_dq15_b() -> None:
    lane, transport, _store, clock = make(admin=AdminAccounts.WITHOUT_CUSTODY)
    transport.on(Route.VERIFY, answer(privileges_body(cluster=("manage_api_key",),
                                                      argus=("argus:admin",))))  # fmt: skip
    access = await lane.verify(ME, deadline=soon(clock))
    assert access.admin_account
    assert not access.custody
    assert access.capabilities == {Capability.VIEW, Capability.ADMIN}
    transport.on(Route.VERIFY, answer(privileges_body(cluster=("all",))))
    error = await fails(lane.verify(ME, deadline=soon(clock)))
    assert error.reason == "superuser"  # never, whatever the setting


# --------------------------------------------------------------------------- denials


async def test_a_403_is_a_denial() -> None:
    index = IndexCheck()
    lane, transport, _store, clock = make(index)
    transport.on(Route.WHOAMI, answer({"error": {"type": "security_exception"}}, 403))
    error = await fails(lane.whoami(ME, deadline=soon(clock)))
    assert isinstance(error, IdentityDeniedError)
    assert (error.reason, error.counts) == ("forbidden", True)
    assert index.calls == 0  # a 403 needs no index check


async def test_a_401_is_a_denial_only_with_the_security_index_usable() -> None:
    for results, expected in (
        ([True], ("IdentityDeniedError", "unauthenticated")),
        ([False], ("IdentityUnavailableError", "security_index")),
        ([None], ("IdentityUnavailableError", "security_index")),
    ):
        index = IndexCheck(list(results))
        lane, transport, _store, clock = make(index)
        transport.on(Route.WHOAMI, answer({"error": {"type": "security_exception"}}, 401))
        transport.on(Route.VERIFY, answer({"error": {"type": "security_exception"}}, 401))
        for call in (lane.whoami, lane.verify):
            error = await fails(call(ME, deadline=soon(clock)))
            assert (type(error).__name__, error.reason) == expected
            assert error.counts is (expected[0] == "IdentityDeniedError")


async def test_without_an_index_check_a_401_is_never_a_denial() -> None:
    clock = FakeClock(T0)
    store = MemoryStore(memory=HealthMemory(probed_at=T0))
    transport = ScriptedIdentity(clock).on(Route.WHOAMI, answer(DENIED, 401))
    lane = IdentityLane(transport, store, LaneGate(store, clock=clock, sleep=clock.sleep),
                        clock=clock)  # fmt: skip
    error = await fails(lane.whoami(ME, deadline=soon(clock)))
    assert isinstance(error, IdentityUnavailableError)
    assert error.reason == "security_index"


async def test_a_usable_index_is_believed_for_a_while_only() -> None:
    index = IndexCheck([True, False])
    lane, transport, _store, clock = make(index)
    transport.on(Route.WHOAMI, answer(DENIED, 401))
    assert isinstance(
        await fails(lane.whoami(ME, deadline=soon(clock), kind=Kind.RECHECK)), IdentityDeniedError
    )
    assert isinstance(
        await fails(lane.whoami(ME, deadline=soon(clock), kind=Kind.RECHECK)), IdentityDeniedError
    )
    assert index.calls == 1  # within INDEX_CHECK_FRESH
    clock.advance(INDEX_CHECK_FRESH)
    error = await fails(lane.whoami(ME, deadline=soon(clock), kind=Kind.RECHECK))
    assert isinstance(error, IdentityUnavailableError)
    assert index.calls == 2
    clock.advance(timedelta(seconds=1))
    index.results = [True]
    assert isinstance(
        await fails(lane.whoami(ME, deadline=soon(clock), kind=Kind.RECHECK)), IdentityDeniedError
    )
    assert index.calls == 3  # an unusable answer is never cached


# --------------------------------------------------------------------------- unavailable


@pytest.mark.parametrize(
    ("reply", "reason"),
    [
        (answer({}, 500), "http_500"),
        (answer({"error": {"type": "x"}}, 404), "http_404"),
        (answer({}, 302), "http_302"),
        (answer({}, 502), "http_502"),
        (answer({}, 429), "overloaded"),
        (answer({}, 503), "http_503"),
        (answer({}, 999), "http_unknown"),
        (WireResponse(200, b"not json", 5.0), "answer_not_json"),
        (WireResponse(200, b"[1, 2]", 5.0), "answer_not_json"),
        (TimedOutError(), "timed_out"),
        (TimedOutError("no connection", reached=False), "timed_out"),
        (TransportFailedError("reset", retriable=False), "transport_failure"),
        (TransportFailedError("refused", retriable=False, reached=False), "transport_failure"),
        (ResponseError("the answer is larger than 262144 bytes"), "response_error"),
    ],
)
async def test_anything_else_is_unavailable(reply: Reply, reason: str) -> None:
    lane, transport, store, clock = make()
    transport.on(Route.WHOAMI, reply)
    error = await fails(lane.whoami(ME, deadline=soon(clock)))
    assert isinstance(error, IdentityUnavailableError)
    assert error.reason == reason
    assert not error.counts
    assert len(store.ledger) == 1


async def test_a_passed_deadline_sends_nothing() -> None:
    lane, transport, store, clock = make()
    error = await fails(lane.whoami(ME, deadline=clock.now))
    assert (type(error), error.reason) == (IdentityUnavailableError, "deadline_passed")
    assert transport.calls == []
    assert store.ledger == []


# --------------------------------------------------------------------------- the gate


@pytest.mark.parametrize(
    "reply",
    [answer({}, 429), answer({}, 503),
     answer({"error": {"type": "es_rejected_execution_exception"}}, 500),
     answer({"error": {"root_cause": [{"type": "circuit_breaking_exception"}]}}, 500)],
)  # fmt: skip
async def test_an_overload_opens_the_gate_at_once(reply: WireResponse) -> None:
    lane, transport, store, clock = make()
    transport.on(Route.WHOAMI, reply)
    await fails(lane.whoami(ME, deadline=soon(clock)))
    assert store.identity.reason == "overloaded"
    error = await fails(lane.whoami(ME, deadline=soon(clock)))
    assert (type(error), error.reason) == (IdentityUnavailableError, "overloaded")
    assert len(transport.calls) == 1  # nothing sent while open
    clock.advance(COOLDOWNS[0])
    transport.on(Route.WHOAMI, answer(whoami_body()))
    assert (await lane.whoami(ME, deadline=soon(clock))).username == "devuser"  # the trial
    assert store.identity.open_until is None


async def test_unreachable_twice_opens_the_gate_and_costs_nothing() -> None:
    lane, transport, store, clock = make()
    refused = TransportFailedError("refused", retriable=False, reached=False)
    transport.on(Route.WHOAMI, refused)
    for _ in range(2):
        error = await fails(lane.whoami(ME, deadline=soon(clock)))
        assert error.reason == "transport_failure"
    assert store.identity.reason == "unreachable"
    error = await fails(lane.whoami(ME, deadline=soon(clock)))
    assert error.reason == "unreachable"
    assert len(transport.calls) == 2
    assert [e.took_ms for e in store.ledger] == [0, 0]  # no connection: no charge


async def test_a_401_or_403_is_an_answer_and_keeps_the_gate_closed() -> None:
    lane, transport, store, clock = make()
    transport.on(Route.WHOAMI, TransportFailedError("refused", retriable=False, reached=False),
                 answer(DENIED, 403), TransportFailedError("x", retriable=False, reached=False),
                 answer(DENIED, 401))  # fmt: skip
    for _ in range(4):
        await fails(lane.whoami(ME, deadline=soon(clock), kind=Kind.RECHECK))
    assert store.identity.open_until is None
    assert store.identity.failures == ()


async def test_an_answer_that_is_no_overload_is_answered() -> None:
    lane, transport, store, clock = make()
    seen: list[Signal] = []
    original = store.identity_reach_report

    async def spy(now: datetime, signal: Signal) -> Any:
        seen.append(signal)
        return await original(now, signal)

    store.identity_reach_report = spy  # type: ignore[method-assign]
    for reply in (answer({}, 500), answer({"error": {"type": "other"}}, 400), answer({}, 302),
                  answer(whoami_body()), TimedOutError()):  # fmt: skip
        transport.on(Route.WHOAMI, reply)
        with contextlib.suppress(IdentityError):
            await lane.whoami(ME, deadline=soon(clock, 120))
    assert seen == [Signal.ANSWERED] * 4 + [Signal.UNREACHABLE]


# --------------------------------------------------------------------------- the SIEM's health


@pytest.mark.parametrize(
    "memory",
    [
        HealthMemory(state=HealthState.STOP, probed_at=T0, reasons=("auth_failed",)),
        HealthMemory(state=HealthState.DEGRADED, probed_at=T0),
        HealthMemory(probed_at=T0 - timedelta(hours=3)),  # a stale probe
        HealthMemory(),  # never probed
    ],
)
async def test_never_gated_on_siem_health(memory: HealthMemory) -> None:
    lane, transport, _store, clock = make(memory=memory)
    checked = await lane.check(ME, deadline=soon(clock))
    assert checked.access.capabilities == {Capability.VIEW}
    assert len(transport.calls) == 2


async def test_never_gated_on_siem_breaker() -> None:
    lane, _transport, store, clock = make()
    await store.breaker_overload(T0)
    assert not (await store.breaker_peek(T0))[0]
    assert (await lane.whoami(ME, deadline=soon(clock))).username == "devuser"


async def test_siem_down_leaves_its_health_and_breaker_alone() -> None:
    lane, transport, store, clock = make(IndexCheck([None]))
    memory, breaker, budget = store.memory, store.breaker, store.budget
    for reply in (TransportFailedError("refused", retriable=False, reached=False),
                  TimedOutError(), answer({}, 429), answer({}, 401), answer({}, 403),
                  answer({}, 503)):  # fmt: skip
        transport.on(Route.WHOAMI, reply)
        await fails(lane.whoami(ME, deadline=soon(clock)))
        clock.advance(COOLDOWNS[-1])
    assert store.memory == memory
    assert store.breaker == breaker
    assert store.budget == budget  # the collector's bucket is not the identity lane's


# --------------------------------------------------------------------------- the lane


@pytest.mark.parametrize("switch", ["identity", "global"])
async def test_the_switch_stops_it_with_no_request(switch: str) -> None:
    lane, transport, store, clock = make()
    store.stopped.add(switch)
    error = await fails(lane.check(ME, deadline=soon(clock)))
    assert (type(error), error.reason) == (IdentityUnavailableError, "stopped")
    assert transport.calls == []
    assert store.ledger == []


async def test_other_switches_do_not() -> None:
    lane, _transport, store, clock = make()
    store.stopped.update({"collector", "kibana", "cases", "writeback", "enrichment"})
    assert (await lane.whoami(ME, deadline=soon(clock))).username == "devuser"


async def test_a_signin_leaves_two_checks_a_minute_to_rechecks() -> None:
    """§7.8: 6 checks a minute; a sign-in's whoami leaves 3 and its verify 2 (review E1-8), so
    two whole sign-ins fit and the re-checks always keep their two."""
    lane, transport, store, clock = make()
    assert store.lane_plan.spec(Lane.IDENTITY).per_minute_requests == 6
    for _ in range(2):
        await lane.check(ME, deadline=clock.now + timedelta(seconds=5))  # 4 starts
    started = clock.now
    error = await fails(lane.whoami(ME, deadline=clock.now + timedelta(seconds=5)))
    assert (type(error), error.reason) == (IdentityUnavailableError, "busy")
    assert clock.now == started  # it did not wait past its deadline
    for _ in range(KEPT_FOR_RECHECKS):
        await lane.whoami(ME, deadline=clock.now + timedelta(seconds=5), kind=Kind.RECHECK)
        clock.advance(timedelta(seconds=1))
    error = await fails(lane.whoami(ME, deadline=clock.now + timedelta(seconds=5),
                                    kind=Kind.RECHECK))  # fmt: skip
    assert error.reason == "busy"  # 6 in the minute
    assert len(transport.calls) == 6


async def test_a_signin_waits_within_its_deadline() -> None:
    lane, transport, _store, clock = make()
    for _ in range(4):
        await lane.whoami(ME, deadline=soon(clock, 120))
    assert (await lane.whoami(ME, deadline=soon(clock, 120))).username == "devuser"
    assert len(transport.calls) == 5
    assert clock.slept  # it waited for the minute to free a check


async def test_charges() -> None:
    lane, transport, store, clock = make()
    transport.on(Route.WHOAMI, answer(whoami_body(), elapsed_ms=3.2), answer(whoami_body(),
                 elapsed_ms=180.1), TimedOutError(),
                 TransportFailedError("reset", retriable=False))  # fmt: skip
    for _ in range(4):
        with contextlib.suppress(IdentityError):
            await lane.whoami(ME, deadline=soon(clock, 600))
        clock.advance(timedelta(minutes=30))  # a timeout's debt: 5 s at 200 ms a minute
    # the estimate at least; a round trip; a timeout its whole timeout; a reset its round trip
    assert [e.took_ms for e in store.ledger] == [50, 181, 5000, 50]


async def test_a_timeout_puts_the_lane_in_debt_for_its_whole_timeout() -> None:
    """§7.8: a timeout is charged its whole timeout, and each lane spends only its own share,
    so one 5 s timeout keeps the identity lane (200 ms a minute) busy for about 25 minutes;
    the collector's bucket is untouched."""
    lane, transport, store, clock = make()
    transport.on(Route.WHOAMI, TimedOutError(), answer(whoami_body()))
    await fails(lane.whoami(ME, deadline=soon(clock)))
    error = await fails(lane.whoami(ME, deadline=soon(clock, 600)))
    assert error.reason == "busy"
    clock.advance(timedelta(minutes=25))
    assert (await lane.whoami(ME, deadline=soon(clock, 60))).username == "devuser"
    assert store.budget == type(store.budget)()


async def test_one_ledger_row_per_request_without_the_name() -> None:
    lane, transport, store, clock = make()
    store.stopped.add("collector")
    await lane.check(ME, deadline=soon(clock))
    transport.on(Route.WHOAMI, answer({}, 403))
    await fails(lane.whoami(ME, deadline=soon(clock)))
    assert len(store.ledger) == 3
    for entry in store.ledger:
        assert (entry.component, entry.purpose, entry.lane) == ("identity", "identity", "identity")
        assert entry.target == "elasticsearch"
        assert entry.indices == ()
        assert entry.attempts == 1
        assert entry.health == "normal"
        assert entry.switches == ("collector",)
        assert entry.task_key is None
    assert [(e.template, e.version, e.outcome, e.http_status) for e in store.ledger] == [
        ("identity.whoami", 1, "ok", 200), ("identity.verify", 1, "ok", 200),
        ("identity.whoami", 1, "auth_failed", 403),
    ]  # fmt: skip
    text = repr(store.ledger)
    assert "devuser" not in text
    assert SECRET not in text


async def test_a_cancelled_check_settles_its_lease_and_leaves_a_row() -> None:
    lane, transport, store, clock = make()
    started = asyncio.Event()

    async def hang(request: IdentityRequest, auth: SecretStr) -> WireResponse:
        started.set()
        await asyncio.sleep(3600)
        raise AssertionError("never")

    transport.send = hang  # type: ignore[method-assign]
    task = asyncio.create_task(lane.whoami(ME, deadline=soon(clock)))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert [e.outcome for e in store.ledger] == ["aborted"]
    assert store.ledger[0].took_ms >= 50  # it may have landed: at least the estimate
    assert store.lanes.bucket(Lane.IDENTITY).leases == ()


# --------------------------------------------------------------------------- no password


async def test_no_password_in_logs_exceptions_or_the_ledger(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    lane, transport, store, clock = make(IndexCheck([True, None]))
    replies: list[Reply] = [
        answer(whoami_body()), answer({}, 401), answer({}, 401), answer({}, 403),
        answer({}, 500), TimedOutError(), TransportFailedError("x", retriable=False),
        WireResponse(200, b"{", 1.0),
    ]  # fmt: skip
    transport.on(Route.WHOAMI, *replies)
    shown: list[str] = []
    for _ in replies:
        try:
            await lane.whoami(ME, deadline=soon(clock, 600))
        except IdentityError as exc:
            shown += [str(exc), repr(exc), repr(exc.args), "".join(traceback.format_exception(exc))]
        clock.advance(COOLDOWNS[-1])
    header = authorization(ME).get_secret_value()
    kept = repr({k: v for k, v in vars(lane).items() if k != "transport"})  # the fake records
    for text in (caplog.text, repr(store.ledger), *shown, repr(ME), kept):
        assert SECRET not in text
        assert header.split(" ", 1)[1] not in text
    assert all(header not in repr(request) for _route, request, _a in transport.calls)


def test_the_transport_request_holds_no_credential() -> None:
    request = IdentityRequest(Route.WHOAMI, None, 5)
    assert set(vars(request)) == {"route", "body", "timeout_s"}
    with pytest.raises(ValueError, match="only the privileges check"):
        IdentityRequest(Route.WHOAMI, b"{}", 5)
    with pytest.raises(ValueError, match="only the privileges check"):
        IdentityRequest(Route.VERIFY, None, 5)
    for bad in (0, -1, 5.01):
        with pytest.raises(ValueError, match="at most"):
            IdentityRequest(Route.WHOAMI, None, bad)


# --------------------------------------------------------------------------- the index check


async def test_the_index_check_through_the_gateway() -> None:
    from argus.gateway.health import HealthState
    from argus.identity.lane import gateway_index_check
    from tests.unit.gateway.fakes import make as make_gateway
    from tests.unit.gateway.fakes import ok

    green = {"status": "green", "active_primary_shards": 1, "unassigned_primary_shards": 0}
    red = {"status": "red", "active_primary_shards": 0, "unassigned_primary_shards": 1}
    gateway, transport, store, clock = make_gateway()
    transport.on("/_cluster/health/.security", ok(green), ok(red), ok({}, 401))
    check = gateway_index_check(gateway)
    deadline = clock.now + timedelta(seconds=20)
    store.memory = HealthMemory(state=HealthState.STOP, probed_at=clock.now)
    assert await check(deadline) is True  # the identity purpose runs in STOP
    assert await check(deadline) is False
    assert await check(deadline) is None  # ARGUS's own key refused: could not tell
    assert [e.template for e in store.ledger] == ["health.security_index"] * 3
    assert {e.lane for e in store.ledger} == {"identity"}
    assert {e.component for e in store.ledger} == {"identity"}
