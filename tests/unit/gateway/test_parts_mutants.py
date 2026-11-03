"""Tests written for mutation survivors (D-040) in the budget, health, responses, transport and
cassettes: stored values pinned, frozenness, exact boundaries, messages and file handling."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import ssl
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from argus.gateway import budget as bu
from argus.gateway import cassettes as ca
from argus.gateway import health as he
from argus.gateway import responses as rs
from argus.gateway import transport as tr
from argus.gateway.errors import (
    OverloadedError,
    PartialResultError,
    TimedOutError,
    TransportFailedError,
)
from argus.gateway.templates import CostClass, Endpoint, Family, Spec
from argus.gateway.validator import FinalRequest

pytestmark = pytest.mark.unit

T0 = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)
MIN = timedelta(minutes=1)
CFG = bu.BudgetConfig()
HCFG = he.HealthConfig()
DATA = Path(__file__).parent / "data"


def frozen(*items: Any) -> None:
    for item in items:
        field = dataclasses.fields(item)[0].name
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(item, field, None)


# --------------------------------------------------------------------------- budget


def test_budget_values_defaults_and_frozenness() -> None:
    assert [v.value for v in bu.Verdict] == ["admitted", "wait", "exhausted"]
    state = bu.BudgetState()
    assert (state.day_used_ms, state.heavy_day, state.expired) == (0, 0, ())
    lease = bu.Lease("a", CostClass.LIGHT, 50, T0)
    admission, _ = bu.admit(state, CFG, CostClass.LIGHT, T0, scale=1.0, lease_id="a")
    assert (admission.verdict, admission.reason) == (bu.Verdict.ADMITTED, "ok")
    probe, _ = bu.admit(state, CFG, CostClass.PROBE, T0, scale=0.0, lease_id="p")
    assert probe.reason == "ok"
    frozen(CFG, lease, state, admission)


def test_at_most_256_expired_leases_are_remembered() -> None:
    leases = tuple(bu.Lease(str(n), CostClass.PROBE, 1, T0) for n in range(300))
    state = bu.roll(bu.BudgetState(day=T0.date(), leases=leases), CFG, T0, 1.0)
    assert state.expired == tuple(str(n) for n in range(44, 300))


def test_a_probe_start_is_forgotten_after_exactly_a_minute() -> None:
    state = bu.BudgetState(day=T0.date(), probe_starts=(T0,) * 12)
    early, _ = bu.admit(
        state, CFG, CostClass.PROBE, T0 + MIN - timedelta(1e-3), scale=1.0, lease_id="a"
    )
    assert early.verdict is bu.Verdict.WAIT
    late, _ = bu.admit(state, CFG, CostClass.PROBE, T0 + MIN, scale=1.0, lease_id="b")
    assert late.verdict is bu.Verdict.ADMITTED


def test_a_heavy_query_needs_only_the_scaled_burst() -> None:
    """At a quarter of the budget the bucket holds 750 ms: a 1,000 ms estimate needs 750."""
    state = bu.BudgetState(tokens_ms=750.0, refilled_at=T0, day=T0.date())
    admission, _ = bu.admit(state, CFG, CostClass.HEAVY, T0, scale=0.25, lease_id="h")
    assert admission.verdict is bu.Verdict.ADMITTED


def test_budget_messages() -> None:
    with pytest.raises(
        ValueError, match=r"^work other than probes needs a budget scale in \(0, 1\]$"
    ):
        bu.admit(bu.BudgetState(), CFG, CostClass.LIGHT, T0, scale=0.0, lease_id="a")
    with pytest.raises(ValueError, match=r"^took is never negative$"):
        bu.settle(bu.BudgetState(), CFG, bu.Lease("a", CostClass.LIGHT, 50, T0), -1, T0, scale=1.0)


def test_settling_on_a_new_day_counts_on_that_day() -> None:
    lease = bu.Lease("a", CostClass.LIGHT, 50, T0 + timedelta(days=2))
    state = bu.BudgetState(tokens_ms=0.0, refilled_at=T0, day=T0.date(), day_used_ms=500,
                           leases=(lease,))  # fmt: skip
    state = bu.settle(state, CFG, lease, 10, T0 + timedelta(days=1), scale=1.0)
    assert (state.day, state.day_used_ms) == ((T0 + timedelta(days=1)).date(), 10)


# --------------------------------------------------------------------------- health


def test_health_values_defaults_and_frozenness() -> None:
    assert [s.value for s in he.HealthState] == ["normal", "caution", "degraded", "stop"]
    readings = he.Readings(at=T0)
    assert he.evaluate(he.HealthMemory(), readings, HCFG).state is he.HealthState.NORMAL
    frozen(HCFG, readings, he.Baselines(), he.HealthMemory())


def test_breaker_trips_degrade() -> None:
    first = he.evaluate(he.HealthMemory(), he.Readings(at=T0, breakers_tripped=1), HCFG)
    rose = he.evaluate(first, he.Readings(at=T0, breakers_tripped=2), HCFG)
    assert (rose.state, rose.reasons) == (he.HealthState.DEGRADED, ("breaker_trips",))


def test_staying_degraded_is_not_a_recovery() -> None:
    degraded = he.evaluate(he.HealthMemory(), he.Readings(at=T0, disk_percent=91.0), HCFG)
    again = he.evaluate(degraded, he.Readings(at=T0 + MIN, disk_percent=91.0), HCFG)
    assert (again.state, again.recovered_at) == (he.HealthState.DEGRADED, None)


def test_effective_reasons() -> None:
    assert he.effective(he.HealthMemory(), T0, HCFG).reasons == ("never_probed",)
    stale = he.HealthMemory(probed_at=T0 - 4 * MIN)
    assert he.effective(stale, T0, HCFG).reasons == ("probe_stale",)
    assert he.effective(stale, T0 + 20 * MIN, HCFG).reasons == ("probe_stale",)


def test_an_auth_failure_keeps_the_start_of_an_earlier_stop() -> None:
    stop = he.HealthMemory(state=he.HealthState.STOP, since=T0 - MIN)
    assert he.on_auth_failed(stop, T0).since == T0 - MIN
    normal = he.HealthMemory(since=T0 - MIN)
    assert he.on_auth_failed(normal, T0).since == T0
    assert he.on_auth_failed(he.HealthMemory(state=he.HealthState.STOP), T0).since == T0


GOOD = {"_nodes": {"failed": 0}}


@pytest.mark.parametrize("nodes", [{}, {"a": {}, "b": {}}, {"a": 1}, []])
def test_a_probe_without_exactly_one_usable_node_failed(nodes: Any) -> None:
    assert not he.readings_from_node_stats({**GOOD, "nodes": nodes}, T0).probe_ok


@pytest.mark.parametrize(
    ("available", "percent"), [(0, 100.0), (3, 0.0), (1, 66.67), (4, None), (-1, None)]
)
def test_disk_percent_bounds_and_rounding(available: int, percent: float | None) -> None:
    node = {"fs": {"total": {"total_in_bytes": 3, "available_in_bytes": available}}}
    assert he.readings_from_node_stats({**GOOD, "nodes": {"n": node}}, T0).disk_percent == percent


# --------------------------------------------------------------------------- responses


def test_overload_types_and_messages() -> None:
    with pytest.raises(OverloadedError):
        rs.check_status(500, {"error": {"type": "too_many_requests"}})
    with pytest.raises(OverloadedError, match=r"^HTTP 429$"):
        rs.check_status(429, None)


def test_error_types_up_to_100_characters() -> None:
    body = {"error": {"type": "x" * 100, "root_cause": [{"type": "y" * 101}]}}
    assert rs.error_types(body) == ("x" * 100,)


ANSWER = {"timed_out": False, "_shards": {"total": 1, "successful": 1, "failed": 0},
          "hits": {"hits": []}}  # fmt: skip


@pytest.mark.parametrize(
    ("endpoint", "body", "message"),
    [
        (Endpoint.SEARCH, [], "the answer is not a JSON object"),
        (Endpoint.SEARCH, {}, "the search timed out (or did not say it did not)"),
        (Endpoint.SEARCH, {**ANSWER, "terminated_early": True}, "the search terminated early"),
        (Endpoint.SEARCH, {"timed_out": False}, "the answer has no shard summary"),
        (Endpoint.SEARCH, {**ANSWER, "_shards": {"total": "1"}}, "the shard summary is malformed"),
        (Endpoint.SEARCH, {**ANSWER, "_shards": {"total": 2, "successful": 1, "failed": 0}},
         "shards failed or were not searched"),
        (Endpoint.SEARCH, {**ANSWER, "hits": {}}, "the answer has no hits list"),
        (Endpoint.MGET, {}, "the answer has no docs list"),
        (Endpoint.MGET, {"docs": [1]}, "a document could not be read"),
        (Endpoint.MGET, {"docs": [{"found": True, "error": {}}]}, "a document could not be read"),
        (Endpoint.MGET, {"docs": [{"_id": "a"}]}, "a document could not be read"),
    ],
)  # fmt: skip
def test_incomplete_answers(endpoint: Endpoint, body: Any, message: str) -> None:
    with pytest.raises(Exception) as info:  # noqa: PT011 - checked below
        rs.check_complete(endpoint, body)
    assert str(info.value) == message
    assert isinstance(info.value, rs.ResponseError)


def test_complete_mget_and_zero_took() -> None:
    rs.check_complete(Endpoint.MGET, {"docs": [{"found": False}]})
    assert rs.took_ms(Endpoint.SEARCH, {"took": 0}, 5.0) == 0
    with pytest.raises(PartialResultError):
        rs.check_complete(Endpoint.SEARCH, {**ANSWER, "_shards": {"total": 0, "successful": 0,
                                                                  "failed": 0}})  # fmt: skip


# --------------------------------------------------------------------------- transport


def sender(handler: Any) -> tr.HttpxTransport:
    out = tr.HttpxTransport("https://127.0.0.1:9", ssl.create_default_context(), SecretStr("k"))
    out.client = httpx.AsyncClient(base_url="https://127.0.0.1:9",
                                   transport=httpx.MockTransport(handler))  # fmt: skip
    return out


REQUEST = tr.WireRequest("GET", "/", (), None, "argus-c/t@1", 5.0)


def test_transport_constants_and_frozenness() -> None:
    assert tr.MAX_RESPONSE_BYTES == 33_554_432
    frozen(REQUEST, tr.WireResponse(200, b"", 1.0), tr.CaSummary("x", T0))
    pool = tr.HttpxTransport(
        "https://127.0.0.1:9", ssl.create_default_context(), SecretStr("k")
    ).client._transport._pool  # type: ignore[attr-defined]
    assert (pool._max_connections, pool._max_keepalive_connections) == (2, 2)
    with pytest.raises(ValueError, match=r"^the SIEM is reached over https only$"):
        tr.HttpxTransport("http://x", ssl.create_default_context(), SecretStr("k"))


def test_paths_keep_index_and_pattern_characters() -> None:
    spec = Spec("t", 1, Endpoint.SEARCH, Family.ALERTS, CostClass.LIGHT)
    assert tr.wire_path(FinalRequest(spec, ("a.b-c_d+e", "f"))) == ("POST", "/a.b-c_d+e,f/_search")
    listing = Spec("t", 1, Endpoint.RESOLVE_INDEX, Family.CLUSTER, CostClass.PROBE)
    assert tr.wire_path(FinalRequest(listing, (), "a.b-c_d+*")) == (
        "GET", "/_resolve/index/a.b-c_d+*",
    )  # fmt: skip


def test_a_certificate_without_a_common_name() -> None:
    assert tr.ca_summary(DATA / "no-cn-ca.crt").subject == "(no common name)"


async def test_close_and_failures() -> None:
    def refused(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    out = sender(refused)
    with pytest.raises(TransportFailedError, match=r"^connection failed$") as caught:
        await out.send(REQUEST)
    assert caught.value.reached is False
    assert caught.value.retriable is True
    await out.aclose()
    assert out.client.is_closed


@pytest.mark.parametrize(
    ("error", "kind", "message", "reached", "retriable"),
    [
        (httpx.ConnectTimeout("x"), TimedOutError, "no connection before the deadline", False,
         False),
        (httpx.PoolTimeout("x"), TimedOutError, "no connection before the deadline", False,
         False),
        (httpx.ReadTimeout("x"), TimedOutError, "no response before the deadline", True, False),
        (httpx.ReadError("x"), TransportFailedError, "connection failed or reset", True, True),
        (httpx.RemoteProtocolError("x"), TransportFailedError, "connection failed or reset",
         True, True),
    ],
)  # fmt: skip
async def test_whether_a_failure_reached_siem(
    error: Exception, kind: type, message: str, reached: bool, retriable: bool
) -> None:
    def fail(request: httpx.Request) -> httpx.Response:
        raise error

    with pytest.raises(kind) as caught:
        await sender(fail).send(REQUEST)
    assert type(caught.value) is kind
    assert str(caught.value) == message
    assert caught.value.reached is reached
    assert caught.value.retriable is retriable


def test_errors_reach_by_default() -> None:
    assert TransportFailedError("x", retriable=True).reached is True
    assert TimedOutError().reached is True


async def test_the_body_and_the_elapsed_time(monkeypatch: pytest.MonkeyPatch) -> None:
    async def chunks() -> Any:
        for part in (b"ab", b"cd", b"ef"):
            yield part

    ticks = iter([10.0, 10.25])

    class Clock:
        @staticmethod
        def monotonic() -> float:
            return next(ticks)

    monkeypatch.setattr(tr, "time", Clock)
    response = await sender(lambda request: httpx.Response(200, content=chunks())).send(REQUEST)
    assert (response.body, response.elapsed_ms) == (b"abcdef", 250.0)


# --------------------------------------------------------------------------- cassettes

WIRE = tr.WireRequest("POST", "/a/_search", (("z", "1"), ("a", "2")),
                      b'{"size":1,"query":{"b":1,"a":2},"timeout":"9s"}',
                      "argus-collector/alerts.ids@1", 5.0)  # fmt: skip


def test_the_cassette_key_is_pinned() -> None:
    canonical = json.dumps(
        [1, "alerts.ids@1", "POST", "/a/_search", [["a", "2"], ["z", "1"]],
         {"query": {"a": 2, "b": 1}, "size": 1}],
        sort_keys=True, separators=(",", ":"),
    )  # fmt: skip
    assert ca.FORMAT == 1
    assert ca.cassette_key(WIRE) == hashlib.sha256(canonical.encode()).hexdigest()
    reordered = dataclasses.replace(WIRE, body=b'{"query":{"a":2,"b":1},"size":1}')
    assert ca.cassette_key(reordered) == ca.cassette_key(WIRE)


class Inner:
    async def send(self, request: tr.WireRequest) -> tr.WireResponse:
        return tr.WireResponse(200, b"\xffok", 5.06)


async def test_recording_entries_and_replay_misses(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match=r"^recording needs a transport to record from$"):
        ca.CassetteTransport(tmp_path / "x.json", "record")
    path = tmp_path / "deep" / "er" / "c.json"
    recorder = ca.CassetteTransport(path, "record", Inner())
    await recorder.send(WIRE)
    (entry,) = recorder.entries.values()
    assert entry == {"template": "alerts.ids@1", "path": "/a/_search", "status": 200,
                     "body": "�ok", "elapsed_ms": 5.1}  # fmt: skip
    recorder.save()
    assert recorder.changed is False
    assert path.is_file()
    assert oct(path.parent.stat().st_mode & 0o777) == "0o700"
    other = dataclasses.replace(WIRE, path="/b/_search")
    with pytest.raises(ca.CassetteMissError, match=r"^alerts.ids@1: no recorded answer"):
        await ca.CassetteTransport(path).send(other)


async def test_a_failed_save_leaves_no_temporary_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorder = ca.CassetteTransport(tmp_path / "c.json", "record", Inner())
    await recorder.send(WIRE)
    names: list[str] = []

    def fail(source: str, target: Any) -> None:
        names.append(os.path.basename(source))
        raise OSError("disk full")

    monkeypatch.setattr(ca.os, "replace", fail)
    with pytest.raises(OSError, match="disk full"):
        recorder.save()
    assert names[0].startswith(".cassette-")
    assert list(tmp_path.iterdir()) == []  # noqa: ASYNC240 - a test
    assert recorder.changed is True
