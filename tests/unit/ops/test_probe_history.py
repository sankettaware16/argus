"""Q-A2: every health probe's readings are kept (for Q-A3's re-measurement), from what the probe
read anyway: no request is added, and losing a reading never fails the probe."""

from __future__ import annotations

import json
import logging
import math
from datetime import timedelta
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from sqlalchemy import BigInteger, Integer, SmallInteger

from argus.config.settings import SiemSettings
from argus.db.models import SiemProbe
from argus.gateway.budget import BudgetConfig, BudgetState
from argus.gateway.health import HealthMemory, HealthState, Readings
from argus.gateway.pgstore import probe_row
from argus.gateway.service import probe
from argus.gateway.state import MemoryStore
from tests.unit.gateway.fakes import T0, FakeTransport, make, ok

pytestmark = pytest.mark.unit

SETTINGS = SiemSettings()
NODE = {
    "_nodes": {"total": 1, "successful": 1, "failed": 0},
    "nodes": {
        "n": {
            "fs": {"total": {"total_in_bytes": 100, "available_in_bytes": 40}},
            "jvm": {"mem": {"heap_used_percent": 50}},
            "os": {"cpu": {"load_average": {"1m": 2.0}}},
            "thread_pool": {"search": {"queue": 0, "rejected": 7}, "write": {"rejected": 3}},
            "breakers": {"parent": {"tripped": 0}},
        }
    },
}
BLOCKS = {".internal.alerts-security.alerts-acme-soc-000001": {"settings": {"index.uuid": "u"}}}


def answers() -> FakeTransport:
    return FakeTransport().on("_nodes", ok(NODE)).on("_settings", ok(BLOCKS))


async def test_a_probe_keeps_what_it_read_and_sends_nothing_more() -> None:
    gateway, sent, store, _ = make(answers())
    memory = await probe(gateway, store, SETTINGS, T0)
    assert len(sent.calls) == 2  # node stats and index blocks, as before Q-A2
    ((readings, kept),) = store.probes
    assert kept == memory
    assert (readings.disk_percent, readings.heap_percent, readings.search_rejected) == (60.0, 50, 7)
    row = probe_row(readings, memory)
    assert (row["state"], row["disk"], row["rejected"], row["write_rejected"]) == (
        "normal", 60.0, 7, 3)  # fmt: skip
    assert json.loads(row["lag"]) == {}


async def test_a_failed_probe_is_kept_too() -> None:
    gateway, _, store, _ = make(FakeTransport().on("_nodes", ok({}, status=500)))
    memory = await probe(gateway, store, SETTINGS, T0)
    ((readings, _),) = store.probes
    assert readings.probe_ok is False
    assert "probe_failed" in memory.reasons


async def test_a_probe_the_gateway_refused_learnt_nothing_and_keeps_nothing() -> None:
    gateway, sent, store, _ = make(answers())
    store.budget = BudgetState(
        refilled_at=T0, day=T0.date(), probe_starts=(T0,) * BudgetConfig().probes_per_minute
    )  # the probe allowance is spent: the gateway refuses before sending
    await probe(gateway, store, SETTINGS, T0)
    assert (sent.calls, store.probes) == ([], [])


class _Broken(MemoryStore):
    async def record_probe(self, readings: Readings, memory: HealthMemory) -> None:
        raise RuntimeError("relation siem_probes does not exist")


async def test_losing_a_reading_never_fails_the_probe(caplog: pytest.LogCaptureFixture) -> None:
    store = _Broken(memory=HealthMemory(probed_at=T0))
    gateway, _, _, _ = make(answers(), store=store)
    with caplog.at_level(logging.WARNING, logger="argus.gateway"):
        memory = await probe(gateway, store, SETTINGS, T0)
    assert memory.state is HealthState.NORMAL
    assert (await store.health()) == memory  # the state itself was saved
    assert "probe readings not stored: RuntimeError" in caplog.text


finite = st.floats(allow_nan=True, allow_infinity=True)
# every column's limit is reached: a value that passes the code but not the column's width would
# fail the insert and lose the whole reading (QA2-R5)
counts = st.one_of(
    st.none(),
    st.integers(min_value=-(2**70), max_value=2**70),
    st.sampled_from([2**31 - 1, 2**31, 2**63 - 1, 2**63]),
)
COUNTERS = {"queue": "search_queue", "rejected": "search_rejected",
            "tripped": "breakers_tripped", "write_rejected": "write_rejected",
            "stale": "stale_rules"}  # fmt: skip


def column_limit(column: str) -> int:
    """The largest value ``siem_probes.<column>`` holds, from the model's type."""
    kind = SiemProbe.__table__.c[column].type
    if isinstance(kind, BigInteger):
        return 2**63 - 1
    if isinstance(kind, SmallInteger):
        return 2**15 - 1
    assert isinstance(kind, Integer), kind
    return 2**31 - 1


def test_every_counter_column_holds_what_the_code_lets_through() -> None:
    row = probe_row(
        Readings(at=T0, search_queue=2**63 - 1, search_rejected=2**63 - 1,
                 breakers_tripped=2**63 - 1, write_rejected=2**63 - 1, stale_rules=2**31),
        HealthMemory(),
    )  # fmt: skip
    for counter, column in COUNTERS.items():
        assert row[counter] is not None, counter
        assert row[counter] <= column_limit(column), counter


@given(
    disk=st.one_of(st.none(), finite),
    heap=st.one_of(st.none(), finite),
    load=st.one_of(st.none(), finite),
    queue=counts,
    rejected=counts,
    tripped=counts,
    stale=counts,
    lag=st.dictionaries(st.text(max_size=300), st.timedeltas(max_value=timedelta(days=9))),
    blocked=st.lists(st.text(max_size=400), max_size=5),
)
def test_a_row_always_satisfies_the_table_constraints(
    disk: float | None,
    heap: float | None,
    load: float | None,
    queue: int | None,
    rejected: int | None,
    tripped: int | None,
    stale: int | None,
    lag: dict[str, timedelta],
    blocked: list[str],
) -> None:
    """Whatever the SIEM answers, the stored row passes siem_probes' checks, so a strange reading
    is stored as unknown rather than failing the insert."""
    readings = Readings(
        at=T0, disk_percent=disk, heap_percent=heap, load_1m=load, search_queue=queue,
        search_rejected=rejected, breakers_tripped=tripped, write_rejected=rejected,
        blocked_indices=tuple(blocked), ingest_lag=lag, stale_rules=stale,
    )  # fmt: skip
    row = probe_row(readings, HealthMemory(state=HealthState.CAUTION, reasons=("disk_caution",)))
    for gauge, high in (("disk", 100.0), ("heap", 100.0), ("load", None)):
        value: Any = row[gauge]
        assert value is None or (math.isfinite(value) and value >= 0)
        assert value is None or high is None or value <= high
    for counter, column in COUNTERS.items():
        value = row[counter]
        assert value is None or 0 <= value <= column_limit(column), (counter, value)
    assert row["state"] in ("normal", "caution", "degraded", "stop")
    stored = json.loads(row["lag"])
    assert all(isinstance(v, float | int) for v in stored.values())
    assert all(len(name) <= 300 for name in row["blocked"])


@pytest.mark.parametrize(
    ("value", "kept"),
    [(None, None), (0.0, 0.0), (100.0, 100.0), (100.0001, None), (-0.1, None),
     (float("nan"), None), (float("inf"), None), (True, None), ("50", None)],
)  # fmt: skip
def test_a_percentage_outside_0_to_100_is_unknown(value: Any, kept: Any) -> None:
    row = probe_row(Readings(at=T0, disk_percent=value), HealthMemory())
    assert row["disk"] == kept
