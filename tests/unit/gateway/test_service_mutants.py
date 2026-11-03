"""The health probe and the settings glue (service.py), written for mutation survivors (D-040):
every probe outcome, the probe's 20-second deadline, and the settings mappings."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from argus.config.errors import ConfigError
from argus.config.settings import SiemBudgetSettings, SiemHealthSettings, SiemSettings
from argus.gateway.budget import BudgetState
from argus.gateway.gateway import utcnow
from argus.gateway.health import HealthMemory, HealthState
from argus.gateway.service import budget_config, health_config, probe, selftest, transport
from argus.gateway.transport import HttpxTransport
from tests.unit.gateway.fakes import T0, FakeTransport, make, ok

pytestmark = pytest.mark.unit

SETTINGS = SiemSettings()
NODE = {
    "_nodes": {"failed": 0},
    "nodes": {"n": {
        "fs": {"total": {"total_in_bytes": 100, "available_in_bytes": 50}},
        "jvm": {"mem": {"heap_used_percent": 50}},
        "os": {"cpu": {"load_average": {"1m": 1.0}}},
        "thread_pool": {"search": {"queue": 0, "rejected": 0}},
    }},
}  # fmt: skip
BLOCKS = {".internal.alerts-security.alerts-acme-soc-000001": {"settings": {"index.uuid": "u"}}}
NOT_FOUND = ok({"error": {"type": "index_not_found_exception"}}, 404)


def test_settings_map_one_to_one() -> None:
    budget = SiemBudgetSettings(
        took_per_minute_ms=1_001, burst_ms=1_002, took_per_day_ms=100_003, concurrency=3,
        heavy_concurrency=2, heavy_per_minute=7, heavy_per_day=8, probes_per_minute=9,
    )  # fmt: skip
    config = budget_config(SiemSettings(budget=budget))
    assert (
        config.took_per_minute_ms, config.burst_ms, config.took_per_day_ms, config.concurrency,
        config.heavy_concurrency, config.heavy_per_minute, config.heavy_per_day,
        config.probes_per_minute,
    ) == (1_001, 1_002, 100_003, 3, 2, 7, 8, 9)  # fmt: skip
    health = SiemHealthSettings(
        disk_caution=81, disk_degraded=82, disk_stop=83, heap_caution=84, load_caution=85,
        ingest_lag_degraded=timedelta(minutes=7),
    )  # fmt: skip
    h = health_config(SiemSettings(health=health))
    assert (h.disk_caution, h.disk_degraded, h.disk_stop, h.heap_caution, h.load_caution,
            h.ingest_lag_degraded) == (81, 82, 83, 84, 85, timedelta(minutes=7))  # fmt: skip


def test_the_transport_needs_a_key_and_the_ca(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match=r"^siem.api_key is not set \(ARGUS_SIEM__API_KEY"):
        transport(SETTINGS)
    ca = Path(__file__).parent / "data" / "test-ca.crt"
    sender = transport(
        SiemSettings(url="https://siem.example:9200", api_key=SecretStr("k"), ca_file=ca)
    )
    assert isinstance(sender, HttpxTransport)
    assert str(sender.client.base_url) == "https://siem.example:9200"


async def run(transport_: FakeTransport, **kw: Any) -> tuple[HealthMemory, FakeTransport, Any]:
    gateway, sent, store, _ = make(transport_)
    for key, value in kw.items():
        setattr(store, key, value)
    memory = await probe(gateway, store, SETTINGS, T0)  # type: ignore[arg-type]
    return memory, sent, store


async def test_a_healthy_probe_is_recorded_as_the_probe() -> None:
    memory, _, store = await run(FakeTransport().on("_nodes", ok(NODE)).on("_settings", ok(BLOCKS)))
    assert memory.state is HealthState.NORMAL
    assert [e.component for e in store.ledger] == ["probe", "probe"]


@pytest.mark.parametrize(
    ("nodes", "blocks", "state", "reason", "calls"),
    [
        (ok({}, 401), None, HealthState.STOP, "auth_failed", 1),
        (ok({}, 500), None, HealthState.DEGRADED, "probe_failed", 1),
        (NOT_FOUND, None, HealthState.DEGRADED, "probe_failed", 1),
        (ok(NODE), ok([".internal.alerts-security.alerts-acme-soc-1"]),
         HealthState.DEGRADED, "probe_failed", 2),
        (ok(NODE), ok({}, 403), HealthState.STOP, "auth_failed", 2),
        (ok(NODE), NOT_FOUND, HealthState.DEGRADED, "probe_failed", 2),
    ],
)  # fmt: skip
async def test_probe_outcomes(nodes: Any, blocks: Any, state: HealthState, reason: str,
                              calls: int) -> None:  # fmt: skip
    transport_ = FakeTransport().on("_nodes", nodes)
    if blocks is not None:
        transport_.on("_settings", blocks)
    memory, sent, _ = await run(transport_)
    assert (memory.state, memory.reasons) == (state, (reason,))
    assert len(sent.calls) == calls


async def test_a_refused_blocks_probe_leaves_the_memory() -> None:
    before = HealthMemory(state=HealthState.CAUTION, probed_at=T0, reasons=("heap",))
    budget = BudgetState(refilled_at=T0, day=T0.date(), probe_starts=(T0,) * 11)
    memory, sent, _ = await run(
        FakeTransport().on("_nodes", ok(NODE)).on("_settings", ok(BLOCKS)), memory=before,
        budget=budget,
    )  # fmt: skip
    assert memory == before
    assert len(sent.calls) == 1  # node stats went; the blocks probe had no allowance left


@pytest.mark.parametrize(("wait", "sent"), [(20.0, 0), (19.5, 2)])
async def test_the_probe_waits_at_most_20_seconds(wait: float, sent: int) -> None:
    """The probe allowance is full until 20 s (or 19.5 s) from now: the probe's deadline is
    exactly 20 s, so only the shorter wait is waited out."""
    starts = (T0 - timedelta(seconds=60 - wait),) * 12
    budget = BudgetState(refilled_at=T0, day=T0.date(), probe_starts=starts)
    _, transport_, _ = await run(
        FakeTransport().on("_nodes", ok(NODE)).on("_settings", ok(BLOCKS)), budget=budget
    )
    assert len(transport_.calls) == sent


async def test_probe_and_selftest_default_to_now() -> None:
    gateway, sent, store, _ = make(
        FakeTransport().on("_nodes", ok(NODE)).on("_settings", ok(BLOCKS))
    )
    gateway.clock = utcnow
    store.memory = HealthMemory(probed_at=gateway.clock())
    memory = await probe(gateway, store, SETTINGS)  # type: ignore[arg-type]
    assert memory.probed_at is not None
    info = {"version": {"number": "8.19.12"}}
    auth = {"authentication_type": "api_key"}
    sent.on("/_security/_authenticate", ok(auth)).on("_has_privileges", ok({})).on("/", ok(info))
    problems = await selftest(gateway, SETTINGS)
    assert problems == ["the answer is not a privilege report"]
    assert store.ledger[-1].component == "selftest"
