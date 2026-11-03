"""The health probe and the identity self-test on Postgres state, against a scripted the SIEM."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.config.errors import ConfigError
from argus.config.settings import SiemSettings
from argus.gateway.builtin import CANARY_CLUSTER, CANARY_INDEX, REQUIRED_CLUSTER, REQUIRED_INDEX
from argus.gateway.errors import ResponseError
from argus.gateway.health import HealthState
from argus.gateway.service import build_gateway, probe, selftest, transport
from tests.unit.gateway.fakes import T0, FakeClock, FakeTransport, ok

pytestmark = pytest.mark.integration

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


def scripted(*routes: tuple[str, Any]) -> tuple[FakeTransport, FakeClock]:
    clock = FakeClock()
    sender = FakeTransport(clock=clock)
    for path, reply in routes:
        sender.on(path, reply)
    return sender, clock


async def test_a_healthy_probe(app_engine: AsyncEngine) -> None:
    sender, clock = scripted(("_nodes", ok(NODE)), ("_settings", ok(BLOCKS)))
    gateway, store = build_gateway(SETTINGS, app_engine, sender=sender)
    gateway.clock, gateway.sleep = clock, clock.sleep
    memory = await probe(gateway, store, SETTINGS, T0)
    assert (memory.state, memory.search_rejected) == (HealthState.NORMAL, 7)
    assert (await store.health()).search_rejected == 7
    blocks = next(c for c in sender.calls if "_settings" in c.path)
    assert blocks.path == (
        "/.alerts-security.alerts-acme-soc,acme-logs-squid-2026.10.09,"
        "acme-logs-dns-2026.10.09,acme-logs-nginx-2026.10.09,"
        "acme-logs-postfix-2026.10.09/_settings/index.blocks.*,index.uuid"
    )
    assert dict(blocks.params) == {"flat_settings": "true", "ignore_unavailable": "true"}


async def test_probe_outcomes(app_engine: AsyncEngine) -> None:
    blocked = {
        **BLOCKS,
        "acme-logs-squid-2026.10.09": {"settings": {"index.blocks.read_only_allow_delete": "true"}},
    }
    cases: list[tuple[tuple[tuple[str, Any], ...], HealthState, tuple[str, ...]]] = [
        ((("_nodes", ok(NODE)), ("_settings", ok(blocked))), HealthState.STOP, ("index_blocked",)),
        ((("_nodes", ok({}, 401)),), HealthState.STOP, ("auth_failed",)),
        ((("_nodes", ok({}, 500)),), HealthState.DEGRADED, ("probe_failed",)),
        (
            (("_nodes", ok(NODE)), ("_settings", ok({}, 500))),
            HealthState.DEGRADED,
            ("probe_failed",),
        ),
    ]
    for routes, state, reasons in cases:
        sender, clock = scripted(*routes)
        gateway, store = build_gateway(SETTINGS, app_engine, sender=sender)
        gateway.clock, gateway.sleep = clock, clock.sleep
        await store.save_health(type(await store.health())())
        memory = await probe(gateway, store, SETTINGS, T0)
        assert (memory.state, memory.reasons) == (state, reasons)


async def test_the_kill_switch_puts_the_health_state_in_stop(app_engine: AsyncEngine) -> None:
    sender, clock = scripted(("_nodes", ok(NODE)), ("_settings", ok(BLOCKS)))
    gateway, store = build_gateway(SETTINGS, app_engine, sender=sender)
    gateway.clock, gateway.sleep = clock, clock.sleep
    await store.set_switch("global", stopped=True, actor="tester", reason="drill")
    memory = await probe(gateway, store, SETTINGS, T0)
    assert (memory.state, memory.reasons) == (HealthState.STOP, ("kill_switch",))
    assert len(sender.calls) == 2  # the probe itself still runs


def privileges(**overrides: bool) -> dict[str, Any]:
    names = (
        ".alerts-security.alerts-acme-soc",
        "acme-logs-*",
        "abuse-ioc",
        "acme-threat-intel",
    )
    index = {
        name: {**dict.fromkeys(REQUIRED_INDEX, True), **dict.fromkeys(CANARY_INDEX, False)}
        for name in names
    }
    cluster = {**dict.fromkeys(REQUIRED_CLUSTER, True), **dict.fromkeys(CANARY_CLUSTER, False)}
    for key, value in overrides.items():
        if key in cluster:
            cluster[key] = value
        else:
            index["abuse-ioc"][key] = value
    return {"cluster": cluster, "index": index}


async def run_selftest(app_engine: AsyncEngine, info: Any, auth: Any, held: Any) -> list[str]:
    sender, clock = scripted(("_has_privileges", ok(held)), ("_authenticate", ok(auth)))
    sender.default = info
    gateway, _ = build_gateway(SETTINGS, app_engine, sender=sender)
    gateway.clock, gateway.sleep = clock, clock.sleep
    problems = await selftest(gateway, SETTINGS, T0)
    body = next(c for c in sender.calls if "_has_privileges" in c.path).body
    assert b'"acme-logs-*"' in (body or b"")
    return problems


async def test_selftest(app_engine: AsyncEngine) -> None:
    info = {"version": {"number": "8.19.12"}}
    key = {"authentication_type": "api_key", "api_key": {"name": "argus_reader"}}
    assert await run_selftest(app_engine, info, key, privileges()) == []
    problems = await run_selftest(
        app_engine,
        {"version": {"number": "9.0.0"}},
        {"authentication_type": "realm"},
        privileges(write=True, monitor=False, manage_security=True),
    )
    assert problems == [
        "server version 9.0.0 is not in the range >=8.19,<8.20",
        "not authenticated with an API key",
        "lacks cluster privilege monitor",
        "holds cluster privilege manage_security",
        "holds write on abuse-ioc",
    ]
    assert await run_selftest(app_engine, {}, {}, {}) == [
        "server version None is not in the range >=8.19,<8.20",
        "not authenticated with an API key",
        "the answer is not a privilege report",
    ]
    with pytest.raises(ResponseError):
        await run_selftest(app_engine, [], key, privileges())  # not even an object


def test_the_transport_needs_a_key_and_the_ca(tmp_path: Any) -> None:
    with pytest.raises(ConfigError, match="api_key"):
        transport(SETTINGS)
    keyed = SETTINGS.model_copy(update={"api_key": SecretStr("k")})
    with pytest.raises(ConfigError, match="ca_file"):
        transport(keyed.model_copy(update={"ca_file": tmp_path / "none.crt"}))
