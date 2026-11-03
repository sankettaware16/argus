"""The review fixes of `argus discover` (P4-D1 F1, F2, F4, F6, F7, F10, F11, F15, F17): it
remembers no failure in the shared store, probes without overwriting the health memory, survives
every legal index name, prints and writes nothing a hostile name can steer, and writes its file
whole or not at all."""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import typer
import yaml
from hypothesis import example, given, settings
from hypothesis import strategies as st

from argus import site
from argus.config.settings import SiemSettings
from argus.discover import cli, run
from argus.discover.classify import Candidate, candidates, retention_of, valid_day
from argus.discover.propose import (
    Inputs,
    Proposal,
    checked_yaml,
    propose,
    render_text,
    render_yaml,
    safe,
)
from argus.gateway.errors import DeferredError
from argus.gateway.health import HealthMemory, HealthState
from argus.gateway.kibana.writes import KibanaLaneState
from argus.gateway.service import probe
from argus.gateway.state import MemoryStore
from argus.gateway.templates import NoParams, Purpose
from argus.gateway.transport import WireRequest, WireResponse
from argus.site import SiteSettings
from tests.unit.discover.fakes import (
    NODE_STATS,
    daily_listing,
    discovery_gateways,
    elastic,
    gateways,
    kibana,
)
from tests.unit.discover.test_discover import DAILY_MAPPINGS
from tests.unit.gateway.fakes import T0, FakeTransport, ok
from tests.unit.gateway.kibana.fakes import reply

pytestmark = pytest.mark.unit

BLOCKS = {".internal.alerts-security.alerts-acme-soc-000001": {"settings": {"index.uuid": "u"}}}
MIN = timedelta(minutes=1)


def failing(
    transport: FakeTransport, when: Callable[[WireRequest], bool], status: int
) -> FakeTransport:
    """``transport`` answering ``status`` (a refusal) to the requests ``when`` picks."""
    inner = transport.send

    async def send(request: WireRequest) -> WireResponse:
        if when(request):
            transport.calls.append(request)
            body = json.dumps({"error": {"type": "security_exception"}}).encode()
            return WireResponse(status, body, 3.0)
        return await inner(request)

    transport.send = send  # type: ignore[method-assign]
    return transport


ES_READS: dict[str, Callable[[WireRequest], bool]] = {
    "version": lambda r: r.path == "/",
    "licence": lambda r: r.path == "/_license",
    "indices": lambda r: r.path == "/_resolve/index/*",
    "alerts": lambda r: r.path.startswith("/_resolve/index/.alerts"),
    "mapping": lambda r: "/_mapping/field/" in r.path,
    "privileges": lambda r: r.path == "/_security/user/_has_privileges",
    "ilm": lambda r: r.path == "/_ilm/policy",
}
KIBANA_READS = ("/api/status", "/api/spaces/space", "/api/features")


# --------------------------------------------------------------------- F1: no failure remembered


@pytest.mark.parametrize("status", [401, 403])
@pytest.mark.parametrize("read", sorted(ES_READS))
async def test_a_refused_elasticsearch_read_is_a_warning_and_the_shared_state_is_as_found(
    read: str, status: int
) -> None:
    transport = failing(
        elastic(daily_listing(), DAILY_MAPPINGS, read_ilm=True), ES_READS[read], status
    )
    es, lane, _, real, clock = discovery_gateways(transport, kibana())
    before = real.memory
    p = propose(await run.collect(es, lane, clock=clock))
    assert real.memory == before  # not STOP: the real memory was never touched
    assert real.memory.state is HealthState.NORMAL
    assert real.kibana == KibanaLaneState()
    assert any("was not read: auth_failed" in w for w in p.warnings), p.warnings
    assert "auth_failed" in [e.outcome for e in real.ledger]  # the ledger says what happened
    # the reads after it were still made (in STOP the gateway would have refused them)
    later = "licence" if read == "version" else "privileges"
    assert any(ES_READS[later](c) for c in transport.calls), [c.path for c in transport.calls]
    if read != "indices":
        assert p.families  # judged by name where a mapping could not be read


@pytest.mark.parametrize("status", [401, 403])
@pytest.mark.parametrize("path", KIBANA_READS)
async def test_a_refused_kibana_read_stops_neither_kibana_nor_elasticsearch(
    path: str, status: int
) -> None:
    server = kibana()
    server.routes[:] = [r for r in server.routes if not r[1].endswith(path)]
    server.on("GET", path, reply({"statusCode": status, "error": "Forbidden"}, status=status))
    es, lane, _, real, clock = discovery_gateways(elastic(daily_listing(), DAILY_MAPPINGS), server)
    before = real.memory
    p = propose(await run.collect(es, lane, clock=clock))
    assert real.kibana == KibanaLaneState()  # no "403 on a read", no 401 stop
    assert real.kibana.stopped is None
    assert real.memory == before
    reason = "kibana_auth_failed" if status == 401 else "kibana_forbidden"
    assert any("was not read: " + reason in w for w in p.warnings), p.warnings
    # the other two Kibana reads were still made (a stopped lane would have refused them)
    assert len(server.calls) == 3
    assert p.families  # and the Elasticsearch part is proposed whatever Kibana said


async def test_the_same_refusals_on_the_plain_store_do_stop_things() -> None:
    """The control: without the discovery store a 403 puts the SIEM in STOP, and a Kibana read's
    403 stops the lane (so the tests above would fail on the old behaviour)."""
    transport = failing(elastic(daily_listing(), DAILY_MAPPINGS), ES_READS["licence"], 403)
    es, _, store, _ = gateways(transport, None)
    await run.collect(es, None, clock=lambda: T0)
    assert store.memory.state is HealthState.STOP
    server = kibana()
    server.routes[:] = [r for r in server.routes if not r[1].endswith("/api/features")]
    server.on("GET", "/api/features", reply({"statusCode": 403}, status=403))
    es, lane, store, clock = gateways(elastic(daily_listing(), DAILY_MAPPINGS), server)
    await run.collect(es, lane, clock=clock)
    assert store.kibana.stopped == "403 on a read"


async def test_a_stopped_kibana_lane_or_a_global_switch_is_still_respected() -> None:
    real = MemoryStore(memory=HealthMemory(probed_at=T0))
    real.kibana = KibanaLaneState(stopped="401", stopped_at=T0)
    es, lane, _, _, clock = discovery_gateways(
        elastic(daily_listing(), DAILY_MAPPINGS), kibana(), real
    )
    p = propose(await run.collect(es, lane, clock=clock))
    assert len([w for w in p.warnings if w.startswith("Kibana's kibana.")]) == 3
    assert server_calls(lane) == 0  # a stopped lane sends nothing
    assert real.kibana.stopped == "401"  # and it is not changed either way
    real.stopped.add("global")
    es, _, _, _, clock = discovery_gateways(elastic(daily_listing(), DAILY_MAPPINGS), None, real)
    stopped = propose(await run.collect(es, None, clock=clock))
    assert stopped.families == ()
    assert any("stopped" in w for w in stopped.warnings)


def server_calls(lane: Any) -> int:
    return len(lane.transport.calls)


async def test_the_discovery_requests_are_ledgered_on_the_collectors_lane() -> None:
    es, lane, _, real, clock = discovery_gateways(
        elastic(daily_listing(), DAILY_MAPPINGS), kibana()
    )
    await run.collect(es, lane, clock=clock)
    discovery = [e for e in real.ledger if e.purpose == "discover"]
    assert discovery
    assert {e.lane for e in discovery} == {"collector"}  # D9: the lane is the collector's
    assert {e.component for e in discovery} == {"discover"}


# --------------------------------------------------------------------- F2: the probe before it


def memory_of(state: HealthState, reasons: tuple[str, ...], age: timedelta) -> HealthMemory:
    return HealthMemory(state=state, reasons=reasons, probed_at=T0 - age, since=T0 - age)


FRESH_BAD = [
    memory_of(HealthState.STOP, ("index_blocked",), timedelta(seconds=10)),
    memory_of(HealthState.DEGRADED, ("ingest_lag:dns", "ingest_lag:squid"), timedelta(seconds=45)),
    memory_of(HealthState.CAUTION, ("load",), timedelta(seconds=89)),
]


@pytest.mark.parametrize("memory", FRESH_BAD)
async def test_a_fresh_memory_is_the_verdict_and_no_probe_is_sent(memory: HealthMemory) -> None:
    transport = FakeTransport()
    es, _, shadow, real, clock = discovery_gateways(transport, None, MemoryStore(memory=memory))
    got = await run.siem_state(es, shadow, SiemSettings(), clock=clock)
    assert (got.state, got.reasons) == (memory.state, memory.reasons)
    assert transport.calls == []  # nothing sent
    assert real.memory == memory  # the production memory is as it was
    assert real.probes == []
    with pytest.raises(cli._RefusedError, match="discovery runs only when it is NORMAL"):
        await cli.discover_with(es, shadow, None, SiemSettings(), clock=clock)
    assert real.memory == memory
    assert transport.calls == []


async def test_a_fresh_normal_memory_lets_discovery_run_without_a_probe() -> None:
    transport = elastic(daily_listing(), DAILY_MAPPINGS)
    memory = memory_of(HealthState.NORMAL, (), timedelta(seconds=30))
    es, _, shadow, real, _ = discovery_gateways(transport, kibana(), MemoryStore(memory=memory))
    got = await run.siem_state(es, shadow, SiemSettings(), clock=lambda: T0)
    assert got.state is HealthState.NORMAL
    assert not [c for c in transport.calls if "_nodes" in c.path]
    assert real.memory == memory


async def test_the_freshness_bound_is_the_collectors_probe_interval_and_a_margin() -> None:
    from argus.collector.runner import PROBE_EVERY

    assert PROBE_EVERY + timedelta(seconds=30) == run.FRESH_FOR
    edge = memory_of(HealthState.STOP, ("index_blocked",), run.FRESH_FOR)
    transport = FakeTransport().on("_nodes", ok(NODE_STATS)).on("_settings", ok(BLOCKS))
    es, _, shadow, _, clock = discovery_gateways(transport, None, MemoryStore(memory=edge))
    await run.siem_state(es, shadow, SiemSettings(), clock=clock)
    assert [c for c in transport.calls if "_nodes" in c.path]  # at the bound it is stale


@pytest.mark.parametrize(
    "memory",
    [
        memory_of(HealthState.STOP, ("index_blocked",), 10 * MIN),
        memory_of(HealthState.DEGRADED, ("ingest_lag:dns", "ingest_lag:squid"), 2 * MIN),
        HealthMemory(),  # never probed
    ],
)
async def test_a_stale_memory_is_probed_in_full_and_the_real_memory_is_left_alone(
    memory: HealthMemory,
) -> None:
    transport = FakeTransport().on("_nodes", ok(NODE_STATS)).on("_settings", ok(BLOCKS))
    es, _, shadow, real, clock = discovery_gateways(transport, None, MemoryStore(memory=memory))
    got = await run.siem_state(es, shadow, SiemSettings(), clock=clock)
    paths = [c.path for c in transport.calls]
    assert any("_nodes" in p for p in paths)
    assert any("_settings" in p for p in paths)  # the index blocks of the site's families too
    assert got.state is HealthState.NORMAL  # a healthy, complete reading
    assert real.memory == memory  # never saved over the production memory
    assert real.probes == []  # and never recorded as a probe of Q-A3
    assert await shadow.health() == got  # this command's requests are admitted by it


async def test_a_stale_memory_with_a_blocked_index_stays_not_normal() -> None:
    blocked = {
        **BLOCKS,
        ".alerts-x": {"settings": {"index.blocks.read_only_allow_delete": "true"}},
    }
    transport = FakeTransport().on("_nodes", ok(NODE_STATS)).on("_settings", ok(blocked))
    memory = memory_of(HealthState.NORMAL, (), 10 * MIN)
    es, _, shadow, real, clock = discovery_gateways(transport, None, MemoryStore(memory=memory))
    got = await run.siem_state(es, shadow, SiemSettings(), clock=clock)
    assert (got.state, got.reasons) == (HealthState.STOP, ("index_blocked",))
    assert real.memory == memory
    with pytest.raises(cli._RefusedError):
        await cli.discover_with(es, shadow, None, SiemSettings(), clock=clock)


async def test_a_site_without_families_has_no_index_to_look_at() -> None:
    transport = FakeTransport().on("_nodes", ok(NODE_STATS))
    memory = memory_of(HealthState.NORMAL, (), 10 * MIN)
    es, _, shadow, real, clock = discovery_gateways(transport, None, MemoryStore(memory=memory))
    with site.using(SiteSettings()):
        got = await run.siem_state(es, shadow, SiemSettings(), clock=clock)
    assert got.state is HealthState.NORMAL
    assert not [c for c in transport.calls if "_settings" in c.path]
    assert real.memory == memory
    assert real.probes == []


async def test_a_probe_that_failed_leaves_discovery_refused_and_the_memory_alone() -> None:
    transport = failing(FakeTransport(), lambda r: "_nodes" in r.path, 503)
    memory = memory_of(HealthState.NORMAL, (), 10 * MIN)
    es, _, shadow, real, clock = discovery_gateways(transport, None, MemoryStore(memory=memory))
    with pytest.raises(cli._RefusedError):
        await cli.discover_with(es, shadow, None, SiemSettings(), clock=clock)
    assert real.memory == memory
    assert real.probes == []


async def test_a_partial_probe_is_never_saved_whoever_asks() -> None:
    """``indices=False`` reads node stats only; a reading without the index blocks, the ingest
    lag or the stale rules would clear what a fuller one found (F2)."""
    transport = FakeTransport().on("_nodes", ok(NODE_STATS)).on("_settings", ok(BLOCKS))
    stop = HealthMemory(state=HealthState.STOP, reasons=("index_blocked",), probed_at=T0 - 10 * MIN)
    store = MemoryStore(memory=stop)
    es, _, _, _ = gateways(transport, None, store)
    got = await probe(es, store, SiemSettings(), T0, indices=False)
    assert got.state is HealthState.NORMAL  # what the partial reading says ...
    assert store.memory == stop  # ... and is not kept
    assert store.probes == []
    full = await probe(es, store, SiemSettings(), T0)
    assert store.memory == full  # a full probe is saved as ever
    assert len(store.probes) == 1


# --------------------------------------------------------------------- F10: the quiet hours


@pytest.mark.parametrize(
    ("at", "refused"),
    [
        (datetime(2026, 10, 9, 0, 0, tzinfo=UTC), True),
        (datetime(2026, 10, 9, 1, 29, 59, tzinfo=UTC), True),
        (datetime(2026, 10, 9, 1, 30, tzinfo=UTC), False),
    ],
)
async def test_a_discovery_request_waits_for_the_end_of_the_quiet_hours(
    at: datetime, refused: bool
) -> None:
    from argus.gateway.builtin import ClusterLicense

    es, _, _, _, clock = discovery_gateways(elastic(daily_listing(), DAILY_MAPPINGS), None)
    clock.now = at
    es.state = MemoryStore(memory=HealthMemory(probed_at=at))
    call = es.run(
        ClusterLicense(),
        NoParams(),
        purpose=Purpose.DISCOVER,
        component="discover",
        deadline=at + timedelta(seconds=30),
    )
    if refused:
        with pytest.raises(DeferredError, match="quiet hours"):
            await call
    else:
        await call


# --------------------------------------------------------------------- F4, F6: legal names

ES_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789-_.+@=&'()!$%;^`{}[]~éüñß中日"
names = st.text(alphabet=ES_ALPHABET, min_size=1, max_size=40).filter(
    lambda n: n[0] not in "-_+" and n not in {".", ".."}
)
days = st.builds(
    lambda y, m, d: f"{y:04d}.{m:02d}.{d:02d}",
    st.integers(0, 9999),
    st.integers(0, 99),
    st.integers(0, 99),
)
dated = st.builds(lambda stem, sep, day: f"{stem}{sep}{day}", names, st.sampled_from("-._"), days)
listings = st.fixed_dictionaries(
    {
        "indices": st.lists(st.builds(lambda n: {"name": n}, st.one_of(names, dated)), max_size=20),
        "aliases": st.lists(st.builds(lambda n: {"name": n}, names), max_size=5),
        "data_streams": st.lists(
            st.builds(
                lambda n, backing, field: {
                    "name": n,
                    "timestamp_field": field,
                    "backing_indices": backing,
                },
                names,
                st.lists(st.builds(lambda n, d: f".ds-{n}-{d}-000001", names, days), max_size=3),
                st.one_of(st.just("@timestamp"), names),
            ),
            max_size=4,
        ),
    }
)


def printable(text: str) -> bool:
    return all(c == "\n" or c.isprintable() for c in text)


@settings(max_examples=60, deadline=None)
@given(listings)
def test_no_legal_index_name_breaks_discovery_or_its_output(listing: dict[str, Any]) -> None:
    async def go() -> Proposal:
        es, _, _, _, clock = discovery_gateways(elastic(listing, {}), None)
        return propose(await run.collect(es, None, clock=clock))

    p = asyncio.run(go())
    text = render_text(p)
    assert printable(text)
    out = checked_yaml(p)  # loads back as exactly this proposal
    assert printable(out)
    assert yaml.safe_load(out)["site"].keys() <= {"space", "kibana_features", "families"}
    skipped: list[str] = []
    for candidate in candidates(listing, skipped):
        assert site.family_pattern_ok(candidate.pattern)
        retention_of(candidate)  # never raises
    assert len(set(skipped)) == len(skipped)


def test_the_reproductions_of_the_review_no_longer_break_the_run() -> None:
    listing = daily_listing()
    listing["indices"] += [
        {"name": "café-logs-2026.10.30"},
        {"name": "my@app-2026.10.30"},
        {"name": "acme-logs-squid-2026.13.45"},
        {"name": "x-0000.00.00"},
        {"name": "y-2026.02.30"},
    ]

    async def go() -> Proposal:
        es, lane, _, _, clock = discovery_gateways(elastic(listing, DAILY_MAPPINGS), kibana())
        return propose(await run.collect(es, lane, clock=clock, max_mappings=40))

    p = asyncio.run(go())
    assert {f.family.pattern for f in p.families} >= {"acme-logs-squid-*"}
    (warning,) = [w for w in p.warnings if "names were left out" in w]
    assert "5 names were left out" in warning
    assert "café-logs-2026.10.30" in warning


@pytest.mark.parametrize(
    ("day", "valid"),
    [
        ("2026.10.30", True),
        ("2024.02.29", True),
        ("2026.02.29", False),
        ("2026.02.30", False),
        ("2026.13.45", False),
        ("0000.00.00", False),
        ("0000.01.01", False),
        ("9999.12.31", True),
        ("not.a.day", False),
    ],
)
def test_a_day_is_a_day_of_the_calendar(day: str, valid: bool) -> None:
    assert valid_day(day) is valid


def test_retention_ignores_impossible_dates() -> None:
    bad = Candidate("x-*", "daily", indices=("x-2026.13.45", "x-2026.02.30"))
    assert bad.days == ()
    assert retention_of(bad).note == "no dated index to count days from"
    mixed = Candidate("x-*", "daily", indices=("x-2026.10.01", "x-2026.13.45", "x-2026.10.03"))
    assert retention_of(mixed).days_kept == 3
    stream = Candidate(
        "s", "stream", backing=(".ds-s-2026.99.99-000001", ".ds-s-2026.10.05-000001")
    )
    assert stream.days == ("2026.10.05",)


async def test_a_mapping_read_with_a_name_the_template_cannot_take_is_a_warning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Building the parameters is inside the guard too (F4): whatever gets past the listing."""
    bad = Candidate("x-*", "daily", indices=("Caf\u00e9-2026.10.30",))
    with pytest.raises(ValueError, match="validation error"):
        run.mapping_params(bad)()
    real = run.classify.candidates
    monkeypatch.setattr(
        run.classify, "candidates", lambda listing, skipped=None: [bad, *real(listing, skipped)]
    )
    es, _, _, _, clock = discovery_gateways(elastic(daily_listing(), DAILY_MAPPINGS), None)
    inputs = await run.collect(es, None, clock=clock)
    assert any("the mapping of x-* was not read: not a name" in w for w in inputs.warnings)
    assert inputs.mappings  # and the other families' mappings were read


# --------------------------------------------------------------------- F15: an empty mapping


async def test_an_answer_that_maps_none_of_the_fields_is_no_reading_of_the_mapping() -> None:
    transport = elastic(daily_listing(), {})
    transport.routes.insert(0, ("_mapping/field", [ok({})]))  # filter_path left nothing
    es, lane, _, _, clock = discovery_gateways(transport, kibana())
    p = propose(await run.collect(es, lane, clock=clock))
    assert any("named none of the fields asked about" in w for w in p.warnings)
    named = {f.family.role.value for f in p.families}
    assert {"proxy", "web", "dns", "auth", "mail"} <= named  # judged by name, none lost
    assert all(any("mapping was not read" in n for n in f.notes) for f in p.families)


# --------------------------------------------------------------------- F7: hostile names

ESC = "\x1b[2J\x1b[Hnginx"
HOSTILE_ALIAS = (
    ".alerts-security.alerts-x\nsite:\n  elastic_versions: '*'\n  kibana_versions: '*'\n#"
)


def test_safe_makes_text_fit_to_print() -> None:
    assert safe("a\x1bb\rc\nd\x07e\x7ff\x85g\u2028h\u200bi\u202ej") == "a?b?c?d?e?f?g?h?i?j"
    assert safe("x" * 300, 120) == "x" * 119 + "…"
    assert safe("café 日本: ok") == "café 日本: ok"
    assert safe(None) == "None"


def test_hostile_names_reach_neither_the_terminal_nor_the_yaml() -> None:
    listing = {
        "indices": [
            {"name": f"{ESC}-2026.10.30"},
            {"name": "zz\rLog families proposed: 0-2026.10.30"},
            {"name": "plain-2026.10.30"},
        ],
        "aliases": [{"name": "alias\x1b[31m-red"}],
        "data_streams": [],
    }
    p = propose(
        Inputs(
            data=listing,
            alerts={"aliases": [{"name": HOSTILE_ALIAS}, {"name": ".alerts-security.alerts-ok"}]},
            spaces=[{"id": "ok", "name": "Ok"}, {"id": "x\ny", "name": "bad"}],
            elastic_version="8.19.12\nsite: {space: evil}",
            kibana_version="\x1b[2J9",
            warnings=("read \x1b[31m failed\r",),
            now=datetime(2026, 10, 31, tzinfo=UTC),
        )
    )
    text = render_text(p)
    assert "\x1b" not in text
    assert "\r" not in text
    assert printable(text)
    assert p.space == "ok"  # the hostile alias is no space
    assert any("alerts aliases were left out" in w for w in p.warnings)
    out = checked_yaml(p)
    assert printable(out)
    loaded = yaml.safe_load(out)["site"]
    assert "elastic_versions" not in loaded
    assert "kibana_versions" not in loaded
    assert loaded.get("space") in (None, "ok")
    assert out.splitlines()[0].startswith("# Proposed by `argus discover`")
    assert all(line.startswith(("#", "site:", " ")) or not line for line in out.splitlines())


def test_a_yaml_that_would_not_load_back_as_the_proposal_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from argus.discover import propose as module

    p = propose(Inputs(data=daily_listing()))
    assert checked_yaml(p) == render_yaml(p)
    monkeypatch.setattr(module, "render_yaml", lambda _p: "site:\n  space: elsewhere\n")
    with pytest.raises(ValueError, match="does not load back"):
        checked_yaml(p)
    monkeypatch.setattr(module, "render_yaml", lambda _p: "site: [unclosed\n")
    with pytest.raises(ValueError, match="does not load back"):
        checked_yaml(p)
    monkeypatch.setattr(module, "render_yaml", lambda _p: "not a mapping")
    with pytest.raises(ValueError, match="does not load back"):
        checked_yaml(p)


def test_the_command_writes_nothing_when_the_yaml_does_not_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from typer.testing import CliRunner

    from argus.cli import app

    config = tmp_path / "argus.yaml"
    config.write_text("environment: dev\n", encoding="utf-8")
    proposal = propose(Inputs(data=daily_listing()))

    async def fake(settings: object, max_mappings: int, no_kibana: bool) -> Proposal:
        return proposal

    def broken(_p: Proposal) -> str:
        raise ValueError("the proposed YAML does not load back as the proposal")

    monkeypatch.setattr(cli, "_discover", fake)
    monkeypatch.setattr(cli, "checked_yaml", broken)
    monkeypatch.setattr(cli, "in_quiet_hours", lambda now: False)
    result = CliRunner().invoke(app, ["discover", "--write", "--config", str(config)])
    assert result.exit_code == 1
    assert "nothing is shown as YAML and nothing is written" in result.output
    assert not (tmp_path / "site.yaml").exists()


# --------------------------------------------------------------------- F11: the file whole


def test_a_forced_write_keeps_the_old_file_when_the_new_one_cannot_be_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "site.yaml"
    target.write_text("site:\n  space: old\n", encoding="utf-8")

    def refuse(_fd: int) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "fsync", refuse)
    with pytest.raises(typer.Exit) as caught:
        cli._write(target, "site:\n  space: new\n", force=True)
    assert caught.value.exit_code == 1
    assert target.read_text(encoding="utf-8") == "site:\n  space: old\n"
    assert [p.name for p in tmp_path.iterdir()] == ["site.yaml"]  # and no temporary file left


def test_a_new_file_that_cannot_be_written_is_not_left_half_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "site.yaml"

    def refuse(_fd: int) -> None:
        raise OSError(5, "Input/output error")

    monkeypatch.setattr(os, "fsync", refuse)
    with pytest.raises(typer.Exit) as caught:
        cli._write(target, "site:\n  space: new\n", force=False)
    assert caught.value.exit_code == 1
    assert list(tmp_path.iterdir()) == []


def test_the_written_file_is_group_readable_and_replaced_whole(tmp_path: Path) -> None:
    target = tmp_path / "site.yaml"
    target.write_text("old", encoding="utf-8")
    target.chmod(0o600)
    cli._write(target, "new\n", force=True)
    assert target.read_text(encoding="utf-8") == "new\n"
    assert target.stat().st_mode & 0o777 == 0o644
    other = tmp_path / "fresh.yaml"
    cli._write(other, "fresh\n", force=False)
    assert other.stat().st_mode & 0o777 == 0o644


def test_a_file_that_appears_meanwhile_is_never_written_over(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "site.yaml"
    target.write_text("theirs", encoding="utf-8")
    monkeypatch.setattr(Path, "exists", lambda self: False)  # the check came first, and passed
    with pytest.raises(typer.Exit) as caught:
        cli._write(target, "mine", force=False)
    assert caught.value.exit_code == 2
    assert target.read_text(encoding="utf-8") == "theirs"


def test_a_dangling_link_is_not_written_through(tmp_path: Path) -> None:
    target = tmp_path / "site.yaml"
    target.symlink_to(tmp_path / "nowhere")
    for force in (False, True):
        with pytest.raises(typer.Exit) as caught:
            cli._write(target, "x", force=force)
        assert caught.value.exit_code == 1
    assert not (tmp_path / "nowhere").exists()


# --------------------------------------------------------------------- junk answers


junk = st.recursive(
    st.one_of(st.none(), st.booleans(), st.integers(), st.text(max_size=8)),
    lambda inner: st.one_of(
        st.lists(inner, max_size=3), st.dictionaries(st.text(max_size=8), inner, max_size=3)
    ),
    max_leaves=8,
)


def answering(
    transport: FakeTransport, when: Callable[[WireRequest], bool], body: Any
) -> FakeTransport:
    """``transport`` answering 200 with ``body`` to the requests ``when`` picks."""
    inner = transport.send

    async def send(request: WireRequest) -> WireResponse:
        if when(request):
            transport.calls.append(request)
            return ok(body)
        return await inner(request)

    transport.send = send  # type: ignore[method-assign]
    return transport


@example(read="version", body={"version": "8.19.12"})  # a version that is not an object
@example(read="version", body={"version": ["x"]})
@example(read="indices", body={"indices": "x", "aliases": 3, "data_streams": [None, "a", {}]})
@example(read="mapping", body={"idx": {"mappings": ["x"]}})
@example(read="mapping", body={"idx": {"mappings": {"url.path": "x"}}})
@example(read="ilm", body={"p": {"in_use_by": "x", "policy": {"phases": []}}})
@example(read="privileges", body={"cluster": "x"})
@example(read="licence", body={"license": ["x"]})
@settings(max_examples=80, deadline=None)
@given(st.sampled_from([*sorted(ES_READS), *KIBANA_READS]), junk)
def test_a_malformed_answer_to_any_read_is_a_warning_and_never_a_crash(
    read: str, body: Any
) -> None:
    async def go() -> Proposal:
        server = kibana()
        transport = elastic(daily_listing(), DAILY_MAPPINGS, read_ilm=True)
        if read in ES_READS:
            transport = answering(transport, ES_READS[read], body)
        else:
            server.routes[:] = [r for r in server.routes if not r[1].endswith(read)]
            server.on("GET", read, reply(body))
        es, lane, _, _, clock = discovery_gateways(transport, server)
        return propose(await run.collect(es, lane, clock=clock))

    p = asyncio.run(go())
    assert printable(render_text(p))
    checked_yaml(p)
