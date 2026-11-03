"""Q-F3: how the wave's answers reach a dossier. The batch-1 readings in the generic pack (inert
without such evidence), the wave pack's ident, and which references a new dossier is derived
from."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from argus.context import batch1, beacon
from argus.context.evidence import SignalValue, content
from argus.context.generic import GenericPack
from argus.context.packs import WAVE_IDENT, PackRegistry, StubPack, WavePack, default_registry
from argus.investigation import wave
from tests.unit.investigation.kit import C2, HOST, NOW, body, step

pytestmark = pytest.mark.unit
START = datetime(2026, 10, 24, 9, 0, tzinfo=UTC)


def pair_params(**over: Any) -> beacon.PairParams:
    base: dict[str, Any] = {"host": HOST, "destination": C2, "start": START,
                            "end": START + timedelta(hours=2)}  # fmt: skip
    return beacon.PairParams(**{**base, **over})


def pair_ref(status: str = "ok", params: beacon.PairParams | None = None) -> dict[str, Any]:
    task = batch1.TaskSpec(beacon.ProxyPair(), params or pair_params())
    ref = task.ref()
    return {
        "task_key": ref["task_key"], "template": "proxy.pair@1", "status": status,
        "coverage": {}, "row_count": None, "truncated": False,
        "result_hash": "h" * 64 if status in ("ok", "empty") else None,
        "params": ref["params"],
    }  # fmt: skip


def beats(minutes: list[int]) -> dict[str, Any]:
    base = int(START.timestamp() * 1000)
    return {"aggregations": {
        "beats": {"buckets": [{"key": base + m * 60_000, "doc_count": 1} for m in minutes]},
        "requests": {"value": len(minutes)},
        "first": {"value": base + minutes[0] * 60_000},
        "last": {"value": base + minutes[-1] * 60_000 + 7_000},
    }}  # fmt: skip


FIVE = [0, 5, 10, 14, 19, *range(25, 120, 5)]


def by_name(signals: list[SignalValue]) -> dict[str, SignalValue]:
    return {s.name: s for s in signals}


# ----------------------------------------------------------------------------- readings


def test_a_reference_names_its_batch_1_task() -> None:
    ref = pair_ref()
    task = batch1.task_of(ref)
    assert task is not None
    assert task.params == pair_params()
    assert batch1.is_batch1(ref)
    assert batch1.task_of({**ref, "template": "proxy.pair@2"}) is None  # another version
    assert batch1.task_of({**ref, "params": {"host": "not an address"}}) is None
    assert batch1.task_of({k: v for k, v in ref.items() if k != "params"}) is None
    assert batch1.task_of({**ref, "template": "proxy.host@1"}) is None
    assert not batch1.is_batch1({"template": "proxy.host@1"})
    assert batch1.is_batch1({"template": "proxy.pair@9"})  # any version is still batch-1's


def test_the_pairs_rhythm_is_read_from_its_answer() -> None:
    ref = pair_ref()
    got = by_name(batch1.signals(12, {ref["task_key"]: ref}, {ref["task_key"]: beats(FIVE)}))
    assert got["pair.period_s"].value == 300
    assert got["pair.beats"].status == "known"
    assert got["pair.still_active"].value is True  # the last beat is within two periods of the end


def test_a_failed_pair_gives_unknown_signals_not_a_negative() -> None:
    ref = pair_ref("timeout")
    got = batch1.signals(12, {ref["task_key"]: ref}, {})
    assert got
    assert all(s.status == "unknown" and s.unknown_reason == "timeout" for s in got)


def test_one_subject_per_template_the_first_complete_one() -> None:
    a, b = (
        pair_ref(params=pair_params(host="10.20.3.4")),
        pair_ref(params=pair_params(host="10.20.3.9")),
    )
    assert a["task_key"] != b["task_key"]
    low, high = sorted((a, b), key=lambda r: r["task_key"])
    snaps = {low["task_key"]: beats(FIVE), high["task_key"]: beats([0, 1, 2])}
    evidence = {low["task_key"]: low, high["task_key"]: high}
    same = batch1.signals(12, evidence, snaps)
    assert same == batch1.signals(12, dict(reversed(list(evidence.items()))), snaps)
    assert len([s for s in same if s.name == "pair.beats"]) == 1
    failed = {**low, "status": "timeout", "result_hash": None}
    got = by_name(batch1.signals(12, {low["task_key"]: failed, high["task_key"]: high}, snaps))
    assert got["pair.beats"].evidence == (high["task_key"],)  # the complete one is read


def test_no_batch_1_reference_no_signal() -> None:
    assert batch1.signals(12, {}, {}) == []
    assert batch1.signals(12, {"k": {"template": "proxy.host@1", "status": "ok"}}, {}) == []


# ----------------------------------------------------------------------------- the pack


def context() -> dict[str, Any]:
    dossier = body(steps=[step(2, "deferred", ["timeline"])])
    return {"facts": dossier["facts"], "context": dossier["context"]}


def test_without_batch_1_evidence_the_pack_is_what_it_was() -> None:
    pack = GenericPack()
    c = context()
    signals = pack.signals(c["facts"], c["context"], {}, {})
    assert not any(s.name.split(".")[0] in ("pair", "contact", "dns", "source_events")
                   or s.name.startswith("web.paths") for s in signals)  # fmt: skip
    assert pack.version == 12  # a dossier it made, and its hash, are unchanged
    steps = pack.report(c["facts"], c["context"], {}, [s.as_dict() for s in signals])["steps"]
    assert steps[0]["status"] == "deferred"


def test_a_known_rhythm_answers_the_notes_timeline_step() -> None:
    pack = GenericPack()
    c = context()
    ref = pair_ref()
    evidence, snaps = {ref["task_key"]: ref}, {ref["task_key"]: beats(FIVE)}
    signals = pack.signals(c["facts"], c["context"], evidence, snaps)
    assert by_name(signals)["pair.period_s"].value == 300
    report = pack.report(c["facts"], c["context"], evidence, [s.as_dict() for s in signals])
    (step_,) = report["steps"]
    assert step_["status"] == "answered"
    assert "about every 5 minutes" in step_["sentence"]
    assert "10.20.3.4" not in step_["sentence"]  # no value from the logs enters a sentence
    counts = {s.name: s.value for s in signals if s.name.startswith("steps.")}
    assert counts == {"steps.answered": 1, "steps.deferred": 0, "steps.manual": 0,
                      "steps.unknown": 0}  # fmt: skip


def test_a_failed_batch_1_check_leaves_the_threat_list_readings_alone() -> None:
    """The threat-intel module cites every reference it is given; the wave's own checks are not
    given to it, so a timed-out pair cannot make a threat-list reading unknown."""
    pack = GenericPack()
    c = context()
    ref = pair_ref("timeout")
    plain = pack.signals(c["facts"], c["context"], {}, {})
    with_failure = pack.signals(c["facts"], c["context"], {ref["task_key"]: ref}, {})
    keep = {s.name: s for s in plain}
    for s in with_failure:
        if s.name in keep and not s.name.startswith("steps."):
            assert s == keep[s.name], s.name
    assert not any(s.name == "ti.listed_remote" for s in with_failure)


# ----------------------------------------------------------------------------- the wave pack


def test_a_wave_pack_has_its_own_ident_and_reads_as_its_base() -> None:
    base = GenericPack()
    wave_pack = WavePack(base, 2)
    assert wave_pack.ident == "generic+wave.2@12"
    assert wave_pack.family == "generic"
    assert wave_pack.max_waves == 0
    c = context()
    ref = pair_ref()
    evidence, snaps = {ref["task_key"]: ref}, {ref["task_key"]: beats(FIVE)}
    assert wave_pack.local_signals(c["facts"], c["context"]) == base.local_signals(
        c["facts"], c["context"]
    )
    one = wave_pack.signals(c["facts"], c["context"], evidence, snaps)
    assert one == base.signals(c["facts"], c["context"], evidence, snaps)
    assert wave_pack.report(c["facts"], c["context"], evidence, []) == base.report(
        c["facts"], c["context"], evidence, []
    )
    with pytest.raises(ValueError, match="1 to 99"):
        WavePack(base, 0)


def test_the_registry_finds_a_wave_dossiers_pack() -> None:
    registry = default_registry()
    found = registry.get("generic+wave.3@12")
    assert isinstance(found, WavePack)
    assert found.ident == "generic+wave.3@12"
    assert registry.get("generic@12") is registry.get("generic@12")
    for ident in (
        "generic+wave.3@11", "other+wave.1@12", "generic+wave.0@12", "generic+wave.100@12",
        "generic+wave.1@12+wave.1@12", "generic+wave.x@12", "",
    ):  # fmt: skip
        assert registry.get(ident) is None, ident
    assert registry.resolve({}).ident == "generic@12"  # a wave pack is never picked for new work


def test_a_wave_pack_is_not_a_family() -> None:
    registry = PackRegistry([StubPack()], default="generic")
    assert registry.get("stub+wave.1@1") is not None
    assert WAVE_IDENT.match("stub+wave.1@1")
    with pytest.raises(ValueError, match="one pack per family"):
        PackRegistry([StubPack(), WavePack(StubPack(), 1)])  # only real packs are registered


# ----------------------------------------------------------------------------- feeding


def ref_of(key: str, template: str, status: str = "ok", **extra: Any) -> dict[str, Any]:
    return {"task_key": key, "template": f"{template}@1", "status": status, "coverage": {},
            "row_count": 1, "truncated": False, "result_hash": "h" * 64, **extra}  # fmt: skip


def test_a_new_reference_of_a_held_template_is_taken_only_for_the_same_request() -> None:
    base = {"a": ref_of("a", "proxy.host", "timeout")}
    retried = {"a": ref_of("a", "proxy.host", "ok", reused=False)}
    other_host = {"b": ref_of("b", "proxy.host")}
    new_template = {"c": ref_of("c", "proxy.destination")}
    assert wave.feed(base, retried)["a"]["status"] == "ok"
    assert set(wave.feed(base, other_host)) == {"a"}  # another subject: a check of its own
    assert set(wave.feed(base, new_template)) == {"a", "c"}
    assert list(wave.feed(base, {**new_template, **retried})) == ["a", "c"]  # sorted by key


def test_changed_looks_at_content_not_at_reuse() -> None:
    base = {"a": ref_of("a", "proxy.host")}
    assert not wave.changed(base, {"a": ref_of("a", "proxy.host", reused=True)})
    assert wave.changed(base, {"a": ref_of("a", "proxy.host", "timeout")})
    assert wave.changed(base, {**base, "b": ref_of("b", "proxy.destination")})
    assert not wave.changed(base, wave.feed(base, {}))
    assert content({"x": 1, "reused": True}) == {"x": 1}


def test_a_fed_batch_1_reference_keeps_its_params_in_the_dossier_body() -> None:
    ref = pair_ref()
    fed = wave.feed({}, {ref["task_key"]: ref})
    assert fed[ref["task_key"]]["params"] == ref["params"]
    assert NOW  # the clock of the kit
