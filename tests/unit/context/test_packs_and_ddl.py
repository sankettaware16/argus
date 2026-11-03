"""Packs, the registry, the graph's pure parts, and the frozen checkpoint DDL (D-054)."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path
from typing import Any

import pytest
from langgraph.checkpoint.postgres.base import BasePostgresSaver

from argus.context.checkpoints import serializer, state_bytes
from argus.context.evidence import PackBug, task_key
from argus.context.graph import dispatch, dossier_of, route_after_wave
from argus.context.packs import (
    MAX_WAVES,
    SNAPSHOT_BYTES,
    SNAPSHOT_ROWS,
    PackRegistry,
    StubPack,
    TaskSpec,
    default_registry,
    rebuild,
)
from argus.db import migrate
from argus.gateway.templates import (
    REGISTRY,
    CostClass,
    Endpoint,
    Family,
    Params,
    Template,
    register,
)

pytestmark = pytest.mark.unit


class NP(Params):
    n: int


@register
class Registered(Template):
    name = "test.unit.registered"
    version = 3
    endpoint = Endpoint.SEARCH
    family = Family.ALERTS
    cost = CostClass.LIGHT
    params_model = NP


class Unregistered(Registered):
    name = "test.unit.unregistered"


def test_task_refs_round_trip_and_are_capped() -> None:
    spec = TaskSpec(Registered(), NP(n=4), priority=2, max_rows=10_000, max_bytes=10**9)
    ref = spec.ref()
    assert ref == {
        "task_key": task_key(Registered(), NP(n=4)), "template": "test.unit.registered",
        "version": 3, "cost": "light", "params": {"n": 4}, "priority": 2,
        "max_rows": SNAPSHOT_ROWS, "max_bytes": SNAPSHOT_BYTES,
    }  # fmt: skip
    template, params = rebuild(ref)
    assert type(template) is Registered
    assert params == NP(n=4)


def test_unregistered_or_changed_templates_are_refused() -> None:
    with pytest.raises(PackBug, match="not registered"):
        TaskSpec(Unregistered(), NP(n=1)).ref()
    ref = TaskSpec(Registered(), NP(n=1)).ref()
    with pytest.raises(PackBug, match="@2 is not registered"):
        rebuild({**ref, "version": 2})
    with pytest.raises(PackBug, match="no longer valid"):
        rebuild({**ref, "params": {"n": "one"}})
    with pytest.raises(PackBug, match="does not match"):
        rebuild({**ref, "params": {"n": 2}})
    with pytest.raises(PackBug, match="not registered"):
        rebuild({**ref, "template": "nope"})
    assert "test.unit.unregistered" not in REGISTRY


def test_registry_rules() -> None:
    stub = StubPack()
    assert default_registry().resolve({}).ident == "generic@12"
    assert default_registry().get("generic@12") is not None
    assert default_registry().get("stub@1") is None
    with pytest.raises(ValueError, match="one pack per family"):
        PackRegistry([stub, StubPack()])
    with pytest.raises(ValueError, match=r"^one pack per family, and one for the default family$"):
        PackRegistry([stub], default="proxy")

    class Deep(StubPack):
        family = "deep"
        max_waves = MAX_WAVES + 1

    with pytest.raises(ValueError, match="max_waves"):
        PackRegistry([stub, Deep()])


def test_the_stub_pack_reads_only_the_store() -> None:
    facts = {"alert_count": 3, "duplicate_count": 1, "late_arrivals": 0, "span_minutes": None,
             "entity_counts": {"ip": 2, "domain": 1}}  # fmt: skip
    context = {"related_total": 4, "continues": None, "supernode_entities": 0}
    signals = {s.name: s for s in StubPack().local_signals(facts, context)}
    assert signals["alert_count"].value == 3
    assert signals["entities.ip"].value == 2
    assert signals["span_minutes"].status == "unknown"
    assert signals["continues_previous_day"].value is False
    assert StubPack().plan(1, facts, context, {}) == ()
    assert StubPack().signals(facts, context, {}, {}) == []


def test_route_dispatch_and_dossier_status() -> None:
    base: Any = {"wave": 1, "max_waves": 2, "wave_tasks": 3}
    assert route_after_wave(base) == "plan_wave"
    assert route_after_wave({**base, "wave_tasks": 0}) == "derive_signals"
    assert route_after_wave({**base, "wave": 2}) == "derive_signals"
    assert dispatch({"planned": []}) == "validate_evidence"  # type: ignore[typeddict-item]
    sends = dispatch({"planned": [{"task_key": "b"}, {"task_key": "a"}],  # type: ignore[typeddict-item]
                      "investigation_id": "i", "version": 1})  # fmt: skip
    assert [s.arg["task"]["task_key"] for s in sends] == ["a", "b"]

    def state(*statuses: str, reason: str | None = None) -> Any:
        ev = {f"{n}": {"task_key": f"{n}", "status": s, "reused": n % 2 == 0,
                       "coverage": {"reason": reason} if reason else {}}
              for n, s in enumerate(statuses)}  # fmt: skip
        return {"investigation_id": "i", "version": 1, "facts_version": 1, "run_kind": "collect",
                "family": "f", "pack": "p@1", "facts": {}, "context": {}, "local_signals": [],
                "signals": [], "evidence": ev}  # fmt: skip

    assert dossier_of(state())["status"] == "evidence_ready"
    assert dossier_of(state("ok", "empty"))["status"] == "evidence_ready"
    partial = dossier_of(state("ok", "timeout", "skipped_budget"))
    assert (partial["status"], partial["partial_reason"]) == (
        "evidence_partial",
        "skipped_budget,timeout",
    )
    failed = dossier_of(state("deferred", "deferred", reason="context_partial"))
    assert (failed["status"], failed["partial_reason"]) == ("evidence_failed", "context_partial")
    a, b = state("ok", "empty"), state("ok", "empty")
    b["evidence"]["0"]["reused"] = not b["evidence"]["0"]["reused"]
    assert dossier_of(a)["hash"] == dossier_of(b)["hash"]  # reuse never changes the hash
    b["facts"] = {"x": 1}
    assert dossier_of(a)["hash"] != dossier_of(b)["hash"]


def test_the_serializer_is_strict() -> None:
    serde = serializer()
    assert serde.pickle_fallback is False
    kind, blob = serde.dumps_typed({"a": [1, "b", None]})
    assert serde.loads_typed((kind, blob)) == {"a": [1, "b", None]}
    assert state_bytes({"a": "x" * 1000, "b": 1}) > 1000


def _ddl(sql: str) -> str:
    sql = sql.replace("CONCURRENTLY ", "")
    return re.sub(r"\s+", " ", sql).strip().rstrip(";").strip()


def test_the_frozen_checkpoint_ddl_matches_the_installed_saver() -> None:
    """Migration 0008 carries a copy of the saver's migrations: a package upgrade that adds
    one fails here until a new Alembic revision carries it (D-054)."""
    path = Path(migrate.MIGRATIONS_DIR) / "versions" / "0008_context_graph.py"
    spec = importlib.util.spec_from_file_location("argus_migration_0008", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    frozen = [_ddl(s) for s in module.CHECKPOINT_DDL]
    installed = [_ddl(s) for s in BasePostgresSaver.MIGRATIONS]
    assert [re.sub(r"\(\s+", "(", s).replace(" )", ")") for s in frozen] == [
        re.sub(r"\(\s+", "(", s).replace(" )", ")") for s in installed
    ]
