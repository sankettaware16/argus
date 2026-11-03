"""Evidence packs: what to ask about an investigation, and what it means.

A pack is a plain object with a name and a version. The framework calls ``local_signals`` once,
``plan`` once per wave (up to ``max_waves``), then ``signals``; it allocates the pack's per-run
budget, runs the tasks through the gateway and stores the evidence. Tasks travel through the graph
state as plain dicts (``TaskSpec.ref``). The stub pack is local-only; the generic pack replaces it.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, ClassVar

from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.context.evidence import PackBug, SignalValue, canonical, local, task_key, unknown
from argus.gateway.templates import REGISTRY, CostClass, Params, Template

MAX_WAVES = 3  # with the fixed nodes, a run stays below the recursion limit of 25
MAX_TASKS_PER_WAVE = 32
MAX_TASKS_PER_RUN = 64
SNAPSHOT_ROWS = 50
SNAPSHOT_BYTES = 16_384


@dataclass(frozen=True)
class TaskSpec:
    """One evidence task: a registered template with its parameters."""

    template: Template
    params: Params
    priority: int = 0  # lower runs first, and gets the budget first
    max_rows: int = SNAPSHOT_ROWS
    max_bytes: int = SNAPSHOT_BYTES

    def ref(self) -> dict[str, Any]:
        spec = type(self.template).spec()
        if REGISTRY.get(spec.name) is not type(self.template):
            raise PackBug(f"template {spec.name} is not registered")
        return {
            "task_key": task_key(self.template, self.params),
            "template": spec.name,
            "version": spec.version,
            "cost": spec.cost.value,
            "params": self.params.model_dump(mode="json"),
            "priority": self.priority,
            "max_rows": min(self.max_rows, SNAPSHOT_ROWS),
            "max_bytes": min(self.max_bytes, SNAPSHOT_BYTES),
        }


def rebuild(ref: Mapping[str, Any]) -> tuple[Template, Params]:
    """The template and parameters of a task reference; a template that changed version
    since the task was planned is refused (its key would no longer match)."""
    cls = REGISTRY.get(str(ref["template"]))
    if cls is None or cls.version != ref["version"]:
        raise PackBug(f"template {ref['template']}@{ref['version']} is not registered")
    template = cls()
    try:
        params = cls.params_model.model_validate_json(canonical(ref["params"]))
    except ValidationError as exc:
        raise PackBug(f"{ref['template']}: stored parameters no longer valid") from exc
    if task_key(template, params) != ref["task_key"]:
        raise PackBug(f"{ref['template']}: task key does not match its parameters")
    return template, params


class Pack(ABC):
    name: ClassVar[str]
    version: ClassVar[int]
    family: ClassVar[str]
    max_waves: ClassVar[int] = 0
    # Remote requests a run may make, per cost class; reused evidence is free.
    budget: ClassVar[Mapping[CostClass, int]] = {}

    @property
    def ident(self) -> str:
        return f"{self.name}@{self.version}"

    @abstractmethod
    def local_signals(
        self, facts: Mapping[str, Any], context: Mapping[str, Any]
    ) -> list[SignalValue]: ...

    def plan(
        self,
        wave: int,
        facts: Mapping[str, Any],
        context: Mapping[str, Any],
        evidence: Mapping[str, Mapping[str, Any]],
    ) -> Sequence[TaskSpec]:
        return ()

    def signals(
        self,
        facts: Mapping[str, Any],
        context: Mapping[str, Any],
        evidence: Mapping[str, Mapping[str, Any]],
        snapshots: Mapping[str, Any],
    ) -> list[SignalValue]:
        return []

    async def extra_context(
        self, conn: AsyncConnection, facts: Mapping[str, Any]
    ) -> dict[str, Any]:
        """What the pack reads from Postgres itself (bounded, JSON-like): ``context["pack"]``."""
        return {}

    def report(
        self,
        facts: Mapping[str, Any],
        context: Mapping[str, Any],
        evidence: Mapping[str, Mapping[str, Any]],
        signals: Sequence[Mapping[str, Any]] = (),
    ) -> dict[str, Any]:
        """The pack's part of the dossier body (e.g. the note's steps and their outcomes),
        given its derived ``signals``."""
        return {}


class StubPack(Pack):
    """The local-only pack: what ARGUS's own store says, no SIEM query."""

    name = "stub"
    version = 1
    family = "generic"

    def local_signals(
        self, facts: Mapping[str, Any], context: Mapping[str, Any]
    ) -> list[SignalValue]:
        v = self.version
        signals = [
            local("alert_count", v, facts["alert_count"]),
            local("duplicate_count", v, facts["duplicate_count"]),
            local("late_arrivals", v, facts["late_arrivals"]),
            local("span_minutes", v, facts["span_minutes"]),
            related(v, context["related_total"], context["supernode_entities"]),
            local("continues_previous_day", v, context["continues"] is not None),
        ]
        signals += [
            local(f"entities.{kind}", v, count)
            for kind, count in sorted(facts["entity_counts"].items())
        ]
        return signals


def related(version: int, total: int, supernodes: int) -> SignalValue:
    """How many investigations share an entity with this one. Entities in more than 200
    investigations are left out, so with any of them the count is a lower bound,
    and none found is not known to be none."""
    if not supernodes:
        return local("related_investigations", version, total)
    if total > 0:
        return SignalValue("related_investigations", version, total, "known", None,
                           "lower_bound", ())  # fmt: skip
    return unknown("related_investigations", version, "supernode_entities")


# The ident of a dossier derived again after the deterministic wave or a person's "Check more":
# the base pack's ident with ``+wave.<round>`` after its name.
WAVE_IDENT = re.compile(
    r"^(?P<name>[a-z0-9_.-]+)\+wave\.(?P<round>[1-9][0-9]?)@(?P<version>[0-9]+)$"
)


class WavePack(Pack):
    """The base pack read over more evidence: a dossier derived again after the
    deterministic wave or a person's "Check more" is one more dossier of the same investigation
    version (a dossier is never changed), under an ident of its own, ``generic+wave.1@12``.
    Everything is the base pack's; it plans nothing (its evidence is already asked)."""

    name = "wave"
    version = 0
    family = "wave"

    def __init__(self, base: Pack, round_: int) -> None:
        if not 1 <= round_ <= 99:
            raise ValueError("a wave round is 1 to 99")
        self.base = base
        self.round = round_
        self.family = base.family  # type: ignore[misc]

    @property
    def ident(self) -> str:
        return f"{self.base.name}+wave.{self.round}@{self.base.version}"

    def local_signals(
        self, facts: Mapping[str, Any], context: Mapping[str, Any]
    ) -> list[SignalValue]:
        return self.base.local_signals(facts, context)

    def signals(
        self,
        facts: Mapping[str, Any],
        context: Mapping[str, Any],
        evidence: Mapping[str, Mapping[str, Any]],
        snapshots: Mapping[str, Any],
    ) -> list[SignalValue]:
        return self.base.signals(facts, context, evidence, snapshots)

    def report(
        self,
        facts: Mapping[str, Any],
        context: Mapping[str, Any],
        evidence: Mapping[str, Mapping[str, Any]],
        signals: Sequence[Mapping[str, Any]] = (),
    ) -> dict[str, Any]:
        return self.base.report(facts, context, evidence, signals)


class PackRegistry:
    """Which pack works on an investigation. For now every rule is the generic family
    (the rules registry may later map rules to families)."""

    def __init__(self, packs: Sequence[Pack], default: str = "generic") -> None:
        self._by_family = {pack.family: pack for pack in packs}
        self._by_ident = {pack.ident: pack for pack in packs}
        if len(self._by_family) != len(packs) or default not in self._by_family:
            raise ValueError("one pack per family, and one for the default family")
        for pack in packs:
            if not 0 <= pack.max_waves <= MAX_WAVES:
                raise ValueError(f"{pack.ident}: max_waves must be 0 to {MAX_WAVES}")
        self.default = default

    def resolve(self, facts: Mapping[str, Any]) -> Pack:
        return self._by_family[self.default]

    def get(self, ident: str) -> Pack | None:
        found = self._by_ident.get(ident)
        if found is not None:
            return found
        wave = WAVE_IDENT.match(ident)  # a wave dossier reads as its base pack does
        base = None if wave is None else self._by_ident.get(f"{wave['name']}@{wave['version']}")
        return None if wave is None or base is None else WavePack(base, int(wave["round"]))


def default_registry(
    classifier: Any = None,
    *,
    remote_ti: bool = False,
    log_queries: bool = False,
    proxy_aggregations: bool = False,
    clock: Any = None,
) -> PackRegistry:
    """The generic pack for every rule; ``classifier`` is the asset map's;
    ``remote_ti``/``log_queries``/``proxy_aggregations``: its modules may ask the SIEM (each
    after its own first production run)."""
    from argus.context.generic import GenericPack

    return PackRegistry(
        [
            GenericPack(
                classifier,
                remote_ti=remote_ti,
                log_queries=log_queries,
                proxy_aggregations=proxy_aggregations,
                clock=clock,
            )
        ]
    )
