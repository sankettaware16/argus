"""What a rule says about itself, for the engine (E0): its ATT&CK tactics and the coarse stages
they cover, the log family it reads (from its index patterns and the site's families) and a
**lineage** that survives the rule being recreated in Kibana.

A lineage is sticky: a rule keeps the one it got first, so renaming it changes nothing; a new rule
(a new id) whose name is that of a rule already known takes that rule's lineage, so a recreated
rule keeps its statistics; otherwise it gets its own, made from its id. Nothing here knows any
rule: only Kibana's own fields (``kibana.alert.rule.threat``, ``kibana.alert.rule.indices``)."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.normalize.fields import values
from argus.risk.config import STAGES
from argus.site import LogFamily, names_family

# ATT&CK tactics (enterprise) by coarse stage: what came before access, access, a foothold up to
# command and control, and actions on objectives.
TACTIC_STAGE = {
    "reconnaissance": "recon",
    "resource development": "recon",
    "initial access": "access",
    "execution": "access",
    "credential access": "access",
    "persistence": "foothold",
    "privilege escalation": "foothold",
    "defense evasion": "foothold",
    "discovery": "foothold",
    "lateral movement": "foothold",
    "command and control": "foothold",
    "collection": "actions",
    "exfiltration": "actions",
    "impact": "actions",
}
MAX_TACTICS = 14
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_SPACES = re.compile(r"\s+")
RULE = "kibana.alert.rule."
# The newest stored alert of a rule that still holds its raw document, its rule fields only.
_META = text(
    "SELECT a.event_time, a.normalized -> 'ancestors' AS ancestors,"
    " (SELECT jsonb_object_agg(k, v) FROM jsonb_each(a.raw) AS e(k, v)"
    "  WHERE k IN ('kibana', 'kibana.alert', 'kibana.alert.rule', 'kibana.alert.rule.threat',"
    "  'kibana.alert.rule.indices', 'kibana.alert.rule.parameters',"
    "  'kibana.alert.rule.parameters.index')) AS fields"
    " FROM alert_records a WHERE a.rule_id = :rule AND a.raw <> '{}'::jsonb"
    " AND a.event_time >= CAST(:now AS timestamptz) - interval '45 days'"
    " ORDER BY a.event_time DESC LIMIT 1"
)


@dataclass(frozen=True)
class RuleMeta:
    rule_id: str
    lineage: str
    stage_mask: int
    family: str | None
    first_alert_at: datetime | None


def name_key(name: str | None) -> str | None:
    """A rule name as the lineage compares it: case and spacing do not count."""
    if not name or not name.strip():
        return None
    return _SPACES.sub(" ", name.strip().lower())


def new_lineage(rule_id: str) -> str:
    return "L" + hashlib.sha256(rule_id.encode("utf-8")).hexdigest()[:15]


def tactics_of(threat: Any) -> tuple[str, ...]:
    """The tactic names of ``kibana.alert.rule.threat`` (each entry's ``tactic.name``), lower
    case, once each, in order."""
    found: list[str] = []
    entries = threat if isinstance(threat, list) else [threat]
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        for name in values(entry, "tactic.name"):
            if isinstance(name, str) and name.strip():
                key = _SPACES.sub(" ", name.strip().lower())
                if key not in found:
                    found.append(key)
    return tuple(found[:MAX_TACTICS])


def stage_mask(tactics: Iterable[str]) -> int:
    """The coarse stages the tactics cover, as bits (recon, access, foothold, actions)."""
    mask = 0
    for tactic in tactics:
        stage = TACTIC_STAGE.get(tactic)
        if stage is not None:
            mask |= 1 << STAGES.index(stage)
    return mask


def family_of(indices: Sequence[str], families: Sequence[LogFamily]) -> str | None:
    """The site's log family a rule reads: the one every index entry of the rule names. None
    when an entry is wider than one family (``acme-logs-*``) or the entries name several: such a
    rule's alert groups each take the family of their own alerts (:func:`index_family`), never
    the rule's newest alert's."""
    named: set[str] = set()
    for entry in indices:
        found = {f.name for f in families if names_family(entry, f)}
        if not found:
            return None
        named |= found
    return named.pop() if len(named) == 1 else None


def index_family(indices: Iterable[str], families: Sequence[LogFamily]) -> str | None:
    """The one log family that owns these concrete source indices (an alert group's alerts'):
    a daily index, a stream or one of its backing indices. None for none or several."""
    owners = {
        f.name
        for index in indices
        for f in families
        if f.owns_index(index) or f.owns_index(index.removeprefix(".ds-"))
    }
    return owners.pop() if len(owners) == 1 else None


def source_index(ancestors: Any) -> str | None:
    """The concrete index an alert was made from (``ancestors``' first entry that names one)."""
    if isinstance(ancestors, list):
        for item in ancestors:
            index = item.get("index") if isinstance(item, Mapping) else None
            if isinstance(index, str) and index and "*" not in index:
                return index
    return None


def meta_from(fields: Mapping[str, Any] | None, ancestors: Any) -> tuple[
    tuple[str, ...], tuple[str, ...], str | None
]:  # fmt: skip
    """(tactics, index entries, concrete source index) from an alert's rule fields."""
    doc = dict(fields or {})
    tactics = tactics_of(values(doc, RULE + "threat"))
    indices = [v for v in values(doc, RULE + "indices") if isinstance(v, str)]
    if not indices:
        indices = [v for v in values(doc, RULE + "parameters.index") if isinstance(v, str)]
    entries = tuple(dict.fromkeys(i.strip() for i in indices if i.strip()))[:16]
    return tactics, entries, source_index(ancestors)


@dataclass(frozen=True)
class _Row:
    rule_id: str
    name: str | None
    lineage: str | None
    first_alert_at: datetime | None


def assign_lineages(rows: Sequence[_Row]) -> dict[str, str]:
    """The lineage of each rule that has none yet (see the module's docstring): oldest first, so
    of two rules made with one name the first gives the lineage."""
    by_name: dict[str, str] = {}
    for row in rows:
        key = name_key(row.name)
        if row.lineage and key is not None:
            by_name.setdefault(key, row.lineage)
    out: dict[str, str] = {}
    order = sorted(
        (r for r in rows if not r.lineage),
        key=lambda r: (r.first_alert_at is None, r.first_alert_at or _EPOCH, r.rule_id),
    )
    for row in order:
        key = name_key(row.name)
        lineage = by_name.get(key) if key is not None else None
        if lineage is None:
            lineage = new_lineage(row.rule_id)
            if key is not None:
                by_name[key] = lineage
        out[row.rule_id] = lineage
    return out


async def sync(conn: AsyncConnection, families: Sequence[LogFamily], now: datetime) -> int:
    """Give every rule its lineage, and its tactics, stages, index entries and family from its
    newest stored alert (of the last 45 days) when they were never read or its definition changed
    since. Returns how many rules changed. Postgres only; a rule whose alerts' raw documents are
    all purged keeps no tactics and no family (it still scores, with no stage)."""
    rows = (
        await conn.execute(
            text(
                "SELECT rule_id, name, lineage, first_alert_at, definition_at, meta_at"
                " FROM rules ORDER BY rule_id"
            )
        )
    ).all()
    lineages = assign_lineages([_Row(r.rule_id, r.name, r.lineage, r.first_alert_at) for r in rows])
    changed = 0
    for row in rows:
        stale = row.meta_at is None or (
            row.definition_at is not None and row.definition_at > row.meta_at
        )
        lineage = lineages.get(row.rule_id)
        if not stale and lineage is None:
            continue
        values_: dict[str, Any] = {"r": row.rule_id, "lineage": lineage or row.lineage}
        sets = ["lineage = :lineage"]
        if stale:
            found = (await conn.execute(_META, {"rule": row.rule_id, "now": now})).first()
            if found is not None:
                tactics, indices, _ = meta_from(found.fields, found.ancestors)
                values_.update(
                    tactics=list(tactics), stages=stage_mask(tactics), indices=list(indices),
                    family=family_of(indices, families),
                )  # fmt: skip
                sets.append(
                    "tactics = :tactics, stage_mask = :stages, indices = :indices, family = :family"
                )
            # read once per definition, found or not (no rescan of a rule whose raw is purged)
            values_["at"] = max(
                t for t in (row.definition_at, found.event_time if found else None, now) if t
            )
            sets.append("meta_at = :at")
        statement = f"UPDATE rules SET {', '.join(sets)} WHERE rule_id = :r"  # noqa: S608 - constant fragments; values are bound
        await conn.execute(text(statement), values_)
        changed += 1
    return changed


async def load(conn: AsyncConnection) -> dict[str, RuleMeta]:
    """Every rule's lineage, stages, family and the first alert of its lineage (a recreated rule's
    probation counts from its lineage's first alert)."""
    rows = (
        await conn.execute(
            text(
                "SELECT rule_id, coalesce(lineage, '') AS lineage, coalesce(stage_mask, 0) AS"
                " stages, family, min(first_alert_at) OVER (PARTITION BY coalesce(lineage,"
                " rule_id)) AS first FROM rules"
            )
        )
    ).all()
    return {
        r.rule_id: RuleMeta(r.rule_id, r.lineage or new_lineage(r.rule_id), int(r.stages),
                            r.family, r.first)
        for r in rows
    }  # fmt: skip
