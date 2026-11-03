"""The generic pack: every investigation's dossier, from what ARGUS stores.

* the rule's own note (the rules registry) becomes steps, each with an outcome (``notes``);
* field facts: for the fields the steps name and a base set, the distinct values and their
  counts over the investigation's alerts (at most ``ALERTS`` read, newest first);
* the asset map's view of every IP shown (asset, organisation prefix, internal, public);
* the stub pack's signals, and counts of the steps by outcome.

No SIEM request: the steps that need one say which pack will answer them.
"""

from __future__ import annotations

import re
import uuid
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, ClassVar

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.assets.classify import IpClassifier
from argus.context import batch1, heuristics, intel, notes, proxy, web
from argus.context.evidence import SignalValue, local
from argus.context.packs import Pack, StubPack, TaskSpec
from argus.gateway.templates import CostClass
from argus.normalize.fields import values as field_values

ALERTS = 1000  # alerts read per investigation (newest first); more: the facts are a lower bound
TOP = 8  # values shown per field
VALUE_CHARS = intel.VALUE_CHARS
MAX_FIELDS = 24
BASE_FIELDS = (
    "source.ip",
    "destination.ip",
    "destination.port",
    "destination.domain",
    "url.domain",
    "url.path",
    "url.original",
    "user_agent.original",
    "host.name",
    "user.name",
    "destination.geo.country_name",
    "destination.as.organization.name",
    "http.request.method",
    "http.response.status_code",
    "event.action",
    "url.full",
    "file.hash.sha256",
    "file.hash.sha1",
    "file.hash.md5",
)
IP_FIELDS = ("source.ip", "destination.ip", "client.ip", "server.ip", "host.ip")
# The log templates an investigation asks once: later runs plan the same request again, so
# its stored answer is reused, never asked again.
LOG_TEMPLATES = ("proxy.host", "proxy.destination", "web.followups")


def _text(value: Any) -> str:
    return str(value)[:VALUE_CHARS]


def field_facts(docs: list[Mapping[str, Any]], paths: list[str]) -> dict[str, Any]:
    """For each field: how many alerts have it, how many distinct values, the top values."""
    facts: dict[str, Any] = {}
    for path in paths:
        counts: Counter[str] = Counter()
        present = 0
        for doc in docs:
            found = {_text(v) for v in field_values(doc, path) if v is not None and v != ""}
            if found:
                present += 1
                counts.update(found)
        top = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:TOP]
        facts[path] = {"alerts": present, "distinct": len(counts), "top": [list(t) for t in top]}
    return facts


GENERIC_LEAVES = frozenset(
    {"name", "id", "type", "value", "code", "original", "full", "address", "ip", "port",
     "domain", "bytes", "count", "number", "hash", "version"}
)  # fmt: skip


def _words(name: str) -> set[str]:
    return {w for w in re.split(r"[^a-z0-9]+", name.lower()) if w}


def _stand_in(path: str, flat: Sequence[str]) -> str | None:
    """The top-level field that answers ``path``: one with its last segment as a whole word
    (or that word's plural), preferring one that also names the segment before it
    (``attempted_paths`` for ``url.path``; never ``description`` for ``source.ip``)."""
    *parents, leaf = path.lower().split(".")
    wanted = {leaf, leaf + "s", leaf + "es"}
    found = [k for k in flat if _words(k) & wanted]
    if parents:
        both = [k for k in found if parents[-1] in _words(k)]
        # A common word alone says nothing (`service_name` is no `dns.question.name`): then the
        # segment before it must be named too.
        found = both if both or leaf in GENERIC_LEAVES else found
    return found[0] if found else None


class GenericPack(Pack):
    """The pack for every rule: the note's steps and what the alerts answer."""

    name = "generic"
    # Bump the version whenever the dossier the pack derives changes: every dossier is then
    # derived again, locally.
    version = 12
    family = "generic"
    budget: ClassVar[Mapping[CostClass, int]] = {
        CostClass.LIGHT: 4,
        CostClass.MEDIUM: 1,
        CostClass.HEAVY: 2,
    }

    def __init__(
        self,
        classifier: IpClassifier | None = None,
        *,
        remote_ti: bool = False,
        log_queries: bool = False,
        proxy_aggregations: bool = False,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.classifier = classifier
        self.now = clock or (lambda: datetime.now(UTC))  # tests pass the worker's clock
        # Remote evidence only after a person's live checks: reference.ti_sync and
        # enrichment.log_queries.
        self.remote_ti = remote_ti
        self.log_queries = log_queries
        self.proxy_aggregations = proxy_aggregations
        self.max_waves = 1 if remote_ti or log_queries or proxy_aggregations else 0  # type: ignore[misc]
        self.stub = StubPack()

    async def extra_context(
        self, conn: AsyncConnection, facts: Mapping[str, Any]
    ) -> dict[str, Any]:
        rule = (
            await conn.execute(
                text("SELECT note, note_hash FROM rules WHERE rule_id = :r"),
                {"r": facts["rule_id"]},
            )
        ).first()
        note = rule.note if rule is not None else None
        rows = await conn.execute(
            text(
                "SELECT a.raw FROM investigation_alerts l JOIN alert_records a"
                " ON a.alert_id = l.alert_id WHERE l.investigation_id = :id"
                " AND l.duplicate_of IS NULL ORDER BY a.detected_at DESC NULLS LAST,"
                " a.alert_id LIMIT :n"
            ),
            {"id": uuid.UUID(str(facts["investigation_id"])), "n": ALERTS},
        )
        docs = [row.raw for row in rows]
        roots = frozenset(k.split(".", 1)[0] for doc in docs for k in doc)
        steps = notes.steps(note, roots)
        named = [f for s in steps for f in s.fields]
        paths = list(dict.fromkeys([*named, *BASE_FIELDS]))[:MAX_FIELDS]
        fields = field_facts(docs, paths)
        indices = sorted(
            {str(i) for doc in docs[:1] for i in (doc.get("kibana.alert.rule.indices") or [])}
        )[:10]
        # An aggregating rule (ES|QL, threshold) writes its own names: a step's missing field
        # is answered by a top-level field with its last segment in its name, shown as such
        # (``url.path`` from ``attempted_paths``).
        flat = sorted({k for doc in docs for k in doc if "." not in k and k not in notes.ROOTS})
        for path in [f for f in named if not fields.get(f, {}).get("distinct")]:
            stand_in = _stand_in(path, flat)
            if stand_in is not None:
                fact = field_facts(docs, [stand_in])[stand_in]
                if fact["distinct"]:
                    fields[path] = {**fact, "from": stand_in}
        earlier = {
            str(r.template): dict(r.params)
            for r in await conn.execute(
                text(
                    "SELECT DISTINCT ON (template) template, params FROM evidence"
                    " WHERE investigation_id = :i AND template = ANY(:t)"
                    " AND status IN ('ok', 'empty') ORDER BY template, version"
                ),
                {"i": uuid.UUID(str(facts["investigation_id"])), "t": list(LOG_TEMPLATES)},
            )
        }
        return {
            "earlier_logs": earlier,  # asked once per investigation, then reused
            "note_hash": notes.note_hash(note) if note else None,
            "has_note": bool(note),
            "steps": [
                {"number": s.number, "text": s.text, "fields": list(s.fields)} for s in steps
            ],
            "fields": {k: v for k, v in fields.items() if v["distinct"]},
            "alerts_read": len(docs),
            "complete": len(docs) == facts["alert_count"],
            "ips": self._ips(fields),
            "ti": await intel.context(
                conn,
                facts,
                fields,
                self.classifier,
                len(docs) == facts["alert_count"],
                now=self.now(),
            ),
            "indices": indices,
            "web": web.context(docs, fields) if web.applies(indices) else {},
            "heuristics": heuristics.context(fields, len(docs) == facts["alert_count"])
            if proxy.applies(indices)
            else {},
        }

    def _ips(self, fields: Mapping[str, Any]) -> dict[str, Any]:
        found: dict[str, Any] = {}
        for path in IP_FIELDS:
            for value, _ in fields.get(path, {}).get("top", []):
                if self.classifier is None or value in found:
                    continue
                got = self.classifier.classify(value)
                entry = got.asset.entries[0] if got.asset and got.asset.entries else None
                found[value] = {
                    "class": got.ip_class.value,
                    "asset": None if entry is None else entry.name[:VALUE_CHARS],
                }
        return found

    def local_signals(
        self, facts: Mapping[str, Any], context: Mapping[str, Any]
    ) -> list[SignalValue]:
        return self.stub.local_signals(facts, context)

    def _outcomes(
        self, context: Mapping[str, Any], derived: Sequence[Mapping[str, Any]] = ()
    ) -> list[dict[str, Any]]:
        pack = context.get("pack") or {}
        fields = pack.get("fields", {})
        ips = pack.get("ips", {})
        source = fields.get("source.ip", {}).get("top", [])
        owner = any(ips.get(v, {}).get("asset") for v, _ in source)
        answers = {**web.answers(pack.get("web", {}), derived), **proxy.answers(derived)}
        for step, sentence in batch1.answers(derived).items():  # the wave's answers
            answers[step] = f"{answers[step]} {sentence}" if step in answers else sentence
        told = intel.sentence(pack.get("ti", {}), derived)
        if told:
            answers["reputation"] = told
        return [
            notes.outcome(
                notes.Step(s["number"], s["text"], tuple(s["fields"])),
                fields,
                answers,
                owner_known=owner,
            )
            for s in pack.get("steps", [])
        ]

    def plan(
        self,
        wave: int,
        facts: Mapping[str, Any],
        context: Mapping[str, Any],
        evidence: Mapping[str, Mapping[str, Any]],
    ) -> Sequence[TaskSpec]:
        if wave != 1:
            return ()
        pack = context.get("pack") or {}
        found = intel.tasks(pack.get("ti", {})) if self.remote_ti else []
        earlier = pack.get("earlier_logs", {})
        if self.log_queries and web.applies(pack.get("indices", [])):
            found += web.tasks(
                facts, pack.get("fields", {}), self.now(), earlier, pack.get("indices", [])
            )
        if self.proxy_aggregations and proxy.applies(pack.get("indices", [])):
            found += proxy.tasks(
                facts,
                pack.get("fields", {}),
                pack.get("ips", {}),
                self.now(),
                earlier,
                pack.get("indices", []),
            )
        return found

    def signals(
        self,
        facts: Mapping[str, Any],
        context: Mapping[str, Any],
        evidence: Mapping[str, Mapping[str, Any]],
        snapshots: Mapping[str, Any],
    ) -> list[SignalValue]:
        ti = (context.get("pack") or {}).get("ti", {})
        # The wave's and "Check more"'s batch-1 answers are read by batch1.signals
        # alone: the intel module cites every reference it is given, so a failed batch-1
        # check must not make a threat-list reading unknown. Without them nothing changes.
        own = {k: r for k, r in evidence.items() if not batch1.is_batch1(r)}
        found = intel.signals(self.version, ti, own, snapshots)
        found += proxy.signals(self.version, own, snapshots)
        pack = context.get("pack") or {}
        indices = pack.get("indices", [])
        if web.applies(indices):  # each module's facts only where its source is read
            found += web.signals(self.version, pack.get("web", {}), evidence, snapshots)
        if proxy.applies(indices):
            found += heuristics.signals(self.version, pack.get("heuristics", {}))
        found += batch1.signals(self.version, evidence, snapshots)
        counts = Counter(o["status"] for o in self._outcomes(context, [s.as_dict() for s in found]))
        found += [
            local(f"steps.{status}", self.version, counts.get(status, 0))
            for status in ("answered", "deferred", "manual", "unknown")
        ]
        return found

    def report(
        self,
        facts: Mapping[str, Any],
        context: Mapping[str, Any],
        evidence: Mapping[str, Mapping[str, Any]],
        signals: Sequence[Mapping[str, Any]] = (),
    ) -> dict[str, Any]:
        pack = context.get("pack") or {}
        return {
            "steps": self._outcomes(context, signals),
            "summary": [
                *web.summary(pack.get("web", {})),
                *heuristics.summary(pack.get("heuristics", {})),
            ],
            "has_note": pack.get("has_note", False),
            "note_hash": pack.get("note_hash"),
            "complete": pack.get("complete", True),
            "alerts_read": pack.get("alerts_read", 0),
        }
