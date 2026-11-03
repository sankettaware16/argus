"""The deterministic decision engine (P4; plan §2.3, §3, §5.3, D-085): decides only what human
labels clearly support, and never proposes benign while any floor signal is present or
unknown.

**Keys** are learned from people's labels (never the assistant's, never the gold set's
*test* part, which is what the engine is scored on):
- ``("steps", rule, step outcomes)``: the rule's steps answered the same way;
- ``("field", rule, field, value)``: a value of a field the rule's own steps name, when the
  investigation has few values of it (``FEW``), not its grouping key.
A key decides only with at least ``MIN_SUPPORT`` labels, at least ``MIN_AGREEMENT`` of them
alike, its newest label within ``MAX_AGE``, and (for a benign outcome) no true positive
among them. Keys that match one investigation and disagree never decide.

**The floor** (§2.3) always wins over a benign key. It is engaged by any of:
- a threat-list hit;
- a detection by outside threat intel (AR3: VirusTotal engines flag an external indicator the
  item holds, ``body["outside"]``);
- successes after an attack;
- a regular beacon;
- a destination few campus hosts reach;
- remote-admin, P2P or anonymizer ports;
- high or critical severity;
- an entity seen for the first time;
- a volume spike against the same rule and key's recent days;
- and by any of these not known (D-023: unknown is never negative).
A true-positive key is not stopped by the floor.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.assess.runner import Verdict
from argus.evaluation.harness import BENIGN
from argus.outside import facts as outside
from argus.outside import read as outside_read
from argus.outside.read import View

NAME = "engine@1"
MIN_SUPPORT = 5
MIN_AGREEMENT = 0.95
MAX_AGE = timedelta(days=30)
FEW = 3
SPIKE = 3.0  # alerts above this many times the recent median of the same rule and key
SPIKE_DAYS = 5
BEACON = 0.3  # proxy.regularity below this is regular, like a beacon
RARE = 1  # a destination reached by at most this many campus hosts
POSITIVE = "true_positive"
Key = tuple[str, ...]


def _signals(body: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    out = {}
    for s in [*(body.get("local_signals") or []), *(body.get("signals") or [])]:
        if isinstance(s, Mapping) and isinstance(s.get("name"), str):
            out[s["name"]] = s
    return out


def _rule(body: Mapping[str, Any]) -> str:
    facts = body.get("facts") or {}
    return str(facts.get("rule_name") or facts.get("rule_id") or "?")


def _key_fields(body: Mapping[str, Any]) -> set[str]:
    raw = (body.get("facts") or {}).get("group_key")
    try:
        pairs = json.loads(raw) if isinstance(raw, str) else []
    except ValueError:
        return set()
    return {str(p[0]) for p in pairs if isinstance(p, list) and p}


def keys(body: Mapping[str, Any]) -> list[Key]:
    """The keys an investigation matches."""
    rule = _rule(body)
    steps = [s for s in ((body.get("report") or {}).get("steps") or []) if isinstance(s, Mapping)]
    out: list[Key] = []
    if steps:
        out.append(("steps", rule, ",".join(f"{s.get('number')}:{s.get('status')}" for s in steps)))
    named = {f for s in steps for f in (s.get("fields") or [])} - _key_fields(body)
    facts = ((body.get("context") or {}).get("pack") or {}).get("fields") or {}
    for name in sorted(named):
        fact = facts.get(name) or {}
        top = fact.get("top") or []
        if top and fact.get("distinct", 0) <= FEW:
            out += [("field", rule, str(name), str(row[0])) for row in top if row]
    return out


@dataclass(frozen=True)
class Label:
    outcome: str
    at: datetime


@dataclass
class Learned:
    """Every key's labels."""

    by_key: dict[Key, list[Label]] = field(default_factory=lambda: defaultdict(list))

    def add(self, body: Mapping[str, Any], label: Label) -> None:
        for key in keys(body):
            self.by_key[key].append(label)

    def fingerprint(self) -> str:
        """Changes whenever any key's labels change (then every assessment is checked again)."""
        parts = sorted(
            (key, sorted((x.outcome, x.at.isoformat()) for x in labels))
            for key, labels in self.by_key.items()
        )
        return hashlib.sha256(repr(parts).encode()).hexdigest()[:12]


def qualified(labels: Sequence[Label], now: datetime) -> str | None:
    """The outcome a key may decide, or None."""
    if len(labels) < MIN_SUPPORT or now - max(x.at for x in labels) > MAX_AGE:
        return None
    outcome, count = Counter(x.outcome for x in labels).most_common(1)[0]
    if count / len(labels) < MIN_AGREEMENT:
        return None
    if outcome in BENIGN and any(x.outcome == POSITIVE for x in labels):
        return None
    return outcome


def floor(body: Mapping[str, Any], first_seen: bool | None, spike: bool | None) -> list[str]:
    """Why a benign proposal is not allowed (empty: the floor is clear)."""
    sig = _signals(body)
    out = []

    def known(name: str) -> tuple[bool, Any]:
        s = sig.get(name)
        if s is None:
            return False, None
        return s.get("status") == "known", s.get("value")

    for name, why in (("ti.listed", "on a threat list"), ("ti.listed_remote", "on a threat list")):
        ok, value = known(name)
        if name in sig and (not ok or (value or 0) > 0):
            out.append(why if ok else f"{name} not known")
    if "ti.listed" not in sig:
        out.append("threat lists not checked")
    if outside.any_flagged(body.get("outside")):
        out.append(outside.FLAG)
    for name, why in (("web.successes_after", "successful answers after the alert"),
                      ("ports.risky", "remote-admin, P2P or anonymizer ports")):  # fmt: skip
        ok, value = known(name)
        if name in sig and (not ok or (value or 0) > 0):
            out.append(why if ok else f"{name} not known")
    ok, value = known("proxy.regularity")
    if "proxy.regularity" in sig and (not ok or (value is not None and value < BEACON)):
        out.append("regular like a beacon" if ok else "proxy.regularity not known")
    ok, value = known("proxy.hosts_to_destination")
    if "proxy.hosts_to_destination" in sig and (not ok or (value or 0) <= RARE):
        out.append("a destination few campus hosts reach" if ok else "destinations not known")
    severity = str((body.get("facts") or {}).get("severity") or "").lower()
    if severity in ("high", "critical"):
        out.append(f"severity {severity}")
    if first_seen is not False:
        out.append("an entity seen for the first time" if first_seen else "first-seen not known")
    if spike is not False:
        out.append("a volume spike" if spike else "volume baseline not known")
    return list(dict.fromkeys(out))


@dataclass(frozen=True)
class Decision:
    outcome: str | None
    reasons: list[str]
    key: Key | None = None


def decide(
    body: Mapping[str, Any],
    learned: Learned,
    now: datetime,
    first_seen: bool | None,
    spike: bool | None,
) -> Decision:
    matched = {k: qualified(learned.by_key.get(k, []), now) for k in keys(body)}
    deciding = {k: o for k, o in matched.items() if o is not None}
    if not deciding:
        return Decision(None, ["no key with enough consistent human labels"])
    outcomes = set(deciding.values())
    if len(outcomes) > 1:
        return Decision(None, ["keys disagree: " + ", ".join(sorted(outcomes))])
    (outcome,) = outcomes
    key = sorted(deciding)[0]
    labels = learned.by_key[key]
    why = f"key {' / '.join(key)}: {len(labels)} human labels, all or nearly all {outcome}"
    if outcome in BENIGN:
        blocked = floor(body, first_seen, spike)
        if blocked:
            return Decision(None, [why, "floor: " + "; ".join(blocked)], key)
    return Decision(outcome, [why], key)


# -- the store's side -----------------------------------------------------------------------

_LABELS = """
SELECT DISTINCT ON (e.investigation_id) e.investigation_id, e.outcome, e.created_at, d.body
FROM review_events e
JOIN users u ON u.id = e.user_id
JOIN LATERAL (SELECT body FROM dossiers x WHERE x.investigation_id = e.investigation_id
              AND x.version = e.version ORDER BY x.created_at DESC LIMIT 1) d ON true
WHERE e.outcome IS NOT NULL AND e.action = 'reviewed' AND u.username <> :assistant
  AND e.assessment_id IS NULL
  AND NOT EXISTS (SELECT 1 FROM gold_items g WHERE g.investigation_id = e.investigation_id
                  AND g.split = 'test')
ORDER BY e.investigation_id, e.id DESC
"""
_GOLD_DEV = """
SELECT DISTINCT ON (l.investigation_id) l.investigation_id, l.outcome, l.created_at, d.body
FROM gold_labels l JOIN gold_items g USING (set_name, investigation_id)
JOIN dossiers d ON d.investigation_id = g.investigation_id AND d.version = g.version
  AND d.pack = g.pack AND d.dossier_hash = g.dossier_hash
WHERE g.split = 'dev'
ORDER BY l.investigation_id, l.id DESC
"""


async def learn(conn: AsyncConnection) -> Learned:
    """Keys from people's reviews (not confirmed proposals, not gold test items) and the gold
    set's dev answers; a person's newest outcome per investigation."""
    learned = Learned()
    seen: dict[uuid.UUID, Label] = {}
    bodies: dict[uuid.UUID, Mapping[str, Any]] = {}
    for query in (_LABELS, _GOLD_DEV):
        for investigation_id, outcome, at, body in await conn.execute(
            text(query), {"assistant": "argus-assistant"}
        ):
            if investigation_id not in seen or seen[investigation_id].at < at:
                seen[investigation_id] = Label(outcome, at)
                bodies[investigation_id] = body
    for investigation_id, label in seen.items():
        learned.add(bodies[investigation_id], label)
    return learned


async def first_seen(conn: AsyncConnection, investigation_id: uuid.UUID) -> bool:
    """Whether any of its entities appears in no other investigation."""
    found = await conn.scalar(
        text(
            "SELECT EXISTS (SELECT 1 FROM investigation_entities e WHERE e.investigation_id = :i"
            " AND NOT EXISTS (SELECT 1 FROM investigation_entities o WHERE o.kind = e.kind"
            " AND o.value = e.value AND o.investigation_id <> e.investigation_id))"
        ),
        {"i": investigation_id},
    )
    return bool(found)


async def spike(conn: AsyncConnection, investigation_id: uuid.UUID) -> bool | None:
    """Whether its alert count is over ``SPIKE`` times the median of the same rule and key
    on the ``SPIKE_DAYS`` days before; None without such days."""
    row = (
        await conn.execute(
            text(
                "SELECT i.alert_count, percentile_cont(0.5) WITHIN GROUP (ORDER BY p.alert_count)"
                " FROM investigations i LEFT JOIN investigations p ON p.rule_id = i.rule_id"
                " AND p.group_key = i.group_key AND p.bucket_start < i.bucket_start"
                " AND p.bucket_start >= i.bucket_start - make_interval(days => :days)"
                " WHERE i.id = :i GROUP BY i.alert_count"
            ),
            {"i": investigation_id, "days": SPIKE_DAYS},
        )
    ).first()
    if row is None or row[1] is None:
        return None
    return bool(row[0] > SPIKE * row[1])


class Engine:
    """The assessor (P3's protocol): learns once, then decides each investigation."""

    name = NAME

    def __init__(self, learned: Learned, now: datetime, view: View | None = None) -> None:
        self.learned = learned
        self.now = now
        self.view = view  # the outside cache (AR3): a detection there blocks a benign key
        self.stamp = f"{NAME}#{learned.fingerprint()}"

    async def assess(
        self, conn: AsyncConnection, investigation_id: uuid.UUID, body: Mapping[str, Any]
    ) -> Verdict:
        if self.view is not None:
            found = await outside_read.facts_for(
                conn,
                [investigation_id],
                self.now,
                self.view.window,
                self.view.threshold,
                clean_window=self.view.clean_window,
                parent_ok=self.view.parent_ok,
            )
            if found.get(investigation_id):
                body = {**body, "outside": found[investigation_id]}
        d = decide(body, self.learned, self.now, await first_seen(conn, investigation_id),
                   await spike(conn, investigation_id))  # fmt: skip
        decided_by = self.stamp if d.key is None else f"{self.stamp}: {' / '.join(d.key)}"
        return Verdict(d.outcome, decided_by, d.reasons, 1.0 if d.outcome else None)


def describe(learned: Learned, now: datetime) -> Iterable[tuple[Key, int, str | None]]:
    """Every key with its support and what it may decide (for the gate report)."""
    for key in sorted(learned.by_key):
        labels = learned.by_key[key]
        yield key, len(labels), qualified(labels, now)
