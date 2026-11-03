"""Reference data in Postgres: the rules registry rebuilt from the stored alerts, the
truncated-execution feed of the coverage ledger, the threat-intel mirrors (``site.ti_sources`` of
mode ``mirror``), the cached lookups of the sources of mode ``lookup``, and threat-intel answers
for a list of values."""

from __future__ import annotations

import hashlib
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncConnection

from argus import site
from argus.gateway.gateway import Result
from argus.gateway.templates import Params, Template
from argus.reference.templates import (
    LOOKUP_SIZE,
    MIRROR_SIZE,
    NewestParams,
    TiLookup,
    TiMirrorPage,
    TiNewest,
    lookup_params,
    mirror_params,
)
from argus.reference.ti import Freshness, Indicator, answer, from_document, variants

LOOKUP_TTL = timedelta(hours=24)
LOOKUP_BATCH = 50  # values per lookup: with their spellings, at most the 200 terms allowed
KEPT_ROWS = 20  # distinct indicator rows kept per value (a feed may repeat one many times)
RULE = "kibana.alert.rule."

Run = Callable[[Template, Params], Awaitable[Result]]


class IncompleteAnswer(Exception):  # noqa: N818
    """More than one bounded read returns (the mirror, or one lookup batch): nothing from it
    is used or stored."""


# ----------------------------------------------------------------------------- rules


def note_hash(note: str | None) -> str:
    return hashlib.sha256((note or "").encode("utf-8")).hexdigest()


LOCK_KEY = int.from_bytes(b"ARGUSRUL", "big")
HOLD = timedelta(minutes=5)  # longer than any ingest transaction (statement timeout 30 s)
BATCH = 5000  # alerts per refresh call: each call stays well inside the statement timeout
CURSOR = "rules_refresh"  # collector_cursors row: the newest first_seen_at already counted
_NUMBERS = (
    f"coalesce(raw ->> '{RULE}revision', '') ~ '^[0-9]{{1,9}}$'"
    f" AND coalesce(raw ->> '{RULE}version', '0') ~ '^[0-9]{{1,9}}$'"
    f" AND coalesce(raw ->> '{RULE}max_signals', '0') ~ '^[0-9]{{1,9}}$'"
)
_EXECUTED = (
    "CASE WHEN raw ->> 'kibana.alert.rule.execution.timestamp' ~ '^[0-9]{4}-'"
    " THEN (raw ->> 'kibana.alert.rule.execution.timestamp')::timestamptz END"
)
_NEW = "rule_id IS NOT NULL AND first_seen_at > :since AND first_seen_at <= :upto"
# The newest readable definition of each rule among the alerts stored since the last refresh.
_LATEST = (
    "SELECT DISTINCT ON (rule_id) rule_id, detected_at,"  # noqa: S608 - constant fragments; values are bound
    f" raw ->> '{RULE}uuid' AS uuid, raw ->> '{RULE}name' AS name, raw ->> '{RULE}type' AS type,"
    f" (raw ->> '{RULE}version')::int AS version, (raw ->> '{RULE}revision')::int AS revision,"
    f" raw ->> '{RULE}interval' AS interval, raw ->> '{RULE}from' AS lookback,"
    f" (raw ->> '{RULE}max_signals')::int AS max_signals, raw ->> '{RULE}severity' AS severity,"
    f" raw ->> '{RULE}note' AS note FROM alert_records"
    f" WHERE {_NEW} AND detected_at IS NOT NULL AND {_NUMBERS}"
    " ORDER BY rule_id, detected_at DESC, alert_id DESC"
)
_NEW_STATS = (
    f"SELECT rule_id, count(*) AS alerts, min(detected_at) AS first,"  # noqa: S608 - constant fragments; values are bound
    f" max(detected_at) AS last, max({_EXECUTED}) AS executed"
    f" FROM alert_records WHERE {_NEW} GROUP BY rule_id"
)
_REVISIONS = (
    f"SELECT rule_id, (raw ->> '{RULE}revision')::int AS revision, raw ->> '{RULE}note' AS note,"  # noqa: S608 - constant fragments; values are bound
    f" min(raw ->> '{RULE}name') AS name, min(detected_at) AS first_seen_at FROM alert_records"
    f" WHERE {_NEW} AND detected_at IS NOT NULL"
    f" AND coalesce(raw ->> '{RULE}revision', '') ~ '^[0-9]{{1,9}}$' GROUP BY 1, 2, 3"
)
# Executions seen among the new alerts, counted over all their alerts (a run's alerts are
# written within minutes of each other: an hour either side holds them all).
_TRUNCATED = (
    "WITH runs AS (SELECT DISTINCT rule_id,"  # noqa: S608 - constant fragments; values are bound
    " raw ->> 'kibana.alert.rule.execution.uuid' AS execution FROM alert_records"
    f" WHERE {_NEW} AND raw ? 'kibana.alert.rule.execution.uuid'),"
    " span AS (SELECT min(detected_at) - interval '1 hour' AS lo,"
    f"  max(detected_at) + interval '1 hour' AS hi FROM alert_records WHERE {_NEW})"
    " SELECT a.rule_id, r.execution, count(*) AS alerts,"
    f"  min(coalesce({_EXECUTED.replace('raw', 'a.raw')}, a.detected_at)) AS at,"
    "  max(CASE WHEN a.raw ->> 'kibana.alert.rule.max_signals' ~ '^[0-9]{1,9}$'"
    "   THEN (a.raw ->> 'kibana.alert.rule.max_signals')::int END) AS max_signals"
    " FROM span, alert_records a JOIN runs r ON r.rule_id = a.rule_id"
    "  AND a.raw ->> 'kibana.alert.rule.execution.uuid' = r.execution"
    " WHERE a.detected_at BETWEEN span.lo AND span.hi"
    " GROUP BY 1, 2"
    " HAVING count(*) >= max(CASE WHEN a.raw ->> 'kibana.alert.rule.max_signals' ~ '^[0-9]{1,9}$'"
    "  THEN (a.raw ->> 'kibana.alert.rule.max_signals')::int END)"
)
_DEFINITION_COLUMNS = (
    "uuid",
    "name",
    "type",
    "version",
    "revision",
    "interval",
    "lookback",
    "max_signals",
    "severity",
    "note",
    "note_hash",
)

_KEEP = ", ".join(  # the definition of the newest readable alert, whichever batch it was in
    f"{c} = CASE WHEN rules.definition_at IS NULL OR EXCLUDED.definition_at >="
    f" rules.definition_at THEN EXCLUDED.{c} ELSE rules.{c} END"
    for c in (*_DEFINITION_COLUMNS, "definition_at")
)
_UPSERT = (
    "INSERT INTO rules (rule_id, uuid, name, type, version, revision, interval, lookback,"  # noqa: S608 - constant fragments; values are bound
    " max_signals, severity, note, note_hash, definition_at, alerts, first_alert_at,"
    " last_alert_at, last_execution_at, execution_status, refreshed_at) VALUES (:rule_id,"
    " :uuid, :name, :type, :version, :revision, :interval, :lookback, :max_signals,"
    " :severity, :note, :note_hash, :definition_at, :alerts, :first, :last, :executed,"
    " 'unknown', :now)"
    f" ON CONFLICT (rule_id) DO UPDATE SET {_KEEP}, alerts = rules.alerts + EXCLUDED.alerts,"
    " first_alert_at = least(rules.first_alert_at, EXCLUDED.first_alert_at),"
    " last_alert_at = greatest(rules.last_alert_at, EXCLUDED.last_alert_at),"
    " last_execution_at = greatest(rules.last_execution_at, EXCLUDED.last_execution_at),"
    " refreshed_at = EXCLUDED.refreshed_at"
)


async def refresh_rules(
    conn: AsyncConnection, now: datetime, batch: int = BATCH, hold: timedelta = HOLD
) -> dict[str, int]:
    """Bring the registry up to date with the alerts stored since the last refresh (no SIEM
    request): counts, first/last alert and execution, the definition from a newer alert, every
    (revision, note), and a closed ``truncated_execution`` gap for every execution that hit
    ``max_signals``. One call reads at most ``batch`` alerts; ``pending`` says how many are left.

    One refresh at a time (an advisory lock); the cursor stays ``hold`` behind the database clock,
    longer than any ingest transaction lasts, because a transaction that began before a refresh may
    commit after it."""
    await conn.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": LOCK_KEY})
    since = (
        await conn.execute(text("SELECT at FROM collector_cursors WHERE name = :n"), {"n": CURSOR})
    ).scalar_one_or_none()
    start = since or datetime(1970, 1, 1, tzinfo=UTC)
    # at most ``batch`` alerts per call (all of the last first_seen_at it reaches)
    upto = (
        await conn.execute(
            text(
                "SELECT max(first_seen_at) FROM (SELECT first_seen_at FROM alert_records"
                " WHERE first_seen_at > :since AND first_seen_at <= now() - :hold"
                " ORDER BY first_seen_at LIMIT :n) s"
            ),
            {"since": start, "n": batch, "hold": hold},
        )
    ).scalar_one()
    known = (await conn.execute(text("SELECT count(*) FROM rules"))).scalar_one()
    if upto is None:
        return {"rules": known, "new_revisions": 0, "new_truncated": 0, "pending": 0}
    window = {"since": start, "upto": upto}
    stats = {row.rule_id: row for row in await conn.execute(text(_NEW_STATS), window)}
    latest = {row.rule_id: row for row in await conn.execute(text(_LATEST), window)}
    for rule_id, s in stats.items():
        rule = latest.get(rule_id)
        if rule is None:  # no readable definition among the new alerts: counts only
            await conn.execute(
                text(
                    "INSERT INTO rules (rule_id, alerts, first_alert_at, last_alert_at,"
                    " last_execution_at, execution_status, refreshed_at) VALUES (:r, :n,"
                    " :first, :last, :executed, 'unknown', :now) ON CONFLICT (rule_id) DO UPDATE"
                    " SET alerts = rules.alerts + EXCLUDED.alerts, last_alert_at ="
                    " greatest(rules.last_alert_at, EXCLUDED.last_alert_at), first_alert_at ="
                    " least(rules.first_alert_at, EXCLUDED.first_alert_at), last_execution_at ="
                    " greatest(rules.last_execution_at, EXCLUDED.last_execution_at),"
                    " refreshed_at = EXCLUDED.refreshed_at"
                ),
                {
                    "n": s.alerts,
                    "last": s.last,
                    "first": s.first,
                    "executed": s.executed,
                    "now": now,
                    "r": rule_id,
                },
            )
            continue
        await conn.execute(
            text(_UPSERT),
            {
                **{k: v for k, v in rule._mapping.items() if k != "detected_at"},
                "definition_at": rule.detected_at,
                "note_hash": note_hash(rule.note),
                "alerts": s.alerts,
                "first": s.first,
                "last": s.last,
                "executed": s.executed,
                "now": now,
            },
        )
    revisions = 0
    for rev in await conn.execute(text(_REVISIONS), window):
        inserted = await conn.execute(
            text(
                "INSERT INTO rule_revisions (rule_id, revision, note_hash, name, first_seen_at)"
                " VALUES (:r, :v, :h, :n, :t) ON CONFLICT DO NOTHING RETURNING 1"
            ),
            {
                "r": rev.rule_id,
                "v": rev.revision,
                "h": note_hash(rev.note),
                "n": rev.name,
                "t": rev.first_seen_at,
            },
        )
        revisions += inserted.first() is not None
    truncated = 0
    for ex in await conn.execute(text(_TRUNCATED), window):
        subject = f"rule:{ex.rule_id}:execution:{ex.execution}"
        added = await conn.execute(  # opened, then closed: what the runtime role may do
            text(
                "INSERT INTO coverage_gaps (kind, subject, start_at, detail)"
                " SELECT 'truncated_execution', :s, :at, :d WHERE NOT EXISTS"
                " (SELECT 1 FROM coverage_gaps WHERE kind = 'truncated_execution'"
                "  AND subject = :s) RETURNING id"
            ),
            {
                "s": subject,
                "at": ex.at,
                "d": f"{ex.alerts} alerts, the rule's limit is {ex.max_signals}: more may exist",
            },
        )
        gap = added.scalar_one_or_none()
        if gap is not None:
            await conn.execute(
                text("UPDATE coverage_gaps SET end_at = start_at WHERE id = :id"), {"id": gap}
            )
        truncated += gap is not None
    await conn.execute(
        text(
            "INSERT INTO collector_cursors (name, at) VALUES (:n, :at)"
            " ON CONFLICT (name) DO UPDATE SET at = EXCLUDED.at, updated_at = now()"
        ),
        {"n": CURSOR, "at": upto},
    )
    rules = (await conn.execute(text("SELECT count(*) FROM rules"))).scalar_one()
    pending = (
        await conn.execute(
            text("SELECT count(*) FROM alert_records WHERE first_seen_at > :upto"), {"upto": upto}
        )
    ).scalar_one()
    return {
        "rules": rules,
        "new_revisions": revisions,
        "new_truncated": truncated,
        "pending": pending,
    }


# ----------------------------------------------------------------------------- TI sources


async def freshness(conn: AsyncConnection) -> list[Freshness]:
    """How fresh each of the site's threat-intel sources is (none configured: an empty list)."""
    rows = await conn.execute(text("SELECT source, newest, checked_at FROM ti_sources"))
    known = {row.source: Freshness(row.source, row.newest, row.checked_at) for row in rows}
    return [known.get(i, Freshness(i, None, None)) for i in site.active().ti_indices]


async def _source(
    conn: AsyncConnection,
    source: str,
    *,
    newest: datetime | None,
    checked_at: datetime | None,
    indicators: int | None,
    error: str | None,
) -> None:
    await conn.execute(
        text(
            "INSERT INTO ti_sources (source, newest, checked_at, indicators, error)"
            " VALUES (:s, :n, :c, :i, :e) ON CONFLICT (source) DO UPDATE SET"
            " newest = coalesce(EXCLUDED.newest, ti_sources.newest),"
            " checked_at = coalesce(EXCLUDED.checked_at, ti_sources.checked_at),"
            " indicators = coalesce(EXCLUDED.indicators, ti_sources.indicators),"
            " error = EXCLUDED.error"
        ),
        {"s": source, "n": newest, "c": checked_at, "i": indicators, "e": error},
    )


def newest_of(result: Result) -> datetime | None:
    """The newest row's time; None if it has none, or one without a time zone."""
    hits = result.body.get("hits", {}).get("hits", []) if isinstance(result.body, dict) else []
    if not hits:
        return None
    stamp = (hits[0].get("_source") or {}).get("@timestamp")
    try:
        parsed = datetime.fromisoformat(str(stamp).replace("Z", "+00:00")) if stamp else None
    except ValueError:
        return None
    return parsed if parsed is not None and parsed.tzinfo is not None else None


async def sync_mirror(
    conn: AsyncConnection, run: Run, now: datetime, source: site.TiSource
) -> dict[str, int]:
    """Replace one mirror source's rows with one complete read: indicators that vanished
    are marked removed, not deleted. A read that cannot hold everything, or an empty one
    while the mirror holds indicators, changes nothing. Documents with no readable
    indicator are counted (``unreadable``)."""
    index = source.index
    result = await run(TiMirrorPage(), mirror_params(source))
    body = result.body if isinstance(result.body, dict) else {}
    hits = body.get("hits", {}).get("hits", [])
    total = body.get("hits", {}).get("total", {})
    count = total.get("value") if isinstance(total, dict) else None
    if not isinstance(count, int) or total.get("relation", "eq") != "eq" or count > MIRROR_SIZE:
        raise IncompleteAnswer(f"{index} holds {count} documents; one read holds {MIRROR_SIZE}")
    if len(hits) != count:
        raise IncompleteAnswer(f"{index}: {len(hits)} of {count} documents returned")
    held = (
        await conn.execute(
            text("SELECT count(*) FROM ti_indicators WHERE source = :s AND removed_at IS NULL"),
            {"s": index},
        )
    ).scalar_one()
    if count == 0 and held:
        raise IncompleteAnswer(f"{index} answered empty; the mirror holds {held}: kept")
    parsed = [from_document(source.schema_, index, hit.get("_source") or {}) for hit in hits]
    unreadable = sum(1 for found in parsed if not found)
    indicators = {(i.kind, i.value, i.type_raw): i for found in parsed for i in found}
    for ind in indicators.values():
        await conn.execute(
            text(
                "INSERT INTO ti_indicators (source, kind, value, type_raw, first_seen, last_seen,"
                " confidence, description, synced_at, removed_at) VALUES (:source, :kind,"
                " :value, :type_raw, :first_seen, :last_seen, :confidence, :description, :now,"
                " NULL) ON CONFLICT (source, kind, value, type_raw) DO UPDATE SET"
                " first_seen = EXCLUDED.first_seen, last_seen = EXCLUDED.last_seen,"
                " confidence = EXCLUDED.confidence, description = EXCLUDED.description,"
                " synced_at = EXCLUDED.synced_at, removed_at = NULL"
            ),
            {**asdict(ind), "now": now},
        )
    removed = await conn.execute(
        text(
            "UPDATE ti_indicators SET removed_at = :now WHERE source = :s AND removed_at IS NULL"
            " AND synced_at < :now RETURNING 1"
        ),
        {"s": index, "now": now},
    )
    error = f"{unreadable} documents without a readable indicator" if unreadable else None
    await _source(
        conn, index, newest=newest_of(result), checked_at=now, indicators=len(indicators),
        error=error,
    )  # fmt: skip
    return {
        "documents": count,
        "indicators": len(indicators),
        "removed": len(removed.all()),
        "unreadable": unreadable,
    }


async def sync_newest(
    conn: AsyncConnection, run: Run, now: datetime, source: site.TiSource
) -> datetime | None:
    """How fresh a looked-up source is (its newest row)."""
    newest = newest_of(await run(TiNewest(), NewestParams(index=source.index)))
    await _source(conn, source.index, newest=newest, checked_at=None, indicators=None, error=None)
    return newest


async def lookup(
    conn: AsyncConnection, run: Run | None, kinds_values: Iterable[tuple[str, str]], now: datetime
) -> list[dict[str, Any]]:
    """Answers for (kind, canonical value) pairs: the mirrors, then the cached lookups of each
    lookup source (asked again, with every spelling the source may store, in batches of
    ``LOOKUP_BATCH`` values when older than 24 h, if ``run`` is given). A match is a match
    whatever kind the source filed it under. Never asked, or asked more than 24 h ago and not
    again: ``not_checked``. A site with no source has an answer with no sources: threat intel
    is off, which is not "clean"."""
    wanted = sorted(set(kinds_values))
    values = sorted({v for _, v in wanted})
    kinds: dict[str, set[str]] = {}
    for kind, value in wanted:
        kinds.setdefault(value, set()).add(kind)
    profile = site.active()
    matches: list[Indicator] = []
    if profile.ti_mirrors:
        mirrored = await conn.execute(
            text(
                "SELECT source, kind, value, type_raw, first_seen, last_seen, confidence,"
                " description FROM ti_indicators WHERE value = ANY(:v) AND removed_at IS NULL"
                " AND source = ANY(:s)"
            ),
            {"v": values, "s": [m.index for m in profile.ti_mirrors]},
        )
        matches = [Indicator(**row._mapping) for row in mirrored]
    current: dict[str, dict[str, Any]] = {}  # lookup source -> value -> cached answer in force
    for source in profile.ti_lookups:
        cached: dict[str, Any] = {
            row.value: row
            for row in await conn.execute(
                text(
                    "SELECT value, indicators, checked_at FROM ti_lookups WHERE source = :s"
                    " AND value = ANY(:v)"
                ),
                {"s": source.index, "v": values},
            )
        }
        due = [v for v in values if v not in cached or now - cached[v].checked_at >= LOOKUP_TTL]
        if run is not None and due:
            await _ask(conn, run, source, due, kinds, cached, now)
        current[source.index] = {v: c for v, c in cached.items() if now - c.checked_at < LOOKUP_TTL}
        for row in current[source.index].values():
            matches += [_indicator(source.index, d) for d in row.indicators]
    sources = await freshness(conn)
    synced = {s.source for s in sources if s.checked_at is not None}
    answers = []
    for kind, value in wanted:
        per = answer(value, matches, sources, now)
        for source in profile.ti_lookups:
            if value not in current[source.index]:  # not asked (recently): not a no-match
                per["sources"][source.index] = {
                    "not_checked": per["sources"][source.index].get("no_match")
                }
        for mirror in profile.ti_mirrors:
            if mirror.index not in synced:
                per["sources"][mirror.index] = {
                    "not_checked": per["sources"][mirror.index].get("no_match")
                }
        per["kind"] = kind
        answers.append(per)
    return answers


async def _ask(
    conn: AsyncConnection,
    run: Run,
    source: site.TiSource,
    due: list[str],
    kinds: dict[str, set[str]],
    cached: dict[str, Any],
    now: datetime,
) -> None:
    """Ask one lookup source for the values it has not answered within a day, and cache what
    it says (an empty answer too)."""
    batches = [due[at : at + LOOKUP_BATCH] for at in range(0, len(due), LOOKUP_BATCH)]
    while batches:
        batch = batches.pop(0)
        terms = sorted({t for v in batch for k in kinds[v] for t in variants(k, v)})
        result = await run(TiLookup(), lookup_params([source], tuple(terms)))
        hits = result.body.get("hits", {}).get("hits", [])
        if len(hits) >= LOOKUP_SIZE and len(batch) > 1:
            # Which values had the rows past the cap is unknown: ask again in halves
            # (a refreshed feed holds many rows per indicator).
            half = len(batch) // 2
            batches[:0] = [batch[:half], batch[half:]]
            continue
        found: dict[str, list[dict[str, Any]]] = {v: [] for v in batch}
        for hit in hits:  # one value past the cap is a match all the same
            for ind in from_document(source.schema_, source.index, hit.get("_source") or {}):
                if ind.value in found:
                    row = _json(ind)
                    if row not in found[ind.value] and len(found[ind.value]) < KEPT_ROWS:
                        found[ind.value].append(row)
        for value, rows in found.items():
            await conn.execute(
                text(
                    "INSERT INTO ti_lookups (source, value, indicators, checked_at)"
                    " VALUES (:s, :v, :i, :now) ON CONFLICT (source, value) DO UPDATE SET"
                    " indicators = EXCLUDED.indicators, checked_at = EXCLUDED.checked_at"
                ).bindparams(bindparam("i", type_=JSONB)),
                {"s": source.index, "v": value, "i": rows, "now": now},
            )
            cached[value] = _Cached(rows, now)
    await _source(conn, source.index, newest=None, checked_at=now, indicators=None, error=None)


class _Cached:
    def __init__(self, indicators: list[dict[str, Any]], checked_at: datetime) -> None:
        self.indicators = indicators
        self.checked_at = checked_at


def _json(ind: Indicator) -> dict[str, Any]:
    return {
        "kind": ind.kind,
        "value": ind.value,
        "type_raw": ind.type_raw,
        "first_seen": None if ind.first_seen is None else ind.first_seen.isoformat(),
        "last_seen": None if ind.last_seen is None else ind.last_seen.isoformat(),
        "confidence": ind.confidence,
        "description": ind.description,
    }


def _indicator(source: str, d: dict[str, Any]) -> Indicator:
    def when(v: Any) -> datetime | None:
        return None if v is None else datetime.fromisoformat(v)

    return Indicator(
        source,
        d["kind"],
        d["value"],
        d["type_raw"],
        when(d["first_seen"]),
        when(d["last_seen"]),
        d["confidence"],
        d["description"],
    )
