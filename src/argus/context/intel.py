"""The threat-intel module of the generic pack.

For an investigation's indicators (IPs that are not private or special, domains, URLs,
hashes): what the TI sources say (the site's mirror sources locally; its lookup
sources from the 24 h cache, or as a budgeted remote lookup once ``reference.ti_sync`` is on),
which other investigations name a listed indicator, when each source host was last seen, and
how regularly the alerts came. Never "clean" from a source that was not checked; a
site with no source configured has threat intel off, and says so.
"""

from __future__ import annotations

import itertools
import statistics
import uuid
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus import site
from argus.assets.classify import IpClassifier
from argus.context.evidence import COMPLETE, SignalValue, derived, local, unknown
from argus.context.packs import TaskSpec
from argus.reference import store as reference
from argus.reference.templates import LOOKUP_SIZE, TiLookup, lookup_params
from argus.reference.ti import canonical, values_of, variants

MAX_VALUES = 40  # indicators checked per investigation
VALUE_CHARS = 100  # the field facts' value length (generic.VALUE_CHARS)
LOOKUP_VALUES = 50  # per remote lookup (with spellings: within the 200 terms)
NO_SOURCES_SENTENCE = (
    "Threat intel: no source is configured (site.ti_sources), so no indicator was checked."
)
SKIP_CLASSES = frozenset({"internal", "special", "invalid"})
URL_FIELDS = ("url.original", "url.full")
HASH_FIELDS = ("file.hash.sha256", "file.hash.sha1", "file.hash.md5")


def _values(
    entities: Sequence[tuple[str, str]],
    fields: Mapping[str, Any],
    classifier: IpClassifier | None,
    complete: bool,
) -> tuple[list[tuple[str, str]], bool]:
    """The indicators to check, and whether the list was cut: more than ``MAX_VALUES``, a URL
    or hash field with more values than the facts show, values cut to the facts' length, or
    alerts not all read. A cut list cannot be called clean."""
    found: list[tuple[str, str]] = []
    cut = False
    classify = classifier or IpClassifier(None)  # without the map private space is still known
    for kind, value in entities:
        if kind not in ("ip", "domain"):
            continue
        if kind == "ip" and classify.classify(value).ip_class.value in SKIP_CLASSES:
            continue
        got = canonical(kind, value)
        if got is not None:
            found.append((kind, got))
    for kind, paths in (("url", URL_FIELDS), ("hash", HASH_FIELDS)):
        for path in paths:
            fact = fields.get(path, {})
            top = fact.get("top", [])
            if top and (not complete or fact.get("distinct", 0) > len(top)):
                cut = True
            for value, _ in top:
                if len(str(value)) >= VALUE_CHARS:  # cut by the field facts: cannot match
                    cut = True
                    continue
                got = canonical(kind, value)
                if got is not None:
                    found.append((kind, got))
    unique = sorted(set(found))
    return unique[:MAX_VALUES], cut or len(unique) > MAX_VALUES


async def context(
    conn: AsyncConnection,
    facts: Mapping[str, Any],
    fields: Mapping[str, Any],
    classifier: IpClassifier | None,
    complete: bool = True,
    now: datetime | None = None,
) -> dict[str, Any]:
    inv = uuid.UUID(str(facts["investigation_id"]))
    entities = [
        (str(k), str(v))
        for k, v in await conn.execute(
            text(
                "SELECT kind, value FROM investigation_entities WHERE investigation_id = :i"
                " ORDER BY kind, value"
            ),
            {"i": inv},
        )
    ]
    pairs, cut = _values(entities, fields, classifier, complete)
    now = now or datetime.now(UTC)
    answers = await reference.lookup(conn, None, pairs, now) if pairs else []
    listed = [a["value"] for a in answers if any("match" in s for s in a["sources"].values())]
    same: dict[str, int] = {}
    for value in listed[:10]:
        same[value] = (
            await conn.execute(
                text(
                    "SELECT count(DISTINCT investigation_id) FROM investigation_entities"
                    " WHERE value = :v AND investigation_id <> :i"
                ),
                {"v": value, "i": inv},
            )
        ).scalar_one()
    hosts = [v for k, v in entities if k == "ip"][:10]
    seen: dict[str, Any] = {}
    for host in hosts:
        last = (
            await conn.execute(
                text(
                    "SELECT max(i.last_event_at) FROM investigation_entities e"
                    " JOIN investigations i ON i.id = e.investigation_id"
                    " WHERE e.kind = 'ip' AND e.value = :v AND e.investigation_id <> :i"
                ),
                {"v": host, "i": inv},
            )
        ).scalar_one()
        seen[host] = None if last is None else last.isoformat()
    times = list(
        (
            await conn.execute(
                text(
                    "SELECT a.detected_at FROM investigation_alerts l JOIN alert_records a"
                    " ON a.alert_id = l.alert_id WHERE l.investigation_id = :i"
                    " AND l.duplicate_of IS NULL AND a.detected_at IS NOT NULL"
                    " ORDER BY a.detected_at LIMIT 1000"
                ),
                {"i": inv},
            )
        ).scalars()
    )
    gaps = [(b - a).total_seconds() for a, b in itertools.pairwise(times)]
    cadence = None
    if len(gaps) >= 3 and statistics.fmean(gaps) > 0:
        cadence = round(statistics.pstdev(gaps) / statistics.fmean(gaps), 3)
    return {
        "values": [list(p) for p in pairs],
        "cut": cut,
        "answers": answers,
        "listed": listed,
        "same_ioc": same,
        "host_last_seen": seen,
        "cadence_cv": cadence,
        "cadence_alerts": len(times),
    }


def tasks(ti: Mapping[str, Any]) -> list[TaskSpec]:
    """Remote lookups of the values some lookup source has not answered within 24 h: one request
    asks every lookup source at once."""
    lookups = site.active().ti_lookups
    due = [
        (k, v)
        for (k, v), a in zip(ti.get("values", []), ti.get("answers", []), strict=False)
        if any("not_checked" in a["sources"].get(s.index, {}) for s in lookups)
    ]
    found = []
    for at in range(0, len(due), LOOKUP_VALUES):
        batch = due[at : at + LOOKUP_VALUES]
        terms = tuple(sorted({t for k, v in batch for t in variants(k, v)}))
        found.append(TaskSpec(TiLookup(), lookup_params(lookups, terms, LOOKUP_SIZE)))
    return found


def remote_matches(snapshots: Mapping[str, Any], wanted: Sequence[str]) -> list[str]:
    rows = [r.get("_source") or {} for s in snapshots.values() for r in (s or {}).get("rows", [])]
    found = {value for row in rows for value in values_of(row)}
    return sorted(v for v in wanted if v in found)


def _source_state(
    answers: Sequence[Mapping[str, Any]], source: str, remote_checked: bool = False
) -> str:
    """fresh | stale | not_checked: how much a miss in this source says. ``remote_checked``:
    the values the cache had not answered were asked live, completely, in this run."""
    states = [a["sources"].get(source, {}) for a in answers]
    if not states:
        return "not_checked"
    seen = []
    for state in states:
        if "not_checked" in state:
            if not remote_checked:
                return "not_checked"
            state = {"no_match": state["not_checked"]}
        seen.append(state.get("no_match") or state.get("freshness") or {})
    return "fresh" if all(f.get("stale") is False for f in seen) else "stale"


def _remote(
    evidence: Mapping[str, Mapping[str, Any]], snaps: Any, values: Sequence[str]
) -> tuple[list[str], bool]:
    """The live lookup's matches (from evidence complete in status) and whether it covered
    everything it was asked (complete in coverage too)."""
    refs = list(evidence.values())
    if not refs or any(str(r["status"]) not in COMPLETE for r in refs):
        return [], False
    full = not any(r.get("truncated") or r.get("coverage") for r in refs)
    return remote_matches(snaps, values), full


def signals(
    version: int, ti: Mapping[str, Any], evidence: Mapping[str, Mapping[str, Any]], snaps: Any
) -> list[SignalValue]:
    """``ti.listed`` counts the indicators any source lists (the stored answers and the live
    lookup); 0 is known only when every source was checked and fresh for every indicator and
    the list was not cut."""
    answers = ti.get("answers", [])
    out = [
        local("ti.values", version, len(answers)),
        local("same_ioc.investigations", version, sum(ti.get("same_ioc", {}).values())),
    ]
    cadence = ti.get("cadence_cv")
    out.append(
        local("alerts.cadence_cv", version, cadence)
        if cadence is not None
        else unknown("alerts.cadence_cv", version, "too_few_alerts")
    )
    values = [v for _, v in ti.get("values", [])]
    refs = list(evidence.values())
    keys = tuple(sorted(str(r["task_key"]) for r in refs))
    if refs:  # a remote lookup ran: its matches count only from complete evidence
        out.append(
            derived(
                "ti.listed_remote", version, refs,
                lambda: len(remote_matches(snaps, values)), counts=True,
            )
        )  # fmt: skip
    remote, full = _remote(evidence, snaps, values)
    listed = sorted(set(ti.get("listed", [])) | set(remote))
    states = [
        _source_state(answers, s.index, remote_checked=full and s.mode == "lookup")
        for s in site.active().ti_sources
    ]
    cut = bool(ti.get("cut"))
    if listed:
        out.append(
            SignalValue(
                "ti.listed", version, len(listed), "known", None,
                "lower_bound" if cut else "exact", keys,
            )
        )  # fmt: skip
    elif not site.active().ti_sources:
        out.append(unknown("ti.listed", version, "no_sources"))
    elif not answers:
        out.append(unknown("ti.listed", version, "values_cut" if cut else "no_indicators"))
    elif "not_checked" in states:
        out.append(unknown("ti.listed", version, "source_not_checked", keys))
    elif "stale" in states:
        out.append(unknown("ti.listed", version, "source_stale", keys))
    elif cut:
        out.append(unknown("ti.listed", version, "values_cut", keys))
    else:
        out.append(SignalValue("ti.listed", version, 0, "known", None, "exact", keys))
    return out


def sentence(ti: Mapping[str, Any], derived: Sequence[Mapping[str, Any]] = ()) -> str | None:
    """What the TI module says for a step that asks for reputation, from ``ti.listed`` (None:
    nothing to say, the step stays deferred)."""
    answers = ti.get("answers", [])
    listed = next((s for s in derived if s.get("name") == "ti.listed"), None)
    if listed is not None and listed.get("unknown_reason") == "no_sources":
        return NO_SOURCES_SENTENCE
    if not answers or listed is None or listed.get("status") != "known":
        return None
    states = {s.index: _source_state(answers, s.index) for s in site.active().ti_sources}
    where = "; ".join(f"{s}: {state.replace('_', ' ')}" for s, state in states.items())
    count = int(listed["value"])
    if count:
        names = ti.get("listed", [])[:5]
        more = count - len(ti.get("listed", []))
        shown = ", ".join(names) + (f", and {more} from the live lookup" if more > 0 else "")
        least = "at least " if listed.get("completeness") == "lower_bound" else ""
        return (
            f"Threat intel: {least}{count} of {len(answers)} on a list ({shown.lstrip(', ')})."
            f" ({where})"
        )
    return f"Threat intel: none of {len(answers)} on a list. ({where})"
