"""Action tracking for a case, on the database: :func:`actions_for` (the catalogue's advice, what
is stored and the newest verdict; writes nothing), :func:`recommend`, :func:`request` /
:func:`report_done` (a person's words: an attestation) and :func:`refresh` (ARGUS's verdict when
the evidence is definite). The web's login runs the same functions and may only insert or update a
person's ``requested`` or ``reported_done``. Nothing here reaches the SIEM, Kibana or a model."""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from argus import site
from argus.cases import watch, watchrun
from argus.cases.model import CONFIRMED, Actor, Capability, QuietWindow
from argus.cases.service import CaseService
from argus.db.audit import record_audit
from argus.responder import catalogue as cat
from argus.responder import facts as fct
from argus.responder import machine
from argus.responder.machine import ActionRefused, State, Verdict

ACTOR = Actor.argus("responder")
_cache: dict[tuple[str, int, int], cat.Catalogue] = {}


def current(path: Path | None = None) -> cat.Catalogue:
    """The catalogue, read again when the file changes (the path, its size and its mtime)."""
    where = cat.PATH if path is None else path
    try:
        info = where.stat()
    except OSError:
        return cat.load(where)  # raises the catalogue's own error
    key = (str(where), info.st_mtime_ns, info.st_size)
    if key not in _cache:
        _cache.clear()
        _cache[key] = cat.load(where)
    return _cache[key]


@dataclass(frozen=True)
class Stored:
    id: int
    action: str
    family: str
    owner: str
    catalogue_version: int
    state: State
    requested_at: datetime | None
    requested_by: str | None
    requested_name: str | None
    reported_at: datetime | None
    reported_by: str | None
    reported_name: str | None
    attestation: str | None
    verdict_at: datetime | None
    verdict: str | None
    last_beat: datetime | None


@dataclass(frozen=True)
class ActionView:
    """One action of a case as a page shows it. ``stored_state`` is None while ARGUS has not
    recorded it yet (a recommendation computed now); ``state`` is what holds now."""

    action: str
    family: str
    family_title: str
    title: str
    say: str
    owner: str
    owner_name: str
    rank: int
    state: State
    stored_state: State | None
    id: int | None
    requested_by: str | None
    requested_name: str | None
    requested_at: datetime | None
    reported_by: str | None
    reported_name: str | None
    reported_at: datetime | None
    attestation: str | None
    verifier: str
    verdict: Verdict | None
    last_beat: datetime | None
    advised: bool
    detail: str


_STORED = text(
    "SELECT a.id, a.action, a.family, a.owner, a.catalogue_version, a.state, a.requested_at,"
    " a.requested_by, ru.display_name AS requested_name, a.reported_at, a.reported_by,"
    " rp.display_name AS reported_name, a.attestation, a.verdict_at, a.verdict, a.last_beat"
    " FROM case_actions a"
    " LEFT JOIN users ru ON a.requested_by = 'user:' || ru.id"
    " LEFT JOIN users rp ON a.reported_by = 'user:' || rp.id"
    " WHERE a.case_id = :c ORDER BY a.id"
)


async def _case(conn: AsyncConnection, case_id: uuid.UUID) -> Any:
    return (
        await conn.execute(
            text("SELECT id, number, state FROM cases WHERE id = :c"), {"c": case_id}
        )
    ).first()


async def stored(conn: AsyncConnection, case_id: uuid.UUID) -> list[Stored]:
    return [
        Stored(
            r.id,
            r.action,
            r.family,
            r.owner,
            r.catalogue_version,
            r.state,
            r.requested_at,
            r.requested_by,
            r.requested_name,
            r.reported_at,
            r.reported_by,
            r.reported_name,
            r.attestation,
            r.verdict_at,
            r.verdict,
            r.last_beat,
        )
        for r in await conn.execute(_STORED, {"c": case_id})
    ]


async def _readings(
    conn: AsyncConnection, case_id: uuid.UUID, done_at: datetime, required: frozenset[str]
) -> list[machine.PathReading]:
    """The newest stored ``web.path_outcomes`` answers of the case's investigations asked after
    ``done_at`` about any of the ``required`` paths: when, from when they read, and each path's
    outcome. The newest are read, so a later check (the path served again) is never the one left
    out."""
    rows = await conn.execute(
        text(
            "SELECT e.params, e.snapshot, e.asked_at FROM evidence e JOIN case_members m"
            " ON m.investigation_id = e.investigation_id WHERE m.case_id = :c"
            " AND m.removed_at IS NULL AND e.template = 'web.path_outcomes'"
            " AND e.status IN ('ok', 'empty') AND e.snapshot IS NOT NULL"
            " AND e.asked_at IS NOT NULL AND e.asked_at > :t"
            " AND jsonb_exists_any(e.params -> 'paths', CAST(:req AS text[]))"
            " ORDER BY e.asked_at DESC, e.task_key LIMIT :n"
        ),
        {"c": case_id, "t": done_at, "req": sorted(required), "n": fct.EVIDENCE_READ},
    )
    out = []
    for row in rows:
        params = row.params
        if not isinstance(params, Mapping):
            continue
        asked = params.get("paths")
        start = params.get("start")
        if not isinstance(asked, list) or not isinstance(start, str):
            continue
        try:
            began = datetime.fromisoformat(start)
        except ValueError:
            continue
        if began.tzinfo is None:
            continue
        outcomes = fct.outcomes_of(row.snapshot, asked)
        out.append(machine.PathReading(row.asked_at, began, {o.path: o.outcome for o in outcomes}))
    return out


async def verdict_for(
    conn: AsyncConnection,
    case_id: uuid.UUID,
    action: cat.Action,
    row: Stored,
    now: datetime,
    *,
    ctx: watchrun.Context | None,
    facts: fct.Facts,
    family: cat.Family | None,
    memo: dict[uuid.UUID, QuietWindow] | None = None,
) -> Verdict:
    """The verdict on a reported "done" from what the database holds. For the watch's verifiers
    (the proxy logs, ARGUS's alerts) the days after the action must pass, nothing may have been
    active since, and then the watch's own finder (:class:`argus.cases.watchrun.Finder`)
    must call the case quiet: it blocks a key too common to search and looks for matching
    investigations not yet joined. Without ``ctx`` it cannot be asked, so nothing is verified.
    ``memo`` keeps the finder's answer for one case within a pass."""
    assert row.reported_at is not None
    verify = action.verify
    if verify.kind == "none":
        return machine.not_verifiable(verify.not_verifiable or "no check is defined")
    if verify.kind == "web.path_outcomes":
        required = fct.required_paths(facts, family) if family is not None else frozenset()
        readings = await _readings(conn, case_id, row.reported_at, required) if required else []
        return machine.verify_paths(required, readings, row.reported_at)
    done_day = watch.utc_day(row.reported_at)
    found = await watchrun.rows(conn, case_id, done_day)
    activity = await watchrun.alert_activity(conn, case_id, (), watch.day_window(done_day)[0])
    gate = machine.gate_watch(verify.kind, found, activity, ctx is not None, row.reported_at, now)
    if gate is not None:
        return gate
    if ctx is None:
        return Verdict(
            "waiting", "waiting: the watch's settings are not available here, so ARGUS cannot"
            " vouch that the case stayed quiet",
        )  # fmt: skip
    window = memo.get(case_id) if memo is not None else None
    if window is None:
        case = await CaseService(conn, now).get(case_id)
        if case is None:
            return Verdict("waiting", "waiting: the case cannot be read")
        window = await watchrun.Finder(conn, ctx, lambda: now)(case)
        if memo is not None:
            memo[case_id] = window
    return machine.window_verdict(window)


def _detail(
    spec: cat.Action, owner: str, state: State, row: Stored | None, verdict: Verdict | None
) -> str:
    """One plain line about where the action stands. A person's own words (the attestation)
    are not put into it: they are shown apart, as the text they are."""
    if row is None or state == "recommended":
        return f"Recommended. Owner: {owner}."
    if state == "requested":
        who = row.requested_name or row.requested_by
        when = machine.ist12(row.requested_at) if row.requested_at else "an unknown time"
        return f"Requested: the {owner} was asked by {who} at {when}."
    who = row.reported_name or row.reported_by
    when = machine.ist12(row.reported_at) if row.reported_at else "an unknown time"
    told = f"Reported done by {who} at {when} (an attestation: ARGUS cannot see the action)."
    if verdict is None and state == "verified":  # the record stands; the check cannot be repeated
        when = machine.ist_day(row.verdict_at) if row.verdict_at else "an unknown date"
        return f"{told} Verified on {when} ({site.zone_label()}), not re-checked since."
    if verdict is None:  # not verified earlier, and nothing newer to say
        verdict = Verdict("not_verified", row.verdict or "", row.last_beat)
    said = machine.say(verdict, spec.verify.kind).rstrip(".")
    return f"{told} {said[:1].upper()}{said[1:]}."


async def actions_for(
    conn: AsyncConnection,
    case_id: uuid.UUID,
    *,
    ctx: watchrun.Context | None = None,
    now: datetime | None = None,
    catalogue: cat.Catalogue | None = None,
) -> list[ActionView]:
    """Every action of a case, advice first (in the catalogue's order), then actions recorded
    before that the advice no longer names. Reads only. ``ctx`` is the watch's context
    (:func:`argus.cases.watchrun.context_for`): without it a reported "done" of a proxy-log
    action can be found *not verified* (activity after it) but never *verified*, because the
    case's addresses cannot be listed."""
    now = now or datetime.now(UTC)
    catalogue = catalogue or current()
    case = await _case(conn, case_id)
    if case is None:
        return []
    held = {r.action: r for r in await stored(conn, case_id)}
    facts = fct.Facts()
    advised: dict[str, cat.Family] = {}
    if case.state in CONFIRMED:
        facts = await fct.read_facts(conn, case_id)
        for family in fct.match(catalogue, facts):
            for action in family.actions:
                advised[action.id] = family
    ids = [*advised, *sorted(set(held) - set(advised))]
    memo: dict[uuid.UUID, QuietWindow] = {}
    views = []
    for action_id in ids:
        spec = catalogue.action(action_id)
        if spec is None:  # recorded under an action the catalogue no longer has
            continue
        row = held.get(action_id)
        family = advised.get(action_id) or catalogue.family(spec.family)
        owner = catalogue.owners[spec.owner].name
        state: State = row.state if row else "recommended"
        shown: Verdict | None = None
        if row is not None and row.state in ("reported_done", "verified", "not_verified"):
            live = await verdict_for(
                conn, case_id, spec, row, now,
                ctx=ctx, facts=facts, family=advised.get(action_id), memo=memo,
            )  # fmt: skip
            state = machine.settle(row.state, live)
            if state == "reported_done" or live.kind == state:
                shown = live  # what holds now; else the record's own words stand
        last = shown.last if shown is not None and shown.kind == "not_verified" else None
        views.append(
            ActionView(
                action_id,
                spec.family,
                family.title,
                spec.title,
                spec.say,
                spec.owner,
                owner,
                spec.rank,
                state,
                row.state if row else None,
                row.id if row else None,
                row.requested_by if row else None,
                row.requested_name if row else None,
                row.requested_at if row else None,
                row.reported_by if row else None,
                row.reported_name if row else None,
                row.reported_at if row else None,
                row.attestation if row else None,
                spec.verify.kind,
                shown,
                last or (row.last_beat if row and state == "not_verified" else None),
                action_id in advised,
                _detail(spec, owner, state, row, shown),
            )
        )
    return views


async def _audit(
    conn: AsyncConnection, actor: Actor, action: str, case_id: uuid.UUID, details: Mapping[str, Any]
) -> None:
    session = AsyncSession(bind=conn)
    try:
        await record_audit(
            session,
            actor=actor.name,
            action=action,
            target_type="case",
            target_id=str(case_id),
            details=dict(details),
        )
    finally:
        await session.close()


async def recommend(
    conn: AsyncConnection,
    case_id: uuid.UUID,
    now: datetime,
    *,
    catalogue: cat.Catalogue | None = None,
) -> list[str]:
    """Record the advice for a confirmed case: the catalogue's actions for the families the
    case shows, each once. Returns the ids newly recorded. Deterministic: no model is asked."""
    catalogue = catalogue or current()
    case = await _case(conn, case_id)
    if case is None:
        raise ActionRefused("not_found", "no such case")
    if case.state not in CONFIRMED:
        raise ActionRefused(
            "conflict", f"advice is given for a confirmed case; this one is {case.state}"
        )
    families = fct.match(catalogue, await fct.read_facts(conn, case_id))
    new = []
    for family in families:
        for action in family.actions:
            done = await conn.execute(
                text(
                    "INSERT INTO case_actions (case_id, action, family, owner,"
                    " catalogue_version, state, recommended_at, recommended_by)"
                    " VALUES (:c, :a, :f, :o, :v, 'recommended', :t, :by)"
                    " ON CONFLICT (case_id, action) DO NOTHING RETURNING id"
                ),
                {
                    "c": case_id,
                    "a": action.id,
                    "f": family.key,
                    "o": action.owner,
                    "v": catalogue.version,
                    "t": now,
                    "by": ACTOR.name,
                },
            )
            if done.first() is not None:
                new.append(action.id)
    if new:
        details = {"number": case.number, "actions": new, "catalogue": catalogue.version}
        await _audit(conn, ACTOR, "case.actions_recommended", case_id, details)
    return new


def _person(actor: Actor) -> None:
    if not actor.may(Capability.MANAGE):
        raise ActionRefused("forbidden", "recording what was done about a case needs manage_cases")


# A person's rows: only the columns the web's login may write (migration 0044)
_INSERT = {
    "requested": text(
        "INSERT INTO case_actions (case_id, action, family, owner, catalogue_version, state,"
        " requested_at, requested_by) VALUES (:c, :a, :f, :o, :v, :s, :t, :by)"
        " ON CONFLICT (case_id, action) DO NOTHING RETURNING id"
    ),
    "reported_done": text(
        "INSERT INTO case_actions (case_id, action, family, owner, catalogue_version, state,"
        " reported_at, reported_by, attestation) VALUES (:c, :a, :f, :o, :v, :s, :t, :by, :att)"
        " ON CONFLICT (case_id, action) DO NOTHING RETURNING id"
    ),
}
_UPDATE = {
    "requested": text(
        "UPDATE case_actions SET state = :s, requested_at = :t, requested_by = :by"
        " WHERE id = :i AND state = :old RETURNING id"
    ),
    "reported_done": text(
        "UPDATE case_actions SET state = :s, reported_at = :t, reported_by = :by,"
        " attestation = :att WHERE id = :i AND state = :old RETURNING id"
    ),
}


async def _row(conn: AsyncConnection, case_id: uuid.UUID, action_id: str) -> Any:
    return (
        await conn.execute(
            text(
                "SELECT id, state FROM case_actions WHERE case_id = :c AND action = :a FOR UPDATE"
            ),
            {"c": case_id, "a": action_id},
        )
    ).first()


async def _person_move(
    conn: AsyncConnection,
    case_id: uuid.UUID,
    action_id: str,
    actor: Actor,
    now: datetime,
    to: State,
    attestation: str | None,
    catalogue: cat.Catalogue,
) -> State | None:
    """A person's request or report: inserted, or moved from where the row is (the database
    holds the same edges)."""
    _person(actor)
    spec = catalogue.action(action_id)
    if spec is None:
        raise ActionRefused("invalid", f"{action_id!r} is not an action of the catalogue")
    family = catalogue.family(spec.family)
    case = await _case(conn, case_id)
    if case is None:
        raise ActionRefused("not_found", "no such case")
    row = await _row(conn, case_id, action_id)
    before: State | None = row.state if row else None
    machine.move(before, to, person=True)
    if row is None:  # not recorded yet: it must be one the case is advised
        if case.state not in CONFIRMED:
            raise ActionRefused("conflict", f"advice is for a confirmed case; this is {case.state}")
        if family not in fct.match(catalogue, await fct.read_facts(conn, case_id)):
            raise ActionRefused("conflict", f"{action_id} is not advised for this case")
    sql = (_INSERT if row is None else _UPDATE)[to]
    done = await conn.execute(
        sql,
        {
            "c": case_id,
            "a": action_id,
            "f": family.key,
            "o": spec.owner,
            "v": catalogue.version,
            "s": to,
            "t": now,
            "by": actor.name,
            "att": attestation,
            "i": row.id if row else None,
            "old": before,
        },
    )
    if done.first() is None:  # someone else recorded it (or moved it) first
        raise ActionRefused("conflict", "the action changed meanwhile; look again")
    return before


async def request(
    conn: AsyncConnection,
    case_id: uuid.UUID,
    action_id: str,
    actor: Actor,
    now: datetime,
    *,
    catalogue: cat.Catalogue | None = None,
) -> None:
    """A person asked the owner to do the action (``requested``)."""
    catalogue = catalogue or current()
    before = await _person_move(conn, case_id, action_id, actor, now, "requested", None, catalogue)
    details = {"action": action_id, "from": before, "via": actor.via}
    await _audit(conn, actor, "case.action_requested", case_id, details)


async def report_done(
    conn: AsyncConnection,
    case_id: uuid.UUID,
    action_id: str,
    actor: Actor,
    attestation: str,
    now: datetime,
    *,
    catalogue: cat.Catalogue | None = None,
) -> None:
    """A person says the action was done (``reported_done``): an attestation, in their words.
    A new report after "not verified" starts the check again from the new time."""
    catalogue = catalogue or current()
    said = machine.attest(attestation)
    before = await _person_move(
        conn, case_id, action_id, actor, now, "reported_done", said, catalogue
    )
    details = {"action": action_id, "from": before, "attestation": said, "via": actor.via}
    await _audit(conn, actor, "case.action_reported_done", case_id, details)


async def refresh(
    conn: AsyncConnection,
    case_id: uuid.UUID,
    now: datetime,
    *,
    ctx: watchrun.Context | None = None,
    catalogue: cat.Catalogue | None = None,
) -> list[tuple[str, State]]:
    """Record ARGUS's verdict on every reported "done" whose evidence is definite: verified,
    or not verified (with the last sign of activity, updated when a newer one is seen). A
    waiting or not-verifiable action keeps its state. Returns the moves made."""
    held = {r.id: r for r in await stored(conn, case_id)}
    moved = []
    for view in await actions_for(conn, case_id, ctx=ctx, now=now, catalogue=catalogue):
        verdict = view.verdict
        if view.id is None or view.stored_state is None or verdict is None:
            continue
        again = (
            view.state == view.stored_state == "not_verified"
            and verdict.kind == "not_verified"
            and verdict.last != held[view.id].last_beat
        )
        if view.state == view.stored_state and not again:
            continue
        machine.move(view.stored_state, view.state, person=False)
        done = await conn.execute(
            text(
                "UPDATE case_actions SET state = :s, verdict_at = :t, verdict = :v,"
                " last_beat = :b WHERE id = :i AND state = :old AND reported_at = :r RETURNING id"
            ),
            {
                "s": view.state,
                "t": now,
                "v": verdict.reason[:300],
                "b": verdict.last if view.state == "not_verified" else None,
                "i": view.id,
                "old": view.stored_state,
                "r": view.reported_at,  # the verdict is for this report, not a newer one
            },
        )
        if done.first() is not None:
            moved.append((view.action, view.state))
            last = verdict.last.isoformat() if verdict.last else None
            details = {"action": view.action, "from": view.stored_state, "last": last}
            await _audit(conn, ACTOR, f"case.action_{view.state}", case_id, details)
    return moved
