# ruff: noqa: S608 - the f-strings put fixed column lists in the SQL; values are bound
"""The case team's database access.

Every function takes the connection of the transaction it belongs to and the time from the caller.
The writer's login moves the posts and steps, the web's records approvals, the runtime login the
verdict comments it read. Steps only move forward (``planned -> sending -> sent -> verified``, into
doubt or out of the way); a step's text and payload never change once written."""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import Any, cast

from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.caseteam import visual
from argus.caseteam.model import (
    DONE_STATES,
    OPEN_STATES,
    PERSON_EDIT,
    Author,
    Plan,
    Step,
    left_by_person,
)
from argus.caseteam.plan import Posted, PostedComment, PostedGlance

LOOKUP_AFTER = (
    timedelta(minutes=2),
    timedelta(minutes=5),
    timedelta(minutes=15),
    timedelta(minutes=30),
)  # the writer's schedule (kibana-cases.md): a write in doubt is looked for four times
LOCK_KEY = int.from_bytes(b"ARGUSTEM", "big") >> 1  # one case-team run at a time (advisory lock)
STEP_COLUMNS = (
    "id, case_id, gen, seq, key, kind, author, part, report_version, payload, text_body, units,"
    " request_hash, state, state_reason, sent_count, kibana_ids, lookups, next_lookup_at, sent_at,"
    " verified_at"
)


@dataclass(frozen=True)
class PostRow:
    case_id: uuid.UUID
    incident_id: str
    kibana_case_id: str | None
    state: str
    held_reason: str | None
    opened_at: datetime | None
    last_version: int | None
    last_round_at: datetime | None


@dataclass(frozen=True)
class StepRow:
    id: int
    case_id: uuid.UUID
    gen: int
    seq: int
    key: str
    kind: str
    author: str
    part: str
    report_version: int
    payload: Mapping[str, Any]
    text_body: str | None
    units: tuple[str, ...]
    request_hash: str
    state: str
    state_reason: str | None
    sent_count: int
    kibana_ids: Mapping[str, Any] = field(default_factory=dict)
    lookups: int = 0
    next_lookup_at: datetime | None = None
    sent_at: datetime | None = None
    verified_at: datetime | None = None

    def step(self) -> Step:
        """The planned step this row holds (its text and payload as written)."""
        return Step(
            self.key,
            cast(Any, self.kind),
            Author(self.author),
            self.part,
            self.text_body,
            dict(self.payload),
            self.units,
            self.request_hash,
        )


def _step_row(r: Any) -> StepRow:
    return StepRow(
        int(r.id),
        r.case_id,
        int(r.gen),
        int(r.seq),
        r.key,
        r.kind,
        r.author,
        r.part,
        int(r.report_version),
        dict(r.payload),
        r.text_body,
        tuple(r.units),
        r.request_hash,
        r.state,
        r.state_reason,
        int(r.sent_count),
        dict(r.kibana_ids),
        int(r.lookups),
        r.next_lookup_at,
        r.sent_at,
        r.verified_at,
    )


async def post_of(conn: AsyncConnection, case_id: uuid.UUID) -> PostRow | None:
    r = (
        await conn.execute(
            text(
                "SELECT case_id, incident_id, kibana_case_id, state, held_reason, opened_at,"
                " last_version, last_round_at FROM case_team_posts WHERE case_id = :c"
            ),
            {"c": case_id},
        )
    ).first()
    return (
        None
        if r is None
        else PostRow(
            r.case_id,
            r.incident_id,
            r.kibana_case_id,
            r.state,
            r.held_reason,
            r.opened_at,
            r.last_version,
            r.last_round_at,
        )
    )


async def steps_of(
    conn: AsyncConnection, case_id: uuid.UUID, gen: int | None = None
) -> list[StepRow]:
    rows = await conn.execute(
        text(
            f"SELECT {STEP_COLUMNS} FROM case_team_steps WHERE case_id = :c"
            " AND (CAST(:g AS integer) IS NULL OR gen = CAST(:g AS integer)) ORDER BY gen, seq"
        ),
        {"c": case_id, "g": gen},
    )
    return [_step_row(r) for r in rows]


async def step_by_id(conn: AsyncConnection, step_id: int) -> StepRow | None:
    r = (
        await conn.execute(
            text(f"SELECT {STEP_COLUMNS} FROM case_team_steps WHERE id = :i"), {"i": step_id}
        )
    ).first()
    return None if r is None else _step_row(r)


async def latest_gen(conn: AsyncConnection, case_id: uuid.UUID) -> int:
    return int(
        (
            await conn.execute(
                text("SELECT coalesce(max(gen), 0) FROM case_team_steps WHERE case_id = :c"),
                {"c": case_id},
            )
        ).scalar_one()
    )


async def ensure_post(conn: AsyncConnection, case_id: uuid.UUID, incident_id: str) -> PostRow:
    await conn.execute(
        text(
            "INSERT INTO case_team_posts (case_id, incident_id) VALUES (:c, :i)"
            " ON CONFLICT (case_id) DO NOTHING"
        ),
        {"c": case_id, "i": incident_id},
    )
    found = await post_of(conn, case_id)
    assert found is not None
    return found


async def write_generation(conn: AsyncConnection, case_id: uuid.UUID, plan: Plan) -> None:
    """The plan's steps as ``planned`` rows, in order (the generation number must be free)."""
    statement = text(
        "INSERT INTO case_team_steps (case_id, gen, seq, key, kind, author, part, report_version,"
        " payload, text_body, units, request_hash) VALUES (:c, :g, :n, :k, :kind, :a, :p, :v,"
        " :payload, :t, :units, :h)"
    ).bindparams(bindparam("payload", type_=JSONB), bindparam("units", type_=JSONB))
    for n, step in enumerate(plan.steps, 1):
        await conn.execute(
            statement,
            {
                "c": case_id,
                "g": plan.gen,
                "n": n,
                "k": step.key,
                "kind": step.kind,
                "a": step.author.value,
                "p": step.part,
                "v": plan.report_version,
                "payload": step.payload,
                "t": step.text,
                "units": list(step.units),
                "h": step.request_hash,
            },
        )


def plan_of(rows: Sequence[StepRow], incident_id: str, kibana_case_id: str | None) -> Plan:
    """The plan a generation's rows hold (its hash is the one an approval bound)."""
    first = rows[0]
    return Plan(
        incident_id,
        str(first.case_id),
        first.gen,
        first.report_version,
        tuple(r.step() for r in rows),
        kibana_case_id,
    )


async def supersede_planned(conn: AsyncConnection, case_id: uuid.UUID, gen: int, why: str) -> int:
    """A generation nothing was sent for is replaced by a new plan: its rows step aside."""
    done = await conn.execute(
        text(
            "UPDATE case_team_steps SET state = 'superseded', state_reason = :w"
            " WHERE case_id = :c AND gen = :g AND state = 'planned' AND sent_count = 0"
        ),
        {"c": case_id, "g": gen, "w": why[:300]},
    )
    return int(done.rowcount)


async def begin_sending(conn: AsyncConnection, step_id: int, now: datetime) -> None:
    """``planned`` (or a person's ``resend``) -> ``sending``, counted and committed before the
    request leaves; the request goes once."""
    moved = await conn.execute(
        text(
            "UPDATE case_team_steps SET state = 'sending', sent_count = sent_count + 1,"
            " sent_at = :now, state_reason = NULL, next_lookup_at = NULL, lookups = 0"
            " WHERE id = :i AND state IN ('planned', 'resend')"
        ),
        {"i": step_id, "now": now},
    )
    if moved.rowcount != 1:
        raise StateMovedError(f"step {step_id} is no longer waiting to be sent")


class StateMovedError(RuntimeError):
    """The row is not in the state the poster read it in (another run, a person): not sent."""


async def settle(
    conn: AsyncConnection,
    step_id: int,
    to: str,
    *,
    only_from: Sequence[str],
    now: datetime,
    reason: str | None = None,
    ids: Mapping[str, Any] | None = None,
    next_lookup_at: datetime | None = None,
    lookups: int | None = None,
) -> bool:
    """Move a step on. Only from the states named: a step another run or a person moved is left
    alone (False)."""
    statement = text(
        "UPDATE case_team_steps SET state = CAST(:to AS text),"
        " state_reason = coalesce(CAST(:why AS text), state_reason),"
        " kibana_ids = coalesce(CAST(:ids AS jsonb), kibana_ids),"
        " verified_at = CASE WHEN CAST(:to AS text) = 'verified' THEN CAST(:now AS timestamptz)"
        " ELSE verified_at END,"
        " next_lookup_at = CASE WHEN CAST(:to AS text) = 'ambiguous'"
        " THEN CAST(:nl AS timestamptz) ELSE NULL END,"
        " lookups = coalesce(CAST(:lk AS integer), lookups)"
        " WHERE id = :i AND state = ANY(CAST(:froms AS text[]))"
    ).bindparams(bindparam("ids", type_=JSONB(none_as_null=True)))
    done = await conn.execute(
        statement,
        {
            "i": step_id,
            "to": to,
            "why": None if reason is None else reason[:500],
            "ids": None if ids is None else dict(ids),
            "now": now,
            "nl": next_lookup_at,
            "lk": lookups,
            "froms": list(only_from),
        },
    )
    return bool(done.rowcount == 1)


def left_out_of(row: StepRow) -> frozenset[str]:
    """The alerts of an attach that were left out of its call (closed alerts while Sync
    alerts was on), as recorded in its ``kibana_ids``."""
    return frozenset(str(a) for a in row.kibana_ids.get("left_out", ()))


def attach_view(rows: Sequence[StepRow], row: StepRow) -> Step:
    """The attach step as it is to be sent or looked for now: without the alerts left out of it,
    and with ``expect_total`` lowered by every alert left out of this step and of the attaches
    before it in the generation (the case will never hold them). The stored payload is the plan's
    and stays as written; with nothing left out this is the step as planned."""
    step = row.step()
    earlier = [r for r in rows if r.kind == "attach" and r.seq <= row.seq] or [row]
    dropped = sum(len(left_out_of(r)) for r in earlier)
    left = left_out_of(row)
    if not dropped and not left:
        return step
    payload = dict(step.payload)
    payload["alerts"] = [[a, i] for a, i in payload["alerts"] if a not in left]
    payload["expect_total"] = int(payload["expect_total"]) - dropped
    return replace(step, payload=payload)


async def not_open_alerts(conn: AsyncConnection, alert_ids: Sequence[str]) -> set[str]:
    """Which of these alerts ARGUS records as not open (acknowledged or closed). An alert whose
    status was never recorded counts as open, as the write-back reads it."""
    rows = await conn.execute(
        text(
            "SELECT alert_id FROM alert_records WHERE alert_id = ANY(CAST(:ids AS text[]))"
            " AND coalesce(workflow_status, 'open') <> 'open'"
        ),
        {"ids": list(alert_ids)},
    )
    return {str(r.alert_id) for r in rows}


async def leave_out_alerts(
    conn: AsyncConnection, step_id: int, left_out: Sequence[str], why: str, *, skip: bool = False
) -> bool:
    """Record the alerts an attach leaves out (all of them: the step is ``skipped`` when ``skip``)
    before it is sent. Only a step that is still waiting to be sent; False when it moved."""
    done = await conn.execute(
        text(
            "UPDATE case_team_steps SET state_reason = :w,"
            " kibana_ids = kibana_ids || CAST(:ids AS jsonb),"
            " state = CASE WHEN CAST(:skip AS boolean) THEN 'skipped' ELSE state END"
            " WHERE id = :i AND state IN ('planned', 'resend')"
        ).bindparams(bindparam("ids", type_=JSONB)),
        {"i": step_id, "w": why[:500], "ids": {"left_out": sorted(left_out)}, "skip": skip},
    )
    return bool(done.rowcount == 1)


async def set_kibana_case(
    conn: AsyncConnection, case_id: uuid.UUID, kibana_case_id: str, now: datetime
) -> None:
    await conn.execute(
        text(
            "UPDATE case_team_posts SET kibana_case_id = :k, opened_at = coalesce(opened_at, :n),"
            " state = 'active', held_reason = NULL"
            " WHERE case_id = :c AND (kibana_case_id IS NULL OR kibana_case_id = :k)"
        ),
        {"k": kibana_case_id, "n": now, "c": case_id},
    )


async def finish_generation(
    conn: AsyncConnection, case_id: uuid.UUID, version: int, now: datetime
) -> None:
    await conn.execute(
        text("UPDATE case_team_posts SET last_version = :v, last_round_at = :n WHERE case_id = :c"),
        {"v": version, "n": now, "c": case_id},
    )


async def hold_post(conn: AsyncConnection, case_id: uuid.UUID, reason: str) -> None:
    await conn.execute(
        text("UPDATE case_team_posts SET state = 'held', held_reason = :r WHERE case_id = :c"),
        {"r": reason[:500], "c": case_id},
    )


async def release_post(conn: AsyncConnection, case_id: uuid.UUID) -> None:
    await conn.execute(
        text("UPDATE case_team_posts SET state = 'active', held_reason = NULL WHERE case_id = :c"),
        {"c": case_id},
    )


async def posted_state(conn: AsyncConnection, case_id: uuid.UUID) -> Posted | None:
    """What the case already holds, from the steps that went through: the units of each part, the
    files' hashes, the alerts attached, the verdict posted last, and what ARGUS last wrote as the
    title, the description and each comment (the posting, or its newest edit). None until
    the case is open."""
    post = await post_of(conn, case_id)
    if post is None or post.kibana_case_id is None:
        return None
    every = await steps_of(conn, case_id)
    rows = [r for r in every if r.state in ("sent", "verified")]
    units: dict[str, set[str]] = {}
    files: dict[str, str] = {}
    attached: set[str] = set()
    gone: set[str] = set()
    verdict: tuple[str | None, float | None] | None = None
    title: str | None = None
    title_at: datetime | None = None
    description: str | None = None
    comments: dict[str, PostedComment] = {}
    glance: PostedGlance | None = None
    for r in rows:
        if r.kind in ("comment", "edit_comment"):
            units.setdefault(r.part, set()).update(r.units)
        if r.part == visual.PART and r.kind in ("comment", "edit_comment"):  # the newest wins
            glance = PostedGlance(
                r.units[0] if r.units else "",
                visual.Seen.load(r.payload.get("seen")),
                visual.Seen.load(r.payload.get("since")),
            )
        if r.kind == "open":
            title, description = str(r.payload.get("title")), r.text_body
            title_at = r.sent_at or r.verified_at
        elif r.kind == "retitle":
            title = str(r.payload.get("title"))
            title_at = r.sent_at or r.verified_at
        elif r.kind == "redescribe":
            description = r.text_body
        elif r.kind == "comment":
            ident = r.kibana_ids.get("comment")
            # the first posting of a key is the part's own comment; a later generation's
            # comment of the same key is an "Update" and is not what a refresh rewrites
            if ident and r.key not in comments and not (r.text_body or "").startswith("## Update"):
                comments[r.key] = PostedComment(
                    r.key, r.part, r.author, str(ident), r.text_body or ""
                )
        elif r.kind == "edit_comment":
            of = str(r.payload.get("of"))
            if of in comments:
                comments[of] = replace(comments[of], text=r.text_body or "")
        elif r.kind == "file":
            files[str(r.payload.get("file_kind"))] = str(r.payload.get("sha256"))
        elif r.kind == "attach":
            left = left_out_of(r)
            attached.update(a for a, _ in r.payload.get("alerts", ()) if a not in left)
        elif r.kind == "tag":
            gone.update(str(a) for a in r.kibana_ids.get("gone", ()))
        if r.part == "verdict" and r.kind == "comment":
            verdict = (r.payload.get("outcome"), r.payload.get("confidence"))
    by_person = any(
        r.kind == "retitle"
        and r.state == "skipped"
        and (r.state_reason or "").endswith(PERSON_EDIT)
        for r in every
    )
    left = frozenset(
        str(r.payload.get("of"))
        for r in every
        if r.kind == "edit_comment" and r.state == "skipped" and left_by_person(r.state_reason)
    )
    # every attach's, sent or skipped (an attach to a case that is not open is skipped whole)
    left_out = frozenset(a for r in every if r.kind == "attach" for a in left_out_of(r))
    version = max((r.report_version for r in rows), default=post.last_version or 1)
    gen = await latest_gen(conn, case_id)
    return Posted(
        post.kibana_case_id,
        version,
        gen,
        {k: frozenset(v) for k, v in units.items()},
        files,
        frozenset(attached),
        verdict,
        frozenset(gone),
        title,
        by_person,
        title_at,
        description,
        comments,
        glance,
        left,
        left_out - attached,
    )


_IN_DOUBT_OPEN = (
    "EXISTS (SELECT 1 FROM case_team_steps s WHERE s.case_id = p.case_id AND s.kind = 'open'"
    " AND s.state IN ('sending', 'sent', 'ambiguous', 'resend')"
)


async def opened_between(conn: AsyncConnection, start: datetime, end: datetime) -> int:
    """Cases opened in [start, end): the Kibana case exists, or its create was sent and its
    outcome is in doubt (it may have landed, so it counts against the cap)."""
    return int(
        (
            await conn.execute(
                text(
                    "SELECT count(*) FROM case_team_posts p WHERE (p.opened_at >= :s"
                    " AND p.opened_at < :e) OR (p.opened_at IS NULL AND "
                    + _IN_DOUBT_OPEN
                    + " AND s.sent_at >= :s AND s.sent_at < :e))"
                ),
                {"s": start, "e": end},
            )
        ).scalar_one()
    )


async def opened_total(conn: AsyncConnection) -> int:
    """Cases ever opened, with the creates in doubt (the canary's count)."""
    return int(
        (
            await conn.execute(
                text(
                    "SELECT count(*) FROM case_team_posts p WHERE p.opened_at IS NOT NULL OR "
                    + _IN_DOUBT_OPEN
                    + ")"
                )
            )
        ).scalar_one()
    )


async def case_row(conn: AsyncConnection, case_id: uuid.UUID) -> Any:
    return (
        await conn.execute(
            text("SELECT id, number, state FROM cases WHERE id = :c"), {"c": case_id}
        )
    ).first()


@dataclass(frozen=True)
class PersonDecision:
    """The newest decision a person made on any version of the case's report."""

    decision: str  # confirmed | rejected
    outcome: str | None  # the outcome the decision names (a confirm: the verdict it confirmed)
    version: int  # the report version it was made on


async def person_decision(conn: AsyncConnection, case_id: uuid.UUID) -> PersonDecision | None:
    row = (
        await conn.execute(
            text(
                "SELECT d.decision, coalesce(d.outcome, r.verdict_outcome) AS outcome, r.version"
                " FROM incident_report_decisions d"
                " JOIN incident_reports r ON r.id = d.report_id WHERE r.case_id = :c"
                " ORDER BY d.id DESC LIMIT 1"
            ),
            {"c": case_id},
        )
    ).first()
    return None if row is None else PersonDecision(str(row.decision), row.outcome, int(row.version))


async def alerts_of(conn: AsyncConnection, case_id: uuid.UUID, limit: int) -> list[tuple[str, str]]:
    """The incident's alerts with their concrete index, the newest first, at most ``limit``
    (duplicates, quarantined and missing alerts, and alerts with no index, are left out)."""
    rows = await conn.execute(
        text(
            "SELECT a.alert_id, a.index AS alert_index,"
            " max(coalesce(a.event_time, a.detected_at, a.first_seen_at)) AS at"
            " FROM case_members m JOIN investigation_alerts ia"
            " ON ia.investigation_id = m.investigation_id"
            " JOIN alert_records a ON a.alert_id = ia.alert_id"
            " WHERE m.case_id = :c AND m.removed_at IS NULL AND ia.duplicate_of IS NULL"
            " AND a.status = 'normalized' AND a.source_missing_at IS NULL AND a.index IS NOT NULL"
            " GROUP BY a.alert_id, a.index ORDER BY at DESC NULLS LAST, a.alert_id LIMIT :n"
        ),
        {"c": case_id, "n": limit},
    )
    return [(r.alert_id, r.alert_index) for r in rows]


_OPEN_STEP = "'planned', 'sending', 'sent', 'ambiguous', 'resend', 'held'"
# A case a person deleted in Kibana (the read-back's mirror) is neither updated nor
# opened again: the poster leaves it alone and ``argus case team status`` says why.
KIBANA_DELETED = (
    "EXISTS (SELECT 1 FROM kibana_mirror k WHERE k.case_id = c.id AND k.deleted_at IS NOT NULL)"
)
_CANDIDATES = text(
    "SELECT c.id FROM cases c"
    " LEFT JOIN case_team_posts p ON p.case_id = c.id"
    " LEFT JOIN case_team_looks l ON l.case_id = c.id"
    " LEFT JOIN LATERAL (SELECT r.id, r.version, r.verdict_outcome, r.verdict_confidence,"
    "   r.core_hash AS core, r.body #>> '{verdict,kind}' AS kind"
    "   FROM incident_reports r WHERE r.case_id = c.id"
    "   ORDER BY r.version DESC LIMIT 1) n ON true"
    " LEFT JOIN LATERAL (SELECT d.decision, coalesce(d.outcome, r2.verdict_outcome) AS outcome,"
    "   d.report_id, r2.core_hash AS core FROM incident_report_decisions d"
    "   JOIN incident_reports r2 ON r2.id = d.report_id WHERE r2.case_id = c.id"
    "   ORDER BY d.id DESC LIMIT 1) person ON true"
    " WHERE NOT " + KIBANA_DELETED + " AND ("
    # an unfinished post: a started sequence is finished first, whatever else is true
    "   EXISTS (SELECT 1 FROM case_team_steps s WHERE s.case_id = c.id"
    f"     AND s.state IN ({_OPEN_STEP}) AND s.sent_count > 0)"
    # to be opened: suggested or open, no Kibana case yet, and a route that could qualify
    "   OR (c.state IN ('suspected', 'open', 'assigned') AND n.id IS NOT NULL"
    "       AND (p.case_id IS NULL OR p.kibana_case_id IS NULL)"
    "       AND coalesce(person.decision, '') <> 'rejected'"
    # a confirm of a true positive holds while the newest report says true positive
    "       AND ((person.decision = 'confirmed' AND person.outcome = 'true_positive'"
    "             AND n.verdict_outcome = 'true_positive')"
    "         OR (n.verdict_outcome = 'true_positive' AND n.kind IN ('person', 'proposal', 'case')"
    "             AND n.verdict_confidence >= :min)))"
    # a case already in Kibana: a newer report, a verdict not yet acknowledged, steps waiting
    "   OR (c.state IN ('suspected', 'open', 'assigned', 'contained')"
    "       AND p.kibana_case_id IS NOT NULL AND n.id IS NOT NULL"
    "       AND (n.version > coalesce(p.last_version, 0)"
    "         OR EXISTS (SELECT 1 FROM case_team_steps s WHERE s.case_id = c.id"
    f"                    AND s.state IN ({_OPEN_STEP}))"
    "         OR EXISTS (SELECT 1 FROM case_team_seen v WHERE v.case_id = c.id"
    "                    AND v.status = 'recorded' AND NOT EXISTS (SELECT 1 FROM case_team_steps t"
    "                    WHERE t.case_id = c.id AND t.state IN ('verified', 'skipped')"
    "                    AND t.key = 'comment:closing:' || left(encode("
    "                    sha256(convert_to(v.kibana_comment_id || '|' || v.text_hash, 'UTF8')),"
    "                    'hex'), 10)))"
    "         OR EXISTS (SELECT 1 FROM case_team_steps g WHERE g.case_id = c.id"
    "                    AND g.kind = 'tag' AND g.state = 'verified'"
    "                    AND (coalesce((g.kibana_ids ->> 'gone_count')::int, 0) > 0"
    "                         OR coalesce((g.kibana_ids ->> 'untagged')::int, 0) > 0)"
    "                    AND NOT EXISTS (SELECT 1 FROM case_team_steps t WHERE t.case_id = c.id"
    "                    AND t.state IN ('verified', 'skipped')"
    "                    AND t.key = 'comment:untagged:' || g.id)))))"
    " ORDER BY EXISTS (SELECT 1 FROM case_team_steps s WHERE s.case_id = c.id"
    "                  AND s.state IN ('sending', 'sent', 'ambiguous', 'resend')) DESC,"
    "          l.examined_at NULLS FIRST, p.last_round_at NULLS FIRST, c.number LIMIT :n"
)


async def candidates(
    conn: AsyncConnection, look: int, min_confidence: float | None = 0.8
) -> list[uuid.UUID]:
    """The cases that could be posted or updated now, picked in SQL (an unfinished post first,
    then the least recently examined), at most ``look``. Only cases that could qualify are
    selected: a person's confirm of a true positive on the newest report, a true positive of at
    least ``min_confidence`` that is ARGUS's own (None: never, ``case_team.auto`` off), or a case
    already in Kibana with a newer report, an unacknowledged verdict or steps waiting. A case at
    the back of a long list is therefore reached in one pass; the policy still decides each one."""
    rows = await conn.execute(_CANDIDATES, {"n": look, "min": min_confidence})
    return [r.id for r in rows]


async def kibana_deleted_at(conn: AsyncConnection, case_id: uuid.UUID) -> datetime | None:
    """When the read-back found the case's Kibana case deleted by a person, or None. A deleted
    case is not written to again (:data:`KIBANA_DELETED`)."""
    found = (
        await conn.execute(
            text("SELECT deleted_at FROM kibana_mirror WHERE case_id = :c"), {"c": case_id}
        )
    ).first()
    return None if found is None else cast(datetime | None, found.deleted_at)


async def kibana_paused(conn: AsyncConnection, case_id: uuid.UUID) -> str | None:
    """Why the read-back paused the case's Kibana case (a person changed its Sync alerts or
    ARGUS's tags there), or None: the poster writes nothing to it until the owner lifts it."""
    return cast(
        str | None,
        await conn.scalar(
            text("SELECT paused_reason FROM kibana_mirror WHERE case_id = :c"), {"c": case_id}
        ),
    )


async def touch_examined(conn: AsyncConnection, case_id: uuid.UUID, now: datetime) -> None:
    """The poster looked at this case now (its place in the rotation)."""
    await conn.execute(
        text(
            "INSERT INTO case_team_looks (case_id, examined_at) VALUES (:c, :n)"
            " ON CONFLICT (case_id) DO UPDATE SET examined_at = EXCLUDED.examined_at"
        ),
        {"c": case_id, "n": now},
    )


async def names(conn: AsyncConnection, user_ids: Sequence[int]) -> dict[int, str]:
    if not user_ids:
        return {}
    rows = await conn.execute(
        text("SELECT id, display_name FROM users WHERE id = ANY(:ids)"), {"ids": list(user_ids)}
    )
    return {int(r.id): r.display_name for r in rows}


@dataclass(frozen=True)
class ApprovalRow:
    id: int
    case_id: uuid.UUID
    gen: int
    plan_hash: str
    report_version: int
    approver_user_id: int
    statement: Mapping[str, Any]
    signature: str
    approved_at: datetime
    expires_at: datetime


async def approvals_for(
    conn: AsyncConnection, case_id: uuid.UUID, plan_hash: str
) -> list[ApprovalRow]:
    rows = await conn.execute(
        text(
            "SELECT id, case_id, gen, plan_hash, report_version, approver_user_id, statement,"
            " signature, approved_at, expires_at FROM case_team_approvals"
            " WHERE case_id = :c AND plan_hash = :h ORDER BY id DESC"
        ),
        {"c": case_id, "h": plan_hash},
    )
    return [
        ApprovalRow(
            r.id,
            r.case_id,
            r.gen,
            r.plan_hash,
            r.report_version,
            r.approver_user_id,
            dict(r.statement),
            r.signature,
            r.approved_at,
            r.expires_at,
        )
        for r in rows
    ]


async def add_approval(
    conn: AsyncConnection,
    *,
    case_id: uuid.UUID,
    gen: int,
    plan_hash: str,
    report_version: int,
    approver_user_id: int,
    statement: Mapping[str, Any],
    signature: str,
    approved_at: datetime,
    expires_at: datetime,
) -> int:
    statement_param = bindparam("s", type_=JSONB)
    made = await conn.execute(
        text(
            "INSERT INTO case_team_approvals (case_id, gen, plan_hash, report_version,"
            " approver_user_id, statement, signature, approved_at, expires_at)"
            " VALUES (:c, :g, :h, :v, :u, :s, :sig, :a, :e) RETURNING id"
        ).bindparams(statement_param),
        {
            "c": case_id,
            "g": gen,
            "h": plan_hash,
            "v": report_version,
            "u": approver_user_id,
            "s": dict(statement),
            "sig": signature,
            "a": approved_at,
            "e": expires_at,
        },
    )
    return int(made.scalar_one())


async def seen_has(conn: AsyncConnection, comment_id: str, text_hash: str) -> bool:
    """Whether this comment text was decided (anything but ``unmatched``, which is looked at
    again when a matching ARGUS person appears)."""
    return (
        await conn.execute(
            text(
                "SELECT 1 FROM case_team_seen WHERE kibana_comment_id = :i AND text_hash = :h"
                " AND status <> 'unmatched'"
            ),
            {"i": comment_id, "h": text_hash},
        )
    ).first() is not None


async def seen_unmatched(conn: AsyncConnection, comment_id: str, text_hash: str) -> bool:
    return (
        await conn.execute(
            text(
                "SELECT 1 FROM case_team_seen WHERE kibana_comment_id = :i AND text_hash = :h"
                " AND status = 'unmatched'"
            ),
            {"i": comment_id, "h": text_hash},
        )
    ).first() is not None


async def seen_add(
    conn: AsyncConnection,
    *,
    comment_id: str,
    text_hash: str,
    case_id: uuid.UUID,
    author: str,
    written_at: datetime,
    verdict: str | None,
    status: str,
    detail: str | None,
    user_id: int | None,
    review_ids: Sequence[int],
    counts: Mapping[str, Any] | None = None,
) -> None:
    await conn.execute(
        text(
            "INSERT INTO case_team_seen (kibana_comment_id, text_hash, case_id, author, written_at,"
            " verdict, status, detail, user_id, review_ids, counts) VALUES (:i, :h, :c, :a, :w,"
            " :v, :s, :d, :u, CAST(:r AS bigint[]), :k)"
        ).bindparams(bindparam("k", type_=JSONB(none_as_null=True))),
        {
            "i": comment_id,
            "h": text_hash,
            "c": case_id,
            "a": author,
            "w": written_at,
            "v": verdict,
            "s": status,
            "d": None if detail is None else detail[:500],
            "u": user_id,
            "r": list(review_ids),
            "k": None if counts is None else dict(counts),
        },
    )


@dataclass(frozen=True)
class SeenRow:
    kibana_comment_id: str
    text_hash: str
    case_id: uuid.UUID
    author: str
    written_at: datetime
    verdict: str | None
    status: str
    user_id: int | None
    detail: str | None = None
    review_ids: tuple[int, ...] = ()
    counts: Mapping[str, Any] = field(default_factory=dict)

    @property
    def ref(self) -> str:
        """What names this verdict in a step's key (one note for each comment text)."""
        return f"{self.kibana_comment_id}|{self.text_hash}"


async def recorded_verdicts(conn: AsyncConnection, case_id: uuid.UUID) -> list[SeenRow]:
    rows = await conn.execute(
        text(
            "SELECT kibana_comment_id, text_hash, case_id, author, written_at, verdict, status,"
            " user_id, detail, review_ids, counts FROM case_team_seen"
            " WHERE case_id = :c AND status = 'recorded'"
            " ORDER BY written_at, kibana_comment_id"
        ),
        {"c": case_id},
    )
    return [
        SeenRow(
            r.kibana_comment_id,
            r.text_hash,
            r.case_id,
            r.author,
            r.written_at,
            r.verdict,
            r.status,
            r.user_id,
            r.detail,
            tuple(r.review_ids or ()),
            dict(r.counts or {}),
        )
        for r in rows
    ]


async def unmatched_now_matchable(conn: AsyncConnection) -> set[uuid.UUID]:
    """Cases with a verdict comment kept as ``unmatched`` whose author now is the ELK name of
    exactly one enabled ARGUS person (checked in the database alone): their comments are read
    again, whatever Kibana says changed."""
    rows = await conn.execute(
        text(
            "SELECT DISTINCT s.case_id FROM case_team_seen s WHERE s.status = 'unmatched'"
            " AND NOT EXISTS (SELECT 1 FROM case_team_seen f WHERE f.kibana_comment_id ="
            "   s.kibana_comment_id AND f.text_hash = s.text_hash AND f.status <> 'unmatched')"
            " AND (SELECT count(*) FROM users u WHERE u.elk_username = s.author AND NOT u.disabled"
            "      AND u.frozen_at IS NULL AND u.kind = 'person') = 1"
        )
    )
    return {r.case_id for r in rows}


async def user_for_kibana(
    conn: AsyncConnection, kibana_username: str
) -> tuple[int, str, str] | None:
    """The ARGUS person behind a Kibana account: (id, username, display name) of the one enabled,
    not frozen person whose ELK name is this one; None when there is none (or more than one)."""
    rows = (
        await conn.execute(
            text(
                "SELECT id, username, display_name FROM users WHERE elk_username = :n"
                " AND NOT disabled AND frozen_at IS NULL AND kind = 'person'"
            ),
            {"n": kibana_username},
        )
    ).all()
    if len(rows) != 1:
        return None
    return int(rows[0].id), str(rows[0].username), str(rows[0].display_name)


async def access_of(conn: AsyncConnection, user_id: int, *, elk: bool) -> frozenset[Any] | None:
    """What ARGUS lets this person do, decided as the web's access model decides it
    (:func:`argus.web.auth.capabilities_of`): in local mode what the account stores, in ELK mode
    the snapshot of their newest ELK session (plus the gold-key grant). None when ELK mode has
    no snapshot of this person at all (they never signed in through ELK)."""
    from argus.web import auth

    grants = (
        await conn.execute(text("SELECT capabilities FROM users WHERE id = :u"), {"u": user_id})
    ).scalar_one()
    if not elk:
        return auth.capabilities_of("local", None, grants)
    snapshot = (
        await conn.execute(
            text(
                "SELECT capabilities FROM user_sessions WHERE user_id = :u AND mode = 'elk'"
                " AND capabilities IS NOT NULL ORDER BY checked_at DESC NULLS LAST,"
                " created_at DESC LIMIT 1"
            ),
            {"u": user_id},
        )
    ).first()
    if snapshot is None:
        return None
    return auth.capabilities_of("elk", snapshot.capabilities, grants)


@dataclass(frozen=True)
class ReadMark:
    """What the Kibana case looked like when its comments were last read."""

    updated_at: datetime | None
    comments: int


async def read_marks(conn: AsyncConnection) -> dict[uuid.UUID, ReadMark]:
    rows = await conn.execute(
        text("SELECT case_id, kibana_updated_at, comment_count FROM case_team_reads")
    )
    return {r.case_id: ReadMark(r.kibana_updated_at, int(r.comment_count)) for r in rows}


async def put_read_mark(
    conn: AsyncConnection, case_id: uuid.UUID, mark: ReadMark, now: datetime
) -> None:
    await conn.execute(
        text(
            "INSERT INTO case_team_reads (case_id, kibana_updated_at, comment_count, read_at)"
            " VALUES (:c, :u, :n, :t) ON CONFLICT (case_id) DO UPDATE SET"
            " kibana_updated_at = EXCLUDED.kibana_updated_at,"
            " comment_count = EXCLUDED.comment_count, read_at = EXCLUDED.read_at"
        ),
        {"c": case_id, "u": mark.updated_at, "n": mark.comments, "t": now},
    )


def all_done(rows: Sequence[StepRow]) -> bool:
    return bool(rows) and all(r.state in DONE_STATES for r in rows)


def any_open(rows: Sequence[StepRow]) -> bool:
    return any(r.state in OPEN_STATES for r in rows)
