"""The incident engine's routes of ``/api/v1`` (P4-F E5): the Today page, and the ``engine`` block
the case routes add to a case the engine made. Read only, from the engine's own tables (the
linker's ``risk_incidents``, the presenter's columns on it, ``risk_gray_items``, ``risk_groups``,
``risk_mode``) and the cases; the presenter writes them. Presenting, Needs you is the queue's
own set (``needsyou.NEEDS_YOU``, what ``GET /cases?view=queue`` lists): the cards are the part of it
the daily capacity has shown, ``more_waiting`` the rest (spec Q-2)."""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime, timedelta
from typing import Annotated, Any, cast, get_args

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus import site
from argus.web import auth, needsyou
from argus.web.capabilities import Capability
from argus.web.deps import Conn, Surface, need
from argus.web.v1 import engine_models as em

VIEW = need(Capability.VIEW, Surface.V1)
Viewer = Annotated[auth.Reviewer, Depends(VIEW)]
CARDS = 50  # cards a list holds
GRAY = 5
FIRST_VISIT = timedelta(hours=24)  # "since your last visit" on a first visit
CONFIRMED = ("open", "assigned", "contained")
CERTAINTY_WORDS: tuple[str, ...] = get_args(em.Certainty)
# the digest's categories in plain words (argus.risk.score.CATEGORIES; "presented" is not one)
CATEGORY_WORDS = {
    "known_infection": "Known infections (the owner was already told)",
    "inbound_blocked": "Attacks from outside that were blocked",
    "inbound_attempt": "Probes from outside with no sign of success",
    "inbound_success": "Probes from outside that got an answer (not verified)",
    "gray_band": "Just under the bar: watched",
    "probation": "New rules on probation",
    "rules_only": "Rule hits with nothing else behind them",
    "outbound_low": "{Own:activity} below every lane",
    "unattributed": "No {own:device} or site named",
    "hub_activity": "Shared gateways (NAT, proxy, resolver)",
}

_COLUMNS = (
    "r.id, r.state, c.id AS case_id, r.title, r.priority, r.band, r.certainty, r.view, r.version,"
    " r.changed, r.raised_by_ai, r.first_seen, r.last_seen, r.queued_at,"
    " c.number AS case_number, c.state AS case_state, c.version AS case_version,"
    " c.title AS case_title"
)
_FROM = " FROM risk_incidents r LEFT JOIN cases c ON c.id = r.case_id"
# a card's case as the spec's Card has it: who took it, the owner told, Kibana's state
_CARD = (
    f"{_COLUMNS}, c.notified_at, c.kibana_wait, ow.username AS owner_username,"
    " coalesce(ow.display_name, ow.username) AS owner_name,"
    f" coalesce({needsyou.IN_KIBANA}, false) AS in_kibana,"
    " coalesce(r.queued_at, c.opened_at, c.created_at) AS waiting_since"
)
_CARD_FROM = f"{_FROM} LEFT JOIN users ow ON ow.id = c.owner_user_id"
_ROOT = "r.parent_id IS NULL AND r.state <> 'merged'"
_ORDER = " ORDER BY r.band, r.priority DESC, r.queued_at DESC NULLS LAST, r.id"
# in shadow: every live incident the governor shows, the engine's own card (no case); every P1
# and P2 (by band; a quiet one, no activity for 72 h, still waits for its decision, after the
# live ones of its band), then P3 and P4 up to the list's length; ``total`` counts them all
_SHADOW_CARDS = text(
    f"SELECT * FROM (SELECT {_CARD}, row_number() OVER (ORDER BY r.band,"  # noqa: S608
    " r.state = 'quiet', r.priority DESC, r.queued_at DESC NULLS LAST, r.id) AS place,"
    " count(*) OVER () AS total"
    f"{_CARD_FROM} WHERE {_ROOT} AND r.shown AND r.view ->> 'elsewhere' IS NULL"
    " AND r.case_id IS NULL AND r.state IN ('active', 'quiet')) x"
    " WHERE x.band IN ('P1', 'P2') OR x.place <= :n ORDER BY x.place"
)
_SHADOW_WAITING = text(
    f"SELECT count(*) FROM risk_incidents r WHERE {_ROOT} AND r.state IN ('active', 'quiet')"  # noqa: S608
    " AND NOT r.shown AND r.view ->> 'elsewhere' IS NULL"
)
# presenting: the queue's cases (one predicate with GET /cases?view=queue), each with the engine's
# incident when it made the case; a card is one the daily capacity has shown (every P1 and P2,
# and every case the engine did not make); the queue's count less the cards is ``more_waiting``
_QUEUE_FROM = (
    " FROM cases c LEFT JOIN risk_incidents r ON r.case_id = c.id AND r.parent_id IS NULL"
    " AND r.state <> 'merged' LEFT JOIN users ow ON ow.id = c.owner_user_id"
)
_PRESENT_CARDS = text(
    f"SELECT * FROM (SELECT {_CARD}, row_number() OVER (ORDER BY r.band NULLS LAST,"  # noqa: S608
    " r.state = 'quiet', r.priority DESC NULLS LAST, r.queued_at DESC NULLS LAST,"
    " c.updated_at DESC, c.number) AS place"
    f"{_QUEUE_FROM} WHERE {needsyou.NEEDS_YOU}"
    " AND (r.id IS NULL OR r.shown OR r.band IN ('P1', 'P2'))) x"
    " WHERE x.band IN ('P1', 'P2') OR x.place <= :n ORDER BY x.place"
)
# the Incidents tab's Needs you (view=queue): Today's cards and its count are one set (spec §3.1)
_QUEUE_COUNT = text(f"SELECT count(*) FROM cases c WHERE {needsyou.NEEDS_YOU}")  # noqa: S608
# a confirmed case with a material change the viewer has not acted on since; a closed case the
# presenter told of new strong evidence on the alert groups it holds (``activity_after_closure``)
_NEW_ACTIVITY = text(
    f"SELECT {_CARD}{_CARD_FROM} WHERE {_ROOT} AND r.version > 1"
    " AND (c.state IN ('open', 'assigned', 'contained') OR (c.state = 'closed'"
    " AND c.merged_into_id IS NULL AND r.view ? 'after_closure'))"
    " AND r.version > coalesce((r.view ->> 'seen_version')::int, 0)"
    f"{_ORDER} LIMIT :n"
)
_GRAY = text(
    "SELECT g.object_id, g.priority, g.band, g.certainty, g.title, g.view, g.first_seen,"
    " g.last_seen FROM risk_gray_items g ORDER BY g.priority DESC, g.last_seen DESC, g.object_id"
    " LIMIT :n"
)
_MODE = text("SELECT present FROM risk_mode WHERE id = 1")
_HANDLED = text(
    "SELECT category, count(*) AS n FROM risk_groups WHERE at >= :since AND at <= :now"
    " AND category IS NOT NULL AND category <> 'presented' GROUP BY category"
    " ORDER BY 2 DESC, 1"
)
_AUDIT = text(
    "SELECT g.investigation_id, g.category, g.at, i.rule_name FROM risk_groups g"
    " JOIN investigations i ON i.id = g.investigation_id WHERE g.at >= :since AND g.at <= :now"
    " AND g.category IS NOT NULL AND g.category NOT IN ('presented', 'known_infection')"
    " ORDER BY md5(g.investigation_id::text || :day), g.investigation_id LIMIT 1"
)


def _block(
    view: Mapping[str, Any], *, incident_id: int, priority: int, band: str, certainty: str,
    raised_by_ai: bool, first_seen: datetime, last_seen: datetime, version: int,
    changed: Iterable[str],
) -> em.EngineOut:  # fmt: skip
    return em.EngineOut(
        incident_id=incident_id, priority=int(view.get("priority", priority)),
        band=view.get("band", band), lane=view.get("lane") or "slow",
        certainty=cast(em.Certainty, certainty),
        why=[em.WhyItemOut(op=w["op"], points=float(w["points"]), text=str(w["text"]))
             for w in view.get("why", [])],
        why_line=str(view.get("why_line", "")),
        checks=[em.EngineCheckOut(state=c["state"], text=str(c["text"]))
                for c in view.get("checks", [])],
        alternatives=[em.AlternativeOut(name=str(a["name"]), state=a["state"],
                                        test=str(a["test"]))
                      for a in view.get("alternatives", [])],
        # the organisation's own devices, accounts and sites are the side at risk, whichever of
        # them opened the connection (a beaconing device acts, and is what is affected)
        objects=[em.EngineObjectOut(
                     kind=o["kind"], label=str(o["label"]),
                     role="affected" if o["kind"] in ("device", "account", "site") else o["role"])
                 for o in view.get("objects", [])],
        raised_by_ai=raised_by_ai, active=bool(view.get("active", False)),
        first_seen=first_seen, last_seen=last_seen, version=version, changed=list(changed),
        alert_groups=int(view.get("groups", 0)), alerts=int(view.get("alerts", 0)),
    )  # fmt: skip


def certainty_of(view: Mapping[str, Any], stored: str) -> str:
    """The evidence's certainty word: the view's (the presenter stores it beside the engine's
    word, which is "Confirmed" once a person confirmed); a row without it, confirmed, is Likely
    (a person confirmed what the evidence showed)."""
    word = view.get("certainty")
    if word in CERTAINTY_WORDS:
        return str(word)
    return stored if stored in CERTAINTY_WORDS else "Likely"


def engine_view(row: Any) -> em.EngineOut:
    """A stored incident as the API's engine block (the evidence's certainty word: the UI says
    "Confirmed" from the case's state). The strip of changes empties once the viewer acted."""
    view: Mapping[str, Any] = row.view or {}
    seen = int(view.get("seen_version") or 0)
    changed = list(row.changed or ()) if int(row.version) > seen else []
    return _block(
        view, incident_id=int(row.id), priority=int(row.priority), band=row.band,
        certainty=certainty_of(view, row.certainty), raised_by_ai=bool(row.raised_by_ai),
        first_seen=row.first_seen, last_seen=row.last_seen, version=int(row.version),
        changed=changed,
    )  # fmt: skip


def card(row: Any) -> em.TodayCardOut:
    """A case's card (kind ``incident``), with the engine's block when the engine made it; in
    shadow the engine's own incident (kind ``shadow``: its id and version are the engine's)."""
    taken = None
    if row.owner_username is not None:
        taken = em.TakenByOut(username=row.owner_username, name=row.owner_name)
    with_case = row.case_id is not None
    return em.TodayCardOut(
        kind="incident" if with_case else "shadow",
        id=str(row.case_id if with_case else row.id), number=row.case_number,
        title=row.case_title or row.title or "Possible incident", state=row.case_state,
        version=int(row.case_version if with_case else row.version),
        engine=engine_view(row) if row.id is not None else None, taken_by=taken,
        notified_at=row.notified_at, in_kibana=bool(row.in_kibana), kibana_wait=row.kibana_wait,
        waiting_since=row.waiting_since,
    )  # fmt: skip


def gray_card(row: Any) -> em.TodayCardOut:
    block = _block(
        row.view or {}, incident_id=0, priority=int(row.priority), band=row.band,
        certainty=certainty_of(row.view or {}, row.certainty), raised_by_ai=False,
        first_seen=row.first_seen, last_seen=row.last_seen, version=0, changed=(),
    )  # fmt: skip
    return em.TodayCardOut(
        kind="gray", id=f"gray:{row.object_id}", number=None, title=row.title, state=None,
        version=0, engine=block, taken_by=None, notified_at=None, in_kibana=False,
        kibana_wait=None, waiting_since=None,
    )  # fmt: skip


# the newest written reading of each kind per incident (D-324)
_READINGS = text(
    "SELECT DISTINCT ON (x.incident_id, x.kind) x.incident_id, x.kind, x.version, x.body,"
    " x.model, x.created_at FROM risk_readings x"
    " WHERE x.incident_id = ANY(CAST(:ids AS bigint[])) AND x.state = 'written'"
    " ORDER BY x.incident_id, x.kind, x.version DESC, x.id DESC"
)
READING_KINDS = {"story": "story", "opinion": "second_opinion"}


def reading_view(row: Any, version: int) -> em.AiReadingOut | None:
    """A stored reading as the API's block (None when its body is not the shape written)."""
    body: Mapping[str, Any] = row.body or {}
    facts: Mapping[str, Any] = body.get("facts") or {}
    try:
        sections = [
            em.AiSectionOut(
                key=str(s["key"]), title=str(s["title"]),
                claims=[em.AiClaimOut(text=str(c["text"]),
                                      based_on=[str(facts[f]) for f in c["cites"] if f in facts])
                        for c in s["claims"]],
            )
            for s in body.get("sections", [])
        ]  # fmt: skip
        return em.AiReadingOut(
            kind=cast(Any, READING_KINDS[row.kind]), model=str(row.model or "a model"),
            written_at=row.created_at, current=int(row.version) == version,
            agrees=body.get("agrees") is not False, incidents=body.get("incidents"),
            sections=sections,
        )  # fmt: skip
    except (KeyError, TypeError, ValueError):
        return None


async def with_readings(
    conn: AsyncConnection, blocks: Mapping[uuid.UUID, em.EngineOut]
) -> dict[uuid.UUID, em.EngineOut]:
    """``blocks`` with ARGUS AI's reading of their incidents (D-324), and the disagreement line
    of a current one that disagrees with the engine (the story's, else the second opinion's)."""
    from argus.risk.reading import disagreement

    ids = sorted({b.incident_id for b in blocks.values()})
    if not ids:
        return dict(blocks)
    found: dict[int, dict[str, Any]] = {}
    for r in await conn.execute(_READINGS, {"ids": ids}):
        found.setdefault(int(r.incident_id), {})[r.kind] = r
    out = {}
    for key, block in blocks.items():
        rows = found.get(block.incident_id, {})
        story = rows.get("story")
        opinion = rows.get("opinion")
        line = None
        for got in (story, opinion):
            if line is None and got is not None and int(got.version) == block.version:
                line = disagreement(got.body or {}, block.band, block.certainty)
        out[key] = block.model_copy(update={
            "ai_story": None if story is None else reading_view(story, block.version),
            "ai_second_opinion": None if opinion is None else reading_view(opinion, block.version),
            "disagreement": line,
        })  # fmt: skip
    return out


async def views_for(
    conn: AsyncConnection, case_ids: Iterable[uuid.UUID]
) -> dict[uuid.UUID, em.EngineOut]:
    """The engine block of each of these cases the engine made (others are left out), with
    ARGUS AI's reading."""
    ids = sorted(set(case_ids), key=str)
    if not ids:
        return {}
    rows = await conn.execute(
        text(f"SELECT {_COLUMNS}{_FROM} WHERE r.case_id = ANY(CAST(:ids AS uuid[]))"),
        {"ids": ids},
    )
    return await with_readings(conn, {r.case_id: engine_view(r) for r in rows})


async def today(
    conn: AsyncConnection, now: datetime, since: datetime | None, me_id: int
) -> em.TodayOut:
    """What a person should look at now, and what ARGUS handled since their last visit."""
    present = bool((await conn.execute(_MODE)).scalar_one_or_none())
    if present:
        needs = [card(r) for r in await conn.execute(_PRESENT_CARDS, {"n": CARDS, "me": me_id})]
        waiting = int((await conn.execute(_QUEUE_COUNT, {"me": me_id})).scalar_one()) - len(needs)
    else:
        rows = list(await conn.execute(_SHADOW_CARDS, {"n": CARDS}))
        needs = [card(r) for r in rows]
        beyond = int(rows[0].total) - len(rows) if rows else 0  # shown, past the list's length
        waiting = int((await conn.execute(_SHADOW_WAITING)).scalar_one()) + beyond
    activity = [card(r) for r in await conn.execute(_NEW_ACTIVITY, {"n": CARDS})]
    gray = [gray_card(r) for r in await conn.execute(_GRAY, {"n": GRAY})]
    start = since if since is not None and since < now else now - FIRST_VISIT
    bound = {"since": start, "now": now}
    categories = [
        em.HandledCategoryOut(
            key=r.category, label=site.say(CATEGORY_WORDS.get(r.category, r.category)),
            count=int(r.n),
        )
        for r in await conn.execute(_HANDLED, bound)
    ]  # fmt: skip
    pick = (await conn.execute(_AUDIT, {**bound, "day": now.date().isoformat()})).first()
    audit = None
    if pick is not None:
        label = site.say(CATEGORY_WORDS.get(pick.category, pick.category))
        audit = em.AuditItemOut(
            id=str(pick.investigation_id), kind="alert_group", title=pick.rule_name or label,
            closed_as=label, category=pick.category, at=pick.at,
        )  # fmt: skip
    handled = em.HandledOut(since=start, count=sum(c.count for c in categories),
                            categories=categories, audit=audit)  # fmt: skip
    return em.TodayOut(mode="present" if present else "shadow", needs_you=needs,
                       more_waiting=waiting, new_activity=activity, gray=gray,
                       handled=handled)  # fmt: skip


def install(
    router: APIRouter,
    *,
    clock: Callable[[], datetime],
    errors: Callable[..., dict[int | str, dict[str, Any]]],
) -> None:
    """Add the engine's routes to ``router``."""

    @router.get("/today", tags=["engine"], operation_id="getToday", responses=errors(401, 403))
    async def get_today(me: Viewer, conn: Conn) -> em.TodayOut:
        """Today: what needs a person (the queue's cases: possible incidents to confirm or
        dismiss, confirmed ones nobody has taken; by band then priority; at most ten new cards a
        day, P1 and P2 always), how many more of the queue wait for room, confirmed incidents
        with new activity (and closed ones told of new strong evidence), the gray band (just
        under a lane) and what ARGUS handled since the person's last visit, with one item to
        spot-check. In shadow (``risk.present`` off) the cards are the engine's own incidents
        (kind ``shadow``) and carry no case."""
        return await today(conn, clock(), me.previous_seen_at, me.user_id)
