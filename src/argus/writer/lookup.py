"""Writes in doubt: the looks, the "resend?" and the resend.

A write whose outcome is unknown is ``ambiguous`` and looked for at 2, 5, 15 and 30 minutes
(:func:`run_lookups`): a **create** by the case's ``argus:case:<uuid>`` tag and its payload, a
**change** by re-reading the case and planning again (nothing left to do means it landed), a
**comment** by the case's newest comments, an **attachment** by the alerts' case ids. One match is
the write and it becomes ``verified``; two matches for one create are a duplicate (flagged, class
paused, never deleted). If the fourth look finds nothing while Kibana answers, an outbox row gets
the "resend?" mark and a step is closed as lost. A resend needs a person's complete, signed
approval bound to the exact write and send count; the writer looks once more first."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import text

from argus.cases import approvals
from argus.cases import kibana as intent
from argus.gateway.errors import GatewayError
from argus.gateway.kibana.errors import KibanaResponseError
from argus.gateway.kibana.templates import CasesFind, FindParams
from argus.writer import approval, plan, render, store

if TYPE_CHECKING:
    from argus.writer.sender import Item, Writer

RESEND = "resend?"  # a row's reason once the four looks found nothing
_READ = timedelta(minutes=2)
_RETRY = timedelta(minutes=2)  # a look that could not be made is made again then


def resend_payload(row: plan.Row) -> dict[str, Any]:
    """What a resend approval binds: this write, as it was sent the ``sent_count``-th time."""
    return {
        "outbox": row.id,
        "key": row.idempotency_key,
        "payload_hash": row.payload_hash,
        "sent_count": row.sent_count,
    }


def _why(exc: BaseException) -> str:
    return render.clean(f"{type(exc).__name__}: {exc}", 160)


def _without_link(text_: str) -> list[str]:
    return [line for line in text_.splitlines() if "/go/case/" not in line]


def is_ours(case: Mapping[str, Any], payload: Mapping[str, Any], wanted: str, author: str) -> bool:
    """A case Kibana returned is the create ARGUS sent: made by ARGUS, with the payload's title,
    severity and tags, and the description written for it (the link line aside, so a changed
    public address does not hide a case that landed)."""
    return (
        (case.get("created_by") or {}).get("username") == author
        and case.get("title") == plan.kibana_title(payload.get("title"))
        and case.get("severity") == payload.get("severity")
        and set(payload.get("argus_tags", ())) <= set(case.get("tags") or ())
        and _without_link(str(case.get("description"))) == _without_link(wanted)
    )


async def find_created(w: Writer, row: plan.Row) -> tuple[list[Mapping[str, Any]], int]:
    """(the cases that are this create, the others found under its tag). A search that cannot
    be made (Kibana or the lane refuses or fails) or a description that cannot be written is a
    look that is not made: ``RunStopped``, and the look comes again."""
    from argus.writer.sender import RunStopped

    tag = next(t for t in row.payload["argus_tags"] if t.startswith("argus:case:"))
    try:
        result = await w.gateway.read(
            CasesFind(),
            FindParams(tags=(tag,), reporters="argus", per_page=20),
            component="writer",
            deadline=w.clock() + _READ,
        )
        found: list[Mapping[str, Any]] = result.body["cases"]
        wanted = render.description(
            row.payload["description"]["params"], render.Context(w.link_base)
        )
    except (GatewayError, KibanaResponseError, render.RenderError, KeyError, TypeError) as exc:
        raise RunStopped(f"the look for the created case cannot be made ({_why(exc)})") from None
    ours = [c for c in found if is_ours(c, row.payload, wanted, w.author)]
    return ours, len(found) - len(ours)


async def look(w: Writer, item: Item) -> tuple[str, dict[str, Any], str | None]:
    """One look for an ambiguous item: (outcome, details, the Kibana case id it found)."""
    if item.row is not None and item.row.op == "create":
        ours, others = await find_created(w, item.row)
        if len(ours) > 1:
            return "duplicate", {"cases": [c["id"] for c in ours]}, None
        if ours:
            return "found", {"case": ours[0]["id"]}, str(ours[0]["id"])
        return ("foreign" if others else "not_found"), {"others": others}, None
    # anything else: the compare the read-back makes decides
    ok, why = await w._compare(item)
    return ("found", {}, None) if ok else ("not_found", {"why": why}, None)


async def run_lookups(w: Writer) -> None:
    """Make every look that is due."""
    from argus.writer.sender import RunStopped

    async with w.engine.connect() as conn:
        due = await store.due_lookups(conn, w.clock())
    for lk in due:
        now = w.clock()
        async with w.engine.connect() as conn:
            table = store.OUTBOX if lk.subject == "outbox" else store.STEPS
            item = await w._load(conn, table, lk.subject_id)
        if item is None or item.sent_count != lk.sent_count or not await _ambiguous(w, item):
            async with w.engine.begin() as conn:
                await store.finish_lookup(conn, lk.id, "not_needed", {}, now)
            continue
        try:
            outcome, details, kibana_id = await look(w, item)
        except RunStopped:
            async with w.engine.begin() as conn:  # not a look: made again later
                await store.postpone_lookup(conn, lk.id, now + _RETRY)
            continue
        async with w.engine.begin() as conn:
            await store.finish_lookup(conn, lk.id, outcome, details, now)
        try:
            await _settle(w, item, lk.attempt, outcome, details, kibana_id)
        except RunStopped:
            continue  # the read-back paused the class or could not read: the other looks go on


async def _ambiguous(w: Writer, item: Item) -> bool:
    async with w.engine.connect() as conn:
        state = (
            await conn.execute(
                text(f"SELECT state FROM {item.table} WHERE id = :i"),  # noqa: S608 - fixed name
                {"i": item.id},
            )
        ).scalar_one_or_none()
    return state == "ambiguous"


async def _settle(
    w: Writer,
    item: Item,
    attempt: int,
    outcome: str,
    details: dict[str, Any],
    kibana_id: str | None,
) -> None:
    """Act on a look that was made."""
    from argus.writer.sender import RunReport

    now = w.clock()
    if outcome == "found":
        async with w.engine.begin() as conn:
            await store.move(
                conn,
                item.table,
                item.id,
                "sent",
                None,
                kibana_case_id=kibana_id,
                only_from=["ambiguous"],
            )
            await store.audit(
                conn,
                "kibana.write.found",
                item.case_id,
                {"item": item.ledger_id, "attempt": attempt, **details},
            )
        await w._verify(item, RunReport(item.write_class), None)
    elif outcome == "duplicate":
        async with w.engine.begin() as conn:
            await store.note(conn, item.table, item.id, f"duplicate: {details['cases']}")
            await store.finding_attention(
                conn,
                "duplicate_case",
                item.case_id,
                None,
                f"writer:dup:{item.key}",
                {"item": item.ledger_id, **details},
                now,
            )
            await store.audit(
                conn,
                "kibana.write.duplicate",
                item.case_id,
                {"item": item.ledger_id, **details},
                outcome="failure",
            )
        await w._pause_class(item.write_class, f"{item.ledger_id} landed twice")
    elif attempt == 4 and outcome in ("not_found", "foreign"):
        await _gave_up(w, item)


async def _gave_up(w: Writer, item: Item) -> None:
    """Four looks made, nothing found, Kibana answering: an outbox row asks for a resend; a
    step is lost (a missing step beats a duplicate)."""
    async with w.engine.begin() as conn:
        if item.row is not None:
            await store.note(
                conn, item.table, item.id, f"{RESEND} not found in Kibana after 30 minutes"
            )
            await store.audit(
                conn,
                "kibana.write.resend_asked",
                item.case_id,
                {"item": item.ledger_id, "sent_count": item.sent_count},
            )
        else:
            await store.move(
                conn,
                item.table,
                item.id,
                "skipped",
                "lost: not found in Kibana after 30 minutes; not sent again",
                only_from=["ambiguous"],
            )
            await store.audit(
                conn, "kibana.step.lost", item.case_id, {"item": item.ledger_id}, outcome="failure"
            )


async def resend_items(w: Writer) -> list[plan.Row]:
    """Rows that ask a person for a resend (the approvals queue's "resend?" items)."""
    async with w.engine.connect() as conn:
        rows = await store.rows_in(conn, "ambiguous")
        asking = []
        for row in rows:
            reason = (
                await conn.execute(
                    text("SELECT state_reason FROM kibana_outbox WHERE id = :i"), {"i": row.id}
                )
            ).scalar_one()
            if str(reason or "").startswith(RESEND):
                asking.append(row)
    return asking


async def apply_resends(w: Writer) -> list[str]:
    """Move a "resend?" row back to ``planned`` when a person's complete approval of exactly
    this write, this send, stands; returns what was refused."""
    refused: list[str] = []
    for row in await resend_items(w):
        async with w.engine.connect() as conn:
            ids = await store.complete_requests(conn, "resend", outbox_id=row.id)
        for request_id in ids:
            async with w.engine.connect() as conn:
                request = await approvals.record(conn, request_id)
                assert request is not None
                why = _binding(request, row)
                if why is None:
                    why = await approval.problem(
                        conn, request, w.verifier, approval.privilege_for(row.op, row.write_class)
                    )
            if why is not None:
                refused.append(f"request {request_id}: {why}")
                continue
            await _resend(w, row, request_id)
            break
    return refused


def _binding(request: Any, row: plan.Row) -> str | None:
    if request.outbox_sent_count != row.sent_count:
        return "it was asked for another send of this write"
    if request.payload != resend_payload(row) or request.payload_hash != intent.payload_hash(
        request.payload
    ):
        return "it does not bind this write"
    return None


async def _resend(w: Writer, row: plan.Row, request_id: int) -> None:
    """The last look, then ``ambiguous`` -> ``planned`` with one more send allowed."""
    from argus.writer.sender import RunStopped, item_of

    item = item_of(row)
    try:
        outcome, details, kibana_id = await look(w, item)
    except RunStopped:
        return  # not now: the approval stands, the next run looks again
    if outcome != "not_found" and outcome != "foreign":
        await _settle(w, item, 4, outcome, details, kibana_id)
        return
    async with w.engine.begin() as conn:
        moved = await conn.execute(
            text(
                "UPDATE kibana_outbox SET state = 'planned', resends = resends + 1,"
                " state_reason = :r WHERE id = :i AND state = 'ambiguous'"
            ),
            {"i": row.id, "r": f"resend approved ({request_id})"},
        )
        if moved.rowcount == 1:
            await store.close_lookups(conn, "outbox", row.id, w.clock())
            await store.audit(
                conn,
                "kibana.write.resend_approved",
                row.case_id,
                {"item": row.id, "request": request_id},
            )
