"""Approved compensating writes (plan §3 rule 3, §7.1): the undo of a W2 or W3 write.

ARGUS cannot undo W1; W2 and W3 are undone by a write a person approved, read back like any
other. :func:`build` is the one place that says what such a write is (an approval binds its
hash; Q-B3's preview must use it): the fields the write changed, put back as the Kibana case
had them before (the row's before-image), then a correcting comment. The comment the earlier
write added stays. The writer acts on a complete, signed request of kind ``compensating`` for a
verified row only when the request's payload is exactly what :func:`build` gives now, and plans
two steps (:mod:`argus.writer.store`), which run in a W2 run when the case has nothing else in
doubt.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.cases import approvals
from argus.cases import kibana as intent
from argus.cases.approvals import RequestRecord
from argus.cases.identity import UPDATE_CASE
from argus.writer import approval, plan, store

if TYPE_CHECKING:
    from argus.writer.sender import Writer


def build(row: plan.Row, before: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """The payload of the compensating write for ``row`` (an update or a closure), or None when
    it cannot be built (no before-image, or the row is not W2/W3, or changed nothing)."""
    if row.op not in ("update", "close") or before is None:
        return None
    fields: dict[str, Any] = {}
    if row.op == "close" or "status" in row.payload:
        fields["status"] = before["status"]
    if row.op == "update" and "severity" in row.payload:
        fields["severity"] = before["severity"]
    if row.op == "close" or "argus_tags" in row.payload:
        fields["argus_tags"] = sorted(t for t in before["tags"] if plan.is_managed(t))
    if not fields:
        return None
    return {
        "outbox": row.id,
        "case": str(row.case_id),
        "of": row.idempotency_key,
        "what": row.op,
        "status_from": "closed" if row.op == "close" else row.payload.get("status"),
        "writes": [
            {"class": "W2", "op": "update", "payload": fields},
            {
                "class": "W2",
                "op": "comment",
                "payload": {
                    "template": "corrected",
                    "params": {"what": row.op, "of": row.idempotency_key},
                },
            },
        ],
    }


def hashed(payload: Mapping[str, Any]) -> str:
    return intent.payload_hash(dict(payload))


async def before_image(conn: AsyncConnection, outbox_id: int) -> Mapping[str, Any] | None:
    found = (
        await conn.execute(
            text("SELECT before_image FROM kibana_outbox WHERE id = :i"), {"i": outbox_id}
        )
    ).scalar_one_or_none()
    return found if isinstance(found, dict) else None


async def apply(w: Writer) -> list[str]:
    """Plan the steps of every complete compensating request that has none yet; returns what
    was refused, for the report."""
    refused: list[str] = []
    async with w.engine.connect() as conn:
        ids = await store.complete_requests(conn, "compensating")
    for request_id in ids:
        async with w.engine.begin() as conn:
            made = await conn.execute(
                text("SELECT 1 FROM kibana_steps WHERE approval_request_id = :r"), {"r": request_id}
            )
            if made.first() is not None:
                continue
            request = await approvals.record(conn, request_id)
            assert request is not None
            why = await _refusal(w, conn, request)
            if why is not None:
                refused.append(f"request {request_id}: {why}")
                continue
            row = await store.get_row(conn, int(request.outbox_id or 0))
            assert row is not None
            payload = request.payload
            ids_ = []
            for seq, write in enumerate(payload["writes"]):
                body = dict(write["payload"])
                if seq == 0:
                    body["status_from"] = payload.get("status_from")
                ids_.append(
                    await store.insert_step(
                        conn,
                        case_id=row.case_id,
                        outbox_id=row.id,
                        approval_request_id=request_id,
                        kind="compensate_update" if seq == 0 else "compensate_comment",
                        seq=seq,
                        key=f"{request_id}:comp:{seq}",
                        write_class="W2",
                        payload=body,
                    )
                )
            await store.audit(
                conn,
                "kibana.compensation.planned",
                row.case_id,
                {"request": request_id, "outbox": row.id, "steps": ids_},
            )
    return refused


async def _refusal(w: Writer, conn: AsyncConnection, request: RequestRecord) -> str | None:
    row = None if request.outbox_id is None else await store.get_row(conn, request.outbox_id)
    if row is None or row.state != "verified" or row.write_class not in ("W2", "W3"):
        return "the write it undoes is not a verified W2 or W3 write"
    expected = build(row, await before_image(conn, row.id))
    if expected is None or request.payload != expected or request.payload_hash != hashed(expected):
        return "the payload is not the compensating write ARGUS builds now"
    return await approval.problem(conn, request, w.verifier, UPDATE_CASE)
