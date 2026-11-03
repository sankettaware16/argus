"""The shared closure payload builder (plan §5 Q-C3): the exact writes a closure or merge will
plan, which a request binds to (by its hash), the approver sees (Q-B3's preview must equal
it), the close step checks again and the send-time check compares with each outbox row.

The payload is ARGUS-level intent, as :mod:`argus.cases.kibana` plans it: for a mirrored case
one W3 change (closed status, the reason's tags, ARGUS's own tags only) and the closing comment
as a template with the reason; nothing for a case Kibana does not hold. It depends only on the
case as it is when the closure is requested and the reason (and a merge's target), never on
the time, so the same request always builds the same payload.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any

from argus.cases import kibana
from argus.cases.model import Case, Reason


@dataclass(frozen=True)
class ClosurePayload:
    payload: dict[str, Any]
    payload_hash: str

    @property
    def writes(self) -> list[dict[str, Any]]:
        writes: list[dict[str, Any]] = self.payload["writes"]
        return writes


def build(
    before: Case, reason: Reason, now: datetime, *, target: uuid.UUID | None = None
) -> ClosurePayload:
    """What closing ``before`` (the case at the request's version) for ``reason`` writes."""
    closed = replace(
        before, state="closed", closure_reason=reason, closed_at=now, merged_into_id=target
    )
    writes = kibana.close(closed) if before.mirrored else []
    payload: dict[str, Any] = {
        "case": str(before.id),
        "version": before.version,
        "reason": reason,
        "writes": [{"class": w.write_class, "op": w.op, "payload": w.payload} for w in writes],
    }
    if target is not None:
        payload["target"] = str(target)
    return ClosurePayload(payload, kibana.payload_hash(payload))


def write_at(payload: dict[str, Any], position: int) -> dict[str, Any] | None:
    """The approved write at ``position``, or None."""
    writes = payload.get("writes")
    if not isinstance(writes, list) or not 0 <= position < len(writes):
        return None
    found = writes[position]
    return found if isinstance(found, dict) else None
