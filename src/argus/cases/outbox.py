"""The Kibana outbox's states: pure, mirrored by the ``argus_outbox_guard`` trigger (a test keeps
it equal to :data:`MOVES`).

planned → approved → sending → sent → verified, or ambiguous, conflict, paused, skipped. ``sending``
is committed before the request, so a crash leaves it there and it becomes ``ambiguous``. Nothing
is resent automatically: a row is sent again only after ``ambiguous → planned``, which needs a
person's approval of the resend (``sent_count <= 1 + resends``). ``verified`` and ``skipped`` are
final."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, get_args

OutboxState = Literal[
    "planned",
    "approved",
    "sending",
    "sent",
    "verified",
    "ambiguous",
    "conflict",
    "paused",
    "skipped",
]
OUTBOX_STATES: tuple[OutboxState, ...] = get_args(OutboxState)
MOVES: dict[OutboxState, frozenset[OutboxState]] = {
    "planned": frozenset({"approved", "paused", "skipped"}),
    "approved": frozenset({"planned", "sending", "paused", "skipped"}),
    "sending": frozenset({"sent", "ambiguous", "conflict", "paused"}),
    "sent": frozenset({"verified", "conflict", "paused"}),
    "ambiguous": frozenset({"sent", "verified", "planned", "paused", "skipped"}),
    "conflict": frozenset({"paused", "skipped"}),
    "paused": frozenset({"planned", "approved", "skipped"}),
    "verified": frozenset(),
    "skipped": frozenset(),
}
FINAL: frozenset[OutboxState] = frozenset(s for s, moves in MOVES.items() if not moves)


@dataclass(frozen=True)
class Row:
    state: OutboxState
    sent_count: int
    resends: int


class OutboxRefused(ValueError):  # noqa: N818 - a refusal, not an error
    pass


def move(row: Row, to: OutboxState, *, resend_approved: bool = False) -> Row:
    """The row after moving it to ``to``; OutboxRefused when the outbox does not allow it."""
    if to not in MOVES[row.state]:
        raise OutboxRefused(f"an outbox row does not move from {row.state} to {to}")
    resends = row.resends
    if row.state == "ambiguous" and to == "planned":
        if not resend_approved:
            raise OutboxRefused("a resend needs a person's approval")
        resends += 1
    sent = row.sent_count + (1 if to == "sending" else 0)
    if sent > 1 + resends:
        raise OutboxRefused("a write is sent again only after an approved resend")
    return Row(to, sent, resends)
