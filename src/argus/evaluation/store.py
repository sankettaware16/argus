"""The gold set in the store (P2, D-080): frozen items and a person's append-only answers.

- ``import_set`` stores a chosen set once (``gold_select`` writes the manifest), each item
  checked against the dossier it was chosen at; a set that exists is never changed;
- ``answer`` records a person's outcome (a correction is a new row; the newest counts);
- ``items`` / ``item`` / ``progress`` read them back for the labelling page and the harness;
  with ``ANY`` they span every set (the labelling page shows them all; an investigation is in
  one set at most, ``gold.extend`` excludes the existing items).
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.db.models import GOLD_SPLITS, OUTCOMES

SET = "v1"
ANY = None  # every set
NOTE_LIMIT = 4000


class GoldError(ValueError):
    pass


@dataclass(frozen=True)
class GoldRow:
    investigation_id: uuid.UUID
    rule_name: str
    split: str
    why: tuple[str, ...]
    suggestion: Mapping[str, Any]
    outcome: str | None  # the person's newest answer
    note: str | None
    answered_by: str | None
    answered_at: datetime | None


async def import_set(
    conn: AsyncConnection, records: Sequence[Mapping[str, Any]], set_name: str = SET
) -> int:
    """Store ``records`` as the set ``set_name``; refuse if it exists or an item's dossier
    is not the one it was chosen at."""
    if not records:
        raise GoldError("no items")
    exists = await conn.scalar(
        text("SELECT count(*) FROM gold_items WHERE set_name = :s"), {"s": set_name}
    )
    if exists:
        raise GoldError(f"the set {set_name!r} exists ({exists} items): a set is frozen")
    for n, r in enumerate(records, start=1):
        if r.get("split") not in GOLD_SPLITS:
            raise GoldError(f"item {n}: split must be one of {', '.join(GOLD_SPLITS)}")
        found = await conn.scalar(
            text(
                "SELECT count(*) FROM dossiers WHERE investigation_id = :i AND version = :v"
                " AND pack = :p AND dossier_hash = :h"
            ),
            {"i": r["investigation_id"], "v": r["version"], "p": r["pack"], "h": r["dossier_hash"]},
        )
        if not found:
            raise GoldError(f"item {n}: no dossier with that version, pack and hash")
        await conn.execute(
            text(
                "INSERT INTO gold_items (set_name, investigation_id, version, pack, dossier_hash,"
                " rule_name, split, why, suggestion) VALUES (:s, :i, :v, :p, :h, :r, :sp, :w,"
                " CAST(:sg AS jsonb))"
            ),
            {"s": set_name, "i": r["investigation_id"], "v": r["version"], "p": r["pack"],
             "h": r["dossier_hash"], "r": r["rule_name"], "sp": r["split"],
             "w": list(r.get("why") or []), "sg": json.dumps(r["suggestion"])},
        )  # fmt: skip
    return len(records)


async def answer(
    conn: AsyncConnection,
    investigation_id: uuid.UUID,
    user_id: int,
    outcome: str,
    note: str | None = None,
    set_name: str | None = SET,
) -> None:
    if outcome not in OUTCOMES:
        raise GoldError("choose an outcome")
    note = (note or "").strip() or None
    if note is not None and len(note) > NOTE_LIMIT:
        raise GoldError(f"the note is longer than {NOTE_LIMIT} characters")
    sets = (
        await conn.scalars(
            text(
                "SELECT set_name FROM gold_items WHERE investigation_id = :i"
                " AND (CAST(:s AS text) IS NULL OR set_name = :s)"
            ),
            {"s": set_name, "i": investigation_id},
        )
    ).all()
    if not sets:
        raise GoldError("not in the gold set")
    if len(sets) > 1:
        raise GoldError("in more than one gold set: name the set")
    set_name = sets[0]
    await conn.execute(
        text(
            "INSERT INTO gold_labels (set_name, investigation_id, user_id, outcome, note)"
            " VALUES (:s, :i, :u, :o, :n)"
        ),
        {"s": set_name, "i": investigation_id, "u": user_id, "o": outcome, "n": note},
    )


_ROWS = """
SELECT g.investigation_id, g.rule_name, g.split, g.why, g.suggestion,
       l.outcome, l.note, u.display_name, l.created_at
FROM gold_items g
LEFT JOIN LATERAL (
  SELECT * FROM gold_labels x WHERE x.set_name = g.set_name
    AND x.investigation_id = g.investigation_id ORDER BY x.id DESC LIMIT 1
) l ON true
LEFT JOIN users u ON u.id = l.user_id
WHERE (CAST(:s AS text) IS NULL OR g.set_name = :s) {where}
ORDER BY (l.outcome IS NOT NULL), g.rule_name, g.investigation_id
"""


def _row(r: Any) -> GoldRow:
    return GoldRow(r[0], r[1], r[2], tuple(r[3] or ()), r[4] or {}, r[5], r[6], r[7], r[8])


async def items(conn: AsyncConnection, set_name: str | None = SET) -> list[GoldRow]:
    """Every item, unanswered first, then by rule."""
    rows = await conn.execute(text(_ROWS.format(where="")), {"s": set_name})
    return [_row(r) for r in rows]


async def item(
    conn: AsyncConnection, investigation_id: uuid.UUID, set_name: str | None = SET
) -> GoldRow | None:
    rows = await conn.execute(
        text(_ROWS.format(where="AND g.investigation_id = :i")),
        {"s": set_name, "i": investigation_id},
    )
    found = rows.first()
    return _row(found) if found else None


async def progress(conn: AsyncConnection, set_name: str | None = SET) -> dict[str, int]:
    """Items, answered, and answered per split."""
    rows = await items(conn, set_name)
    out = {"items": len(rows), "answered": sum(r.outcome is not None for r in rows)}
    for part in GOLD_SPLITS:
        out[f"{part}_answered"] = sum(r.outcome is not None and r.split == part for r in rows)
    return out
