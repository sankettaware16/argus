"""Raise by evidence (AR2b, D-160, D-164, D-165, D-168): an investigation whose newest dossier
carries a threat-list hit, a detection by outside threat intel (its destination, or the registered
parent of a name it holds) or a tie to one (same operator as a flagged destination), and another
generic flag is in Needs attention whatever the rule's severity; any flag puts it first in the
investigator's queue.

The flags are the evidence's own, from generic signals only (``evaluation.gold.flags``: a
threat-list hit, successful answers after an attack, a regular beacon-like rhythm, remote-admin,
P2P or anonymizer ports), never a rule's name. :func:`evaluate` reads the newest dossier of every
unreviewed investigation it has not read yet and stores the flags (``investigation_raises``); the
pages and the investigator's queue read that table. A raise is a reason to look, never a verdict:
nothing is closed, proposed or written to Kibana from it.
"""

from __future__ import annotations

import json
import logging
import uuid
from collections.abc import Collection, Mapping, Sequence
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.evaluation import gold
from argus.outside import facts as outside
from argus.outside import read as outside_read
from argus.outside.read import View

log = logging.getLogger("argus.raised")

HORIZON = timedelta(days=3)  # how far back an investigation's last alert may be
BATCH = 1000  # dossiers read in one pass (the rest wait for the next pass)
PREFIX = "ARGUS raised it: "
THREAT_LIST = "on a threat list"
OUTSIDE = outside.FLAG  # "flagged by outside threat intel" (AR3, D-165)
# AR2c (D-168): set by ``argus.campaigns``, not by a dossier's signals
OPERATOR = "same operator as a flagged destination"  # raises like a detection
CAMPAIGN = "many campus devices reach one rare domain"  # one flag more, raises nothing alone
STRONG = (THREAT_LIST, OUTSIDE, OPERATOR)  # the flags that, with another flag, raise
# replayed on 21 to 27 Oct: any flag raised 552 investigations a day and the beacon flag alone 302;
# a threat-list hit with another flag, 19 (D-164). An outside detection counts as a hit (D-165),
# and so does a tie to the operator of one (D-168).
MIN_FLAGS = 2

_UNREAD = """
SELECT n.investigation_id, n.version, n.dossier_hash, n.local_signals, n.signals FROM (
  SELECT DISTINCT ON (d.investigation_id) d.investigation_id, d.version, d.dossier_hash,
         d.created_at, d.body -> 'local_signals' AS local_signals, d.body -> 'signals' AS signals
  FROM dossiers d JOIN investigations i ON i.id = d.investigation_id AND i.version = d.version
  WHERE i.last_event_at >= :since
  ORDER BY d.investigation_id, d.created_at DESC, d.pack DESC
) n
WHERE NOT EXISTS (SELECT 1 FROM review_events r WHERE r.investigation_id = n.investigation_id
                  AND r.action = 'reviewed' AND r.version = n.version)
  AND NOT EXISTS (SELECT 1 FROM investigation_raises x WHERE x.investigation_id = n.investigation_id
                  AND x.version = n.version AND x.dossier_hash = n.dossier_hash)
ORDER BY n.created_at DESC, n.investigation_id
LIMIT :limit
"""
_STORE = """
INSERT INTO investigation_raises (investigation_id, version, dossier_hash, flags)
VALUES (:i, :v, :h, CAST(:f AS jsonb))
ON CONFLICT (investigation_id) DO UPDATE SET version = EXCLUDED.version,
  dossier_hash = EXCLUDED.dossier_hash, flags = EXCLUDED.flags, evaluated_at = :now
"""


def flags_of(local_signals: Any, signals: Any) -> tuple[str, ...]:
    """The flags a dossier's signals carry, in plain words (an empty tuple: none)."""
    body: dict[str, Any] = {}
    if isinstance(local_signals, list):
        body["local_signals"] = local_signals
    if isinstance(signals, list):
        body["signals"] = signals
    return gold.flags(body)


def words(flags: Sequence[str]) -> str:
    """The reason as the pages say it: "ARGUS raised it: regular traffic, like a beacon"."""
    return PREFIX + "; ".join(flags)


def raises(flags: Sequence[str]) -> bool:
    """Whether flags put an investigation in Needs attention (the pages' ``RAISED`` in SQL): a
    threat-list hit, an outside detection or a tie to the operator of one, and at least one other
    flag."""
    return any(f in flags for f in STRONG) and len(set(flags)) >= MIN_FLAGS


def reason(stored: Any) -> str | None:
    """The words for a stored list of flags, or None when they do not raise it."""
    if not isinstance(stored, list):
        return None
    flags = [f for f in stored if isinstance(f, str) and f]
    return words(flags) if raises(flags) else None


async def evaluate(
    conn: AsyncConnection, now: datetime, *, horizon: timedelta = HORIZON, limit: int = BATCH,
    view: View | None = None,
) -> Mapping[str, int]:  # fmt: skip
    """Read the newest dossier of unreviewed investigations not read yet (newest first) and store
    its flags, with :data:`OUTSIDE` when ``view`` is given and the cache holds a detection for one
    of the investigation's external indicators. Returns ``{"read": n, "raised": m}``, and
    ``"skipped"`` when a dossier could not be read: that one is said in the log and stored with no
    flags (so it is not read again), and the others go on. Idempotent: a dossier is read once; an
    outside detection that arrives later is added by :func:`refresh_outside`."""
    rows = (await conn.execute(text(_UNREAD), {"since": now - horizon, "limit": limit})).all()
    cached = (
        await outside_read.facts_for(
            conn,
            [r[0] for r in rows],
            now,
            view.window,
            view.threshold,
            clean_window=view.clean_window,
            parent_ok=view.parent_ok,
        )
        if view is not None
        else {}
    )
    raised = skipped = 0
    for investigation_id, version, dossier_hash, local_signals, signals in rows:
        try:
            found = outside.with_flag(
                flags_of(local_signals, signals), cached.get(investigation_id)
            )
        except Exception as exc:  # one malformed dossier must not stop the others
            skipped += 1
            found = ()
            log.warning("raise: the dossier of investigation %s (version %s) could not be read: %s",
                        investigation_id, version, type(exc).__name__)  # fmt: skip
        raised += bool(found)
        await conn.execute(
            text(_STORE),
            {"i": investigation_id, "v": version, "h": dossier_hash,
             "f": json.dumps(list(found)), "now": now},
        )  # fmt: skip
    counts = {"read": len(rows), "raised": raised}
    return {**counts, "skipped": skipped} if skipped else counts


_REFRESH = """
UPDATE investigation_raises r SET flags = r.flags || to_jsonb(CAST(:flag AS text)),
  evaluated_at = :now
FROM investigations i
WHERE i.id = r.investigation_id AND r.version = i.version AND i.last_event_at >= :since
  AND NOT jsonb_exists(r.flags, CAST(:flag AS text))
  AND NOT EXISTS (SELECT 1 FROM review_events rv WHERE rv.investigation_id = i.id
                  AND rv.action = 'reviewed' AND rv.version = i.version)
  AND EXISTS (
    SELECT 1 FROM investigation_entities e
    JOIN outside_lookups o ON o.kind = e.kind AND o.indicator = e.value
    WHERE e.investigation_id = i.id AND e.kind IN ('ip', 'domain')
      AND o.source = 'virustotal' AND o.status = 'found' AND o.fetched_at >= :fresh
      AND CAST(COALESCE(NULLIF(o.answer ->> 'malicious', ''), '0') AS integer) >= :threshold)
RETURNING r.investigation_id
"""


async def refresh_outside(
    conn: AsyncConnection, now: datetime, view: View, *, horizon: timedelta = HORIZON
) -> int:
    """Add :data:`OUTSIDE` to the stored flags of unreviewed investigations (current version, last
    alert within ``horizon``) one of whose external indicators the cache now holds as a detection:
    the lookups come after the dossier is read, so this is how a beacon whose server VirusTotal
    flags is raised. Returns how many were changed."""
    done = await conn.execute(
        text(_REFRESH),
        {"flag": OUTSIDE, "now": now, "since": now - horizon, "fresh": now - view.window,
         "threshold": view.threshold},
    )  # fmt: skip
    return len(done.all())


_ADD = """
UPDATE investigation_raises r SET flags = r.flags || to_jsonb(CAST(:flag AS text)),
  evaluated_at = :now
FROM investigations i
WHERE i.id = r.investigation_id AND r.version = i.version AND i.last_event_at >= :since
  AND r.investigation_id = ANY(:ids)
  AND NOT jsonb_exists(r.flags, CAST(:flag AS text))
  AND NOT EXISTS (SELECT 1 FROM review_events rv WHERE rv.investigation_id = i.id
                  AND rv.action = 'reviewed' AND rv.version = i.version)
RETURNING r.investigation_id
"""


async def add_flag(
    conn: AsyncConnection, now: datetime, flag: str, ids: Collection[uuid.UUID], *,
    horizon: timedelta = HORIZON,
) -> int:  # fmt: skip
    """Add ``flag`` to the stored flags of the unreviewed investigations in ``ids`` (current
    version, last alert within ``horizon``) that lack it: how a campaign's flags (D-168) reach the
    investigations of its families. Returns how many were changed."""
    if not ids:
        return 0
    done = await conn.execute(
        text(_ADD).bindparams(bindparam("ids", type_=ARRAY(UUID))),
        {"flag": flag, "now": now, "since": now - horizon, "ids": list(ids)},
    )
    return len(done.all())
