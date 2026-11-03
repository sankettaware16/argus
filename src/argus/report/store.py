"""report@2's inputs from Postgres: a few bounded reads, nothing written.

The report of an assessment reads the dossier it assessed, the evidence of that version as the
assessment had it (``facts.as_of``), the investigation's E-ids, and for each evidence row the ledger
row that answered it (``_LEDGER``). Without an assessment: the newest dossier and every row."""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.context.packs import PackRegistry, default_registry
from argus.report.build import AssessmentRow, Inputs, build
from argus.report.facts import EvidenceRow, LedgerRow, RequestRow, as_of
from argus.report.model import Report

_ASSESSMENT = """
SELECT id, version, pack, dossier_hash, assessor, status, outcome, confidence, decided_by,
       reasons, created_at, finished_at
FROM assessments WHERE id = :a AND investigation_id = :i
"""
_CURRENT = """
SELECT DISTINCT ON (a.assessor) a.id
FROM assessments a JOIN investigations i ON i.id = a.investigation_id AND i.version = a.version
WHERE a.investigation_id = :i
ORDER BY a.assessor, a.id DESC
"""
_DOSSIER = """
SELECT version, pack, dossier_hash, body FROM dossiers
WHERE investigation_id = :i AND version = :v AND pack = :p AND dossier_hash = :h
"""
_NEWEST = """
SELECT version, pack, dossier_hash, body FROM dossiers WHERE investigation_id = :i
ORDER BY version DESC, created_at DESC, pack DESC LIMIT 1
"""
_EVIDENCE = """
SELECT task_key, version, template, template_version, params, status, coverage, row_count,
       truncated, snapshot, result_hash, took_ms, source_watermark, reused_from_version, error,
       collected_at, snapshot_purged_at IS NOT NULL AS purged
FROM evidence WHERE investigation_id = :i AND version = :v ORDER BY task_key
"""
_REQUESTS = """
SELECT eid, task_key, template, template_version, origin, reason, first_version, created_at
FROM evidence_requests WHERE investigation_id = :i ORDER BY eid
"""
# The ledger has no investigation id: a request is matched to the evidence row it answered by
# its content address, made by the evidence step (component enrichment, or investigation: the
# deterministic wave's and "Check more"'s lane) within the hour before
# the row was stored, and for an answer by the server time stored with it. A row that sent
# nothing (deferred, skipped, copied from an earlier version) has no ledger row.
_LEDGER = """
SELECT e.task_key, l.at, l.indices, l.outcome, l.took_ms, l.attempts
FROM evidence e CROSS JOIN LATERAL (
  SELECT r.at, r.indices, r.outcome, r.took_ms, r.attempts FROM siem_requests r
  WHERE r.task_key = e.task_key AND r.component IN ('enrichment', 'investigation')
    AND r.at <= e.collected_at AND r.at >= e.collected_at - interval '1 hour'
    AND ((e.status IN ('ok', 'empty') AND r.outcome = 'ok' AND r.took_ms = e.took_ms)
         OR e.status IN ('timeout', 'failed'))
  ORDER BY r.at DESC LIMIT 1
) l
WHERE e.investigation_id = :i AND e.version = :v AND e.reused_from_version IS NULL
"""


def _assessment(row: Any) -> AssessmentRow:
    reasons = row.reasons if isinstance(row.reasons, list) else []
    return AssessmentRow(
        id=int(row.id), assessor=str(row.assessor), status=str(row.status),
        outcome=row.outcome, confidence=row.confidence, decided_by=row.decided_by,
        reasons=reasons, created_at=row.created_at, finished_at=row.finished_at,
    )  # fmt: skip


async def inputs(
    conn: AsyncConnection, investigation_id: uuid.UUID, assessment_id: int | None = None
) -> Inputs | None:
    """What the report of one assessment (or, without one, of the newest dossier) reads;
    None without a dossier, or for an assessment of another investigation."""
    i = {"i": investigation_id}
    assessment = None
    if assessment_id is not None:
        found = (await conn.execute(text(_ASSESSMENT), {**i, "a": assessment_id})).first()
        if found is None:
            return None
        assessment = _assessment(found)
        dossier = (
            await conn.execute(
                text(_DOSSIER),
                {**i, "v": found.version, "p": found.pack, "h": found.dossier_hash},
            )
        ).first()
    else:
        dossier = (await conn.execute(text(_NEWEST), i)).first()
    if dossier is None:
        return None
    v = {**i, "v": dossier.version}
    until = assessment.finished_at if assessment is not None else None
    evidence = [
        EvidenceRow(
            task_key=r.task_key,
            version=r.version,
            template=r.template,
            template_version=r.template_version,
            params=r.params or {},
            status=r.status,
            coverage=r.coverage or {},
            row_count=r.row_count,
            truncated=bool(r.truncated),
            snapshot=r.snapshot,
            result_hash=r.result_hash,
            took_ms=r.took_ms,
            source_watermark=r.source_watermark,
            reused_from_version=r.reused_from_version,
            error=r.error,
            collected_at=r.collected_at,
            purged=bool(r.purged),
        )
        for r in await conn.execute(text(_EVIDENCE), v)
    ]
    refs = [e for e in dossier.body.get("evidence") or [] if isinstance(e, Mapping)]
    evidence = as_of(evidence, refs, int(dossier.version), until)
    requests = [
        RequestRow(
            eid=int(r.eid),
            task_key=r.task_key,
            template=r.template,
            template_version=int(r.template_version),
            origin=r.origin,
            reason=r.reason,
            first_version=int(r.first_version),
            created_at=r.created_at,
        )
        for r in await conn.execute(text(_REQUESTS), i)
    ]
    ledger: Mapping[str, LedgerRow] = {
        r.task_key: LedgerRow(
            task_key=r.task_key,
            at=r.at,
            indices=tuple(r.indices or ()),
            outcome=r.outcome,
            took_ms=int(r.took_ms),
            attempts=int(r.attempts),
        )
        for r in await conn.execute(text(_LEDGER), v)
    }
    return Inputs(
        investigation_id=str(investigation_id),
        version=int(dossier.version),
        pack=str(dossier.pack),
        dossier_hash=str(dossier.dossier_hash),
        body=dossier.body,
        evidence=evidence,
        requests=requests,
        ledger=ledger,
        assessment=assessment,
    )


async def report(
    conn: AsyncConnection,
    investigation_id: uuid.UUID,
    assessment_id: int | None = None,
    packs: PackRegistry | None = None,
) -> Report | None:
    got = await inputs(conn, investigation_id, assessment_id)
    if got is None:
        return None
    return build(got, (packs or default_registry()).get(got.pack))


async def current(
    conn: AsyncConnection, investigation_id: uuid.UUID, packs: PackRegistry | None = None
) -> list[Report]:
    """report@2 of each assessor's newest assessment at the investigation's current version,
    the AI investigator's first; the newest dossier's alone when nothing assessed it."""
    registry = packs or default_registry()
    ids = list((await conn.execute(text(_CURRENT), {"i": investigation_id})).scalars())
    out = []
    for assessment_id in ids:
        got = await report(conn, investigation_id, int(assessment_id), registry)
        if got is not None:
            out.append(got)
    if not out:
        alone = await report(conn, investigation_id, None, registry)
        return [] if alone is None else [alone]
    return sorted(out, key=lambda r: (r.verdict.source != "the AI investigator",
                                      r.verdict.assessor or ""))  # fmt: skip
