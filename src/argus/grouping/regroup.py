"""Rebuild every investigation from the stored alerts (after a grouping change, D-053). Run
by the operator as the schema owner: it empties the derived tables, which ARGUS itself may
never do. Refused while reviews, the gold set or cases exist, because they belong to the old
investigations (the case tables, empty then, are emptied with them: Q-C1's foreign keys)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.grouping.store import group
from argus.normalize import NormalizedAlert

BATCH = 1000


class ReviewsExistError(Exception):
    pass


async def regroup(engine: AsyncEngine, now: datetime) -> tuple[int, int]:
    """(alerts grouped, investigations) after rebuilding from ``alert_records``."""
    async with engine.begin() as conn:
        reviews = (await conn.execute(text("SELECT count(*) FROM review_events"))).scalar_one()
        if reviews:
            raise ReviewsExistError(f"{reviews} reviews refer to the current investigations")
        gold = (await conn.execute(text("SELECT count(*) FROM gold_items"))).scalar_one()
        if gold:  # the answer key belongs to the current investigations too (P2)
            raise ReviewsExistError(f"{gold} gold-set items refer to the current investigations")
        cases = (
            await conn.execute(
                text("SELECT (SELECT count(*) FROM cases) + (SELECT count(*) FROM case_openings)")
            )
        ).scalar_one()
        if cases:  # Q-C1: cases and the opener's decisions name the current investigations
            raise ReviewsExistError(f"{cases} cases or case decisions refer to the investigations")
        await conn.execute(
            text(
                "TRUNCATE signals, dossiers, evidence, evidence_requests, langgraph.checkpoints,"
                " langgraph.checkpoint_blobs, langgraph.checkpoint_writes, jobs,"
                " investigation_entities, entities, investigation_alerts, review_events,"
                " review_state, gold_labels, gold_items, assessments, llm_shadow, investigations,"
                " case_openings, case_members, case_indicators, case_events, case_notes,"
                " kibana_mirror, kibana_findings, action_ledger, approval_decisions, kibana_steps,"
                " kibana_lookups, kibana_outbox, approval_requests, cases, freshness_shadow,"
                " freshness_proposals, investigation_checks, case_watch_checks, case_suggestions,"
                " notices, case_actions, writeback_outbox, assessment_shares,"
                " investigation_raises, case_known_matches, case_known_keys, case_reminders,"
                " case_notices, incident_report_checks, incident_report_decisions,"
                " incident_reports, case_team_looks, case_team_reads, case_team_seen,"
                " case_team_approvals, case_team_steps, case_team_posts"
                # review_events, the gold set and the case tables are empty (checked above:
                # their append-only guards refuse a TRUNCATE that would lose a row); the rest
                # is derived, the shadows' answers too (Q-G2's model shadow and Q-F1's zeros:
                # about the old investigations, measured again) and the read-back's findings
                # (Q-D3's kibana_findings name cases: a foreign key, so truncated with them), and
                # the case writer's steps and looks (Q-D4: kibana_steps names cases, the outbox
                # and approvals; the looks name outbox rows). Its runs and ramp steps name
                # nothing here and are the writer's own history: kept. Q-C2's watch answers and
                # suggestions name cases (and investigations): empty with them, and so are Q-H4's
                # notices (they name cases and investigations by id). Q-D5's write-back rows
                # follow reviews and closures (a closure row names its approval request), and
                # neither exists here: stale, emptied with them. AR2's shared runs and AR2b's
                # raises name assessments and investigations: derived, emptied with them. AR4b's
                # known-infection rows, reminders and notices name cases (and investigations): empty
                # with them (the notices are append-only: the case count above refuses first). AR7's
                # incident reports, their decisions and checks name cases: empty with them too, and
                # so are AR8's case-team posts, steps, approvals and reads.
                # AR6's sign-in sightings and lookups are not derived from grouping (the SSO logs
                # last five days at the SIEM, and they are the only copy): not truncated.
            )
        )
    grouped = 0
    after = ""
    while True:
        async with engine.begin() as conn:
            rows = (
                await conn.execute(
                    text(
                        "SELECT alert_id, normalized FROM alert_records"
                        " WHERE status = 'normalized' AND alert_id > :after"
                        " ORDER BY alert_id LIMIT :n"
                    ),
                    {"after": after, "n": BATCH},
                )
            ).all()
            if not rows:
                break
            alerts = [NormalizedAlert.model_validate(row.normalized) for row in rows]
            await group(conn, alerts, now)
            grouped += len(alerts)
            after = rows[-1].alert_id
    async with engine.connect() as conn:
        investigations = (
            await conn.execute(text("SELECT count(*) FROM investigations"))
        ).scalar_one()
    return grouped, investigations
