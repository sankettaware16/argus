"""Rebuild every investigation from the stored alerts (after a grouping change). Run by the
operator as the schema owner: it empties the derived tables, which ARGUS itself may never do.
Refused while reviews, the gold set or cases exist, because they belong to the old
investigations."""

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
        if gold:  # the answer key belongs to the current investigations too
            raise ReviewsExistError(f"{gold} gold-set items refer to the current investigations")
        cases = (
            await conn.execute(
                text("SELECT (SELECT count(*) FROM cases) + (SELECT count(*) FROM case_openings)")
            )
        ).scalar_one()
        if cases:  # cases and the opener's decisions name the current investigations
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
                # Append-only tables (review events, the gold set, the cases) are empty here:
                # their guards refuse a TRUNCATE that would lose a row. Everything else listed is
                # derived from the investigations or names cases/investigations by foreign key,
                # so it is emptied with them. Not listed: the case writer's runs and ramp steps
                # (its own history) and the sign-in sightings (not derived from grouping, and
                # the only copy).
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
