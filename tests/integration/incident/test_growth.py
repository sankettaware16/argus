"""An ongoing case must not create a new report version every 30 minutes for alert-count changes
alone (AR7, D-190, D-205). The signal that decides whether a case's report is read again uses
buckets (the log base 2 of the alert count, the IST day of the last event) plus what changes the
report in kind: a new device, indicator, flag, threat-list hit, role or proposal. This measures
a case that is active all day (alerts every 30 minutes) and shows what the old signal did."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.incident import gather
from argus.incident.run import key_of
from tests.integration.cases.conftest import Person
from tests.integration.cases.knownkit import SERVERS
from tests.integration.incident import kit

pytestmark = pytest.mark.integration
# 5:30 PM IST, after the last of the kit's own events (dated from the clock at import: a fixed
# date fell behind them and the day of the last event stopped moving); midnight IST is 18:30 UTC
BASE = kit.day(5, 12)
EVERY = timedelta(minutes=30)


async def signal(app: AsyncEngine, case: uuid.UUID) -> str:
    async with app.connect() as conn:
        found = await gather.signals(conn, [case])
    return found[case].text


async def an_alert_arrives(owner: AsyncEngine, inv: uuid.UUID, at: datetime, n: int = 3) -> None:
    """n more alerts on the investigation, the last at ``at`` (its version moves too)."""
    async with owner.begin() as conn:
        await conn.execute(
            text(
                "UPDATE investigations SET alert_count = alert_count + :n, last_event_at = :t,"
                " updated_at = :t, version = version + 1 WHERE id = :i"
            ),
            {"n": n, "t": at, "i": inv},
        )


async def old_growth(owner: AsyncEngine, case: uuid.UUID) -> tuple[object, ...]:
    """The parts of the first version's signal that grow with every alert."""
    async with owner.connect() as conn:
        row = (
            await conn.execute(
                text(
                    "SELECT coalesce(sum(i.version), 0), coalesce(sum(i.alert_count), 0),"
                    " max(i.last_event_at), max(i.updated_at) FROM case_members m JOIN"
                    " investigations i ON i.id = m.investigation_id WHERE m.case_id = :c"
                ),
                {"c": case},
            )
        ).one()
    return tuple(row)


async def test_a_case_that_is_active_all_day_changes_its_signal_a_few_times_not_forty_eight(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case, invs = await kit.amadey(migrated_engine, app_engine, people["asha"])
    await an_alert_arrives(migrated_engine, invs[-1], BASE)  # already active today
    seen = [await signal(app_engine, case)]
    old = [await old_growth(migrated_engine, case)]
    alerts = [35 + 3]
    for step in range(1, 49):  # 24 hours of alerts, every 30 minutes
        await an_alert_arrives(migrated_engine, invs[-1], BASE + step * EVERY)
        seen.append(await signal(app_engine, case))
        old.append(await old_growth(migrated_engine, case))
        alerts.append(alerts[-1] + 3)

    changes = [n for n in range(1, len(seen)) if seen[n] != seen[n - 1]]
    old_changes = [n for n in range(1, len(old)) if old[n] != old[n - 1]]
    assert len(old_changes) == 48  # the first signal: a new version to write every 30 minutes
    # the buckets: 38 alerts grow to 182 (2 doublings: 64 at the 9th event, 128 at the 30th),
    # and the IST day of the last event turns at 18:30 UTC, the 13th event
    assert alerts[9] >= 64 > alerts[8]
    assert alerts[30] >= 128 > alerts[29]
    assert changes == [9, 13, 30]
    assert len(changes) <= 3 + 1  # versions a day for an active case: its doublings and its day


async def test_a_case_that_grows_slowly_changes_its_signal_only_when_a_day_turns(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case, invs = await kit.amadey(migrated_engine, app_engine, people["asha"])
    await an_alert_arrives(migrated_engine, invs[-1], BASE, 10)
    before = await signal(app_engine, case)  # 45 alerts
    for step in range(1, 12):
        await an_alert_arrives(migrated_engine, invs[-1], BASE + step * EVERY, 1)
    assert await signal(app_engine, case) == before  # 56 alerts: the same bucket, the same day
    await an_alert_arrives(migrated_engine, invs[-1], BASE + 13 * EVERY, 1)
    assert await signal(app_engine, case) != before  # midnight IST has passed


async def test_a_new_device_indicator_flag_listed_hit_role_or_proposal_is_a_change(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case, invs = await kit.amadey(migrated_engine, app_engine, people["asha"])
    await an_alert_arrives(migrated_engine, invs[-1], BASE)
    keys = [await signal(app_engine, case)]

    async def changes(sql: str, **params: object) -> bool:
        async with migrated_engine.begin() as conn:
            await conn.execute(text(sql), params)
        keys.append(await signal(app_engine, case))
        return keys[-1] != keys[-2]

    assert await changes(  # a new campus device
        "INSERT INTO case_indicators (case_id, kind, value, role, source, added_version,"
        " added_by) VALUES (:c, 'ip', '10.55.9.9', 'actor', 'investigation', 1, 'argus')",
        c=case,
    )
    assert await changes(  # a new server
        "INSERT INTO case_indicators (case_id, kind, value, role, source, added_version,"
        " added_by) VALUES (:c, 'ip', '203.0.113.99', 'c2', 'threat_intel', 1, 'argus')",
        c=case,
    )
    assert await changes(  # the same indicator in another role
        "UPDATE case_indicators SET role = 'indicator'"
        " WHERE case_id = :c AND value = '203.0.113.99'",
        c=case,
    )
    assert await changes(  # a flag ARGUS's evidence raised
        "UPDATE investigation_raises SET flags = flags || '\"success after the attack\"'::jsonb"
        " WHERE investigation_id = :i",
        i=invs[0],
    )
    assert await changes(  # a threat-list hit on the dossier
        "UPDATE dossiers SET body = jsonb_set(body, '{context,pack,ti,listed}',"
        " '[\"77.221.155.150\"]') WHERE investigation_id = :i",
        i=invs[1],
    )
    assert await changes(  # a proposal that says something else
        "UPDATE assessments SET outcome = 'benign_expected' WHERE investigation_id = :i", i=invs[2]
    )
    assert await changes(  # an indicator taken off the case
        "UPDATE case_indicators SET removed_at = now(), removed_version = 2"
        " WHERE case_id = :c AND value = '10.55.9.9'",
        c=case,
    )


async def test_what_comes_with_the_alerts_is_not_a_change_until_it_doubles(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case, invs = await kit.amadey(migrated_engine, app_engine, people["asha"])
    await an_alert_arrives(migrated_engine, invs[-1], BASE)
    first = await signal(app_engine, case)
    await kit.pair_evidence(migrated_engine, invs[0], SERVERS[0], 77, BASE)  # a 6th check
    assert await signal(app_engine, case) == first  # five checks are bucket 2, six too
    await kit.pair_evidence(migrated_engine, invs[1], SERVERS[1], 5, BASE)
    await kit.pair_evidence(migrated_engine, invs[2], SERVERS[2], 5, BASE)
    assert await signal(app_engine, case) != first  # eight: the bucket 3
    async with migrated_engine.begin() as conn:  # another proposal of the same outcome and
        await conn.execute(  # confidence (to a tenth) says nothing new
            text("UPDATE assessments SET confidence = 0.83 WHERE investigation_id = :i"),
            {"i": invs[0]},
        )
    again = await signal(app_engine, case)
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("UPDATE assessments SET confidence = 0.81 WHERE investigation_id = :i"),
            {"i": invs[0]},
        )
    assert await signal(app_engine, case) == again


async def test_the_check_key_still_turns_with_the_standing_and_the_writer(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case, _ = await kit.amadey(migrated_engine, app_engine, people["asha"])
    async with app_engine.connect() as conn:
        found = (await gather.signals(conn, [case]))[case]
    ctx = kit.context()
    quiet = kit.context(now=ctx.as_at + timedelta(days=20))
    assert key_of(found, ctx) != key_of(found, quiet)  # time makes it quiet, nothing else moved
