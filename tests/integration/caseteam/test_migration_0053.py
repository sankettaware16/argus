"""Migration 0053 (AR8): the case team's four tables, who may write which, and the rules the
database keeps whatever the code does (only the lead opens a case or touches alerts, only the
reporter uploads; approvals and the verdicts read are append-only)."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError, ProgrammingError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.db import migrate
from tests.integration.cases.conftest import Person
from tests.integration.caseteam.kit import a_case

pytestmark = pytest.mark.integration
HASH = "a" * 64
INCIDENT = "ACME-IR-2026-1027-01"
NOW = datetime(2026, 10, 27, 9, 0, tzinfo=UTC)


async def case_with_post(owner: AsyncEngine, app: AsyncEngine, person: Person) -> uuid.UUID:
    case = await a_case(owner, app, person)
    async with owner.begin() as conn:
        await conn.execute(
            text("INSERT INTO case_team_posts (case_id, incident_id) VALUES (:c, :i)"),
            {"c": case, "i": INCIDENT},
        )
    return case


def step(case: uuid.UUID, **more: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "c": case,
        "g": 1,
        "n": 1,
        "k": "open",
        "kind": "open",
        "a": "argus-lead",
        "p": "open",
        "t": "text",
        "h": HASH,
        "s": "planned",
    }
    values.update(more)
    return values


INSERT = (
    "INSERT INTO case_team_steps (case_id, gen, seq, key, kind, author, part, report_version,"
    " text_body, request_hash, state) VALUES (:c, :g, :n, :k, :kind, :a, :p, 1, :t, :h, :s)"
)


WRITER_INSERT = INSERT.replace(", state)", ")").replace(", :s)", ")")


async def test_the_database_keeps_who_may_do_what(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case = await case_with_post(migrated_engine, app_engine, people["asha"])
    async with migrated_engine.begin() as conn:
        await conn.execute(text(INSERT), step(case))  # the lead opens
        await conn.execute(
            text(INSERT),
            step(case, n=2, k="comment:x", kind="comment", a="argus-hunter", p="queries"),
        )
        await conn.execute(
            text(INSERT),
            step(case, n=3, k="file:pdf", kind="file", a="argus-reporter", p="files", t=None),
        )
    bad = [
        step(case, n=4, k="o2", a="argus-evidence"),  # only the lead opens a case
        step(case, n=4, k="a1", kind="attach", a="argus-intel", t=None),  # ... or attaches
        step(case, n=4, k="t1", kind="tag", a="argus-responder", t=None),  # ... or tags alerts
        step(case, n=4, k="f2", kind="file", a="argus-lead", t=None),  # only the reporter uploads
        step(case, n=4, k="c2", kind="comment", t=None, a="argus-lead"),  # a comment has text
        step(case, n=4, k="c3", kind="attach", a="argus-lead", t="text"),  # an attach has none
        step(case, n=4, k="c4", a="argus"),  # not one of the six
        step(case, n=4, k="c5", kind="delete"),
        step(case, n=4, k="c6", s="sent-ish"),
        step(case, n=4, k="c7", h="nothex"),
        step(case, n=3, k="dup-seq"),  # the position is taken
        step(case, n=4, k="open"),  # the key is taken in this generation
    ]
    for values in bad:
        with pytest.raises(IntegrityError):
            async with migrated_engine.begin() as conn:
                await conn.execute(text(INSERT), values)
    with pytest.raises(IntegrityError):  # an incident id is the hand-made case's form
        async with migrated_engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO case_team_posts (case_id, incident_id)"
                    " VALUES (gen_random_uuid(), 'x')"
                )
            )


async def test_each_login_holds_exactly_what_it_needs(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    web_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    case = await case_with_post(migrated_engine, app_engine, people["asha"])

    async def denied(engine: AsyncEngine, sql: str, **params: Any) -> None:
        with pytest.raises(ProgrammingError, match="permission denied"):
            async with engine.begin() as conn:
                await conn.execute(text(sql), params)

    # the writer posts: it inserts steps and moves them, it never deletes or changes a text
    async with writer_engine.begin() as conn:
        await conn.execute(text(WRITER_INSERT), step(case))  # a step is born planned: no state
        await conn.execute(text("UPDATE case_team_steps SET state = 'sending', sent_count = 1"))
        await conn.execute(text("UPDATE case_team_posts SET kibana_case_id = 'k1'"))
        assert (await conn.execute(text("SELECT count(*) FROM incident_reports"))).scalar_one() == 1
    await denied(writer_engine, "DELETE FROM case_team_steps")
    await denied(writer_engine, "UPDATE case_team_steps SET text_body = 'edited'")
    await denied(writer_engine, "UPDATE case_team_steps SET author = 'argus-hunter'")
    await denied(writer_engine, "UPDATE case_team_steps SET request_hash = :h", h=HASH)
    await denied(writer_engine, "DELETE FROM case_team_posts")
    await denied(writer_engine, "UPDATE case_team_posts SET incident_id = 'x'")
    await denied(
        writer_engine,
        "INSERT INTO case_team_seen (kibana_comment_id, text_hash, case_id,"
        " author, written_at, status) VALUES ('c', :h, :c, 'a', now(), 'recorded')",
        h=HASH,
        c=case,
    )

    # the runtime reads posts and steps, and records the verdicts it read; it posts nothing
    async with app_engine.begin() as conn:
        assert (await conn.execute(text("SELECT count(*) FROM case_team_steps"))).scalar_one() == 1
        await conn.execute(
            text(
                "INSERT INTO case_team_seen (kibana_comment_id, text_hash, case_id, author,"
                " written_at, status) VALUES ('c1', :h, :c, 'asha.k', now(), 'unmatched')"
            ),
            {"h": HASH, "c": case},
        )
    await denied(
        app_engine,
        INSERT.replace(":c", "'" + str(case) + "'", 1),
        **{k: v for k, v in step(case).items() if k != "c"},
    )
    await denied(app_engine, "UPDATE case_team_posts SET kibana_case_id = 'k2'")
    await denied(app_engine, "UPDATE case_team_seen SET status = 'recorded'")
    await denied(
        app_engine,
        "INSERT INTO case_team_approvals (case_id, gen, plan_hash, report_version,"
        " approver_user_id, statement, signature, expires_at) VALUES (:c, 1, :h, 1, 1,"
        " '{}', 's', now() + interval '1 hour')",
        c=case,
        h=HASH,
    )

    # the web records an approval and reads the rest; it cannot post, change or delete anything
    async with web_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO case_team_approvals (case_id, gen, plan_hash, report_version,"
                " approver_user_id, statement, signature, approved_at, expires_at) VALUES"
                " (:c, 1, :h, 1, :u, CAST(:s AS jsonb), 'sig', :a, :e)"
            ),
            {
                "c": case,
                "h": HASH,
                "u": people["meera"].user_id,
                "s": json.dumps({}),
                "a": NOW,
                "e": NOW + timedelta(hours=30),
            },
        )
        assert (await conn.execute(text("SELECT count(*) FROM case_team_steps"))).scalar_one() == 1
    await denied(web_engine, "UPDATE case_team_approvals SET plan_hash = 'x'")
    await denied(web_engine, "DELETE FROM case_team_approvals")
    await denied(web_engine, "UPDATE case_team_steps SET state = 'verified'")
    await denied(
        web_engine,
        "INSERT INTO case_team_posts (case_id, incident_id) VALUES (gen_random_uuid(), 'x')",
    )


async def test_approvals_and_the_verdicts_read_are_append_only_even_for_the_owner(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case = await case_with_post(migrated_engine, app_engine, people["asha"])
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO case_team_approvals (case_id, gen, plan_hash, report_version,"
                " approver_user_id, statement, signature, approved_at, expires_at) VALUES"
                " (:c, 1, :h, 1, :u, '{}', 'sig', :a, :e)"
            ),
            {
                "c": case,
                "h": HASH,
                "u": people["meera"].user_id,
                "a": NOW,
                "e": NOW + timedelta(hours=30),
            },
        )
        await conn.execute(
            text(
                "INSERT INTO case_team_seen (kibana_comment_id, text_hash, case_id, author,"
                " written_at, status) VALUES ('c1', :h, :c, 'a', now(), 'unmatched')"
            ),
            {"h": HASH, "c": case},
        )
    statements = (
        "UPDATE case_team_approvals SET signature = 'x'",
        "DELETE FROM case_team_approvals",
        "TRUNCATE case_team_approvals",
        "UPDATE case_team_seen SET status = 'recorded'",
        "DELETE FROM case_team_seen",
        "TRUNCATE case_team_seen",
    )
    for sql in statements:
        with pytest.raises(DBAPIError, match=r"append-only|cannot be"):
            async with migrated_engine.begin() as conn:
                await conn.execute(text(sql))
    with pytest.raises(IntegrityError):  # an approval expires after it is given
        async with migrated_engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO case_team_approvals (case_id, gen, plan_hash, report_version,"
                    " approver_user_id, statement, signature, approved_at, expires_at) VALUES"
                    " (:c, 1, :h, 1, :u, '{}', 'sig', :a, :e)"
                ),
                {"c": case, "h": HASH, "u": people["meera"].user_id, "a": NOW, "e": NOW},
            )


async def test_a_downgrade_that_would_lose_a_recorded_verdict_is_refused_a_clean_one_round_trips(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case = await case_with_post(migrated_engine, app_engine, people["asha"])
    head = await migrate.current_revision(migrated_engine)
    assert head == "0065"  # 0060 (the flat hours check) sits on 0059 (the retitled event)
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO case_team_seen (kibana_comment_id, text_hash, case_id, author,"
                " written_at, verdict, status, user_id) VALUES ('c1', :h, :c, 'asha.k', now(),"
                " 'true_positive', 'recorded', :u)"
            ),
            {"h": HASH, "c": case, "u": people["asha"].user_id},
        )
    with pytest.raises(DBAPIError, match="labels were written"):
        await migrate.downgrade(migrated_engine, "0052")
    assert await migrate.current_revision(migrated_engine) == head

    async with migrated_engine.begin() as conn:  # the owner removes the record the one way there is
        await conn.execute(text("ALTER TABLE case_team_seen DISABLE TRIGGER USER"))
        await conn.execute(text("DELETE FROM case_team_seen"))
        await conn.execute(text("ALTER TABLE case_team_seen ENABLE TRIGGER USER"))
    await migrate.downgrade(migrated_engine, "0052")
    assert await migrate.current_revision(migrated_engine) == "0052"
    async with migrated_engine.connect() as conn:
        left = (await conn.execute(text("SELECT to_regclass('case_team_posts')"))).scalar_one()
    assert left is None
    await migrate.upgrade(migrated_engine)
    assert await migrate.current_revision(migrated_engine) == head


async def test_a_downgrade_that_would_lose_the_record_of_what_was_sent_is_refused(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """D-201 point 14: the steps are the only record of what the case team wrote to production."""
    case = await case_with_post(migrated_engine, app_engine, people["asha"])
    async with migrated_engine.begin() as conn:
        await conn.execute(text(INSERT), step(case))
        await conn.execute(text("UPDATE case_team_steps SET state = 'verified', sent_count = 1"))
    with pytest.raises(DBAPIError, match="requests to Kibana"):
        await migrate.downgrade(migrated_engine, "0052")
    assert await migrate.current_revision(migrated_engine) == "0065"
    async with migrated_engine.begin() as conn:
        left = (await conn.execute(text("SELECT count(*) FROM case_team_steps"))).scalar_one()
    assert left == 1  # nothing was dropped

    async with migrated_engine.begin() as conn:  # steps nothing was sent for do not stop it
        await conn.execute(text("UPDATE case_team_steps SET state = 'planned', sent_count = 0"))
    await migrate.downgrade(migrated_engine, "0052")
    assert await migrate.current_revision(migrated_engine) == "0052"
