"""Fixtures for the case record (Q-C1): investigations to put in cases, people with web
sessions, and ``api_engine``, a login that is a member of ``argus_runtime`` and
``argus_approvals`` (what the web's own login will be, Q-A2)."""

from __future__ import annotations

import json
import secrets
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from psycopg import sql
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from argus.cases import approvals, signing
from argus.cases.identity import LiveCheck
from argus.cases.model import LOCAL_CAPABILITIES, Actor, Capability
from argus.config import DatabaseSettings
from argus.db import roles
from argus.db.engine import create_engine
from argus.web import auth
from tests.integration.conftest import admin_connect

NOW = datetime(2026, 10, 20, 6, 0, tzinfo=UTC)
PASSWORD = "correct horse battery"
APPROVER = frozenset({*LOCAL_CAPABILITIES, Capability.APPROVE.value})
# Q-C3: the web's signing key in tests, and the Kibana privileges an ELK-checked approver holds
TEST_KEY = signing.Key(signing.key_id(b"\x07" * 32), b"\x07" * 32)
SIGNER = signing.Signer(TEST_KEY)
VERIFIER = signing.Verifier([TEST_KEY])
KIBANA = frozenset({"updateCase", "createCase", "createComment"})


@pytest.fixture
async def api_engine(
    make_login: Callable[[], Awaitable[DatabaseSettings]],
    db_settings: DatabaseSettings,
    test_database: str,
    migrated_engine: AsyncEngine,
) -> AsyncIterator[AsyncEngine]:
    login = await make_login()
    with admin_connect(db_settings, test_database) as conn:
        conn.execute(
            sql.SQL("GRANT {} TO {}").format(
                sql.Identifier(roles.APPROVALS_ROLE), sql.Identifier(login.user)
            )
        )
    engine = create_engine(login, database=test_database)
    try:
        yield engine
    finally:
        await engine.dispose()


@dataclass(frozen=True)
class Person:
    user_id: int
    username: str
    session_token: str  # the raw web session token (the cookie); the approval functions hash it

    @property
    def session_hash(self) -> str:
        return auth.token_hash(self.session_token)

    def actor(
        self,
        capabilities: frozenset[str] = LOCAL_CAPABILITIES,
        *,
        kibana: frozenset[str] = frozenset(),
        checked_at: datetime | None = None,
    ) -> Actor:
        return Actor.person(self.user_id, capabilities, via="test", kibana=kibana,
                            kibana_checked_at=checked_at)  # fmt: skip


async def make_person(engine: AsyncEngine, username: str, *, signs_in: bool = True) -> Person:
    """An account with a live session. ``signs_in=False`` starts the session without the
    sign-in check, for a service identity (which cannot sign in, Q-E2) that a test wants a
    session for anyway, to prove the database refuses it."""
    async with engine.begin() as conn:
        user_id = await auth.add_user(conn, username, username.title(), PASSWORD)
        if signs_in:
            result = await auth.login(conn, username, PASSWORD, datetime.now(UTC))
        else:
            result = await auth.start(conn, user_id, datetime.now(UTC))
    assert result is not None
    token, _ = result
    return Person(user_id, username, token)


@pytest.fixture
async def people(app_engine: AsyncEngine) -> dict[str, Person]:
    return {name: await make_person(app_engine, name) for name in ("asha", "ravi", "meera")}


async def investigation(
    owner: AsyncEngine,
    *,
    rule: str = "rule-1",
    actor: Sequence[tuple[str, str]] = (("source.ip", "10.0.0.1"),),
    entities: Sequence[tuple[str, str]] = (),
    severity: str = "high",
    day: int = 0,
    alerts: int = 2,
) -> uuid.UUID:
    """An investigation (rule, actor, IST day) with entities and alerts, written as the owner."""
    inv = uuid.uuid4()
    start = datetime(2026, 10, 10, 18, 30, tzinfo=UTC) + timedelta(days=day)
    key = json.dumps([list(pair) for pair in sorted(actor)], separators=(",", ":"))
    async with owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO investigations (id, grouping_version, rule_id, rule_name, group_key,"
                " bucket_start, bucket_end, previous_id, severity, alert_count, version)"
                " VALUES (:id, '2', :rule, :name, :key, :start, :end, :prev, :sev, :n, 1)"
            ),
            {"id": inv, "rule": rule, "name": f"Rule {rule}", "key": key, "start": start,
             "end": start + timedelta(days=1), "prev": uuid.uuid4(), "sev": severity,
             "n": alerts},
        )  # fmt: skip
        values = {(k.split(".")[-1] if k.endswith(".ip") else "host", v) for k, v in actor}
        values |= set(entities)
        for kind, value in sorted(values):
            await conn.execute(
                text(
                    "INSERT INTO investigation_entities (investigation_id, kind, value)"
                    " VALUES (:i, :k, :v) ON CONFLICT DO NOTHING"
                ),
                {"i": inv, "k": kind, "v": value},
            )
        for n in range(alerts):
            alert_id = f"{inv.hex}-{n}"
            await _alert(conn, alert_id, inv, start + timedelta(minutes=n))
    return inv


async def _alert(conn: AsyncConnection, alert_id: str, inv: uuid.UUID, at: datetime) -> None:
    await conn.execute(
        text(
            "INSERT INTO alert_records (alert_id, index, status, normalizer_version, raw,"
            " content_hash, state_hash, recovered_by, detected_at)"
            " VALUES (:a, 'alerts', 'normalized', 'test', '{}', 'h', 'h', 'live', :at)"
        ),
        {"a": alert_id, "at": at},
    )
    await conn.execute(
        text("INSERT INTO investigation_alerts (alert_id, investigation_id) VALUES (:a, :i)"),
        {"a": alert_id, "i": inv},
    )


async def rows(engine: AsyncEngine, query: str, **params: Any) -> list[Any]:
    async with engine.connect() as conn:
        return list((await conn.execute(text(query), params)).all())


def token() -> str:
    return secrets.token_hex(4)


async def step_up(conn: AsyncConnection, person: Person) -> datetime:
    """The person confirms their password in this session now (what ``/stepup`` records)."""
    stepped: datetime = (
        await conn.execute(
            text(
                "UPDATE user_sessions SET stepped_up_at = clock_timestamp()"
                " WHERE token_hash = :t RETURNING stepped_up_at"
            ),
            {"t": person.session_hash},
        )
    ).scalar_one()
    return stepped


def live_check(
    person: Person,
    at: datetime,
    *,
    capabilities: frozenset[str] = APPROVER,
    kibana: frozenset[str] = KIBANA,
) -> LiveCheck:
    return LiveCheck(person.user_id, "ok", "fake", at, "person", frozenset(capabilities),
                     frozenset(kibana), f"uid-{person.username}",
                     f"{person.username}@example.org")  # fmt: skip


async def asking(conn: AsyncConnection, person: Person, *, anonymous: bool = False) -> LiveCheck:
    """The web's live check of a person asking for an approval (bound to the request, Q-C3
    review F2); ``anonymous``: a local account's, naming no argus_uid or e-mail address."""
    now = (await conn.execute(text("SELECT clock_timestamp()"))).scalar_one()
    check = live_check(person, now)
    return replace(check, argus_uid=None, email=None) if anonymous else check


async def signed_for(
    conn: AsyncConnection,
    person: Person,
    request_id: int,
    decision: str = "approved",
    *,
    capabilities: frozenset[str] = APPROVER,
    kibana: frozenset[str] = KIBANA,
    batch: dict[str, Any] | None = None,
    signer: signing.Signer = SIGNER,
) -> approvals.Signed:
    """What the web adds to a decision (Q-C3), as :class:`argus.cases.desk.ApprovalDesk` makes
    it: a fresh step-up of the person's session, a live check and the signature."""
    stepped = await step_up(conn, person)
    now = (await conn.execute(text("SELECT clock_timestamp()"))).scalar_one()
    snapshot = live_check(person, now, capabilities=capabilities, kibana=kibana).snapshot()
    record = await approvals.record(conn, request_id)
    signature = "hmac-sha256:" + "0" * 16 + ":" + "0" * 64
    if record is not None:
        statement = approvals.statement(record, approver_user_id=person.user_id,
                                        decision=decision, stepped_up_at=stepped,
                                        check=snapshot, batch=batch)  # fmt: skip
        signature = signer.sign(statement)
    return approvals.Signed(stepped, snapshot, signature, batch)
