"""Inbox tests written for mutation survivors (D-040): sessions, passwords, names."""

from __future__ import annotations

import dataclasses
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.web import auth
from tests.integration.web.conftest import NOW, PASSWORD

pytestmark = pytest.mark.integration


def test_names_and_passwords() -> None:
    assert auth.shown_name("asha") == "asha"
    assert auth.shown_name("as ha") == "(not a valid name)"
    for good in ("x" * 10, "x" * 256):
        assert auth.hash_password(good).startswith("$argon2id$")
    for bad in ("x" * 9, "x" * 257):
        with pytest.raises(ValueError, match=r"^a password has 10 to 256 characters$"):
            auth.hash_password(bad)
    assert timedelta(minutes=1) == auth.SEEN_EVERY


async def test_sessions_tokens_and_idle_edges(
    seeded: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = 0
    real = auth.HASHER

    class Counting:
        def verify(self, hashed: str, password: str) -> bool:
            nonlocal calls
            calls += 1
            return real.verify(hashed, password)

        def hash(self, password: str) -> str:
            return real.hash(password)

    monkeypatch.setattr(auth, "HASHER", Counting())
    async with seeded.begin() as conn:
        assert await auth.login(conn, "nobody", PASSWORD, NOW) is None  # valid form, unknown
        assert await auth.login(conn, "bad name", PASSWORD, NOW) is None  # impossible form
        assert calls == 2  # the same hashing work either way
        made = await auth.login(conn, "asha", PASSWORD, NOW, absolute=timedelta(days=2))
        assert made is not None
        token, reviewer = made
        assert len(token) == len(reviewer.csrf_token) == 43  # 32 random bytes each
        with pytest.raises(dataclasses.FrozenInstanceError):
            reviewer.user_id = 0  # type: ignore[misc]
        idle = timedelta(hours=12)
        assert await auth.session(conn, token, NOW + idle, idle) is not None  # exactly idle
        seen = (await conn.execute(text("SELECT last_seen_at FROM user_sessions"))).scalar_one()
        assert seen == NOW + idle  # kept alive
        assert await auth.session(conn, token, NOW + idle + timedelta(seconds=59), idle)
        same = (await conn.execute(text("SELECT last_seen_at FROM user_sessions"))).scalar_one()
        assert same == NOW + idle  # written at most once a minute
        assert await auth.session(conn, token, NOW + idle + timedelta(minutes=1), idle)
        moved = (await conn.execute(text("SELECT last_seen_at FROM user_sessions"))).scalar_one()
        assert moved == NOW + idle + timedelta(minutes=1)
        await auth.logout(conn, token, NOW + idle)
        assert await auth.session(conn, token, NOW + idle, idle) is None  # the token is dead
        user_id = await auth.add_user(conn, "mira", "Mira", PASSWORD)
        assert user_id > 0


async def test_views_filter_by_state_rule_and_entity(seeded: AsyncEngine) -> None:
    from argus.web import queries
    from argus.web.reviews import add_review

    async with seeded.begin() as conn:
        everything = await queries.inbox(conn, "all")
        made = await auth.login(conn, "asha", PASSWORD, NOW)
        assert made is not None
        reviewer = made[1]
        high = [s for s in everything if s.severity == "high"]
        plain = [s for s in everything if s.severity != "high"]
        assert high
        assert plain
        attention = {s.id for s in await queries.inbox(conn, "attention")}
        assert attention == {s.id for s in high}  # unreviewed high, nothing else
        follow = plain[0]
        await add_review(conn, reviewer, follow.id, action="follow_up", outcome=None,
                         note=None, seen_review=None, seen_version=follow.version)  # fmt: skip
        done = high[0]
        with pytest.raises(ValueError, match=r"^choose an outcome to mark it reviewed$"):
            await add_review(conn, reviewer, done.id, action="reviewed", outcome=None,
                             note=None, seen_review=None, seen_version=done.version)  # fmt: skip
        await add_review(conn, reviewer, done.id, action="reviewed", outcome="benign_policy",
                         note=None, seen_review=None, seen_version=done.version)  # fmt: skip
        attention = {s.id for s in await queries.inbox(conn, "attention")}
        assert attention == {s.id for s in high[1:]} | {follow.id}
        first = await queries.inbox(conn, "attention")
        assert first[0].id == follow.id  # follow-ups first
        open_ids = {s.id for s in await queries.inbox(conn, "open")}
        assert open_ids == {s.id for s in everything} - {done.id}
        assert len(await queries.inbox(conn, "all", limit=2)) == 2
        ordered = await queries.inbox(conn, "all")
        shifted = await queries.inbox(conn, "all", offset=1)
        assert shifted[0].id == ordered[1].id
        ruled = await queries.inbox(conn, "all", rule="rule-1")
        assert ruled
        assert {s.rule_id for s in ruled} == {"rule-1"}
        by_ip = await queries.inbox(conn, "all", entity=("ip", "10.0.0.1"))
        assert by_ip
        assert all(
            any(f == "source.ip" and v == "10.0.0.1" for f, v in s.key_fields) for s in by_ip
        )


async def test_health_summary(seeded: AsyncEngine) -> None:
    from argus.web import queries

    async with seeded.connect() as conn:
        h = await queries.health(conn, NOW)
    assert h == {
        "siem_state": "degraded", "siem_reasons": ["never_probed"], "siem_probed_at": None,
        "live_cursor": None, "backfill_cursor": None, "open_gaps": [],
        "last_reconciliation": None, "alerts": 24, "quarantined": 0,
        "investigations": h["investigations"], "jobs_waiting": h["investigations"],
        "jobs_deferred": 0, "jobs_failed": 0, "dossiers": 0, "checkpoint_threads": 0,
        "checkpoint_bytes": h["checkpoint_bytes"],
        "kibana_sync": {"state": "none", "last_cycle_at": None, "last_outcome": None,
                        "last_reason": None, "last_complete_at": None},
    }  # fmt: skip
    assert h["checkpoint_bytes"] > 0  # the empty tables and their indexes
    assert h["investigations"] > 0


async def test_review_errors_and_audit(seeded: AsyncEngine) -> None:
    import uuid

    from argus.web import queries
    from argus.web.reviews import NotFoundError, add_review

    async with seeded.begin() as conn:
        made = await auth.login(conn, "asha", PASSWORD, NOW)
        assert made is not None
        reviewer = made[1]
        inv = (await queries.inbox(conn, "all"))[0]

        async def review(investigation: uuid.UUID, action: str, note: str | None) -> Any:
            return await add_review(
                conn, reviewer, investigation, action=action,  # type: ignore[arg-type]
                outcome="benign_expected" if action == "reviewed" else None, note=note,
                seen_review=None, seen_version=inv.version,
            )  # fmt: skip

        with pytest.raises(NotFoundError):
            await review(uuid.uuid4(), "reviewed", None)
        with pytest.raises(ValueError, match=r"^a note needs text$"):
            await review(inv.id, "note", "")
        with pytest.raises(ValueError, match=r"^a note has at most 4000 characters$"):
            await review(inv.id, "note", "x" * 4001)
        done = await review(inv.id, "note", "x" * 4000)
        row = (await conn.execute(text(
            "SELECT actor, action, target_type, target_id, details FROM audit_events"
            " WHERE action LIKE 'review.%'"))).one()  # fmt: skip
    details = {"review_id": done.review_id, "version": inv.version, "outcome": None}
    assert row == ("user:asha", "review.note", "investigation", str(inv.id), details)
