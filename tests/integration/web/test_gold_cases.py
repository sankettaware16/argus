"""The privacy comparison reads the gold set (P2/P5): each item of the named set once, with its
stored dossier and the person's newest answer."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.evaluation import comparison, store
from argus.web import auth
from tests.integration.web.conftest import NOW, PASSWORD
from tests.integration.web.test_gold import with_dossiers

pytestmark = pytest.mark.integration


async def test_the_gold_cases_hold_the_newest_answer(
    seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    records = await with_dossiers(seeded, migrated_engine, 3)
    first, second = (uuid.UUID(r["investigation_id"]) for r in records[:2])
    async with seeded.begin() as conn:
        await store.import_set(conn, records)
        made = await auth.login(conn, "asha", PASSWORD, NOW)
        assert made is not None
        user = made[1].user_id
        await store.answer(conn, first, user, "true_positive")
        await store.answer(conn, first, user, "benign_policy")
        await store.answer(conn, second, user, "rule_false_positive")
    async with seeded.connect() as conn:
        cases = await comparison.gold_cases(conn)
        assert await comparison.gold_cases(conn, "other") == []
    assert sorted((c.investigation_id, c.label) for c in cases) == sorted(
        [(first, "benign_policy"), (second, "rule_false_positive")]
    )
    assert all(c.body == {} for c in cases)
