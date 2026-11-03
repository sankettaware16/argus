"""An investigation with sign-in sightings, and everything a model could be given about it (AR6,
D-216): the stored dossier the investigator and the decision engine read, the privacy layer's
request built from it, and the incident report's guarded prose input hold no account name."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.incident import prose, run
from argus.llm.privacy import Privacy, load_policy
from argus.signins import model as m
from argus.signins import store
from tests.integration.cases.conftest import Person
from tests.integration.cases.knownkit import open_case
from tests.integration.signins import kit as k
from tests.unit.llm.conftest import ASSETS, CAMPUS_PREFIX
from tests.unit.signins import kit

pytestmark = pytest.mark.integration
NAME = "user-ar6-gamma"
D28 = kit.DAY


async def seed(app: AsyncEngine, address: str) -> None:
    looks = [m.Lookup(address, D28, datetime(2026, 10, 30, tzinfo=UTC), True, 1, 0)]
    seen = [kit.sighting(NAME, address=address, hours=tuple(range(24)), events=48)]
    async with app.begin() as conn:
        await store.save(conn, looks, seen)


async def test_the_dossier_and_the_request_a_model_reads_hold_no_account(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    invs = await k.world(migrated_engine)
    await seed(app_engine, k.HOST_A)
    async with migrated_engine.connect() as conn:
        bodies = [
            r.body
            for r in await conn.execute(
                text("SELECT body FROM dossiers WHERE investigation_id = :i"), {"i": invs["a"]}
            )
        ]
        stored_names = (await conn.execute(text("SELECT user_name FROM signin_sightings"))).all()
    assert bodies
    assert [r[0] for r in stored_names] == [NAME]
    privacy = Privacy.build(load_policy(), ASSETS, (CAMPUS_PREFIX,))
    for body in bodies:
        assert NAME not in json.dumps(body)
        request = privacy.request([body])
        assert NAME not in request.text


async def test_the_reports_prose_input_for_a_case_with_accounts_holds_none(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    from argus.assets.classify import IpClassifier

    invs = await k.world(migrated_engine)
    case = await open_case(app_engine, people["asha"], [invs["a"]], host=k.HOST_A, servers=())
    await seed(app_engine, k.HOST_A)
    now = datetime(2026, 10, 30, 6, 0, tzinfo=UTC)
    ctx = run.context_for(k.settings(), now, IpClassifier(None, ()))
    made = await run.make(app_engine, case, ctx)
    assert made is not None
    report = made.report
    assert NAME in report.model_dump_json()  # the report has it, for people who may read it
    shown = prose.shown(report)
    request = prose.request_text(shown)
    assert NAME not in request
    assert k.HOST_A not in request
    assert all(NAME not in f.text for f in shown.facts.values())
