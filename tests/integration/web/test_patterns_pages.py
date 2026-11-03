"""AR2 and AR2b on the pages: an investigation that shares its pattern's investigator run says
"same pattern as <id>" with a link (classic page and ``/api/v1``), never offers to accept it and
shows nothing for the one the run was made on; an investigation ARGUS raised from its evidence is
in Needs attention with the reason, on the Inbox and its own page."""

from __future__ import annotations

import html
import json
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.assess import patterns, raised, runner
from argus.assess.runner import Verdict
from argus.llm.privacy import Privacy, load_policy
from argus.web import queries
from tests.integration.web.conftest import NOW, PASSWORD
from tests.integration.web.test_gold import with_dossiers
from tests.unit.llm.conftest import ASSETS, CAMPUS_PREFIX

pytestmark = pytest.mark.integration
AGENT = "agent@1"
BEACON = {"name": "proxy.regularity", "status": "known", "value": 0.0}
LISTED = {"name": "ti.listed", "status": "known", "value": 1}


@pytest.fixture(scope="module")
def layer() -> Privacy:
    return Privacy.build(load_policy(), ASSETS, (CAMPUS_PREFIX,))


class Fake:
    name = AGENT

    async def assess(self, conn: Any, investigation_id: uuid.UUID, body: Any) -> Verdict:
        return Verdict("true_positive", "agent@1#fake", ["It beacons every 300 s."], 0.75)


async def sign_in(client: httpx.AsyncClient) -> None:
    await client.post("/login", data={"username": "asha", "password": PASSWORD})


def flat(page: str) -> str:
    return " ".join(html.unescape(page).split())


async def pair(seeded: AsyncEngine, migrated: AsyncEngine, layer: Privacy) -> tuple[Any, Any]:
    """Run the pattern picker over the seeded investigations and finish its runs; returns the
    investigation a run was made on and another one of its pattern."""
    await with_dossiers(seeded, migrated, 24)
    async with seeded.begin() as conn:
        await patterns.schedule(conn, layer, AGENT, NOW, limit=50, per_day=None)
    done = await runner.run_once(seeded, Fake(), "w", lambda: NOW, 50)
    assert done["proposed"] >= 1
    found = await seeded.connect()
    try:
        shared = (await found.execute(text(
            "SELECT s.assessment_id, a.investigation_id AS rep, s.investigation_id AS member"
            " FROM assessment_shares s JOIN assessments a ON a.id = s.assessment_id"
            " WHERE s.investigation_id <> a.investigation_id ORDER BY s.assessment_id LIMIT 1"
        ))).first()  # fmt: skip
    finally:
        await found.close()
    assert shared is not None
    return shared.rep, shared.member


async def test_the_classic_page_and_the_api_show_the_run_on_the_pattern_s_other_members(
    client: httpx.AsyncClient, seeded: AsyncEngine, migrated_engine: AsyncEngine, layer: Privacy
) -> None:
    rep, member = await pair(seeded, migrated_engine, layer)
    await sign_in(client)

    page = (await client.get(f"/investigations/{member}")).text
    words = flat(page)
    assert f'Same pattern as <a class="mono" href="/investigations/{rep}">{rep}</a>' in words
    assert "the AI investigator proposed <strong>True positive</strong>" in words
    assert "(confidence 75%)" in words
    assert "It beacons every 300 s." in words
    assert "It is not a proposal for this investigation and cannot be accepted here" in words
    assert "Not assessed yet" not in words
    assert 'name="assessment_id"' not in page  # nothing to accept

    shown = (await client.get(f"/api/v1/investigations/{member}")).json()
    assert shown["assessments"] == []
    assert shown["acceptable_assessment_id"] is None
    same = shown["same_pattern"]
    assert (same["investigation_id"], same["earlier"]) == (str(rep), False)
    assert same["assessment"]["status"] == "proposed"
    assert same["assessment"]["outcome"] == "true_positive"
    assert same["assessment"]["confidence"] == 0.75

    own = (await client.get(f"/api/v1/investigations/{rep}")).json()
    assert own["same_pattern"] is None  # its own assessment is its own
    assert [a["status"] for a in own["assessments"]] == ["proposed"]
    assert own["acceptable_assessment_id"] is not None
    assert "Same pattern as" not in (await client.get(f"/investigations/{rep}")).text


async def test_nothing_is_a_proposal_for_the_members_of_the_pattern(
    client: httpx.AsyncClient, seeded: AsyncEngine, migrated_engine: AsyncEngine, layer: Privacy
) -> None:
    rep, member = await pair(seeded, migrated_engine, layer)
    await sign_in(client)
    async with seeded.connect() as conn:
        proposals = (await conn.execute(text(
            "SELECT investigation_id FROM assessments WHERE assessor = :a AND status = 'proposed'"
        ), {"a": AGENT})).scalars().all()  # fmt: skip
        run = (await conn.execute(text(
            "SELECT id FROM assessments WHERE investigation_id = :i AND assessor = :a"),
            {"i": rep, "a": AGENT})).scalar_one()  # fmt: skip
    assert member not in proposals  # a proposal is the assessed investigation's alone
    page = (await client.get(f"/investigations/{member}")).text
    token = page.split('name="csrf_token" value="')[1].split('"')[0]
    # whatever the form says, what it accepts is the run's own: the assessed investigation's review
    accept = await client.post(f"/investigations/{member}/accept",
                               data={"assessment_id": run, "csrf_token": token})  # fmt: skip
    assert accept.status_code == 303
    async with seeded.connect() as conn:
        reviews = dict((await conn.execute(text(
            "SELECT investigation_id, count(*) FROM review_events GROUP BY 1"))).all())  # fmt: skip
    assert reviews == {rep: 1}  # the member is still unreviewed
    shown = (await client.get(f"/api/v1/investigations/{member}")).json()
    assert shown["investigation"]["human_state"] == "unreviewed"


async def test_a_raised_investigation_is_in_needs_attention_with_the_reason(
    client: httpx.AsyncClient, seeded: AsyncEngine, migrated_engine: AsyncEngine, layer: Privacy
) -> None:
    async with seeded.connect() as conn:
        mild = next(s for s in await queries.inbox(conn, "all", limit=100)
                    if s.severity not in ("critical", "high"))  # fmt: skip
        before = {s.id for s in await queries.inbox(conn, "attention", limit=100)}
    assert mild.id not in before
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO dossiers (investigation_id, version, pack, facts_version, job_id,"
                " run_kind, family, status, dossier_hash, body, evidence_count, created_at)"
                " VALUES (:i, :v, 'generic@12', :v, 1, 'collect', 'proxy', 'evidence_ready',"
                " :h, CAST(:b AS jsonb), 0, :t)"
            ),
            {
                "i": mild.id,
                "v": mild.version,
                "h": "c" * 64,
                "t": datetime.now(UTC),
                "b": json.dumps({"local_signals": [BEACON, LISTED], "signals": []}),
            },
        )
    async with seeded.begin() as conn:
        counts = await raised.evaluate(conn, mild.last_event_at)
    assert counts["raised"] == 1
    await sign_in(client)

    inbox = (await client.get("/?view=attention")).text
    assert f"/investigations/{mild.id}" in inbox
    assert "ARGUS raised from its own evidence" in flat(inbox)
    page = flat((await client.get(f"/investigations/{mild.id}")).text)
    assert "ARGUS raised it: on a threat list; regular traffic, like a beacon." in page
    api = (await client.get("/api/v1/investigations", params={"view": "attention"})).json()
    row = next(i for i in api["items"] if i["id"] == str(mild.id))
    assert row["reasons"] == ["ARGUS raised it: on a threat list; regular traffic, like a beacon."]
    counted = (await client.get("/api/v1/counts")).json()
    assert counted["attention"] == len(before) + 1
