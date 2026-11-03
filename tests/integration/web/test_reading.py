"""AR1: an investigation whose AI run proposed nothing but left a reading shows it, on the classic
page and in the ``/api/v1`` view; one without a reading shows nothing new; a reading is never a
proposal (it cannot be accepted and is not in the proposals). The runs are the real agent's, with
a fake model, stored the way the worker stores a no-decision run."""

from __future__ import annotations

import html
from typing import Any

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.assess import queue
from argus.assess.runner import Verdict
from argus.llm.privacy import Privacy, load_policy
from argus.web import queries
from tests.integration.web.conftest import NOW, PASSWORD
from tests.integration.web.test_gold import with_dossiers
from tests.unit.agent.test_agent import INV, Model, agent, body, say
from tests.unit.agent.test_reading import low
from tests.unit.llm.conftest import ASSETS, CAMPUS_PREFIX

pytestmark = pytest.mark.integration
H = "a" * 64
EVIL = "<script>window.__pwned=1</script>"


@pytest.fixture(scope="module")
def layer() -> Privacy:
    return Privacy.build(load_policy(), ASSETS, (CAMPUS_PREFIX,))


async def verdict(layer: Privacy, reply: str, item: dict[str, Any] | None = None) -> Verdict:
    return await agent(layer, Model(reply)).run(INV, item or body(), False, False)


async def store(engine: AsyncEngine, inv: Any, got: Verdict, seq: int = 0) -> None:
    """The worker's way of finishing a run that proposed nothing."""
    assert got.outcome is None
    async with engine.begin() as conn:
        await queue.enqueue(conn, inv.id, inv.version, "generic@12", H, f"{seq:064x}", "agent@1",
                            NOW)  # fmt: skip
        (job,) = await queue.claim(conn, "w", NOW, "agent@1")
        await queue.no_decision(conn, job, NOW, got.decided_by, list(got.reasons))


async def first(engine: AsyncEngine, owner: AsyncEngine, n: int = 2) -> Any:
    await with_dossiers(engine, owner, n)
    async with engine.connect() as conn:
        return (await queries.inbox(conn, "all"))[:n]


def flat(page: str) -> str:
    return " ".join(html.unescape(page).split())


async def sign_in(client: httpx.AsyncClient) -> None:
    await client.post("/login", data={"username": "asha", "password": PASSWORD})


KINDS = [
    ("undecided", say(outcome="inconclusive", confidence=0.4, reason=EVIL), None,
     "ARGUS's reading: inconclusive (40%) — not proposed because the evidence did not settle it"),
    ("citation", say(cites=["severity high", "made up"]), None,
     "ARGUS's reading: a true positive (70%) — not proposed because it quoted something that is"
     " not in the evidence"),
    ("benign_citation", say(outcome="benign_expected", cites=["Proxy: beacon from"]), "low",
     "ARGUS's reading: benign, expected activity (70%) — not proposed because its reasons for"
     " calling this harmless came only from quoted log or alert text, not from anything ARGUS"
     " itself found"),
    ("floor", say(outcome="benign_expected"), None,
     "ARGUS's reading: benign, expected activity (70%) — not proposed because a safety check"
     " needs a person: threat lists were not checked; the severity is high"),
]  # fmt: skip


@pytest.mark.parametrize(("kind", "reply", "item", "headline"), KINDS)
async def test_the_classic_page_and_the_api_show_each_kind_of_reading(
    client: httpx.AsyncClient, seeded: AsyncEngine, migrated_engine: AsyncEngine,
    layer: Privacy, kind: str, reply: str, item: str | None, headline: str,
) -> None:  # fmt: skip
    inv, other = await first(seeded, migrated_engine)
    got = await verdict(layer, reply, low() if item == "low" else None)
    await store(seeded, inv, got)
    await sign_in(client)

    page = (await client.get(f"/investigations/{inv.id}")).text
    assert headline in flat(page)
    assert EVIL not in page  # the model's words stay text
    assert "This is ARGUS's reading, not a proposal" in flat(page)
    assert "Facts it relied on" in page
    assert "Why no proposal" not in page  # the plain words replace the raw refusal
    assert "assessment_id" not in page  # nothing to accept

    shown = (await client.get(f"/api/v1/investigations/{inv.id}")).json()
    (a,) = shown["assessments"]
    assert (a["status"], a["outcome"], a["confidence"]) == ("no_decision", None, None)
    assert a["reading"]["kind"] == kind
    assert a["reading"]["headline"] == headline
    assert shown["acceptable_assessment_id"] is None

    quiet = (await client.get(f"/api/v1/investigations/{other.id}")).json()
    assert quiet["assessments"] == []  # another investigation shows nothing
    assert "ARGUS's reading" not in (await client.get(f"/investigations/{other.id}")).text


async def test_the_facts_are_marked_checked_or_not(
    client: httpx.AsyncClient, seeded: AsyncEngine, migrated_engine: AsyncEngine, layer: Privacy
) -> None:
    inv, _ = await first(seeded, migrated_engine)
    await store(seeded, inv, await verdict(layer, say(cites=["severity high", "made up"])))
    await sign_in(client)
    reading = (await client.get(f"/api/v1/investigations/{inv.id}")).json()["assessments"][0][
        "reading"]  # fmt: skip
    assert reading["facts"] == [{"text": "severity high", "checked": True},
                                {"text": "made up", "checked": False}]  # fmt: skip
    assert reading["reason"] == "r"
    page = flat((await client.get(f"/investigations/{inv.id}")).text)
    assert '<q>severity high</q> <span class="badge badge-answered">checked, found' in page
    assert '<q>made up</q> <span class="badge">not found in the evidence' in page
    brief = page.split('id="assessment"')[0]
    assert "ARGUS's reading: a true positive (70%)" in brief  # the overview's card too


async def test_a_run_without_a_reading_shows_nothing_new(
    client: httpx.AsyncClient, seeded: AsyncEngine, migrated_engine: AsyncEngine, layer: Privacy
) -> None:
    inv, _ = await first(seeded, migrated_engine)
    await store(seeded, inv, await verdict(layer, "not json at all"))  # no usable answer
    await sign_in(client)
    page = (await client.get(f"/investigations/{inv.id}")).text
    assert "no usable answer from the model" in page
    assert "ARGUS's reading" not in flat(page)
    (a,) = (await client.get(f"/api/v1/investigations/{inv.id}")).json()["assessments"]
    assert (a["status"], a["reading"]) == ("no_decision", None)


async def test_a_proposal_is_shown_as_before(
    client: httpx.AsyncClient, seeded: AsyncEngine, migrated_engine: AsyncEngine, layer: Privacy
) -> None:
    inv, _ = await first(seeded, migrated_engine)
    got = await verdict(layer, say())
    assert got.outcome == "true_positive"
    async with seeded.begin() as conn:
        await queue.enqueue(conn, inv.id, inv.version, "generic@12", H, "b" * 64, "agent@1", NOW)
        (job,) = await queue.claim(conn, "w", NOW, "agent@1")
        await queue.propose(conn, job, NOW, got.outcome, got.decided_by, list(got.reasons),
                            got.confidence)  # fmt: skip
    await sign_in(client)
    page = (await client.get(f"/investigations/{inv.id}")).text
    assert "proposes <strong>True positive</strong>" in " ".join(page.split())
    assert "ARGUS's reading" not in flat(page)
    (a,) = (await client.get(f"/api/v1/investigations/{inv.id}")).json()["assessments"]
    assert (a["status"], a["outcome"], a["reading"]) == ("proposed", "true_positive", None)


async def test_a_reading_is_never_a_proposal(
    client: httpx.AsyncClient, seeded: AsyncEngine, migrated_engine: AsyncEngine, layer: Privacy
) -> None:
    inv, _ = await first(seeded, migrated_engine)
    for n, (_, reply, item, _) in enumerate(KINDS):
        got = await verdict(layer, reply, low() if item == "low" else None)
        await store(seeded, inv, got, n)
    async with seeded.connect() as conn:
        rows = (await conn.execute(text(
            "SELECT status, outcome, confidence FROM assessments"))).all()  # fmt: skip
        proposals = (
            await conn.execute(text("SELECT count(*) FROM assessments WHERE status = 'proposed'"))
        ).scalar_one()
    assert rows == [("no_decision", None, None)] * 4
    assert proposals == 0
    await sign_in(client)
    page = (await client.get(f"/investigations/{inv.id}")).text
    assert "/accept" not in page  # no Accept form
    token = page.split('name="csrf_token" value="')[1].split('"')[0]
    aid = (await client.get(f"/api/v1/investigations/{inv.id}")).json()["assessments"][0]["id"]
    refused = await client.post(f"/investigations/{inv.id}/accept",
                                data={"assessment_id": aid, "csrf_token": token})  # fmt: skip
    assert refused.status_code >= 400
    async with seeded.connect() as conn:
        reviews = (await conn.execute(text("SELECT count(*) FROM review_events"))).scalar_one()
    assert reviews == 0
    listed = (await client.get("/api/v1/proposals")).json()
    assert [g for g in listed if g["outcome"]] == []
