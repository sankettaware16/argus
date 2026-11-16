"""ARGUS AI's reading of presented incidents (D-324) on the runtime login, a fake model answering:
a story per presented incident and version, cached (a second pass asks nothing; a material change
asks again), a second opinion for P1 only, the day's cap per kind (config/llm.yaml's purposes),
"no model can take it now" stores nothing and is tried again, a refused answer is stored, not
shown and not asked again, and nothing of the queue changes. The web's login reads the reading in
the case's engine block, with the line of a disagreement. Made-up site (ACME)."""

from __future__ import annotations

import ipaddress
import json
import uuid
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.assets import parse_asset_map
from argus.llm.gateway import Call, Completion, NoCapacity
from argus.llm.privacy import Privacy, load_policy
from argus.llm.providers import LlmConfig
from argus.risk import reading_run
from argus.risk import run as risk_run
from argus.web.v1 import engine_routes
from tests.integration.risk.conftest import NOW, all_rows, scalar
from tests.integration.risk.test_present import presenting, world

pytestmark = pytest.mark.integration
ASSETS = parse_asset_map(
    b"""
networks:
  - name: Lab block
    range: 10.1.1.0/24
    fields: {site.type: lab}
"""
)
LATER = NOW + timedelta(minutes=5)


def privacy() -> Privacy:
    return Privacy.build(load_policy(), ASSETS, (ipaddress.ip_network("198.51.100.0/24"),))


def claim(words: str) -> list[dict[str, Any]]:
    return [{"text": words, "cites": ["F1", "F2"]}]


def answer(call: Call, agrees: bool = True) -> str:
    if call.purpose == "story":
        body: dict[str, Any] = {
            "happened": claim("The engine raised it on one device."),
            "against": claim("It could be an ordinary program."),
            "split": [], "incidents": "unsure",
            "next_steps": claim("Ask the owner what runs on the device."),
        }  # fmt: skip
    else:
        body = {"reading": claim("It looks real."), "doubts": claim("The signs are weak."),
                "decide": claim("Look at the proxy logs.")}  # fmt: skip
    body["agrees"] = agrees
    body["differ"] = [] if agrees else claim("The evidence is thinner than the priority says.")
    return json.dumps(body)


class Model:
    """A fake model: answers, refuses or is busy; records every call."""

    def __init__(self, mode: str = "answer", agrees: bool = True) -> None:
        self.mode = mode
        self.agrees = agrees
        self.calls: list[Call] = []

    async def __call__(self, call: Call) -> Completion:
        self.calls.append(call)
        if self.mode == "busy":
            raise NoCapacity(NOW + timedelta(minutes=1), "every provider waits")
        words = answer(call, self.agrees) if self.mode == "answer" else "I cannot do that."
        return Completion(words, "fake", "model-1", 10, 20, 0.0, 5, uuid.uuid4())


def caps(story: int = 15, opinion: int = 3) -> LlmConfig:
    return LlmConfig.model_validate({
        "providers": [{"name": "fake", "base_url": "https://fake.example/v1", "keys": ["K"],
                       "models": {"medium": {"name": "m"}, "large": {"name": "l"}}}],
        "purposes": {"story": {"calls_per_day": story}, "opinion": {"calls_per_day": opinion}},
    })  # fmt: skip


async def presented(owner: AsyncEngine, app: AsyncEngine) -> list[Any]:
    await world(owner)
    await risk_run.step(app, presenting(True), NOW)
    return await all_rows(
        owner, "SELECT id, version, band, priority, case_id FROM risk_incidents"
        " WHERE case_id IS NOT NULL ORDER BY band, priority DESC, id",
    )  # fmt: skip


async def queue_state(owner: AsyncEngine) -> list[Any]:
    return await all_rows(
        owner, "SELECT r.id, r.version, r.band, r.priority, r.shown, r.raised_by_ai, c.state,"
        " c.version AS cv FROM risk_incidents r LEFT JOIN cases c ON c.id = r.case_id"
        " ORDER BY r.id",
    )  # fmt: skip


async def readings(owner: AsyncEngine) -> list[Any]:
    return await all_rows(owner, "SELECT incident_id, version, kind, state, model, why"
                                 " FROM risk_readings ORDER BY id")  # fmt: skip


async def test_a_story_per_presented_incident_and_version_cached_and_nothing_else_changes(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    shown = await presented(migrated_engine, app_engine)
    assert len(shown) == 3
    before = await queue_state(migrated_engine)
    model = Model()
    no_opinion = caps(opinion=0)
    for _ in range(len(shown)):  # the highest priority first, PER_PASS a pass
        done = await reading_run.run_pass(app_engine, privacy(), model, LATER, no_opinion)
        assert done.written == {"story": reading_run.PER_PASS}
    assert await reading_run.run_pass(app_engine, privacy(), model, LATER, no_opinion) \
        == reading_run.Report()  # fmt: skip
    rows = await readings(migrated_engine)
    assert [(r.incident_id, r.kind, r.state, r.model) for r in rows] == [
        (s.id, "story", "written", "fake/model-1") for s in shown
    ]
    assert len(model.calls) == 3
    assert all(c.purpose == "story" for c in model.calls)
    assert all("10.1.1." not in c.request.text for c in model.calls)  # pseudonymised
    assert await queue_state(migrated_engine) == before  # text only: the queue is unchanged
    # a material change: the new version is read again
    top = shown[0]
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("UPDATE risk_incidents SET version = version + 1, queued_at = :t WHERE id = :i"),
            {"i": top.id, "t": LATER},
        )
    again = await reading_run.run_pass(app_engine, privacy(), model, LATER, no_opinion)
    assert again.written == {"story": 1}
    assert (await readings(migrated_engine))[-1].version == top.version + 1


async def test_a_second_opinion_for_p1_only(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    shown = await presented(migrated_engine, app_engine)
    async with migrated_engine.begin() as conn:  # one P1, the others below
        await conn.execute(text("UPDATE risk_incidents SET band = CASE WHEN id = :i THEN 'P1'"
                                " ELSE 'P3' END"), {"i": shown[-1].id})  # fmt: skip
    model = Model()
    for _ in range(4):
        await reading_run.run_pass(app_engine, privacy(), model, LATER, caps())
    rows = await readings(migrated_engine)
    assert [(r.incident_id, r.state) for r in rows if r.kind == "opinion"] == [
        (shown[-1].id, "written")
    ]
    assert sum(r.kind == "story" for r in rows) == 3
    assert {c.tier.value for c in model.calls if c.purpose == "opinion"} == {"large"}
    assert {c.tier.value for c in model.calls if c.purpose == "story"} == {"medium"}


async def test_the_days_cap_holds_and_a_new_day_opens_it(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    await presented(migrated_engine, app_engine)
    model = Model("refuse")
    for _ in range(3):
        await reading_run.run_pass(app_engine, privacy(), model, LATER, caps(story=1, opinion=0))
    rows = await readings(migrated_engine)
    assert [(r.kind, r.state) for r in rows] == [("story", "refused")]  # refused counts too
    assert rows[0].why.startswith("not shown: ")
    assert len(model.calls) == 1
    tomorrow = LATER + timedelta(days=1)
    await reading_run.run_pass(app_engine, privacy(), Model(), tomorrow, caps(story=1, opinion=0))
    assert len(await readings(migrated_engine)) == 2
    # a refused version is not asked again
    assert [r.state for r in await readings(migrated_engine)] == ["refused", "written"]


async def test_no_model_now_stores_nothing_and_the_next_pass_tries_again(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    await presented(migrated_engine, app_engine)
    busy = Model("busy")
    report = await reading_run.run_pass(app_engine, privacy(), busy, LATER, caps(opinion=0))
    assert report.waiting
    assert report.line() == "ARGUS AI's reading: waiting for a model"
    assert len(busy.calls) == 1  # one try a pass, then it waits
    assert await scalar(migrated_engine, "SELECT count(*) FROM risk_readings") == 0
    done = await reading_run.run_pass(app_engine, privacy(), Model(), LATER, caps(opinion=0))
    assert done.written == {"story": reading_run.PER_PASS}


async def test_nothing_is_read_in_shadow(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    await world(migrated_engine)
    await risk_run.step(app_engine, presenting(False), NOW)
    model = Model()
    assert await reading_run.run_pass(app_engine, privacy(), model, LATER, caps()) \
        == reading_run.Report()  # fmt: skip
    assert model.calls == []


async def test_the_engine_block_carries_the_reading_and_a_disagreement_line(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, web_engine: AsyncEngine
) -> None:
    shown = await presented(migrated_engine, app_engine)
    for _ in range(2):
        await reading_run.run_pass(app_engine, privacy(), Model(agrees=False), LATER, caps())
    top = shown[0]
    async with web_engine.connect() as conn:  # the web's own login reads it
        blocks = await engine_routes.views_for(conn, [s.case_id for s in shown])
    block = blocks[top.case_id]
    story = block.ai_story
    assert story is not None
    assert story.kind == "story"
    assert (story.model, story.current, story.agrees, story.incidents) == (
        "fake/model-1",
        True,
        False,
        "unsure",
    )
    assert [s.key for s in story.sections] == ["happened", "against", "next_steps", "differ"]
    happened = story.sections[0].claims[0]
    assert happened.text == "The engine raised it on one device."
    assert happened.based_on[0].startswith(f"The engine's priority is {top.band}")
    assert top.band == "P1"  # its second opinion too
    opinion = block.ai_second_opinion
    assert opinion is not None
    assert opinion.kind == "second_opinion"
    assert [s.key for s in opinion.sections] == ["reading", "doubts", "decide", "differ"]
    assert block.disagreement == (
        f"ARGUS AI reads this differently from the engine ({block.band}, {block.certainty}):"
        " The evidence is thinner than the priority says."
    )
    unread = blocks[shown[-1].case_id]  # the third waits for the next pass
    assert (unread.ai_story, unread.disagreement) == (None, None)
    # after a material change the old story is shown as of an earlier version, without the line
    async with migrated_engine.begin() as conn:
        await conn.execute(text("UPDATE risk_incidents SET version = version + 1 WHERE id = :i"),
                           {"i": top.id})  # fmt: skip
    async with web_engine.connect() as conn:
        block = (await engine_routes.views_for(conn, [top.case_id]))[top.case_id]
    assert block.ai_story is not None
    assert block.ai_story.current is False
    assert block.disagreement is None


async def test_a_confirmed_incident_is_read_with_the_evidences_word_and_its_band(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    # once a person confirms, the stored word is "Confirmed"; the model is asked about the
    # evidence's word (the one the page and the disagreement line use) and told a person
    # confirmed it
    shown = await presented(migrated_engine, app_engine)
    top = shown[0]
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("UPDATE risk_incidents SET certainty = 'Confirmed',"
                 " view = view || jsonb_build_object('certainty', 'Suspected', 'band', 'P2')"
                 " WHERE id = :i"),
            {"i": top.id},
        )  # fmt: skip
    async with app_engine.connect() as conn:
        snap = await reading_run.snapshot(conn, top.id)
    assert snap is not None
    assert (snap.certainty, snap.band, snap.confirmed) == ("Suspected", "P2", True)
    first = [f.plain for f in reading_run.reading.facts_of(snap, LATER)]
    assert "Suspected" in first[0]
    assert "Confirmed" not in first[0]
    assert any("A person confirmed" in f for f in first)
