"""P2 (D-080): the gold set stored once, answered by a person, corrected by a new answer;
the labelling page and its next-item flow."""

from __future__ import annotations

import json
import uuid
from typing import Any

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.evaluation import store
from argus.web import auth, queries
from tests.integration.web.conftest import NOW, PASSWORD

pytestmark = pytest.mark.integration
HASH = "a" * 64


async def with_dossiers(engine: AsyncEngine, owner: AsyncEngine, n: int) -> list[dict[str, Any]]:
    """Gold records for the first ``n`` investigations, each with a stored dossier."""
    async with engine.connect() as conn:
        found = (await queries.inbox(conn, "all"))[:n]
    records = []
    async with owner.begin() as conn:
        for k, inv in enumerate(found):
            await conn.execute(
                text(
                    "INSERT INTO dossiers (investigation_id, version, pack, facts_version, job_id,"
                    " run_kind, family, status, dossier_hash, body, evidence_count, created_at)"
                    " VALUES (:i, :v, 'generic@12', :v, 1, 'collect', 'generic',"
                    " 'evidence_ready', :h, '{}'::jsonb, 0, now())"
                ),
                {"i": inv.id, "v": inv.version, "h": HASH},
            )
            records.append({
                "investigation_id": str(inv.id), "version": inv.version, "pack": "generic@12",
                "dossier_hash": HASH, "rule_name": f"rule {k}", "split": "dev" if k else "test",
                "why": ["a kind of this rule"],
                "suggestion": {"outcome": "benign_expected", "reasons": ["no hit"],
                               "source": "signals"},
            })  # fmt: skip
    return records


async def test_a_set_is_stored_once_and_checked(
    seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    records = await with_dossiers(seeded, migrated_engine, 3)
    bad = [{**records[0], "dossier_hash": "b" * 64}]
    async with seeded.begin() as conn:
        with pytest.raises(store.GoldError, match="no dossier with that version"):
            await store.import_set(conn, bad, "other")
    async with seeded.begin() as conn:
        with pytest.raises(store.GoldError, match=r"^item 1: split must be one of dev, test$"):
            await store.import_set(conn, [{**records[0], "split": "x"}], "other")
    async with seeded.begin() as conn:
        with pytest.raises(store.GoldError, match=r"^no items$"):
            await store.import_set(conn, [], "other")
    async with seeded.begin() as conn:
        assert await store.import_set(conn, records) == 3
    async with seeded.begin() as conn:
        with pytest.raises(store.GoldError, match="exists \\(3 items\\): a set is frozen"):
            await store.import_set(conn, records)
    assert store.SET == "v1"
    async with seeded.connect() as conn:
        rows = await store.items(conn)
        with pytest.raises(AttributeError):
            rows[0].split = "x"  # type: ignore[misc]
        assert await store.progress(conn) == {
            "items": 3, "answered": 0, "dev_answered": 0, "test_answered": 0}  # fmt: skip


async def test_answers_are_appended_and_the_newest_counts(
    seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    records = await with_dossiers(seeded, migrated_engine, 3)
    first = uuid.UUID(records[0]["investigation_id"])
    async with seeded.begin() as conn:
        await store.import_set(conn, records)
        made = await auth.login(conn, "asha", PASSWORD, NOW)
        assert made is not None
        user = made[1].user_id
        with pytest.raises(store.GoldError, match=r"^choose an outcome$"):
            await store.answer(conn, first, user, "")
        with pytest.raises(store.GoldError, match=r"^not in the gold set$"):
            await store.answer(conn, uuid.uuid4(), user, "true_positive")
        with pytest.raises(store.GoldError, match="longer than 4000"):
            await store.answer(conn, first, user, "true_positive", "x" * 4001)
        await store.answer(conn, first, user, "true_positive", "x" * 4000)  # at the limit
        second = uuid.UUID(records[1]["investigation_id"])
        await store.answer(conn, second, user, "inconclusive")  # no note at all
        await store.answer(conn, first, user, "true_positive", "  c2 seen ")
        await store.answer(conn, first, user, "benign_policy", " ")
    async with seeded.connect() as conn:
        row = await store.item(conn, first)
        rows = await store.items(conn)
        count = await conn.scalar(text("SELECT count(*) FROM gold_labels"))
        assert await store.item(conn, uuid.uuid4()) is None
        progress = await store.progress(conn)
    assert row is not None
    assert (row.outcome, row.note, row.answered_by) == ("benign_policy", None, "Asha")
    assert count == 4  # earlier answers are kept
    by_id = {r.investigation_id: r for r in rows}
    assert (by_id[second].outcome, by_id[second].note) == ("inconclusive", None)
    assert (by_id[first].rule_name, by_id[first].split, by_id[first].why) == (
        "rule 0", "test", ("a kind of this rule",)
    )  # fmt: skip
    assert by_id[first].suggestion == records[0]["suggestion"]
    assert (rows[0].investigation_id, rows[0].outcome) == (
        uuid.UUID(records[2]["investigation_id"]),
        None,
    )  # unanswered first
    assert progress == {"items": 3, "answered": 2, "dev_answered": 1, "test_answered": 1}


async def test_the_page_and_the_next_item(
    client: httpx.AsyncClient, seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    records = await with_dossiers(seeded, migrated_engine, 2)
    async with seeded.begin() as conn:
        await store.import_set(conn, records)
    assert (await client.get("/gold")).status_code in (303, 307)  # signed out: to the login
    await client.post("/login", data={"username": "asha", "password": PASSWORD})
    listing = (await client.get("/gold")).text
    assert "<strong>0 of 2 answered</strong>" in listing
    assert (
        '<a aria-current="page" href="/gold" title="The answer key that measures how often ARGUS'
        ' is right">Gold set</a>' in listing
    )
    one, two = (r["investigation_id"] for r in records)
    detail = (await client.get(f"/investigations/{one}")).text
    assert "<h2>Gold set: your answer</h2>" in detail
    assert "<strong>Suggested:</strong> Benign: expected activity" in detail
    csrf = detail.split('name="csrf_token" value="')[1].split('"')[0]
    expired = await client.post(f"/investigations/{one}/gold",
                                data={"csrf_token": "x", "outcome": "true_positive"})  # fmt: skip
    assert expired.status_code == 403
    missing = await client.post(f"/investigations/{one}/gold", data={"csrf_token": csrf})
    assert missing.status_code == 422
    assert "choose an outcome" in missing.text
    answer = {"csrf_token": csrf, "outcome": "true_positive", "note": "c2"}
    saved = await client.post(f"/investigations/{one}/gold", data=answer)
    assert saved.status_code == 303
    remaining = {one, two} - {one}
    assert saved.headers["location"] == f"/investigations/{remaining.pop()}?saved=gold"
    last = await client.post(f"/investigations/{two}/gold",
                             data={"csrf_token": csrf, "outcome": "inconclusive"})  # fmt: skip
    assert last.headers["location"] == "/gold"
    done = (await client.get("/gold")).text
    assert "<strong>2 of 2 answered</strong>" in done
    assert "<em>not yet</em>" not in done
    again = (await client.get(f"/investigations/{one}")).text
    assert "<strong>Your answer:</strong> True positive — c2" in again
    other = (await client.get("/api/investigations", params={"view": "all"})).json()
    plain = next(i["id"] for i in other if i["id"] not in (one, two))
    assert "Gold set: your answer" not in (await client.get(f"/investigations/{plain}")).text
    assert json.dumps(records)  # the records stay plain JSON (the manifest's format)


async def test_reviewing_can_answer_the_gold_set_and_every_save_is_confirmed(
    client: httpx.AsyncClient, seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    records = await with_dossiers(seeded, migrated_engine, 2)
    async with seeded.begin() as conn:
        await store.import_set(conn, records)
    await client.post("/login", data={"username": "asha", "password": PASSWORD})
    one, two = (r["investigation_id"] for r in records)
    page = (await client.get(f"/investigations/{one}")).text
    assert "<strong>Your answer:</strong> <em>not given yet</em>" in page
    assert 'name="also_gold" value="1" checked' in page
    csrf = page.split('name="csrf_token" value="')[1].split('"')[0]
    inv = (await client.get("/api/investigations", params={"view": "all"})).json()
    seen = next(i for i in inv if i["id"] == one)
    form = {"csrf_token": csrf, "action": "follow_up", "outcome": "inconclusive",
            "note": "check 2xx", "seen_version": seen["version"], "also_gold": "1"}  # fmt: skip
    saved = await client.post(f"/investigations/{one}/review", data=form)
    assert saved.status_code == 303, saved.text[:500]
    assert saved.headers["location"] == f"/investigations/{one}?saved=follow_up&gold=1"
    after = (await client.get(saved.headers["location"])).text
    assert "Saved: marked as needing follow-up. Also saved as your gold-set answer." in after
    assert "<strong>Your answer:</strong> Inconclusive — check 2xx" in after

    def hidden(html: str, name: str) -> str:
        return html.split(f'name="{name}" value="')[1].split('"')[0]

    note = {**form, "action": "note", "outcome": "", "note": "only a note",
            "seen_version": hidden(after, "seen_version"),
            "seen_review": hidden(after, "seen_review")}  # fmt: skip
    noted = await client.post(f"/investigations/{one}/review", data=note)
    assert noted.headers["location"] == f"/investigations/{one}?saved=note"  # no outcome: no answer
    assert "Saved: note added." in (await client.get(noted.headers["location"])).text
    gold_page = (await client.get(f"/investigations/{two}")).text
    csrf = gold_page.split('name="csrf_token" value="')[1].split('"')[0]
    nxt = await client.post(f"/investigations/{two}/gold",
                            data={"csrf_token": csrf, "outcome": "benign_expected"})  # fmt: skip
    assert nxt.headers["location"] == "/gold"  # every item answered
    async with seeded.connect() as conn:
        assert (await store.progress(conn))["answered"] == 2
    unknown = (await client.get(f"/investigations/{one}?saved=<b>x</b>")).text
    assert "<b>x</b>" not in unknown


async def test_any_spans_every_set_and_an_answer_finds_its_set(
    seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    records = await with_dossiers(seeded, migrated_engine, 3)
    second = uuid.UUID(records[2]["investigation_id"])
    async with seeded.begin() as conn:
        await store.import_set(conn, records[:2])
        await store.import_set(conn, records[2:], "v2")
        made = await auth.login(conn, "asha", PASSWORD, NOW)
        assert made is not None
        user = made[1].user_id
        with pytest.raises(store.GoldError, match=r"^not in the gold set$"):
            await store.answer(conn, second, user, "benign_expected")  # v1 only by default
        await store.answer(conn, second, user, "benign_expected", set_name=store.ANY)
        await store.import_set(conn, records[2:], "v3")  # the same item in two sets
        with pytest.raises(store.GoldError, match="more than one gold set"):
            await store.answer(conn, second, user, "true_positive", set_name=store.ANY)
    async with seeded.connect() as conn:
        assert len(await store.items(conn)) == 2
        assert len(await store.items(conn, "v2")) == 1
        assert len(await store.items(conn, store.ANY)) == 4
        assert (await store.progress(conn, "v2"))["answered"] == 1
        row = await store.item(conn, second, "v2")
        label_set = await conn.scalar(text("SELECT set_name FROM gold_labels"))
    assert row is not None
    assert row.outcome == "benign_expected"
    assert label_set == "v2"
