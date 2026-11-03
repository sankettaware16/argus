"""The page routes exactly (2026-10-21: the mutation run of ``app.py`` with Phase 2's tests
found what no test pinned): the login redirect of every page and form, the expired-form refusal
of every form, every message word for word, the allowed values of every typed parameter, the
API's documented responses, and the fallbacks when the model gateway is not configured."""

from __future__ import annotations

import html
import re
import uuid
from datetime import timedelta
from typing import Any

import httpx
import pytest
from markupsafe import escape
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.evaluation import store as gold_store
from argus.web import queries
from argus.web.app import SAVED, create_app
from tests.integration.web.conftest import BASE, NOW, PASSWORD, SAME_ORIGIN, to_signin
from tests.integration.web.test_assessments import csrf, propose, signed_in
from tests.integration.web.test_gold import with_dossiers

pytestmark = pytest.mark.integration
EXPIRED = "The form expired; reload the page and try again."


def alert(message: str) -> str:
    return f'<p class="message" role="alert">{escape(message)}</p>'


async def first(engine: AsyncEngine, n: int = 1) -> list[queries.Summary]:
    async with engine.connect() as conn:
        return (await queries.inbox(conn, "all"))[:n]


async def test_signed_out_every_page_and_form_goes_to_the_login(
    client: httpx.AsyncClient, seeded: AsyncEngine
) -> None:
    (a,) = await first(seeded)
    pages = ["/", "/rules", "/glossary", "/patterns", "/hosts", "/health", "/gold", "/proposals",
             "/tuning", "/metrics", "/dashboard", f"/investigations/{a.id}",
             f"/investigations/{a.id}/alerts/x"]  # fmt: skip
    for path in pages:
        got = await client.get(path)
        assert (got.status_code, got.headers.get("location")) == (303, to_signin(path)), path
    forms: list[tuple[str, dict[str, Any]]] = [
        ("/patterns/review", {"items": f"{a.id}:1", "outcome": "true_positive"}),
        (f"/investigations/{a.id}/gold", {"outcome": "true_positive"}),
        (f"/investigations/{a.id}/review", {"action": "note", "seen_version": 1}),
        (f"/investigations/{a.id}/accept", {"assessment_id": 1}),
        (f"/investigations/{a.id}/assess", {}),
        ("/proposals/confirm", {"group": "g", "ids": "1"}),
    ]
    for path, data in forms:
        got = await client.post(path, data=data)
        page = path.rsplit("/", 1)[0]  # back to the form's page after signing in
        assert (got.status_code, got.headers.get("location")) == (303, to_signin(page)), path


async def test_every_form_refuses_an_expired_token(
    client: httpx.AsyncClient, seeded: AsyncEngine
) -> None:
    (a,) = await first(seeded)
    await signed_in(client)
    forms: list[tuple[str, dict[str, Any]]] = [
        ("/patterns/review", {"items": f"{a.id}:1", "outcome": "true_positive"}),
        (f"/investigations/{a.id}/gold", {"outcome": "true_positive"}),
        (f"/investigations/{a.id}/review", {"action": "note", "seen_version": 1}),
        (f"/investigations/{a.id}/accept", {"assessment_id": 1}),
        (f"/investigations/{a.id}/assess", {}),
        ("/proposals/confirm", {"group": "g", "ids": "1"}),
    ]
    for path, data in forms:
        for token in ({}, {"csrf_token": "x"}):  # missing, or wrong
            got = await client.post(path, data={**data, **token})
            assert got.status_code == 403, path
            assert alert(EXPIRED) in got.text, path


async def test_the_pattern_form_word_for_word(
    client: httpx.AsyncClient, seeded: AsyncEngine
) -> None:
    a, b = await first(seeded, 2)
    await signed_in(client)
    token = csrf((await client.get("/patterns")).text)

    async def post(items: list[str], outcome: str) -> httpx.Response:
        return await client.post("/patterns/review",
                                 data={"items": items, "outcome": outcome,
                                       "csrf_token": token})  # fmt: skip

    unknown = await post([f"{a.id}:{a.version}"], "maybe")
    assert (unknown.status_code, alert("Unknown outcome.") in unknown.text) == (422, True)
    none = await post([f"{a.id}:{a.version}"], "")
    assert (none.status_code, alert("Choose an outcome for the group.") in none.text) == (422, True)
    broken = await post(["not-a-uuid:1"], "true_positive")
    assert (broken.status_code, alert("A malformed item.") in broken.text) == (422, True)
    too_many = await post([f"{uuid.uuid4()}:1"] * 201, "true_positive")
    assert too_many.status_code == 422  # the form takes at most 200
    done = await post([f"{a.id}:{a.version}", f"{b.id}:{b.version + 5}"], "benign_expected")
    assert '<p class="message" role="status">1 reviewed. 1 changed since you looked and were' \
           ' left as they are.</p>' in " ".join(done.text.split())  # fmt: skip


async def test_the_review_form_word_for_word(
    client: httpx.AsyncClient, seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    records = await with_dossiers(seeded, migrated_engine, 3)
    async with seeded.begin() as conn:
        await gold_store.import_set(conn, records[:1])  # the first is in the gold set
    a, b, c = await first(seeded, 3)
    gold_id = uuid.UUID(records[0]["investigation_id"])
    gold_inv = next(s for s in (a, b, c) if s.id == gold_id)
    plain = next(s for s in (a, b, c) if s.id != gold_id)
    await signed_in(client)
    token = csrf((await client.get(f"/investigations/{plain.id}")).text)

    async def review(inv: queries.Summary, **data: Any) -> httpx.Response:
        return await client.post(f"/investigations/{inv.id}/review",
                                 data={"csrf_token": token, "seen_version": inv.version,
                                       **data})  # fmt: skip

    unknown = await review(plain, action="reviewed", outcome="maybe")
    assert (unknown.status_code, alert("Unknown outcome.") in unknown.text) == (422, True)
    missing = await client.post(f"/investigations/{uuid.uuid4()}/review",
                                data={"csrf_token": token, "action": "note", "note": "n",
                                      "seen_version": 0})  # fmt: skip
    assert (missing.status_code, alert("No such investigation.") in missing.text) == (404, True)
    stale = await review(plain, action="follow_up", seen_version=plain.version + 1)
    assert stale.status_code == 409
    assert alert("Someone else reviewed this, or new alerts arrived, while you were reading."
                 " Here is the current state; nothing was saved.") in stale.text  # fmt: skip
    # a follow-up without outcome or note: neither is invented
    follow = await review(plain, action="follow_up")
    assert follow.headers["location"] == f"/investigations/{plain.id}?saved=follow_up"
    async with seeded.connect() as conn:
        row = (await conn.execute(text(
            "SELECT outcome, note FROM review_events WHERE investigation_id = :i"),
            {"i": plain.id})).one()  # fmt: skip
    assert tuple(row) == (None, None)
    # the gold box: only with also_gold=1 and an outcome; never on an item outside the set
    kept = await review(gold_inv, action="reviewed", outcome="true_positive")
    assert kept.headers["location"] == f"/investigations/{gold_inv.id}?saved=reviewed"
    gold_inv = (await first(seeded, 3))[[s.id for s in await first(seeded, 3)].index(gold_inv.id)]
    async with seeded.connect() as conn:
        gold_inv = await queries.investigation(conn, gold_inv.id)  # type: ignore[assignment]
    both = await review(gold_inv, action="reviewed", outcome="true_positive", also_gold="1",
                        seen_review=str(gold_inv.latest_review))  # fmt: skip
    assert both.headers["location"] == f"/investigations/{gold_inv.id}?saved=reviewed&gold=1"
    async with seeded.connect() as conn:
        plain = await queries.investigation(conn, plain.id)  # type: ignore[assignment]
    outside = await review(plain, action="reviewed", outcome="benign_expected", also_gold="1",
                           seen_review=str(plain.latest_review))  # fmt: skip
    assert outside.headers["location"] == f"/investigations/{plain.id}?saved=reviewed"
    # the gold form without a note keeps none
    answered = await client.post(f"/investigations/{gold_id}/gold",
                                 data={"csrf_token": token,
                                       "outcome": "true_positive"})  # fmt: skip
    assert answered.status_code == 303
    async with seeded.connect() as conn:
        notes = (await conn.execute(text("SELECT note FROM gold_labels"))).scalars().all()
    assert notes[-1] is None


@pytest.mark.parametrize("key", sorted(SAVED))
async def test_each_saved_message_word_for_word(
    key: str, client: httpx.AsyncClient, seeded: AsyncEngine
) -> None:
    (a,) = await first(seeded)
    await signed_in(client)
    page = (await client.get(f"/investigations/{a.id}", params={"saved": key})).text
    assert alert(SAVED[key]) in page
    gold = (await client.get(f"/investigations/{a.id}", params={"saved": key, "gold": "1"})).text
    assert alert(SAVED[key] + " Also saved as your gold-set answer.") in gold


async def test_messages_that_must_not_show(client: httpx.AsyncClient, seeded: AsyncEngine) -> None:
    (a,) = await first(seeded)
    await signed_in(client)
    for params in ({"gold": "1"}, {"saved": "nothing"}, {}):
        got = await client.get(f"/investigations/{a.id}", params=params)
        assert got.status_code == 200
        assert 'class="message"' not in got.text
    assert "Confirmed" not in (await client.get("/proposals")).text
    missing = await client.get(f"/investigations/{uuid.uuid4()}")
    assert (missing.status_code, alert("No such investigation.") in missing.text) == (404, True)
    raw = await client.get(f"/investigations/{a.id}/alerts/nope")
    assert (raw.status_code, alert("No such alert here.") in raw.text) == (404, True)
    assert SAVED == {
        "reviewed": "Saved: marked reviewed.",
        "follow_up": "Saved: marked as needing follow-up.",
        "note": "Saved: note added.",
        "gold": "Saved your gold-set answer for the previous one. This is the next to answer.",
        "accepted": "Saved: you accepted ARGUS's proposal (a confirmed proposal).",
        "asked": "Asked: the AI investigator will look at this within a few minutes. Reload to"
        " see its answer.",
        "asked_exists": "The AI investigator has already assessed what this investigation shows"
        " now: its answer is below.",
    }


async def test_columns_from_the_query_and_the_first_two_hundred_asked(
    client: httpx.AsyncClient, seeded: AsyncEngine
) -> None:
    (a,) = await first(seeded)
    await signed_in(client)
    asked = await client.get(f"/investigations/{a.id}", params={"cols": "source.ip"})
    assert '<th scope="col" class="mono">source.ip</th>' in asked.text
    late = await client.get(f"/investigations/{a.id}",
                            params=[("cols", f"x{k}") for k in range(200)]
                            + [("cols", "source.ip")])  # fmt: skip
    assert '<th scope="col" class="mono">source.ip</th>' not in late.text  # past the first 200


async def test_accepting_and_confirming_record_what_they_did(
    client: httpx.AsyncClient, seeded: AsyncEngine
) -> None:
    ids = await propose(seeded, 2, "engine@1#k", "benign_expected")
    (a,) = await first(seeded)
    await signed_in(client)
    token = csrf((await client.get(f"/investigations/{a.id}")).text)
    stale = await client.post(f"/investigations/{a.id}/accept",
                              data={"csrf_token": token, "assessment_id": 999_999})  # fmt: skip
    assert stale.status_code == 409
    assert alert("The proposal changed (new alerts, a newer assessment, or someone reviewed it)"
                 " while you were reading; nothing was saved.") in stale.text  # fmt: skip
    group = "g" * 250
    done = await client.post("/proposals/confirm",
                             data={"csrf_token": token, "group": group,
                                   "ids": ",".join(map(str, ids))})  # fmt: skip
    assert done.status_code == 303
    async with seeded.connect() as conn:
        audit = (await conn.execute(text(
            "SELECT action, target_type, length(target_id) FROM audit_events"
            " WHERE action LIKE 'assessment.%' ORDER BY id"))).all()  # fmt: skip
    assert [tuple(r) for r in audit] == [("assessment.confirm", "assessment_group", 200)]
    accepted = await client.post(f"/investigations/{a.id}/accept",
                                 data={"csrf_token": token, "assessment_id": ids[0]})  # fmt: skip
    async with seeded.connect() as conn:
        last = (await conn.execute(text(
            "SELECT action, target_type, target_id FROM audit_events ORDER BY id DESC LIMIT 1"))
        ).one()  # fmt: skip
    if accepted.status_code == 303:  # still current: the accept is audited on the assessment
        assert tuple(last) == ("assessment.accept", "assessment", str(ids[0]))


async def test_asking_without_a_dossier_or_a_privacy_layer(
    seeded: AsyncEngine, client: httpx.AsyncClient, web_engine: AsyncEngine
) -> None:
    from argus.llm.privacy import Privacy, load_policy
    from tests.unit.llm.conftest import ASSETS

    (a,) = await first(seeded)  # no dossier stored for it
    await signed_in(client)
    token = csrf((await client.get(f"/investigations/{a.id}")).text)
    off = await client.post(f"/investigations/{a.id}/assess", data={"csrf_token": token})
    assert off.status_code == 503
    assert alert("The AI investigator is not available on this server.") in off.text
    app = create_app(web_engine, clock=lambda: NOW + timedelta(hours=1),
                     privacy=Privacy.build(load_policy(), ASSETS))  # fmt: skip
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=BASE, headers=SAME_ORIGIN
    ) as http:
        await signed_in(http)
        token = csrf((await http.get(f"/investigations/{a.id}")).text)
        early = await http.post(f"/investigations/{a.id}/assess", data={"csrf_token": token})
        assert early.status_code == 409
        assert alert("ARGUS has not built this investigation's dossier yet; try again in a few"
                     " minutes.") in early.text  # fmt: skip
    async with seeded.connect() as conn:
        assert await conn.scalar(text(
            "SELECT count(*) FROM audit_events"
            " WHERE action = 'assessment.request'")) == 0  # fmt: skip


async def test_the_gateway_fallbacks(
    seeded: AsyncEngine, web_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    import argus.llm.providers as providers

    def broken(*_: Any, **__: Any) -> Any:
        raise RuntimeError("no gateway configured here")

    monkeypatch.setattr(providers, "load_config", broken)
    app = create_app(web_engine, clock=lambda: NOW + timedelta(hours=1))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=BASE, headers=SAME_ORIGIN
    ) as http:
        await signed_in(http)
        cost = (await http.get("/api/cost")).json()
        metrics = await http.get("/metrics")
    assert (cost["cap_usd"], cost["paid_until_usd"], cost["daily_cap_usd"]) == (10.0, 8.0, None)
    assert metrics.status_code == 200
    assert "Today against the limits" not in metrics.text
    assert "Calls allowed." in metrics.text  # not stopped
    monkeypatch.undo()
    app = create_app(web_engine, clock=lambda: NOW + timedelta(hours=1))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=BASE, headers=SAME_ORIGIN
    ) as http:
        await signed_in(http)
        assert "Today against the limits" in (await http.get("/metrics")).text


async def test_every_typed_value_is_accepted(client: httpx.AsyncClient) -> None:
    await signed_in(client)
    for sort in ("newest", "oldest", "urgent", "reviewed"):
        assert (await client.get("/", params={"view": "reviewed", "sort": sort})).status_code == 200
    page = (await client.get("/", params={"sort": "newest"})).text
    assert ">oldest first</a>" in page
    for name, values in (("severity", ("critical", "high", "medium", "low")),
                         ("state", ("unreviewed", "follow_up", "changed_since_review", "reviewed")),
                         ("verdict", ("true_positive", "benign_expected", "benign_policy",
                                      "rule_false_positive", "inconclusive", "none")),
                         ("ai", ("proposed_tp", "proposed_other", "no_proposal", "working",
                                 "none"))):  # fmt: skip
        for value in values:
            got = await client.get("/api/dashboard", params={name: value})
            assert got.status_code == 200, (name, value)
    for kind in ("ip", "host", "domain", "user"):
        found = await client.get("/api/dashboard", params={"kind": kind, "value": "203.0.113.9"})
        assert found.json()["kpis"]["cases"] == 0, kind  # the filter applies
        inbox = await client.get("/", params={"view": "all", "kind": kind, "value": "203.0.113.9"})
        assert "Nothing here." in inbox.text, kind
    early = await client.get("/api/dashboard", params={"start": "2019-06-01", "end": "2020-03-01"})
    assert early.json()["start"] == "2019-12-31T18:30:00+00:00"  # clamped to 2020-01-01 IST
    one = await client.get("/dashboard", params={"start": "2026-10-01", "end": ""})
    assert one.status_code == 200  # one date: the time menu's span, the page still renders
    assert "Last 7 days:" in one.text


async def test_the_validation_answer_and_the_logout_cookie(client: httpx.AsyncClient) -> None:
    bad = await client.get("/api/dashboard", params={"range": "1y"})
    await signed_in(client)
    bad = await client.get("/api/dashboard", params={"range": "1y"})
    assert bad.status_code == 422
    (error,) = bad.json()["detail"]
    assert set(error) == {"type", "loc", "msg"}
    assert error["loc"] == ["query", "range"]
    wrong = await client.post("/login", data={"username": "asha", "password": "wrong-pass-1"})
    assert '<p class="message" role="alert">Wrong name or password.</p>' in wrong.text
    out = await client.post("/logout", data={})
    assert "Path=/" in out.headers["set-cookie"]
    token = await client.post("/api/login", json={"username": "asha", "password": PASSWORD})
    api_out = await client.post("/api/logout", headers={"X-CSRF-Token": token.json()["csrf_token"]})
    assert api_out.status_code == 204
    assert "Path=/" in api_out.headers["set-cookie"]


async def test_the_documented_responses(client: httpx.AsyncClient) -> None:
    spec = (await client.get("/api/openapi.json")).json()

    def codes(path: str, method: str) -> list[str]:
        return sorted(spec["paths"][path][method]["responses"])

    assert codes("/api/login", "post") == ["200", "400", "401", "410", "422", "429", "503"]
    assert spec["paths"]["/api/login"]["post"]["responses"]["429"]["description"] == (
        "too many failed logins; try again in 15 minutes"
    )
    assert codes("/api/logout", "post") == ["204", "401", "403"]
    review = spec["paths"]["/api/investigations/{investigation_id}/reviews"]["post"]["responses"]
    assert sorted(review) == ["201", "400", "401", "403", "404", "409", "422"]
    assert review["422"] == {
        "description": "the body is invalid, or the review is refused (the reason in detail)",
        "content": {"application/json": {"schema": {"anyOf": [
            {"$ref": "#/components/schemas/HTTPValidationError"},
            {"type": "object", "required": ["detail"],
             "properties": {"detail": {"type": "string"}}},
        ]}}},
    }  # fmt: skip
    for path in ("/api/investigations", "/api/rules", "/api/entities", "/api/cost",
                 "/api/dashboard", "/api/health"):  # fmt: skip
        assert "401" in codes(path, "get"), path
    one = "/api/investigations/{investigation_id}"
    assert {"401", "404"} <= set(codes(one, "get"))
    raw = [p for p in spec["paths"] if p.endswith("/raw")]
    for path in raw:
        assert {"401", "404"} <= set(codes(path, "get")), path


async def test_the_api_review_body_limits(client: httpx.AsyncClient, seeded: AsyncEngine) -> None:
    (a,) = await first(seeded)
    token = (await client.post("/api/login", json={"username": "asha", "password": PASSWORD})
             ).json()["csrf_token"]  # fmt: skip
    url = f"/api/investigations/{a.id}/reviews"

    async def post(body: dict[str, Any]) -> int:
        got = await client.post(url, json={"seen_review": None, "seen_version": a.version, **body},
                                headers={"X-CSRF-Token": token})  # fmt: skip
        return got.status_code

    for outcome in ("benign_expected", "benign_policy", "rule_false_positive", "true_positive",
                    "inconclusive"):  # fmt: skip
        assert await post({"action": "follow_up", "outcome": outcome, "note": "n"}) in (201, 409)
    assert await post({"action": "note", "note": ""}) == 422
    assert await post({"action": "note", "note": "x" * 4001}) == 422
    assert await post({"action": "follow_up", "note": ""}) == 422
    assert await post({"action": "follow_up", "note": "x" * 4001}) == 422
    assert await post({"action": "note", "note": "n", "seen_review": 0}) == 422
    assert await post({"action": "note", "note": "n", "seen_version": -1}) == 422
    assert await post({"action": "follow_up", "seen_review": 0}) == 422
    assert await post({"action": "follow_up", "seen_version": -1}) == 422
    assert re.fullmatch(r"20\d|409", str(await post({"action": "note", "note": "x" * 4000})))


async def test_the_last_gaps(client: httpx.AsyncClient, seeded: AsyncEngine) -> None:
    """The mutation run's last survivors (2026-10-22): each one pinned here."""
    a, b = await first(seeded, 2)
    token = (await client.post("/api/login", json={"username": "asha", "password": PASSWORD})
             ).json()["csrf_token"]  # fmt: skip
    headers = {"X-CSRF-Token": token}
    gone = await client.get(f"/api/investigations/{uuid.uuid4()}")
    assert (gone.status_code, gone.json()) == (404, {"detail": "no such investigation"})
    bad = await client.get("/api/dashboard", params={"range": "1y"})
    (error,) = bad.json()["detail"]
    assert error["type"] == "literal_error"
    assert error["msg"].startswith("Input should be '24h'")
    # the request model refuses first: a list of errors, not the review's own sentence
    url = f"/api/investigations/{a.id}/reviews"
    long = await client.post(url, headers=headers, json={
        "action": "note", "note": "x" * 4001, "seen_review": None,
        "seen_version": a.version})  # fmt: skip
    assert long.json()["detail"][0]["loc"] == ["body", "note", "note"]
    long = await client.post(url, headers=headers, json={
        "action": "follow_up", "note": "x" * 4001, "seen_review": None,
        "seen_version": a.version})  # fmt: skip
    assert long.json()["detail"][0]["loc"] == ["body", "follow_up", "note"]
    # the smallest allowed values pass the model (then the review decides)
    one = await client.post(url, headers=headers, json={
        "action": "note", "note": "x", "seen_review": None, "seen_version": a.version})  # fmt: skip
    assert one.status_code == 201
    short = await client.post(url, headers=headers, json={
        "action": "follow_up", "note": "y", "seen_review": None,
        "seen_version": a.version})  # fmt: skip
    assert short.status_code in (201, 409)
    edge = await client.post(f"/api/investigations/{b.id}/reviews", headers=headers, json={
        "action": "follow_up", "seen_review": 1, "seen_version": 0})  # fmt: skip
    assert edge.status_code == 409  # valid input, but not what is current: a conflict, not 422
    note = await client.post(f"/api/investigations/{b.id}/reviews", headers=headers, json={
        "action": "note", "note": "z", "seen_review": 1, "seen_version": 0})  # fmt: skip
    assert note.status_code != 422  # the smallest allowed values pass the note's model too
    # the pattern form when nothing changed: the count alone
    await signed_in(client)
    form = csrf((await client.get("/patterns")).text)
    async with seeded.connect() as conn:
        b = await queries.investigation(conn, b.id)  # type: ignore[assignment]
    done = await client.post("/patterns/review", data={
        "items": [f"{b.id}:{b.version}:{b.latest_review}"], "outcome": "benign_expected",
        "csrf_token": form})  # fmt: skip
    assert '<p class="message" role="status">1 reviewed.</p>' in done.text


async def test_asking_and_confirming_exactly(
    client: httpx.AsyncClient,
    seeded: AsyncEngine,
    migrated_engine: AsyncEngine,
    web_engine: AsyncEngine,
) -> None:
    from argus.llm.privacy import Privacy, load_policy
    from tests.unit.llm.conftest import ASSETS

    await with_dossiers(seeded, migrated_engine, 1)
    (a,) = await first(seeded)
    app = create_app(web_engine, clock=lambda: NOW + timedelta(hours=1),
                     privacy=Privacy.build(load_policy(), ASSETS))  # fmt: skip
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=BASE, headers=SAME_ORIGIN
    ) as http:
        await signed_in(http)
        token = csrf((await http.get(f"/investigations/{a.id}")).text)
        asked = await http.post(f"/investigations/{a.id}/assess", data={"csrf_token": token})
    assert asked.status_code == 303
    ids = await propose(seeded, 1, "engine@1#k", "benign_expected", start=1)
    await signed_in(client)
    listing = (await client.get("/proposals")).text
    token = csrf(listing)
    group = html.unescape(listing.split('name="group" value="')[1].split('"')[0])
    done = await client.post("/proposals/confirm",
                             data={"csrf_token": token, "group": group,
                                   "ids": str(ids[0])})  # fmt: skip
    assert done.status_code == 303
    async with seeded.connect() as conn:
        audit = (await conn.execute(text(
            "SELECT target_type FROM audit_events"
            " WHERE action = 'assessment.request'"))).scalar()  # fmt: skip
        notes = (await conn.execute(text(
            "SELECT note FROM review_events WHERE assessment_id = :i"),
            {"i": ids[0]})).scalars().all()  # fmt: skip
    assert audit == "investigation"
    assert notes == ["confirmed with its group"]


async def test_an_unknown_name_with_the_dummy_password_is_refused(
    client: httpx.AsyncClient,
) -> None:
    """The dummy hash makes an unknown name cost as much as a wrong password; its own password
    must not let anyone in, nor crash the login (no row behind it)."""
    got = await client.post(
        "/api/login", json={"username": "nobody", "password": "argus-dummy-password"}
    )
    assert got.status_code == 401


async def test_api_bodies_are_strictly_typed(
    client: httpx.AsyncClient, seeded: AsyncEngine
) -> None:
    """Schemathesis (2026-10-22): ``"seen_version": true`` was taken as 1 and saved a review."""
    (a,) = await first(seeded)
    token = (await client.post("/api/login", json={"username": "asha", "password": PASSWORD})
             ).json()["csrf_token"]  # fmt: skip
    url = f"/api/investigations/{a.id}/reviews"
    for body in ({"action": "note", "note": "n", "seen_review": None, "seen_version": True},
                 {"action": "note", "note": "n", "seen_review": None, "seen_version": "1"},
                 {"action": "note", "note": "n", "seen_review": True, "seen_version": a.version},
                 {"action": "follow_up", "seen_review": False,
                  "seen_version": a.version}):  # fmt: skip
        got = await client.post(url, json=body, headers={"X-CSRF-Token": token})
        assert got.status_code == 422, body
    assert (await client.post("/api/login", json={"username": "asha", "password": 1})
            ).status_code == 422  # fmt: skip
    whole = {"action": "note", "note": "n", "seen_review": None, "seen_version": float(a.version)}
    assert (await client.post(url, json=whole, headers={"X-CSRF-Token": token})).status_code == 201
    # 1.0 is a JSON integer (JSON Schema): accepted, as the documented schema says
    async with seeded.connect() as conn:
        assert await conn.scalar(text("SELECT count(*) FROM review_events")) == 1  # the 1.0 one


async def test_dashboard_days_are_iso_only(client: httpx.AsyncClient) -> None:
    """Schemathesis (2026-10-22): "0" was read as a Unix time (1970-01-01) and accepted."""
    await signed_in(client)
    for day in ("0", "1700000000", "2026-1-1", "21-10-2026", "2026-10-21T00:00"):
        got = await client.get("/api/dashboard", params={"start": day, "end": "2026-10-21"})
        assert got.status_code == 422, day
    ok = await client.get("/api/dashboard", params={"start": "2026-10-20", "end": "2026-10-21"})
    assert ok.status_code == 200


def test_each_request_commits_before_its_response() -> None:
    """The intermittent HTTPS test (10-21/22): a login's session was committed after the 303
    was sent, so the next request sometimes found no session."""
    from argus.web.app import Conn

    (dependency,) = Conn.__metadata__
    assert dependency.scope == "function"


async def test_the_type_refusals_word_for_word(
    client: httpx.AsyncClient, seeded: AsyncEngine
) -> None:
    (a,) = await first(seeded)
    token = (await client.post("/api/login", json={"username": "asha", "password": PASSWORD})
             ).json()["csrf_token"]  # fmt: skip
    got = await client.post(f"/api/investigations/{a.id}/reviews", headers={"X-CSRF-Token": token},
                            json={"action": "note", "note": "n", "seen_review": None,
                                  "seen_version": True})  # fmt: skip
    assert got.json()["detail"][0]["msg"] == "Value error, a whole number"
    day = await client.get("/api/dashboard", params={"start": "0", "end": "2026-10-21"})
    assert day.json()["detail"][0]["msg"] == "Value error, a day as YYYY-MM-DD"
