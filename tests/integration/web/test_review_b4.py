"""Q-B4 independent review: repros on the real app that fail on the reviewed head
(docs/gates/q-b4-review.md)."""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.integration.web.conftest import log_in
from tests.integration.web.test_classic_switch import ON, an_investigation, make_client, rows

pytestmark = pytest.mark.integration


async def test_r1_a_classic_review_to_an_unhyphenated_id_writes_under_fallback(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    """``/investigations/<32 hex digits>/review`` reaches the review route (FastAPI parses the id)
    but not the switch's refusal (its pattern wants hyphens): under ``fallback`` it saves."""
    async with make_client(web_engine, ON) as http:
        csrf = await log_in(http)
        listed = await http.get("/api/investigations", params={"view": "all"})
        inv = listed.json()[0]
        body = {"csrf_token": csrf, "action": "note", "note": "written through the back door",
                "seen_version": str(inv["version"]), "seen_review": "", "outcome": ""}  # fmt: skip
        canonical = await http.post(f"/investigations/{inv['id']}/review", data=body)
        assert canonical.status_code == 403  # the switch's refusal, as built
        before = await rows(seeded)
        hexed = str(inv["id"]).replace("-", "")
        sneaked = await http.post(f"/investigations/{hexed}/review", data=body)
        after = await rows(seeded)
        async with seeded.connect() as conn:
            notes = (await conn.execute(text(
                "SELECT count(*) FROM review_events WHERE note = :n"),
                {"n": body["note"]})).scalar_one()  # fmt: skip
    assert (after, notes) == (before, 0), (before, after, notes, sneaked.status_code)
    assert sneaked.status_code == 403, sneaked.status_code


async def test_r3_the_classic_choice_is_not_set_by_a_same_site_page(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    """A page on a sibling host name (same site, other origin) can load ``/classic`` with the
    Strict session cookie attached; the answer sets the read-only cookie in the victim's browser."""
    async with make_client(web_engine, ON) as http:
        await log_in(http)
        assert await an_investigation(http)
        planted = await http.get("/classic", headers={"Sec-Fetch-Site": "same-site",
                                                      "Sec-Fetch-Mode": "no-cors",
                                                      "Sec-Fetch-Dest": "image"})  # fmt: skip
    assert "set-cookie" not in planted.headers, planted.headers.get("set-cookie")
