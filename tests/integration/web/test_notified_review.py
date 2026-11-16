"""AR4b after the review (D-181) through ``/api/v1``, on the web's own
database login: a notice recorded by mistake is withdrawn by a manager (and only a manager, with
the CSRF token, on a case that is notified); the new destinations a notified device reached are
listed on the case page; the block list is only counted, never built, for the case page; the
dashboard's table shows the reminders that are due; and an investigation of a case that ended
keeps its "known" mark in the API."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases import blocklist
from argus.cases.model import Indicator
from tests.integration.web.b3_support import V1, World, make_world, post, sign_in

pytestmark = pytest.mark.integration

SERVER = "77.221.155.150"
HOST = "10.0.0.1"


@pytest.fixture
async def world(
    seeded: AsyncEngine, web_engine: AsyncEngine, migrated_engine: AsyncEngine, tmp_path: Path
) -> World:
    return await make_world(seeded, web_engine, migrated_engine, tmp_path)


def told(**more: object) -> dict[str, object]:
    body: dict[str, object] = {"expected_version": 1, "told": "Hostel 5 warden", "how": "phone"}
    body.update(more)
    return body


def withdrawn(**more: object) -> dict[str, object]:
    body: dict[str, object] = {"expected_version": 2, "reason": "recorded on the wrong case"}
    body.update(more)
    return body


async def a_case(world: World) -> object:
    return await world.open_case(
        1, title="Regular beaconing from a campus host",
        indicators=(Indicator("ip", HOST, "actor"), Indicator("ip", SERVER, "c2")),
    )  # fmt: skip


# --------------------------------------------------------------------------- withdrawing


async def test_a_manager_withdraws_a_notice_recorded_by_mistake(world: World) -> None:
    case = await a_case(world)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        assert (await post(http, csrf, f"/cases/{case}/notices", told())).status_code == 200
        before = (await http.get(f"{V1}/cases/{case}")).json()["known"]
        assert before["withdraw_notice"]["enabled"] is True
        done = await post(http, csrf, f"/cases/{case}/notices/withdraw", withdrawn(who="Mina"))
        assert done.status_code == 200, done.text
        assert done.json()["case"]["version"] == 3
        assert done.json()["case"]["notified_at"] is None
        detail = (await http.get(f"{V1}/cases/{case}")).json()
        notified = (await http.get(f"{V1}/cases", params={"view": "notified"})).json()
        active = (await http.get(f"{V1}/cases", params={"view": "active"})).json()
    assert detail["known"]["notified_at"] is None
    assert detail["known"]["withdraw_notice"]["enabled"] is False
    assert "no notice to withdraw" in detail["known"]["withdraw_notice"]["why_not"]
    assert [(n["told"], n["withdrawn"]) for n in detail["known"]["notices"]] == [
        ("Hostel 5 warden", True)
    ]  # the notice stays as it was said
    assert notified["items"] == []
    assert [c["number"] for c in active["items"]] == [detail["case"]["number"]]  # active again
    events = await world.rows(
        "SELECT kind, details FROM case_events WHERE case_id = :c ORDER BY case_version", c=case
    )
    assert [e.kind for e in events] == ["opened", "notified", "notice_withdrawn"]
    assert events[2].details["by"] == "Mina"
    assert events[2].details["reason"] == "recorded on the wrong case"
    history = [h["text"] for h in detail["history"]]
    assert any("withdrew the owner notice" in t for t in history)


async def test_the_withdrawal_defaults_to_the_person_who_makes_it(world: World) -> None:
    case = await a_case(world)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        await post(http, csrf, f"/cases/{case}/notices", told())
        assert (await post(http, csrf, f"/cases/{case}/notices/withdraw", withdrawn())
                ).status_code == 200  # fmt: skip
    (event,) = await world.rows(
        "SELECT details FROM case_events WHERE case_id = :c AND kind = 'notice_withdrawn'", c=case
    )
    assert event.details["by"] == "Mina Manager"


async def test_a_withdrawal_is_a_managers_with_the_token_on_a_notified_case(world: World) -> None:
    case = await a_case(world)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        none_yet = await post(http, csrf, f"/cases/{case}/notices/withdraw",
                              withdrawn(expected_version=1))  # fmt: skip
        assert none_yet.status_code == 409  # no notice to withdraw
        assert none_yet.json()["code"] == "conflict"
        await post(http, csrf, f"/cases/{case}/notices", told())
        no_token = await http.post(f"{V1}/cases/{case}/notices/withdraw", json=withdrawn())
        assert no_token.status_code == 403
        assert no_token.json()["code"] == "csrf"
        stale = await post(http, csrf, f"/cases/{case}/notices/withdraw",
                           withdrawn(expected_version=1))  # fmt: skip
        assert stale.status_code == 409
        bad = await post(http, csrf, f"/cases/{case}/notices/withdraw", withdrawn(reason=""))
        assert bad.status_code == 422
        viewer = await sign_in(http, "vera")
        assert (await post(http, viewer, f"/cases/{case}/notices/withdraw", withdrawn())
                ).status_code == 403  # fmt: skip
        reviewer = await sign_in(http, "rita")  # may review, not manage cases
        assert (await post(http, reviewer, f"/cases/{case}/notices/withdraw", withdrawn())
                ).status_code == 403  # fmt: skip
    (row,) = await world.rows("SELECT notified_at FROM cases WHERE id = :c", c=case)
    assert row.notified_at is not None  # nothing of that was done


# --------------------------------------------------------------------------- the case page


async def test_the_new_destinations_are_listed_and_the_block_list_is_only_counted(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = await a_case(world)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        await post(http, csrf, f"/cases/{case}/notices", told())
        async with world.runtime.begin() as conn:  # the pass counts them (knownrun does this)
            await conn.execute(
                text("INSERT INTO case_known_keys (case_id, kind, value, source) VALUES"
                     " (:c, 'new_destination', 'ip:91.121.5.50', 'change'),"
                     " (:c, 'new_destination', 'domain:cdn.fresh-names.net', 'change'),"
                     " (:c, 'new_destination', 'ip:91.121.5.9', 'notice')"), {"c": case},
            )  # fmt: skip

        async def never(*_: object, **__: object) -> None:
            raise AssertionError("the case page builds the whole block list to count it")

        monkeypatch.setattr(blocklist, "build", never)
        detail = (await http.get(f"{V1}/cases/{case}")).json()
    known = detail["known"]
    assert known["new_destinations_total"] == 2  # those since the notice, not the seed's own
    assert sorted((d["kind"], d["value"]) for d in known["new_destinations"]) == [
        ("domain", "cdn.fresh-names.net"),
        ("ip", "91.121.5.50"),
    ]
    assert known["blocklist_entries"] == 1  # the one server


async def test_an_investigation_of_a_case_that_ended_is_still_known_in_the_api(
    world: World,
) -> None:
    case = await a_case(world)
    inv = world.investigations[0]  # the case's member
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        await post(http, csrf, f"/cases/{case}/notices", told())
        async with world.runtime.begin() as conn:
            await conn.execute(
                text("INSERT INTO case_known_matches (investigation_id, case_id, version,"
                     " outcome) SELECT :i, :c, i.version, 'known' FROM investigations i"
                     " WHERE i.id = :i"), {"i": inv, "c": case},
            )  # fmt: skip
        live = (await http.get(f"{V1}/investigations/{inv}")).json()
        assert live["investigation"]["known"]["outcome"] == "known"
        assert live["investigation"]["known"]["notified_at"] is not None
        await post(http, csrf, f"/cases/{case}/notices/withdraw", withdrawn())
        ended = (await http.get(f"{V1}/investigations/{inv}")).json()
    assert ended["investigation"]["known"]["outcome"] == "known"  # frozen: it does not come back
    assert ended["investigation"]["known"]["notified_at"] is None
    assert (
        ended["investigation"]["known"]["case_number"]
        == live["investigation"]["known"]["case_number"]
    )


# --------------------------------------------------------------------------- the dashboard


async def test_the_dashboards_notified_rows_list_the_reminders_that_are_due(
    world: World,
) -> None:
    case = await a_case(world)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        await post(http, csrf, f"/cases/{case}/notices", told())
        quiet = (await http.get(f"{V1}/dashboard")).json()
        assert quiet["notified"][0]["reminders"] == []
        async with world.runtime.begin() as conn:
            await conn.execute(
                text("INSERT INTO case_reminders (case_id, kind, why) VALUES (:c, 'notify_again',"
                     " 'Still active 7 days after the owner was told: consider telling the owner"
                     " again.')"), {"c": case},
            )  # fmt: skip
        api = (await http.get(f"{V1}/dashboard")).json()
    assert api["notified"][0]["reminders"] == ["notify_again"]
