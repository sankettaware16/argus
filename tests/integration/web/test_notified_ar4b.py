"""AR4b (D-169, D-176) through ``/api/v1`` and the classic pages, on the web's own database login:
a person records that the owner was told and that a block was put on the network; a view-only
account and a request without the CSRF token are refused; a suspected case takes no notice; the
case page shows the record; the ready block list is a JSON, a CSV and an e-mail; a reminder is
dismissed; and the lists count new work and known work apart."""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases.model import Indicator
from tests.integration.web.b3_support import V1, World, headers, make_world, post, sign_in

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


async def a_case(world: World) -> object:
    return await world.open_case(
        1, title="Regular beaconing from a campus host",
        indicators=(Indicator("ip", HOST, "actor"), Indicator("ip", SERVER, "c2")),
    )  # fmt: skip


# --------------------------------------------------------------------------- recording


async def test_a_manager_records_that_the_owner_was_told_and_the_case_page_shows_it(
    world: World,
) -> None:
    case = await a_case(world)
    when = datetime.now(UTC) - timedelta(hours=5)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        done = await post(
            http, csrf, f"/cases/{case}/notices",
            told(at=when.isoformat(), note="she will bring the laptop in"),
        )  # fmt: skip
        assert done.status_code == 200, done.text
        assert done.json()["case"]["version"] == 2
        detail = (await http.get(f"{V1}/cases/{case}")).json()
        counts = (await http.get(f"{V1}/cases", params={"view": "notified"})).json()
        active = (await http.get(f"{V1}/cases", params={"view": "active"})).json()
    known = detail["known"]
    assert known["notified_at"] is not None
    assert known["managed"] is False  # no asset map here: unknown is personal
    assert known["alerts"] == 0
    assert known["line"].startswith("still active: 0 alerts in 1 day since the owner was notified")
    (notice,) = known["notices"]
    assert (notice["kind"], notice["told"], notice["how"]) == ("owner", "Hostel 5 warden", "phone")
    assert notice["by"] == "Mina Manager"
    assert notice["note"] == "she will bring the laptop in"
    assert known["notify"]["enabled"] is True  # a second notice is recordable
    assert known["block"]["enabled"] is True
    assert [c["number"] for c in counts["items"]] == [detail["case"]["number"]]
    assert counts["counts"]["notified"] == 1
    assert active["items"] == []  # a notified case leaves the active list
    assert active["counts"]["active"] == 0
    assert detail["case"]["attention"] is None
    events = await world.rows(
        "SELECT kind FROM case_events WHERE case_id = :c ORDER BY case_version", c=case
    )
    assert [e.kind for e in events] == ["opened", "notified"]
    (row,) = await world.rows("SELECT kind, told, how, managed, by_user_id FROM case_notices")
    assert (row.kind, row.told, row.how, row.managed) == (
        "owner",
        "Hostel 5 warden",
        "phone",
        False,
    )
    assert row.by_user_id == await world.user_id("mina")


async def test_a_second_notice_is_recorded_and_the_first_time_stays(world: World) -> None:
    case = await a_case(world)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        first = await post(http, csrf, f"/cases/{case}/notices", told())
        second = await post(
            http, csrf, f"/cases/{case}/notices",
            told(expected_version=2, told="the department head", how="in_person"),
        )  # fmt: skip
        assert first.status_code == second.status_code == 200
        detail = (await http.get(f"{V1}/cases/{case}")).json()
    assert [n["told"] for n in detail["known"]["notices"]] == [
        "Hostel 5 warden", "the department head",
    ]  # fmt: skip
    (row,) = await world.rows("SELECT notified_at FROM cases WHERE id = :c", c=case)
    (first_notice,) = await world.rows(
        "SELECT at FROM case_notices WHERE case_id = :c AND case_version = 2", c=case
    )  # fmt: skip
    assert row.notified_at == first_notice.at


async def test_a_view_only_account_and_a_missing_token_are_refused(world: World) -> None:
    case = await a_case(world)
    async with world.app() as http:
        viewer = await sign_in(http, "vera")
        refused = await post(http, viewer, f"/cases/{case}/notices", told())
        assert refused.status_code == 403
        assert refused.json()["code"] == "forbidden"
        refused = await post(http, viewer, f"/cases/{case}/blocks",
                             {"expected_version": 1, "by": "net", "where": "DNS"})  # fmt: skip
        assert refused.status_code == 403
        reviewer = await sign_in(http, "rita")  # may review, not manage cases
        assert (await post(http, reviewer, f"/cases/{case}/notices", told())).status_code == 403
    async with world.app() as http:
        await sign_in(http, "mina")
        nothing = await http.post(f"{V1}/cases/{case}/notices", json=told())  # no CSRF token
        assert nothing.status_code == 403
        assert nothing.json()["code"] == "csrf"
        wrong = await http.post(f"{V1}/cases/{case}/notices", json=told(),
                                headers=headers("not-the-token"))  # fmt: skip
        assert wrong.status_code == 403
    assert await world.rows("SELECT id FROM case_notices") == []
    (row,) = await world.rows("SELECT version, notified_at FROM cases WHERE id = :c", c=case)
    assert (row.version, row.notified_at) == (1, None)


async def test_the_viewer_sees_why_they_may_not_record_a_notice(world: World) -> None:
    case = await a_case(world)
    async with world.app() as http:
        await sign_in(http, "vera")
        detail = (await http.get(f"{V1}/cases/{case}")).json()
    assert detail["known"]["notify"]["enabled"] is False
    assert "manage_cases" in detail["known"]["notify"]["why_not"]


@pytest.mark.parametrize(
    ("body", "field"),
    [
        (told(told=""), "told"),
        (told(told="  "), "told"),
        (told(told="x" * 201), "told"),
        (told(how="carrier pigeon"), "how"),
        (told(at="2026-10-26T09:00:00"), "at"),  # no time zone
        (told(note="a\x00b"), "note"),
        (told(unknown="field"), "unknown"),
        ({"told": "owner", "how": "email"}, "expected_version"),
    ],
)
async def test_a_bad_notice_is_a_422_and_nothing_is_saved(
    world: World, body: dict[str, object], field: str
) -> None:
    case = await a_case(world)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        refused = await post(http, csrf, f"/cases/{case}/notices", body)
    assert refused.status_code == 422, refused.text
    assert field in refused.text
    assert await world.rows("SELECT id FROM case_notices") == []


async def test_a_notice_dated_in_the_future_or_long_ago_is_refused(world: World) -> None:
    case = await a_case(world)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        ahead = (datetime.now(UTC) + timedelta(hours=2)).isoformat()
        future = await post(http, csrf, f"/cases/{case}/notices", told(at=ahead))
        assert future.status_code == 422
        assert "future" in future.json()["detail"]
        back = (datetime.now(UTC) - timedelta(days=400)).isoformat()
        old = await post(http, csrf, f"/cases/{case}/notices", told(at=back))
        assert old.status_code == 422


async def test_a_case_that_moved_is_a_409_and_a_suspected_case_takes_no_notice(
    world: World,
) -> None:
    case = await a_case(world)
    suspected = await world.open_suspected(5)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        stale = await post(http, csrf, f"/cases/{case}/notices", told(expected_version=7))
        assert stale.status_code == 409
        refused = await post(http, csrf, f"/cases/{suspected}/notices", told())
        assert refused.status_code == 409
        assert refused.json()["detail"] == (
            "Only an open or assigned case can have a notice recorded; this one is suspected."
        )
        detail = (await http.get(f"{V1}/cases/{suspected}")).json()
    assert detail["known"] is None  # a suspected case has no owner to tell yet
    assert await world.rows("SELECT id FROM case_notices") == []


async def test_a_double_submit_is_one_notice(world: World) -> None:
    case = await a_case(world)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        one = await post(http, csrf, f"/cases/{case}/notices", told())
        two = await post(http, csrf, f"/cases/{case}/notices", told())  # the same version
    assert one.status_code == 200
    assert two.status_code == 409
    assert len(await world.rows("SELECT id FROM case_notices")) == 1


# --------------------------------------------------------------------------- blocks


async def test_a_block_is_recorded_and_the_line_says_the_device_is_still_infected(
    world: World,
) -> None:
    case = await a_case(world)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        await post(http, csrf, f"/cases/{case}/notices", told())
        blocked = await post(
            http, csrf, f"/cases/{case}/blocks",
            {"expected_version": 2, "by": "network team (Ravi)", "where": "DNS and the proxy"},
        )  # fmt: skip
        assert blocked.status_code == 200, blocked.text
        detail = (await http.get(f"{V1}/cases/{case}")).json()
    known = detail["known"]
    assert known["blocked_at"] is not None
    assert known["line"].startswith("blocked at the network; the device is still infected;")
    kinds = [(n["kind"], n["told"], n["how"]) for n in known["notices"]]
    assert ("block", "network team (Ravi)", "DNS and the proxy") in kinds
    history = [h["text"] for h in detail["history"]]
    assert any("recorded a block at the network" in t for t in history)
    assert any("recorded that the owner was told" in t for t in history)


# --------------------------------------------------------------------------- the block list


async def test_the_block_list_is_a_json_a_csv_and_an_email(world: World) -> None:
    case = await a_case(world)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        await post(http, csrf, f"/cases/{case}/notices", told())
        listing = (await http.get(f"{V1}/cases/{case}/blocklist")).json()
        as_csv = await http.get(f"{V1}/cases/{case}/blocklist.csv")
        as_text = await http.get(f"{V1}/cases/{case}/blocklist.txt")
    assert [(e["type"], e["value"]) for e in listing["entries"]] == [("address", SERVER)]
    assert listing["entries"][0]["evidence"] == "no outside record yet"  # nothing is made up
    assert listing["skipped"] == 0
    assert as_csv.headers["content-type"].startswith("text/csv")
    assert "attachment" in as_csv.headers["content-disposition"]
    assert as_csv.content.startswith(b"\xef\xbb\xbf")  # UTF-8 with a byte order mark: Excel
    rows = list(csv.reader(io.StringIO(as_csv.content.decode("utf-8-sig"))))
    assert rows[0][:2] == ["type", "value"]
    assert rows[1][:2] == ["address", SERVER]
    assert as_text.headers["content-type"].startswith("text/plain")
    assert "To the head of cybersecurity," in as_text.text
    assert SERVER in as_text.text
    assert "The owners were told on" in as_text.text
    assert HOST not in as_text.text  # a campus device is never a block


async def test_the_block_list_of_a_case_that_does_not_exist_is_a_404(world: World) -> None:
    async with world.app() as http:
        await sign_in(http, "vera")
        gone = await http.get(f"{V1}/cases/00000000-0000-0000-0000-000000000009/blocklist")
        assert gone.status_code == 404
        assert (await http.get(f"{V1}/cases/00000000-0000-0000-0000-000000000009/blocklist.csv")
                ).status_code == 404  # fmt: skip


# --------------------------------------------------------------------------- reminders


async def test_a_reminder_is_shown_and_a_manager_dismisses_it(world: World) -> None:
    case = await a_case(world)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        await post(http, csrf, f"/cases/{case}/notices", told())
        async with world.runtime.begin() as conn:  # the pass suggests it (knownrun does this)
            await conn.execute(
                text("INSERT INTO case_reminders (case_id, kind, why) VALUES (:c, 'notify_again',"
                     " 'Still active 7 days after the owner was told.')"), {"c": case},
            )  # fmt: skip
        detail = (await http.get(f"{V1}/cases/{case}")).json()
        assert [r["kind"] for r in detail["known"]["reminders"]] == ["notify_again"]
        gone = await post(http, csrf, f"/cases/{case}/reminders/notify_again/dismiss")
        assert gone.status_code == 200, gone.text
        again = await post(http, csrf, f"/cases/{case}/reminders/notify_again/dismiss")
        assert again.status_code == 404
        detail = (await http.get(f"{V1}/cases/{case}")).json()
        assert detail["known"]["reminders"] == []
        viewer = await sign_in(http, "vera")
        assert (await post(http, viewer, f"/cases/{case}/reminders/notify_again/dismiss")
                ).status_code == 403  # fmt: skip


async def test_a_second_notice_answers_the_notify_again_reminder(world: World) -> None:
    case = await a_case(world)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        await post(http, csrf, f"/cases/{case}/notices", told())
        async with world.runtime.begin() as conn:
            await conn.execute(
                text("INSERT INTO case_reminders (case_id, kind, why) VALUES (:c, 'notify_again',"
                     " 'Still active 7 days after the owner was told.')"), {"c": case},
            )  # fmt: skip
        await post(http, csrf, f"/cases/{case}/notices", told(expected_version=2))
        detail = (await http.get(f"{V1}/cases/{case}")).json()
    assert detail["known"]["reminders"] == []  # told again: nothing waits for a person


# --------------------------------------------------------------------------- the counts


async def test_the_counts_and_the_dashboard_count_new_and_known_apart(world: World) -> None:
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        counts = (await http.get(f"{V1}/counts")).json()
        assert counts["known"] == 0
        api = (await http.get(f"{V1}/dashboard")).json()
        assert api["kpis"]["known"] == 0
        assert api["notified"] == []
        assert csrf  # the session is a manager's
