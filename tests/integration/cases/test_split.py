"""``CaseService.split`` against Postgres (D-211): a suggested case that grouped two devices (case 6
of the live example, in miniature) is split so each device has its own case; the moved
investigations are never in no case, the source keeps its C2 and indicator rows and loses only the
moved device's actor row, a removed row can come back, the pieces replay to the stored cases, the
watch and the known infection see the split, and concurrent changes neither deadlock nor lose a
write."""

from __future__ import annotations

import asyncio
import ipaddress
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.assets.classify import IpClassifier
from argus.cases import knownrun, splitting
from argus.cases.machine import (
    CaseRefused,
    Confirm,
    Link,
    Notify,
    Open,
    Take,
    Unlink,
    replay,
    same_case,
)
from argus.cases.model import Actor, Case, Indicator, Member
from argus.cases.service import CaseService, Split
from tests.integration.cases.conftest import Person, investigation
from tests.integration.cases.knownkit import context as known_context

pytestmark = pytest.mark.integration

A = "10.201.7.11"  # the Amadey host, whose owner the CISO told
B = "10.152.49.26"  # a second device, not yet reviewed
C = "10.77.3.4"
S = "158.94.208.81"  # the server both reached
CLASSIFIER = IpClassifier(None, ())


@dataclass(frozen=True)
class Six:
    """Case 6 in miniature: two investigations of device A, one of device B, one server."""

    case: uuid.UUID
    a1: uuid.UUID
    a2: uuid.UUID
    b1: uuid.UUID


async def make_six(
    owner: AsyncEngine,
    runtime: AsyncEngine,
    *,
    suspected: bool = True,
    person: Person | None = None,
) -> Six:
    a1 = await investigation(owner, rule="beacon", actor=(("source.ip", A),), entities=(("ip", S),))
    a2 = await investigation(owner, rule="download", actor=(("source.ip", A),),
                             entities=(("ip", S),), day=1)  # fmt: skip
    b1 = await investigation(owner, rule="beacon", actor=(("source.ip", B),), entities=(("ip", S),))
    members = (Member(a1, "actor", A), Member(a2, "actor", A), Member(b1, "actor", B))
    marks = (Indicator("ip", A, "actor"), Indicator("ip", B, "actor"),
             Indicator("ip", S, "indicator"))  # fmt: skip
    async with runtime.begin() as conn:
        service = await CaseService.start(conn)
        if suspected:
            applied = await service.open(
                Actor.argus("raise"),
                Open("Several campus devices reach outside infrastructure flagged by threat intel",
                     "high", "raised", members, marks, suspected=True,
                     attention="ARGUS suggests this case: 2 devices reached one server."),
            )  # fmt: skip
        else:
            assert person is not None
            applied = await service.open(
                person.actor(), Open("Regular beaconing from campus hosts", "high", "person",
                                     members, marks),
            )  # fmt: skip
    return Six(applied.case.id, a1, a2, b1)


async def do_split(
    engine: AsyncEngine, person: Person, case: uuid.UUID, ids: Sequence[uuid.UUID], *,
    into: uuid.UUID | None = None, title: str | None = "Hostel device", severity: str = "medium",
    reason: str = "two separate devices", version: int | None = None,
) -> Split:  # fmt: skip
    async with engine.begin() as conn:
        service = await CaseService.start(conn)
        return await service.split(
            person.actor(), case, ids, reason=reason, carry=splitting.carrier(conn, CLASSIFIER),
            expected_version=version, title=None if into else title,
            severity=severity, into_id=into,  # type: ignore[arg-type]
        )  # fmt: skip


async def held(engine: AsyncEngine, case: uuid.UUID) -> set[uuid.UUID]:
    async with engine.connect() as conn:
        found = await conn.execute(
            text("SELECT investigation_id FROM case_members WHERE case_id = :c"
                 " AND removed_at IS NULL"), {"c": case},
        )  # fmt: skip
        return set(found.scalars())


async def marks(engine: AsyncEngine, case: uuid.UUID) -> set[tuple[str, str, str]]:
    async with engine.connect() as conn:
        found = await conn.execute(
            text("SELECT kind, value, role FROM case_indicators WHERE case_id = :c"
                 " AND removed_at IS NULL"), {"c": case},
        )  # fmt: skip
        return {(r.kind, r.value, r.role) for r in found}


async def stored(engine: AsyncEngine, case: uuid.UUID) -> tuple[Case, list[str]]:
    async with engine.connect() as conn:
        service = await CaseService.start(conn)
        found = await service.get(case)
        assert found is not None
        events = await service.events(case)
        assert same_case(replay(events), found), "the events no longer rebuild the case"
        return found, [e.kind for e in events]


async def events_of(engine: AsyncEngine, case: uuid.UUID, kind: str) -> list[dict[str, object]]:
    async with engine.connect() as conn:
        found = await conn.execute(
            text("SELECT details FROM case_events WHERE case_id = :c AND kind = :k"
                 " ORDER BY case_version"), {"c": case, "k": kind},
        )  # fmt: skip
        return [dict(r.details) for r in found]


async def in_one_case_each(engine: AsyncEngine) -> bool:
    async with engine.connect() as conn:
        found = await conn.execute(
            text("SELECT investigation_id FROM case_members WHERE removed_at IS NULL"
                 " GROUP BY 1 HAVING count(*) > 1")
        )  # fmt: skip
        return found.first() is None


# --------------------------------------------------------------------------- into a new case


async def test_a_device_moves_into_a_new_case_and_the_source_keeps_the_server(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    six = await make_six(migrated_engine, app_engine)
    done = await do_split(app_engine, people["asha"], six.case, [six.b1], severity="high",
                          version=1)  # fmt: skip
    source, kinds = await stored(app_engine, six.case)
    target, target_kinds = await stored(app_engine, done.target.case.id)

    assert kinds == ["suspected", "unlinked"]
    assert source.version == 2
    assert source.state == "suspected"  # a split moves nothing along the lifecycle
    assert source.members == frozenset({six.a1, six.a2})
    assert await marks(app_engine, six.case) == {
        ("ip", A, "actor"), ("ip", S, "indicator"),  # the server is a fact of both cases
    }  # fmt: skip
    assert done.carried.leaving == (Indicator("ip", B, "actor"),)
    assert done.carried.staying == ()

    assert target_kinds == ["opened"]
    assert done.new
    assert target.state == "open"
    assert target.cause == "person"
    assert target.severity == "high"
    assert target.number == done.target.case.number != source.number
    assert target.kibana_wait is not None  # like `argus case open`: waits for someone who may
    assert target.members == frozenset({six.b1})
    assert await marks(app_engine, target.id) == {("ip", B, "actor"), ("ip", S, "indicator")}
    assert await in_one_case_each(app_engine)


async def test_the_removed_rows_and_the_events_say_what_moved_and_why(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    six = await make_six(migrated_engine, app_engine)
    done = await do_split(app_engine, people["asha"], six.case, [six.b1])
    (out,) = await events_of(app_engine, six.case, "unlinked")
    assert out == {
        "target": str(done.target.case.id),
        "reason": "two separate devices",
        "set": {},
        "members": {"added": [], "removed": [str(six.b1)]},
        "indicators_removed": [["ip", B, "actor"]],
    }
    (opened,) = await events_of(app_engine, done.target.case.id, "opened")
    assert opened["split_from"] == str(six.case)
    number = done.source.case.number
    assert opened["members"] == {
        "added": [[str(six.b1), "person", f"case:{number}"]],
        "removed": [],
    }
    async with migrated_engine.connect() as conn:  # nothing is deleted: the row says when it left
        gone = (
            await conn.execute(
                text("SELECT removed_version, removed_at IS NOT NULL AS dated FROM case_indicators"
                     " WHERE case_id = :c AND value = :v"), {"c": six.case, "v": B},
            )
        ).one()  # fmt: skip
        member = (
            await conn.execute(
                text("SELECT removed_version FROM case_members WHERE case_id = :c"
                     " AND investigation_id = :i"), {"c": six.case, "i": six.b1},
            )
        ).scalar_one()  # fmt: skip
        audited = (
            await conn.execute(
                text("SELECT actor, details FROM audit_events WHERE action = 'case.unlinked'")
            )
        ).one()  # fmt: skip
    assert (gone.removed_version, gone.dated, member) == (2, True, 2)
    assert audited.actor == f"user:{people['asha'].user_id}"
    assert audited.details["via"] == "test"


async def test_a_new_case_carries_the_actors_of_what_it_took_and_the_servers_they_touch(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """The moved investigation's own device goes to the target even when the source never held it
    as an actor, and a server it does not touch is not copied."""
    other = Indicator("ip", "203.0.113.9", "c2")
    six = await make_six(migrated_engine, app_engine)
    async with app_engine.begin() as conn:  # the source also holds a server only device A reached
        await (await CaseService.start(conn)).apply(
            people["asha"].actor(), six.case, Link((), (other,)), expected_version=None
        )
    c1 = await investigation(migrated_engine, actor=(("source.ip", C),), entities=(("ip", S),))
    async with app_engine.begin() as conn:
        await (await CaseService.start(conn)).apply(
            people["asha"].actor(), six.case, Link((Member(c1, "person"),)), expected_version=None
        )
    done = await do_split(app_engine, people["asha"], six.case, [c1])
    assert done.carried.leaving == ()  # the source never held C as an actor
    assert await marks(app_engine, done.target.case.id) == {
        ("ip", C, "actor"), ("ip", S, "indicator"),  # not 203.0.113.9: c1 did not reach it
    }  # fmt: skip
    assert ("ip", other.value, "c2") in await marks(app_engine, six.case)


# --------------------------------------------------------------------------- into an existing case


async def test_a_device_moves_into_an_existing_case(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    six = await make_six(migrated_engine, app_engine)
    mine = await investigation(migrated_engine, actor=(("source.ip", C),))
    async with app_engine.begin() as conn:
        there = (
            await (await CaseService.start(conn)).open(
                people["ravi"].actor(),
                Open(
                    "Another device",
                    "low",
                    "person",
                    (Member(mine, "person"),),
                    (Indicator("ip", C, "actor"),),
                ),
            )
        ).case
    done = await do_split(app_engine, people["asha"], six.case, [six.b1], into=there.id)
    assert not done.new
    target, kinds = await stored(app_engine, there.id)
    assert kinds == ["opened", "linked"]
    assert target.members == frozenset({mine, six.b1})
    assert await marks(app_engine, there.id) == {
        ("ip", C, "actor"), ("ip", B, "actor"), ("ip", S, "indicator"),
    }  # fmt: skip
    (linked,) = await events_of(app_engine, there.id, "linked")
    assert linked["split_from"] == str(six.case)
    (out,) = await events_of(app_engine, six.case, "unlinked")
    assert out["target"] == str(there.id)
    assert (await stored(app_engine, six.case))[0].members == frozenset({six.a1, six.a2})
    assert await in_one_case_each(app_engine)


async def test_a_closed_target_and_the_source_itself_are_refused_and_nothing_changes(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    six = await make_six(migrated_engine, app_engine)
    other = await make_six(migrated_engine, app_engine)
    async with migrated_engine.begin() as conn:  # a closed case, as the owner can make one
        await conn.execute(text("ALTER TABLE cases DISABLE TRIGGER USER"))
        await conn.execute(
            text("UPDATE cases SET state = 'closed', closed_at = now(), closure_reason ="
                 " 'created_in_error' WHERE id = :c"), {"c": other.case},
        )  # fmt: skip
        await conn.execute(text("ALTER TABLE cases ENABLE TRIGGER USER"))
    with pytest.raises(CaseRefused, match="closed"):
        await do_split(app_engine, people["asha"], six.case, [six.b1], into=other.case)
    with pytest.raises(CaseRefused, match="they are in"):
        await do_split(app_engine, people["asha"], six.case, [six.b1], into=six.case)
    with pytest.raises(CaseRefused, match="no such case"):
        await do_split(app_engine, people["asha"], six.case, [six.b1], into=uuid.uuid4())
    source, kinds = await stored(app_engine, six.case)
    assert (source.version, kinds) == (1, ["suspected"])
    assert source.members == frozenset({six.a1, six.a2, six.b1})  # the unlink was rolled back
    assert len(await marks(app_engine, six.case)) == 3


async def test_exactly_one_of_a_title_and_a_target(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    six = await make_six(migrated_engine, app_engine)
    async with app_engine.connect() as conn:
        service = await CaseService.start(conn)
        carry = splitting.carrier(conn, CLASSIFIER)
        for title, into in ((None, None), ("t", six.case)):
            with pytest.raises(CaseRefused, match="not both and not neither"):
                await service.split(people["asha"].actor(), six.case, [six.b1], reason="r",
                                    carry=carry, expected_version=None, title=title,
                                    into_id=into)  # fmt: skip


# ------------------------------------------------------------------------- refusals leave no trace


@pytest.mark.parametrize(
    ("pick", "message"),
    [
        ("all", "is a merge"),
        ("none", "name the investigations"),
        ("stranger", "is not in this case"),
        ("twice", "named once"),
    ],
)
async def test_a_refused_split_changes_nothing(
    pick: str, message: str, migrated_engine: AsyncEngine, app_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    six = await make_six(migrated_engine, app_engine)
    ids = {
        "all": [six.a1, six.a2, six.b1], "none": [], "stranger": [uuid.uuid4()],
        "twice": [six.b1, six.b1],
    }[pick]  # fmt: skip
    with pytest.raises(CaseRefused, match=message):
        await do_split(app_engine, people["asha"], six.case, ids)
    source, kinds = await stored(app_engine, six.case)
    assert (source.version, kinds) == (1, ["suspected"])
    async with migrated_engine.connect() as conn:
        count = (await conn.execute(text("SELECT count(*) FROM cases"))).scalar_one()
    assert count == 1


async def test_a_reason_is_required_and_a_bad_title_rolls_the_unlink_back(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    six = await make_six(migrated_engine, app_engine)
    with pytest.raises(CaseRefused, match="reason is required"):
        await do_split(app_engine, people["asha"], six.case, [six.b1], reason="  ")
    with pytest.raises(CaseRefused, match="title is required"):
        await do_split(app_engine, people["asha"], six.case, [six.b1], title="")
    source, kinds = await stored(app_engine, six.case)
    assert (source.version, kinds) == (1, ["suspected"])  # the unlink happened first, then undone
    assert await held(app_engine, six.case) == {six.a1, six.a2, six.b1}


async def test_only_a_person_who_may_manage_cases_splits_and_the_version_is_checked(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    six = await make_six(migrated_engine, app_engine)
    async with app_engine.begin() as conn:
        service = await CaseService.start(conn)
        carry = splitting.carrier(conn, CLASSIFIER)
        for actor in (Actor.argus("watch"), people["ravi"].actor(frozenset({"view", "review"}))):
            with pytest.raises(CaseRefused) as info:
                await service.split(actor, six.case, [six.b1], reason="r", carry=carry,
                                    expected_version=None, title="t")  # fmt: skip
            assert info.value.code == "forbidden"
    with pytest.raises(CaseRefused, match="changed meanwhile"):
        await do_split(app_engine, people["asha"], six.case, [six.b1], version=7)
    async with app_engine.begin() as conn:
        with pytest.raises(CaseRefused, match="split"):  # not through apply
            await (await CaseService.start(conn)).apply(
                people["asha"].actor(),
                six.case,
                Unlink((six.b1,), "r", uuid.uuid4()),
                expected_version=None,
            )


async def test_a_closed_case_cannot_split(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    six = await make_six(migrated_engine, app_engine)
    async with migrated_engine.begin() as conn:
        await conn.execute(text("ALTER TABLE cases DISABLE TRIGGER USER"))
        await conn.execute(
            text("UPDATE cases SET state = 'closed', closed_at = now(), closure_reason ="
                 " 'created_in_error' WHERE id = :c"), {"c": six.case},
        )  # fmt: skip
        await conn.execute(text("ALTER TABLE cases ENABLE TRIGGER USER"))
    with pytest.raises(CaseRefused, match="closed"):
        await do_split(app_engine, people["asha"], six.case, [six.b1])


# --------------------------------------------------------------------------- shared devices


async def test_a_device_a_remaining_investigation_also_involves_stays_and_is_said(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """Two investigations of A: moving one of them cannot take A's row with it."""
    six = await make_six(migrated_engine, app_engine)
    done = await do_split(app_engine, people["asha"], six.case, [six.a2])
    assert done.carried.leaving == ()
    assert done.carried.staying == (Indicator("ip", A, "actor"),)
    assert ("ip", A, "actor") in await marks(app_engine, six.case)
    assert ("ip", A, "actor") in await marks(app_engine, done.target.case.id)  # and the target
    (out,) = await events_of(app_engine, six.case, "unlinked")
    assert "indicators_removed" not in out


async def test_a_dns_investigation_that_lists_both_devices_keeps_them_both_on_the_source(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """A rule that groups by the domain lists every source address in its key (D-172): the
    investigation that stays involves both devices, so neither actor row can leave."""
    six = await make_six(migrated_engine, app_engine)
    dns = await investigation(migrated_engine, rule="dns", actor=(("source.ip", A),))
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("UPDATE investigations SET group_key = CAST(:k AS text) WHERE id = :i"),
            {"k": f'[["source.ip",["{A}","{B}"]]]', "i": dns},
        )
    async with app_engine.begin() as conn:
        await (await CaseService.start(conn)).apply(
            people["asha"].actor(), six.case, Link((Member(dns, "person"),)), expected_version=None
        )
    campus = IpClassifier(None, (ipaddress.ip_network("10.0.0.0/8"),))  # the addresses count
    async with app_engine.begin() as conn:
        service = await CaseService.start(conn)
        done = await service.split(
            people["asha"].actor(), six.case, [six.b1], reason="r",
            carry=splitting.carrier(conn, campus), expected_version=None, title="t",
        )  # fmt: skip
    assert done.carried.leaving == ()
    assert Indicator("ip", B, "actor") in done.carried.staying


# --------------------------------------------------------------------------- a row can come back


async def test_an_investigation_and_its_device_move_out_and_back_without_a_unique_violation(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    six = await make_six(migrated_engine, app_engine)
    b2 = await investigation(migrated_engine, rule="download", actor=(("source.ip", B),),
                             entities=(("ip", S),), day=1)  # fmt: skip
    async with app_engine.begin() as conn:
        await (await CaseService.start(conn)).apply(
            people["asha"].actor(), six.case, Link((Member(b2, "actor", B),)), expected_version=None
        )
    first = await do_split(app_engine, people["asha"], six.case, [six.b1, b2])
    new_case = first.target.case.id
    assert ("ip", B, "actor") not in await marks(app_engine, six.case)
    # undo: one of the two goes back to the source, which once held both as members and B as actor
    back = await do_split(app_engine, people["asha"], new_case, [six.b1], into=six.case)
    assert back.carried.staying == (Indicator("ip", B, "actor"),)  # b2 stays there, B too
    source, kinds = await stored(app_engine, six.case)
    assert kinds == ["suspected", "linked", "unlinked", "linked"]
    assert source.members == frozenset({six.a1, six.a2, six.b1})
    assert ("ip", B, "actor") in await marks(app_engine, six.case)
    async with migrated_engine.connect() as conn:
        rows = (
            await conn.execute(
                text("SELECT added_version, added_by, source, removed_at FROM case_indicators"
                     " WHERE case_id = :c AND kind = 'ip' AND value = :v"), {"c": six.case, "v": B},
            )
        ).all()  # fmt: skip
        member = (
            await conn.execute(
                text("SELECT link, link_value, added_version, removed_version FROM case_members"
                     " WHERE case_id = :c AND investigation_id = :i"), {"c": six.case, "i": six.b1},
            )
        ).all()  # fmt: skip
    assert len(rows) == 1  # one row for the key: it was revived, not duplicated
    assert rows[0].added_version == source.version
    assert rows[0].added_by == f"user:{people['asha'].user_id}"
    assert rows[0].source == "person"
    assert rows[0].removed_at is None
    assert len(member) == 1
    assert (member[0].link, member[0].added_version, member[0].removed_version) == (
        "person", source.version, None,
    )  # fmt: skip
    assert await in_one_case_each(app_engine)
    again, _ = await stored(app_engine, new_case)
    assert again.members == frozenset({b2})


async def test_an_indicator_that_left_comes_back_with_the_role_it_is_given(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    six = await make_six(migrated_engine, app_engine)
    await do_split(app_engine, people["asha"], six.case, [six.b1])
    asha = people["asha"].actor()
    async with app_engine.begin() as conn:
        await (await CaseService.start(conn)).apply(
            asha, six.case, Link((), (Indicator("ip", B, "c2"),)), expected_version=None
        )
    source, _ = await stored(app_engine, six.case)
    assert ("ip", B, "c2") in await marks(app_engine, six.case)
    assert Indicator("ip", B, "actor") not in source.indicators
    async with migrated_engine.connect() as conn:
        count = (
            await conn.execute(
                text("SELECT count(*) FROM case_indicators WHERE case_id = :c AND value = :v"),
                {"c": six.case, "v": B},
            )
        ).scalar_one()
    assert count == 1


async def test_the_web_login_can_link_what_a_split_took_back_and_cannot_sign_it_as_argus(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, web_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    """A person's Link from a page revives a row (the grants), as that person (the trigger)."""
    six = await make_six(migrated_engine, app_engine)
    await do_split(app_engine, people["asha"], six.case, [six.b1])
    async with web_engine.begin() as conn:
        await (await CaseService.start(conn)).apply(
            people["meera"].actor(), six.case, Link((), (Indicator("ip", B, "c2"),)),
            expected_version=None,
        )  # fmt: skip
    assert ("ip", B, "c2") in await marks(app_engine, six.case)
    async with migrated_engine.connect() as conn:
        added_by = (
            await conn.execute(
                text("SELECT added_by FROM case_indicators WHERE case_id = :c AND value = :v"),
                {"c": six.case, "v": B},
            )
        ).scalar_one()
    assert added_by == f"user:{people['meera'].user_id}"
    # a hijacked web process cannot revive a row under ARGUS's name, or rename who added one
    for table in ("case_indicators", "case_members"):
        with pytest.raises(DBAPIError, match="only as a person"):
            async with web_engine.begin() as conn:
                await conn.execute(
                    text(f"UPDATE {table} SET added_by = 'argus:opener' WHERE case_id = :c"),  # noqa: S608
                    {"c": six.case},
                )
    async with web_engine.begin() as conn:  # an update that leaves added_by alone passes
        await conn.execute(
            text("UPDATE case_members SET link = link, removed_version = removed_version"
                 " WHERE case_id = :c"), {"c": six.case},
        )  # fmt: skip


# --------------------------------------------------------------------------- the notified source


async def test_the_owner_notice_covers_only_the_device_that_stays(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """The point of the split: record the notice on the case that holds only the notified host,
    and the known infection's fingerprint holds that device alone."""
    six = await make_six(migrated_engine, app_engine)
    await do_split(app_engine, people["asha"], six.case, [six.b1])
    async with app_engine.begin() as conn:  # the suggested case is confirmed, then the owner told
        service = await CaseService.start(conn)
        await service.apply(people["asha"].actor(), six.case, Confirm(None), expected_version=None)
    async with app_engine.begin() as conn:
        service = await CaseService.start(conn)
        await service.apply(people["asha"].actor(), six.case,
                            Notify("the owner", "email"), expected_version=None)  # fmt: skip
    async with app_engine.connect() as conn:
        tracked = await knownrun.tracked(conn, known_context(), datetime.now(UTC))
    (case,) = [t for t in tracked if t.id == six.case]
    assert case.fingerprint.devices == frozenset({("ip", A)})
    assert ("ip", S) in case.fingerprint.destinations  # the server stays a destination of both


async def test_a_notified_case_can_still_split_and_keeps_its_notice(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    six = await make_six(migrated_engine, app_engine, suspected=False, person=people["asha"])
    async with app_engine.begin() as conn:
        await (await CaseService.start(conn)).apply(
            people["asha"].actor(), six.case, Notify("the owner", "email"), expected_version=None
        )
    done = await do_split(app_engine, people["asha"], six.case, [six.b1])
    source, kinds = await stored(app_engine, six.case)
    assert source.notified
    assert kinds == ["opened", "notified", "unlinked"]
    assert not done.target.case.notified  # the notice is the source's alone
    async with migrated_engine.connect() as conn:
        notices = (
            await conn.execute(
                text("SELECT count(*) FROM case_notices WHERE case_id = :c"), {"c": six.case}
            )
        ).scalar_one()
    assert notices == 1


# --------------------------------------------------------------------------- other states


async def test_a_mirrored_or_assigned_case_splits_without_planning_kibana_writes(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    six = await make_six(migrated_engine, app_engine, suspected=False, person=people["asha"])
    async with app_engine.begin() as conn:
        await (await CaseService.start(conn)).apply(
            people["asha"].actor(), six.case, Take(), expected_version=None
        )
    done = await do_split(app_engine, people["asha"], six.case, [six.b1])
    assert done.source.outbox_ids == ()
    source, _ = await stored(app_engine, six.case)
    assert (source.state, source.owner_user_id) == ("assigned", people["asha"].user_id)


# --------------------------------------------------------------------------- the pieces together


async def test_after_a_split_the_watch_joins_each_device_to_its_own_case(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    from tests.integration.cases.watchkit import C2, H1, H2, World, at, context

    world = World(migrated_engine, app_engine)
    asha = people["asha"]
    a1 = await world.investigation(H1, [at(0, 9)])
    a2 = await world.investigation(H1, [at(0, 10)], rule="download")
    b1 = await world.investigation(H2, [at(0, 9, 30)])
    source = await world.open_case(asha, [a1, a2, b1], [H1, H2], at(0, 11), mirrored=False)
    async with app_engine.begin() as conn:
        service = CaseService(conn, at(0, 12))
        done = await service.split(
            asha.actor(), source, [b1], reason="two separate devices",
            carry=splitting.carrier(conn, IpClassifier(None, ())), expected_version=None,
            title="Hostel device",
        )  # fmt: skip
    target = done.target.case.id
    live = await marks(app_engine, source)
    assert ("ip", H1, "actor") in live
    assert ("ip", H2, "actor") not in live
    assert ("ip", C2, "c2") in live  # the server stays on the source
    a3 = await world.investigation(H1, [at(1, 9)])  # device A alerts again
    b2 = await world.investigation(H2, [at(1, 8)])  # so does device B
    await world.run(context(None), at(2, 3))
    assert await world.members(source) == {a1, a2, a3}
    assert await world.members(target) == {b1, b2}  # the moved device did not go back
    async with migrated_engine.connect() as conn:
        offered = (
            await conn.execute(text("SELECT investigation_id, case_id, kind FROM case_suggestions"))
        ).all()  # fmt: skip
    # the server both cases hold is also offered to the other case ("also"), never joined
    assert {(r.investigation_id, r.case_id, r.kind) for r in offered} == {
        (b2, source, "also"), (a3, target, "also"),
    }  # fmt: skip


async def test_the_suggester_leaves_the_moved_investigations_where_they_are(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """The moved investigation is in a case, so the suggester sees it as held and opens nothing
    for it (an investigation of one case is never suggested into another)."""
    from argus.cases import suggest

    six = await make_six(migrated_engine, app_engine)
    done = await do_split(app_engine, people["asha"], six.case, [six.b1])
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("UPDATE investigations SET last_event_at = now() WHERE id = ANY(:ids)"),
            {"ids": [six.a1, six.a2, six.b1]},
        )
    async with app_engine.connect() as conn:
        seen = await suggest.load_seen(conn, datetime.now(UTC), CLASSIFIER)
    held = {s.investigation_id: s.held for s in seen}
    assert held[six.b1] is not None
    assert held[six.b1].case_id == done.target.case.id
    assert held[six.a1] is not None
    assert held[six.a1].case_id == six.case


# --------------------------------------------------------------------------- concurrency


async def _eventually(*tasks: asyncio.Task[object], seconds: float = 30.0) -> list[object]:
    return list(await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), seconds))


async def test_two_splits_between_the_same_two_cases_in_opposite_directions_do_not_deadlock(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    one = await make_six(migrated_engine, app_engine)
    two = await make_six(migrated_engine, app_engine)
    asha, ravi = people["asha"], people["ravi"]
    results = await _eventually(
        asyncio.ensure_future(do_split(app_engine, asha, one.case, [one.b1], into=two.case)),
        asyncio.ensure_future(do_split(app_engine, ravi, two.case, [two.b1], into=one.case)),
    )
    assert all(isinstance(r, Split) for r in results), results
    assert (await stored(app_engine, one.case))[0].members == frozenset({one.a1, one.a2, two.b1})
    assert (await stored(app_engine, two.case))[0].members == frozenset({two.a1, two.a2, one.b1})
    assert await in_one_case_each(app_engine)


async def test_two_splits_of_the_same_investigation_one_wins_and_one_is_refused(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    six = await make_six(migrated_engine, app_engine)
    results = await _eventually(
        asyncio.ensure_future(
            do_split(app_engine, people["asha"], six.case, [six.b1], title="first")
        ),
        asyncio.ensure_future(
            do_split(app_engine, people["ravi"], six.case, [six.b1], title="second")
        ),
    )
    won = [r for r in results if isinstance(r, Split)]
    lost = [r for r in results if isinstance(r, CaseRefused)]
    assert (len(won), len(lost)) == (1, 1), results
    assert lost[0].code == "conflict"
    async with migrated_engine.connect() as conn:
        cases = (await conn.execute(text("SELECT count(*) FROM cases"))).scalar_one()
    assert cases == 2  # the loser opened nothing
    assert await in_one_case_each(app_engine)
    await stored(app_engine, six.case)


async def test_a_split_and_a_link_on_the_same_case_both_land(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    six = await make_six(migrated_engine, app_engine)
    extra = await investigation(migrated_engine, actor=(("source.ip", C),))

    async def link() -> None:
        async with app_engine.begin() as conn:
            await (await CaseService.start(conn)).apply(
                people["ravi"].actor(),
                six.case,
                Link((Member(extra, "person"),)),
                expected_version=None,
            )

    results = await _eventually(
        asyncio.ensure_future(do_split(app_engine, people["asha"], six.case, [six.b1])),
        asyncio.ensure_future(link()),
    )
    assert not [r for r in results if isinstance(r, BaseException)], results
    source, kinds = await stored(app_engine, six.case)
    assert source.members == frozenset({six.a1, six.a2, extra})
    assert sorted(kinds) == ["linked", "suspected", "unlinked"]
    assert source.version == 3


async def test_a_split_waits_for_the_openers_lock_and_goes_on_when_it_is_let_go(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """The membership lock is the opener's: while a writer of membership holds it, a split waits."""
    from argus.cases import opener

    six = await make_six(migrated_engine, app_engine)
    release = asyncio.Event()
    taken = asyncio.Event()

    async def hold() -> None:
        async with app_engine.begin() as conn:
            await conn.execute(text("SELECT pg_advisory_xact_lock(:k)"),
                               {"k": opener.OPENER_LOCK_KEY})  # fmt: skip
            taken.set()
            await release.wait()

    holder = asyncio.ensure_future(hold())
    await taken.wait()
    splitting_now = asyncio.ensure_future(do_split(app_engine, people["asha"], six.case, [six.b1]))
    await asyncio.sleep(1.0)
    assert not splitting_now.done()  # waiting for the lock
    assert (await stored(app_engine, six.case))[0].version == 1
    release.set()
    await asyncio.wait_for(holder, 10)
    done = await asyncio.wait_for(splitting_now, 30)
    assert done.source.case.version == 2


def test_the_membership_lock_is_the_openers() -> None:
    from argus.cases import opener, service

    assert service.MEMBERSHIP_LOCK_KEY == opener.OPENER_LOCK_KEY


async def test_the_new_case_is_open_from_now_on(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    six = await make_six(migrated_engine, app_engine)
    done = await do_split(app_engine, people["asha"], six.case, [six.b1])
    assert done.target.case.opened_at is not None
    assert abs(done.target.case.opened_at - datetime.now(UTC)) < timedelta(minutes=5)


async def test_a_moved_investigation_no_longer_holds_the_sources_benign_closure(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """Every reader of a case's members skips the removed ones: the write-back's hold on a benign
    closure (Q-F1's verified zero on a member) looks at the case's members as they are now."""
    from argus import writeback

    six = await make_six(migrated_engine, app_engine)
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO freshness_shadow (investigation_id, version, pack, signal, mode,"
                 " verdict, reason, bridged_verdict, complete_to, refs, margins, decided_at)"
                 " VALUES (:i, 1, 'p', 's', 'on', 'known_zero', 'verified', 'known_zero', now(),"
                 " '[]', '{}', now())"), {"i": six.b1},
        )  # fmt: skip
    async with app_engine.connect() as conn:
        assert (await conn.execute(text(writeback._F1_CASE), {"c": six.case})).scalar_one()
    await do_split(app_engine, people["asha"], six.case, [six.b1])
    async with app_engine.connect() as conn:
        assert not (await conn.execute(text(writeback._F1_CASE), {"c": six.case})).scalar_one()


async def test_a_member_comes_back_with_no_link_value_too(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """A revived row takes the new link and its value, or none (a NULL inside the arrays)."""
    six = await make_six(migrated_engine, app_engine)
    async with migrated_engine.begin() as conn:  # a removal made by hand, as the owner
        await conn.execute(
            text("UPDATE case_members SET removed_version = 2, removed_at = now()"
                 " WHERE case_id = :c AND investigation_id = :i"), {"c": six.case, "i": six.b1},
        )  # fmt: skip
    async with app_engine.begin() as conn:
        await (await CaseService.start(conn)).apply(
            people["asha"].actor(), six.case, Link((Member(six.b1, "person"),)),
            expected_version=None,
        )  # fmt: skip
    async with migrated_engine.connect() as conn:
        row = (
            await conn.execute(
                text("SELECT link, link_value, removed_at, added_version FROM case_members"
                     " WHERE case_id = :c AND investigation_id = :i"), {"c": six.case, "i": six.b1},
            )
        ).one()  # fmt: skip
    assert (row.link, row.link_value, row.removed_at, row.added_version) == (
        "person", None, None, 2,
    )  # fmt: skip
