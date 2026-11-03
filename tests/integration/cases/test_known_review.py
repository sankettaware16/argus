"""AR4b after the adversarial review (D-181), against the database as the runtime login runs it.
Each test is a finding of the review turned into a regression test: a change that lasts, another
person's devices, a moved address that is another laptop, new destinations, the data volume,
``per_pass`` starvation, the ending of a case, threat-intel values and the block list, a notice
withdrawn, a proposal that expired, and a refused link."""

from __future__ import annotations

import ipaddress
import json
import uuid
from datetime import datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.assets.classify import IpClassifier
from argus.campaigns.analysis import Campaign
from argus.cases import blocklist, knownrun, knownview, suggest
from argus.cases.machine import CaseRefused, Link, WithdrawNotice
from argus.cases.model import Indicator, Member
from argus.cases.service import CaseService
from argus.web import auth, casepages
from argus.web.capabilities import Capability
from tests.integration.cases.conftest import APPROVER, Person, asking, rows, signed_for
from tests.integration.cases.knownkit import (
    BEACON,
    HOST,
    NEW_SERVER,
    OTHER_HOST,
    OUTSIDE,
    SERVERS,
    SUCCESS,
    at,
    context,
    flag_server,
    known_rows,
    make,
    members,
    notify,
    open_case,
)
from tests.integration.cases.test_known_pass import attention, counts, incident

pytestmark = pytest.mark.integration

CAMPUS_NETS = IpClassifier(None, [ipaddress.ip_network("10.55.0.0/16")])


async def bump(
    owner: AsyncEngine, inv: uuid.UUID, when: datetime, flags: tuple[str, ...] = (BEACON, OUTSIDE)
) -> int:
    """One more alert in the investigation: its version goes up, and the evidence is read again
    at that version (the raises row follows)."""
    async with owner.begin() as conn:
        version = (
            await conn.execute(
                text(
                    "UPDATE investigations SET version = version + 1, last_event_at = :t"
                    " WHERE id = :i RETURNING version"
                ),
                {"t": when, "i": inv},
            )
        ).scalar_one()
        await conn.execute(
            text("UPDATE investigation_raises SET version = :v, evaluated_at = :t,"
                 " flags = CAST(:f AS jsonb) WHERE investigation_id = :i"),
            {"v": version, "t": when, "f": json.dumps(list(flags)), "i": inv},
        )  # fmt: skip
    return int(version)


async def review(owner: AsyncEngine, inv: uuid.UUID, user: int, version: int) -> None:
    async with owner.begin() as conn:
        await conn.execute(
            text("INSERT INTO review_events (investigation_id, version, alert_count, user_id,"
                 " action, outcome) VALUES (:i, :v, 1, :u, 'reviewed', 'true_positive')"),
            {"i": inv, "v": version, "u": user},
        )  # fmt: skip


def a_manager(person: Person) -> auth.Reviewer:
    """The signed-in person as the web sees them, allowed to manage cases."""
    return auth.Reviewer(
        user_id=person.user_id, username=person.username, display_name=person.username.title(),
        csrf_token="x", previous_seen_at=None, capabilities=frozenset(Capability),
    )  # fmt: skip


async def case_page(engine: AsyncEngine, case: uuid.UUID) -> bool:
    async with engine.connect() as conn:
        page = await casepages.row_of(conn, case)
    assert page is not None
    return page.needs_attention


# --------------------------------------------------------------------------- 1. a change lasts


async def test_a_change_is_not_erased_by_the_investigations_next_alert(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """The blocker: the next alert of a changed investigation bumped its version, the pass decided
    it known, and the change left Needs attention before anyone saw it."""
    case, _, _ = await incident(migrated_engine, app_engine, people)
    await knownrun.run(app_engine, context(), at(3, 10))
    await flag_server(migrated_engine, NEW_SERVER, at(5))
    fifth = await make(migrated_engine, when=at(5, 11), servers=(*SERVERS[:2], NEW_SERVER))
    await bump(migrated_engine, fifth, at(5, 11, 30))  # it has its second version when it is read
    await knownrun.run(app_engine, context(), at(5, 12))
    outcome, why = (await known_rows(app_engine, case))[fifth]
    assert (outcome, why) == (
        "changed",
        "changed since notice: a new flagged destination (185.9.9.9)",
    )
    assert fifth in await attention(app_engine)
    assert await case_page(app_engine, case)

    await bump(migrated_engine, fifth, at(5, 13))  # one more alert: the third version
    assert fifth in await attention(app_engine)  # before the pass reads it
    report = await knownrun.run(app_engine, context(), at(5, 14))
    assert report.problems == []
    assert report.cases[0].kept == 1  # decided known again, and still a change
    assert (await known_rows(app_engine, case))[fifth] == (outcome, why)
    shown = await attention(app_engine)
    assert fifth in shown
    assert "Changed since notice: a new flagged destination (185.9.9.9)." in shown[fifth].reasons
    assert await case_page(app_engine, case)
    assert (await counts(app_engine))["attention"] == 1
    async with app_engine.connect() as conn:
        found = await conn.scalar(
            text("SELECT changed_version FROM case_known_matches WHERE investigation_id = :i"),
            {"i": fifth},
        )
    assert found == 2  # the version at which it was decided

    # a later change appends its reason
    await bump(migrated_engine, fifth, at(5, 15), (BEACON, OUTSIDE, SUCCESS))
    await knownrun.run(app_engine, context(), at(5, 16))
    outcome, why = (await known_rows(app_engine, case))[fifth]
    assert outcome == "changed"
    assert why == (
        "changed since notice: a new flagged destination (185.9.9.9);"
        " a kind of evidence the case did not have (successful answers after the alert)"
    )

    # a review of a version before the change does not end it; one at or after it does
    await review(migrated_engine, fifth, people["ravi"].user_id, 1)  # before the change
    assert fifth in await attention(app_engine)
    current = await bump(migrated_engine, fifth, at(5, 17), (BEACON, OUTSIDE, SUCCESS))
    await review(migrated_engine, fifth, people["ravi"].user_id, current)
    assert fifth not in await attention(app_engine)
    assert not await case_page(app_engine, case)
    # only then may a later version be known
    await bump(migrated_engine, fifth, at(5, 18), (BEACON, OUTSIDE, SUCCESS))
    assert fifth in await attention(app_engine)  # changed since the review, until the pass reads it
    await knownrun.run(app_engine, context(), at(5, 19))
    assert (await known_rows(app_engine, case))[fifth] == ("known", None)
    assert fifth not in await attention(app_engine)


# --------------------------------------------------------------------------- 2. other devices


async def test_an_investigation_that_lists_another_persons_devices_too_is_not_known(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """One notified device does not absorb the investigation that lists it with three other
    people's devices (a rule that groups by destination): the normal pipeline decides, and the
    suggester (D-171) offers the new devices to the case."""
    case, _, _ = await incident(migrated_engine, app_engine, people)
    ctx = context(classifier=CAMPUS_NETS)
    await knownrun.run(app_engine, ctx, at(3, 10))
    others = (("ip", "10.55.7.9"), ("ip", "10.55.7.10"), ("ip", "10.55.7.11"))
    multi = await make(migrated_engine, when=at(4, 12), rule="dest-grouped", extra=others)
    report = await knownrun.run(app_engine, ctx, at(4, 13))
    assert report.problems == []
    assert multi not in await known_rows(app_engine, case)
    assert multi not in await members(app_engine, case)
    assert multi in await attention(app_engine)  # new work, as it was before notices
    # the new devices are offered to the case
    campaign = Campaign(
        frozenset({multi}), frozenset(others), (), SERVERS, SERVERS[:1], (), (), 0.0,
        {multi: frozenset(others)},
    )  # fmt: skip
    made = await suggest.run(app_engine, classifier=CAMPUS_NETS, dry_run=False, now=at(4, 14),
                             campaigns=[campaign])  # fmt: skip
    assert made.applied
    offers = await rows(app_engine, "SELECT investigation_id, case_id FROM case_suggestions")
    assert {(o.investigation_id, o.case_id) for o in offers} <= {(multi, case)}
    # once the case holds those devices (a person added them), the same shape is the case's
    async with app_engine.begin() as conn:
        await (await CaseService.start(conn)).apply(
            people["asha"].actor(), case,
            Link((), tuple(Indicator("ip", v, "actor") for _, v in others)),
            expected_version=None,
        )  # fmt: skip
    again = await make(migrated_engine, when=at(4, 15), rule="dest-grouped-2", extra=others)
    await knownrun.run(app_engine, ctx, at(4, 16))
    assert (await known_rows(app_engine, case))[again][0] == "known"


# --------------------------------------------------------------------------- 3. a moved address


async def test_another_persons_laptop_is_not_merged_as_a_move_of_a_case_with_two_devices(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case, _, _ = await incident(migrated_engine, app_engine, people)
    b = await make(migrated_engine, when=at(4, 9), host="10.198.36.231")
    async with app_engine.begin() as conn:
        await (await CaseService.start(conn)).apply(
            people["asha"].actor(), case,
            Link((Member(b, "actor"),), (Indicator("ip", "10.198.36.231", "actor"),)),
            expected_version=None,
        )  # fmt: skip
    await make(migrated_engine, when=at(4, 16), rule="beacon-late")  # device A keeps alerting
    await knownrun.run(app_engine, context(), at(4, 16, 30))
    c = await make(migrated_engine, when=at(4, 17), host="10.198.99.4", rule="beacon-c")
    report = await knownrun.run(app_engine, context(), at(4, 17, 30))
    assert report.problems == []
    assert c not in await members(app_engine, case)
    assert c not in await known_rows(app_engine, case)
    assert c in await attention(app_engine)  # another person's laptop is new work
    assert await rows(
        app_engine, "SELECT id FROM case_events WHERE case_id = :c AND kind = 'address_moved'",
        c=case,
    ) == []  # fmt: skip


async def move_to(
    owner: AsyncEngine, new: str, started: datetime, *, rule: str = "beacon-new"
) -> uuid.UUID:
    """A new address begins at ``started`` (the investigation's first alert), with the same
    servers."""
    inv = await make(owner, when=at(4, 8), host=new, rule=rule)
    async with owner.begin() as conn:
        await conn.execute(
            text("UPDATE investigations SET first_event_at = :t WHERE id = :i"),
            {"t": started, "i": inv},
        )
    return inv


async def test_the_old_address_alerting_again_after_a_move_is_two_devices(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case, _, _ = await incident(migrated_engine, app_engine, people)
    await knownrun.run(app_engine, context(), at(3, 10))
    moved = await move_to(migrated_engine, "10.198.99.4", at(1, 10) + timedelta(hours=20))
    await knownrun.run(app_engine, context(), at(4, 9))
    assert (await known_rows(app_engine, case))[moved][0] == "known"
    assert len(await rows(app_engine, "SELECT id FROM case_events WHERE case_id = :c AND"
                          " kind = 'address_moved'", c=case)) == 1  # fmt: skip
    # the old address alerts again, after the new one began: these are two devices
    again = await make(migrated_engine, when=at(4, 20), rule="beacon-old-again")
    await knownrun.run(app_engine, context(), at(4, 21))
    outcome, why = (await known_rows(app_engine, case))[again]
    assert outcome == "changed"
    assert why == f"changed since notice: two devices: {HOST} active again after the move"
    assert again in await attention(app_engine)
    # the new address's own alerts stay known, and the two addresses are not one any longer: a
    # third address is not merged as a move of either
    await make(migrated_engine, when=at(5, 8), host="10.198.99.4", rule="beacon-new-2")
    await knownrun.run(app_engine, context(), at(5, 9))
    third = await move_to(migrated_engine, "10.198.99.77", at(5, 12), rule="beacon-3")
    report = await knownrun.run(app_engine, context(), at(5, 13))
    assert report.problems == []
    assert third not in await members(app_engine, case)
    assert third in await attention(app_engine)


# --------------------------------------------------------------------------- 4. new destinations


async def test_new_destinations_are_noted_on_the_case_not_raised_and_a_late_flag_is_a_change(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """One known destination no longer absorbs new ones silently: they are counted on the case
    and listed; if the look-ups flag one later, the investigation comes back as a change."""
    case, _, _ = await incident(migrated_engine, app_engine, people)
    await knownrun.run(app_engine, context(), at(3, 10))
    fresh = ("91.121.5.50", "91.121.5.51")
    third = await make(migrated_engine, when=at(4, 12), servers=(*SERVERS, *fresh))
    report = await knownrun.run(app_engine, context(), at(4, 13))
    assert report.cases[0].known == 1
    assert (await known_rows(app_engine, case))[third] == ("known", None)
    assert third not in await attention(app_engine)  # not raised

    async def listed() -> tuple[int, list[str]]:
        async with app_engine.connect() as conn:
            (status,) = await knownview.notified(conn, at(5), case_id=case)
        return status.new_total, [d.value for d in status.new_destinations]

    assert await listed() == (2, list(fresh))
    # the same new destinations again are not counted twice
    await make(migrated_engine, when=at(4, 15), servers=(*SERVERS, *fresh), rule="beacon-again")
    await knownrun.run(app_engine, context(), at(4, 16))
    assert await listed() == (2, list(fresh))
    # the case page and the API show them
    async with app_engine.connect() as conn:
        held = await (await CaseService.start(conn)).get(case)
        assert held is not None
        section = await casepages.known_section(conn, held, a_manager(people["asha"]), at(5), {})
    assert section is not None
    assert section.new_destinations_total == 2
    assert [d.value for d in section.new_destinations] == list(fresh)

    # the outside look-ups flag one of them later: the evidence is read again, and it is a change
    await flag_server(migrated_engine, fresh[0], at(5))
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text(
                "UPDATE investigation_raises SET evaluated_at = now() WHERE investigation_id = :i"
            ),
            {"i": third},
        )
    await knownrun.run(app_engine, context(), at(5, 12))
    outcome, why = (await known_rows(app_engine, case))[third]
    assert outcome == "changed"
    assert why == "changed since notice: a new flagged destination (91.121.5.50)"
    assert third in await attention(app_engine)


# --------------------------------------------------------------------------- 5. the volume


async def test_a_level_of_zero_is_not_judged_and_one_bad_subject_never_fails_the_pass(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    for ip in SERVERS:
        await flag_server(migrated_engine, ip, at(0))
    first = await make(migrated_engine, when=at(0, 10), nbytes=0)
    case = await open_case(app_engine, people["asha"], [first])
    await notify(app_engine, people["asha"], case, at(3, 9))
    await knownrun.run(app_engine, context(), at(3, 10))
    kinds = {r.kind for r in await rows(app_engine, "SELECT kind FROM case_known_keys WHERE"
                                        " case_id = :c", c=case)}  # fmt: skip
    assert "bytes" not in kinds  # a level of 0 is not kept
    third = await make(migrated_engine, when=at(4, 12), nbytes=5_000_000_000)
    report = await knownrun.run(app_engine, context(), at(4, 15))
    assert report.problems == []
    assert report.cases[0].known == 1
    assert report.cases[0].unjudged == 1
    assert (await known_rows(app_engine, case))[third] == ("known", None)


async def test_small_steps_cannot_creep_past_the_level_at_the_notice(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """Each investigation nine times the one before: known growth never moves the level, so the
    second step (81 times the notice) is a change, and the level is then that change's."""
    for ip in SERVERS:
        await flag_server(migrated_engine, ip, at(0))
    first = await make(migrated_engine, when=at(0, 10), nbytes=1_000_000)
    case = await open_case(app_engine, people["asha"], [first])
    await notify(app_engine, people["asha"], case, at(3, 9))
    await knownrun.run(app_engine, context(), at(3, 10))
    seen = []
    size = 1_000_000
    for step in range(4):
        size *= 9
        inv = await make(migrated_engine, when=at(4, 10 + step), nbytes=size, rule=f"r{step}")
        await knownrun.run(app_engine, context(), at(4, 10 + step, 30))
        seen.append((await known_rows(app_engine, case))[inv])
    assert [o for o, _ in seen] == ["known", "changed", "known", "changed"]
    assert "much more traffic than at the notice (about 81 times)" in (seen[1][1] or "")


# --------------------------------------------------------------------------- 6. per_pass


async def test_other_devices_on_the_same_servers_never_use_up_the_passes_reads(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case, _, _ = await incident(migrated_engine, app_engine, people)
    await knownrun.run(app_engine, context(per_pass=10), at(3, 10))
    mine = await make(migrated_engine, when=at(4, 9), rule="beacon-mine")
    for n in range(12):  # newer than mine, same servers, other people's devices
        await make(migrated_engine, when=at(4, 9, 10 + n), host=f"10.77.0.{n + 1}", rule=f"r{n}")
    report = await knownrun.run(app_engine, context(per_pass=10), at(4, 20))
    assert report.problems == []
    assert (await known_rows(app_engine, case))[mine] == ("known", None)
    assert mine not in await attention(app_engine)


async def test_the_moved_address_read_is_a_separate_small_query(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """The newcomer is found within its own cap, whatever per_pass is; strangers that began before
    the device went quiet are not read for it at all."""
    case, _, _ = await incident(migrated_engine, app_engine, people)
    await knownrun.run(app_engine, context(per_pass=10), at(3, 10))
    for n in range(6):  # other devices on the same servers, newer than the newcomer
        stranger = await make(migrated_engine, when=at(4, 9, n), host=f"10.77.1.{n + 1}",
                              rule=f"s{n}")  # fmt: skip
        async with migrated_engine.begin() as conn:  # ... that began before the device went quiet
            await conn.execute(text("UPDATE investigations SET first_event_at = :t WHERE id = :i"),
                               {"t": at(0, 20), "i": stranger})  # fmt: skip
    moved = await move_to(migrated_engine, "10.198.99.4", at(1, 10) + timedelta(hours=20))
    await knownrun.run(app_engine, context(per_pass=10, moved_per_pass=1), at(4, 10))
    assert (await known_rows(app_engine, case))[moved][0] == "known"
    assert moved in await members(app_engine, case)


async def test_two_new_addresses_that_fit_the_quiet_device_are_never_guessed_between(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case, _, _ = await incident(migrated_engine, app_engine, people)
    await knownrun.run(app_engine, context(), at(3, 10))
    one = await move_to(migrated_engine, "10.198.99.4", at(2, 6), rule="beacon-a")
    two = await move_to(migrated_engine, "10.198.99.5", at(2, 8), rule="beacon-b")
    await knownrun.run(app_engine, context(), at(4, 9))
    assert not {one, two} & await members(app_engine, case)
    assert {one, two} <= set(await attention(app_engine))


async def test_an_actor_of_the_grouping_key_is_a_device_match_without_an_entity(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case, _, _ = await incident(migrated_engine, app_engine, people)
    await knownrun.run(app_engine, context(per_pass=10), at(3, 10))
    keyed = await make(migrated_engine, when=at(4, 9), rule="beacon-keyed")
    async with migrated_engine.begin() as conn:  # the key names the host; no entity does
        await conn.execute(
            text("DELETE FROM investigation_entities WHERE investigation_id = :i AND kind = 'ip'"
                 " AND value = :v"), {"i": keyed, "v": HOST},
        )  # fmt: skip
    report = await knownrun.run(app_engine, context(per_pass=10), at(4, 10))
    assert report.problems == []
    assert (await known_rows(app_engine, case))[keyed][0] == "known"


async def test_a_case_that_fails_does_not_stop_the_others(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person],
    monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    first_case, _, _ = await incident(migrated_engine, app_engine, people)
    other = await make(migrated_engine, when=at(0, 11), host=OTHER_HOST, rule="beacon-o")
    second_case = await open_case(app_engine, people["meera"], [other], host=OTHER_HOST)
    await notify(app_engine, people["meera"], second_case, at(3, 9))
    real = knownrun._case

    async def failing(engine: AsyncEngine, ctx: knownrun.Context, case: knownrun.Tracked,
                      now: datetime, result: knownrun.CaseResult) -> None:  # fmt: skip
        if case.number == 1:
            raise RuntimeError("a case that cannot be read")
        await real(engine, ctx, case, now, result)

    monkeypatch.setattr(knownrun, "_case", failing)
    report = await knownrun.run(app_engine, context(), at(3, 10))
    assert report.problems == ["case 1: RuntimeError"]
    assert await known_rows(app_engine, first_case) == {}
    assert set(await known_rows(app_engine, second_case)) == {other}  # the other was seeded


# --------------------------------------------------------------------------- 7. the ending


async def test_a_case_that_stopped_after_notice_does_not_flood_needs_attention(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person],
    api_engine: AsyncEngine,
) -> None:  # fmt: skip
    case, _, _ = await incident(migrated_engine, app_engine, people)
    long = context(history=timedelta(days=30))
    await knownrun.run(app_engine, long, at(3, 10))
    absorbed = [await make(migrated_engine, when=at(4 + n, 12), rule=f"b{n}") for n in range(10)]
    await knownrun.run(app_engine, long, at(14, 13))
    assert await attention(app_engine) == {}
    asha, ravi = people["asha"], people["ravi"]
    async with api_engine.begin() as conn:
        service = await CaseService.start(conn)
        version = (await service.get(case)).version  # type: ignore[union-attr]
        _, rid = await service.request_closure(
            asha.actor(), case, expected_version=version, reason="stopped_after_notice",
            session_token=asha.session_token, check=await asking(conn, asha),
        )  # fmt: skip
    async with api_engine.begin() as conn:
        service = await CaseService.start(conn)
        signed = await signed_for(conn, ravi, rid)
        await service.decide(ravi.actor(APPROVER), rid, session_token=ravi.session_token,
                             decision="approved", signed=signed)  # fmt: skip
    assert await attention(app_engine) == {}  # frozen: what was known stays known
    assert (await counts(app_engine))["known"] == 0
    rowset = await known_rows(app_engine, case)
    assert all(rowset[i] == ("known", None) for i in absorbed)
    # a later version of one of them goes through the normal pipeline
    await bump(migrated_engine, absorbed[0], at(15, 9))
    assert set(await attention(app_engine)) == {absorbed[0]}


# --------------------------------------------------------------------------- 8. threat intel


async def test_listed_values_are_typed_hashes_are_no_destination_and_a_bad_link_is_reported(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person],
    monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    case, _, _ = await incident(migrated_engine, app_engine, people)
    await knownrun.run(app_engine, context(), at(3, 10))
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    url = "http://payload.example.com/" + "a" * 600
    bare = "http://91.121.9.7:8080/x"
    listed = await make(migrated_engine, when=at(4, 12), listed=[url, md5, bare], rule="download2")
    ok = [await make(migrated_engine, when=at(4, 13 + n), rule=f"ok{n}") for n in range(3)]
    poison = await make(migrated_engine, when=at(4, 17), rule="poison")

    real = CaseService.apply

    async def refusing(self: CaseService, actor: object, case_id: object, command: object,
                       *, expected_version: int | None) -> object:  # fmt: skip
        if isinstance(command, Link) and any(m.investigation_id == poison for m in command.members):
            raise CaseRefused("invalid", "a value the case refuses")
        return await real(self, actor, case_id, command, expected_version=expected_version)  # type: ignore[arg-type]

    monkeypatch.setattr(CaseService, "apply", refusing)
    report = await knownrun.run(app_engine, context(), at(4, 20))
    monkeypatch.undo()
    # the poison is a reported problem; the rest of its chunk went on
    assert report.problems == [
        f"case 1: investigation {poison} not joined: a value the case refuses"
    ]
    decided = await known_rows(app_engine, case)
    assert all(decided[i][0] == "known" for i in ok)
    assert decided[listed][0] == "changed"
    assert poison not in decided
    assert poison in await attention(app_engine)
    held = {(r.kind, r.value) for r in await rows(
        app_engine,
        "SELECT kind, value FROM case_indicators WHERE case_id = :c AND role <> 'actor'",
        c=case)}  # fmt: skip
    assert ("domain", "payload.example.com") in held  # a URL is its host, typed
    assert ("ip", "91.121.9.7") in held
    assert not any(v == md5 for _, v in held)  # a hash is no destination
    kept = {
        (r.kind, r.value)
        for r in await rows(
            app_engine, "SELECT kind, value FROM case_known_keys WHERE case_id = :c", c=case
        )
    }
    assert not any(md5 in v for _, v in kept)  # nor part of the fingerprint
    async with app_engine.connect() as conn:
        found = await blocklist.build(conn, case)
    assert found is not None
    assert not any(md5 in e.value for e in found.entries)
    # the poison is tried again on the next pass (and reported again until it can join)
    again = await knownrun.run(app_engine, context(), at(4, 21))
    assert again.problems == []
    assert (await known_rows(app_engine, case))[poison][0] == "known"


async def test_the_block_list_holds_public_addresses_and_names_only_and_counting_is_cheap(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case, _, _ = await incident(migrated_engine, app_engine, people)
    async with app_engine.begin() as conn:
        await (await CaseService.start(conn)).apply(
            people["asha"].actor(), case,
            Link((), (
                Indicator("ip", "10.1.1.1", "c2"),
                Indicator("ip", "127.0.0.1", "indicator"),
                Indicator("ip", "192.168.4.4", "indicator"),
                Indicator("domain", "=cmd|' /C calc'!A0.example.com", "indicator"),
                Indicator("domain", "d41d8cd98f00b204e9800998ecf8427e", "indicator"),
                Indicator("domain", "c2.evil-names.net", "indicator"),
            )),
            expected_version=None,
        )  # fmt: skip
    campus = IpClassifier(None, [ipaddress.ip_network("77.221.155.152/31")])
    async with app_engine.connect() as conn:
        listing = await blocklist.build(conn, case, classifier=campus)
        counted = await blocklist.count(conn, case, classifier=campus)
        plain = await blocklist.build(conn, case)
    assert listing is not None
    assert plain is not None
    values = {e.value for e in listing.entries}
    assert values == {"77.221.155.150", "77.221.155.151", "evil-names.net", "c2.evil-names.net"}
    assert {"77.221.155.152", "77.221.155.153"}.isdisjoint(values)  # the campus prefix says no
    assert counted == len(listing.entries)
    assert len(plain.entries) == counted + 2  # without the campus prefix, those two are public


# --------------------------------------------------------------------------- 9. withdrawn


async def test_a_withdrawn_notice_stops_the_absorbing_and_leaves_what_was_decided(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case, first, second = await incident(migrated_engine, app_engine, people)
    await knownrun.run(app_engine, context(), at(3, 10))
    third = await make(migrated_engine, when=at(4, 12))
    await knownrun.run(app_engine, context(), at(4, 13))
    assert await attention(app_engine) == {}
    asha = people["asha"]
    async with app_engine.begin() as conn:
        service = await CaseService.start(conn)
        applied = await service.apply(
            asha.actor(), case, WithdrawNotice("Asha", "recorded on the wrong case"),
            expected_version=None,
        )  # fmt: skip
    assert applied.step.kind == "notice_withdrawn"
    (row,) = await rows(app_engine, "SELECT state, notified_at, version FROM cases WHERE id = :c",
                        c=case)  # fmt: skip
    assert (row.state, row.notified_at) == ("open", None)
    (event,) = await rows(
        app_engine,
        "SELECT details FROM case_events WHERE case_id = :c AND kind = 'notice_withdrawn'",
        c=case,
    )  # fmt: skip
    assert event.details["by"] == "Asha"
    assert event.details["reason"] == "recorded on the wrong case"
    # the pass does not track it, nothing it decided comes back, and a new alert is normal work
    assert (await knownrun.run(app_engine, context(), at(5, 9))).cases == []
    assert await attention(app_engine) == {}
    assert set(await known_rows(app_engine, case)) == {first, second, third}
    fourth = await make(migrated_engine, when=at(5, 12))
    await knownrun.run(app_engine, context(), at(5, 13))
    assert fourth not in await known_rows(app_engine, case)
    assert fourth in await attention(app_engine)
    # the notice stays as said, marked withdrawn; the page no longer lists a notified case
    async with app_engine.connect() as conn:
        (notice,) = await knownview.notices(conn, case)
        assert await knownview.notified(conn, at(6)) == []
    assert notice.withdrawn
    # a notice recorded again starts afresh: one notice counted, the case tracked once more
    await notify(app_engine, asha, case, at(5, 14), told="the owner, Hostel 5 (this time)")
    async with app_engine.connect() as conn:
        (status,) = await knownview.notified(conn, at(6))
    assert status.owner_notices == 1
    report = await knownrun.run(app_engine, context(), at(5, 15))
    assert report.cases[0].number == 1
    notices = await rows(app_engine, "SELECT case_version FROM case_notices WHERE case_id = :c"
                         " ORDER BY case_version", c=case)  # fmt: skip
    assert len(notices) == 2


async def test_withdrawing_needs_a_notice_and_a_person(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    for_asha = await make(migrated_engine, when=at(0, 10))
    case = await open_case(app_engine, people["asha"], [for_asha])
    async with app_engine.begin() as conn:
        service = await CaseService.start(conn)
        with pytest.raises(CaseRefused, match="no notice to withdraw"):
            await service.apply(people["asha"].actor(), case, WithdrawNotice("Asha", "x"),
                                expected_version=None)  # fmt: skip


# --------------------------------------------------------------------------- 10. seeding


async def test_a_member_linked_after_the_notice_is_judged_like_any_new_investigation(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """The seed absorbs only what the owner was told about: the members linked at or before the
    notice. A later member with a new kind of evidence is a change, not part of the fingerprint."""
    case, first, second = await incident(migrated_engine, app_engine, people)
    late = await make(migrated_engine, when=at(4, 12), flags=(BEACON, OUTSIDE, SUCCESS))
    async with app_engine.begin() as conn:
        await (await CaseService.start(conn)).apply(
            people["asha"].actor(), case,
            Link((Member(late, "person"),), ()), expected_version=None,
        )  # fmt: skip
    report = await knownrun.run(app_engine, context(), at(4, 13))
    assert report.problems == []
    decided = await known_rows(app_engine, case)
    assert decided[first] == decided[second] == ("known", None)
    assert decided[late][0] == "changed"
    assert "successful answers after the alert" in (decided[late][1] or "")
    assert late in await attention(app_engine)
    flags = {r.value for r in await rows(app_engine, "SELECT value FROM case_known_keys WHERE"
                                         " case_id = :c AND kind = 'flag' AND source = 'notice'",
                                         c=case)}  # fmt: skip
    assert flags == {BEACON, OUTSIDE}


# --------------------------------------------------------------------------- 11. the days


async def test_the_alerts_a_day_are_ist_days(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """20:00 UTC is 1:30 AM IST of the next day: the day counts are IST days, as the reports."""
    case, _, _ = await incident(migrated_engine, app_engine, people)
    await knownrun.run(app_engine, context(), at(3, 10))
    late = await make(migrated_engine, when=at(4, 20), alerts=2)
    await knownrun.run(app_engine, context(), at(4, 21))
    assert late in await members(app_engine, case)
    async with app_engine.connect() as conn:
        (status,) = await knownview.notified(conn, at(6), case_id=case)
    ist = (at(4, 20) + timedelta(hours=5, minutes=30)).date().isoformat()
    assert set(status.per_day) == {ist}  # not the UTC day of the alerts
    assert sum(status.per_day.values()) == 2


# --------------------------------------------------------------------------- 12. an old proposal


async def test_a_stop_proposal_that_expired_is_made_again_and_a_waiting_one_is_not(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case, _, _ = await incident(migrated_engine, app_engine, people)
    await knownrun.run(app_engine, context(), at(3, 10))
    later = at(3, 10) + timedelta(days=15)
    first = await knownrun.run(app_engine, context(), later)
    assert first.cases[0].proposed
    waiting = await knownrun.run(app_engine, context(), later + timedelta(hours=1))
    assert not waiting.cases[0].proposed  # asked once while it waits
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("ALTER TABLE approval_requests DISABLE TRIGGER approval_requests_append_only_rows")
        )
    async with migrated_engine.begin() as conn:
        await conn.execute(text("UPDATE approval_requests SET expires_at = now() - interval"
                                " '1 minute', requested_at = now() - interval '2 days'"
                                " WHERE case_id = :c"), {"c": case})  # fmt: skip
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text(
                "ALTER TABLE approval_requests ENABLE ALWAYS TRIGGER"
                " approval_requests_append_only_rows"
            )
        )
    again = await knownrun.run(app_engine, context(), later + timedelta(days=4))
    assert again.cases[0].proposed
    requests = await rows(app_engine, "SELECT reason FROM approval_requests WHERE case_id = :c",
                          c=case)  # fmt: skip
    assert [r.reason for r in requests] == ["stopped_after_notice", "stopped_after_notice"]
