"""The known infection of a notified case against the database (AR4b, D-169, D-176), as the
runtime login runs it: the acceptance test of D-169 (the Amadey host, its owner told on the fourth
day), a moved address, the reminders, the proposal to close, and what the pages count."""

from __future__ import annotations

import uuid
from datetime import timedelta

import pytest
from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.assess import patterns
from argus.campaigns.analysis import Campaign
from argus.cases import knownrun, suggest
from argus.cases.known import Rules
from argus.cases.machine import Contain, Link, RecordBlock
from argus.cases.model import Indicator, Member, QuietWindow
from argus.cases.service import CaseService
from argus.web import queries
from tests.integration.cases.conftest import APPROVER, Person, asking, rows, signed_for
from tests.integration.cases.knownkit import (
    BEACON,
    CLASSIFIER,
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

pytestmark = pytest.mark.integration


async def attention(engine: AsyncEngine) -> dict[uuid.UUID, queries.Summary]:
    async with engine.connect() as conn:
        return {s.id: s for s in await queries.inbox(conn, "attention", limit=100)}


async def counts(engine: AsyncEngine) -> dict[str, int]:
    async with engine.connect() as conn:
        return await queries.counts(conn, at(9))


async def ai_candidates(engine: AsyncEngine) -> set[uuid.UUID]:
    """The investigations the AI investigator's picker would read now (``patterns.schedule``'s
    own query)."""
    async with engine.connect() as conn:
        found = await conn.execute(
            text(patterns._CANDIDATES).bindparams(bindparam("skip", type_=ARRAY(UUID))),
            {"assessor": "agent@1", "after": None, "skip": [], "since": at(-5), "fetch": 500},
        )
        return {r.investigation_id for r in found}


async def incident(
    migrated: AsyncEngine, app: AsyncEngine, people: dict[str, Person]
) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID]:
    """The Amadey host: a download on the first day and a beacon on the second, both in one case;
    the owner was told on the fourth day at 09:00 UTC."""
    for ip in SERVERS:
        await flag_server(migrated, ip, at(0))
    first = await make(migrated, when=at(0, 10), rule="download")
    second = await make(migrated, when=at(1, 10), rule="beacon")
    case = await open_case(app, people["asha"], [first, second])
    await notify(app, people["asha"], case, at(3, 9))
    return case, first, second


async def test_the_amadey_acceptance_known_alerts_join_silently_and_a_change_is_raised(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case, first, second = await incident(migrated_engine, app_engine, people)
    assert set(await attention(app_engine)) == {first, second}  # both raised: beacon + outside

    # the first pass takes the fingerprint; what the case holds is what the owner was told about
    report = await knownrun.run(app_engine, context(), at(3, 10))
    assert report.problems == []
    assert await known_rows(app_engine, case) == {first: ("known", None), second: ("known", None)}
    assert await attention(app_engine) == {}
    seed = await rows(app_engine, "SELECT kind, value FROM case_known_keys WHERE case_id = :c",
                      c=case)  # fmt: skip
    kinds = {(r.kind, r.value) for r in seed}
    assert {("flag", BEACON), ("flag", OUTSIDE), ("seed", ""), ("bytes", "1000000")} <= kinds

    # the next day: more of the same lands, after the notice: it joins the case and is counted
    third = await make(migrated_engine, when=at(4, 12))
    fourth = await make(migrated_engine, when=at(4, 14), rule="download", nbytes=3_000_000)
    stranger = await make(migrated_engine, when=at(4, 12), host=OTHER_HOST, rule="beacon-2")
    assert third in await attention(app_engine)  # until the pass reads it
    report = await knownrun.run(app_engine, context(), at(4, 15))
    assert report.cases[0].known == 2
    assert report.cases[0].changed == 0
    assert await members(app_engine, case) >= {first, second, third, fourth}
    assert stranger not in await members(app_engine, case)  # another device: not absorbed
    shown = await attention(app_engine)
    assert {third, fourth}.isdisjoint(shown)  # never raised: they are known
    assert stranger in shown  # another device's alerts are new work
    assert (await counts(app_engine))["known"] == 4
    assert third not in await ai_candidates(app_engine)  # and no AI run is spent on them
    assert fourth not in await ai_candidates(app_engine)
    assert stranger in await ai_candidates(app_engine)

    # a new flagged server on the same host is a change: raised, with its reason
    await flag_server(migrated_engine, NEW_SERVER, at(5))
    fifth = await make(migrated_engine, when=at(5, 11), servers=(*SERVERS[:2], NEW_SERVER))
    report = await knownrun.run(app_engine, context(), at(5, 12))
    assert report.cases[0].changed == 1
    outcome, why = (await known_rows(app_engine, case))[fifth]
    assert outcome == "changed"
    assert why == "changed since notice: a new flagged destination (185.9.9.9)"
    shown = await attention(app_engine)
    assert fifth in shown
    assert "Changed since notice: a new flagged destination (185.9.9.9)." in shown[fifth].reasons
    assert fifth in await members(app_engine, case)  # it is the same infection: in the case
    assert fifth in await ai_candidates(app_engine)  # new information: the investigator looks
    indicators = await rows(app_engine, "SELECT value FROM case_indicators WHERE case_id = :c",
                            c=case)  # fmt: skip
    assert NEW_SERVER in {r.value for r in indicators}

    # ... and it speaks once: the next investigation to the same new server is known
    sixth = await make(migrated_engine, when=at(5, 15), servers=(*SERVERS[:2], NEW_SERVER))
    await knownrun.run(app_engine, context(), at(5, 16))
    assert (await known_rows(app_engine, case))[sixth] == ("known", None)
    assert sixth not in await attention(app_engine)

    # a new kind of evidence (success after an attack) is a change too
    seventh = await make(migrated_engine, when=at(5, 17), flags=(BEACON, OUTSIDE, SUCCESS))
    await knownrun.run(app_engine, context(), at(5, 18))
    outcome, why = (await known_rows(app_engine, case))[seventh]
    assert outcome == "changed"
    assert "successful answers after the alert" in (why or "")

    # new work and known work, counted apart: the first four and the sixth are known; the
    # stranger, the new server's and the new kind of evidence are new
    totals = await counts(app_engine)
    assert totals["known"] == 5
    assert totals["attention"] == 3

    # the new host on the same servers becomes a suggested addition to the same case
    other = await make(migrated_engine, when=at(5, 18), host=OTHER_HOST, rule="beacon-3")
    await knownrun.run(app_engine, context(), at(5, 19))
    assert other not in await members(app_engine, case)
    campaign = Campaign(
        frozenset({other}), frozenset({("ip", OTHER_HOST)}), (), SERVERS, SERVERS[:1], (), (),
        0.0, {other: frozenset({("ip", OTHER_HOST)})},
    )  # fmt: skip
    made = await suggest.run(app_engine, classifier=CLASSIFIER, dry_run=False, now=at(5, 20),
                             campaigns=[campaign])  # fmt: skip
    assert made.applied == {"offered": 1}
    offers = await rows(app_engine, "SELECT investigation_id, case_id, kind FROM case_suggestions")
    # one offer for the new device (its two investigations together), to the same case
    assert {(o.investigation_id, o.case_id, o.kind) for o in offers} == {
        (stranger, case, "also"), (other, case, "also"),
    }  # fmt: skip
    assert len(await rows(app_engine, "SELECT id FROM cases")) == 1  # no new case, ever


async def test_a_notice_recorded_after_the_fact_does_not_make_later_activity_known(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """The live Amadey case (10-30): the notice was recorded a day after the CISO's mail, and the
    case already held a beacon to a new flagged server sent after the mail. What the owner was told
    about ends at the notice's time: the later beacon is a change, not known."""
    for ip in SERVERS:
        await flag_server(migrated_engine, ip, at(0))
    await flag_server(migrated_engine, NEW_SERVER, at(4))
    first = await make(migrated_engine, when=at(0, 10), rule="download")
    second = await make(migrated_engine, when=at(1, 10), rule="beacon")
    late = await make(migrated_engine, when=at(4, 12), servers=(*SERVERS[:2], NEW_SERVER))
    case = await open_case(app_engine, people["asha"], [first, second, late])
    await notify(app_engine, people["asha"], case, at(3, 9))  # told on day 3, recorded on day 5

    report = await knownrun.run(app_engine, context(), at(5, 10))
    assert report.problems == []
    decided = await known_rows(app_engine, case)
    assert decided[first] == ("known", None)
    assert decided[second] == ("known", None)
    assert decided[late] == (
        "changed",
        "changed since notice: a new flagged destination (185.9.9.9)",
    )
    assert late in await attention(app_engine)


async def test_a_pass_is_idempotent_and_decides_each_version_once(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case, _, _ = await incident(migrated_engine, app_engine, people)
    third = await make(migrated_engine, when=at(4, 12))
    await knownrun.run(app_engine, context(), at(4, 13))
    before = await rows(app_engine, "SELECT version FROM cases WHERE id = :c", c=case)
    again = await knownrun.run(app_engine, context(), at(4, 14))
    assert again.cases[0].quiet
    assert await rows(app_engine, "SELECT version FROM cases WHERE id = :c", c=case) == before
    assert (await known_rows(app_engine, case))[third] == ("known", None)
    # a new version of the investigation is decided again
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("UPDATE investigations SET version = 2, last_event_at = :t WHERE id = :i"),
            {"t": at(4, 20), "i": third},
        )
        await conn.execute(
            text("UPDATE investigation_raises SET version = 2, evaluated_at = :t WHERE"
                 " investigation_id = :i"),
            {"t": at(4, 20), "i": third},
        )  # fmt: skip
    assert third in (await attention(app_engine))  # until the pass reads the new version
    await knownrun.run(app_engine, context(), at(4, 21))
    rowset = await rows(app_engine, "SELECT version FROM case_known_matches WHERE"
                        " investigation_id = :i", i=third)  # fmt: skip
    assert [r.version for r in rowset] == [2]
    assert third not in await attention(app_engine)


async def test_a_reviewed_investigation_is_left_alone_and_other_cases_keep_theirs(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case, _, _ = await incident(migrated_engine, app_engine, people)
    reviewed = await make(migrated_engine, when=at(4, 12))
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO review_events (investigation_id, version, alert_count, user_id,"
                 " action, outcome) VALUES (:i, 1, 3, :u, 'reviewed', 'true_positive')"),
            {"i": reviewed, "u": people["ravi"].user_id},
        )  # fmt: skip
    elsewhere = await make(migrated_engine, when=at(4, 13))
    other_case = await open_case(app_engine, people["meera"], [elsewhere], host=OTHER_HOST)
    await knownrun.run(app_engine, context(), at(4, 14))
    decided = await known_rows(app_engine, case)
    assert reviewed not in decided  # a person looked at it: it needs nothing
    assert elsewhere not in decided  # another case holds it
    assert elsewhere in await members(app_engine, other_case)


async def test_nothing_is_decided_for_a_case_that_was_never_notified(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    for ip in SERVERS:
        await flag_server(migrated_engine, ip, at(0))
    first = await make(migrated_engine, when=at(0, 10))
    case = await open_case(app_engine, people["asha"], [first])
    follower = await make(migrated_engine, when=at(4, 12))
    report = await knownrun.run(app_engine, context(), at(4, 13))
    assert report.cases == []
    assert await known_rows(app_engine, case) == {}
    assert follower in await attention(app_engine)  # a case nobody told anyone about: new work


async def _verified(case: object) -> QuietWindow:
    return QuietWindow(True, "72 quiet hours")


async def test_a_contained_case_is_no_longer_a_known_infection_but_keeps_what_it_decided(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """D-181: what was decided known before the case ended is frozen (it never floods Needs
    attention); the case is not tracked any more, and a later version is judged afresh."""
    case, first, _ = await incident(migrated_engine, app_engine, people)
    await knownrun.run(app_engine, context(), at(3, 10))
    assert await attention(app_engine) == {}
    async with app_engine.begin() as conn:
        service = await CaseService.start(conn, _verified)  # type: ignore[arg-type]
        await service.apply(
            people["asha"].actor(), case, Contain("cleaned", QuietWindow(True, "x")),
            expected_version=None,
        )  # fmt: skip
    (row,) = await rows(app_engine, "SELECT state, notified_at FROM cases WHERE id = :c", c=case)
    assert (row.state, row.notified_at) == ("contained", None)
    assert await attention(app_engine) == {}  # frozen: not new work
    assert (await counts(app_engine))["known"] == 0  # and no longer "notified, still active"
    assert (await knownrun.run(app_engine, context(), at(4, 10))).cases == []
    # a later version of the investigation goes through the normal pipeline
    async with migrated_engine.begin() as conn:
        await conn.execute(text("UPDATE investigations SET version = 2 WHERE id = :i"),
                           {"i": first})  # fmt: skip
        await conn.execute(text("UPDATE investigation_raises SET version = 2 WHERE"
                                " investigation_id = :i"), {"i": first})  # fmt: skip
    assert set(await attention(app_engine)) == {first}


async def test_the_assessment_pass_runs_the_known_infections_and_says_so(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    from argus import raising

    case, first, second = await incident(migrated_engine, app_engine, people)
    done = await raising.run(app_engine, CLASSIFIER, at(3, 10), suggesting=False, last=None,
                             known=context())  # fmt: skip
    assert done.warned == []
    assert any(line.startswith("known infections: case ") and "known 2" in line
               for line in done.said)  # fmt: skip
    assert await known_rows(app_engine, case) == {first: ("known", None), second: ("known", None)}
    quiet = await raising.run(app_engine, CLASSIFIER, at(3, 11), suggesting=False, last=None,
                              known=context())  # fmt: skip
    assert any(line == "known infections: nothing new" for line in quiet.said)
    # a failure is said, and the pass goes on
    broken = await raising.run(
        app_engine,
        CLASSIFIER,
        at(3, 12),
        suggesting=False,
        last=None,
        known=context(per_pass="many"),
    )  # type: ignore[arg-type]
    assert any("known infections failed" in line or "known infections:" in line
               for line in [*broken.warned, *broken.said])  # fmt: skip


# --------------------------------------------------------------------------- a moved address


async def test_the_same_indicators_from_a_new_address_is_a_note_not_a_new_case(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case, _, _ = await incident(migrated_engine, app_engine, people)
    await knownrun.run(app_engine, context(), at(3, 10))
    # the host's last alert was on the second day at 10:00; the new address begins 20 hours later
    moved = await make(migrated_engine, when=at(4, 8), host="10.198.99.4")
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("UPDATE investigations SET first_event_at = :t WHERE id = :i"),
            {"t": at(1, 10) + timedelta(hours=20), "i": moved},
        )
    await knownrun.run(app_engine, context(), at(4, 9))
    outcome, _ = (await known_rows(app_engine, case))[moved]
    assert outcome == "known"
    assert moved in await members(app_engine, case)
    indicators = await rows(
        app_engine,
        "SELECT value, role FROM case_indicators WHERE case_id = :c AND kind = 'ip'", c=case,
    )  # fmt: skip
    assert ("10.198.99.4", "actor") in {(r.value, r.role) for r in indicators}
    (event,) = await rows(
        app_engine,
        "SELECT details FROM case_events WHERE case_id = :c AND kind = 'address_moved'", c=case,
    )  # fmt: skip
    assert event.details["old"] == HOST
    assert event.details["new"] == "10.198.99.4"
    assert event.details["hours"] == 20
    assert event.details["summary"].startswith("probably the same device, new address (")
    assert len(await rows(app_engine, "SELECT id FROM cases")) == 1
    # no new-device offer is made for it: the address is a device of the case now
    campaign = Campaign(
        frozenset({moved}), frozenset({("ip", "10.198.99.4")}), (), SERVERS, SERVERS[:1], (), (),
        0.0, {moved: frozenset({("ip", "10.198.99.4")})},
    )  # fmt: skip
    made = await suggest.run(app_engine, classifier=CLASSIFIER, dry_run=False, now=at(4, 10),
                             campaigns=[campaign])  # fmt: skip
    assert made.applied == {}


async def test_two_devices_that_could_be_the_old_one_are_never_guessed_between(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case, _, _ = await incident(migrated_engine, app_engine, people)
    second_host = await make(migrated_engine, when=at(1, 11), host="10.198.36.231")
    async with app_engine.begin() as conn:
        await (await CaseService.start(conn)).apply(
            people["asha"].actor(), case,
            Link((Member(second_host, "actor"),), (Indicator("ip", "10.198.36.231", "actor"),)),
            expected_version=None,
        )  # fmt: skip
    await knownrun.run(app_engine, context(), at(3, 10))
    newcomer = await make(migrated_engine, when=at(4, 8), host="10.198.99.4")
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("UPDATE investigations SET first_event_at = :t WHERE id = :i"),
            {"t": at(1, 20), "i": newcomer},
        )
    await knownrun.run(app_engine, context(), at(4, 9))
    assert newcomer not in await members(app_engine, case)  # two old devices fit: no guess
    assert newcomer not in await known_rows(app_engine, case)


async def test_a_host_name_the_case_holds_makes_a_new_address_the_same_device(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """A stronger key than any timing: the data carries the host name."""
    case, _, _ = await incident(migrated_engine, app_engine, people)
    async with app_engine.begin() as conn:
        await (await CaseService.start(conn)).apply(
            people["asha"].actor(), case,
            Link((), (Indicator("host", "LAB-PC-7", "actor"),)), expected_version=None,
        )  # fmt: skip
    await knownrun.run(app_engine, context(), at(3, 10))
    again = await make(migrated_engine, when=at(30, 8), host="10.198.77.7",
                       extra=(("host", "LAB-PC-7"),))  # fmt: skip
    async with migrated_engine.begin() as conn:  # the host name is a key of the grouping, too
        await conn.execute(
            text("UPDATE investigations SET group_key = :k WHERE id = :i"),
            {"k": '[["host.name","LAB-PC-7"],["source.ip","10.198.77.7"]]', "i": again},
        )
    await knownrun.run(app_engine, context(), at(30, 9))
    assert (await known_rows(app_engine, case))[again][0] == "known"
    (event,) = await rows(
        app_engine,
        "SELECT details FROM case_events WHERE case_id = :c AND kind = 'address_moved'", c=case,
    )  # fmt: skip
    assert event.details["old"] == "host LAB-PC-7"
    assert event.details["new"] == "10.198.77.7"


# --------------------------------------------------------------------------- reminders, ending


async def test_a_case_still_active_earns_two_reminders_and_a_quiet_one_a_proposal_to_close(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case, _, _ = await incident(migrated_engine, app_engine, people)
    await knownrun.run(app_engine, context(), at(3, 10))
    await make(migrated_engine, when=at(9, 8))  # activity six days after the notice
    one = await knownrun.run(app_engine, context(), at(10, 9))  # seven days after it
    assert one.cases[0].reminders == ["notify_again"]
    (reminder,) = await rows(app_engine, "SELECT kind, why FROM case_reminders")
    assert reminder.kind == "notify_again"
    assert "7 days after the owner was told" in reminder.why
    again = await knownrun.run(app_engine, context(), at(10, 10))
    assert again.cases[0].reminders == []  # one suggestion, once
    await make(migrated_engine, when=at(23, 8))
    two = await knownrun.run(app_engine, context(), at(24, 9))  # 21 days after the notice
    assert two.cases[0].reminders == ["network_action"]
    assert {r.kind for r in await rows(app_engine, "SELECT kind FROM case_reminders")} == {
        "notify_again", "network_action",
    }  # fmt: skip
    # no alarm: the case did not change state and nothing came back into Needs attention
    (row,) = await rows(app_engine, "SELECT state FROM cases WHERE id = :c", c=case)
    assert row.state == "open"
    assert await attention(app_engine) == {}
    # 14 days without matching activity: ARGUS proposes closing as "stopped after notice"
    done = await knownrun.run(app_engine, context(), at(23, 8) + timedelta(days=15))
    assert done.cases[0].proposed
    (request,) = await rows(
        app_engine, "SELECT reason, proposed_by, kind FROM approval_requests WHERE case_id = :c",
        c=case,
    )  # fmt: skip
    assert (request.reason, request.kind) == ("stopped_after_notice", "closure")
    assert request.proposed_by == "argus:proposer"
    nothing = await knownrun.run(app_engine, context(), at(23, 8) + timedelta(days=16))
    assert not nothing.cases[0].proposed  # asked once; a person decides


async def test_the_days_are_settings_and_a_block_ends_the_network_reminder(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case, _, _ = await incident(migrated_engine, app_engine, people)
    quick = Rules(renotify_days=1, network_days=2, active_days=2, quiet_days=30)
    await knownrun.run(app_engine, context(rules=quick), at(3, 10))
    await make(migrated_engine, when=at(5, 8))
    async with app_engine.begin() as conn:
        await (await CaseService.start(conn)).apply(
            people["ravi"].actor(), case, RecordBlock("network team", "DNS"), expected_version=None
        )  # fmt: skip
    report = await knownrun.run(app_engine, context(rules=quick), at(5, 9))
    assert report.cases[0].reminders == ["notify_again"]  # blocked: no network-side suggestion


async def test_a_case_stopped_after_notice_speaks_again_if_the_device_comes_back(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person],
    api_engine: AsyncEngine,
) -> None:  # fmt: skip
    case, _, _ = await incident(migrated_engine, app_engine, people)
    await knownrun.run(app_engine, context(), at(3, 10))
    asha, ravi = people["asha"], people["ravi"]
    async with api_engine.begin() as conn:  # a person asks, an approver closes it
        service = await CaseService.start(conn)
        version = (await service.get(case)).version  # type: ignore[union-attr]
        _, request_id = await service.request_closure(
            asha.actor(), case, expected_version=version, reason="stopped_after_notice",
            session_token=asha.session_token, check=await asking(conn, asha),
        )  # fmt: skip
    async with api_engine.begin() as conn:
        service = await CaseService.start(conn)
        signed = await signed_for(conn, ravi, request_id)
        await service.decide(ravi.actor(APPROVER), request_id, session_token=ravi.session_token,
                             decision="approved", signed=signed)  # fmt: skip
    # the story's own clock: the case was closed on day 20 (the owner may switch its guard off)
    async with migrated_engine.begin() as conn:
        await conn.execute(text("ALTER TABLE cases DISABLE TRIGGER cases_guard"))
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("UPDATE cases SET closed_at = :t WHERE id = :c"), {"t": at(20), "c": case}
        )
    async with migrated_engine.begin() as conn:
        await conn.execute(text("ALTER TABLE cases ENABLE ALWAYS TRIGGER cases_guard"))

    (row,) = await rows(app_engine, "SELECT state, notified_at, closure_reason FROM cases"
                        " WHERE id = :c", c=case)  # fmt: skip
    assert (row.state, row.notified_at, row.closure_reason) == ("closed", None,
                                                               "stopped_after_notice")  # fmt: skip
    back = await make(migrated_engine, when=at(25, 8))
    report = await knownrun.run(app_engine, context(), at(25, 9))
    assert report.cases[0].changed == 1
    outcome, why = (await known_rows(app_engine, case))[back]
    assert outcome == "changed"
    assert why is not None
    assert "it is active again after it stopped (case" in why
    assert back not in await members(app_engine, case)  # nothing is reopened or joined
    assert back in await attention(app_engine)
