"""AR2b (D-154, D-155, D-160) against the database, as ARGUS's own login: the Amadey shape (one
host, a download and a beacon on one day, low and medium, then more over three days) is raised
into Needs attention and becomes one suggested case; the Git shape (two outside addresses at the
same rare directories) becomes one; nothing is opened, a person confirms; runs repeat without
duplicates. Synthetic data only."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, date, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.assess import raised
from argus.assets.classify import IpClassifier
from argus.cases import membership, opener, suggest
from argus.cases.machine import (
    NEW_ACTIVITY,
    RAISED_REASON,
    Confirm,
    Contain,
    Dismiss,
    NewActivity,
    replay,
)
from argus.cases.membership import Shared
from argus.cases.model import Actor, Member, QuietWindow
from argus.cases.service import CaseService
from argus.web import casepages, queries
from tests.integration.cases.conftest import Person, investigation, rows
from tests.integration.cases.test_opener import _review

pytestmark = pytest.mark.integration
CLASSIFIER = IpClassifier(None)
NOW = datetime(2026, 10, 24, 12, 0, tzinfo=UTC)
HOST = "10.20.30.40"
BEACON = {"name": "proxy.regularity", "status": "known", "value": 0.0}
LISTED = {"name": "ti.listed", "status": "known", "value": 1}
SERVER = "203.0.113.50"  # not linkable as an address; the directories carry the Git shape
DAY0 = date(2026, 10, 11)  # the helper's day 0, in IST


def ist_day(day: date) -> int:
    return (day - DAY0).days


async def make(
    owner: AsyncEngine,
    *,
    rule: str,
    host: str = HOST,
    day: date = date(2026, 10, 24),
    hours: float = 1.0,
    severity: str = "low",
    signals: tuple[dict[str, Any], ...] = (),
    paths: tuple[str, ...] = (),
    entities: tuple[tuple[str, str], ...] = (),
) -> uuid.UUID:
    """An unreviewed investigation of ``host`` with its newest dossier (signals and the paths its
    alerts asked for), last active ``hours`` before NOW."""
    inv = await investigation(owner, rule=rule, actor=(("source.ip", host),), entities=entities,
                              severity=severity, day=ist_day(day))  # fmt: skip
    fields = {"url.path": {"alerts": 1, "distinct": len(paths),
                           "top": [[p, 3] for p in paths]}} if paths else {}  # fmt: skip
    body = {"local_signals": list(signals), "signals": [], "report": {"steps": []},
            "context": {"pack": {"fields": fields}}}  # fmt: skip
    async with owner.begin() as conn:
        await conn.execute(
            text("UPDATE investigations SET first_event_at = :t, last_event_at = :t WHERE id = :i"),
            {"t": NOW - timedelta(hours=hours), "i": inv},
        )
        await conn.execute(
            text(
                "INSERT INTO dossiers (investigation_id, version, pack, facts_version, job_id,"
                " run_kind, family, status, dossier_hash, body, evidence_count, created_at)"
                " VALUES (:i, 1, 'generic@12', 1, 1, 'collect', 'proxy', 'evidence_ready',"
                " :h, CAST(:b AS jsonb), 0, now())"
            ),
            {"i": inv, "h": inv.hex.ljust(64, "0"), "b": json.dumps(body)},
        )
    return inv


async def cycle(engine: AsyncEngine, now: datetime = NOW, *, dry: bool = False) -> suggest.Report:
    """What the assessment service does every pass: read the evidence, then suggest."""
    async with engine.begin() as conn:
        await raised.evaluate(conn, now)
    return await suggest.run(engine, classifier=CLASSIFIER, dry_run=dry, shared=Shared(), now=now)


async def attention(engine: AsyncEngine) -> dict[uuid.UUID, queries.Summary]:
    async with engine.connect() as conn:
        found = await queries.inbox(conn, "attention", limit=100)
    return {s.id: s for s in found}


async def case_of(engine: AsyncEngine) -> Any:
    (case,) = await rows(engine, "SELECT * FROM cases")
    return case


async def members(engine: AsyncEngine) -> set[uuid.UUID]:
    found = await rows(engine, "SELECT investigation_id FROM case_members WHERE removed_at IS NULL")
    return {m.investigation_id for m in found}


# -- the Amadey replay ------------------------------------------------------------------------


async def test_the_amadey_shape_is_raised_and_becomes_one_suggested_case_as_it_arrives(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    quiet = await make(migrated_engine, rule="scan", host="10.1.1.1", hours=2)  # unrelated noise
    download = await make(migrated_engine, rule="download", signals=(BEACON, LISTED), hours=6)
    beacon = await make(migrated_engine, rule="beacon", severity="medium", signals=(BEACON, LISTED),
                        hours=5)  # fmt: skip

    # within one assess cycle of the second investigation ...
    dry = await cycle(app_engine, dry=True)
    assert [suggest.describe(a) for a in dry.planned] == [
        "suggested   2 investigations: Beaconing from 10.20.30.40"
    ]
    assert await rows(app_engine, "SELECT * FROM cases") == []  # a dry run writes nothing
    report = await cycle(app_engine)
    assert report.applied == {"suggested": 1}
    shown = await attention(app_engine)
    # a beacon whose server is on a threat list is a raise (D-164); a beacon alone is not, and
    # without a raise the pair is no story either (D-168)
    assert {download, beacon} <= set(shown)
    assert quiet not in shown

    # ... and one suggested case, suspected: ARGUS opened nothing
    case = await case_of(app_engine)
    assert (case.state, case.cause, case.opened_at) == ("suspected", "raised", None)
    assert case.title == "Beaconing from 10.20.30.40"
    assert case.attention.startswith("ARGUS suggests this case: 2 investigations of one campus")
    assert HOST not in case.attention  # no log value in the reason; the title names the device
    assert await members(app_engine) == {download, beacon}
    marks = await rows(app_engine, "SELECT kind, value, role FROM case_indicators")
    assert [tuple(m) for m in marks] == [("ip", HOST, "actor")]
    assert await rows(app_engine, "SELECT * FROM kibana_outbox") == []  # nothing for Kibana

    # a second cycle changes nothing
    again = await cycle(app_engine)
    assert (again.planned, again.applied) == ([], {})

    # the next day: two more of the host arrive and join the same case
    d2 = await make(migrated_engine, rule="download", day=date(2026, 10, 24), hours=0.5)
    d3 = await make(migrated_engine, rule="beacon", signals=(BEACON, LISTED), hours=0.4)
    linked = await cycle(app_engine)
    assert linked.applied == {"linked": 1}
    assert await members(app_engine) == {download, beacon, d2, d3}
    assert len(await rows(app_engine, "SELECT * FROM cases")) == 1

    # days later, past the first ones' window: one more still joins, as an actor of the case
    later = NOW + timedelta(hours=100)
    last = await make(migrated_engine, rule="download", day=date(2026, 10, 28), hours=-99)
    joined = await cycle(app_engine, later)
    assert joined.applied == {"linked": 1}
    assert await members(app_engine) == {download, beacon, d2, d3, last}
    case = await case_of(app_engine)
    assert (case.state, case.version) == ("suspected", 3)

    # the history rebuilds the case, with its reason
    async with app_engine.connect() as conn:
        service = await CaseService.start(conn)
        stored = await service.get(case.id)
        assert stored is not None
        assert replay(await service.events(case.id)) == stored
        assert stored.attention == case.attention
        assert stored.cause == "raised"


async def test_a_person_confirms_the_suggestion_and_only_then_is_a_case_open(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    await make(migrated_engine, rule="download", signals=(BEACON, LISTED))
    await make(migrated_engine, rule="beacon", signals=(BEACON, LISTED))
    await cycle(app_engine)
    case = await case_of(app_engine)
    async with app_engine.begin() as conn:
        service = await CaseService.start(conn)
        done = await service.apply(people["asha"].actor(), case.id, Confirm(), expected_version=1)
    assert done.case.state == "open"
    assert done.case.attention == case.attention
    await cycle(app_engine)  # an open case takes no more from the raise
    assert (await case_of(app_engine)).state == "open"


async def test_a_dismissed_suggestion_is_not_made_again(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    await make(migrated_engine, rule="download", signals=(BEACON, LISTED))
    await make(migrated_engine, rule="beacon", signals=(BEACON, LISTED))
    await cycle(app_engine)
    case = await case_of(app_engine)
    async with app_engine.begin() as conn:
        service = await CaseService.start(conn)
        await service.apply(people["ravi"].actor(), case.id, Dismiss("benign_expected"),
                            expected_version=1)  # fmt: skip
    again = await cycle(app_engine)
    assert (again.planned, again.applied) == ([], {})  # the two are held by the closed case
    assert len(await rows(app_engine, "SELECT * FROM cases")) == 1


async def test_noise_is_not_suggested(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    await make(migrated_engine, rule="a")  # two rules, no flag
    await make(migrated_engine, rule="b")
    await make(
        migrated_engine, rule="a", host="10.9.9.9", signals=(BEACON, LISTED)
    )  # one flagged alone
    await make(
        migrated_engine, rule="a", host="10.8.8.8", signals=(BEACON, LISTED), hours=100
    )  # old
    await make(migrated_engine, rule="b", host="10.8.8.8", signals=(BEACON, LISTED), hours=100)
    report = await cycle(app_engine, NOW)
    assert (report.planned, report.applied) == ([], {})
    assert await rows(app_engine, "SELECT * FROM cases") == []


async def test_a_reviewed_investigation_is_left_out(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    done = await make(migrated_engine, rule="download", signals=(BEACON, LISTED))
    await make(migrated_engine, rule="beacon", signals=(BEACON, LISTED))
    async with app_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO review_events (investigation_id, version, alert_count, user_id,"
                " action, outcome) VALUES (:i, 1, 2, :u, 'reviewed', 'benign_expected')"
            ),
            {"i": done, "u": people["asha"].user_id},
        )
    assert (await cycle(app_engine)).planned == []  # one left is not a story


async def test_members_of_an_open_case_get_suggestions_not_a_competing_case(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    first = await make(migrated_engine, rule="download", signals=(BEACON, LISTED))
    second = await make(migrated_engine, rule="beacon", signals=(BEACON, LISTED))
    from argus.cases.machine import Open
    from argus.cases.model import Member

    async with app_engine.begin() as conn:
        service = await CaseService.start(conn)
        opened = await service.open(people["asha"].actor(), Open(
            "Opened by a person", "high", "person", (Member(first, "person"),)))  # fmt: skip
    report = await cycle(app_engine)
    assert report.applied == {"offered": 1}
    (offer,) = await rows(app_engine, "SELECT investigation_id, case_id, kind, link FROM"
                                      " case_suggestions")  # fmt: skip
    assert (offer.investigation_id, offer.case_id, offer.kind, offer.link) == (
        second, opened.case.id, "also", "actor"
    )  # fmt: skip
    assert len(await rows(app_engine, "SELECT * FROM cases")) == 1
    assert await members(app_engine) == {first}  # a person joins the other
    assert (await cycle(app_engine)).applied == {}  # already offered: nothing new, no duplicate
    assert len(await rows(app_engine, "SELECT * FROM case_suggestions")) == 1


# -- D-162: a person's "no" stands, the budget is the suggester's own, a verdict is not a Confirm --


async def dismissed_story(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, person: Person
) -> None:
    await make(migrated_engine, rule="download", signals=(BEACON, LISTED), hours=6)
    await make(migrated_engine, rule="beacon", signals=(BEACON, LISTED), hours=5)
    await cycle(app_engine)
    case = await case_of(app_engine)
    async with app_engine.begin() as conn:
        service = await CaseService.start(conn)
        await service.apply(person.actor(), case.id, Dismiss("benign_expected"), expected_version=1)


async def test_new_investigations_of_a_dismissed_host_do_not_bring_the_suggestion_back(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    await dismissed_story(app_engine, migrated_engine, people["ravi"])
    both = (BEACON, LISTED)
    new = [await make(migrated_engine, rule="download", signals=both, hours=1),
           await make(migrated_engine, rule="beacon", signals=both, hours=0.5)]  # fmt: skip
    again = await cycle(app_engine)
    assert (again.planned, again.applied) == ([], {})  # the same host, the same kind of flag
    assert len(await rows(app_engine, "SELECT * FROM cases")) == 1
    assert not set(new) & await members(app_engine)

    # a flag kind the dismissed case did not have is news
    risky = {"name": "ports.risky", "status": "known", "value": 1}
    await make(migrated_engine, rule="download", signals=(LISTED, risky), hours=0.2)
    news = await cycle(app_engine)
    assert news.applied == {"suggested": 1}
    assert len(await rows(app_engine, "SELECT * FROM cases")) == 2


async def test_a_dismissal_stands_for_two_weeks(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    await dismissed_story(app_engine, migrated_engine, people["ravi"])
    async with app_engine.connect() as conn:
        now = datetime.now(UTC)
        (no,) = await suggest.load_dismissed(conn, now)
        assert no.actors == frozenset({("ip", HOST)})
        assert no.flags == frozenset({"on a threat list", "regular traffic, like a beacon"})
        later = now + suggest.DISMISSAL_STANDS + timedelta(days=1)
        assert await suggest.load_dismissed(conn, later) == []


async def test_a_confirmed_suggestion_leaves_needs_attention_and_keeps_its_reason(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    await make(migrated_engine, rule="download", signals=(BEACON, LISTED))
    await make(migrated_engine, rule="beacon", signals=(BEACON, LISTED))
    await cycle(app_engine)
    case = await case_of(app_engine)
    asha = people["asha"]

    async def view() -> tuple[casepages.m.CasePage, casepages.m.CaseRowOut | None]:
        async with migrated_engine.connect() as conn:
            page = await casepages.list_cases(conn, asha.user_id, "attention", offset=0, limit=10)
            return page, await casepages.row_of(conn, case.id)

    page, row = await view()
    assert [c.id for c in page.items] == [case.id]  # suspected: a person must decide
    assert page.counts.attention == 1
    async with app_engine.begin() as conn:
        service = await CaseService.start(conn)
        await service.apply(asha.actor(), case.id, Confirm(), expected_version=1)
    page, row = await view()
    assert page.items == []
    assert (page.counts.attention, page.counts.active) == (0, 1)
    assert row is not None
    assert (row.state, row.needs_attention) == ("open", False)
    assert (row.attention or "").startswith(RAISED_REASON)  # ARGUS's reason is still on the case

    # new activity after a containment is a reason for a person, whoever opened the case
    async def quiet(_: object) -> QuietWindow:
        return QuietWindow(True, "72 h quiet (test)")

    again = await make(migrated_engine, rule="beacon", signals=(BEACON, LISTED), hours=0.1)
    async with app_engine.begin() as conn:
        service = await CaseService.start(conn, quiet_windows=quiet)
        await service.apply(asha.actor(), case.id, Contain("cleaned", QuietWindow(False, "x")),
                            expected_version=None)  # fmt: skip
        await service.apply(Actor.argus("opener"), case.id,
                            NewActivity("again", (Member(again, "actor", HOST),), (), "medium"),
                            expected_version=None)  # fmt: skip
    page, row = await view()
    assert row is not None
    assert row.attention == NEW_ACTIVITY
    assert ([c.id for c in page.items], page.counts.attention) == ([case.id], 1)


async def test_a_persons_verdict_on_a_member_does_not_confirm_a_suggested_case(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    download = await make(migrated_engine, rule="download", signals=(BEACON, LISTED))
    await make(migrated_engine, rule="beacon", signals=(BEACON, LISTED))
    await cycle(app_engine)
    await _review(app_engine, people["asha"], download)  # true positive, a regular beacon
    report = await opener.run(
        app_engine, window=timedelta(days=5), classifier=CLASSIFIER, dry_run=False, shared=Shared()
    )
    assert report.applied == {"member_already": 1}
    case = await case_of(app_engine)
    assert (case.state, case.opened_at, case.version) == ("suspected", None, 1)
    assert await rows(app_engine, "SELECT * FROM kibana_outbox") == []
    (decided,) = await rows(app_engine, "SELECT decision, case_id FROM case_openings")
    assert (decided.decision, decided.case_id) == ("member_already", case.id)  # recorded as usual


async def test_suggestions_have_a_budget_of_their_own_spent_by_priority(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(suggest, "MAX_SUGGESTED_PER_HOUR", 1)
    quiet = [await make(migrated_engine, rule=r, host="10.1.1.1", signals=(BEACON, LISTED), hours=3)
             for r in ("a", "b")]  # fmt: skip
    grave = [await make(migrated_engine, rule=r, host="10.2.2.2", signals=(BEACON, LISTED), hours=9,
                        severity="critical") for r in ("a", "b")]  # fmt: skip
    first = await cycle(app_engine)
    assert first.applied == {"suggested": 1}
    assert await members(app_engine) == set(grave)  # the most severe, though older
    async with app_engine.connect() as conn:
        assert await suggest.suggested_last_hour(conn) == 1
        assert await opener.created_last_hour(conn) == 0  # the opener's twenty are all its own
    second = await cycle(app_engine)  # the hour's pool is spent: the other waits
    assert (second.planned, second.applied) == ([], {})
    assert not set(quiet) & await members(app_engine)


async def test_a_scanner_with_thousands_of_destinations_is_read_up_to_a_cap(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    names = tuple(("domain", f"a{n:03d}.example.net") for n in range(suggest.MAX_ENTITIES * 3))
    shared = ("domain", "zz-shared.example.net")  # last in name order, reached by 3 investigations
    scanner = await make(migrated_engine, rule="scan", host="10.5.5.5", entities=(*names, shared))
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO entities (kind, value, investigations) VALUES (:k, :v, 3)"),
            {"k": shared[0], "v": shared[1]},
        )
    async with app_engine.connect() as conn:
        (found,) = [s for s in await suggest.load_seen(conn, NOW, CLASSIFIER)
                    if s.investigation_id == scanner]  # fmt: skip
    assert len(found.targets) == suggest.MAX_ENTITIES
    assert shared in found.targets  # the one other investigations share comes first, not last


# -- the Git replay ---------------------------------------------------------------------------

SCOUT, COLLECTOR, LATER = "185.220.101.4", "185.220.101.5", "185.220.101.6"
REPOS = ("/~repo-a/.git/HEAD", "/~repo-b/.git/config", "/~repo-c/.git/refs/heads/main")


async def test_the_git_shape_two_outside_addresses_at_the_same_directories_are_one_case(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    scout = await make(migrated_engine, rule="scan", host=SCOUT, severity="high", hours=40,
                       paths=REPOS)  # fmt: skip
    collector = await make(
        migrated_engine, rule="volume", host=COLLECTOR, severity="high", hours=20,
        paths=("/~repo-a/.git/objects/ab/cd", "/~repo-b/.git/objects/ef/01",
               "/~repo-c/.git/packed-refs", "/~other/index.html"),
    )  # fmt: skip
    prober = await make(migrated_engine, rule="scan", host=LATER, severity="high", hours=2,
                        paths=("/.env",))  # fmt: skip
    report = await cycle(app_engine)
    assert report.applied == {"suggested": 1}
    case = await case_of(app_engine)
    assert (case.state, case.cause) == ("suspected", "raised")
    assert await members(app_engine) == {scout, collector}  # the prober shares nothing
    assert case.title == "Probing for Git repository folders by 2 outside addresses"  # D-232
    assert "2 actors reached the same 3 rare targets" in case.attention
    marks = await rows(app_engine, "SELECT kind, value, role FROM case_indicators")
    assert {tuple(m) for m in marks} == {
        ("ip", SCOUT, "actor"), ("ip", COLLECTOR, "actor"),
        ("url", "/~repo-a/.git", "indicator"), ("url", "/~repo-b/.git", "indicator"),
        ("url", "/~repo-c/.git", "indicator"),
    }  # fmt: skip
    links = await rows(app_engine, "SELECT investigation_id, link, link_value FROM case_members")
    assert {(m.investigation_id, m.link, m.link_value) for m in links} == {
        (scout, "actor", SCOUT), (collector, "actor", COLLECTOR)
    }  # fmt: skip
    assert prober not in await members(app_engine)

    again = await cycle(app_engine)
    assert again.planned == []


async def test_a_rare_server_two_hosts_reach_is_a_story_unless_it_is_everywhere(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    c2 = (("ip", "185.220.101.9"), ("domain", "update-check.example.net"))
    await make(migrated_engine, rule="beacon", host="10.5.5.5", entities=c2, severity="high")
    await make(migrated_engine, rule="beacon", host="10.6.6.6", entities=c2)
    dry = await cycle(app_engine, dry=True)
    assert len(dry.planned) == 1
    # the same server in very many investigations of the last days (the prevalence gate) says
    # nothing about who is behind it
    async with migrated_engine.begin() as conn:
        for k in range(membership.COMMON_INVESTIGATIONS):
            other = await older(conn, k)
            for kind, value in c2:
                await conn.execute(
                    text("INSERT INTO investigation_entities VALUES (:i, :k, :v)"),
                    {"i": other, "k": kind, "v": value},
                )
    report = await cycle(app_engine)
    assert report.planned == []
    assert await rows(app_engine, "SELECT * FROM cases") == []


async def older(conn: Any, k: int) -> uuid.UUID:
    """An unreviewed investigation of 100 hours ago: outside the 72 hours, inside the days the
    prevalence gate counts."""
    inv = uuid.uuid4()
    start = NOW - timedelta(hours=100)
    await conn.execute(
        text(
            "INSERT INTO investigations (id, grouping_version, rule_id, rule_name, group_key,"
            " bucket_start, bucket_end, previous_id, severity, alert_count, version,"
            " last_event_at) VALUES (:id, '2', 'plain', 'Plain', :key, :s, :e, :p, 'low', 1, 1,"
            " :s)"
        ),
        {"id": inv, "key": json.dumps([["source.ip", f"10.77.{k // 250}.{k % 250}"]]),
         "s": start, "e": start + timedelta(days=1), "p": uuid.uuid4()},
    )  # fmt: skip
    return inv
