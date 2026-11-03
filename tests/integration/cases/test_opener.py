"""DQ4's opening rules against the database (Q-C1): a PS1Bot-like incident across hosts and
days becomes one case; dry runs write nothing; runs repeat and overlap without duplicates."""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.assets.classify import IpClassifier
from argus.cases import opener
from argus.cases.machine import CaseRefused, Contain, replay
from argus.cases.model import Actor, QuietWindow
from argus.cases.service import CaseService
from tests.integration.cases.conftest import Person, investigation, rows

C2 = "77.221.155.150"
CLASSIFIER = IpClassifier(None)
WINDOW = timedelta(days=5)
BEACON = [
    {"name": "proxy.regularity", "status": "known", "value": 0.08},
    {"name": "ti.listed", "status": "known", "value": 1},
]


async def _dossier(owner: AsyncEngine, inv: uuid.UUID, signals: list[dict[str, Any]],
                   listed: list[str] = ()) -> None:  # type: ignore[assignment]  # fmt: skip
    body = {
        "signals": signals,
        "local_signals": [],
        "context": {"pack": {"ti": {"listed": list(listed)}}},
    }
    async with owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO dossiers (investigation_id, version, pack, facts_version, job_id,"
                " run_kind, family, status, dossier_hash, body, evidence_count, created_at)"
                " VALUES (:i, 1, 'generic@11', 1, 1, 'collect', 'proxy', 'evidence_ready',"
                " repeat('c', 64), CAST(:b AS jsonb), 0, now())"
            ),
            {"i": inv, "b": json.dumps(body)},
        )


async def _review(
    engine: AsyncEngine,
    person: Person,
    inv: uuid.UUID,
    outcome: str = "true_positive",
    *,
    ready: bool = True,
) -> int:
    """A person's review; ``ready``: made under an ELK check that showed the alert-status
    privileges (``kibana_ok``), the only verdict that may open a case (Q-E2 review F12)."""
    async with engine.begin() as conn:
        review_id: int = (
            await conn.execute(
                text(
                    "INSERT INTO review_events (investigation_id, version, alert_count, user_id,"
                    " action, outcome, kibana_ok) VALUES (:i, 1, 2, :u, 'reviewed', :o, :ok)"
                    " RETURNING id"
                ),
                {"i": inv, "u": person.user_id, "o": outcome, "ok": ready},
            )
        ).scalar_one()
    return review_id


async def _run(engine: AsyncEngine, *, dry_run: bool = False) -> opener.Report:
    return await opener.run(engine, window=WINDOW, classifier=CLASSIFIER, dry_run=dry_run)


async def _ps1bot(owner: AsyncEngine) -> list[uuid.UUID]:
    """Host A beacons on day 0 (the dossier shows it), host B contacts the same C2 on day 1,
    host A again on day 3: three investigations, two hosts, three days."""
    first = await investigation(owner, rule="c2", actor=(("source.ip", "10.8.235.157"),),
                                entities=(("ip", C2),), day=0)  # fmt: skip
    second = await investigation(owner, rule="c2", actor=(("source.ip", "10.198.50.62"),),
                                 entities=(("ip", C2),), day=1)  # fmt: skip
    third = await investigation(owner, rule="c2", actor=(("source.ip", "10.8.235.157"),),
                                entities=(("ip", "203.0.113.9"),), day=3)  # fmt: skip
    await _dossier(owner, first, BEACON, [C2])
    return [first, second, third]


async def test_a_c2_incident_across_hosts_and_days_is_one_case(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    first, second, third = await _ps1bot(migrated_engine)
    for inv in (first, second, third):
        await _review(app_engine, people["asha"], inv)
    dry = await _run(app_engine, dry_run=True)
    assert [(o.decision, o.link) for o in dry.planned] == [
        ("opened", None), ("linked", "c2"), ("linked", "actor"),
    ]  # fmt: skip
    assert dry.planned[0].reasons == (
        "a regular beacon", "a campus host in contact with a threat-listed address",
    )  # fmt: skip
    assert dry.planned[0].title == "Beaconing to 77.221.155.150 from 10.8.235.157"
    assert await rows(app_engine, "SELECT * FROM cases") == []  # a dry run writes nothing
    assert await rows(app_engine, "SELECT * FROM case_openings") == []

    report = await _run(app_engine)
    assert report.applied == {"opened": 1, "linked": 2}
    assert report.counts() == dry.counts()
    cases = await rows(app_engine, "SELECT id, state, cause, version, kibana_wait FROM cases")
    assert len(cases) == 1
    case_id = cases[0].id
    assert (cases[0].state, cases[0].cause, cases[0].version) == ("open", "verdict", 3)
    members = await rows(app_engine, "SELECT investigation_id, link, link_value FROM case_members"
                                     " ORDER BY added_version")  # fmt: skip
    assert [(m.investigation_id, m.link, m.link_value) for m in members] == [
        (first, "verdict", None), (second, "c2", C2), (third, "actor", "10.8.235.157"),
    ]  # fmt: skip
    marks = await rows(app_engine, "SELECT kind, value, role, source FROM case_indicators"
                                   " ORDER BY value")  # fmt: skip
    assert [tuple(m) for m in marks] == [
        ("ip", "10.198.50.62", "actor", "investigation"),
        ("ip", "10.8.235.157", "actor", "investigation"),
        ("ip", C2, "c2", "threat_intel"),
    ]
    openings = await rows(app_engine, "SELECT decision, case_id, decided_by FROM case_openings"
                                      " ORDER BY source_id")  # fmt: skip
    assert [(o.decision, o.case_id, o.decided_by) for o in openings] == [
        ("opened", case_id, "argus:opener"), ("linked", case_id, "argus:opener"),
        ("linked", case_id, "argus:opener"),
    ]  # fmt: skip
    again = await _run(app_engine)  # decided once: a second run does nothing
    assert (again.planned, again.applied) == ([], {})
    async with app_engine.connect() as conn:
        service = await CaseService.start(conn)
        assert replay(await service.events(case_id)) == await service.get(case_id)


async def test_overlapping_runs_open_nothing_twice(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    for inv in await _ps1bot(migrated_engine):
        await _review(app_engine, people["asha"], inv)
    reports = await asyncio.gather(_run(app_engine), _run(app_engine), _run(app_engine))
    assert sum(sum(r.applied.values()) for r in reports) == 3
    assert len(await rows(app_engine, "SELECT id FROM cases")) == 1
    assert len(await rows(app_engine, "SELECT 1 FROM case_openings")) == 3


async def test_a_true_positive_without_impact_is_an_attempt(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    scanner = await investigation(
        migrated_engine, rule="scan", actor=(("source.ip", "185.220.101.4"),)
    )
    await _dossier(
        migrated_engine, scanner, [{"name": "web.successes_after", "status": "known", "value": 0}]
    )
    review = await _review(app_engine, people["asha"], scanner)
    benign = await investigation(
        migrated_engine, rule="scan", actor=(("source.ip", "185.220.101.5"),)
    )
    await _review(app_engine, people["asha"], benign, "benign_expected")
    report = await _run(app_engine)
    assert report.applied == {"attempt": 1}
    rows_ = await rows(
        app_engine, "SELECT source_id, decision, case_id, reasons FROM case_openings"
    )
    assert [tuple(r) for r in rows_] == [
        (review, "attempt", None, ["no impact or campus-host signal"])
    ]
    assert await rows(app_engine, "SELECT * FROM cases") == []


async def test_successes_after_an_attack_open_a_case_for_the_attacker(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    attack = await investigation(
        migrated_engine, rule="web", actor=(("source.ip", "185.220.101.4"),)
    )
    await _dossier(
        migrated_engine, attack, [{"name": "web.successes_after", "status": "known", "value": 3}]
    )
    await _review(app_engine, people["asha"], attack)
    later = await investigation(
        migrated_engine, rule="web2", actor=(("source.ip", "185.220.101.4"),), day=1
    )
    await _review(app_engine, people["ravi"], later)
    report = await _run(app_engine)
    assert report.applied == {"opened": 1, "linked": 1}
    case = (await rows(app_engine, "SELECT title FROM cases"))[0]
    assert case.title == "Web attack by 185.220.101.4 got successful answers"


async def test_shared_egress_addresses_link_nothing(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """The campus proxy's egress address is many hosts: never an actor to link by."""
    classifier = IpClassifier(None, [__import__("ipaddress").ip_network("131.21.124.0/22")])
    one = await investigation(migrated_engine, rule="c2", actor=(("source.ip", "131.21.124.10"),),
                              entities=(("ip", C2),))  # fmt: skip
    await _dossier(migrated_engine, one, BEACON, [C2])
    egress = (("source.ip", "131.21.124.10"),)
    two = await investigation(migrated_engine, rule="other", actor=egress,
                              entities=(("ip", "192.0.2.80"),), day=1)  # fmt: skip
    await _review(app_engine, people["asha"], one)
    await _review(app_engine, people["asha"], two)
    report = await opener.run(app_engine, window=WINDOW, classifier=classifier, dry_run=False)
    assert report.applied == {"opened": 1, "attempt": 1}
    marks = await rows(app_engine, "SELECT value, role FROM case_indicators")
    assert [tuple(m) for m in marks] == [(C2, "c2")]


async def test_arguss_own_proposals_make_suspected_cases(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    with_floor = await investigation(migrated_engine, rule="p", actor=(("source.ip", "10.0.0.7"),))
    without = await investigation(migrated_engine, rule="p", severity="low",
                                  actor=(("source.ip", "10.0.0.8"),))  # fmt: skip
    await _dossier(migrated_engine, with_floor, [{"name": "proxy.hosts_to_destination",
                                                  "status": "known", "value": 1}])  # fmt: skip
    async with migrated_engine.begin() as conn:
        for inv in (with_floor, without):
            await conn.execute(
                text(
                    "INSERT INTO assessments (investigation_id, version, pack, dossier_hash,"
                    " view_hash, assessor, run_after, status, outcome) VALUES (:i, 1, 'p',"
                    " repeat('a', 64), :v, 'agent@1', now(), 'proposed', 'true_positive')"
                ),
                {"i": inv, "v": uuid.uuid4().hex * 2},
            )
    assistant = await __import__("tests.integration.cases.conftest", fromlist=["x"]).make_person(
        app_engine, "argus-assistant", signs_in=False
    )
    await _review(app_engine, assistant, without)  # the assistant's verdict opens nothing
    report = await _run(app_engine)
    assert report.applied == {"suspected": 1, "attempt": 1}
    case = (await rows(app_engine, "SELECT state, cause, opened_at FROM cases"))[0]
    assert (case.state, case.cause, case.opened_at) == ("suspected", "proposal", None)
    assert await rows(app_engine, "SELECT * FROM kibana_outbox") == []


async def test_only_a_kibana_ready_persons_verdict_opens_a_case(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """Q-E2 review F12: a verdict made without an ELK check that showed the privileges (the
    emergency account, an unverified session, local mode) is a verdict, but opens no case, and
    being the newest it keeps an older true positive from opening one behind it."""
    first, second, third = await _ps1bot(migrated_engine)
    await _review(app_engine, people["asha"], first, ready=False)  # not ready: nothing opens
    await _review(app_engine, people["asha"], second)  # ready, then...
    await _review(app_engine, people["ravi"], second, "benign_expected", ready=False)
    async with migrated_engine.begin() as conn:  # the emergency account's kind is never a person
        await conn.execute(text("UPDATE users SET kind = 'break_glass' WHERE username = 'meera'"))
    await _review(app_engine, people["meera"], third)
    assert (await _run(app_engine, dry_run=True)).planned == []
    await _review(app_engine, people["asha"], first)  # a ready verdict opens it
    report = await _run(app_engine, dry_run=True)
    assert [(o.candidate.investigation_id, o.decision) for o in report.planned] == [
        (first, "opened")
    ]


async def test_new_activity_reopens_a_contained_case_and_closed_cases_get_a_follower(
    app_engine: AsyncEngine, api_engine: AsyncEngine, migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    first, second, third = await _ps1bot(migrated_engine)
    await _review(app_engine, people["asha"], first)
    await _run(app_engine)
    case_id = (await rows(app_engine, "SELECT id FROM cases"))[0].id

    async def quiet(case: object) -> QuietWindow:  # what the watch (Q-C2) will say
        return QuietWindow(True, "72 h quiet (test)")

    async with app_engine.begin() as conn:
        service = await CaseService.start(conn, quiet_windows=quiet)
        await service.apply(people["asha"].actor(), case_id,
                            Contain("host reimaged", QuietWindow(False, "the caller's")),
                            expected_version=1)  # fmt: skip
    await _review(app_engine, people["asha"], second)
    report = await _run(app_engine)
    assert report.applied == {"linked": 1}
    case = (await rows(app_engine, "SELECT state, attention FROM cases"))[0]
    assert (case.state, case.attention) == ("open", "New activity after containment")
    events = await rows(app_engine, "SELECT kind FROM case_events ORDER BY case_version")
    assert [e.kind for e in events] == ["opened", "contained", "new_activity"]

    # closed (by approval), then the same host is seen again: a new case follows it
    from tests.integration.cases.test_service import _decide, _request

    request_id = await _request(api_engine, people["asha"], case_id, 3, "benign_policy")
    await _decide(api_engine, people["ravi"], request_id)
    await _review(app_engine, people["asha"], third)
    await _dossier(migrated_engine, third, BEACON, [C2])
    report = await _run(app_engine)
    assert report.applied == {"opened": 1}
    child = await rows(app_engine, "SELECT id, parent_case_id FROM cases WHERE id <> :c", c=case_id)
    assert child[0].parent_case_id == case_id
    closed = await rows(app_engine, "SELECT state, version FROM cases WHERE id = :c", c=case_id)
    assert (closed[0].state, closed[0].version) == ("closed", 6)  # + activity_after_closure
    last = await rows(app_engine, "SELECT kind, details FROM case_events WHERE case_id = :c"
                                  " ORDER BY case_version DESC LIMIT 1", c=case_id)  # fmt: skip
    assert (last[0].kind, last[0].details["child"]) == ("activity_after_closure", str(child[0].id))


async def test_at_most_twenty_new_cases_an_hour(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    for n in range(opener.MAX_NEW_PER_HOUR + 2):
        inv = await investigation(
            migrated_engine, rule=f"r{n}", actor=(("source.ip", f"10.1.0.{n}"),)
        )
        await _dossier(migrated_engine, inv, BEACON[:1])
        await _review(app_engine, people["asha"], inv)
    report = await _run(app_engine)
    assert report.applied == {"opened": opener.MAX_NEW_PER_HOUR}
    assert report.counts()["deferred"] == 2
    again = await _run(app_engine)  # still within the hour: they keep waiting, undecided
    assert again.counts() == {"deferred": 2}
    assert len(await rows(app_engine, "SELECT 1 FROM case_openings")) == opener.MAX_NEW_PER_HOUR
    manual = Actor.person(people["asha"].user_id, via="test")
    assert manual.is_person  # a person may still open more by hand
    assert datetime.now(UTC) > datetime(2026, 1, 1, tzinfo=UTC)


async def test_the_hourly_cap_holds_for_runs_planned_at_the_same_time(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    people: dict[str, Person],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A run planned before another run's cases were committed still opens no more than the
    hour allows: the count is taken again under the opener's lock."""
    for n in range(opener.MAX_NEW_PER_HOUR + 2):
        inv = await investigation(
            migrated_engine, rule=f"r{n}", actor=(("source.ip", f"10.1.0.{n}"),)
        )
        await _dossier(migrated_engine, inv, BEACON[:1])
        await _review(app_engine, people["asha"], inv)
    first = await _run(app_engine)
    assert first.applied == {"opened": opener.MAX_NEW_PER_HOUR}
    real = opener.created_last_hour
    calls = 0

    async def stale(conn: Any) -> int:  # the plan saw the hour before the first run committed
        nonlocal calls
        calls += 1
        return 0 if calls == 1 else await real(conn)

    monkeypatch.setattr(opener, "created_last_hour", stale)
    second = await _run(app_engine)
    assert second.counts() == {"opened": 2}  # what the stale plan wanted
    assert second.applied == {}
    assert [s.split(": ", 1)[1] for s in second.skipped] == [
        f"over {opener.MAX_NEW_PER_HOUR} new cases an hour (another run opened them)"
    ] * 2
    assert len(await rows(app_engine, "SELECT 1 FROM cases")) == opener.MAX_NEW_PER_HOUR
    assert len(await rows(app_engine, "SELECT 1 FROM case_openings")) == opener.MAX_NEW_PER_HOUR


async def test_the_backfill_reaches_back_to_the_ps1bot_verdicts(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """DQ4 (i), D-111: back to 2026-10-14, not only history.window."""
    first, _, _ = await _ps1bot(migrated_engine)
    review = await _review(app_engine, people["asha"], first)
    async with migrated_engine.begin() as conn:  # a verdict of 10-15, older than the window
        await conn.execute(
            text("UPDATE review_events SET created_at = '2026-10-15 10:00+00' WHERE id = :r"),
            {"r": review},
        )
    assert (await _run(app_engine, dry_run=True)).planned == []
    report = await opener.run(app_engine, window=WINDOW, classifier=CLASSIFIER, dry_run=False,
                              since=opener.BACKFILL_FROM)  # fmt: skip
    assert report.applied == {"opened": 1}
    payload = await rows(app_engine, "SELECT payload FROM kibana_outbox")
    assert payload == []  # opened from a verdict: it waits for someone who may open it in Kibana


async def test_an_investigation_in_a_closed_case_stays_there(
    app_engine: AsyncEngine, api_engine: AsyncEngine, migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    """A second true-positive verdict on an investigation of a closed case opens nothing (it
    is in that case); a person cannot put it into another case either."""
    from tests.integration.cases.test_service import _decide, _open, _request

    first, _, _ = await _ps1bot(migrated_engine)
    await _review(app_engine, people["asha"], first)
    await _run(app_engine)
    case_id = (await rows(app_engine, "SELECT id FROM cases"))[0].id
    request = await _request(api_engine, people["asha"], case_id, 1, "benign_policy")
    await _decide(api_engine, people["ravi"], request)
    await _review(app_engine, people["ravi"], first)  # a second verdict, after the closure
    report = await _run(app_engine)
    assert [(o.decision, o.case_ref) for o in report.planned] == [("member_already", case_id)]
    assert report.skipped == []
    with pytest.raises(CaseRefused, match="is in case 1"):
        await _open(app_engine, people["asha"].actor(), [first])
