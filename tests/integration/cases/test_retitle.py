"""D-230 against the real database: a retitle is a recorded case event that replays; a title a
person wrote is theirs and ARGUS never changes it; the assessment pass makes ARGUS's own titles
again from the case's facts, once per case and only when the title differs."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus import raising
from argus.assets.classify import IpClassifier
from argus.cases import chain, titling
from argus.cases.machine import CaseRefused, Dismiss, Link, Open, Retitle
from argus.cases.model import KIBANA_TO_OPEN, Actor, Indicator, Member
from argus.cases.service import CaseService
from tests.integration.cases.conftest import Person, investigation, rows
from tests.integration.cases.test_opener import BEACON, _dossier
from tests.integration.cases.test_split import B, S, Six, events_of, make_six, stored

pytestmark = pytest.mark.integration

CTX = titling.Context(IpClassifier(None, ()), ("example.edu",))
ARGUS = Actor.argus("title")
FROM_FACTS = f"Suspected Amadey contact with {S} (VirusTotal: 7 engines) from 2 campus devices"


async def flag_server(owner: AsyncEngine, tags: str = '["amadey"]') -> None:
    """VirusTotal's cached answer for the server both devices reached: 7 of 94 engines."""
    async with owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO outside_lookups (source, kind, indicator, status, answer)"
                " VALUES ('virustotal', 'ip', :ip, 'found',"
                " CAST(:a AS jsonb))"
            ),
            {"ip": S, "a": f'{{"malicious": 7, "suspicious": 0, "engines": 94, "tags": {tags}}}'},
        )


async def retitle(
    engine: AsyncEngine, actor: Actor, case: uuid.UUID, new: str, reason: str | None = None
) -> None:
    async with engine.begin() as conn:
        service = await CaseService.start(conn)
        await service.apply(actor, case, Retitle(new, reason), expected_version=None)


async def title_of(engine: AsyncEngine, case: uuid.UUID) -> str:
    return str((await rows(engine, "SELECT title FROM cases WHERE id = :c", c=case))[0].title)


@pytest.fixture
async def six(migrated_engine: AsyncEngine, app_engine: AsyncEngine) -> Six:
    made = await make_six(migrated_engine, app_engine)
    await flag_server(migrated_engine)
    return made


async def test_a_person_renames_a_case_and_the_event_records_it(
    app_engine: AsyncEngine, six: Six, people: dict[str, Person]
) -> None:
    asha = people["asha"].actor()
    await retitle(app_engine, asha, six.case, "Amadey infection on 10.201.7.11", "known family")
    case, kinds = await stored(app_engine, six.case)  # the events rebuild the case exactly
    assert (case.title, case.version, case.state) == (
        "Amadey infection on 10.201.7.11", 2, "suspected",
    )  # fmt: skip
    assert kinds == ["suspected", "retitled"]
    (details,) = await events_of(app_engine, six.case, "retitled")
    assert details["old"].startswith("Several campus devices")  # type: ignore[union-attr]
    assert details["new"] == "Amadey infection on 10.201.7.11"
    assert details["by"] == f"user:{people['asha'].user_id}"
    assert details["reason"] == "known family"
    (event,) = await rows(
        app_engine, "SELECT actor, actor_user_id FROM case_events WHERE kind = 'retitled'"
    )
    assert (event.actor, event.actor_user_id) == (f"user:{people['asha'].user_id}",
                                                  people["asha"].user_id)  # fmt: skip
    audit = await rows(app_engine, "SELECT 1 FROM audit_events WHERE action = 'case.retitled'")
    assert len(audit) == 1
    assert await rows(app_engine, "SELECT * FROM kibana_outbox") == []  # nothing for Kibana
    async with app_engine.connect() as conn:
        assert [r.problems for r in await chain.verify_all(conn)] == [[], []]


async def test_a_person_needs_a_reason_and_the_right_to_manage_cases(
    app_engine: AsyncEngine, six: Six, people: dict[str, Person]
) -> None:
    with pytest.raises(CaseRefused) as info:
        await retitle(app_engine, people["asha"].actor(), six.case, "x")
    assert info.value.code == "invalid"
    viewer = people["ravi"].actor(frozenset({"view"}))
    with pytest.raises(CaseRefused) as info:
        await retitle(app_engine, viewer, six.case, "x", "why")
    assert info.value.code == "forbidden"
    assert (await stored(app_engine, six.case))[1] == ["suspected"]


async def test_arguss_retitle_changes_a_title_arguss_own_and_a_person_then_owns_it(
    app_engine: AsyncEngine, six: Six, people: dict[str, Person]
) -> None:
    await retitle(app_engine, ARGUS, six.case, "ARGUS wrote this")
    assert await title_of(app_engine, six.case) == "ARGUS wrote this"
    (event,) = await rows(app_engine, "SELECT actor, actor_user_id FROM case_events"
                                      " WHERE kind = 'retitled'")  # fmt: skip
    assert (event.actor, event.actor_user_id) == ("argus:title", None)

    await retitle(app_engine, people["asha"].actor(), six.case, "A person wrote this", "clearer")
    with pytest.raises(CaseRefused) as info:  # ARGUS leaves a person's title alone
        await retitle(app_engine, ARGUS, six.case, "ARGUS again")
    assert (info.value.code, "person" in info.value.message) == ("conflict", True)
    assert await title_of(app_engine, six.case) == "A person wrote this"
    assert (await stored(app_engine, six.case))[1] == ["suspected", "retitled", "retitled"]


async def test_a_title_a_person_opened_the_case_with_is_theirs_too(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    person = await make_six(migrated_engine, app_engine, suspected=False, person=people["ravi"])
    with pytest.raises(CaseRefused):
        await retitle(app_engine, ARGUS, person.case, "ARGUS wants this")
    assert await title_of(app_engine, person.case) == "Regular beaconing from campus hosts"


async def test_the_pass_makes_arguss_titles_again_and_leaves_a_persons_alone(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, six: Six, people: dict[str, Person]
) -> None:
    mine = await make_six(migrated_engine, app_engine, suspected=False, person=people["ravi"])
    report = await titling.refresh(app_engine, CTX)
    assert (report.looked, report.kept) == (2, 1)
    assert [(c.number, c.new) for c in report.changes] == [(1, FROM_FACTS)]
    assert report.applied == 1
    assert await title_of(app_engine, six.case) == FROM_FACTS
    assert await title_of(app_engine, mine.case) == "Regular beaconing from campus hosts"
    _, kinds = await stored(app_engine, six.case)
    assert kinds == ["suspected", "retitled"]
    (event,) = await rows(app_engine, "SELECT actor, details FROM case_events"
                                      " WHERE kind = 'retitled'")  # fmt: skip
    assert event.actor == "argus:title"
    assert event.details["new"] == FROM_FACTS

    again = await titling.refresh(app_engine, CTX)  # the same facts: nothing to change
    assert (again.changes, again.applied) == ([], 0)
    assert (await stored(app_engine, six.case))[1] == ["suspected", "retitled"]


async def test_the_pass_follows_the_facts_when_they_change(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, six: Six, people: dict[str, Person]
) -> None:
    await titling.refresh(app_engine, CTX)
    async with migrated_engine.begin() as conn:  # the answer is cleared: the server is not flagged
        await conn.execute(
            text("UPDATE outside_lookups SET answer = answer || '{\"malicious\": 0}'")
        )
    report = await titling.refresh(app_engine, CTX)
    assert report.applied == 1
    assert await title_of(app_engine, six.case) == (
        "Suspected: alerts of rule 'Rule beacon' for 2 campus devices"
    )
    await retitle(app_engine, people["asha"].actor(), six.case, "Two devices, one server", "r")
    async with migrated_engine.begin() as conn:  # flagged again, but the title is a person's now
        await conn.execute(
            text("UPDATE outside_lookups SET answer = answer || '{\"malicious\": 9}'")
        )
    after = await titling.refresh(app_engine, CTX)
    assert (after.kept, after.changes) == (1, [])
    assert await title_of(app_engine, six.case) == "Two devices, one server"


async def test_a_dry_run_writes_nothing_and_a_closed_case_waits_for_everything(
    app_engine: AsyncEngine, six: Six, people: dict[str, Person]
) -> None:
    dry = await titling.refresh(app_engine, CTX, dry_run=True)
    assert [c.new for c in dry.changes] == [FROM_FACTS]
    assert dry.applied == 0
    assert (await stored(app_engine, six.case))[1] == ["suspected"]
    async with app_engine.begin() as conn:  # a person dismisses it: the title is still ARGUS's
        service = await CaseService.start(conn)
        await service.apply(people["asha"].actor(), six.case, Dismiss("created_in_error"),
                            expected_version=None)  # fmt: skip
    assert (await titling.refresh(app_engine, CTX)).looked == 0  # a closed case is not looked at
    everything = await titling.refresh(app_engine, CTX, everything=True)
    assert (everything.looked, everything.applied) == (1, 1)
    case, kinds = await stored(app_engine, six.case)
    assert (case.state, case.title, kinds) == (
        "closed", FROM_FACTS, ["suspected", "dismissed", "retitled"],
    )  # fmt: skip


async def test_the_pass_stops_at_its_limit_and_one_case_can_be_named(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, six: Six
) -> None:
    other = await make_six(migrated_engine, app_engine)
    limited = await titling.refresh(app_engine, CTX, limit=1)
    assert (limited.applied, len(limited.changes)) == (1, 1)
    assert [c.case_id for c in limited.changes] == [six.case]
    only = await titling.refresh(app_engine, CTX, only=other.case)
    assert [c.case_id for c in only.changes] == [other.case]


async def test_facts_that_say_nothing_never_become_the_title_alert(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    inv = await investigation(migrated_engine, rule="<b>", actor=(("source.ip", "10.0.0.1"),))
    async with app_engine.begin() as conn:
        service = await CaseService.start(conn)
        applied = await service.open(
            Actor.argus("raise"),
            Open("Old title", "low", "raised", (Member(inv, "actor"),), (), suspected=True,
                 attention="ARGUS suggests this case: x."),
        )  # fmt: skip
    report = await titling.refresh(app_engine, CTX)
    assert report.changes == []
    assert await title_of(app_engine, applied.case.id) == "Old title"


async def test_a_beacon_with_a_listed_server_is_named_from_its_dossier(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    """The flags and the threat-listed server come from the newest dossier, so a case a person's
    verdict opened (its investigation is reviewed, and raising skips it) is named too."""
    inv = await investigation(migrated_engine, rule="c2", actor=(("source.ip", B),),
                              entities=(("ip", S),))  # fmt: skip
    await _dossier(migrated_engine, inv, BEACON, [S])
    async with app_engine.begin() as conn:
        service = await CaseService.start(conn)
        applied = await service.open(
            Actor.argus("raise"),
            Open("Old title", "high", "raised", (Member(inv, "actor", B),),
                 (Indicator("ip", B, "actor"), Indicator("ip", S, "c2")), suspected=True,
                 attention="ARGUS suggests this case: x."),
        )  # fmt: skip
    await titling.refresh(app_engine, CTX)
    assert await title_of(app_engine, applied.case.id) == (
        f"Suspected beaconing from {B} to {S} (on a threat list)"
    )


async def test_the_assessment_pass_refreshes_titles_at_most_every_quarter_hour(
    app_engine: AsyncEngine, six: Six
) -> None:
    now = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
    done = await raising.run(app_engine, None, now, suggesting=False, last=None,
                             titles=CTX, titled_last=None)  # fmt: skip
    assert done.titled_at == now
    assert any(line.startswith("titles: looked 1") for line in done.said)
    assert await title_of(app_engine, six.case) == FROM_FACTS
    soon = await raising.run(app_engine, None, now + timedelta(minutes=5), suggesting=False,
                             last=None, titles=CTX, titled_last=done.titled_at)  # fmt: skip
    assert soon.titled_at == now  # not asked again so soon
    off = await raising.run(app_engine, None, now + timedelta(hours=1), suggesting=False,
                            last=None, titles=None, titled_last=None)  # fmt: skip
    assert off.titled_at is None


async def test_the_refresh_survives_a_case_it_cannot_read(
    app_engine: AsyncEngine, six: Six, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def broken(*_: object, **__: object) -> str | None:
        raise RuntimeError("boom")

    monkeypatch.setattr(titling, "titled_for_case", broken)
    done = await raising.run(app_engine, None, datetime.now(UTC), suggesting=False, last=None,
                             titles=CTX, titled_last=None)  # fmt: skip
    assert any("case titles failed (RuntimeError)" in w for w in done.warned)
    assert done.titled_at is None
    assert await title_of(app_engine, six.case) != FROM_FACTS


async def test_a_case_already_in_kibana_keeps_its_kibana_title(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """The mirror posts a title once, at creation: a retitle plans no Kibana write (D-195)."""
    inv = await investigation(migrated_engine, actor=(("source.ip", B),))
    actor = people["asha"].actor(kibana=KIBANA_TO_OPEN, checked_at=datetime.now(UTC))
    async with app_engine.begin() as conn:
        service = await CaseService.start(conn)
        applied = await service.open(actor, Open("Old title", "high", "person",
                                                 (Member(inv, "person"),)))  # fmt: skip
    assert applied.case.mirrored
    before = await rows(app_engine, "SELECT payload FROM kibana_outbox")
    assert len(before) == 1
    await retitle(app_engine, actor, applied.case.id, "A clearer title", "clearer")
    assert await rows(app_engine, "SELECT payload FROM kibana_outbox") == before
    assert await title_of(app_engine, applied.case.id) == "A clearer title"


async def test_a_follow_up_case_keeps_the_link_to_the_case_it_follows(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, six: Six, people: dict[str, Person]
) -> None:
    async with app_engine.begin() as conn:  # the first case is closed: a person dismisses it
        service = await CaseService.start(conn)
        await service.apply(people["asha"].actor(), six.case, Dismiss("created_in_error"),
                            expected_version=None)  # fmt: skip
    inv = await investigation(migrated_engine, rule="c2", actor=(("source.ip", B),),
                              entities=(("ip", S),))  # fmt: skip
    await _dossier(migrated_engine, inv, BEACON, [S])
    async with app_engine.begin() as conn:
        service = await CaseService.start(conn)
        applied = await service.open(
            Actor.argus("watch"),
            Open("Activity after case 1 was closed", "high", "watch", (Member(inv, "actor", B),),
                 (Indicator("ip", B, "actor"), Indicator("ip", S, "c2")), suspected=True,
                 parent_case_id=six.case),
        )  # fmt: skip
    await titling.refresh(app_engine, CTX)
    assert await title_of(app_engine, applied.case.id) == (
        f"Suspected Amadey beaconing from {B} to {S} — follows case 1"  # the details go first
    )


# -- naming v2: what a retitle records, and when it happens ----------------------------------------

DEVICES = [f"10.0.9.{i}" for i in range(1, 9)]
FLAGGED = "198.51.100.77"


async def device_case(owner: AsyncEngine, runtime: AsyncEngine, n: int) -> uuid.UUID:
    """A suggested case of ``n`` made-up devices that each reached one flagged server."""
    async with owner.begin() as conn:
        await conn.execute(
            text("INSERT INTO outside_lookups (source, kind, indicator, status, answer)"
                 " VALUES ('virustotal', 'ip', :ip, 'found', CAST(:a AS jsonb))"),
            {"ip": FLAGGED, "a": '{"malicious": 6, "suspicious": 0, "engines": 94}'},
        )  # fmt: skip
    members, marks = [], [Indicator("ip", FLAGGED, "indicator")]
    for device in DEVICES[:n]:
        inv = await investigation(owner, rule="beacon", actor=(("source.ip", device),),
                                  entities=(("ip", FLAGGED),))  # fmt: skip
        members.append(Member(inv, "actor", device))
        marks.append(Indicator("ip", device, "actor"))
    async with runtime.begin() as conn:
        service = await CaseService.start(conn)
        applied = await service.open(
            Actor.argus("raise"),
            Open("Old title", "high", "raised", tuple(members), tuple(marks), suspected=True,
                 attention="ARGUS suggests this case: devices reached one server."),
        )  # fmt: skip
    return applied.case.id


async def link_devices(owner: AsyncEngine, runtime: AsyncEngine, case: uuid.UUID,
                       devices: list[str]) -> None:  # fmt: skip
    members, marks = [], []
    for device in devices:
        inv = await investigation(owner, rule="beacon", actor=(("source.ip", device),),
                                  entities=(("ip", FLAGGED),))  # fmt: skip
        members.append(Member(inv, "actor", device))
        marks.append(Indicator("ip", device, "actor"))
    async with runtime.begin() as conn:
        service = await CaseService.start(conn)
        await service.apply(Actor.argus("raise"), case, Link(tuple(members), tuple(marks)),
                            expected_version=None)  # fmt: skip


async def test_a_retitle_records_what_changed_and_each_claim_with_its_fact(
    app_engine: AsyncEngine, six: Six
) -> None:
    await titling.refresh(app_engine, CTX)
    (details,) = await events_of(app_engine, six.case, "retitled")
    assert isinstance(details, dict)
    assert (details["change"], details["reason"]) == ("words", "the facts changed")
    claims = {(c["slot"], c["words"], c["fact"]) for c in details["claims"]}
    assert ("certainty", "Suspected", "certainty:Suspected") in claims
    assert ("family", "Amadey", "family:Amadey") in claims
    assert ("activity", "contact", "activity:contact") in claims
    assert ("object", S, f"server:{S}") in claims
    assert ("object", "VirusTotal: 7 engines", f"vt:{S}:7") in claims
    assert ("actors", "2 campus devices", "actors:contact:2:2") in claims


async def test_a_small_count_change_waits_and_a_large_one_is_retitled_at_once(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    case = await device_case(migrated_engine, app_engine, 4)
    now = datetime.now(UTC)
    first = await titling.refresh(app_engine, CTX, now=now)
    assert first.applied == 1
    assert (await title_of(app_engine, case)).endswith("from 4 campus devices")
    await link_devices(migrated_engine, app_engine, case, DEVICES[4:5])  # 4 -> 5: a quarter more
    soon = await titling.refresh(app_engine, CTX, now=now + timedelta(hours=1))
    assert (soon.applied, soon.waiting) == (0, 1)
    assert (await title_of(app_engine, case)).endswith("from 4 campus devices")
    later = await titling.refresh(app_engine, CTX, now=now + timedelta(hours=7))
    assert later.applied == 1
    assert [c.change for c in later.changes] == ["counts"]
    assert (await title_of(app_engine, case)).endswith("from 5 campus devices")
    await link_devices(migrated_engine, app_engine, case, DEVICES[5:8])  # 5 -> 8: grew by half
    grown = await titling.refresh(app_engine, CTX, now=now + timedelta(hours=7, minutes=1))
    assert grown.applied == 1
    assert (await title_of(app_engine, case)).endswith("from 8 campus devices")
    kinds = [d["change"] for d in await events_of(app_engine, case, "retitled")]  # type: ignore[index]
    assert kinds == ["words", "counts", "counts"]


async def stored_check(
    owner: AsyncEngine, inv: uuid.UUID, template: str, status: str, params: dict[str, object],
    snapshot: dict[str, object] | None,
) -> None:  # fmt: skip
    """A stored web check of ``inv`` (what the follow-ups or a path check left)."""
    import json

    key = uuid.uuid4().hex + uuid.uuid4().hex
    async with owner.begin() as conn:
        await conn.execute(
            text("INSERT INTO evidence_requests (investigation_id, eid, task_key, template,"
                 " template_version, origin, first_version, created_at) VALUES (:i,"
                 " (SELECT coalesce(max(eid), 0) + 1 FROM evidence_requests"
                 " WHERE investigation_id = :i), :k, :t, 1, 'pack', 1, now())"),
            {"i": inv, "k": key, "t": template},
        )  # fmt: skip
        await conn.execute(
            text("INSERT INTO evidence (investigation_id, version, task_key, template,"
                 " template_version, params, status, coverage, row_count, snapshot, result_hash,"
                 " collected_at) VALUES (:i, 1, :k, :t, 1, CAST(:p AS jsonb), :s, '{}'::jsonb,"
                 " 1, CAST(:snap AS jsonb), :h, now())"),
            {"i": inv, "k": key, "t": template, "p": json.dumps(params), "s": status,
             "snap": None if snapshot is None else json.dumps(snapshot), "h": "e" * 64},
        )  # fmt: skip


SITE = "www.lab.example.edu"


def followup(path: str) -> dict[str, object]:
    return {"_source": {"url": {"domain": SITE, "path": path},
                        "http": {"response": {"status_code": 200}}}}  # fmt: skip


async def test_a_web_case_is_named_from_the_stored_checks_and_the_verdicts(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    from tests.integration.incident import kit

    attackers = ("203.0.113.61", "203.0.113.62")
    invs = [await investigation(migrated_engine, rule="Web: path probe",
                                actor=(("source.ip", a),)) for a in attackers]  # fmt: skip
    for inv in invs:
        await kit.propose(migrated_engine, inv)
    await stored_check(migrated_engine, invs[0], "web.followups", "ok",
                       {"ip": attackers[0]}, {"rows": [followup("/.env")]})  # fmt: skip
    marks = (
        *(Indicator("ip", a, "actor") for a in attackers),
        Indicator("url", "/.env", "indicator"),
        Indicator("url", "/api/.env", "indicator"),
    )
    async with app_engine.begin() as conn:
        service = await CaseService.start(conn)
        applied = await service.open(
            Actor.argus("raise"),
            Open("Old title", "high", "raised", tuple(Member(i, "actor") for i in invs), marks,
                 suspected=True, attention="ARGUS suggests this case: x."),
        )  # fmt: skip
    case = applied.case.id
    await titling.refresh(app_engine, CTX)
    assert await title_of(app_engine, case) == (
        f"Likely .env scan of {SITE} by 2 outside IPs — got HTTP 200, not verified"
    )
    asked = {"ip": attackers[0], "site": SITE, "paths": ["/.env", "/nothing"]}
    answer = {"aggregations": {"paths": {"buckets": []}}}
    await stored_check(migrated_engine, invs[0], "web.path_outcomes", "ok", asked, answer)
    found = await titling.refresh(app_engine, CTX, dry_run=True)
    assert found.changes == []  # a path check that shows nothing served never says "served"
    served = {"aggregations": {  # /.env answered 2xx with its own size; /nothing was refused
        "paths": {"buckets": [
            {"key": "/.env", "doc_count": 3,
             "statuses": {"buckets": [{"key": 200, "doc_count": 3}]}},
            {"key": "/nothing", "doc_count": 2,
             "statuses": {"buckets": [{"key": 404, "doc_count": 2}]}},
        ]},
        "ok_0": {"doc_count": 3, "sizes": {"buckets": [{"key": 812, "doc_count": 3}]}},
        "ok_1": {"doc_count": 0, "sizes": {"buckets": []}},
    }}  # fmt: skip
    await stored_check(migrated_engine, invs[1], "web.path_outcomes", "ok", asked, served)
    await titling.refresh(app_engine, CTX)
    assert await title_of(app_engine, case) == (
        f"Likely .env scan of {SITE} by 2 outside IPs — a .env file served"
    )
    async with migrated_engine.begin() as conn:  # a person reviews both: confirmed
        for inv in invs:
            await conn.execute(
                text("INSERT INTO review_state (investigation_id, latest_id, decision_id, action,"
                     " version, alert_count, outcome, decided_at, user_id) VALUES (:i, 1, 1,"
                     " 'reviewed', 1, 2, 'true_positive', now(), :u)"),
                {"i": inv, "u": people["asha"].user_id},
            )  # fmt: skip
    await titling.refresh(app_engine, CTX)
    assert await title_of(app_engine, case) == (
        f"Confirmed .env scan of {SITE} by 2 outside IPs — a .env file served"
    )
    (*_, last) = await events_of(app_engine, case, "retitled")
    assert (last["change"], last["reason"]) == (
        "certainty",
        "the certainty changed: Likely → Confirmed",
    )


async def test_a_single_device_names_the_earlier_case_that_holds_its_server(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    first = await device_case(migrated_engine, app_engine, 3)
    inv = await investigation(migrated_engine, rule="beacon", actor=(("source.ip", "10.0.9.50"),),
                              entities=(("ip", FLAGGED),))  # fmt: skip
    await _dossier(migrated_engine, inv, BEACON, [])
    async with app_engine.begin() as conn:
        service = await CaseService.start(conn)
        later = await service.open(
            Actor.argus("raise"),
            Open("Old title", "high", "raised", (Member(inv, "actor", "10.0.9.50"),),
                 (Indicator("ip", "10.0.9.50", "actor"), Indicator("ip", FLAGGED, "indicator")),
                 suspected=True, attention="ARGUS suggests this case: x."),
        )  # fmt: skip
    await titling.refresh(app_engine, CTX)
    number = (await rows(app_engine, "SELECT number FROM cases WHERE id = :c", c=first))[0].number
    assert await title_of(app_engine, later.case.id) == (
        f"Suspected beaconing from 10.0.9.50 to {FLAGGED} (VirusTotal: 6 engines),"
        f" the server of case {number}"
    )
    assert "the server of case" not in await title_of(app_engine, first)
