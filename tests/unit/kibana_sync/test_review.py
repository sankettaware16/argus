"""The independent review of Q-D3 (gate report, "Review"): each finding's reproduction as a
regression test, written to fail on the code it was found in. The numbers are the review's
(R1-R11) and the small items.

The reviewer's scripts are adapted, not copied: every test names the person or the fault, then
the correct behaviour."""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.gateway.kibana import writes
from argus.kibana_sync import readmodel
from argus.kibana_sync.cycle import SyncConfig
from argus.kibana_sync.model import Kind, SentWrite, clean, untrusted
from tests.unit.kibana_sync.fake import COMMENT, CREATE, INDEX, Rig, rig

PERSON = "ra-anita"
USER_COMMENT = {"type": "user", "comment": "Opened by ARGUS.", "owner": "securitySolution"}


def kinds(r: Rig) -> list[Kind]:
    return sorted(f.kind for _, f in r.store.findings.values())


async def own_case(r: Rig, *writes_: SentWrite) -> tuple[str, uuid.UUID]:
    case = uuid.uuid4()
    r.sent(case, CREATE, *writes_)
    kid = r.kibana.create(argus_case=case)
    record = await r.cycle()
    assert record.outcome == "complete", record.reason
    return kid, case


async def resume_all(r: Rig) -> None:
    def resume(state: writes.KibanaLaneState) -> tuple[None, writes.KibanaLaneState]:
        for cls in writes.WriteClass:
            state = writes.resume(state, cls)
        return None, state

    await r.lane.kibana_change(resume)
    assert not (await r.lane.kibana_lane()).paused


# --------------------------------------------------------------------------- R1


@given(st.text(st.characters(exclude_categories=())))
def test_r1_a_persons_text_holds_nothing_the_database_refuses(text: str) -> None:
    for out in (clean(text), untrusted(text)):
        assert "\x00" not in out
        out.encode("utf-8")  # no lone surrogate
        assert all(ch in "\t\n\r" or (ch >= " " and not "\x7f" <= ch <= "\x9f") for ch in out)
    assert clean(clean(text)) == clean(text)


def test_r1_the_text_around_the_unsafe_characters_is_kept() -> None:
    assert clean("my \x00 title\ud800, line\n\ttab") == "my  title, line\n\ttab"
    assert untrusted("a\x00" * 3_000) == "a" * 2_000


async def test_r1_a_nul_in_a_comment_reaches_no_finding() -> None:
    r = rig()
    kid, _ = await own_case(r)
    r.kibana.comment(kid, PERSON, "hello \x00 world \ud800")
    r.kibana.add_tags(kid, PERSON, "argus:owner:a\x00b")
    await r.cycle()
    texts = [str(f.details) for _, f in r.store.findings.values()]
    assert texts
    assert not any("\x00" in t or "\\x00" in t or "\\ud800" in t for t in texts)


async def test_r1_one_case_the_store_cannot_keep_is_a_finding_and_the_cycle_goes_on() -> None:
    r = rig()
    a, _ = await own_case(r)
    b, _ = await own_case(r)
    r.kibana.comment(a, PERSON, "first")
    r.kibana.comment(b, PERSON, "second")
    real = r.store.apply

    async def apply(mirror: Any, findings: Any, **kw: Any) -> int:
        if mirror.kibana_case_id == a:
            raise ValueError("the database refuses this case")
        return await real(mirror, findings, **kw)

    r.store.apply = apply  # type: ignore[method-assign]
    record = await r.cycle(advance=timedelta(hours=1, minutes=1))
    assert record.outcome == "partial"
    assert "could not be kept" in (record.reason or "")
    assert r.store.mirror[b].actions_seen == 2, "the other case was read and kept"
    assert Kind.ANSWER_UNEXPECTED in kinds(r), "the failure is a finding"
    assert r.store.sync.last_discovery_at is not None
    assert r.store.sync.last_discovery_at > r.clock.now - timedelta(minutes=10), (
        "discovery was not starved by the failing case"
    )
    assert r.store.sync.changes_from is not None
    r.store.apply = real  # type: ignore[method-assign]
    record = await r.cycle()
    assert record.outcome == "complete"
    assert kinds(r).count(Kind.PERSON_COMMENTED) == 2, "the case is kept as soon as it can be"


async def test_r1_a_failure_of_the_database_itself_still_ends_the_cycle() -> None:
    r = rig()
    kid, _ = await own_case(r)
    r.kibana.comment(kid, PERSON, "x")

    async def down(*a: Any, **k: Any) -> int:
        raise ValueError("database down")

    r.store.apply = down  # type: ignore[method-assign]
    r.store.add_findings = down  # type: ignore[method-assign]
    record = await r.cycle()
    assert record.outcome == "failed"


# --------------------------------------------------------------------------- R2


async def test_r2_a_recreated_case_takes_over_the_deleted_ones_mirror() -> None:
    r = rig()
    kid, case = await own_case(r)
    r.kibana.delete(kid)
    await r.cycle()
    assert kinds(r) == [Kind.DELETED_IN_KIBANA]
    r.sent(case, CREATE)  # the approved recreate: the create's sent count is now 2
    second = r.kibana.create(argus_case=case)
    for _ in range(3):
        record = await r.cycle()
        assert record.outcome == "complete", (record.outcome, record.reason)
    assert kinds(r) == [Kind.DELETED_IN_KIBANA], "no duplicate, no alarm"
    assert kid not in r.store.mirror, "one mirror per ARGUS case"
    mirror = r.store.mirror[second]
    assert (mirror.case_id, mirror.active) == (case, True)
    assert (mirror.actions_seen, dict(mirror.argus_actions)) == (1, {"create": 1})
    assert not (await r.lane.kibana_lane()).paused


# --------------------------------------------------------------------------- R3


async def test_r3_a_status_written_before_its_user_action_is_not_lost() -> None:
    r = rig()
    kid, _ = await own_case(r)
    publish = r.kibana.lagging_status(kid, PERSON, "closed")
    await r.cycle()
    assert Kind.CLOSED_IN_KIBANA not in kinds(r), "the action is not visible yet"
    assert r.store.mirror[kid].kibana_version != r.kibana.cases[kid]["version"], (
        "the version is not taken while the actions disagree with the case"
    )
    publish()
    for _ in range(2):
        await r.cycle()
    assert kinds(r) == [Kind.CLOSED_IN_KIBANA]
    assert r.store.mirror[kid].status == "closed"
    assert r.store.mirror[kid].kibana_version == r.kibana.cases[kid]["version"]


async def test_r3_a_case_changed_moments_ago_is_read_again_next_cycle() -> None:
    """A comment shows nowhere on the case itself: only the recency tells the read may be early."""
    r = rig()
    kid, _ = await own_case(r)
    publish = r.kibana.lagging_comment(kid, PERSON, "I called the owner")
    await r.cycle(advance=timedelta(minutes=1))
    assert kinds(r) == []
    publish()
    record = await r.cycle()
    assert record.changed == 1, "read again although the case's version did not move"
    assert kinds(r) == [Kind.PERSON_COMMENTED]
    record = await r.cycle()
    assert record.changed == 0, "settled: nothing is read again"


async def test_r3_a_case_that_never_agrees_is_given_up_with_a_finding() -> None:
    r = rig()
    kid, _ = await own_case(r)
    r.kibana.lagging_status(kid, PERSON, "closed")  # the action never appears
    for _ in range(9):
        await r.cycle()
    assert kinds(r) == [Kind.ANSWER_UNEXPECTED]
    assert r.store.mirror[kid].kibana_version == r.kibana.cases[kid]["version"]
    record = await r.cycle()
    assert record.changed == 0, "no read per cycle for ever"


# --------------------------------------------------------------------------- R4


async def test_r4_a_restart_after_an_unexplained_action_still_pauses_the_writers() -> None:
    r = rig()
    a, _ = await own_case(r)
    b, _ = await own_case(r)
    r.kibana.comment(a, "argus", "stray, no outbox row")
    r.kibana.comment(b, PERSON)
    real = r.kibana.send
    calls = {"n": 0}

    async def send(request: Any) -> Any:
        if request.path.endswith("/user_actions/_find"):
            calls["n"] += 1
            if calls["n"] == 2:  # the process is stopped while reading the second case
                raise asyncio.CancelledError()
        return await real(request)

    r.kibana.send = send  # type: ignore[method-assign]
    with pytest.raises(asyncio.CancelledError):
        await r.cycle()
    assert Kind.UNEXPLAINED_ARGUS_ACTION in kinds(r), "the finding was committed"
    r.kibana.send = real  # type: ignore[method-assign]
    await r.cycle()
    assert (await r.lane.kibana_lane()).paused, "the alarm is on record: the writers are paused"


async def test_r4_the_alert_alarm_survives_a_failure_while_it_is_kept() -> None:
    r = rig()
    kid, _ = await own_case(r, SentWrite("attach", frozenset(), 1))
    r.kibana.attach(kid, "argus", "alert-1")
    r.kibana.alert_status("alert-1", "open", None)
    await r.cycle(advance=timedelta(hours=1))  # the baseline: open
    r.kibana.alert_status("alert-1", "closed", None)  # the internal route: no user
    failures = {"n": 0}
    for name in ("add_findings", "record_alerts"):
        real = getattr(r.store, name)

        def flaky(real: Any = real) -> Any:
            async def call(*args: Any, **kw: Any) -> Any:
                findings = args[-2] if len(args) > 1 else kw.get("findings", ())
                unexplained = any(f.kind is Kind.ALERT_CHANGE_UNEXPLAINED for f in findings)
                if unexplained and failures["n"] == 0:
                    failures["n"] += 1
                    raise RuntimeError("the database blinked")
                return await real(*args, **kw)

            return call

        setattr(r.store, name, flaky())
    for _ in range(4):
        await r.cycle(advance=timedelta(hours=1))
    assert failures["n"] == 1
    assert Kind.ALERT_CHANGE_UNEXPLAINED in kinds(r), "the unexplained change was alarmed"
    assert (await r.lane.kibana_lane()).paused


# --------------------------------------------------------------------------- R5


async def test_r5_a_closed_case_deleted_in_kibana_is_found_the_next_cycle() -> None:
    r = rig()
    kid, _ = await own_case(r)
    r.kibana.set_status(kid, PERSON, "closed")
    await r.cycle()
    assert Kind.CLOSED_IN_KIBANA in kinds(r)
    r.kibana.delete(kid)
    await r.cycle()  # not the daily listing's cycle
    assert Kind.DELETED_IN_KIBANA in kinds(r)
    assert r.store.mirror[kid].deleted_at is not None


async def test_r5_a_quiet_cycle_asks_for_one_closed_case_not_the_closed_listing() -> None:
    r = rig()
    kid, _ = await own_case(r)
    r.kibana.set_status(kid, PERSON, "closed")
    await r.cycle()
    before = len(r.reads(status="closed"))
    for _ in range(3):
        await r.cycle()
    probes = r.reads(status="closed")[before:]
    assert len(probes) == 3
    assert all(p["perPage"] == "1" for p in probes), "one find of one case each cycle"


async def test_r5_a_mismatch_nobody_can_fix_does_not_list_the_closed_cases_every_cycle() -> None:
    r = rig()
    leaked = r.kibana.create(argus_case=uuid.uuid4())  # a case of argus, no sent create
    r.kibana.set_status(leaked, PERSON, "closed")
    await r.cycle()
    assert kinds(r) == [Kind.UNEXPLAINED_ARGUS_CASE]
    listings = lambda: [p for p in r.reads(status="closed") if p["perPage"] != "1"]  # noqa: E731
    first = len(listings())
    for _ in range(4):
        await r.cycle()
    assert len(listings()) == first, "the same total and mirror count are not looked at again"


# --------------------------------------------------------------------------- R6


async def test_r6_closing_a_synced_case_does_not_alarm_for_its_alerts() -> None:
    r = rig()
    kid, case = await own_case(r)
    r.kibana.attach(kid, "argus", "alert-2")
    r.sent(case, SentWrite("attach", frozenset(), 1))
    r.kibana.alert_status("alert-2", "open", None)
    await r.cycle(advance=timedelta(hours=1))
    r.kibana.sync_on(kid, PERSON)
    r.kibana.set_status(kid, PERSON, "closed")
    r.kibana.alert_status("alert-2", "closed", None)  # Kibana's own sync: no user recorded
    await r.cycle(advance=timedelta(hours=1))
    assert Kind.ALERT_CHANGE_UNEXPLAINED not in kinds(r)
    assert not (await r.lane.kibana_lane()).paused


async def test_r6_a_synced_case_nobody_touched_still_alarms_for_an_alert_change() -> None:
    r = rig()
    kid, case = await own_case(r)
    r.kibana.attach(kid, "argus", "alert-2")
    r.sent(case, SentWrite("attach", frozenset(), 1))
    r.kibana.sync_on(kid, PERSON)
    r.kibana.alert_status("alert-2", "open", None)
    await r.cycle(advance=timedelta(hours=1))
    r.kibana.alert_status("alert-2", "closed", None)  # no person changed the case since
    await r.cycle(advance=timedelta(hours=1))
    assert Kind.ALERT_CHANGE_UNEXPLAINED in kinds(r)
    assert (await r.lane.kibana_lane()).paused


# --------------------------------------------------------------------------- R7


async def test_r7_after_a_stray_argus_action_a_sent_comment_is_still_explained() -> None:
    r = rig()
    kid, case = await own_case(r)
    r.kibana.comment(kid, "argus", "stray")  # no outbox row: alarm
    await r.cycle()
    assert kinds(r) == [Kind.UNEXPLAINED_ARGUS_ACTION]
    assert dict(r.store.mirror[kid].unexplained) == {"comment": 1}
    r.sent(case, COMMENT)  # later ARGUS legitimately sends a comment
    r.kibana.comment(kid, "argus", "a legitimate, sent comment")
    await r.cycle()
    assert kinds(r) == [Kind.UNEXPLAINED_ARGUS_ACTION], "the sent comment was flagged too"
    r.kibana.comment(kid, "argus", "another stray")
    await r.cycle()
    assert kinds(r) == [Kind.UNEXPLAINED_ARGUS_ACTION] * 2, "a new stray is still an alarm"


async def test_r7_an_owner_resume_is_not_undone_by_the_next_cycle() -> None:
    r = rig()
    r.kibana.create(argus_case=uuid.uuid4())  # a leaked case, no sent create
    await r.cycle()
    assert (await r.lane.kibana_lane()).paused
    await resume_all(r)
    await r.cycle()
    assert not (await r.lane.kibana_lane()).paused, "re-paused by the same old case"
    assert kinds(r) == [Kind.UNEXPLAINED_ARGUS_CASE], "found once"
    r.kibana.create(argus_case=uuid.uuid4())  # a second one is a new alarm
    await r.cycle()
    assert (await r.lane.kibana_lane()).paused


async def test_r7_an_owner_resume_after_a_stray_action_holds() -> None:
    r = rig()
    kid, _ = await own_case(r)
    r.kibana.comment(kid, "argus", "stray")
    await r.cycle()
    await resume_all(r)
    r.kibana.comment(kid, PERSON, "I looked")
    for _ in range(3):
        await r.cycle()
    assert not (await r.lane.kibana_lane()).paused


# --------------------------------------------------------------------------- R8


def _world(r: Rig, cases: int, alerts: int) -> list[str]:
    ids = []
    for i in range(cases):
        case = uuid.uuid4()
        r.sent(case, CREATE, SentWrite("attach", frozenset(), alerts))
        kid = r.kibana.create(argus_case=case)
        for j in range(alerts):
            alert = f"alert-{i:03d}-{j:03d}"
            r.kibana.attach(kid, "argus", alert)
            r.kibana.alert_status(alert, "open", None)
        ids.append(kid)
    return ids


def _case_searches(r: Rig, start: int = 0) -> list[Any]:
    found = []
    for wire in r.kibana.es_requests[start:]:
        body = wire.body.decode() if isinstance(wire.body, bytes) else str(wire.body)
        if "kibana.alert.case_ids" in body and '"terms"' in body:
            found.append(body)
    return found


async def test_r8_discovery_diffs_a_bounded_slice_and_rotates_over_all_alerts() -> None:
    r = rig(config=SyncConfig(diff_calls=2))
    _world(r, cases=6, alerts=100)  # 600 alerts: six pages
    long = timedelta(hours=3)
    await r.cycle(within=long)
    await r.cycle(within=long)
    seen = set(r.store.alert_state)
    assert len(seen) == 200, "two searches of 100 alerts at the first discovery"
    for _hour in range(2):
        start = len(r.kibana.es_requests)
        await r.cycle(advance=timedelta(hours=1, minutes=1), within=long)
        assert 1 <= len(_case_searches(r, start)) <= 2, "capped per discovery"
    assert len(r.store.alert_state) == 600, "every alert was looked at within three hours"


async def test_r8_only_open_cases_and_recent_ones_are_diffed() -> None:
    r = rig(config=SyncConfig(window=timedelta(days=5)))
    live = _world(r, cases=2, alerts=3)
    old = _world(r, cases=2, alerts=3)
    for kid in old:
        r.kibana.set_status(kid, PERSON, "closed")
    await r.cycle(within=timedelta(hours=3))
    r.clock.now += timedelta(days=6)  # the closed ones are older than history.window
    for kid in live:
        r.kibana.comment(kid, PERSON, "still open")
    start = len(r.kibana.es_requests)
    await r.cycle(advance=timedelta(hours=1, minutes=1), within=timedelta(hours=3))
    searches = " ".join(_case_searches(r, start))
    assert all(kid in searches for kid in live)
    assert not any(kid in searches for kid in old), "old closed cases are not diffed"


def test_r8_the_read_model_uses_the_lane_of_d131_and_agrees_with_the_code() -> None:
    assert readmodel.LANE_MINUTE_MS == 200
    load = readmodel.Load(60, 40, 150, 60, 50, alerts_per_case=20)
    est = readmodel.estimate(load)
    per_discovery = est.parts["discovery searches"] / 24
    assert per_discovery <= SyncConfig().diff_calls + SyncConfig().discovery_calls
    assert est.cycle_minutes == est.cycle_ms / 200
    assert "closed probes" in est.parts


async def test_r8_the_model_bounds_what_a_discovery_asks() -> None:
    config = SyncConfig(diff_calls=3)
    r = rig(config=config)
    _world(r, cases=20, alerts=40)  # 800 alerts
    await r.cycle(within=timedelta(hours=3))
    start = len(r.kibana.es_requests)
    await r.cycle(advance=timedelta(hours=1, minutes=1), within=timedelta(hours=3))
    asked = len(r.kibana.es_requests) - start
    load = readmodel.Load(20, 0, 0, 0, 0, alerts_per_case=40, diff_calls=config.diff_calls)
    assert asked <= readmodel.estimate(load).parts["discovery searches"] / 24


# --------------------------------------------------------------------------- R9


async def test_r9_a_person_deleting_arguss_comment_or_attachment_is_a_deletion() -> None:
    r = rig()
    kid, _ = await own_case(r, COMMENT, SentWrite("attach", frozenset(), 1))
    r.kibana.comment(kid, "argus", "Opened by ARGUS.")
    r.kibana.attach(kid, "argus", "alert-1")
    await r.cycle()
    assert kinds(r) == []
    r.kibana.delete_comment(kid, PERSON, USER_COMMENT)
    alert_attachment = {"type": "alert", "alertId": ["alert-1"], "index": [INDEX]}
    r.kibana.delete_comment(kid, PERSON, alert_attachment)
    await r.cycle()
    assert kinds(r) == [Kind.PERSON_DELETED] * 2
    assert "alerts" in r.store.mirror[kid].unmanaged
    assert not (await r.lane.kibana_lane()).paused, "a person's change pauses no write class"
    first, second = (f for _, f in r.store.findings.values())
    assert {first.details["what"], second.details["what"]} == {"comment", "alert attachment"}


async def test_r9_a_deletion_by_arguss_own_key_is_an_alarm_never_an_explained_comment() -> None:
    r = rig()
    kid, _ = await own_case(r, COMMENT)
    r.kibana.comment(kid, "argus", "Opened by ARGUS.")
    await r.cycle()
    assert kinds(r) == []
    r.kibana.delete_comment(kid, "argus", USER_COMMENT)  # ARGUS never deletes
    await r.cycle()
    assert kinds(r) == [Kind.UNEXPLAINED_ARGUS_ACTION]
    assert (await r.lane.kibana_lane()).paused


# --------------------------------------------------------------------------- R10


async def test_r10_a_case_deleted_between_the_listing_and_its_actions_read() -> None:
    r = rig()
    a, _ = await own_case(r)
    b, _ = await own_case(r)
    r.kibana.comment(a, PERSON)
    r.kibana.comment(b, PERSON)
    real = r.kibana.send
    state = {"done": False}

    async def send(request: Any) -> Any:
        if request.path.endswith("/user_actions/_find") and not state["done"]:
            state["done"] = True
            r.kibana.delete(a)  # the person deletes it just now
        return await real(request)

    r.kibana.send = send  # type: ignore[method-assign]
    record = await r.cycle()
    assert record.outcome == "complete", (record.outcome, record.reason)
    assert Kind.DELETED_IN_KIBANA in kinds(r), "confirmed by a get, at once"
    assert r.store.mirror[a].deleted_at is not None
    assert r.store.mirror[b].actions_seen == 2, "the other case was read"


# --------------------------------------------------------------------------- R11


async def test_r11_no_discovery_and_no_closed_listing_in_the_quiet_hours() -> None:
    r = rig()
    await own_case(r)
    r.store.sync = replace(r.store.sync, last_closed_listing_at=r.clock.now - timedelta(days=2))
    r.clock.now = datetime(2026, 10, 27, 0, 5, tzinfo=UTC)
    es, finds, closed = len(r.kibana.es_requests), len(r.reads()), len(r.reads(status="closed"))
    record = await r.cycle(advance=timedelta(0))
    assert record.outcome == "complete"
    assert len(r.reads()) > finds, "the change poll goes on"
    assert len(r.kibana.es_requests) == es, "no Elasticsearch search at 00:05 UTC"
    assert all(p["perPage"] == "1" for p in r.reads(status="closed")[closed:]), "no closed listing"
    r.clock.now = datetime(2026, 10, 27, 1, 31, tzinfo=UTC)
    await r.cycle(advance=timedelta(0))
    assert len(r.kibana.es_requests) > es, "the discovery that was due runs at 01:31"
    assert any(p["perPage"] != "1" for p in r.reads(status="closed")[closed:])


# --------------------------------------------------------------------------- small items


async def test_small_a_peoples_case_is_kept_after_its_finding() -> None:
    r = rig()
    r.store.alerts = [(r.clock.now, "alert-7")]
    theirs = r.kibana.create(by=PERSON, tags=("phishing",), title="Anita's case")
    r.kibana.attach(theirs, PERSON, "alert-7")

    async def crash(*a: Any, **k: Any) -> None:
        raise RuntimeError("crash while keeping the case")

    real = r.store.save_people_case
    r.store.save_people_case = crash  # type: ignore[method-assign]
    await r.cycle()
    assert Kind.PEOPLE_CASE in kinds(r), "a crash cannot lose the finding"
    assert theirs not in r.store.people
    r.store.save_people_case = real  # type: ignore[method-assign]
    await r.cycle(advance=timedelta(hours=1, minutes=1))
    assert theirs in r.store.people
    assert kinds(r).count(Kind.PEOPLE_CASE) == 1


async def test_small_catching_up_is_bounded_by_the_lane_not_by_the_cycle() -> None:
    """100 changed cases after four days: the lane (200 ms a minute, two reads a minute) is the
    bound, about 16 cases a cycle; the gate report says so."""
    r = rig()
    ids = []
    for _ in range(40):
        kid, _ = await own_case(r)
        ids.append(kid)
    r.clock.now += timedelta(days=4)
    for kid in ids:
        r.kibana.comment(kid, PERSON, "while away")
    cycles = 0
    while True:
        cycles += 1
        record = await r.cycle()
        if record.outcome == "complete":
            break
        assert cycles < 12
    assert 2 <= cycles <= 5
    assert kinds(r).count(Kind.PERSON_COMMENTED) == 40


def test_small_the_sync_unit_is_not_restarted_when_the_read_back_is_off() -> None:
    """``sync run`` exits 0 while it is off; Restart=always would start it again every 30 s."""
    from pathlib import Path

    root = Path(__file__).resolve().parents[3]
    for path in (
        root / "deploy/systemd/argus-kibana-sync.service",
        root / "deploy/custody/units/argus-kibana-sync.service",
    ):
        lines = path.read_text().splitlines()
        assert "Restart=on-failure" in lines, path.name
        assert "Restart=always" not in lines, path.name
