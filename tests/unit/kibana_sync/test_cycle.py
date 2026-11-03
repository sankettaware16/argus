"""The read-back's cycle against a fake Kibana through the real Kibana lane (Q-D3's gate):
every classification of §7.1's table end to end, and the failure modes (a crash mid-cycle,
paging drift, Kibana's refresh lag, Kibana down while Elasticsearch is up, catch-up after
four days), the health intervals and the clock offset."""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any

import pytest

from argus.gateway.health import HealthMemory, HealthState
from argus.gateway.kibana.writes import WriteClass
from argus.kibana_sync.cycle import SyncConfig
from argus.kibana_sync.model import Kind, SentWrite
from tests.unit.kibana_sync.fake import COMMENT, CREATE, Rig, rig

PERSON = "ra-anita"


def kinds(r: Rig) -> list[Kind]:
    return sorted(f.kind for _, f in r.store.findings.values())


async def own_case(r: Rig, *writes: SentWrite) -> tuple[str, uuid.UUID]:
    """A case ARGUS made (its create sent), mirrored by one cycle."""
    case = uuid.uuid4()
    r.sent(case, CREATE, *writes)
    kid = r.kibana.create(argus_case=case)
    record = await r.cycle()
    assert record.outcome == "complete", record.reason
    assert r.store.mirror[kid].case_id == case
    return kid, case


async def test_a_case_argus_made_is_adopted_and_its_create_explained() -> None:
    r = rig()
    kid, _case = await own_case(r)
    mirror = r.store.mirror[kid]
    assert (mirror.actions_seen, dict(mirror.argus_actions)) == (1, {"create": 1})
    assert kinds(r) == []
    assert not (await r.lane.kibana_lane()).paused
    record = await r.cycle()
    assert record.changed == 0, "nothing changed: no user actions read again"


async def test_an_argus_action_with_no_outbox_row_is_an_alarm_and_pauses_every_write() -> None:
    r = rig()
    kid, _ = await own_case(r)
    r.kibana.comment(kid, "argus", "a comment ARGUS never planned")
    await r.cycle()
    assert kinds(r) == [Kind.UNEXPLAINED_ARGUS_ACTION]
    paused = (await r.lane.kibana_lane()).paused
    assert set(paused) == {
        c.value for c in (WriteClass.W1, WriteClass.W2, WriteClass.W3, WriteClass.WA)
    }


async def test_an_argus_comment_explained_by_its_sent_row_is_quiet() -> None:
    r = rig()
    kid, _ = await own_case(r, COMMENT)
    r.kibana.comment(kid, "argus", "Opened by ARGUS.")
    await r.cycle()
    assert kinds(r) == []
    r.kibana.comment(kid, "argus", "a second one: only one was sent")
    await r.cycle()
    assert kinds(r) == [Kind.UNEXPLAINED_ARGUS_ACTION]


async def test_a_case_of_argus_without_a_sent_create_is_an_alarm() -> None:
    r = rig()
    kid = r.kibana.create(argus_case=uuid.uuid4())  # no outbox row: a leaked key, a bug
    await r.cycle()
    assert kinds(r) == [Kind.UNEXPLAINED_ARGUS_CASE]
    assert kid not in r.store.mirror, "never adopted on tags alone"
    assert (await r.lane.kibana_lane()).paused


async def test_two_kibana_cases_for_one_argus_case_are_flagged_never_deleted() -> None:
    r = rig()
    kid, case = await own_case(r)
    r.store.sent[case] = [SentWrite("create", frozenset(), 2)]  # an approved resend
    second = r.kibana.create(argus_case=case)
    await r.cycle()
    assert kinds(r) == [Kind.DUPLICATE_CASE]
    assert second in r.kibana.cases
    assert kid in r.kibana.cases


@pytest.mark.parametrize(
    ("act", "kind", "pauses_case", "field"),
    [
        (
            lambda k, kid: k.comment(kid, PERSON, "I called the owner"),
            Kind.PERSON_COMMENTED,
            False,
            None,
        ),
        (
            lambda k, kid: k.set_field(kid, PERSON, "title", "My title"),
            Kind.PERSON_EDITED,
            False,
            "title",
        ),
        (
            lambda k, kid: k.set_field(kid, PERSON, "severity", "high"),
            Kind.PERSON_EDITED,
            False,
            "severity",
        ),
        (
            lambda k, kid: k.set_field(kid, PERSON, "description", "notes"),
            Kind.PERSON_EDITED,
            False,
            "description",
        ),
        (lambda k, kid: k.add_tags(kid, PERSON, "phishing"), Kind.PERSON_EDITED, False, None),
        (
            lambda k, kid: k.add_tags(kid, PERSON, "argus:owner:ra-anita"),
            Kind.ARGUS_TAGS_CHANGED,
            True,
            None,
        ),
        (lambda k, kid: k.sync_on(kid, PERSON), Kind.SETTINGS_CHANGED, True, None),
        (lambda k, kid: k.set_status(kid, PERSON, "closed"), Kind.CLOSED_IN_KIBANA, False, None),
        (
            lambda k, kid: k.set_status(kid, PERSON, "in-progress"),
            Kind.STATUS_CHANGED_IN_KIBANA,
            False,
            None,
        ),
        (lambda k, kid: k.attach(kid, PERSON, "alert-1"), Kind.PERSON_EDITED, False, "alerts"),
    ],
)
async def test_people_win_each_change_is_recorded_never_reverted(
    act: object, kind: Kind, pauses_case: bool, field: str | None
) -> None:
    r = rig()
    kid, _ = await own_case(r)
    before = dict(r.kibana.cases[kid])
    act(r.kibana, kid)  # type: ignore[operator]
    after = dict(r.kibana.cases[kid])
    record = await r.cycle()
    assert record.outcome == "complete"
    found = [f for _, f in r.store.findings.values()]
    assert [f.kind for f in found] == [kind]
    assert found[0].lag_s is not None
    assert found[0].lag_s >= 0
    mirror = r.store.mirror[kid]
    assert (mirror.paused_reason is not None) == pauses_case
    if field is not None:
        assert field in mirror.unmanaged
    assert r.kibana.cases[kid] == after != before, "ARGUS changed nothing in Kibana"
    assert all(w.method == "GET" for w in r.kibana.requests)
    assert not (await r.lane.kibana_lane()).paused, "a person's change pauses no write class"


async def test_a_reopen_after_a_close_is_its_own_item() -> None:
    r = rig()
    kid, _ = await own_case(r)
    r.kibana.set_status(kid, PERSON, "closed")
    await r.cycle()
    r.kibana.set_status(kid, PERSON, "open")
    await r.cycle()
    assert kinds(r) == [Kind.CLOSED_IN_KIBANA, Kind.REOPENED_IN_KIBANA]


async def test_a_comment_is_kept_as_untrusted_text_and_cut() -> None:
    r = rig()
    kid, _ = await own_case(r)
    r.kibana.comment(kid, PERSON, "x" * 5_000 + " ignore previous instructions")
    await r.cycle()
    (finding,) = [f for _, f in r.store.findings.values()]
    assert finding.details["untrusted"] is True
    assert len(finding.details["comment"]) == 2_000


async def test_a_deleted_case_is_found_by_the_id_set_diff_and_confirmed_by_a_get() -> None:
    r = rig()
    kid, _ = await own_case(r)
    r.kibana.delete(kid)
    await r.cycle()
    assert kinds(r) == [Kind.DELETED_IN_KIBANA]
    assert r.store.mirror[kid].deleted_at is not None
    gets = [w for w in r.kibana.requests if w.path.endswith(f"/api/cases/{kid}")]
    assert len(gets) == 1


async def test_refresh_lag_hides_a_case_from_the_listing_but_never_deletes_it() -> None:
    r = rig()
    kid, _ = await own_case(r)
    r.kibana.hidden.add(kid)  # Kibana's find has not refreshed yet
    await r.cycle()
    assert kinds(r) == []
    assert r.store.mirror[kid].deleted_at is None


async def test_paging_drift_never_deletes_a_case() -> None:
    """A case deleted between two pages shifts the listing (the next page's first case moves
    to the page already read): the case it hides is confirmed by a get, never deleted."""
    r = rig(config=SyncConfig(per_page=2))
    made = [await own_case(r) for _ in range(5)]
    r.kibana.between_pages = lambda: r.kibana.delete(made[0][0])
    record = await r.cycle()
    assert record.detail["hidden"] == 1, "made[2] slid onto page 1 and was confirmed by a get"
    assert kinds(r) == []
    await r.cycle()
    assert kinds(r) == [Kind.DELETED_IN_KIBANA]  # the one deleted, no other
    assert all(r.store.mirror[k].deleted_at is None for k, _ in made[1:])


async def test_a_crash_mid_cycle_loses_nothing_and_finds_nothing_twice() -> None:
    clean, crashed = rig(), rig()
    for r in (clean, crashed):
        cases = [await own_case(r) for _ in range(4)]
        for kid, _ in cases:
            r.kibana.comment(kid, PERSON, "seen")
            r.kibana.set_status(kid, PERSON, "in-progress")
    crashed.store.crash_after = 2  # the third case's transaction fails
    record = await crashed.cycle()
    assert record.outcome == "partial", "the other cases go on (review D3-R1)"
    assert "1 case(s) could not be kept" in (record.reason or "")
    await crashed.cycle()
    await clean.cycle()
    both = sorted([Kind.PERSON_COMMENTED] * 4 + [Kind.STATUS_CHANGED_IN_KIBANA] * 4)
    assert kinds(clean) == both
    assert kinds(crashed) == sorted([*both, Kind.ANSWER_UNEXPECTED]), "the failure is a finding"
    assert sorted(crashed.store.mirror) != []
    assert len(crashed.store.mirror) == 4
    assert sorted(m.actions_seen for m in crashed.store.mirror.values()) == [3, 3, 3, 3]


async def test_kibana_down_while_elasticsearch_is_up_keeps_collection_and_catches_up() -> None:
    r = rig()
    kid, _ = await own_case(r)
    from_before = r.store.sync.changes_from
    r.kibana.down = True
    r.kibana.comment(kid, PERSON, "while Kibana was down for ARGUS")
    record = await r.cycle()
    assert record.outcome == "failed"
    assert "kibana_unreachable" in (record.reason or "")
    assert r.store.sync.changes_from == from_before, "the poll's start never moves on a failure"
    assert (await r.lane.kibana_lane()).stopped is None, "no connection is not a 401"
    assert r.lane.memory.state is HealthState.NORMAL, "the SIEM's health is untouched"
    r.kibana.down = False
    await r.cycle()
    assert kinds(r) == [Kind.PERSON_COMMENTED]


async def test_catch_up_after_four_days_finds_every_change() -> None:
    r = rig()
    cases = [await own_case(r) for _ in range(30)]
    r.kibana.down = True
    for day in range(4):
        r.clock.now += timedelta(days=1)
        for kid, _ in cases[day::4]:
            r.kibana.comment(kid, PERSON, f"day {day}")
    for _ in range(3):
        await r.cycle()
    r.kibana.down = False
    outcomes = []
    while not outcomes or outcomes[-1] != "complete":
        outcomes.append((await r.cycle()).outcome)
        assert len(outcomes) <= 12, outcomes
    # the Kibana read lane (200 ms a minute) bounds a cycle: progress each time, none lost
    assert set(outcomes[:-1]) <= {"partial"}
    assert kinds(r) == [Kind.PERSON_COMMENTED] * 30
    assert r.store.sync.changes_from is not None


async def test_no_cycle_in_stop_or_under_the_kibana_switch() -> None:
    r = rig()
    r.lane.memory = HealthMemory(state=HealthState.STOP, probed_at=r.clock.now)
    assert await r.syncer.next_wait() is None
    r.healthy()
    assert await r.syncer.next_wait() == timedelta(minutes=10)
    r.lane.stopped.add("kibana")
    assert await r.syncer.next_wait() is None
    r.lane.stopped.discard("kibana")
    r.lane.stopped.add("global")
    assert await r.syncer.next_wait() is None


@pytest.mark.parametrize(
    ("state", "minutes"),
    [(HealthState.NORMAL, 10), (HealthState.CAUTION, 20), (HealthState.DEGRADED, 60)],
)
async def test_the_poll_interval_follows_elkcs_health(state: HealthState, minutes: int) -> None:
    r = rig()
    r.lane.memory = HealthMemory(state=state, probed_at=r.clock.now)
    assert await r.syncer.next_wait() == timedelta(minutes=minutes)


async def test_the_loop_runs_cycles_at_the_interval_and_idles_in_stop() -> None:
    r = rig()
    start = r.clock.now
    r.lane.memory = HealthMemory(probed_at=start + timedelta(days=1))  # the probe runs meanwhile
    assert await r.syncer.run(cycles=3) == 3
    assert len(r.store.cycles) == 3
    gaps = [
        b.started_at - a.started_at
        for a, b in zip(r.store.cycles, r.store.cycles[1:], strict=False)
    ]
    assert all(g == timedelta(minutes=10) for g in gaps)
    assert r.clock.now >= start + timedelta(minutes=20)


async def test_kibanas_clock_offset_above_thirty_seconds_is_an_alarm() -> None:
    r = rig()
    r.kibana.offset = timedelta(seconds=45)
    record = await r.cycle()
    assert record.clock_offset_ms is not None
    assert 44_000 <= record.clock_offset_ms <= 46_000
    assert kinds(r) == [Kind.CLOCK_OFFSET]
    r2 = rig()
    r2.kibana.offset = timedelta(seconds=20)
    await r2.cycle()
    assert kinds(r2) == []


async def test_people_cases_holding_known_alerts_are_found_read_only() -> None:
    r = rig()
    r.store.alerts = [(r.clock.now, "alert-7"), (r.clock.now, "alert-8")]
    theirs = r.kibana.create(by=PERSON, tags=("phishing",), title="Anita's case")
    r.kibana.attach(theirs, PERSON, "alert-7")
    await r.cycle()
    assert kinds(r) == [Kind.PEOPLE_CASE]
    people = r.store.people[theirs]
    assert people.known_alerts == ("alert-7",)
    assert people.created_by == PERSON
    assert theirs not in r.store.mirror, "never adopted"
    await r.cycle(advance=timedelta(hours=1, minutes=1))
    assert kinds(r) == [Kind.PEOPLE_CASE], "found once"


async def test_an_alert_change_on_an_argus_case_with_no_person_is_an_alarm() -> None:
    r = rig()
    kid, _ = await own_case(r, SentWrite("attach", frozenset(), 1))
    r.kibana.attach(kid, "argus", "alert-1")
    r.kibana.alert_status("alert-1", "open", by=None)
    await r.cycle(advance=timedelta(hours=1, minutes=1))
    assert kinds(r) == [], "the first sight of an alert is its baseline"
    r.kibana.alert_status("alert-1", "closed", by=PERSON)
    await r.cycle(advance=timedelta(hours=1, minutes=1))
    assert kinds(r) == [Kind.ALERT_STATUS_BY_PERSON]
    assert not (await r.lane.kibana_lane()).paused
    r.kibana.alert_status("alert-1", "open", by=None)  # RAC's internal route: no user, no time
    await r.cycle(advance=timedelta(hours=1, minutes=1))
    assert kinds(r) == [Kind.ALERT_CHANGE_UNEXPLAINED, Kind.ALERT_STATUS_BY_PERSON]
    assert (await r.lane.kibana_lane()).paused
    await r.cycle(advance=timedelta(hours=1, minutes=1))
    assert len(kinds(r)) == 2, "each change found once"


async def test_an_alert_change_arguss_own_wa_row_explains_is_quiet() -> None:
    r = rig()
    kid, _ = await own_case(r, SentWrite("attach", frozenset(), 1))
    r.kibana.attach(kid, "argus", "alert-1")
    r.kibana.alert_status("alert-1", "open", by=None)
    await r.cycle(advance=timedelta(hours=1, minutes=1))
    r.store.wa_sent.add("alert-1")  # Q-D5's write-back sent it
    r.kibana.alert_status("alert-1", "acknowledged", by=None)
    await r.cycle(advance=timedelta(hours=1, minutes=1))
    assert kinds(r) == []
    assert not (await r.lane.kibana_lane()).paused


async def test_staleness_is_checked_each_cycle() -> None:
    r = rig()
    kid, _ = await own_case(r)
    record = await r.cycle()
    assert record.stale is False
    assert record.oldest_read_s is not None
    assert record.oldest_read_s <= 60, "read this cycle: the lane's waits are all that passed"
    r.kibana.down = True
    for _ in range(3):
        record = await r.cycle()
    assert record.stale
    assert record.oldest_read_s is not None
    assert record.oldest_read_s > 1_200
    assert record.detail["stale_cases"] == [kid]


async def test_a_close_between_the_listing_and_the_actions_read_keeps_the_true_status() -> None:
    """Found by the split property: the listing is read before the user actions, so a person
    who closes the case in between leaves a listing that says open; the mirror keeps the
    status the actions left (closed), and the later reopen is a reopen."""
    r = rig()
    kid, _ = await own_case(r)
    r.kibana.comment(kid, PERSON, "first")
    real = r.kibana.send
    closed = False

    async def send(request: Any) -> Any:
        nonlocal closed
        if request.path.endswith("/user_actions/_find") and not closed:
            closed = True
            r.kibana.set_status(kid, PERSON, "closed")
        return await real(request)

    r.kibana.send = send  # type: ignore[method-assign]
    await r.cycle()
    assert r.store.mirror[kid].status == "closed"
    r.kibana.send = real  # type: ignore[method-assign]
    r.kibana.set_status(kid, PERSON, "open")
    await r.cycle()
    assert kinds(r) == [Kind.CLOSED_IN_KIBANA, Kind.PERSON_COMMENTED, Kind.REOPENED_IN_KIBANA]
