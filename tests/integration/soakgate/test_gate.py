"""P4-A1: the soak gate against a throwaway database, read as the runtime login. Rows are written as
the owner; the gate (``run.build``) reads them back with ``argus_runtime``'s grants alone. One
test for each line's way to fail, a world that passes, and the empty store."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.soakgate import run
from argus.soakgate.model import Check, Report, Verdict
from tests.integration.cases.conftest import Person, make_person
from tests.integration.soakgate import kit

pytestmark = pytest.mark.integration

PASS, FAIL, PENDING, OPEN = Verdict.PASS, Verdict.FAIL, Verdict.PENDING, Verdict.OPEN
D = kit.DAY


def at(hours: float = 0.0, minutes: float = 0.0) -> datetime:
    return D + timedelta(hours=hours, minutes=minutes)


async def judged(
    app: AsyncEngine, tmp_path: Path, *, live: bool = False
) -> tuple[Report, dict[str, Check]]:
    report = await run.build(app, kit.settings(tmp_path), kit.window(live=live))
    return report, {c.id: c for line in report.lines for c in line.checks}


class World:
    """Cases of the case team: a report, a person's confirm, a post, its steps and ledger rows."""

    def __init__(self, owner: AsyncEngine, app: AsyncEngine, person: Person) -> None:
        self.owner, self.app, self.person = owner, app, person
        self.cases: list[tuple[uuid.UUID, int]] = []

    async def posted_case(
        self,
        host: str,
        *,
        confirmed_at: datetime | None = D,
        opened_after: float = 5,
        by: Person | None = None,
        mirrored: bool = True,
        probe: str = "normal",
        ledger: bool = True,
    ) -> tuple[uuid.UUID, int, int]:
        """A case with a Kibana case: confirmed (unless ``confirmed_at`` is None) at
        ``confirmed_at``, opened ``opened_after`` minutes later with a verified create and one
        verified comment, each with its ledger row and a probe before it."""
        case_id, number = await kit.case(self.owner, self.app, self.person, host)
        self.cases.append((case_id, number))
        report_id = await kit.report(self.owner, case_id, at=D - timedelta(hours=1))
        if confirmed_at is not None:
            await kit.decide(self.owner, report_id, (by or self.person).user_id, at=confirmed_at)
        opened = (confirmed_at or D) + timedelta(minutes=opened_after)
        await kit.post(self.owner, case_id, number, kibana=f"k-{number}", opened_at=opened)
        first = await kit.step(
            self.owner, case_id, 1, kind="open", sent_at=opened - timedelta(minutes=1),
            verified_at=opened, kibana_ids={"case": f"k-{number}"},
        )  # fmt: skip
        second = await kit.step(
            self.owner, case_id, 2, sent_at=opened + timedelta(minutes=1),
            verified_at=opened + timedelta(minutes=2),
        )  # fmt: skip
        if ledger:
            for step_id, minutes, template in (
                (first, -1, "team.create"),
                (second, 1, "team.comment"),
            ):
                await kit.probe(self.owner, opened + timedelta(minutes=minutes - 1), probe)
                await kit.request(
                    self.owner, opened + timedelta(minutes=minutes), template=template,
                    outbox_id=f"team:{step_id}",
                )  # fmt: skip
        if mirrored:
            await kit.mirror(self.owner, case_id, f"k-{number}")
        return case_id, number, first


async def verdict_comment(owner: AsyncEngine, case_id: uuid.UUID) -> None:
    await kit.run(
        owner,
        "INSERT INTO case_team_seen (kibana_comment_id, text_hash, case_id, author, written_at,"
        " verdict, status, read_at) VALUES ('c1', :h, :c, 'a-person', :t, 'true_positive',"
        " 'recorded', :t)",
        h=kit.digest("c1"), c=case_id, t=at(1),
    )  # fmt: skip


# --------------------------------------------------------------------------- the empty store


async def test_an_empty_store_is_judged_without_a_failure_and_the_runtime_login_reads_all(
    app_engine: AsyncEngine, tmp_path: Path
) -> None:
    report, checks = await judged(app_engine, tmp_path)
    assert [line.number for line in report.lines] == list(range(1, 12))
    assert not report.failed
    assert report.notes == ()  # no table was unreadable for argus_runtime
    assert not [k for k in checks if k.endswith("x")]  # no "facts could not be read" check
    assert all(line.verdict in (PENDING, OPEN) for line in report.lines)
    assert checks["1a"].verdict is PENDING
    assert checks["3d"].verdict is PENDING
    assert checks["9b"].verdict is OPEN
    assert checks["10b"].verdict is OPEN
    assert checks["11b"].verdict is OPEN


# --------------------------------------------------------------------------- a world that passes


async def test_three_confirmed_cases_posted_cleanly_pass_every_case_team_line(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    people: dict[str, Person],
    tmp_path: Path,
) -> None:
    world = World(migrated_engine, app_engine, people["asha"])
    for n, host in enumerate(("10.0.1.1", "10.0.1.2", "10.0.1.3")):
        await world.posted_case(host, confirmed_at=at(0, 10 * n))
    for minute in range(20):
        await kit.cycle(migrated_engine, at(2, minute))
    await verdict_comment(migrated_engine, world.cases[0][0])
    report, c = await judged(app_engine, tmp_path)
    got = {
        k: c[k].verdict for k in ("1a", "1b", "1c", "2a", "3a", "3b", "3c", "3d", "4a", "4b", "6d")
    }
    assert got == dict.fromkeys(got, PASS), {k: c[k].detail for k in got if got[k] is not PASS}
    assert (c["1a"].n, c["1b"].n, c["1c"].n, c["2a"].n) == (6, 3, 3, 3)
    assert c["3a"].measured["ledger_rows"] == 6
    assert c["3d"].measured["got"] == {
        "cases_posted": 3, "verdicts_recorded": 1, "read_back_cycles_complete": 20,
    }  # fmt: skip
    assert c["4a"].measured["creation_lag"]["max_s"] == 300.0
    assert report.notes == ()
    failing = [
        (c_.id, c_.detail) for line in report.lines for c_ in line.checks if c_.verdict is FAIL
    ]
    assert not report.failed, failing


# --------------------------------------------------------------------------- lines 1 and 2


async def test_a_step_in_doubt_a_second_create_and_a_duplicate_case_fail_line_1(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    people: dict[str, Person],
    tmp_path: Path,
) -> None:
    world = World(migrated_engine, app_engine, people["asha"])
    case_id, number, create = await world.posted_case("10.0.2.1")
    await kit.step(
        migrated_engine, case_id, 3, state="ambiguous", sent_at=at(-3), created_at=at(-4)
    )
    await kit.run(
        migrated_engine, "UPDATE case_team_steps SET sent_count = 2 WHERE id = :i", i=create
    )
    await kit.step(migrated_engine, case_id, 4, kind="open", gen=2, kibana_ids={"case": "another"})
    _, c = await judged(app_engine, tmp_path)
    assert c["1a"].verdict is FAIL
    assert f"case {number} step" in c["1a"].detail
    assert c["1b"].verdict is FAIL
    assert c["1c"].verdict is FAIL
    assert f"case {number} (2 Kibana cases)" in c["1c"].detail


async def test_a_kibana_case_without_a_persons_confirm_fails_line_2(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    people: dict[str, Person],
    tmp_path: Path,
) -> None:
    world = World(migrated_engine, app_engine, people["asha"])
    _, none, _ = await world.posted_case("10.0.3.1", confirmed_at=None)
    assistant = await make_person(app_engine, "argus-assistant")
    _, by_assistant, _ = await world.posted_case("10.0.3.2", by=assistant)
    _, by_person, _ = await world.posted_case("10.0.3.3")
    _, c = await judged(app_engine, tmp_path)
    assert c["2a"].verdict is FAIL
    assert f"case {none}, {by_assistant}" in c["2a"].detail
    assert str(by_person) not in c["2a"].detail.split("without one:")[1]
    assert "1 confirmed only by ARGUS's own assistant account" in c["2a"].detail
    assert (c["2a"].n, c["2a"].measured["without_person_confirm"]) == (3, 2)


async def test_a_confirm_after_the_create_does_not_count_for_line_2(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    people: dict[str, Person],
    tmp_path: Path,
) -> None:
    world = World(migrated_engine, app_engine, people["asha"])
    case_id, number, _ = await world.posted_case("10.0.3.9", confirmed_at=None)
    report_id = (
        await kit.run(
            migrated_engine, "SELECT id FROM incident_reports WHERE case_id = :c", c=case_id
        )
    ).id
    await kit.decide(migrated_engine, report_id, people["asha"].user_id, at=at(2))  # later
    _, c = await judged(app_engine, tmp_path)
    assert c["2a"].verdict is FAIL
    assert f"case {number}" in c["2a"].detail


# --------------------------------------------------------------------------- line 3


async def test_the_ledger_gap_and_the_writes_outside_the_rules_fail_line_3(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    people: dict[str, Person],
    tmp_path: Path,
) -> None:
    world = World(migrated_engine, app_engine, people["asha"])
    case_id, _, _ = await world.posted_case("10.0.4.1", probe="caution")
    lost = await kit.step(migrated_engine, case_id, 3, sent_at=at(0, 30), verified_at=at(0, 31))
    # a row naming no step, one at night, one gateway reading of caution, a W1, an unknown template
    await kit.request(migrated_engine, at(0, 40), outbox_id="team:999999")
    await kit.request(migrated_engine, D.replace(hour=20), outbox_id=f"team:{lost}")
    await kit.request(migrated_engine, at(0, 50), outbox_id=f"team:{lost}", health="caution")
    await kit.request(migrated_engine, at(0, 51), write_class="W1", template="cases.create")
    await kit.request(migrated_engine, at(0, 52), write_class=None, template="cases.delete")
    await kit.request(migrated_engine, at(0, 53), write_class=None, template="team.comment")
    _, c = await judged(app_engine, tmp_path)
    assert c["3a"].verdict is FAIL
    assert "999999" not in c["3a"].detail  # the unknown row is counted, not named
    assert "1 rows name no step" in c["3a"].detail
    assert c["3b"].verdict is FAIL
    m = c["3b"].measured
    assert m["not_normal_by_ledger"] == 1
    assert m["not_normal_by_probe"] >= 1
    assert m["outside_window"] == 1
    assert m["other_class_rows"] == {"W1": 1, "team.comment (no class)": 1}
    assert c["3c"].verdict is FAIL
    assert "cases.delete x1" in c["3c"].detail


async def test_a_step_sent_with_no_ledger_row_is_named(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    people: dict[str, Person],
    tmp_path: Path,
) -> None:
    world = World(migrated_engine, app_engine, people["asha"])
    case_id, _, _ = await world.posted_case("10.0.4.2")
    lost = await kit.step(
        migrated_engine, case_id, 3, sent_count=2, sent_at=at(1), verified_at=at(1)
    )
    _, c = await judged(app_engine, tmp_path)
    assert c["3a"].verdict is FAIL
    assert f"steps with no row: {lost}" in c["3a"].detail
    assert c["3a"].measured["sends"] == 4  # two steps sent once, one twice
    assert c["3a"].measured["ledger_rows"] == 2


# --------------------------------------------------------------------------- line 4


async def test_coverage_counts_from_the_next_write_window_for_a_night_confirm(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    people: dict[str, Person],
    tmp_path: Path,
) -> None:
    world = World(migrated_engine, app_engine, people["asha"])
    night = D.replace(day=30, hour=22)  # confirmed at night: ready at the next 02:30
    _, early, _ = await world.posted_case("10.0.5.1", confirmed_at=night)
    # opened at 02:40 next day (10 minutes after the window opened): inside the 15 minutes
    await kit.run(
        migrated_engine,
        "UPDATE case_team_posts SET opened_at = :t",
        t=night + timedelta(hours=4, minutes=40),
    )
    _, c = await judged(app_engine, tmp_path)
    assert c["4a"].verdict is PASS, c["4a"].detail
    assert c["4a"].measured["creation_lag"]["max_s"] == 600.0
    await kit.run(
        migrated_engine, "UPDATE case_team_posts SET opened_at = :t", t=night + timedelta(hours=5)
    )
    _, c = await judged(app_engine, tmp_path)
    assert c["4a"].verdict is FAIL
    assert f"{early} (30 min)" in c["4a"].detail


async def test_a_confirmed_case_never_opened_is_late_and_a_rejection_removes_it(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    people: dict[str, Person],
    tmp_path: Path,
) -> None:
    case_id, _ = await kit.case(migrated_engine, app_engine, people["asha"], "10.0.5.2")
    report_id = await kit.report(migrated_engine, case_id)
    await kit.decide(migrated_engine, report_id, people["asha"].user_id, at=at(0))
    _, c = await judged(app_engine, tmp_path)
    assert c["4a"].verdict is FAIL
    assert "not opened" in c["4a"].detail
    await kit.decide(
        migrated_engine, report_id, people["ravi"].user_id, decision="rejected",
        outcome="benign_expected", at=at(0, 20),
    )  # fmt: skip
    _, c = await judged(app_engine, tmp_path)
    assert c["4a"].verdict is PENDING  # nothing is confirmed any more


# --------------------------------------------------------------------------- line 5


async def test_a_kibana_close_request_fails_line_5_and_a_peoples_dismissal_does_not(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    people: dict[str, Person],
    tmp_path: Path,
) -> None:
    await kit.case(migrated_engine, app_engine, people["asha"], "10.0.6.0")  # an event: opened
    _, c = await judged(app_engine, tmp_path, live=True)
    assert c["5a"].verdict is PASS
    assert c["5b"].verdict is PENDING
    await kit.request(migrated_engine, at(1), template="cases.comment", write_class=None)
    _, c = await judged(app_engine, tmp_path, live=True)
    assert c["5b"].verdict is PASS
    await kit.request(
        migrated_engine, at(2), template="cases.close", write_class="W3", outcome="refused"
    )
    _, c = await judged(app_engine, tmp_path, live=True)
    assert c["5b"].verdict is FAIL
    assert "cases.close x1" in c["5b"].detail


async def test_an_automatic_closure_is_found_by_its_actor_and_a_persons_is_not(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    people: dict[str, Person],
    tmp_path: Path,
) -> None:
    await kit.case(migrated_engine, app_engine, people["asha"], "10.0.6.1")  # opened by a person
    _, c = await judged(app_engine, tmp_path, live=True)
    assert (c["5a"].verdict, c["5a"].measured["closures"]) == (PASS, 0)
    number = await kit.dismissal_by_argus(migrated_engine)
    _, c = await judged(app_engine, tmp_path, live=True)
    assert c["5a"].verdict is FAIL
    assert f"case {number} dismissed by argus:test" in c["5a"].detail
    assert (c["5a"].n, c["5a"].measured["automatic"]) == (1, 1)


# --------------------------------------------------------------------------- line 6


async def test_slow_unexplained_and_unmirrored_changes_show_on_line_6(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    people: dict[str, Person],
    tmp_path: Path,
) -> None:
    world = World(migrated_engine, app_engine, people["asha"])
    case_id, _, _ = await world.posted_case("10.0.7.1", mirrored=False)
    await kit.cycle(migrated_engine, at(0, 0))
    await kit.cycle(migrated_engine, at(3, 0), health="caution")
    await kit.finding(migrated_engine, "closed_in_kibana", at(1), lag_s=120, case_id=case_id)
    await kit.finding(migrated_engine, "person_edited", at(1, 5), lag_s=1_000, case_id=case_id)
    # a slow one found while the SIEM was not normal does not count (NORMAL only)
    await kit.finding(migrated_engine, "person_edited", at(3, 5), lag_s=9_000, case_id=case_id)
    await kit.finding(
        migrated_engine, "unexplained_argus_action", at(1, 10), lag_s=5, case_id=case_id
    )
    await kit.finding(migrated_engine, "unexplained_argus_case", at(1, 11), resolved=True)
    report, c = await judged(app_engine, tmp_path)
    assert c["6a"].verdict is FAIL
    assert c["6a"].n == 2
    assert c["6a"].measured["lag"]["max_s"] == 1_000.0
    assert c["6c"].verdict is FAIL
    assert "1 unresolved" in c["6c"].detail
    assert "1 more were resolved" in c["6c"].detail
    assert c["6d"].verdict is PENDING
    assert any("does not cover the case team's cases yet" in note for note in report.notes)


async def test_an_argus_write_after_a_persons_change_is_a_revert(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    people: dict[str, Person],
    tmp_path: Path,
) -> None:
    world = World(migrated_engine, app_engine, people["asha"])
    case_id, number, _ = await world.posted_case("10.0.7.2")
    await kit.cycle(migrated_engine, at(0, 0))
    _, c = await judged(app_engine, tmp_path)
    assert c["6b"].verdict is PASS
    await kit.finding(migrated_engine, "person_edited", at(0, 30), lag_s=60, case_id=case_id)
    # a step of a kind that is not additive, sent after it (the check allows five kinds today, so
    # the kind is loosened for this test only)
    await kit.run(
        migrated_engine, "ALTER TABLE case_team_steps DROP CONSTRAINT ck_case_team_steps_kind_valid"
    )
    await kit.step(migrated_engine, case_id, 9, kind="retitle", sent_at=at(1))
    _, c = await judged(app_engine, tmp_path)
    assert c["6b"].verdict is FAIL
    assert f"case {number} retitle" in c["6b"].detail


# --------------------------------------------------------------------------- line 7


async def test_an_undecided_member_of_a_notified_case_fails_line_7(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    people: dict[str, Person],
    tmp_path: Path,
) -> None:
    from tests.integration.cases import knownkit

    when = datetime.now(UTC) - timedelta(days=2)
    inv = await knownkit.make(migrated_engine, when=when, host=knownkit.HOST)
    case_id = await knownkit.open_case(app_engine, people["asha"], [inv])
    await knownkit.notify(app_engine, people["asha"], case_id, when + timedelta(hours=1))
    # the investigation alerted again after the notice, two hours ago, and nobody decided it
    await kit.run(
        migrated_engine,
        "UPDATE investigations SET last_event_at = :a, updated_at = :b WHERE id = :i",
        a=datetime.now(UTC) - timedelta(hours=3), b=datetime.now(UTC) - timedelta(hours=2), i=inv,
    )  # fmt: skip
    _, c = await judged(app_engine, tmp_path, live=True)
    assert c["7a"].verdict is FAIL
    assert "investigation" in c["7a"].detail
    assert c["7b"].verdict is PENDING
    # decided at its current version: no longer undecided, and a change is measured
    await kit.run(
        migrated_engine,
        "INSERT INTO case_known_matches (investigation_id, case_id, version, outcome, why,"
        " changed_version, decided_at) SELECT id, :c, version, 'changed', 'a new server', version,"
        " updated_at + interval '2 minutes' FROM investigations WHERE id = :i",
        c=case_id, i=inv,
    )  # fmt: skip
    _, c = await judged(app_engine, tmp_path, live=True)
    assert c["7a"].verdict is PASS
    assert c["7b"].verdict is PASS
    assert c["7b"].measured["lag"]["max_s"] == 120.0


# --------------------------------------------------------------------------- line 8


async def test_the_load_of_each_lane_is_read_against_its_plan(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, tmp_path: Path
) -> None:
    minute = at(1)
    # the collector spends 2,000 ms of its 1,800: over its share, inside what its bucket admits
    await kit.request(
        migrated_engine, minute, template="alerts.states", purpose="collect", lane="collector",
        target="elasticsearch", write_class=None, took_ms=2_000, health=None,
    )  # fmt: skip
    _, c = await judged(app_engine, tmp_path)
    assert c["8a"].verdict is PASS
    assert c["8a"].measured["lanes"]["collector"]["minutes_over_share"] == 1
    # a probe is outside every lane
    await kit.request(
        migrated_engine, minute, template="probe.nodes", purpose="probe", lane=None,
        target="elasticsearch", write_class=None, took_ms=500, health=None,
    )  # fmt: skip
    # the sign-ins lane: two heavy requests a second apart, in the investigation lane
    for n in range(2):
        await kit.request(
            migrated_engine, minute + timedelta(seconds=n), template="signins.day",
            purpose="investigate", lane="investigation", target="elasticsearch", write_class=None,
            took_ms=300, health=None,
        )  # fmt: skip
    _, c = await judged(app_engine, tmp_path)
    assert c["8a"].verdict is PASS  # 600 ms in a minute: over its 400, inside the bucket's 800
    assert c["8a"].measured["lanes"]["investigation"]["worst_ms"] == 600
    assert c["8e"].verdict is FAIL
    assert c["8e"].measured["gap_breaches"] == 1
    assert c["8b"].measured["lane_days"]["investigation"]["2026-10-30"]["heavy"] == 2


async def test_a_lane_beyond_its_bucket_in_a_minute_fails_line_8(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, tmp_path: Path
) -> None:
    for n in range(10):  # 10 x 500 ms in one minute in a 200 ms lane with no burst (D-242)
        await kit.request(
            migrated_engine, at(1) + timedelta(seconds=n * 3), took_ms=500, write_class=None,
            outbox_id=None, template="cases.find", purpose="kibana_read", lane="kibana_read",
        )  # fmt: skip
    _, c = await judged(app_engine, tmp_path)
    assert c["8a"].verdict is FAIL
    assert "kibana_read" in c["8a"].detail


async def test_a_move_out_of_normal_after_arguss_requests_is_for_a_person(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, tmp_path: Path
) -> None:
    await kit.probe(migrated_engine, at(1, 0))
    await kit.request(
        migrated_engine, at(1, 20), template="alerts.states", purpose="collect", lane="collector",
        target="elasticsearch", write_class=None, took_ms=300, health=None,
    )  # fmt: skip
    await kit.probe(migrated_engine, at(1, 1), "caution")
    _, c = await judged(app_engine, tmp_path)
    assert c["8d"].verdict is PASS  # the request came after the probe that saw caution
    await kit.probe(migrated_engine, at(1, 2))
    await kit.probe(migrated_engine, at(1, 3), "caution")
    await kit.request(
        migrated_engine, at(1, 2) + timedelta(seconds=30), template="alerts.states",
        purpose="collect", lane="collector", target="elasticsearch", write_class=None,
        took_ms=300, health=None,
    )  # fmt: skip
    _, c = await judged(app_engine, tmp_path)
    assert c["8d"].verdict is OPEN
    assert c["8d"].measured["moves"] == 2
    assert c["8d"].measured["with_argus_requests_before"] == 1


# --------------------------------------------------------------------------- line 9


async def test_an_incomplete_lookup_nobody_retried_fails_line_9_and_a_stored_leak_fails_the_sweep(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, tmp_path: Path
) -> None:
    day = date(2026, 10, 30)
    await kit.lookup(migrated_engine, "10.1.1.1", day, at(1))
    await kit.lookup(migrated_engine, "10.1.1.2", day, at(2), reason="failed")
    await kit.lookup(migrated_engine, "10.1.1.3", day, at(2), reason="logs_gone")
    _, c = await judged(app_engine, tmp_path)
    assert c["9a"].verdict is FAIL
    assert c["9a"].n == 3
    assert c["9a"].measured["past_retry_time"] == 1
    assert c["9b"].verdict is OPEN
    folder = tmp_path / "gate" / "p1" / "20261031T060000Z"
    folder.mkdir(parents=True)
    body = {"at": at(3).isoformat(), "dossiers": 9, "leaks": 1, "signin_name_leaks": 1,
            "signin_names_checked": 4}  # fmt: skip
    (folder / "sweep.json").write_text(json.dumps(body))
    _, c = await judged(app_engine, tmp_path)
    assert c["9b"].verdict is FAIL


# --------------------------------------------------------------------------- lines 10 and 11


async def test_cost_over_the_daily_cap_fails_line_10(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, tmp_path: Path
) -> None:
    await kit.llm_call(migrated_engine, at(1), 0.2)
    _, c = await judged(app_engine, tmp_path)
    assert c["10c"].verdict is PASS
    await kit.llm_call(migrated_engine, at(2), 100.0)
    _, c = await judged(app_engine, tmp_path)
    assert c["10c"].verdict is FAIL


async def test_a_silent_sampler_fails_line_11_and_fresh_samples_leave_it_open(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, tmp_path: Path
) -> None:
    await kit.sample(migrated_engine, at(1))
    _, c = await judged(app_engine, tmp_path)
    assert c["11a"].verdict is FAIL
    await kit.sample(migrated_engine, kit.window().until - timedelta(minutes=10))
    _, c = await judged(app_engine, tmp_path)
    assert c["11a"].verdict is OPEN
    assert c["11a"].measured["samples"] == 2
    assert c["11a"].measured["gaps"]  # the long silence between them is named


async def test_unreadable_backups_and_a_drill_log_are_judged_from_the_folder(
    app_engine: AsyncEngine, tmp_path: Path
) -> None:
    folder = tmp_path / "backups"
    folder.mkdir()
    until = kit.window().until
    drills = [{"at": (until - timedelta(days=1)).isoformat(), "dump": "nightly/x", "passed": False}]
    (folder / "drills.jsonl").write_text("\n".join(json.dumps(d) for d in drills) + "\n")
    _, c = await judged(app_engine, tmp_path)
    assert c["11c"].verdict is FAIL  # dumps were due and the folder holds none
    assert c["11d"].verdict is FAIL
    assert c["11d"].measured["failed"] == 1


# --------------------------------------------------------------------------- the reading itself


async def test_the_gate_reads_in_a_transaction_that_cannot_write(app_engine: AsyncEngine) -> None:
    from sqlalchemy import text
    from sqlalchemy.exc import DBAPIError
    from sqlalchemy.ext.asyncio import AsyncConnection

    async def write(conn: AsyncConnection) -> list[Check]:
        await conn.execute(
            text("INSERT INTO soak_samples (at, metrics) VALUES (now(), CAST('{}' AS jsonb))")
        )
        return []

    with pytest.raises(DBAPIError, match="read-only"):
        await run._read(app_engine, write)


async def test_a_table_the_runtime_login_may_not_read_costs_its_line_not_the_report(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, tmp_path: Path
) -> None:
    await kit.run(migrated_engine, "REVOKE SELECT ON soak_samples FROM argus_runtime")
    report, c = await judged(app_engine, tmp_path)
    assert c["11x"].verdict is OPEN
    assert "may not read a table" in c["11x"].detail
    assert "a grant on that table for argus_runtime" in (c["11x"].needs or "")
    assert any(note.startswith("line 11:") for note in report.notes)
    assert len(report.lines) == 11
    assert report.lines[10].verdict is OPEN  # not a pass, not a failure: a person is told
    assert "11a" not in c
    assert "1a" in c  # every other line was read
