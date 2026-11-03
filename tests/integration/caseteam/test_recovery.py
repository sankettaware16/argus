"""AR8, D-195 point 5: every write is recorded, and a crash or a timeout part-way through the
sequence resumes from the last confirmed step and never doubles a comment. A write whose outcome
is unknown follows the writer's ambiguity rule: it is looked for in Kibana (at 2, 5, 15 and 30
minutes) before anything is sent again, and when four looks find nothing a person decides.

Each test breaks the sequence at one step of the Amadey-shaped case (the open, an attach, the
tags, each owner's comment, each file, the files' comment, the verdict) and checks Kibana
afterwards: one case, each comment once, 25 alerts, 4 files."""

from __future__ import annotations

import random
import uuid
from collections.abc import Callable

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.integration.cases.conftest import Person
from tests.integration.caseteam.fake import Crash, Fault, posts, writes_by
from tests.integration.caseteam.kit import Rig, a_case, rig

pytestmark = pytest.mark.integration

STEPS: dict[str, Callable[[], Callable[..., bool]]] = {
    "open": lambda: posts("/cases"),
    "attach": lambda: writes_by("argus-lead", "/comments", 1, containing='"alertId"'),
    "last attach": lambda: writes_by("argus-lead", "/comments", 5, containing='"alertId"'),
    "tags": lambda: writes_by("argus-lead", "/tags", 1),
    "evidence": lambda: writes_by("argus-evidence", "/comments", 1),
    "glance": lambda: writes_by("argus-visualiser", "/comments", 1),
    "devices": lambda: writes_by("argus-evidence", "/comments", 2),
    "intel": lambda: writes_by("argus-intel", "/comments", 1),
    "actions": lambda: writes_by("argus-responder", "/comments", 1),
    "queries": lambda: writes_by("argus-hunter", "/comments", 1),
    "pdf": lambda: writes_by("argus-reporter", "/files", 1),
    "last csv": lambda: writes_by("argus-reporter", "/files", 4),
    "files comment": lambda: writes_by("argus-reporter", "/comments", 1),
    "verdict": lambda: writes_by("argus-lead", "/comments", 1, containing="verdict: true positive"),
}
OWNERS = [
    "argus-evidence",
    "argus-visualiser",
    "argus-evidence",
    "argus-intel",
    "argus-responder",
    "argus-hunter",
    "argus-reporter",
    "argus-lead",
]
LOOKS = (121, 180, 600, 900)  # seconds to wait before looks 1 to 4: 2, 5, 15 and 30 minutes in all


async def world(
    app: AsyncEngine, owner: AsyncEngine, writer: AsyncEngine, person: Person
) -> tuple[Rig, uuid.UUID]:
    r = rig(owner, writer)
    return r, await a_case(owner, app, person)


async def assert_exactly_once(r: Rig, case: uuid.UUID) -> None:
    """Kibana holds the case once, whole: each comment once, 25 alerts, 4 files, every alert
    tagged with the incident's two tags; ARGUS's records say verified."""
    [kibana_case] = r.kibana.team_cases()
    assert [u for u, _ in r.kibana.user_comments(kibana_case["id"])] == OWNERS
    texts = [c for _, c in r.kibana.user_comments(kibana_case["id"])]
    assert len(set(texts)) == len(texts)
    assert kibana_case["totalAlerts"] == 25
    assert [f["by"] for f in r.kibana.files[kibana_case["id"]]] == ["argus-reporter"] * 4
    assert len(r.kibana.alert_tags) == 25
    assert all(len(t) == 2 for t in r.kibana.alert_tags.values())
    states = await r.states(case)
    assert set(states) == {"verified"}, states


async def finish(r: Rig, case: uuid.UUID, rounds: int = 70) -> None:
    """Run again, a few minutes at a time, until the sequence is whole. (A timeout is charged to
    the Kibana write lane in full: for about 75 minutes the next write waits, as in production.)"""
    for _ in range(rounds):
        r.advance(130)
        report = await r.run(case)
        if report.stopped is None and not report.held:
            return
    raise AssertionError((report.lines(), await r.steps(case)))


# --------------------------------------------------------------------------- a timeout that landed


@pytest.mark.parametrize("step", STEPS)
async def test_a_timeout_that_landed_is_found_by_the_look_and_never_doubled(
    step: str,
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r, case = await world(app_engine, migrated_engine, writer_engine, people["asha"])
    r.kibana.faults.append(Fault(STEPS[step](), "timeout", land_after=0.0))

    first = await r.run(case)

    assert first.stopped is not None  # the sequence stops at the step in doubt
    assert first.ambiguous == 1
    states = await r.states(case)
    assert states.get("ambiguous") == 1
    assert "failed" not in states
    before = len(r.kibana.writes)
    soon = await r.run(case)  # at once: the first look is two minutes after the send
    assert soon.stopped is not None
    assert len(r.kibana.writes) == before
    await finish(r, case)
    await assert_exactly_once(r, case)


# --------------------------------------------------------------------------- one that never landed


@pytest.mark.parametrize("kind", ["status", "lose"])
@pytest.mark.parametrize("step", STEPS)
async def test_a_write_that_never_landed_is_looked_for_four_times_then_a_person_decides(
    step: str,
    kind: str,
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r, case = await world(app_engine, migrated_engine, writer_engine, people["asha"])
    r.kibana.faults.append(Fault(STEPS[step](), kind, status=500))

    first = await r.run(case)
    assert first.stopped is not None

    if step == "tags":
        # a tag is added to a set: sending the call again changes nothing, so nobody is asked
        await finish(r, case)
        await assert_exactly_once(r, case)
        return

    writes = len(r.kibana.writes)
    for n, wait in enumerate(LOOKS, 1):
        r.advance(wait)
        report = await r.run(case)
        assert report.stopped is not None
        assert len(r.kibana.writes) == writes  # looking is reading: nothing was sent again
        state = (
            await r.sql(
                "SELECT state, lookups FROM case_team_steps WHERE state NOT IN"
                " ('verified', 'planned')"
            )
        )[0]
        assert state.state == ("resend" if n == 4 else "ambiguous")
        if n < 4:
            assert state.lookups == n
    assert any("resend needs a person" in h for h in report.held)

    [stuck] = await r.sql("SELECT id FROM case_team_steps WHERE state = 'resend'")
    assert await r.poster.resend(stuck.id, by="mina")
    await finish(r, case)
    await assert_exactly_once(r, case)
    [row] = await r.sql(
        "SELECT sent_count, state_reason FROM case_team_steps WHERE id = :i", i=stuck.id
    )
    assert row.sent_count == 2


async def test_a_person_can_also_skip_a_step_that_was_done_by_hand(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r, case = await world(app_engine, migrated_engine, writer_engine, people["asha"])
    r.kibana.faults.append(Fault(STEPS["queries"](), "status", status=500))
    await r.run(case)
    for wait in LOOKS:
        r.advance(wait)
        await r.run(case)
    [stuck] = await r.sql("SELECT id FROM case_team_steps WHERE state = 'resend'")
    assert await r.poster.skip(stuck.id, by="mina", reason="written by hand in Kibana")
    await finish(r, case)
    [kibana_case] = r.kibana.team_cases()
    authors = [u for u, _ in r.kibana.user_comments(kibana_case["id"])]
    assert "argus-hunter" not in authors  # it was skipped, never sent
    assert authors[-1] == "argus-lead"


# --------------------------------------------------------------------------- a process that died


@pytest.mark.parametrize("step", ["open", "evidence", "pdf", "verdict"])
async def test_a_crash_after_the_request_landed_resumes_without_a_second_one(
    step: str,
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r, case = await world(app_engine, migrated_engine, writer_engine, people["asha"])
    r.kibana.crashes.append((STEPS[step](), True))
    with pytest.raises(Crash):
        await r.run(case)
    states = await r.states(case)
    assert states.get("sending") == 1  # committed before the request left, never settled
    await finish(r, case)
    await assert_exactly_once(r, case)


@pytest.mark.parametrize("step", ["open", "intel", "last csv"])
async def test_a_crash_before_the_request_landed_needs_a_person_after_four_looks(
    step: str,
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r, case = await world(app_engine, migrated_engine, writer_engine, people["asha"])
    r.kibana.crashes.append((STEPS[step](), False))
    with pytest.raises(Crash):
        await r.run(case)
    for wait in LOOKS:
        r.advance(wait)
        await r.run(case)
    [stuck] = await r.sql("SELECT id FROM case_team_steps WHERE state = 'resend'")
    assert await r.poster.resend(stuck.id, by="mina")
    await finish(r, case)
    await assert_exactly_once(r, case)


async def test_a_crash_between_steps_just_continues(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    """The run is stopped by the lane after some steps (its per-run cap): the next run goes on
    from the last confirmed one."""
    from argus.gateway.kibana.writes import WriteCaps

    r = rig(migrated_engine, writer_engine, caps=WriteCaps(team_per_run=6))
    case = await a_case(migrated_engine, app_engine, people["asha"])
    first = await r.run(case)
    assert first.stopped is not None
    assert "run_cap" in first.stopped
    case_writes = [w for w in r.kibana.writes if not w.path.endswith("/tags")]
    assert len(case_writes) == 6  # the cap counts case writes; alert tags are the lane's other cap
    for _ in range(8):
        r.advance(10)
        await r.run(case)
    await assert_exactly_once(r, case)


# --------------------------------------------------------------------------- random faults


@pytest.mark.parametrize("seed", range(12))
async def test_whatever_breaks_the_sequence_ends_whole_and_never_doubled(
    seed: int,
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    """A state-machine run: random faults (timeouts that landed or not, refusals, lost
    connections, crashes) at random steps, random waits between runs, a person who resends what
    the looks did not find; the invariant at the end is the same as for no fault."""
    dice = random.Random(seed)
    r, case = await world(app_engine, migrated_engine, writer_engine, people["asha"])
    names = list(STEPS)
    for _ in range(dice.randint(1, 5)):
        when = STEPS[dice.choice(names)]()
        kind = dice.choice(
            ["timeout-landed", "timeout-lost", "status", "lose", "crash-landed", "crash-lost"]
        )
        if kind == "timeout-landed":
            r.kibana.faults.append(Fault(when, "timeout", land_after=0.0))
        elif kind == "timeout-lost":
            r.kibana.faults.append(Fault(when, "timeout", land_after=None))
        elif kind.startswith("crash"):
            r.kibana.crashes.append((when, kind == "crash-landed"))
        else:
            r.kibana.faults.append(Fault(when, kind, status=500))
    done = False
    for _ in range(60):
        try:
            report = await r.run(case)
        except Crash:
            report = None
        r.advance(dice.choice([5, 130, 200, 650, 1000]))
        for stuck in await r.sql("SELECT id FROM case_team_steps WHERE state = 'resend'"):
            await r.poster.resend(stuck.id, by="mina")
        if report is not None and report.stopped is None and not report.held:
            done = True
            break
    assert done, await r.steps(case)
    await assert_exactly_once(r, case)
