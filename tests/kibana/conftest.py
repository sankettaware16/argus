"""Contract tests against the local Kibana 8.19.12 tier (Q-D1; plan §12's "local tier" items).

Every test here is marked ``kibana`` (tests/conftest.py, by directory) and records its
exchanges in a strict cassette, tests/kibana/cassettes/<module>__<test>.json:

* **live** when the tier answers (docs/runbooks/kibana-tier.md): the requests go to the tier and
  the normalized recording must equal the committed cassette byte for byte (a changed answer
  is a changed contract: re-record with KIBANA_TIER_RECORD=1 only after reviewing it; a
  missing cassette fails too: a new test records its first with KIBANA_TIER_RECORD=new);
* **replay** otherwise: nothing is sent anywhere; each request must be the cassette's next one
  and gets its recorded answer, so the assertions still run against what the tier answered.
  Tests that need the live tier (timing, the delaying proxy) are skipped in replay.

KIBANA_TIER=live makes a missing tier an error instead of a replay, =replay never
contacts it. Runs in several worktrees at once are safe: each session has its own run id and
touches only objects named after it (tests/kibana/tier.py), and cleans them up at the end.
"""

from __future__ import annotations

import re
from collections.abc import Generator, Iterator

import pytest

from tests.conftest import hide_in_reports
from tests.kibana import kit
from tests.kibana.tier import Tier, mode_requested, new_run_id, record_requested, tier_problem
from tests.kibana.tier import tier_script as _tier_script


@pytest.fixture(scope="session")
def kibana_tier() -> Iterator[Tier]:
    requested = mode_requested()
    settings = _tier_script.Settings.from_env()
    problem = None if requested == "replay" else tier_problem(settings)
    lock = None
    if problem is None and requested != "replay":
        # shared with every other live session, for the whole run: exclusive use, `down` and
        # `reset` wait for it (docs/runbooks/kibana-tier.md, "Exclusive use")
        lock = _tier_script.TierLock(settings.paths)
        try:
            lock.acquire(exclusive=False)
        except _tier_script.TierBusy as exc:
            problem, lock = str(exc), None
    if requested == "live" and problem is not None:
        pytest.fail(f"KIBANA_TIER=live, but {problem}", pytrace=False)
    mode = "live" if requested != "replay" and problem is None else "replay"
    tier = Tier(
        mode,
        new_run_id(),
        record=record_requested(),
        settings=settings,
        data=_tier_script.load_secrets(settings.paths) if mode == "live" else {},
        lock=lock,
    )
    if mode == "live":
        for value in tier.known_secrets():  # masked in every report from now on
            hide_in_reports(value)
        kit.register_cleanup(tier)
    try:
        yield tier
        problems = tier.close()
        if problems:  # pragma: no cover - reported, never hiding the results
            print("kibana tier clean-up:", "; ".join(problems))
    finally:
        if lock is not None:
            lock.release()


@pytest.fixture
def kt(kibana_tier: Tier, request: pytest.FixtureRequest) -> Iterator[Tier]:
    """The tier, recording this test's cassette (checked when the test passes)."""
    module = request.node.module.__name__.rsplit(".", 1)[-1].removeprefix("test_")
    name = re.sub(r"[^A-Za-z0-9_.-]+", "-", f"{module}__{request.node.name}").strip("-")
    kibana_tier.start(name)
    yield kibana_tier
    kibana_tier.recorder = None


@pytest.fixture
def live_kt(kt: Tier) -> Tier:
    """For tests that only the live tier can prove (timing): skipped in replay."""
    if not kt.live:
        pytest.skip(
            "needs the live Kibana tier (timing cannot be replayed): "
            "docs/runbooks/kibana-tier.md, 'What cassettes cannot do'"
        )
    return kt


@pytest.hookimpl(wrapper=True)
def pytest_pyfunc_call(pyfuncitem: pytest.Function) -> Generator[None, object, object]:
    """Check the cassette when the test body passed, so a difference fails the test itself."""
    result = yield
    tier = pyfuncitem.funcargs.get("kt") or pyfuncitem.funcargs.get("live_kt")
    if isinstance(tier, Tier) and tier.recorder is not None:
        tier.recorder.finish(on_note=print)
    return result
