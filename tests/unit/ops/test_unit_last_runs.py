"""P4-E3: the service-units check reads what the user service manager says of the enabled units
(D-305's finding: doctor said "7 of the 7 ... running as installed" while the case team's oneshot
had failed every run since the install). An enabled timer whose service's last run failed fails,
and so does an enabled service that failed; what is not enabled is not asked about. Fixtures
only: the service manager is a fake, nothing here reads the real unit directory."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.config.settings import CaseTeamSettings, Settings, UnitsSettings
from argus.doctor import CheckResult
from argus.ops import case_team_login, checks, units
from argus.ops.checks import LastRun
from argus.ops.units import UNITS_DIR
from tests.unit.ops.test_checks import PARAMS, RENDERED, RUN, _installed_and_enabled, labels

pytestmark = pytest.mark.unit

FAILED = LastRun("failed", "exit-code", "1", datetime(2026, 11, 4, 10, 52, tzinfo=UTC))
REFUSED = LastRun("failed", "exit-code", "2", datetime(2026, 11, 4, 10, 52, tzinfo=UTC))
FINE = LastRun("inactive", "success", "0", datetime(2026, 11, 4, 10, 52, tzinfo=UTC))
RUNNING = LastRun("active", "success", "0", None)


class Manager:
    """A fake user service manager: what it says of each service, and what it was asked."""

    def __init__(self, says: Mapping[str, LastRun] | str) -> None:
        self.says = says
        self.asked: list[list[str]] = []

    def __call__(self, names: Sequence[str]) -> Mapping[str, LastRun] | str:
        self.asked.append(list(names))
        if isinstance(self.says, str):
            return self.says
        return {n: run for n, run in self.says.items() if n in names}


def _results(
    folder: Path, ask: Manager, run: Sequence[str] = RUN, refusing: Mapping[str, str] | None = None
) -> list[CheckResult]:
    return checks.unit_results(
        UNITS_DIR, folder, (), params=PARAMS, run=run, ask=ask, refusing=refusing
    )


def _by_name(results: list[CheckResult], name: str) -> list[CheckResult]:
    return [r for r in results if r.name == name]


def test_an_enabled_timer_whose_service_failed_its_last_run_fails(tmp_path: Path) -> None:
    folder = _installed_and_enabled(tmp_path)
    ask = Manager({"argus-case-team.service": FAILED, "argus-web.service": RUNNING})
    results = _results(folder, ask)
    assert results[0].label == "FAIL"
    assert "6 of the 7 this installation runs running as installed" in results[0].detail
    assert results[0].detail.endswith("; 1 failed their last run")
    [line] = _by_name(results, "unit argus-case-team.service")
    assert line.label == "FAIL"
    assert line.detail.startswith("its last run failed (exit-code, exit status 1, at 2026-11-04 ")
    assert line.detail.endswith(
        ") and argus-case-team.timer keeps starting it: journalctl --user -u"
        " argus-case-team.service -n 30 shows why"
    )
    enabled = [n for n, (role, _) in units.roles_for(RUN).items() if role.value in ("run", "soon")]
    timers = [n for n in enabled if n.endswith(".timer")]
    asked = sorted({*(checks._service_of(n) for n in enabled), *timers})
    assert ask.asked == [asked]  # one question, about what is enabled only


def test_a_stopped_timer_starts_nothing_so_its_service_is_not_judged(tmp_path: Path) -> None:
    """A deploy window stops the case team's timer and leaves it enabled: until it is started
    again, the failed run before the update is not held against the installation."""
    folder = _installed_and_enabled(tmp_path)
    stopped = Manager({"argus-case-team.service": FAILED, "argus-case-team.timer": FINE})
    assert _by_name(_results(folder, stopped), "unit argus-case-team.service") == []
    started = Manager({"argus-case-team.service": FAILED, "argus-case-team.timer": RUNNING})
    [line] = _by_name(_results(folder, started), "unit argus-case-team.service")
    assert line.label == "FAIL"


def test_a_timer_that_is_not_enabled_is_not_judged(tmp_path: Path) -> None:
    """The case team left off by choice (its timer neither listed nor enabled): a failure of its
    last run, from before it was switched off, is not this installation's problem."""
    run = (*units.CORE, "argus-soak-sample.timer", "argus-kibana-sync.service")
    folder = tmp_path / "user"
    folder.mkdir()
    wants = folder / "default.target.wants"
    wants.mkdir()
    for name, (role, _) in units.roles_for(run).items():
        (folder / name).write_text(RENDERED[name])
        if role.value in ("run", "soon"):
            (wants / name).symlink_to(folder / name)
    ask = Manager({"argus-case-team.service": FAILED})
    results = _results(folder, ask, run)
    assert results[0].label == "PASS", results
    assert "argus-case-team.service" not in ask.asked[0]
    assert _by_name(results, "unit argus-case-team.service") == []


def test_an_enabled_service_that_failed_is_not_running(tmp_path: Path) -> None:
    folder = _installed_and_enabled(tmp_path)
    results = _results(folder, Manager({"argus-collector.service": FAILED}))
    assert "6 of the 7" in results[0].detail
    [line] = _by_name(results, "unit argus-collector.service")
    assert line.label == "FAIL"
    assert line.detail.startswith("failed (exit-code, exit status 1, at ")
    assert line.detail.endswith(
        "): it is not running; journalctl --user -u argus-collector.service -n 30 shows why,"
        " then systemctl --user restart it"
    )


def test_running_or_fine_services_and_a_new_run_are_no_failure(tmp_path: Path) -> None:
    folder = _installed_and_enabled(tmp_path)
    says = {"argus-case-team.service": LastRun("activating", "success", "0", None),
            "argus-backup.service": FINE, "argus-web.service": RUNNING}  # fmt: skip
    results = _results(folder, Manager(says))
    assert "7 of the 7" in results[0].detail
    assert "failed their last run" not in results[0].detail
    assert not any(r.detail.startswith(("its last run failed", "failed (")) for r in results)


def test_a_service_manager_that_cannot_be_asked_is_said_not_failed(tmp_path: Path) -> None:
    folder = _installed_and_enabled(tmp_path)
    results = _results(folder, Manager("the user service manager did not answer"))
    assert results[0].detail.endswith(
        "; their last runs not read (the user service manager did not answer)"
    )
    assert ("unit argus-case-team.service", "FAIL") not in labels(results)


def test_nothing_enabled_asks_nothing(tmp_path: Path) -> None:
    folder = tmp_path / "user"
    folder.mkdir()
    for name, text in RENDERED.items():
        (folder / name).write_text(text)
    ask = Manager({"argus-case-team.service": FAILED})
    results = _results(folder, ask)
    assert ask.asked == []
    assert results[0].label == "WARN"  # not started yet, as before


def test_a_failure_line_names_no_time_it_was_not_told() -> None:
    state = units.UnitState("argus-case-team.timer", units.Role.RUN, "", True, True, True, True)
    found, unread, refused = checks._failed_runs(
        [state], (), Manager({"argus-case-team.service": LastRun("failed", "", "", None)})
    )
    assert (unread, refused) == (None, {})
    assert found["argus-case-team.service"].detail.startswith(
        "its last run failed (failed, exit status ?) and"
    )


def test_a_unit_moved_to_custody_is_not_asked_about() -> None:
    state = units.UnitState("argus-case-team.timer", units.Role.OFF, "", True, True, True, True)
    ask = Manager({"argus-case-team.service": FAILED})
    assert checks._failed_runs([state], {"argus-case-team.timer"}, ask) == ({}, None, {})
    assert ask.asked == []


_TIMERS = sorted(n for n in units.MANIFEST if n.endswith(".timer"))
_SERVICES = sorted(n for n in units.MANIFEST if n.endswith(".service"))
_LONG_RUNNING = sorted(n for n, (role, _) in units.MANIFEST.items()
                       if n.endswith(".service") and role is not units.Role.TRIGGERED)  # fmt: skip


@given(
    enabled=st.sets(st.sampled_from(_TIMERS + _LONG_RUNNING)),
    stopped=st.sets(st.sampled_from(_TIMERS)),
    failed=st.sets(st.sampled_from(_SERVICES)),
    exit_2=st.sets(st.sampled_from(_SERVICES)),
    refusing=st.sets(st.sampled_from(_SERVICES), max_size=3),
    moved=st.sets(st.sampled_from(sorted(units.MANIFEST)), max_size=3),
)
def test_exactly_the_enabled_units_that_failed_fail(
    enabled: set[str],
    stopped: set[str],
    failed: set[str],
    exit_2: set[str],
    refusing: set[str],
    moved: set[str],
) -> None:
    """Whatever is enabled, stopped for now, failed (with status 2 or another), switched off by
    choice or moved to custody: a failure for each service of an enabled timer that runs and each
    enabled service that failed, unless it is switched off and its run refused (said instead),
    none for anything else, and a question about enabled units only."""
    states = [
        units.UnitState(name, role, why, True, True, True, name in enabled)
        for name, (role, why) in units.roles_for(RUN).items()
    ]
    says = {name: (REFUSED if name in exit_2 else FAILED) if name in failed else FINE
            for name in _SERVICES}  # fmt: skip
    says |= {name: FINE if name in stopped else RUNNING for name in _TIMERS}
    ask = Manager(says)
    off = {name: f"{name} is off" for name in refusing}
    found, unread, refused = checks._failed_runs(states, moved, ask, off)
    judged = enabled - moved
    failing = {checks._service_of(n) for n in judged - stopped} & failed
    by_choice = failing & refusing & exit_2
    assert unread is None
    assert set(found) == failing - by_choice
    assert refused == {name: f"{name} is off" for name in by_choice}
    assert all(not r.ok and r.name == f"unit {n}" for n, r in found.items())
    assert set(ask.asked[0] if ask.asked else []) <= {*judged, *map(checks._service_of, judged)}
    assert bool(ask.asked) is bool(judged)


def test_the_summary_counts_the_failed_runs(tmp_path: Path) -> None:
    folder = _installed_and_enabled(tmp_path)
    says = {"argus-case-team.service": FAILED, "argus-soak-sample.service": FAILED,
            "argus-worker.service": FAILED}  # fmt: skip
    results = _results(folder, Manager(says))
    assert results[0].label == "FAIL"
    assert "4 of the 7 this installation runs running" in results[0].detail
    assert results[0].detail.endswith("; 3 failed their last run")
    assert {r.name for r in results[1:] if not r.ok} == {
        "unit argus-case-team.service", "unit argus-soak-sample.service",
        "unit argus-worker.service"}  # fmt: skip


# --------------------------------------------------------------------------- posting off by choice


def _switches(root: Path, text: str) -> Settings:
    """This checkout's case-team switches file, and settings whose units run from it."""
    (root / "local").mkdir(parents=True, exist_ok=True)
    (root / case_team_login.SWITCHES).write_text(text)
    return Settings(units=UnitsSettings(root=root))


def test_posting_off_with_the_timer_enabled_is_a_choice_not_a_failure(tmp_path: Path) -> None:
    """The documented stop (docs/case-team.md section 10, the runbook): posting off in the
    switches file, the timer left enabled. Each run then refuses with exit status 2 before it logs
    in, and systemd marks the oneshot failed; doctor says so in the summary and fails nothing."""
    folder = _installed_and_enabled(tmp_path)
    settings = _switches(tmp_path / "argus", "ARGUS_CASE_TEAM__POST=false\n")
    ask = Manager({"argus-case-team.service": REFUSED, "argus-case-team.timer": RUNNING})
    results = _results(folder, ask, refusing=checks.refusing_services(settings))
    assert results[0].label == "PASS", results
    assert "7 of the 7 this installation runs running as installed" in results[0].detail
    assert results[0].detail.endswith(
        "; argus-case-team.service refuses its runs: posting is off (ARGUS_CASE_TEAM__POST is"
        " off in local/argus-writer.env)"
    )
    assert _by_name(results, "unit argus-case-team.service") == []


def test_posting_off_does_not_hide_a_run_that_failed_otherwise(tmp_path: Path) -> None:
    """Only the refusal (exit status 2) is the choice: a unit that cannot start (uv gone: 203)
    or that was killed fails as before, and so does a refusal while posting is on (a key missing,
    Kibana switched off: something to fix)."""
    folder = _installed_and_enabled(tmp_path)
    off = checks.refusing_services(_switches(tmp_path / "argus", "ARGUS_CASE_TEAM__POST=0\n"))
    for other in (FAILED, LastRun("failed", "exit-code", "203", None),
                  LastRun("failed", "signal", "9", None)):  # fmt: skip
        results = _results(folder, Manager({"argus-case-team.service": other}), refusing=off)
        [line] = _by_name(results, "unit argus-case-team.service")
        assert line.label == "FAIL"
        assert "refuses its runs" not in results[0].detail
    results = _results(folder, Manager({"argus-case-team.service": REFUSED}), refusing={})
    [line] = _by_name(results, "unit argus-case-team.service")
    assert (line.label, "exit status 2" in line.detail) == ("FAIL", True)


_OFF = "ARGUS_CASE_TEAM__POST is off in local/argus-writer.env"


@pytest.mark.parametrize(
    ("text", "configured", "why"),
    [
        ("ARGUS_CASE_TEAM__POST=false\n", True, _OFF),  # the unit's file outranks .env and YAML
        ("ARGUS_CASE_TEAM__POST=no\n", False, _OFF),
        ("ARGUS_CASE_TEAM__POST=true\n", False, None),
        ("ARGUS_CASE_TEAM__POST=flase\n", False, None),  # the unit cannot load it: a fault
        ("", False, "case_team.post is false"),
        ("", True, None),
    ],
)
def test_the_case_team_is_switched_off_by_its_own_switch(
    tmp_path: Path, text: str, configured: bool, why: str | None
) -> None:
    settings = _switches(tmp_path, text).model_copy(
        update={"case_team": CaseTeamSettings(post=configured)}
    )
    expected = {} if why is None else {"argus-case-team.service": f"posting is off ({why})"}
    assert checks.refusing_services(settings) == expected


# --------------------------------------------------------------------------- the service manager


class _Done:
    def __init__(self, out: str, code: int = 0) -> None:
        self.stdout, self.returncode = out, code


def test_last_runs_are_read_from_the_user_manager() -> None:
    answer = (
        "Result=exit-code\nExecMainStatus=1\nId=argus-case-team.service\nActiveState=failed\n"
        "InactiveEnterTimestamp=@1793789520\n\n"
        "Id=argus-web.service\nActiveState=active\nResult=success\nExecMainStatus=0\n"
        "InactiveEnterTimestamp=\n"
    )
    seen: list[list[str]] = []

    def run(argv: list[str], **_: Any) -> _Done:
        seen.append(argv)
        return _Done(answer)

    got = checks.last_runs(["argus-case-team.service", "argus-web.service"], run)  # type: ignore[arg-type]
    assert got == {
        "argus-case-team.service": LastRun(
            "failed", "exit-code", "1", datetime.fromtimestamp(1793789520, UTC)
        ),
        "argus-web.service": LastRun("active", "success", "0", None),
    }
    assert isinstance(got, Mapping)
    assert got["argus-case-team.service"].failed
    assert not got["argus-web.service"].failed
    argv = seen[0]
    assert argv[:3] == ["systemctl", "--user", "show"]  # read-only: nothing started or stopped
    assert "--property=Id,ActiveState,Result,ExecMainStatus,InactiveEnterTimestamp" in argv

    def broken(argv: list[str], **_: Any) -> _Done:
        raise FileNotFoundError("systemctl")

    assert "could not be run" in str(checks.last_runs(["a"], broken))  # type: ignore[arg-type]
    down = checks.last_runs(["a"], lambda *_a, **_k: _Done("", 1))  # type: ignore[arg-type]
    assert "did not answer" in str(down)


@pytest.mark.parametrize("stamp", ["", "n/a", "@", "@x", "@99999999999999999999"])
def test_an_odd_timestamp_is_no_time(stamp: str) -> None:
    assert checks._stamp(stamp) is None


async def test_the_registered_check_asks_the_user_manager(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    given: dict[str, Any] = {}

    def results(**kwargs: Any) -> list[CheckResult]:
        given.update(kwargs)
        return [CheckResult("service units", True, "fake")]

    monkeypatch.setattr(checks, "unit_results", results)
    settings = Settings(units=UnitsSettings(root=tmp_path))
    assert labels(await checks.unit_check(settings)) == [("service units", "PASS")]
    assert given["ask"] is checks.last_runs
    assert given["refusing"] == {
        "argus-case-team.service": "posting is off (case_team.post is false)"
    }
