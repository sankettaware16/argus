"""P4-A1: the soak gate's vocabulary, the window, the pure helpers of the fetchers, the files it
reads (the privacy sweep, the backup folder), the report's rendering and its units."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from datetime import UTC, datetime, time, timedelta
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st
from typer.testing import CliRunner

from argus.cli import app
from argus.config.settings import Settings
from argus.ops import units
from argus.soakgate import fetch, judge, render, run
from argus.soakgate.model import (
    Check,
    Line,
    Report,
    Spread,
    Verdict,
    Window,
    nearest_rank,
    percent,
    span_text,
    worst,
)
from tests.conftest import REPO_ROOT, plain, private_text

pytestmark = pytest.mark.unit

PASS, FAIL, PENDING, OPEN = Verdict.PASS, Verdict.FAIL, Verdict.PENDING, Verdict.OPEN
runner = CliRunner()


def at(day: int, hour: int = 0, minute: int = 0) -> datetime:
    return datetime(2026, 11, day, hour, minute, tzinfo=UTC)


# --------------------------------------------------------------------------- verdicts


def test_the_worst_verdict_orders_fail_pending_open_pass() -> None:
    assert worst([PASS, OPEN]) is OPEN
    assert worst([OPEN, PENDING]) is PENDING
    assert worst([PENDING, FAIL, PASS]) is FAIL
    assert worst([PASS, PASS]) is PASS
    assert worst([]) is PENDING


@given(
    st.lists(st.sampled_from(list(Verdict)), min_size=1, max_size=8), st.sampled_from(list(Verdict))
)
def test_adding_a_check_never_improves_a_line(existing: list[Verdict], added: Verdict) -> None:
    assert worst([*existing, added]).severity >= worst(existing).severity


def test_a_line_takes_its_worst_checks_verdict() -> None:
    line = Line(
        1,
        "x",
        (Check("1a", "a", PASS, "d"), Check("1b", "b", OPEN, "d"), Check("1c", "c", PASS, "d")),
    )
    assert line.verdict is OPEN


def test_the_report_counts_lines_by_verdict_and_fails_only_on_fail() -> None:
    w = Window(at(1), at(2))
    lines = (
        Line(1, "a", (Check("1a", "a", PASS, "d"),)),
        Line(2, "b", (Check("2a", "b", PENDING, "d"),)),
        Line(3, "c", (Check("3a", "c", OPEN, "d"),)),
    )
    report = Report("phase3", at(2), w, lines)
    assert report.summary() == {"PASS": 1, "FAIL": 0, "PENDING": 1, "OPEN": 1}
    assert not report.failed
    assert Report("phase3", at(2), w, (*lines, Line(4, "d", (Check("4a", "d", FAIL, "x"),)))).failed


def test_the_json_carries_the_window_the_checks_and_their_numbers() -> None:
    check = Check("1a", "a", PENDING, "d", n=0, measured={"k": 1}, needs="more")
    report = Report("phase3", at(2, 6, 30), Window(at(1), at(2)), (Line(1, "a", (check,)),), ("n",))
    data = json.loads(json.dumps(report.as_json()))
    assert data["schema"] == "soak-gate@1"
    assert data["window"] == {
        "since": "2026-11-01T00:00:00+00:00",
        "until": "2026-11-02T00:00:00+00:00",
        "days": 1.0,
    }
    assert data["lines"][0]["checks"][0] == {
        "id": "1a",
        "title": "a",
        "verdict": "PENDING",
        "n": 0,
        "detail": "d",
        "needs": "more",
        "measured": {"k": 1},
    }
    assert data["summary"]["PENDING"] == 1
    assert data["notes"] == ["n"]


# --------------------------------------------------------------------------- numbers


def test_nearest_rank_is_always_a_value_that_was_seen() -> None:
    assert nearest_rank([], 0.95) is None
    assert nearest_rank([5.0], 0.95) == 5.0
    assert nearest_rank(list(map(float, range(1, 21))), 0.95) == 19.0
    assert nearest_rank(list(map(float, range(1, 21))), 1.0) == 20.0


@given(st.lists(st.floats(0, 1e6, allow_nan=False), min_size=1, max_size=40))
def test_the_spread_lies_between_the_least_and_the_most(values: list[float]) -> None:
    s = Spread.of(values)
    assert s.n == len(values)
    assert s.p95_s is not None
    assert s.max_s == max(values)
    assert min(values) <= s.p95_s <= max(values)


def test_spans_and_percentages_read_for_a_person() -> None:
    assert [span_text(v) for v in (None, 45.0, 120.0, 7_200.0)] == ["n/a", "45 s", "2 min", "2.0 h"]
    assert (percent(1, 3), percent(0, 0)) == ("33.3 %", "n/a")


# --------------------------------------------------------------------------- the window


def test_the_default_window_starts_at_the_phase_3_close() -> None:
    w = run.window_of(at(5))
    assert w.since == datetime(2026, 10, 30, 12, 45, tzinfo=UTC)
    assert w.until == at(5)


def test_days_count_back_from_now_and_since_must_precede_now() -> None:
    assert run.window_of(at(5), days=2).since == at(3)
    assert run.window_of(at(5), since=at(4, 12)).since == at(4, 12)
    for bad in (
        {"since": at(5, 1)},
        {"days": 0.0},
        {"days": -1.0},
        {"since": at(1), "days": 3.0},
        {"since": datetime(2026, 11, 1)},  # noqa: DTZ001 - no zone is the case
    ):
        with pytest.raises(ValueError, match=r"--days|--since|window|before now"):
            run.window_of(at(5), **bad)


def test_a_since_in_another_zone_is_read_in_utc() -> None:
    from datetime import timezone

    ist = timezone(timedelta(hours=5, minutes=30))
    w = run.window_of(at(5), since=datetime(2026, 11, 3, 12, 0, tzinfo=ist))
    assert w.since == at(3, 6, 30)


# --------------------------------------------------------------------------- fetch helpers


@pytest.mark.parametrize(
    ("ready", "expected"),
    [
        (at(1, 3, 0), at(1, 3, 0)),  # inside the window
        (at(1, 2, 30), at(1, 2, 30)),  # the window's first minute
        (at(1, 1, 0), at(1, 2, 30)),  # before it opens: today's start
        (at(1, 17, 30), at(2, 2, 30)),  # the end is outside: tomorrow's start
        (at(1, 23, 0), at(2, 2, 30)),
    ],
)
def test_a_case_ready_outside_the_window_waits_for_the_next_start(
    ready: datetime, expected: datetime
) -> None:
    assert fetch.next_window_start(ready, time(2, 30), time(17, 30)) == expected


@pytest.mark.parametrize(
    ("outbox", "step"),
    [("team:12", 12), ("team:0", 0), ("w1:12", None), ("team:", None), ("team:1x", None),
     (None, None), ("xteam:5", None)],
)  # fmt: skip
def test_a_ledger_row_names_its_step_by_the_outbox_id(outbox: str | None, step: int | None) -> None:
    assert fetch._step_of(outbox) == step


def test_the_allowlist_is_both_registries_and_the_close_templates_are_found() -> None:
    assert fetch.known_template("signins.day")
    assert fetch.known_template("team.create")
    assert fetch.known_template("cases.close")
    assert not fetch.known_template("cases.delete")
    assert "cases.close" in fetch.CLOSE_TEMPLATES
    assert "team.create" not in fetch.CLOSE_TEMPLATES


def test_only_elasticsearch_aggregations_and_unknown_names_are_heavy() -> None:
    assert fetch.is_heavy("signins.day")  # an aggregation on a log index
    assert not fetch.is_heavy("team.comment")  # every Kibana template is light
    assert not fetch.is_heavy("cases.find")
    assert fetch.is_heavy("not.a.template")  # unknown: as the budget counts it


def test_the_signins_template_the_arithmetic_counts_is_the_real_one() -> None:
    from argus.gateway.templates import REGISTRY

    assert fetch.SIGNIN_TEMPLATE in REGISTRY


def test_the_due_times_of_a_daily_and_a_weekly_timer() -> None:
    w = Window(datetime(2026, 10, 30, 12, 45, tzinfo=UTC), at(3, 12))
    daily = fetch._due(w, fetch.DUMP_AT)
    assert [d.strftime("%m-%d %H:%M") for d in daily] == [
        "10-30 21:30", "10-31 21:30", "11-01 21:30", "11-02 21:30"
    ]  # fmt: skip
    weekly = fetch._due(w, fetch.DRILL_AT, fetch.DRILL_WEEKDAY)
    assert [d.strftime("%m-%d %a %H:%M") for d in weekly] == ["11-01 Sun 22:00"]
    short = Window(at(1, 23), at(2, 1))
    assert fetch._due(short, fetch.DUMP_AT) == ()


def test_the_backup_times_are_the_timers_in_deploy_systemd() -> None:
    timer = (REPO_ROOT / "deploy/systemd/argus-backup.timer").read_text()
    drill = (REPO_ROOT / "deploy/systemd/argus-backup-drill.timer").read_text()
    assert f"OnCalendar=*-*-* {fetch.DUMP_AT:%H:%M}:00 UTC" in timer
    assert f"OnCalendar=Sun *-*-* {fetch.DRILL_AT:%H:%M}:00 UTC" in drill
    assert fetch.DRILL_WEEKDAY == 6


def test_d216s_arithmetic_is_the_decisions_numbers() -> None:
    text = private_text(REPO_ROOT / "DECISIONS.md")
    section = " ".join(text.split("## D-216", 1)[1].split("\n## D-", 1)[0].split())
    assert "about 14 requests of 200 addresses for the backfill" in section
    assert "about 3 requests a day for finished days and at most about 24" in section
    assert fetch.SIGNIN_STEADY_PER_DAY == 3 + 24
    assert fetch.SIGNIN_BACKFILL_EXTRA == 14


# --------------------------------------------------------------------------- local files


def _settings(tmp_path: Path) -> Settings:
    return Settings(soak={"dir": tmp_path / "gate" / "soak"}, backup={"dir": tmp_path / "backups"})  # type: ignore[arg-type]


def _sweep_file(tmp_path: Path, stamp: str, **fields: object) -> Path:
    folder = tmp_path / "gate" / "p1" / stamp
    folder.mkdir(parents=True)
    body = {"at": "2026-11-01T05:00:00+00:00", "dossiers": 500, "leaks": 0, "signin_name_leaks": 0,
            "signin_names_checked": 12, **fields}  # fmt: skip
    (folder / "sweep.json").write_text(json.dumps(body))
    return folder / "sweep.json"


def test_the_newest_stored_sweep_is_the_one_beside_the_soak_folder(tmp_path: Path) -> None:
    assert fetch.sweep(_settings(tmp_path)).path is None
    _sweep_file(tmp_path, "20261030T100000Z", leaks=4)
    newest = _sweep_file(tmp_path, "20261101T050000Z")
    found = fetch.sweep(_settings(tmp_path))
    assert found.path == str(newest)
    assert (found.leaks, found.signin_names_checked, found.dossiers) == (0, 12, 500)
    assert found.at == datetime(2026, 11, 1, 5, 0, tzinfo=UTC)


def test_a_sweep_that_cannot_be_read_is_reported_as_such(tmp_path: Path) -> None:
    path = _sweep_file(tmp_path, "20261101T050000Z")
    path.write_text("{not json")
    found = fetch.sweep(_settings(tmp_path))
    assert (found.path, found.leaks, found.at) == (str(path), None, None)
    path.write_text(json.dumps({"at": "2026-11-01T05:00:00"}))  # fields missing
    assert fetch.sweep(_settings(tmp_path)).leaks is None


def test_a_sweep_time_without_a_zone_is_read_as_utc(tmp_path: Path) -> None:
    _sweep_file(tmp_path, "20261101T050000Z", at="2026-11-01T05:00:00")
    assert fetch.sweep(_settings(tmp_path)).at == datetime(2026, 11, 1, 5, 0, tzinfo=UTC)


def test_backups_come_from_the_manifests_and_the_drill_log(tmp_path: Path) -> None:
    base = tmp_path / "backups"
    (base / "nightly").mkdir(parents=True)
    drills = [
        {"at": "2026-11-01T22:03:00+00:00", "dump": "nightly/x", "passed": True},
        {"at": "2026-10-20T22:03:00+00:00", "dump": "nightly/old", "passed": False},  # before
        {"nope": 1},
    ]
    (base / "drills.jsonl").write_text("\n".join(json.dumps(d) for d in drills) + "\nnot json\n")
    w = Window(datetime(2026, 10, 30, 12, 45, tzinfo=UTC), at(2, 6, 30))
    found = fetch.backups(_settings(tmp_path), w)
    assert found.readable
    assert found.drills == ((datetime(2026, 11, 1, 22, 3, tzinfo=UTC), True),)
    assert len(found.dump_due) == 3
    assert found.dumps == ()
    assert len(found.drill_due) == 1


def test_a_missing_backup_folder_is_unreadable(tmp_path: Path) -> None:
    found = fetch.backups(_settings(tmp_path), Window(at(1), at(2)))
    assert not found.readable


# --------------------------------------------------------------------------- the lane of a row


def test_a_ledger_row_without_a_lane_takes_its_purposes_and_a_probe_has_none() -> None:
    assert fetch._lane_of("collector", "collect") == "collector"
    assert fetch._lane_of(None, "investigate") == "investigation"
    assert fetch._lane_of(None, "kibana_write") == "kibana_write"
    assert fetch._lane_of(None, "probe") is None
    assert fetch._lane_of(None, "selftest") is None
    assert fetch._lane_of(None, "something_new") == "unknown"


# --------------------------------------------------------------------------- the table


def test_the_table_has_a_line_a_check_a_detail_and_what_is_needed() -> None:
    report = Report(
        "phase3",
        at(2, 6, 30),
        Window(at(1), at(2)),
        (
            Line(
                3,
                "Production writes",
                (
                    Check("3a", "Sent steps have a row", PASS, "all 4", n=4),
                    Check("3d", "Minimum counts", PENDING, "1 of 3 cases", needs="2 more cases"),
                ),
            ),
        ),
        ("a note",),
    )
    text = "\n".join(render.render(report))
    assert "phase3 gate: 2026-11-01 00:00 to 2026-11-02 00:00 UTC (1.00 days)" in text
    assert re.search(r"^PENDING\s+3  Production writes$", text, re.M)
    assert "PASS     3a  Sent steps have a row [n=4]" in text
    assert "needs: 2 more cases" in text
    assert "PASS 0, FAIL 0, PENDING 1, OPEN 0" in text
    assert "note: a note" in text
    assert "OPEN: only a person can say" in text


def test_a_label_from_the_data_cannot_forge_a_line() -> None:
    check = Check("1a", "t", PASS, "case 3\nPASS     9z  forged\x1b[31m")
    report = Report("phase3", at(2), Window(at(1), at(2)), (Line(1, "x", (check,)),))
    shown = render.render(report)
    assert not any(line.startswith("PASS     9z") for line in shown)
    assert not any("\x1b" in line for line in shown)


# --------------------------------------------------------------------------- the command


def test_the_command_is_under_soak_and_names_its_options() -> None:
    result = runner.invoke(app, ["soak", "phase3", "--help"])
    assert result.exit_code == 0
    for option in ("--since", "--days", "--json", "--write", "--config"):
        assert option in plain(result.output)


def test_a_bad_window_is_a_usage_error_before_any_database_is_touched(
    write_config: Callable[[str], Path],
) -> None:
    config = str(write_config("logging:\n  level: WARNING\n"))
    for args in (["--since", "yesterday"], ["--days", "0"], ["--since", "2099-01-01T00:00:00"],
                 ["--since", "2026-10-30T12:45:00", "--days", "2"]):  # fmt: skip
        result = runner.invoke(app, ["soak", "phase3", "--config", config, *args])
        assert result.exit_code == 2, (args, result.output)
        assert "Traceback" not in result.output


# --------------------------------------------------------------------------- the units


def test_the_timer_runs_daily_at_0630_utc_and_the_service_writes_the_report() -> None:
    timer = (REPO_ROOT / "deploy/systemd/argus-soak-phase3.timer").read_text()
    service = (REPO_ROOT / "deploy/systemd/argus-soak-phase3.service").read_text()
    assert "OnCalendar=*-*-* 06:30:00 UTC" in timer
    assert "Persistent=true" in timer
    assert "ExecStart=@UV@ run argus soak phase3 --write" in service  # a template (D-295)
    assert "[Install]" not in service


def test_the_gate_is_installed_disabled_like_the_other_off_timers() -> None:
    assert units.MANIFEST["argus-soak-phase3.timer"][0] is units.Role.OFF
    assert units.MANIFEST["argus-soak-phase3.service"][0] is units.Role.TRIGGERED
    off = units.UnitState("argus-soak-phase3.timer", units.Role.OFF, "x", True, True, True, True)
    assert units.problems(off) is not None  # enabled before its production step
    quiet = units.UnitState("argus-soak-phase3.timer", units.Role.OFF, "x", True, True, True, False)
    assert units.problems(quiet) is None


def test_the_pure_judges_import_no_database_or_network_module() -> None:
    source = (REPO_ROOT / "src/argus/soakgate/judge.py").read_text()
    for forbidden in ("sqlalchemy", "httpx", "datetime.now", "utcnow", "open(", "Path("):
        assert forbidden not in source, forbidden
    assert judge.MIN_CASES_POSTED == 3
