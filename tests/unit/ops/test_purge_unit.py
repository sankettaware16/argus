"""The retention purge's pure parts (Q-A4): cutoffs (never shorter than history.window), the
plan's counts and file, the drill check, and the settings (D-028)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from argus.config.durations import format_duration
from argus.config.settings import MemorySettings, RetentionSettings, Settings, load_settings
from argus.ops import purge
from argus.ops.purge import CLASSES, ITEMS, Counts, PurgeError
from argus.ops.purge_cli import _plan_json, check_drill, read_plan
from tests.conftest import REPO_ROOT

AT = datetime(2026, 10, 10, 22, 30, tzinfo=UTC)
DAYS = st.integers(1, 365).map(lambda n: timedelta(days=n))


def _settings(**sections: object) -> Settings:
    return Settings(**sections)  # type: ignore[arg-type]


def test_d028s_periods_are_the_defaults_and_in_the_shipped_config() -> None:
    settings = load_settings(REPO_ROOT / "config" / "argus.yaml", env_file=None)
    assert settings.memory.window == timedelta(days=90)
    retention = settings.retention
    assert (retention.raw_source, retention.evidence, retention.quarantine, retention.app_logs) == (
        timedelta(days=30), timedelta(days=90), timedelta(days=30), timedelta(days=14),
    )  # fmt: skip
    assert retention.scheduled is False  # the schedule is the user's (D-109)
    assert Settings().memory == settings.memory
    assert Settings().retention == settings.retention


@pytest.mark.parametrize(
    ("model", "field", "smallest", "largest", "beyond"),
    [
        (MemorySettings, "window", "1d", "3650d", ("23h", "3651d")),
        (RetentionSettings, "raw_source", "1d", "365d", ("23h", "366d")),
        (RetentionSettings, "evidence", "1d", "3650d", ("23h", "3651d")),
        (RetentionSettings, "quarantine", "1d", "365d", ("23h", "366d")),
        (RetentionSettings, "app_logs", "1d", "365d", ("23h", "366d")),
    ],
)
def test_the_periods_have_exact_bounds(
    model: type, field: str, smallest: str, largest: str, beyond: tuple[str, ...]
) -> None:
    for value in (smallest, largest):
        assert getattr(model(**{field: value}), field) > timedelta(0)
    for value in beyond:
        with pytest.raises(ValidationError, match=field):
            model(**{field: value})


def test_a_period_is_set_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ARGUS_MEMORY__WINDOW", "120d")
    monkeypatch.setenv("ARGUS_RETENTION__SCHEDULED", "true")
    settings = load_settings(REPO_ROOT / "config" / "argus.yaml", env_file=None)
    assert settings.memory.window == timedelta(days=120)
    assert settings.retention.scheduled is True


def test_a_misspelt_period_is_refused(tmp_path: Path) -> None:
    config = tmp_path / "argus.yaml"
    config.write_text("retention:\n  raw: 30d\n")
    with pytest.raises(Exception, match=r"retention\.raw"):
        load_settings(config, env_file=None)


@given(
    history=st.integers(1, 365 * 24).map(lambda n: timedelta(hours=n)),
    raw=DAYS,
    quarantine=DAYS,
    evidence=DAYS,
    memory=DAYS,
)
def test_no_cutoff_is_younger_than_history_window(
    history: timedelta,
    raw: timedelta,
    quarantine: timedelta,
    evidence: timedelta,
    memory: timedelta,
) -> None:
    settings = _settings(
        history={"window": history},
        memory={"window": memory},
        retention={"raw_source": raw, "quarantine": quarantine, "evidence": evidence},
    )
    cut = purge.cutoffs(settings, AT)
    configured = {"raw_source": raw, "quarantine": quarantine, "evidence": evidence,
                  "memory": memory}  # fmt: skip
    for name, period in configured.items():
        assert getattr(cut, name) == AT - max(period, history)
        assert getattr(cut, name) <= AT - history
        assert cut.periods[name] == max(period, history)
        assert (name in cut.extended) == (period < history)
    assert cut.params()["at"] == AT
    assert cut.params()["memory_cut"] == cut.memory


def test_cutoffs_need_an_aware_time() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        purge.cutoffs(Settings(), datetime(2026, 11, 10, 22, 30))  # noqa: DTZ001 - the point


def _counts(n: int = 0) -> Counts:
    counts = Counts()
    for name in CLASSES:
        for k, item in enumerate(ITEMS[name]):
            counts.changed[name][item] = n + k
        counts.held[name] = n
    counts.waiting = n + 7
    return counts


def test_counts_round_trip_and_differences() -> None:
    planned = _counts(1)
    assert Counts.from_json(json.loads(json.dumps(planned.as_json()))).as_json() == (
        planned.as_json()
    )
    assert purge.differences(planned, planned) == []
    done = _counts(1)
    done.changed["memory"]["signals"] += 1
    assert purge.differences(planned, done) == [
        f"memory.signals: planned {planned.changed['memory']['signals']},"
        f" done {done.changed['memory']['signals']}"
    ]
    assert Counts().total() == 0
    assert _counts(0).total() == sum(k for c in CLASSES for k in range(len(ITEMS[c])))


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda d: d.pop("held"), "not a purge plan's counts"),
        (lambda d: d["changed"].pop("memory"), "counts for memory are not this ARGUS's"),
        (lambda d: d["changed"]["memory"].pop("signals"), "counts for memory are not"),
        (lambda d: d["changed"]["evidence"].update({"x": 1}), "counts for evidence are not"),
        (lambda d: d["changed"]["raw_source"].update({"alert_records.raw": -1}), "not a count"),
        (lambda d: d["changed"]["raw_source"].update({"alert_records.raw": True}), "not a count"),
        (lambda d: d["changed"]["raw_source"].update({"alert_records.raw": "3"}), "not a count"),
        (lambda d: d["held"].update({"memory": -2}), "held count for memory"),
        (lambda d: d["held"].pop("quarantine"), "held count for quarantine"),
        (lambda d: d.pop("waiting"), "waiting count is not a count"),
        (lambda d: d.update({"waiting": -1}), "waiting count is not a count"),
        (lambda d: d.update({"waiting": False}), "waiting count is not a count"),
    ],
)
def test_a_damaged_plan_is_refused(change: object, message: str) -> None:
    data = _counts(2).as_json()
    change(data)  # type: ignore[operator]
    with pytest.raises(ValueError, match=message):
        Counts.from_json(data)


def test_the_lines_say_every_class_and_why_a_period_was_lengthened() -> None:
    settings = _settings(history={"window": "40d"})
    cut = purge.cutoffs(settings, AT)
    shown = purge.lines(_counts(0), cut, timedelta(days=14))
    assert shown[0] == f"purge at {AT.isoformat()} (rows older than each period go, unless held)"
    assert shown[1].startswith("  raw_source (40d (history.window: never shorter)): nothing;")
    assert "kept by holds: 0" in shown[1]
    assert shown[3] == "  evidence (90d): nothing; kept by holds: 0"
    assert "kept by holds or case records" in shown[4]
    assert shown[4].endswith("; waiting on unfinished work (jobs, assessments, write-backs): 7")
    assert shown[5].startswith("  app_logs (14d): the systemd journal")
    # review A4-R10: what is never purged is said, entity notes among it
    assert shown[6] == "  never purged in Phase 3: the audit trail, case records, entity notes"
    assert shown[-1] == f"  total rows changed: {_counts(0).total()}"


# --------------------------------------------------------------------------- the plan file


def _plan(tmp_path: Path, settings: Settings, **over: object) -> Path:
    data = _plan_json(purge.cutoffs(settings, AT), _counts(3), settings.database.name)
    data.update(over)
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(data))
    return path


def test_a_reviewed_plan_gives_its_own_time_and_counts(tmp_path: Path) -> None:
    settings = Settings()
    cut, counts = read_plan(_plan(tmp_path, settings), settings)
    assert cut.at == AT
    assert cut == purge.cutoffs(settings, AT)
    assert counts.as_json() == _counts(3).as_json()


@pytest.mark.parametrize(
    ("over", "message"),
    [
        ({"format": 1}, "is not a purge plan"),
        ({"database": "other"}, "a plan of another database"),
        ({"at": "2026-10-10T22:30:00"}, "its time has no zone"),
        ({"at": "soon"}, "Invalid isoformat|plan.json"),
        ({"at": "2999-01-01T00:00:00+00:00"}, "its time is in the future"),
        ({"periods": {"raw_source": "31d"}}, "other retention periods"),
        ({"counts": {"changed": {}}}, "not a purge plan's counts"),
    ],
)
def test_a_plan_that_is_not_this_ones_is_refused(
    tmp_path: Path, over: dict[str, object], message: str
) -> None:
    settings = Settings()
    with pytest.raises(PurgeError, match=message):
        read_plan(_plan(tmp_path, settings, **over), settings)


def test_an_unreadable_plan_is_refused(tmp_path: Path) -> None:
    (tmp_path / "plan.json").write_text("{not json")
    with pytest.raises(PurgeError, match=r"cannot read the plan plan\.json"):
        read_plan(tmp_path / "plan.json", Settings())
    with pytest.raises(PurgeError, match=r"cannot read the plan missing\.json"):
        read_plan(tmp_path / "missing.json", Settings())
    (tmp_path / "list.json").write_text("[]")
    with pytest.raises(PurgeError, match="is not a purge plan"):
        read_plan(tmp_path / "list.json", Settings())


def test_a_plan_made_while_history_window_lengthened_a_period(tmp_path: Path) -> None:
    longer = _settings(history={"window": "40d"})
    path = _plan(tmp_path, longer)
    assert read_plan(path, longer)[0].periods["raw_source"] == timedelta(days=40)
    with pytest.raises(PurgeError, match="other retention periods"):
        read_plan(path, Settings())  # history.window back at 5d: raw_source is 30d again


# --------------------------------------------------------------------------- the drill


def _drills(base: Path, *records: dict[str, object]) -> None:
    base.joinpath("drills.jsonl").write_text("".join(json.dumps(r) + "\n" for r in records))


def test_a_purge_needs_a_recent_passed_drill(tmp_path: Path) -> None:
    now = AT
    day = timedelta(days=1)
    with pytest.raises(PurgeError, match="no restore drill has run"):
        check_drill(tmp_path, now, day)
    _drills(tmp_path, {"at": (now - timedelta(hours=2)).isoformat(), "passed": True, "dump": "d"})
    assert check_drill(tmp_path, now, day) == f"d at {(now - timedelta(hours=2)).isoformat()}"
    _drills(tmp_path, {"at": (now - timedelta(hours=2)).isoformat(), "passed": True},
            {"at": (now - timedelta(hours=1)).isoformat(), "passed": False})  # fmt: skip
    with pytest.raises(PurgeError, match="the last restore drill failed"):
        check_drill(tmp_path, now, day)
    _drills(tmp_path, {"at": (now - day - timedelta(seconds=1)).isoformat(), "passed": True})
    with pytest.raises(PurgeError, match=f"older than {format_duration(day)}"):
        check_drill(tmp_path, now, day)
    _drills(tmp_path, {"at": (now - day).isoformat(), "passed": True, "dump": "d"})
    assert check_drill(tmp_path, now, day).startswith("d at")  # exactly a day: still fresh
    _drills(tmp_path, {"at": "2026-10-10T20:00:00", "passed": True})
    with pytest.raises(PurgeError, match="older than"):
        check_drill(tmp_path, now, day)  # a time without a zone proves nothing
    _drills(tmp_path, {"at": "never", "passed": True})
    with pytest.raises(PurgeError, match="has no time"):
        check_drill(tmp_path, now, day)
    _drills(tmp_path, {"at": now.isoformat(), "passed": "yes"})
    with pytest.raises(PurgeError, match="failed"):
        check_drill(tmp_path, now, day)


def test_a_drill_dated_in_the_future_is_not_fresh(tmp_path: Path) -> None:
    """Review A4-R7: a clock stepped back, or an edited drills.jsonl, proves no backup."""
    now, day = AT, timedelta(days=1)
    _drills(tmp_path, {"at": (now + timedelta(days=30)).isoformat(), "passed": True})
    with pytest.raises(PurgeError, match="dated in the future"):
        check_drill(tmp_path, now, day)
    _drills(tmp_path, {"at": (now + timedelta(minutes=5, seconds=1)).isoformat(), "passed": True})
    with pytest.raises(PurgeError, match="dated in the future"):
        check_drill(tmp_path, now, day)
    # a few minutes of skew between the drill's clock and this one: still believed
    _drills(tmp_path, {"at": (now + timedelta(minutes=5)).isoformat(), "passed": True, "dump": "d"})
    assert check_drill(tmp_path, now, day).startswith("d at")
