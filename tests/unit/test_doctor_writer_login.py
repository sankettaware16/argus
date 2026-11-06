"""P4-E3: doctor's writer login, as the case team's unit uses it (D-305's finding: doctor said
"not set up" while the case team failed every run on that login). The login is read with the
unit's own credential and judged only while the installation runs the case team; off is a
choice, so then a login that does not work is a warning. No database here: the checks that need
one stop before connecting, and the rest get a fake ``writer_role_problems`` (the integration
tests log in for real)."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import SecretStr
from sqlalchemy.exc import OperationalError

from argus import doctor
from argus.config.settings import CaseTeamSettings, DatabaseSettings, Settings, UnitsSettings
from argus.config.sources import credentials_layer
from argus.db import roles as db_roles
from argus.doctor import as_the_case_team_runs, writer_login_check
from argus.observability.redaction import redact_text
from argus.ops import case_team_login as team
from argus.ops import custody, units
from argus.ops.case_team_login import TeamLogin

pytestmark = pytest.mark.unit

PASSWORD = "made-up-writer-password-c41e"
SHOWN = "local/creds-writer/database.writer_password"
ON = ("argus-case-team.timer is enabled", "ARGUS_CASE_TEAM__POST is on in local/argus-writer.env")
POSTING = CaseTeamSettings(post=True)
STOPS = (
    "ARGUS_CASE_TEAM__POST=false in local/argus-writer.env, or `systemctl --user disable --now"
    " argus-case-team.timer` and take it out of units.run"
)


def _login(password: str | None = PASSWORD, *, runs: tuple[str, ...] = ON,
           problem: str | None = None, user: str | None = None) -> TeamLogin:  # fmt: skip
    return TeamLogin(password=password, problem=problem, user=user, runs=runs)


@pytest.fixture
def no_database(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_a: object, **_k: object) -> None:
        raise AssertionError("the check connected")

    monkeypatch.setattr(doctor, "create_engine", refuse)


def _problems(monkeypatch: pytest.MonkeyPatch, answer: Callable[[], list[str]]) -> list[str]:
    users: list[str] = []

    async def problems(engine: Any) -> list[str]:
        users.append(engine.url.username)
        return answer()

    monkeypatch.setattr(db_roles, "writer_role_problems", problems)
    return users


def _refused() -> list[str]:
    raise OperationalError(None, None, Exception('password authentication failed for user "x"'))


# --------------------------------------------------------------------------- no password


async def test_a_case_team_set_to_run_without_a_password_fails(no_database: None) -> None:
    result = await writer_login_check(Settings(), _login(None))
    assert result.label == "FAIL"
    assert result.detail == (
        "argus_writer_app: the case team is set to run (argus-case-team.timer is enabled;"
        " ARGUS_CASE_TEAM__POST is on in local/argus-writer.env), but its login has no password:"
        f" put one in {SHOWN} (mode 600) and run `argus init`, which makes the login"
        f" (docs/case-team.md), or stop the case team: {STOPS}"
    )


async def test_a_case_team_that_is_off_without_a_password_passes(no_database: None) -> None:
    result = await writer_login_check(Settings(), _login(None, runs=()))
    assert (result.label, result.detail) == ("PASS", (
        "argus_writer_app is not set up (the writer is off until its canary: put its password in"
        f" {SHOWN} and run `argus init`)"))  # fmt: skip
    plain = await writer_login_check(Settings())  # no unit to read: as before
    assert (plain.label, "run `argus db bootstrap`" in plain.detail) == ("PASS", True)


async def test_a_credential_that_cannot_be_used_fails_only_while_it_runs(no_database: None) -> None:
    running = await writer_login_check(Settings(), _login(None, problem="is empty"))
    assert running.label == "FAIL"
    assert f"{SHOWN} is empty, and the case team is set to run" in running.detail
    off = await writer_login_check(Settings(), _login(None, runs=(), problem="is empty"))
    assert off.label == "PASS"
    assert off.detail.endswith(f"; {SHOWN} is empty")


# --------------------------------------------------------------------------- a password


async def test_the_units_credential_and_login_are_the_ones_checked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    users = _problems(monkeypatch, list)
    result = await writer_login_check(Settings(), _login(user="acme_case_team"))
    assert (result.label, result.detail) == ("PASS", (
        f"acme_case_team: exactly the writer's grants, logs in with {SHOWN}"))  # fmt: skip
    assert users == ["acme_case_team"]
    assert PASSWORD not in redact_text(f"password {PASSWORD}")  # registered for redaction
    off = await writer_login_check(Settings(), _login(runs=()))
    assert off.detail.endswith("(the case team is off)")


async def test_a_login_that_does_not_log_in_fails_while_it_runs_and_names_init(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _problems(monkeypatch, _refused)
    running = await writer_login_check(Settings(), _login())
    assert running.label == "FAIL"
    assert "password authentication failed" in running.detail
    assert running.detail.endswith(
        f" — run `argus init` (it sets the login's password from {SHOWN})"
    )
    off = await writer_login_check(Settings(), _login(runs=()))
    assert off.label == "WARN"
    assert off.detail.startswith(
        "argus_writer_app: the case team is off, and its login does not log in with"
    )
    assert off.detail.endswith(": `argus init` repairs it")


async def test_a_password_given_to_doctor_itself_is_judged_as_before(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Doctor run in the writer's view (its credentials folder in the environment): the person
    asked about this login, so a refusal fails whatever the case team does."""
    _problems(monkeypatch, _refused)
    given = Settings(database=DatabaseSettings(writer_password=SecretStr("given-to-doctor-1")))
    result = await writer_login_check(given, _login(None, runs=()))
    assert result.label == "FAIL"
    assert result.detail.endswith(" — run `argus db bootstrap` to create or repair it")


async def test_a_login_with_the_wrong_grants_fails_while_it_runs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _problems(monkeypatch, lambda: ["is a member of argus_runtime"])
    running = await writer_login_check(Settings(), _login())
    assert running.label == "FAIL"
    assert running.detail == (
        "argus_writer_app: is a member of argus_runtime — run `argus init` to repair the role"
    )
    off = await writer_login_check(Settings(), _login(runs=()))
    assert (off.label, off.detail.startswith("argus_writer_app: the case team is off; is a")) == (
        "WARN", True)  # fmt: skip


async def test_a_database_that_breaks_after_logging_in_is_no_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken() -> list[str]:
        raise OperationalError("SELECT 1", {}, Exception("canceling statement due to timeout"))

    _problems(monkeypatch, broken)
    result = await writer_login_check(Settings(), _login(runs=()))
    assert result.label == "FAIL"  # not a login the case team's choice explains
    assert "argus init" not in result.detail


# --------------------------------------------------------------------------- the unit's view


def _checkout(tmp_path: Path, *, enabled: bool, root: Path | None = None) -> Path:
    """This checkout's units installed in a unit folder, its case-team timer enabled or not."""
    folder = tmp_path / "units"
    folder.mkdir()
    params = units.UnitParams(root or tmp_path / "argus", "/usr/bin/uv")
    for name, text in units.rendered_units(params).items():
        (folder / name).write_text(text)
    if enabled:
        (folder / "timers.target.wants").mkdir()
        (folder / "timers.target.wants" / team.TIMER).symlink_to(folder / team.TIMER)
    return folder


def _view(monkeypatch: pytest.MonkeyPatch, folder: Path, **settings: Any) -> TeamLogin | None:
    monkeypatch.setattr(units, "user_unit_dir", lambda: folder)
    found = as_the_case_team_runs(Settings(**settings))
    return found


def test_the_view_reads_the_units_credential_switches_and_timer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "argus"
    (root / "local" / "creds-writer").mkdir(parents=True)
    (root / "local" / "creds-writer" / "database.writer_password").write_text(PASSWORD + "\n")
    (root / "local" / "argus-writer.env").write_text(
        "ARGUS_CASE_TEAM__POST=true\nARGUS_DATABASE__WRITER_USER=acme_case_team\n"
    )
    folder = _checkout(tmp_path, enabled=True)
    seen = _view(monkeypatch, folder, units=UnitsSettings(root=root))
    assert seen is not None
    assert (seen.password, seen.problem, seen.user) == (PASSWORD, None, "acme_case_team")
    assert seen.runs == (
        "argus-case-team.timer is enabled",
        "ARGUS_CASE_TEAM__POST is on in local/argus-writer.env",
    )
    assert PASSWORD not in repr(seen)


def test_an_enabled_timer_of_another_checkout_does_not_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    folder = _checkout(tmp_path, enabled=True, root=Path("/home/someone/argus"))
    seen = _view(monkeypatch, folder, units=UnitsSettings(root=tmp_path / "argus"))
    assert seen is not None
    assert seen.runs == ()
    listed = _view(
        monkeypatch,
        folder,
        units=UnitsSettings(root=tmp_path / "argus", run=(team.TIMER,)),
        case_team=POSTING,
    )
    assert listed is not None
    assert listed.runs == ("units.run lists argus-case-team.timer", "case_team.post is on")


def _team_checkout(tmp_path: Path, switches: str) -> Path:
    """A checkout whose case-team switches file holds ``switches``, no credential yet."""
    root = tmp_path / "argus"
    (root / "local").mkdir(parents=True)
    (root / "local" / "argus-writer.env").write_text(switches)
    return root


async def test_posting_off_with_the_timer_enabled_is_off(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_database: None
) -> None:
    """The documented gentlest stop: posting off in the unit's own file, the timer left enabled.
    Each run refuses before it logs in, so its login is not judged (no FAIL for a choice)."""
    root = _team_checkout(tmp_path, "ARGUS_CASE_TEAM__POST=false\n")
    folder = _checkout(tmp_path, enabled=True)
    seen = _view(monkeypatch, folder, units=UnitsSettings(root=root, run=(team.TIMER,)),
                 case_team=POSTING)  # fmt: skip
    assert seen is not None
    assert seen.runs == ()  # the unit's file outranks case_team.post in YAML or .env
    result = await writer_login_check(Settings(), seen)
    assert (result.label, result.detail) == ("PASS", (
        "argus_writer_app is not set up (the writer is off until its canary: put its password in"
        f" {SHOWN} and run `argus init`)"))  # fmt: skip


async def test_a_disabled_timer_out_of_units_run_is_off_while_posting_is_on(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The other stop, as init and the runbook advise: the timer disabled and out of units.run,
    the switches file still saying POST=true (production's does). Nothing starts the unit, so a
    missing password passes and a refused login is a warning."""
    root = _team_checkout(tmp_path, "ARGUS_CASE_TEAM__POST=true\n")
    folder = _checkout(tmp_path, enabled=False)
    seen = _view(monkeypatch, folder, units=UnitsSettings(root=root, run=units.CORE))
    assert seen is not None
    assert seen.runs == ()
    missing = await writer_login_check(Settings(), seen)
    assert (missing.label, "is not set up" in missing.detail) == ("PASS", True)
    _problems(monkeypatch, _refused)
    (root / "local" / "creds-writer").mkdir()
    (root / "local" / "creds-writer" / "database.writer_password").write_text(PASSWORD)
    refused = _view(monkeypatch, folder, units=UnitsSettings(root=root, run=units.CORE))
    assert refused is not None
    result = await writer_login_check(Settings(), refused)
    assert result.label == "WARN"
    assert result.detail.startswith("argus_writer_app: the case team is off, and its login")


def test_the_view_is_custodys_under_custody(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(custody, "moved_units", lambda *_a: set(custody.UNITS))
    assert _view(monkeypatch, tmp_path, units=UnitsSettings(root=tmp_path)) is None


# --------------------------------------------------------------------------- the pieces


@pytest.mark.parametrize(
    ("switches", "configured", "posts"),
    [
        ({}, False, False),
        ({}, True, True),  # case_team.post in YAML or .env
        ({team.POST: "true"}, False, True),
        ({team.POST: "false"}, True, False),  # the unit's own file outranks .env and YAML
        ({team.POST: "On"}, False, True),
        ({team.POST: " yes "}, False, True),
        ({team.POST: "maybe"}, True, False),  # the unit cannot load such settings: it posts none
    ],
)
def test_posting_is_the_units_switch(
    switches: dict[str, str], configured: bool, posts: bool
) -> None:
    assert team.posting(switches, configured) is posts


@given(
    run=st.none() | st.lists(st.sampled_from(sorted(units.MANIFEST)), max_size=6),
    enabled=st.sets(st.sampled_from(sorted(units.MANIFEST)), max_size=6),
    post=st.none() | st.sampled_from(["true", "false", "1", "0", "maybe", "TRUE", ""]),
    configured=st.booleans(),
)
def test_the_case_team_runs_exactly_when_something_starts_it_and_it_posts(
    run: list[str] | None, enabled: set[str], post: str | None, configured: bool
) -> None:
    """Either stop is off: nothing starts the unit (its timer neither listed nor enabled), or it
    posts nothing (each run refuses before it logs in). Posting on alone runs nothing."""
    switches = {} if post is None else {team.POST: post}
    found = team.reasons(run, enabled, switches, configured)
    starts = (run is not None and team.TIMER in run) or team.TIMER in enabled
    said = starts and team.posting(switches, configured)
    assert bool(found) is said
    off = team.switched_off(switches, configured)
    assert off is None or not found  # switched off by choice: never set to run
    assert len(found) == len(set(found))
    more = team.reasons([*(run or []), team.TIMER], enabled, switches, configured)
    assert set(found) <= set(more)  # saying more never takes a reason away


@given(st.binary(max_size=80))
def test_the_credential_reads_as_the_units_settings_read_it(content: bytes) -> None:
    """The value doctor and init use is the one the unit's settings load from the same file
    (``credentials_layer``), or there is a reason why neither is usable."""
    from argus.config.errors import ConfigError

    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / team.CREDENTIAL
        path.write_bytes(content)
        value, problem = team.read_credential(path)
        try:
            layer = credentials_layer(Path(directory), Settings)
        except ConfigError:
            layer = None
    loaded = None
    if layer is not None and not layer.problems:
        secret = layer.data.get("database", {}).get("writer_password")
        loaded = None if secret is None else secret.get_secret_value()
    if loaded is not None and "\x00" not in loaded:
        assert (value, problem) == (loaded, None)
    else:
        assert value is None
        assert problem is not None


def test_a_missing_or_odd_credential(tmp_path: Path) -> None:
    assert team.read_credential(tmp_path / "none") == (None, None)
    (tmp_path / "link").symlink_to(tmp_path / "nowhere")
    assert team.read_credential(tmp_path / "link") == (None, None)  # as the unit's settings skip it
    assert team.read_credential(tmp_path) == (None, "is not a regular file")
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    assert team.read_credential(fifo) == (None, "is not a regular file")  # never waits
    big = tmp_path / "big"
    big.write_bytes(b"x" * (team.MAX_BYTES + 1))
    assert team.read_credential(big) == (None, f"is larger than {team.MAX_BYTES // 1024} KiB")


def test_the_unit_view_as_settings_and_environment() -> None:
    login = _login(user="acme_case_team")
    update = login.database_update()
    assert update["writer_user"] == "acme_case_team"
    assert update["writer_password"].get_secret_value() == PASSWORD
    assert login.environment() == {
        "ARGUS_DATABASE__WRITER_PASSWORD": PASSWORD,
        "ARGUS_DATABASE__WRITER_USER": "acme_case_team",
    }
    assert _login(None).environment() == {}
    assert _login(None).database_update() == {}


async def test_a_login_name_its_switches_cannot_have_is_named(no_database: None) -> None:
    running = await writer_login_check(Settings(), _login(user="argus_app"))
    assert running.label == "FAIL"
    assert running.detail.startswith("argus_app: database.writer_user must be a role of its own")
    off = await writer_login_check(Settings(), _login(user="argus_app", runs=()))
    assert off.label == "WARN"


def test_an_unreadable_unit_folder_counts_no_timer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unreadable(*_a: object) -> Path:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(units, "installed_root", unreadable)
    seen = _view(monkeypatch, tmp_path, units=UnitsSettings(root=tmp_path, run=(team.TIMER,)),
                 case_team=POSTING)  # fmt: skip
    assert seen is not None
    assert seen.runs == ("units.run lists argus-case-team.timer", "case_team.post is on")
