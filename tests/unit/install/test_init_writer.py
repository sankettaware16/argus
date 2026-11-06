"""P4-E3: ``argus init`` and the case team's own database login (D-305's finding: a fresh
database never got the login its copied credential names, and the case team failed every run).
A credential whose login is missing or has another password is set on the login; one that logs in
is left alone, so a second run changes nothing; a case team set to run without one is told what to
do; nothing is done for a case team that is off. The database is faked here (the integration tests
use a throwaway one)."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

import pytest
import yaml

from argus.install.answers import InitError, ScriptedAnswers
from argus.ops import units
from tests.unit.install.test_run import Run

pytestmark = pytest.mark.unit

PASSWORD = "made-up-writer-password-7f3a"
SHOWN = "local/creds-writer/database.writer_password"
POSTING = "ARGUS_CASE_TEAM__POST is on in local/argus-writer.env"
STOPS = (
    "ARGUS_CASE_TEAM__POST=false in local/argus-writer.env, or `systemctl --user disable --now"
    " argus-case-team.timer` and take it out of units.run"
)


def _credential(run: Run, value: str = PASSWORD) -> Path:
    folder = run.root / "local" / "creds-writer"
    folder.mkdir(parents=True, exist_ok=True)
    folder.chmod(0o700)
    path = folder / "database.writer_password"
    path.write_text(value)
    path.chmod(0o600)
    return path


def _switches(run: Run, text: str) -> None:
    path = run.root / "local" / "argus-writer.env"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(0o600)


class _Seen:
    """What each bootstrap saw of the writer's login in its environment."""

    def __init__(self, run: Run) -> None:
        self.calls: list[tuple[str | None, str | None]] = []
        self._run = run.bootstrap

        def spy(config: Path) -> None:
            self.calls.append((os.environ.get("ARGUS_DATABASE__WRITER_PASSWORD"),
                               os.environ.get("ARGUS_DATABASE__WRITER_USER")))  # fmt: skip
            self._run(config)

        run.bootstrap = spy


def _again(run: Run, tmp_path: Path) -> int:
    return run.go(ScriptedAnswers({}, tmp_path / "empty.yml"))


def test_a_copied_credential_makes_the_missing_login_and_a_rerun_keeps_it(tmp_path: Path) -> None:
    run = Run(tmp_path)
    _credential(run, PASSWORD + "\n")  # as `openssl rand -hex 32 >` writes it
    seen = _Seen(run)
    assert run.go(run.answers()) == 0, run.text
    assert run.writers == {"argus_writer_app": PASSWORD}  # the final line break is not part of it
    assert seen.calls == [(None, None), (PASSWORD, None)]  # the services', then the writer's
    assert run.db == ["bootstrap", "upgrade", "bootstrap"]
    assert (
        f"the case team's login: repaired from {SHOWN} (argus_writer_app did not log in" in run.text
    )
    assert PASSWORD not in run.text
    assert "ARGUS_DATABASE__WRITER_PASSWORD" not in os.environ
    run.db.clear()
    seen.calls.clear()
    assert _again(run, tmp_path) == 0, run.text
    assert seen.calls == [(None, None)]  # the login logs in: its password is not set again
    assert run.db == ["bootstrap", "upgrade"]
    assert f"the case team's login: kept (argus_writer_app logs in with {SHOWN})" in run.text


def test_a_login_with_another_password_is_set_from_the_credential(tmp_path: Path) -> None:
    run = Run(tmp_path)
    _credential(run)
    run.writers["argus_writer_app"] = "the-old-machines-password"
    assert run.go(run.answers()) == 0, run.text
    assert run.writers == {"argus_writer_app": PASSWORD}
    assert "the case team's login: repaired from" in run.text


def test_the_login_its_switches_name_is_the_one_made(tmp_path: Path) -> None:
    run = Run(tmp_path)
    _credential(run)
    _switches(run, "ARGUS_CASE_TEAM__POST=true\nARGUS_DATABASE__WRITER_USER=acme_case_team\n")
    seen = _Seen(run)
    assert run.go(run.answers()) == 0, run.text
    assert seen.calls[-1] == (PASSWORD, "acme_case_team")
    assert run.writers == {"acme_case_team": PASSWORD}
    assert "ARGUS_DATABASE__WRITER_USER" not in os.environ


def _listed(run: Run) -> None:
    (run.root / "config" / "local.yaml").write_text(
        yaml.safe_dump({"units": {"run": [*units.CORE, "argus-case-team.timer"]}})
    )


def _enabled(run: Run, tmp_path: Path) -> None:
    assert run.go(run.answers()) == 0, run.text  # installs the units of this checkout
    wants = run.units / "timers.target.wants"
    wants.mkdir()
    (wants / "argus-case-team.timer").symlink_to(run.units / "argus-case-team.timer")


def _runs_by_units_run(run: Run, tmp_path: Path) -> int:
    _listed(run)
    _switches(run, "ARGUS_CASE_TEAM__POST=true\n")
    return run.go(run.answers())


def _runs_by_an_enabled_timer(run: Run, tmp_path: Path) -> int:
    _enabled(run, tmp_path)
    _switches(run, "ARGUS_CASE_TEAM__POST=true\n")
    return _again(run, tmp_path)


@pytest.mark.parametrize(
    ("set_up", "why"),
    [
        (_runs_by_units_run, f"units.run lists argus-case-team.timer; {POSTING}"),
        (_runs_by_an_enabled_timer, f"argus-case-team.timer is enabled; {POSTING}"),
    ],
)
def test_a_case_team_set_to_run_without_a_credential_is_told_what_to_do(
    tmp_path: Path, set_up: object, why: str
) -> None:
    run = Run(tmp_path)
    assert callable(set_up)
    assert set_up(run, tmp_path) == 0, run.text
    assert (
        f"warn: the case team is set to run ({why}), but its database login has no password:"
        f" `umask 077; openssl rand -hex 32 > {SHOWN}`, then argus init again (it makes the"
        f" login); or stop it: {STOPS}" in run.text
    )
    assert run.writers == {}
    assert run.db[-2:] == ["bootstrap", "upgrade"]  # no bootstrap for the writer


def _posting_on_alone(run: Run, tmp_path: Path) -> int:
    """The stop init advises: the timer neither listed nor enabled; the switches file still
    says POST=true (production's does)."""
    _switches(run, "ARGUS_CASE_TEAM__POST=true\n")
    return run.go(run.answers())


def _listed_posting_off(run: Run, tmp_path: Path) -> int:
    _listed(run)
    _switches(run, "ARGUS_CASE_TEAM__POST=false\n")
    return run.go(run.answers())


def _enabled_posting_off(run: Run, tmp_path: Path) -> int:
    """The documented gentlest stop: posting off, the timer left enabled (its runs refuse)."""
    _enabled(run, tmp_path)
    _switches(run, "ARGUS_CASE_TEAM__POST=false\n")
    return _again(run, tmp_path)


@pytest.mark.parametrize("set_up", [_posting_on_alone, _listed_posting_off, _enabled_posting_off])
def test_a_stopped_case_team_without_a_credential_is_left_alone(
    tmp_path: Path, set_up: object
) -> None:
    """Either stop is off, for init as for doctor: nothing starts the unit, or it posts nothing
    and each run refuses before it logs in."""
    run = Run(tmp_path)
    assert callable(set_up)
    assert set_up(run, tmp_path) == 0, run.text
    assert "case team" not in run.text
    assert run.writers == {}


def test_a_case_team_that_is_off_without_a_credential_is_left_alone(tmp_path: Path) -> None:
    run = Run(tmp_path)
    _switches(run, "ARGUS_CASE_TEAM__POST=false\n")
    assert run.go(run.answers()) == 0, run.text
    assert "case team" not in run.text
    assert run.db == ["bootstrap", "upgrade"]


def test_an_enabled_timer_of_another_checkout_is_not_this_ones(tmp_path: Path) -> None:
    run = Run(tmp_path)
    run.units.mkdir()
    other = units.UnitParams(Path("/home/someone/argus"), "/usr/bin/uv")
    for name, text in units.rendered_units(other).items():
        (run.units / name).write_text(text)
    wants = run.units / "timers.target.wants"
    wants.mkdir()
    (wants / "argus-case-team.timer").symlink_to(run.units / "argus-case-team.timer")
    assert run.go(run.answers()) == 0, run.text
    assert "the case team is set to run" not in run.text


@pytest.mark.parametrize(
    ("content", "problem"),
    [("", "is empty"), ("\n", "is empty"), ("a\x00b", "must not contain a NUL character")],
)
def test_a_credential_that_cannot_be_used_is_named_never_set(
    tmp_path: Path, content: str, problem: str
) -> None:
    run = Run(tmp_path)
    _credential(run, content)
    assert run.go(run.answers()) == 0, run.text
    assert f"warn: {SHOWN} {problem}" in run.text
    assert run.writers == {}
    assert run.db == ["bootstrap", "upgrade"]


def test_a_login_name_that_cannot_be_made_is_named(tmp_path: Path) -> None:
    run = Run(tmp_path)
    _credential(run)
    _switches(run, "ARGUS_DATABASE__WRITER_USER=argus_app\n")  # the services' own login
    assert run.go(run.answers()) == 0, run.text
    assert "warn: the case team's login cannot be made: database.writer_user must be a role" in (
        run.text
    )
    assert run.db == ["bootstrap", "upgrade"]


def test_a_login_that_still_does_not_work_is_a_warning(tmp_path: Path) -> None:
    run = Run(tmp_path)
    _credential(run)
    run.writer_login = lambda _database: "did not log in (the server refused it)"
    assert run.go(run.answers()) == 0, run.text  # doctor (faked here) fails it
    assert (
        "warn: the case team's login: argus_writer_app did not log in (the server refused it),"
        f" even after `argus db bootstrap` set it from {SHOWN}" in run.text
    )


def test_the_environment_is_put_back_when_the_bootstrap_fails(tmp_path: Path) -> None:
    run = Run(tmp_path)
    _credential(run)
    calls: list[int] = []

    def bootstrap(_config: Path) -> None:
        calls.append(1)
        if len(calls) == 2:  # the writer's
            raise InitError("`argus db bootstrap` failed (the error is above)")

    run.bootstrap = bootstrap
    before = os.environ.get("CREDENTIALS_DIRECTORY")
    assert run.go(run.answers()) == 1
    assert "error: `argus db bootstrap` failed" in run.text
    assert "ARGUS_DATABASE__WRITER_PASSWORD" not in os.environ
    assert os.environ.get("CREDENTIALS_DIRECTORY") == before
    assert PASSWORD not in run.text


def test_the_writers_bootstrap_sees_the_webs_credentials_too(tmp_path: Path) -> None:
    run = Run(tmp_path)
    _credential(run)
    web = run.root / "local" / "creds-web"
    web.mkdir(parents=True)
    (web / "database.api_password").write_text("made-up-web-password\n")
    (run.root / "config" / "local.yaml").write_text(
        yaml.safe_dump({"units": {"web": {"credentials": str(web)}}})
    )
    (run.root / ".env").write_text("ARGUS_DATABASE__PASSWORD=made-up-runtime-password\n")
    folders: list[str | None] = []
    original = run.bootstrap

    def bootstrap(config: Path) -> None:
        folders.append(os.environ.get("CREDENTIALS_DIRECTORY"))
        original(config)

    run.bootstrap = bootstrap
    assert run.go(run.answers()) == 0, run.text
    assert folders == [str(web), str(web)]  # the web's login is never left out of a bootstrap


def test_a_writer_password_in_the_shared_env_is_named(tmp_path: Path) -> None:
    """The unit uses its credential; a different password in .env would make every bootstrap
    set the login back to it."""
    run = Run(tmp_path)
    assert run.go(run.answers()) == 0, run.text
    _credential(run)
    with (run.root / ".env").open("a") as env:
        env.write("ARGUS_DATABASE__WRITER_PASSWORD=made-up-shared-password\n")
    assert _again(run, tmp_path) == 0, run.text
    assert (
        "warn: ARGUS_DATABASE__WRITER_PASSWORD (.env or the environment) is not the password in"
        f" {SHOWN}, which the case team uses: remove it from .env" in run.text
    )
    assert run.writers == {"argus_writer_app": PASSWORD}  # the unit's own password, still
    assert "made-up-shared-password" not in run.text


def test_a_writer_password_in_the_shared_env_never_replaces_the_credentials(
    tmp_path: Path,
) -> None:
    """With another writer password in .env, the first bootstrap of step 3 would set that one
    and lock the case team out for the whole upgrade (a dump first), and every rerun would say
    "repaired". It gets the unit's own instead: the login is never set to .env's value, the
    first init says repaired (it did not log in before), a rerun says kept."""
    run = Run(tmp_path)
    assert run.go(run.answers()) == 0, run.text
    with (run.root / ".env").open("a") as env:
        env.write("ARGUS_DATABASE__WRITER_PASSWORD=made-up-shared-password\n")
    _credential(run)
    passwords: list[str | None] = []  # the login's password after each bootstrap, and during
    bootstrap, upgrade = run.bootstrap, run.upgrade  # the upgrade (a dump first: minutes)

    def watched(step: Callable[[Path], None]) -> Callable[[Path], None]:
        def done(config: Path) -> None:
            step(config)
            passwords.append(run.writers.get("argus_writer_app"))

        return done

    run.bootstrap, run.upgrade = watched(bootstrap), watched(upgrade)
    for said in ("repaired from", "kept"):
        run.db.clear()
        passwords.clear()
        assert _again(run, tmp_path) == 0, run.text
        assert passwords == [PASSWORD, PASSWORD], said  # never .env's, not even for a while
        assert run.db == ["bootstrap", "upgrade"]
        assert f"the case team's login: {said} " in run.text
        assert "made-up-shared-password" not in run.text
    assert "(argus_writer_app logs in with" in run.text
