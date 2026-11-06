"""P4-E3 in the database: ``argus init`` sets the case team's login from its credential file when
the login is missing or has another password (D-305: a fresh database never got it, and the case
team failed every run), a second init leaves it alone, and doctor judges the login as the case
team's unit uses it. Each test uses throwaway logins on a throwaway database; the runtime login is
a throwaway one too, never the configured one."""

from __future__ import annotations

import asyncio
import secrets
from collections.abc import Awaitable, Callable
from pathlib import Path

import pytest
from psycopg import sql
from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.config import DatabaseSettings
from argus.config.settings import Settings
from argus.db import roles
from argus.db.engine import create_engine
from argus.doctor import writer_login_check
from argus.install.answers import ScriptedAnswers
from argus.install.run import Host, Init, Options
from argus.ops.case_team_login import TeamLogin
from tests.conftest import env_copy, hide_in_reports, suite_checkout
from tests.integration.conftest import admin_connect

pytestmark = pytest.mark.integration
MakeLogin = Callable[[], Awaitable[DatabaseSettings]]
SHOWN = "local/creds-writer/database.writer_password"
RUNS = ("argus-case-team.timer is enabled",)


def _password() -> str:
    made = f"made-up-{secrets.token_urlsafe(18)}"
    hide_in_reports(made)
    return made


class Checkout:
    """A checkout of the suite's site whose case team logs in as ``writer`` with ``password``
    (its credential file), on the throwaway database, with a throwaway runtime login."""

    def __init__(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        runtime: DatabaseSettings,
        writer: str,
        password: str,
    ) -> None:
        self.root = suite_checkout(tmp_path / "argus")
        env_copy(self.root, without=frozenset({
            "ARGUS_DATABASE__API_PASSWORD", "ARGUS_DATABASE__WRITER_PASSWORD",
            "ARGUS_DATABASE__WRITER_USER"}))  # fmt: skip
        monkeypatch.chdir(self.root)  # init's own commands read the .env where it runs
        assert runtime.password is not None
        monkeypatch.setenv("ARGUS_DATABASE__NAME", runtime.name)
        monkeypatch.setenv("ARGUS_DATABASE__USER", runtime.user)
        monkeypatch.setenv("ARGUS_DATABASE__PASSWORD", runtime.password.get_secret_value())
        local = self.root / "local"
        (local / "creds-writer").mkdir(parents=True, mode=0o700)
        credential = local / "creds-writer" / "database.writer_password"
        credential.write_text(password + "\n")
        credential.chmod(0o600)
        switches = local / "argus-writer.env"
        switches.write_text(f"ARGUS_CASE_TEAM__POST=true\nARGUS_DATABASE__WRITER_USER={writer}\n")
        switches.chmod(0o600)
        self.said: list[str] = []
        self.tmp = tmp_path

    async def init(self, upgrade: Callable[[Path], None] = lambda _c: None) -> str:
        """``argus init``'s database step (the database is at head already: ``upgrade`` stands
        for the upgrade)."""
        self.said.clear()
        options = Options(root=self.root, config=self.root / "config" / "argus.yaml",
                          compose=False)  # fmt: skip
        host = Host(say=self.said.append, unit_dir=self.tmp / "units", upgrade=upgrade)
        step = Init(options, ScriptedAnswers({}, self.tmp / "answers.yml"), host)
        await asyncio.to_thread(step.database)  # its commands run their own event loops
        return "\n".join(self.said)


async def _logs_in(login: DatabaseSettings) -> list[str]:
    engine = create_engine(login, role="writer")
    try:
        return await roles.writer_role_problems(engine)
    finally:
        await engine.dispose()


async def _writer_bootstraps(engine: AsyncEngine) -> int:
    async with engine.connect() as conn:
        found = await conn.scalar(
            text(
                "SELECT count(*) FROM audit_events WHERE action = 'db.bootstrap'"
                " AND details ? 'writer_login'"
            )
        )
    return int(found or 0)


async def test_init_sets_a_login_with_another_password_and_a_rerun_keeps_it(
    make_login: MakeLogin, make_writer_login: MakeLogin, migrated_engine: AsyncEngine,
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    runtime = await make_login()
    old = await make_writer_login()  # the login exists, with the old machine's password
    password = _password()
    checkout = Checkout(tmp_path, monkeypatch, runtime, old.writer_user, password)
    said = await checkout.init()
    assert f"the case team's login: repaired from {SHOWN} ({old.writer_user} did not log in" in (
        said
    )
    assert password not in said
    now = old.model_copy(update={"writer_password": SecretStr(password)})
    assert await _logs_in(now) == []  # exactly the writer's grants, with the file's password
    with pytest.raises(OperationalError, match="password authentication failed"):
        await _logs_in(old)
    assert await _writer_bootstraps(migrated_engine) == 1
    again = await checkout.init()
    assert f"the case team's login: kept ({old.writer_user} logs in with {SHOWN})" in again
    assert await _writer_bootstraps(migrated_engine) == 1  # nothing set the second time


async def test_init_makes_a_login_the_database_does_not_have(
    make_login: MakeLogin, make_writer_login: MakeLogin, migrated_engine: AsyncEngine,
    db_settings: DatabaseSettings, test_database: str, tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    runtime = await make_login()
    gone = await make_writer_login()  # its name, dropped again: the fixture still cleans it up
    with admin_connect(db_settings, test_database) as conn:
        conn.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(gone.writer_user)))
        conn.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(gone.writer_user)))
    password = _password()
    checkout = Checkout(tmp_path, monkeypatch, runtime, gone.writer_user, password)
    said = await checkout.init()
    assert "the case team's login: repaired from" in said, said
    made = gone.model_copy(update={"writer_password": SecretStr(password)})
    assert await _logs_in(made) == []
    assert "kept" in await checkout.init()


async def test_init_gives_back_a_membership_the_login_lost(
    make_login: MakeLogin, make_writer_login: MakeLogin, migrated_engine: AsyncEngine,
    db_settings: DatabaseSettings, test_database: str, tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    """It logs in with the right password but is no longer a member of argus_writer: the case
    team would log in and be refused every table. Bootstrap repairs that, so init does."""
    runtime = await make_login()
    login = await make_writer_login()
    assert login.writer_password is not None
    password = login.writer_password.get_secret_value()
    with admin_connect(db_settings, test_database) as conn:
        conn.execute(sql.SQL("REVOKE {} FROM {}").format(
            sql.Identifier(roles.WRITER_ROLE), sql.Identifier(login.writer_user)))  # fmt: skip
    assert "does not inherit the privileges of argus_writer" in await _logs_in(login)
    checkout = Checkout(tmp_path, monkeypatch, runtime, login.writer_user, password)
    said = await checkout.init()
    assert (
        f"repaired from {SHOWN} ({login.writer_user} does not inherit the privileges of"
        " argus_writer)" in said
    )
    assert await _logs_in(login) == []


async def test_another_writer_password_in_env_never_reaches_the_login(
    make_login: MakeLogin, make_writer_login: MakeLogin, migrated_engine: AsyncEngine,
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    """A stale ARGUS_DATABASE__WRITER_PASSWORD in .env: the database step's first bootstrap
    would set it, lock the case team out for the whole upgrade (a dump first), and every init
    would say repaired. That bootstrap gets the unit's credential instead: the login logs in with
    it during the upgrade, both inits say kept, and .env's password never logs in."""
    for name in ("ARGUS_DATABASE__WRITER_PASSWORD", "ARGUS_DATABASE__WRITER_USER"):
        monkeypatch.delenv(name, raising=False)
    runtime = await make_login()
    login = await make_writer_login()  # it logs in with its credential already
    assert login.writer_password is not None
    password = login.writer_password.get_secret_value()
    checkout = Checkout(tmp_path, monkeypatch, runtime, login.writer_user, password)
    stale = _password()
    with (checkout.root / ".env").open("a") as env:  # the throwaway login, never the default one
        env.write(f"ARGUS_DATABASE__WRITER_USER={login.writer_user}\n")
        env.write(f"ARGUS_DATABASE__WRITER_PASSWORD={stale}\n")
    during: list[list[str]] = []

    def upgrade(_config: Path) -> None:
        during.append(asyncio.run(_logs_in(login)))  # refused: OperationalError, init stops

    for _ in range(2):
        said = await checkout.init(upgrade)
        assert f"the case team's login: kept ({login.writer_user} logs in with {SHOWN})" in said
        assert f"is not the password in {SHOWN}, which the case team uses" in said
        assert stale not in said
        assert password not in said
    assert during == [[], []]
    assert await _logs_in(login) == []
    with pytest.raises(OperationalError, match="password authentication failed"):
        await _logs_in(login.model_copy(update={"writer_password": SecretStr(stale)}))


async def test_doctor_judges_the_login_as_the_case_team_uses_it(
    make_writer_login: MakeLogin, migrated_engine: AsyncEngine
) -> None:
    login = await make_writer_login()
    assert login.writer_password is not None
    right = login.writer_password.get_secret_value()
    shared = Settings(database=login.model_copy(update={"writer_password": None}))

    def team(password: str, runs: tuple[str, ...] = RUNS) -> TeamLogin:
        return TeamLogin(password=password, problem=None, user=None, runs=runs)

    ok = await writer_login_check(shared, team(right))
    assert ok.label == "PASS"
    assert ok.detail == f"{login.writer_user}: exactly the writer's grants, logs in with {SHOWN}"
    wrong = _password()
    refused = await writer_login_check(shared, team(wrong))
    assert refused.label == "FAIL"
    assert "password authentication failed" in refused.detail
    assert refused.detail.endswith(f"run `argus init` (it sets the login's password from {SHOWN})")
    assert wrong not in refused.detail
    off = await writer_login_check(shared, team(wrong, runs=()))
    assert (off.label, off.detail.endswith(": `argus init` repairs it")) == ("WARN", True)
    missing = await writer_login_check(
        shared, TeamLogin(password=None, problem=None, user=None, runs=RUNS)
    )
    assert (missing.label, "but its login has no password" in missing.detail) == ("FAIL", True)
