"""Q-A2: the web on its own login. ``argus_web`` (the group) holds exactly API_GRANTS; the web's
login (``database.api_user``, default ``argus_api``) is its only member; ``argus db bootstrap``
makes it idempotently once its password is set; doctor checks it from its own point of view.
Throwaway logins only: the configured web login is cluster-wide and may be production's."""

from __future__ import annotations

import secrets
from collections.abc import Awaitable, Callable, Iterator
from pathlib import Path

import psycopg
import pytest
from psycopg import sql
from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine
from typer.testing import CliRunner

from argus.cli import app
from argus.config.settings import DatabaseSettings, Settings, WebSettings
from argus.db import roles
from argus.db.engine import create_engine
from argus.doctor import web_login_check
from tests.conftest import REPO_ROOT, env_copy, hide_in_reports
from tests.integration.conftest import (
    TEST_ROLE_PATTERN,
    TEST_ROLE_PREFIX,
    admin_connect,
    owner_password,
)

pytestmark = pytest.mark.integration

MakeLogin = Callable[[], Awaitable[DatabaseSettings]]
runner = CliRunner()


def as_owner(db: DatabaseSettings, database: str, *statements: str) -> None:
    with admin_connect(db, database) as conn:
        for statement in statements:
            conn.execute(statement)  # type: ignore[arg-type] - constant test statements


async def problems_of(login: DatabaseSettings, database: str) -> list[str]:
    engine = create_engine(login, database=database, role="api")
    try:
        return await roles.api_role_problems(engine)
    finally:
        await engine.dispose()


async def test_a_web_login_holds_exactly_the_webs_grants(
    make_api_login: MakeLogin, migrated_engine: AsyncEngine, test_database: str
) -> None:
    login = await make_api_login()
    assert await problems_of(login, test_database) == []


async def test_doctor_names_every_grant_beyond_or_short_of_the_webs(
    make_api_login: MakeLogin,
    migrated_engine: AsyncEngine,
    db_settings: DatabaseSettings,
    test_database: str,
) -> None:
    login = await make_api_login()
    as_owner(
        db_settings,
        test_database,
        "GRANT DELETE ON review_events TO argus_web",
        "GRANT SELECT ON signals TO argus_web",
        "GRANT INSERT (password_hash) ON users TO argus_web",
        "GRANT UPDATE (version) ON investigations TO argus_web",
        "GRANT SELECT ON langgraph.checkpoint_blobs TO argus_web",
        "REVOKE SELECT ON rules FROM argus_web",
        "REVOKE UPDATE (ended_at) ON user_sessions FROM argus_web",
    )
    found = await problems_of(login, test_database)
    assert sorted(found) == sorted(
        [
            "can DELETE review_events",
            "can read signals",
            "can insert users.password_hash",
            "can update investigations.version",
            "can read langgraph.checkpoint_blobs",
            "cannot read rules",
            "cannot update user_sessions.ended_at",
        ]
    )


async def test_column_grants_on_a_table_the_web_may_not_read_are_named(
    make_api_login: MakeLogin,
    migrated_engine: AsyncEngine,
    db_settings: DatabaseSettings,
    test_database: str,
) -> None:
    """QA2-R4: SELECT on some columns of a table outside API_GRANTS (the request ledger's live
    sessions), and on a column of a table the web writes but must not read."""
    login = await make_api_login()
    as_owner(
        db_settings,
        test_database,
        "GRANT SELECT (id, created_by, max_requests) ON siem_live_sessions TO argus_web",
    )
    engine = create_engine(login, database=test_database, role="api")
    try:
        async with engine.connect() as conn:  # the web login can read those columns now
            await conn.execute(text("SELECT id, created_by FROM siem_live_sessions"))
    finally:
        await engine.dispose()
    assert await problems_of(login, test_database) == ["can read columns of siem_live_sessions"]


async def test_sequence_privileges_of_the_web_are_named(
    make_api_login: MakeLogin,
    migrated_engine: AsyncEngine,
    db_settings: DatabaseSettings,
    test_database: str,
) -> None:
    """QA2-R4: the web needs no sequence (identity columns need none); UPDATE on the audit
    trail's would let it setval() the trail's ids into collisions."""
    login = await make_api_login()
    as_owner(
        db_settings, test_database, "GRANT UPDATE ON SEQUENCE audit_events_id_seq TO argus_web"
    )
    engine = create_engine(login, database=test_database, role="api")
    try:
        async with engine.begin() as conn:
            await conn.execute(text("SELECT setval('audit_events_id_seq', 1, false)"))
    finally:
        await engine.dispose()
    assert await problems_of(login, test_database) == ["can UPDATE sequence audit_events_id_seq"]


async def test_a_web_login_in_another_group_is_named(
    make_api_login: MakeLogin, migrated_engine: AsyncEngine, db_settings: DatabaseSettings,
    test_database: str,
) -> None:  # fmt: skip
    login = await make_api_login()
    as_owner(db_settings, test_database, f'GRANT argus_runtime TO "{login.api_user}"')
    assert "is a member of argus_runtime" in await problems_of(login, test_database)


@pytest.mark.parametrize(
    "statement",
    [
        "INSERT INTO users (username, display_name, password_hash) VALUES ('mallory', 'M', 'x')",
        "UPDATE users SET password_hash = 'x'",  # it freezes an account, never sets a password
        "UPDATE investigations SET version = version + 1",
        "DELETE FROM review_events",
        "UPDATE review_events SET note = 'x'",
        "DELETE FROM audit_events",
        "TRUNCATE audit_events",
        "SELECT count(*) FROM ti_indicators",
        "SELECT count(*) FROM siem_probes",
        "UPDATE siem_switches SET stopped = false",
        "INSERT INTO siem_probes (at, state, reasons, probe_ok, auth_failed, blocked_indices)"
        " VALUES (now(), 'normal', '{}', true, false, '{}')",
        "UPDATE assessments SET outcome = 'benign_expected'",
        "INSERT INTO writeback_outbox (review_id, investigation_id, status, alert_ids)"
        " VALUES (1, gen_random_uuid(), 'x', '{}')",
        "SELECT count(*) FROM langgraph.checkpoint_writes",
        "CREATE TABLE public.stash (x int)",
    ],
)
async def test_the_web_login_cannot_reach_beyond_its_grants(
    make_api_login: MakeLogin, migrated_engine: AsyncEngine, test_database: str, statement: str
) -> None:
    login = await make_api_login()
    engine = create_engine(login, database=test_database, role="api")
    try:
        with pytest.raises(DBAPIError) as refused:
            async with engine.begin() as conn:
                await conn.execute(text(statement))
        assert getattr(refused.value.orig, "sqlstate", None) == "42501"  # insufficient privilege
    finally:
        await engine.dispose()


async def test_a_review_locks_its_investigation_with_update_on_one_column_only(
    make_api_login: MakeLogin, migrated_engine: AsyncEngine, db_settings: DatabaseSettings,
    test_database: str,
) -> None:  # fmt: skip
    """Why the web holds UPDATE (updated_at) on investigations: a review's SELECT ... FOR UPDATE
    needs UPDATE on one column. Without it the lock, and so every review, is refused."""
    login = await make_api_login()
    lock = text("SELECT id FROM investigations FOR UPDATE")
    engine = create_engine(login, database=test_database, role="api")
    try:
        async with engine.begin() as conn:
            await conn.execute(lock)
        as_owner(db_settings, test_database, "REVOKE UPDATE (updated_at) ON investigations"
                 " FROM argus_web")  # fmt: skip
        with pytest.raises(DBAPIError):
            async with engine.begin() as conn:
                await conn.execute(lock)
    finally:
        await engine.dispose()


_MEMBERSHIPS = text(
    "SELECT rolname FROM pg_roles WHERE pg_has_role(current_user, oid, 'MEMBER')"
    " AND rolname <> current_user ORDER BY 1"
)


async def test_the_web_suite_runs_as_a_web_login(web_engine: AsyncEngine) -> None:
    """The fixture every web test uses: a member of argus_web and argus_approvals (Q-C3: the
    web records the approvals it signs), of nothing else."""
    async with web_engine.connect() as conn:
        held = (await conn.execute(_MEMBERSHIPS)).scalars().all()
    assert held == sorted([roles.APPROVALS_ROLE, roles.API_ROLE])


# --------------------------------------------------------------------------- bootstrap, doctor


@pytest.fixture
def web_login_name(db_settings: DatabaseSettings) -> Iterator[tuple[str, str]]:
    """A throwaway name and password for the web's login made through the CLI; dropped after."""
    import time

    name = f"{TEST_ROLE_PREFIX}{int(time.time())}_{secrets.token_hex(4)}"
    assert TEST_ROLE_PATTERN.fullmatch(name)
    password = secrets.token_urlsafe(24)
    hide_in_reports(password)
    try:
        yield name, password
    finally:  # it holds no privilege of its own (only argus_web's, by membership)
        with admin_connect(db_settings) as conn:
            conn.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(name)))


def _cli(*args: str, hidden: tuple[str, ...]) -> tuple[int, str]:
    result = runner.invoke(app, list(args))
    out = result.output + result.stderr
    assert not any(secret in out for secret in hidden), "a password appeared in CLI output"
    return result.exit_code, out


def test_bootstrap_makes_the_web_login_once_its_password_is_set(
    tmp_path: Path,
    web_login_name: tuple[str, str],
    db_settings: DatabaseSettings,
    test_database: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    name, password = web_login_name
    # the repo .env's runtime and owner passwords, without a web password an install wrote
    monkeypatch.chdir(env_copy(tmp_path, without=frozenset({"ARGUS_DATABASE__API_PASSWORD"})))
    monkeypatch.setenv("ARGUS_DATABASE__NAME", test_database)
    monkeypatch.setenv("ARGUS_LOGGING__LEVEL", "WARNING")
    config = str(REPO_ROOT / "config" / "argus.yaml")
    assert db_settings.password is not None
    hidden = (password, db_settings.password.get_secret_value(), owner_password(db_settings))
    code, out = _cli("db", "bootstrap", "-c", config, hidden=hidden)  # no web password yet
    assert code == 0, out
    assert "web login ready" not in out
    assert _cli("db", "upgrade", "-c", config, hidden=hidden)[0] == 0
    monkeypatch.setenv("ARGUS_DATABASE__API_USER", name)
    monkeypatch.setenv("ARGUS_DATABASE__API_PASSWORD", password)
    code, out = _cli("db", "bootstrap", "-c", config, hidden=hidden)
    assert code == 0, out
    assert (
        f"web login ready: {name} (member of argus_web) may connect to {test_database};"
        f" created {name}"
    ) in out
    code, out = _cli("db", "bootstrap", "-c", config, hidden=hidden)
    assert code == 0, out
    assert f"web login ready: {name} (member of argus_web) may connect to {test_database};" \
        " already present" in out  # fmt: skip
    with admin_connect(db_settings, test_database) as conn:
        rows = conn.execute(
            "SELECT details FROM audit_events WHERE action = 'db.bootstrap' ORDER BY id"
        ).fetchall()
    # the first bootstrap ran before the audit table existed: not recorded
    assert [row[0].get("web_login") for row in rows] == [name, name]
    assert [row[0]["created"] for row in rows] == [[name], []]
    with psycopg.connect(
        host=db_settings.host, port=db_settings.port, user=name, password=password,
        dbname=test_database, connect_timeout=5,
    ) as conn:  # fmt: skip
        assert conn.execute("SELECT count(*) FROM users").fetchone() == (0,)
    monkeypatch.setenv("ARGUS_WEB__DATABASE_ROLE", "api")
    code, out = _cli("doctor", "-c", config, hidden=hidden)
    assert "PASS  web login" in out, out
    assert f"{name}: exactly the web's grants, in use" in out


def test_bootstrap_refuses_a_web_login_name_that_is_not_its_own(
    db_settings: DatabaseSettings, test_database: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(REPO_ROOT)
    monkeypatch.setenv("ARGUS_DATABASE__NAME", test_database)
    monkeypatch.setenv("ARGUS_DATABASE__API_PASSWORD", "Synthetic-Web-Login-1")
    config = str(REPO_ROOT / "config" / "argus.yaml")
    for name, reason in (
        ("argus_runtime", "database.api_user may not be argus_runtime"),
        ("argus_web", "database.api_user may not be argus_web"),
        ("Web-Login", "database.api_user must be lowercase letters"),
    ):
        monkeypatch.setenv("ARGUS_DATABASE__API_USER", name)
        result = runner.invoke(app, ["db", "bootstrap", "-c", config])
        assert result.exit_code == 2, result.output
        assert reason in result.stderr


async def test_doctor_on_the_web_login(
    make_api_login: MakeLogin, migrated_engine: AsyncEngine, test_database: str
) -> None:
    login = (await make_api_login()).model_copy(update={"name": test_database})
    in_use = Settings(database=login, web=WebSettings(database_role="api"))
    result = await web_login_check(in_use)
    assert (result.label, result.detail) == (
        "PASS", f"{login.api_user}: exactly the web's grants, in use")  # fmt: skip
    unused = await web_login_check(Settings(database=login))
    assert (unused.label, "set web.database_role: api" in unused.detail) == ("WARN", True)
    wrong = login.model_copy(update={"api_password": SecretStr("not-its-password-at-all")})
    refused = await web_login_check(Settings(database=wrong))
    assert (refused.label, "run `argus db bootstrap`" in refused.detail) == ("FAIL", True)
    none = login.model_copy(update={"api_password": None})
    assert (await web_login_check(Settings(database=none))).label == "WARN"
    broken = await web_login_check(Settings(database=none, web=WebSettings(database_role="api")))
    assert (broken.label, "the web cannot start" in broken.detail) == ("FAIL", True)


def test_until_the_switch_the_runtime_login_can_still_do_all_the_web_does() -> None:
    """LOCK-IN: while production's web still logs in as argus_app (until the checkpoint that
    sets web.database_role: api), every grant the web needs is also the runtime role's, so the
    switch can be undone. A component that gives the web something only argus_web may do (Q-C1's
    approvals) ends this, after the switch: it then changes this test. Q-E2's ELK sign-in is such
    a component: it creates ELK accounts and sessions, which only the web's own login may
    (`web.elk_signin` needs `web.database_role: api`); local mode needs none of it."""
    elk_only = {  # (insert, update) columns that only ELK sign-in (0036) gives the web
        "users": ({"elk_username", "argus_uid", "email", "elk_first_signin_at",
                   "last_good_check_at"},
                  {"email", "argus_uid", "elk_first_signin_at", "last_good_check_at",
                   "frozen_at"}),
        "user_sessions": ({"mode", "capabilities", "checked_at", "map_version", "no_custody",
                           "credential"},
                          {"capabilities", "checked_at", "map_version", "unverified_since",
                           "unverified_why"}),
        # AR8's canary: the approval is signed with the web's key, so only the web records one
        "case_team_approvals": ({"case_id", "gen", "plan_hash", "report_version",
                                 "approver_user_id", "statement", "signature", "approved_at",
                                 "expires_at"}, set()),
    }  # fmt: skip
    for table, grant in roles.API_GRANTS.items():
        runtime = roles.RUNTIME_GRANTS.get(table)
        assert runtime is not None, table
        extra_insert, extra_update = elk_only.get(table, (set(), set()))
        assert grant.select <= runtime.select, table
        assert set(grant.insert) - extra_insert <= set(runtime.insert), table
        assert set(grant.update) - extra_update <= set(runtime.update), table
        assert grant.delete <= runtime.delete, table


def test_every_web_test_gives_the_app_the_web_login() -> None:
    """LOCK-IN (the gate: the web suite passes as argus_api): the app under test gets the
    ``web_engine`` fixture (a throwaway web login); test_r15's helper passes it on as
    ``engine``. An app on the runtime login would hide a grant the web lacks."""
    import re

    calls = []
    for path in sorted((REPO_ROOT / "tests").rglob("test_*.py")):
        for match in re.finditer(r"\bcreate_app\(\s*([A-Za-z_][A-Za-z0-9_]*)", path.read_text()):
            calls.append((path.relative_to(REPO_ROOT).as_posix(), match.group(1)))
    assert calls
    assert [c for c in calls if c[1] not in ("web_engine", "engine")] == []
    helper = (REPO_ROOT / "tests" / "integration" / "web" / "test_r15.py").read_text()
    assert helper.count("client(web_engine)") == helper.count("client(") - 1  # the def itself


def _migration_0021_grants(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    import importlib.util
    from pathlib import Path

    from argus.db import migrate

    path = Path(migrate.MIGRATIONS_DIR) / "versions" / "0021_web_login_argus_web.py"
    spec = importlib.util.spec_from_file_location("argus_migration_0021_test", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    executed: list[str] = []
    monkeypatch.setattr(module.op, "execute", lambda sql: executed.append(" ".join(sql.split())))
    module.upgrade()
    rename = " ".join(module.RENAME.split())  # an old database's tables first (siem_names)
    return [sql for sql in executed if sql != rename]


def _later_web_grants() -> list[str]:
    """What the migrations after 0021 grant argus_web (each one's ``WEB_GRANTS``)."""
    import importlib.util
    from pathlib import Path

    from argus.db import migrate

    out: list[str] = []
    for path in sorted((Path(migrate.MIGRATIONS_DIR) / "versions").glob("0[0-9][0-9][0-9]_*.py")):
        if path.name[:4] <= "0021":
            continue
        spec = importlib.util.spec_from_file_location(f"argus_migration_{path.stem}", path)
        assert spec is not None
        assert spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        out += [" ".join(g.split()) for g in getattr(module, "WEB_GRANTS", ())]
    return out


def _later_web_revokes() -> list[tuple[str, tuple[str, ...]]]:
    """What the migrations after 0021 take back from argus_web: (table, insert columns)."""
    import importlib.util
    import re
    from pathlib import Path

    from argus.db import migrate

    out: list[tuple[str, tuple[str, ...]]] = []
    for path in sorted((Path(migrate.MIGRATIONS_DIR) / "versions").glob("0[0-9][0-9][0-9]_*.py")):
        if path.name[:4] <= "0021":
            continue
        spec = importlib.util.spec_from_file_location(f"argus_migration_{path.stem}", path)
        assert spec is not None
        assert spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for revoke in getattr(module, "WEB_TAKEN_BACK", ()):
            found = re.fullmatch(r"REVOKE INSERT \(([^)]*)\) ON (\w+) FROM argus_web", revoke)
            assert found, revoke
            out.append((found.group(2), tuple(c.strip() for c in found.group(1).split(","))))
    return out


def test_migration_0021_grants_exactly_the_api_grants(monkeypatch: pytest.MonkeyPatch) -> None:
    """What 0021 grants argus_web, with what later migrations grant it (their
    ``WEB_GRANTS``: 0023, report@2; 0024 and 0025, Q-A1), equals roles.API_GRANTS, privilege
    by privilege."""
    import re

    check, *grants = _migration_0021_grants(monkeypatch)
    grants += _later_web_grants()
    assert f"rolname = '{roles.API_ROLE}'" in check
    granted: dict[str, roles.TableGrant] = {}
    schemas = []
    for grant in grants:
        usage = re.fullmatch(r"GRANT USAGE ON SCHEMA (\w+) TO argus_web", grant)
        if usage:
            schemas.append(usage.group(1))
            continue
        found = re.fullmatch(r"GRANT (.+) ON ([\w., ]+) TO argus_web", grant)
        assert found, grant
        privileges, tables = found.groups()
        insert = re.search(r"INSERT \(([^)]*)\)", privileges)
        update = re.search(r"UPDATE \(([^)]*)\)", privileges)
        for table in (t.strip() for t in tables.split(",")):
            before = granted.get(table, roles.TableGrant())  # a later migration adds to it
            granted[table] = roles.TableGrant(
                select=before.select or privileges.startswith("SELECT"),
                insert=before.insert
                + (tuple(c.strip() for c in insert.group(1).split(",")) if insert else ()),
                update=before.update
                + (tuple(c.strip() for c in update.group(1).split(",")) if update else ()),
            )
    assert schemas == ["public", "langgraph"]
    for table, columns in _later_web_revokes():  # a later migration took columns back
        before = granted[table]
        granted[table] = roles.TableGrant(
            select=before.select,
            insert=tuple(c for c in before.insert if c not in columns),
            update=before.update,
            delete=before.delete,
        )

    def normal(grants: dict[str, roles.TableGrant]) -> dict[str, tuple[object, ...]]:
        return {
            t: (g.select, sorted(g.insert), sorted(g.update), g.delete) for t, g in grants.items()
        }

    assert normal(granted) == normal(roles.API_GRANTS)


async def test_0021_without_argus_web_says_to_bootstrap_first(empty_engine: AsyncEngine) -> None:
    """The group is renamed inside the migration's own transaction, so no other session ever
    misses it, and the rename is undone with the failed migration."""
    from argus.db import migrate

    await migrate.upgrade(empty_engine, "0020")
    hidden = f"argus_web_hidden_{secrets.token_hex(4)}"

    async def migrate_with_the_group_hidden() -> None:
        async with migrate.migration_transaction(empty_engine) as conn:
            await conn.exec_driver_sql(f'ALTER ROLE argus_web RENAME TO "{hidden}"')
            await migrate.run(conn, "upgrade", "0021")

    with pytest.raises(DBAPIError) as info:
        await migrate_with_the_group_hidden()
    error = info.value.orig
    assert isinstance(error, psycopg.errors.UndefinedObject)
    assert 'role "argus_web" does not exist' in str(error)
    assert error.diag.message_hint == 'run "argus db bootstrap" first'
    assert await migrate.current_revision(empty_engine) == "0020"
    async with empty_engine.connect() as conn:
        found = await conn.execute(text("SELECT 1 FROM pg_roles WHERE rolname = 'argus_web'"))
        assert found.first() is not None


async def test_downgrading_0021_takes_every_web_grant_back(
    make_api_login: MakeLogin, migrated_engine: AsyncEngine, test_database: str
) -> None:
    from argus.db import migrate

    login = await make_api_login()
    await migrate.downgrade(migrated_engine, "0020")
    engine = create_engine(login, database=test_database, role="api")
    try:
        for statement in ("SELECT count(*) FROM users", "SELECT count(*) FROM audit_events",
                          "SELECT count(*) FROM langgraph.checkpoints"):  # fmt: skip
            with pytest.raises(DBAPIError):
                async with engine.connect() as conn:
                    await conn.execute(text(statement))
    finally:
        await engine.dispose()
    await migrate.upgrade(migrated_engine)
    assert await problems_of(login, test_database) == []
