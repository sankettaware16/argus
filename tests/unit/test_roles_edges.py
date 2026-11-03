"""argus.db.roles without a database (R1 mutation testing): what bootstrap sends to PostgreSQL.

tests/integration/db/test_roles.py runs the role bootstrap against the local server. Two changes
to roles.py would alter the configured runtime login on that server, so scripts/mutation.py
only ever tests them here: the name of the runtime group role, and the password verifier. The
statements themselves are pinned here too, exactly, including when bootstrap sends none.
"""

from __future__ import annotations

import contextlib
import dataclasses
import importlib.util
import re
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, cast

import psycopg
import pytest
from psycopg import sql
from pydantic import SecretStr
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

import argus.db.migrate as migrate
from argus.config import ConfigError, DatabaseSettings
from argus.db import roles

# made up, not a real hash; in two parts so secret scanners do not take it for one
VERIFIER = "SCRAM-SHA-256$4096:" + "c2FsdA==$c3RvcmVkS2V5:c2VydmVyS2V5"
SAFE = "NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT"
# (rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls, rolinherit,
#  no connection limit, no password expiry)
GROUP = (False, False, False, False, False, False, True, True, True)
LOGIN = (True, False, False, False, False, False, True, True, True)
FLAG_CLAUSES = (
    "LOGIN",
    "SUPERUSER",
    "CREATEDB",
    "CREATEROLE",
    "REPLICATION",
    "BYPASSRLS",
    "INHERIT",
)
SETTINGS = DatabaseSettings(password=SecretStr("made-up-password"))
CREATE_GROUP = f'CREATE ROLE "argus_runtime" WITH NOLOGIN {SAFE}'
CREATE_LOGIN = f"CREATE ROLE \"argus_app\" WITH LOGIN {SAFE} PASSWORD '{VERIFIER}'"
ALTER_PASSWORD = f"ALTER ROLE \"argus_app\" WITH PASSWORD '{VERIFIER}'"
MEMBERSHIP = 'GRANT "argus_runtime" TO "argus_app" WITH INHERIT TRUE'
# A membership row as bootstrap reads it: (role, grantor, admin option, inherit option)
IN_GROUP = ("argus_runtime", "argus", False, True)


def _migration_0003_upgrade(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """The statements migration 0003 runs, whitespace collapsed (nothing is executed)."""
    path = Path(migrate.MIGRATIONS_DIR) / "versions" / "0003_runtime_role_grants.py"
    spec = importlib.util.spec_from_file_location("argus_migration_0003_unit", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    executed: list[str] = []
    monkeypatch.setattr(module.op, "execute", lambda text: executed.append(" ".join(text.split())))
    module.upgrade()
    return executed


def test_the_runtime_role_is_the_one_migration_0003_grants_to(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The migration writes the role name out; bootstrap must create exactly that role."""
    check, *grants = _migration_0003_upgrade(monkeypatch)
    assert f"rolname = '{roles.RUNTIME_ROLE}'" in check
    assert grants
    assert all(grant.endswith(f" TO {roles.RUNTIME_ROLE}") for grant in grants)


class _PgConn:
    """libpq's side of the connection: records what it is asked to hash."""

    def __init__(self) -> None:
        self.calls: list[tuple[bytes, bytes, bytes]] = []

    def encrypt_password(self, password: bytes, user: bytes, algorithm: bytes) -> bytes:
        self.calls.append((password, user, algorithm))
        return VERIFIER.encode("ascii")


class _Savepoint:
    async def __aenter__(self) -> None:
        return None

    async def __aexit__(self, *exc: object) -> None:
        return None


class _Answer:
    """What SQLAlchemy returns for a query, as far as argus.db.roles reads it."""

    def __init__(self, value: Any) -> None:
        self.value = value

    def first(self) -> Any:
        return self.value

    def one(self) -> Any:
        return self.value

    def all(self) -> Any:
        return self.value

    def scalar_one(self) -> Any:
        return self.value

    def scalar_one_or_none(self) -> Any:
        return self.value

    def __iter__(self) -> Any:
        return iter(self.value)


class _DriverError(Exception):
    def __init__(self, sqlstate: str, message: str) -> None:
        super().__init__(message)
        self.sqlstate = sqlstate


class _Server:
    """What roles uses of an owner's AsyncConnection: the catalogs (roles, memberships, stored
    settings, the CONNECT check), the advisory lock, savepoints, and the raw psycopg connection
    for libpq's hashing and for quoting. It records the role DDL it is sent; the first
    ``refusals`` statements fail with ``error``. Memberships default to the login being a proper
    member of the group, when both roles exist."""

    def __init__(
        self,
        present: dict[str, tuple[bool, ...]],
        refusals: int = 0,
        error: tuple[str, str] = ("XX000", "tuple concurrently updated"),
        memberships: dict[str, list[tuple[str, str, bool, bool]]] | None = None,
        settings: list[tuple[bool, list[str]]] | None = None,
        may_connect: bool = True,
    ) -> None:
        self.present = present
        self.refusals = refusals
        self.error = error
        self.memberships = (
            memberships
            if memberships is not None
            else (
                {"argus_app": [IN_GROUP]} if {"argus_runtime", "argus_app"} <= set(present) else {}
            )
        )
        self.settings = settings or []
        self.keeps_settings = False  # an owner whose RESET ALL may not remove them all
        self.may_connect = may_connect
        self.attempts = 0
        self.locked = 0
        self.sent: list[str] = []
        self.pgconn = _PgConn()
        self.adapters = psycopg.adapters
        self.connection = None
        self.driver_connection = self

    async def get_raw_connection(self) -> _Server:
        return self

    def state(self, role: str) -> tuple[bool, ...] | None:
        return self.present.get(role)

    async def execute(self, statement: object, params: dict[str, Any] | None = None) -> _Answer:
        query, params = str(statement), params or {}
        if "pg_advisory_xact_lock" in query:
            assert params == {"k": roles.BOOTSTRAP_LOCK_KEY}
            self.locked += 1
            return _Answer(None)
        # These two select from pg_roles too (a sub-select), so they are matched first.
        if "FROM pg_db_role_setting" in query:
            assert params["r"] == "argus_app"
            return _Answer(list(self.settings))
        if "FROM pg_auth_members" in query:  # every grant: (role, member, grantor, admin, inherit)
            return _Answer(
                [
                    (role, member, grantor, admin, inherit)
                    for member, rows in sorted(self.memberships.items())
                    for role, grantor, admin, inherit in rows
                ]
            )
        if "FROM pg_roles WHERE rolname" in query:
            return _Answer(self.state(params["r"]))
        if "has_database_privilege" in query:
            return _Answer(self.may_connect)
        if "SELECT current_user" in query:
            return _Answer("argus")
        raise AssertionError(f"unexpected query: {query}")

    def begin_nested(self) -> _Savepoint:
        return _Savepoint()

    async def exec_driver_sql(self, statement: str) -> None:
        self.attempts += 1
        if self.refusals:
            self.refusals -= 1
            raise DBAPIError(statement, None, _DriverError(*self.error))
        self.sent.append(statement)
        self.apply(statement)

    def apply(self, statement: str) -> None:
        """What the statement changes in the catalogs this fake answers from."""
        if statement.endswith("RESET ALL") and not self.keeps_settings:
            everywhere = " IN DATABASE " not in statement
            self.settings = [row for row in self.settings if row[0] != everywhere]
        revoke = re.fullmatch(r'REVOKE "(.+)" FROM "(.+)" GRANTED BY "(.+)" CASCADE', statement)
        if revoke:
            role, member, grantor = revoke.groups()
            self.memberships[member] = [
                row for row in self.memberships.get(member, []) if row[:2] != (role, grantor)
            ]
        grant = re.fullmatch(r'GRANT "(.+)" TO "(.+)" WITH INHERIT TRUE', statement)
        if grant:
            role, member = grant.groups()
            self.memberships.setdefault(member, []).append((role, "argus", False, True))


def _conn(server: object) -> AsyncConnection:
    return cast(AsyncConnection, server)


async def test_the_password_reaches_the_server_only_as_a_scram_verifier() -> None:
    server = _Server({})
    verifier = await roles._password_verifier(_conn(server), "argus_app", "made-up-password")
    assert server.pgconn.calls == [(b"made-up-password", b"argus_app", b"scram-sha-256")]
    assert isinstance(verifier, sql.Literal)
    assert verifier.as_string() == f"'{VERIFIER}'"


async def test_bootstrap_creates_both_roles_on_a_new_server() -> None:
    server = _Server({})
    changes: list[str] = []
    created = await roles.ensure_roles(_conn(server), SETTINGS, changes=changes)
    assert created == ["argus_runtime", "argus_app"]
    assert server.sent == [CREATE_GROUP, CREATE_LOGIN, MEMBERSHIP]
    assert (server.locked, changes) == (1, [])


async def test_bootstrap_leaves_correct_roles_alone_but_sets_the_password() -> None:
    """The password is set every time (it may have changed), on its own: a CREATEROLE owner may
    not name SUPERUSER and the like. Nothing else is sent while nothing drifted: altering the
    group anyway would make concurrent bootstraps collide on its row."""
    server = _Server({"argus_runtime": GROUP, "argus_app": LOGIN})
    changes: list[str] = []
    assert await roles.ensure_roles(_conn(server), SETTINGS, changes=changes) == []
    assert server.sent == [ALTER_PASSWORD]
    assert changes == []


@pytest.mark.parametrize("drifted", range(len(FLAG_CLAUSES)))
async def test_bootstrap_puts_back_only_the_attribute_that_drifted(drifted: int) -> None:
    for role, safe in (("argus_runtime", GROUP), ("argus_app", LOGIN)):
        state = tuple(not value if index == drifted else value for index, value in enumerate(safe))
        present = {"argus_runtime": GROUP, "argus_app": LOGIN, role: state}
        server = _Server(present)
        changes: list[str] = []
        assert await roles.ensure_roles(_conn(server), SETTINGS, changes=changes) == []
        clause = FLAG_CLAUSES[drifted]
        wanted, found = (clause, f"NO{clause}") if safe[drifted] else (f"NO{clause}", clause)
        alter = f'ALTER ROLE "{role}" WITH {wanted}'
        assert server.sent == [alter, ALTER_PASSWORD]
        assert changes == [f"{role} had {found}: reset"]


@pytest.mark.parametrize(
    ("limit", "expiry", "clauses", "found"),
    [
        (False, True, "CONNECTION LIMIT -1", "a connection limit"),
        (True, False, "VALID UNTIL 'infinity'", "a password expiry"),
        (
            False,
            False,
            "CONNECTION LIMIT -1 VALID UNTIL 'infinity'",
            "a connection limit, a password expiry",
        ),
    ],
)
async def test_bootstrap_lifts_a_connection_limit_and_a_password_expiry_on_the_login(
    limit: bool, expiry: bool, clauses: str, found: str
) -> None:
    login = (*LOGIN[:7], limit, expiry)
    group = (*GROUP[:7], limit, expiry)  # NOLOGIN: neither matters for the group
    server = _Server({"argus_runtime": group, "argus_app": login})
    changes: list[str] = []
    await roles.ensure_roles(_conn(server), SETTINGS, changes=changes)
    assert server.sent == [f'ALTER ROLE "argus_app" WITH {clauses}', ALTER_PASSWORD]
    assert changes == [f"argus_app had {found}: reset"]


async def test_bootstrap_takes_every_dangerous_attribute_off_in_one_statement() -> None:
    login = (False, True, True, True, True, True, False, True, True)
    server = _Server({"argus_runtime": GROUP, "argus_app": login})
    changes: list[str] = []
    await roles.ensure_roles(_conn(server), SETTINGS, changes=changes)
    assert server.sent == [
        'ALTER ROLE "argus_app" WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION'
        " NOBYPASSRLS INHERIT",
        ALTER_PASSWORD,
    ]
    assert changes == [
        "argus_app had NOLOGIN, SUPERUSER, CREATEDB, CREATEROLE, REPLICATION, BYPASSRLS,"
        " NOINHERIT: reset"
    ]


@pytest.mark.parametrize(
    ("rows", "statements"),
    [
        ([(True, ["session_replication_role=replica"])], ['ALTER ROLE "argus_app" RESET ALL']),
        (
            [(False, ["default_transaction_read_only=on", "work_mem=1MB"])],
            ['ALTER ROLE "argus_app" IN DATABASE "argus" RESET ALL'],
        ),
        (
            [(False, ["work_mem=1MB"]), (True, ["work_mem=2MB"])],
            [
                'ALTER ROLE "argus_app" IN DATABASE "argus" RESET ALL',
                'ALTER ROLE "argus_app" RESET ALL',
            ],
        ),
    ],
    ids=["everywhere", "in-its-database", "both"],
)
async def test_settings_stored_on_the_login_are_cleared_and_named_without_values(
    rows: list[tuple[bool, list[str]]], statements: list[str]
) -> None:
    server = _Server({"argus_runtime": GROUP, "argus_app": LOGIN}, settings=rows)
    changes: list[str] = []
    await roles.ensure_roles(_conn(server), SETTINGS, changes=changes)
    assert server.sent == [ALTER_PASSWORD, *statements]
    names = sorted({entry.split("=")[0] for _, config in rows for entry in config})
    assert changes == [f"argus_app had stored settings ({', '.join(names)}): cleared"]
    assert not any("=" in change for change in changes)  # names only, never a value


async def test_every_other_membership_is_revoked_as_its_grantor_made_it() -> None:
    memberships = {
        "argus_runtime": [("pg_read_all_data", "argus", False, True)],
        "argus_app": [
            ("argus_runtime", "argus", False, True),
            ("pg_execute_server_program", "dba", False, True),
        ],
    }
    server = _Server({"argus_runtime": GROUP, "argus_app": LOGIN}, memberships=memberships)
    changes: list[str] = []
    await roles.ensure_roles(_conn(server), SETTINGS, changes=changes)
    assert server.sent == [
        ALTER_PASSWORD,
        'REVOKE "pg_read_all_data" FROM "argus_runtime" GRANTED BY "argus" CASCADE',
        'REVOKE "pg_execute_server_program" FROM "argus_app" GRANTED BY "dba" CASCADE',
    ]
    assert changes == [
        "argus_runtime was a member of pg_read_all_data: revoked",
        "argus_app was a member of pg_execute_server_program: revoked",
    ]


@pytest.mark.parametrize(
    ("membership", "said"),
    [
        (("argus_runtime", "argus", True, True), "ADMIN OPTION"),
        (("argus_runtime", "argus", False, False), "no INHERIT"),
    ],
    ids=["admin-option", "no-inherit"],
)
async def test_a_wrong_membership_in_the_group_is_granted_again(
    membership: tuple[str, str, bool, bool], said: str
) -> None:
    server = _Server(
        {"argus_runtime": GROUP, "argus_app": LOGIN}, memberships={"argus_app": [membership]}
    )
    changes: list[str] = []
    await roles.ensure_roles(_conn(server), SETTINGS, changes=changes)
    assert server.sent == [
        ALTER_PASSWORD,
        'REVOKE "argus_runtime" FROM "argus_app" GRANTED BY "argus" CASCADE',
        MEMBERSHIP,
    ]
    assert changes == [f"argus_app's membership in argus_runtime had {said}: granted again"]


async def test_a_login_that_lost_the_group_gets_it_back_and_is_told() -> None:
    server = _Server({"argus_runtime": GROUP, "argus_app": LOGIN}, memberships={})
    changes: list[str] = []
    await roles.ensure_roles(_conn(server), SETTINGS, changes=changes)
    assert server.sent == [ALTER_PASSWORD, MEMBERSHIP]
    assert changes == ["argus_app was not a member of argus_runtime: granted"]


@pytest.mark.parametrize(
    "error",
    [
        ("XX000", "tuple concurrently updated"),
        ("XX000", "tuple concurrently deleted"),
        ("23505", "duplicate key value"),
    ],
)
async def test_a_statement_a_concurrent_bootstrap_got_to_first_is_tried_again(
    error: tuple[str, str],
) -> None:
    server = _Server({"argus_runtime": GROUP, "argus_app": LOGIN}, refusals=2, error=error)
    assert await roles.ensure_roles(_conn(server), SETTINGS) == []
    assert server.sent == [ALTER_PASSWORD]
    assert server.attempts == 3


async def test_bootstrap_gives_up_after_twenty_five_attempts() -> None:
    """One attempt per overlapping bootstrap; runs on different databases are not serialised by
    the advisory lock (round 4: six at once exhausted five attempts)."""
    assert roles._ATTEMPTS == 25
    server = _Server({"argus_runtime": GROUP, "argus_app": LOGIN}, refusals=25)
    with pytest.raises(DBAPIError, match="tuple concurrently updated"):
        await roles.ensure_roles(_conn(server), SETTINGS)
    assert (server.sent, server.attempts) == ([], 25)


@pytest.mark.parametrize(
    "error", [("XX000", "cache lookup failed for role"), ("42501", "permission denied")]
)
async def test_other_errors_are_not_tried_again(error: tuple[str, str]) -> None:
    server = _Server({"argus_runtime": GROUP, "argus_app": LOGIN}, refusals=1, error=error)
    with pytest.raises(DBAPIError, match=error[1]):
        await roles.ensure_roles(_conn(server), SETTINGS)
    assert (server.sent, server.attempts) == ([], 1)


async def test_a_failed_statement_shows_no_password_verifier() -> None:
    """SQLAlchemy repeats a failed statement in its exception text; role DDL holds the verifier."""
    server = _Server(
        {"argus_runtime": GROUP, "argus_app": LOGIN}, refusals=1, error=("42501", "no")
    )
    with pytest.raises(DBAPIError) as info:
        await roles.ensure_roles(_conn(server), SETTINGS)
    assert info.value.statement == "ALTER ROLE \"argus_app\" WITH PASSWORD 'SCRAM-SHA-256$***'"
    assert "c3RvcmVkS2V5" not in str(info.value)


class _RacedServer(_Server):
    """Both roles are missing when bootstrap first looks, and exist when it creates them."""

    def __init__(self, sqlstate: str) -> None:
        super().__init__({"argus_runtime": GROUP, "argus_app": LOGIN})
        self.sqlstate = sqlstate
        self.looked: set[str] = set()

    def state(self, role: str) -> tuple[bool, ...] | None:
        if role not in self.looked:
            self.looked.add(role)
            return None
        return super().state(role)

    async def exec_driver_sql(self, statement: str) -> None:
        if statement.startswith("CREATE ROLE"):
            raise DBAPIError(statement, None, _DriverError(self.sqlstate, "role already exists"))
        self.sent.append(statement)
        self.apply(statement)


@pytest.mark.parametrize("sqlstate", ["42710", "23505"])
async def test_a_role_another_bootstrap_created_meanwhile_is_checked_instead(sqlstate: str) -> None:
    server = _RacedServer(sqlstate)
    assert await roles.ensure_roles(_conn(server), SETTINGS) == []
    assert server.sent == [ALTER_PASSWORD]


async def test_a_failed_create_is_not_taken_for_a_race() -> None:
    server = _Server({}, refusals=1, error=("42501", "permission denied to create role"))
    with pytest.raises(DBAPIError, match="permission denied"):
        await roles.ensure_roles(_conn(server), SETTINGS)
    assert server.sent == []


@pytest.mark.parametrize("user", ["Argus_App", "argus-app", "1app", "app user"])
async def test_bootstrap_refuses_a_login_name_it_would_have_to_quote(user: str) -> None:
    server = _Server({})
    settings = DatabaseSettings(user=user, password=SecretStr("made-up-password"))
    with pytest.raises(ConfigError) as info:
        await roles.ensure_roles(_conn(server), settings)
    assert str(info.value) == (
        "database.user must be lowercase letters, digits and _ (not starting with a digit)"
        " for `argus db bootstrap` to create it"
    )
    assert server.sent == []


@pytest.mark.parametrize("password", [None, SecretStr("")])
async def test_bootstrap_needs_the_password_it_sets(password: SecretStr | None) -> None:
    server = _Server({})
    with pytest.raises(ConfigError) as info:
        await roles.ensure_roles(_conn(server), DatabaseSettings(password=password))
    assert str(info.value) == (
        "database password is not set; put ARGUS_DATABASE__PASSWORD in .env (bootstrap sets"
        " it on the runtime role)"
    )
    assert server.sent == []


async def test_grant_connect_names_the_database_and_the_runtime_role() -> None:
    server = _Server({})
    await roles.grant_connect(_conn(server), "argus_test_1760000000_deadbeef")
    assert server.sent == [
        'GRANT CONNECT ON DATABASE "argus_test_1760000000_deadbeef" TO "argus_runtime"'
    ]


async def test_grant_connect_that_granted_nothing_is_an_error_with_a_remedy_that_works() -> None:
    """The group role a failed first bootstrap created is rolled back with it, so the remedy
    names the owner (which exists), quoted, and the message ends with the statement."""
    server = _Server({}, may_connect=False)
    with pytest.raises(roles.BootstrapError) as info:
        await roles.grant_connect(_conn(server), "Argus Prod")
    assert str(info.value) == (
        "argus_runtime may not connect to the database, and this owner may not grant that:"
        " bootstrap again once the database's owner has run"
        ' GRANT CONNECT ON DATABASE "Argus Prod" TO "argus" WITH GRANT OPTION'
    )


async def test_settings_an_owner_may_not_remove_fail_bootstrap_instead_of_being_claimed() -> None:
    """RESET ALL by an owner that is no superuser keeps what it may not set itself."""
    rows = [(True, ["session_replication_role=replica", "work_mem=1MB"])]
    server = _Server({"argus_runtime": GROUP, "argus_app": LOGIN}, settings=rows)
    server.keeps_settings = True
    changes: list[str] = []
    with pytest.raises(roles.BootstrapError) as info:
        await roles.ensure_roles(_conn(server), SETTINGS, changes=changes)
    assert str(info.value) == (
        "argus_app has settings stored on it that this owner may not remove"
        " (session_replication_role, work_mem): a superuser must run"
        ' ALTER ROLE "argus_app" RESET ALL (also IN DATABASE for its database)'
    )
    assert "=replica" not in str(info.value)  # names only, never a value
    assert "1MB" not in str(info.value)
    assert changes == []


async def test_an_attribute_the_owner_may_not_change_is_named_with_the_statement_to_run() -> None:
    login = (*LOGIN[:1], True, *LOGIN[2:])  # a superuser runtime login
    server = _Server(
        {"argus_runtime": GROUP, "argus_app": login},
        refusals=1,
        error=("42501", "permission denied to alter role"),
    )
    with pytest.raises(roles.BootstrapError) as info:
        await roles.ensure_roles(_conn(server), SETTINGS)
    assert str(info.value) == (
        "argus_app has SUPERUSER, and this owner may not change that: a superuser must run"
        ' ALTER ROLE "argus_app" WITH NOSUPERUSER'
    )
    assert server.attempts == 1  # a refusal is not a concurrent change: no retry


def test_bootstrap_refuses_a_login_that_is_the_owner_with_the_exact_reason() -> None:
    """model_copy skips the settings validator, so bootstrap repeats the rule (exact text)."""
    same = SETTINGS.model_copy(update={"user": SETTINGS.owner_user})
    with pytest.raises(ConfigError) as info:
        roles.check_bootstrap_settings(same)
    assert str(info.value) == (
        "database.user and database.owner_user must be different roles: ARGUS must not run"
        " as the role that owns its tables (D-029)"
    )


async def test_every_attribute_the_owner_may_not_change_is_named() -> None:
    login = (True, True, False, False, True, False, True, True, True)  # SUPERUSER, REPLICATION
    server = _Server(
        {"argus_runtime": GROUP, "argus_app": login},
        refusals=1,
        error=("42501", "permission denied to alter role"),
    )
    with pytest.raises(roles.BootstrapError) as info:
        await roles.ensure_roles(_conn(server), SETTINGS)
    assert str(info.value) == (
        "argus_app has SUPERUSER, REPLICATION, and this owner may not change that: a superuser"
        ' must run ALTER ROLE "argus_app" WITH NOSUPERUSER NOREPLICATION'
    )


async def test_a_wrong_group_membership_beside_a_good_one_is_revoked_not_granted_again() -> None:
    memberships = {
        "argus_app": [
            ("argus_runtime", "argus", True, True),
            ("argus_runtime", "deputy", False, True),
        ]
    }
    server = _Server({"argus_runtime": GROUP, "argus_app": LOGIN}, memberships=memberships)
    changes: list[str] = []
    await roles.ensure_roles(_conn(server), SETTINGS, changes=changes)
    assert server.sent == [
        ALTER_PASSWORD,
        'REVOKE "argus_runtime" FROM "argus_app" GRANTED BY "argus" CASCADE',
    ]
    assert changes == ["argus_app's membership in argus_runtime had ADMIN OPTION: revoked"]


@pytest.mark.parametrize(
    ("problem", "repaired"),
    [
        ("is a superuser", True),
        ("can create roles", True),
        ("can create databases", True),
        ("can replicate", True),
        ("bypasses row-level security", True),
        ("is a member of pg_read_server_files", True),
        ("does not inherit the privileges of argus_runtime", True),
        ("can grant argus_runtime to other roles (ADMIN OPTION)", True),
        ("has settings stored on it (work_mem)", True),
        ("argus_runtime is missing", True),
        ("audit_events is missing", False),
        ("can create schemas", False),
        ("can create tables in schema public", False),
        ("can UPDATE audit_events", False),
        ("runs with session_replication_role = replica (stored for its database)", False),
    ],
)
def test_doctor_knows_which_problems_one_bootstrap_repairs(problem: str, repaired: bool) -> None:
    assert roles.repaired_by_bootstrap(problem) is repaired


@pytest.mark.parametrize(
    ("update", "message"),
    [
        ({"user": "argus"}, "database.user and database.owner_user must be different roles"),
        ({"user": "argus_runtime"}, "database.user may not be argus_runtime"),
        ({"user": "pg_argus"}, "database.user may not be pg_argus"),
        ({"user": "public"}, "database.user may not be public"),
        ({"user": "none"}, "database.user may not be none"),
        ({"user": "current_user"}, "database.user may not be current_user"),
        ({"password": SecretStr("made-up\x00rest")}, "database.password must not contain a NUL"),
        ({"password": SecretStr("made-up\udcff")}, "database.password must be valid UTF-8 text"),
    ],
)
async def test_bootstrap_refuses_settings_it_cannot_use_before_sending_anything(
    update: dict[str, Any], message: str
) -> None:
    server = _Server({})
    with pytest.raises(ConfigError, match=message.replace(".", r"\.")) as info:
        await roles.ensure_roles(_conn(server), SETTINGS.model_copy(update=update))
    assert "rest" not in str(info.value)
    assert (server.sent, server.locked) == ([], 0)


def test_a_table_grant_allows_nothing_unless_it_says_so() -> None:
    grant = roles.TableGrant()
    assert (grant.select, grant.insert) == (False, ())
    with pytest.raises(dataclasses.FrozenInstanceError):
        cast(Any, grant).select = True


# --------------------------------------------------------------------------- doctor


class _Table:
    def __init__(
        self, *, owner: bool, select: bool, held: frozenset[str] = frozenset(), columns: Any = ()
    ) -> None:
        self.owner, self.select, self.held, self.columns = owner, select, held, columns


class _Catalog:
    """The runtime role's view of the database, answering the queries doctor makes (a query it
    does not expect fails the test)."""

    def __init__(
        self,
        tables: dict[str, _Table],
        functions: dict[str, tuple[bool, bool, bool] | None] | None = None,
    ) -> None:
        self.tables = tables
        # 0026's functions: (exists, the runtime may execute, argus_approvals may execute), or
        # None when argus_approvals is missing; a function not listed does not exist
        self.functions = functions or {}
        self.sequences: list[tuple[str, str, bool, bool, bool]] = []  # name, USAGE, SELECT, UPDATE
        # how the login belongs to an also_member_of role: member, inherits, ADMIN OPTION
        self.also: tuple[bool, bool, bool] | None = (True, True, False)

    async def execute(self, statement: object, params: dict[str, str] | None = None) -> _Answer:
        text, params = str(statement), params or {}
        if "to_regprocedure(:f)" in text:
            assert params["g"] == "argus_approvals"
            return _Answer(self.functions.get(params["f"], (False, False, False)))
        if "SELECT rolsuper" in text:
            return _Answer((False,) * 8)
        if "c.relkind = 'S'" in text:
            return _Answer(self.sequences)
        if "to_regnamespace(:s) IS NOT NULL" in text:
            known = any(name.startswith(f"{params['s']}.") for name in self.tables)
            return _Answer((known, known))
        if "FROM pg_roles a WHERE a.rolname = :r" in text:
            return _Answer(self.also)
        if "pg_has_role(current_user, oid, 'MEMBER')" in text:
            return _Answer([])
        if "MEMBER WITH ADMIN OPTION" in text:
            return _Answer((True, False))
        if "FROM pg_db_role_setting" in text:
            return _Answer([])
        if "FROM pg_settings" in text:
            return _Answer(
                [
                    ("default_transaction_read_only", "off", "default"),
                    ("session_replication_role", "origin", "default"),
                ]
            )
        table = self.tables.get(params["t"])
        if "relowner" in text:
            return _Answer(None if table is None else table.owner)
        assert table is not None, f"asked about a missing table: {text}"
        if "'SELECT')" in text:
            return _Answer(table.select)
        if "privilege(:t, :p)" in text:
            return _Answer(params["p"] in table.held)
        if "FROM pg_attribute" in text:
            return _Answer(table.columns)
        raise AssertionError(f"unexpected query: {text}")


class _Engine:
    def __init__(self, catalog: _Catalog) -> None:
        self.catalog = catalog

    @contextlib.asynccontextmanager
    async def connect(self) -> AsyncIterator[_Catalog]:
        yield self.catalog


class _Memberships(_Catalog):
    """A runtime login with other memberships, a group membership as given, and stored
    settings."""

    def __init__(
        self, others: list[str], group: tuple[bool, bool] | None, settings: list[list[str]]
    ) -> None:
        super().__init__({})
        self.others, self.group, self.settings = others, group, settings

    async def execute(self, statement: object, params: dict[str, str] | None = None) -> _Answer:
        text = str(statement)
        if "pg_has_role(current_user, oid, 'MEMBER')" in text:
            assert params == {"g": "argus_runtime"}
            return _Answer([(name,) for name in self.others])
        if "MEMBER WITH ADMIN OPTION" in text:
            return _Answer(self.group)
        if "FROM pg_db_role_setting" in text:
            return _Answer([(config,) for config in self.settings])
        return await super().execute(statement, params)


@pytest.mark.parametrize(
    ("others", "group", "settings", "expected"),
    [
        (["pg_read_server_files"], (True, False), [], ["is a member of pg_read_server_files"]),
        ([], (False, False), [], ["does not inherit the privileges of argus_runtime"]),
        ([], (True, True), [], ["can grant argus_runtime to other roles (ADMIN OPTION)"]),
        ([], None, [], ["argus_runtime is missing"]),
        (
            [],
            (True, False),
            [["session_replication_role=replica"], ["work_mem=1MB", "search_path=x"]],
            ["has settings stored on it (search_path, session_replication_role, work_mem)"],
        ),
    ],
    ids=["predefined-role", "no-inherit", "admin-option", "group-missing", "stored-settings"],
)
async def test_doctor_reports_memberships_and_stored_settings(
    others: list[str],
    group: tuple[bool, bool] | None,
    settings: list[list[str]],
    expected: list[str],
) -> None:
    catalog = _Memberships(others, group, settings)
    problems = await roles._membership_problems(_conn(catalog))
    problems += await roles._settings_problems(_conn(catalog))
    assert problems == expected


class _Settings(_Catalog):
    def __init__(self, rows: list[tuple[str, str, str]]) -> None:
        super().__init__({})
        self.rows = rows

    async def execute(self, statement: object, params: dict[str, str] | None = None) -> _Answer:
        if "FROM pg_settings" in str(statement):
            return _Answer(self.rows)
        return await super().execute(statement, params)


@pytest.mark.parametrize(
    ("rows", "expected"),
    [
        (
            [("session_replication_role", "replica", "database")],
            ["runs with session_replication_role = replica (stored for its database)"],
        ),
        (
            [("default_transaction_read_only", "on", "global")],
            ["runs with default_transaction_read_only = on (stored for every role)"],
        ),
        (
            [("session_replication_role", "local", "configuration file")],
            ["runs with session_replication_role = local (set in the server's configuration)"],
        ),
        (
            [("session_replication_role", "replica", "user")],
            ["runs with session_replication_role = replica (stored on the login)"],
        ),
        (
            [("default_transaction_read_only", "on", "database user")],
            ["runs with default_transaction_read_only = on (stored on the login for its database)"],
        ),
        (
            [("session_replication_role", "replica", "override")],
            ["runs with session_replication_role = replica (source: override)"],
        ),
        ([("session_replication_role", "origin", "database")], []),
    ],
    ids=[
        "database",
        "every-role",
        "server-config",
        "login",
        "login-in-database",
        "other-source",
        "harmless",
    ],
)
async def test_doctor_reports_session_settings_stored_anywhere(
    rows: list[tuple[str, str, str]], expected: list[str]
) -> None:
    assert await roles._settings_problems(_conn(_Settings(rows))) == expected


class _Attributes(_Memberships):
    """A runtime login with the given attributes (doctor's first query) and memberships."""

    def __init__(self, attributes: tuple[bool, ...], others: list[str]) -> None:
        super().__init__(others, (True, False), [])
        self.attributes = attributes

    async def execute(self, statement: object, params: dict[str, str] | None = None) -> _Answer:
        if "SELECT rolsuper" in str(statement):
            return _Answer(self.attributes)
        return await super().execute(statement, params)


@pytest.mark.parametrize(
    ("attributes", "expected"),
    [
        (
            (False, True, False, False, False, False, False, False),
            ["can create roles", "is a member of pg_read_server_files"],
        ),
        ((True, False, False, False, False, False, False, False), ["is a superuser"]),
    ],
    ids=["createrole-and-a-membership", "superuser"],
)
async def test_doctor_lists_memberships_unless_the_login_is_a_superuser(
    attributes: tuple[bool, ...], expected: list[str]
) -> None:
    """A superuser counts as a member of every role, so its memberships are not listed; any
    other attribute leaves the membership check on."""
    engine = cast(AsyncEngine, _Engine(_Attributes(attributes, ["pg_read_server_files"])))
    problems = await roles.runtime_role_problems(engine)
    assert [p for p in problems if " is missing" not in p] == expected


async def test_doctor_names_each_missing_table() -> None:
    engine = cast(AsyncEngine, _Engine(_Catalog({})))
    problems = await roles.runtime_role_problems(engine)
    functions = roles._ALL_FUNCTIONS
    assert problems == [f"{table} is missing" for table in roles.RUNTIME_GRANTS] + [
        f"function {function.partition('(')[0]} is missing" for function in functions
    ]
    assert problems[:2] == ["alembic_version is missing", "audit_events is missing"]


_DECIDE = "argus_approval_decide(text, bigint, text, text, timestamptz, jsonb, text, jsonb)"
_PROPOSE = roles.RUNTIME_FUNCTIONS[0]
_CHAIN = "argus_chain_append()"


@pytest.mark.parametrize(
    ("functions", "expected"),
    [
        ({}, []),
        ({_DECIDE: (True, True, True)}, ["can execute argus_approval_decide"]),
        ({_DECIDE: (True, False, False)}, ["argus_approvals cannot execute argus_approval_decide"]),
        ({_CHAIN: (True, True, False)}, ["can execute argus_chain_append"]),
        ({_CHAIN: (True, False, True)}, ["argus_approvals can execute argus_chain_append"]),
        ({_DECIDE: None}, ["argus_approvals is missing"]),
        ({_PROPOSE: (True, False, False)}, ["cannot execute argus_approval_propose"]),
        ({_PROPOSE: (True, True, True)}, ["argus_approvals can execute argus_approval_propose"]),
    ],
    ids=["as-planned", "runtime-may-approve", "approvals-may-not", "runtime-may-chain",
         "approvals-may-chain", "approvals-role-missing", "runtime-may-not-propose",
         "approvals-may-propose"],
)  # fmt: skip
async def test_doctor_checks_who_may_execute_the_case_functions(
    functions: dict[str, tuple[bool, bool, bool] | None], expected: list[str]
) -> None:
    """The runtime login executes only ARGUS's proposal function (Q-C3), none of the approval
    or chain functions; argus_approvals exactly the approval functions (Q-C1, Q-C3)."""
    planned: dict[str, tuple[bool, bool, bool] | None] = {
        f: (True, f in roles.RUNTIME_FUNCTIONS, f in roles.APPROVALS_FUNCTIONS)
        for f in roles._ALL_FUNCTIONS
    }
    catalog = _Catalog({}, {**planned, **functions})
    assert await roles._function_problems(_conn(catalog)) == expected


async def test_doctor_reports_a_table_the_runtime_role_must_not_read() -> None:
    catalog = _Catalog({"vault": _Table(owner=False, select=True)})
    problems = await roles._table_problems(_conn(catalog), "vault", roles.TableGrant())
    assert problems == ["can read vault"]
