"""Q-A2: the web's roles in argus.db.roles, on the catalog fakes of test_roles_edges: what
bootstrap sends for the web's group and login, and what doctor says about the web's login."""

from __future__ import annotations

import re
from typing import Any, cast

import pytest
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.config.settings import DatabaseSettings
from argus.db import roles
from tests.unit.test_roles_edges import _Answer, _Catalog, _conn, _Engine, _Server, _Table

pytestmark = pytest.mark.unit

GROUP_STATE = (False, False, False, False, False, False, True, True, True)
LOGIN_STATE = (True, False, False, False, False, False, True, True, True)
WEB = DatabaseSettings(
    password=SecretStr("made-up-password"), api_password=SecretStr("web-pw-made-up")
)


def test_bootstrap_repairs_a_missing_web_group() -> None:
    assert roles.repaired_by_bootstrap("argus_web is missing")
    assert roles.repaired_by_bootstrap("argus_runtime is missing")
    assert not roles.repaired_by_bootstrap("argus_webx is missing")
    assert not roles.repaired_by_bootstrap("can read evidence")


async def test_without_a_web_password_only_the_group_is_made() -> None:
    server = _Server({})
    changes: list[str] = []
    created = await roles.ensure_api_roles(_conn(server), DatabaseSettings(), changes=changes)
    assert created == ["argus_web"]
    assert server.sent == [
        'CREATE ROLE "argus_web" WITH NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION'
        " NOBYPASSRLS INHERIT"
    ]
    assert changes == []
    assert server.locked == 1


async def test_the_web_login_is_made_in_the_web_group_only() -> None:
    server = _Server({})
    created = await roles.ensure_api_roles(_conn(server), WEB)
    assert created == ["argus_web", "argus_api"]
    assert server.sent[0].startswith('CREATE ROLE "argus_web" WITH NOLOGIN')
    assert re.fullmatch(
        r'CREATE ROLE "argus_api" WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION'
        r" NOBYPASSRLS INHERIT PASSWORD 'SCRAM-SHA-256\$[^']+'",
        server.sent[1],
    ), server.sent[1]
    assert server.sent[2:] == ['GRANT "argus_web" TO "argus_api" WITH INHERIT TRUE']
    assert server.pgconn.calls == [(b"web-pw-made-up", b"argus_api", b"scram-sha-256")]


class _WebServer(_Server):
    """_Server, with the web's login as the one whose settings are read."""

    async def execute(self, statement: object, params: dict[str, Any] | None = None) -> _Answer:
        if "FROM pg_db_role_setting" in str(statement):
            assert (params or {})["r"] == "argus_api"
            return _Answer(list(self.settings))
        return await super().execute(statement, params)


async def test_an_existing_web_login_is_put_back_and_leaves_the_runtime_group() -> None:
    drifted = (True, True, False, False, False, False, True, True, True)  # a superuser now
    server = _WebServer(
        {"argus_web": GROUP_STATE, "argus_api": drifted},
        memberships={"argus_api": [("argus_runtime", "argus", False, True),
                                    ("argus_web", "argus", False, True)]},
    )  # fmt: skip
    changes: list[str] = []
    assert await roles.ensure_api_roles(_conn(server), WEB, changes=changes) == []
    assert server.sent[0] == 'ALTER ROLE "argus_api" WITH NOSUPERUSER'
    assert server.sent[1].startswith('ALTER ROLE "argus_api" WITH PASSWORD')
    assert server.sent[2:] == ['REVOKE "argus_runtime" FROM "argus_api" GRANTED BY "argus" CASCADE']
    assert changes == [
        "argus_api had SUPERUSER: reset",
        "argus_api was a member of argus_runtime: revoked",
    ]


@pytest.mark.parametrize(
    ("update", "message"),
    [
        ({"api_user": "argus_runtime"}, "database.api_user may not be argus_runtime"),
        ({"api_user": "argus_web"}, "database.api_user may not be argus_web"),
        ({"api_user": "pg_web"}, "database.api_user may not be pg_web"),
        ({"api_user": "Web"}, "database.api_user must be lowercase letters"),
        ({"api_password": SecretStr("a\x00b")}, "database.api_password must not contain a NUL"),
    ],
)
async def test_bootstrap_refuses_web_settings_before_sending_anything(
    update: dict[str, Any], message: str
) -> None:
    server = _Server({})
    with pytest.raises(roles.ConfigError, match=message):
        await roles.ensure_api_roles(_conn(server), WEB.model_copy(update=update))
    assert (server.sent, server.locked) == ([], 0)


@pytest.mark.parametrize("name", ["argus_web", "argus_runtime"])
def test_the_runtime_login_may_not_take_a_group_name(name: str) -> None:
    with pytest.raises(roles.ConfigError, match=f"database.user may not be {name}"):
        roles.check_bootstrap_settings(WEB.model_copy(update={"user": name}))


async def test_grant_connect_names_the_web_group() -> None:
    server = _Server({})
    await roles.grant_connect(_conn(server), "argus", role="argus_web")
    assert server.sent == ['GRANT CONNECT ON DATABASE "argus" TO "argus_web"']


class _WebMemberships(_Catalog):
    def __init__(self, others: list[str], group: tuple[bool, bool] | None) -> None:
        super().__init__({})
        self.others, self.group = others, group

    async def execute(self, statement: object, params: dict[str, str] | None = None) -> _Answer:
        text = str(statement)
        if "pg_has_role(current_user, oid, 'MEMBER')" in text:
            assert params == {"g": "argus_web"}
            return _Answer([(name,) for name in self.others])
        if "MEMBER WITH ADMIN OPTION" in text:
            return _Answer(self.group)
        return await super().execute(statement, params)


@pytest.mark.parametrize(
    ("others", "group", "expected"),
    [
        (["argus_runtime"], (True, False), ["is a member of argus_runtime"]),
        ([], (False, False), ["does not inherit the privileges of argus_web"]),
        ([], (True, True), ["can grant argus_web to other roles (ADMIN OPTION)"]),
        ([], None, ["argus_web is missing"]),
    ],
)
async def test_doctor_reports_the_web_logins_memberships(
    others: list[str], group: tuple[bool, bool] | None, expected: list[str]
) -> None:
    catalog = _WebMemberships(others, group)
    assert await roles._membership_problems(_conn(catalog), "argus_web") == expected


async def test_a_table_the_login_may_not_touch_needs_no_schema_usage() -> None:
    class _NoUsage(_Catalog):
        async def execute(self, statement: object, params: dict[str, str] | None = None) -> _Answer:
            if "to_regnamespace(:s) IS NOT NULL" in str(statement):
                return _Answer((True, False))  # the schema exists; no USAGE on it
            return await super().execute(statement, params)

    catalog = _NoUsage({})
    assert await roles._table_problems(_conn(catalog), "langgraph.x", roles.TableGrant()) == []
    assert await roles._table_problems(
        _conn(catalog), "langgraph.x", roles.TableGrant(select=True)
    ) == ["cannot use schema langgraph (for langgraph.x)"]


class _EveryTable(_Catalog):
    """The web login's catalog: API_GRANTS' tables as granted, and other tables, one held."""

    def __init__(self, extra: dict[str, _Table]) -> None:
        tables = {
            name: _Table(owner=False, select=grant.select, columns=[
                *((c, True, c in grant.update) for c in grant.insert),
                *((c, False, True) for c in grant.update if c not in grant.insert),
            ])
            for name, grant in roles.API_GRANTS.items()
        }  # fmt: skip
        functions: dict[str, tuple[bool, bool, bool] | None] = {  # as planned (Q-C3): the web
            f: (True, f in roles.WEB_FUNCTIONS, f in roles.APPROVALS_FUNCTIONS)  # login
            for f in roles._ALL_FUNCTIONS  # executes exactly the approval functions
        }
        super().__init__({**tables, **extra}, functions)

    async def execute(self, statement: object, params: dict[str, Any] | None = None) -> _Answer:
        text = str(statement)
        if "c.relkind IN ('r', 'p', 'v', 'm', 'f')" in text:
            assert (params or {})["schemas"] == ["public", "langgraph"]
            return _Answer(
                [
                    (name.split(".")[0], name.split(".")[1]) if "." in name else ("public", name)
                    for name in sorted(self.tables)
                ]
            )
        if "pg_has_role(current_user, oid, 'MEMBER')" in text:
            assert (params or {})["g"] == "argus_web"
        return await super().execute(statement, params)


async def test_the_web_login_must_execute_the_approval_functions() -> None:
    """Q-C3: the web records the approvals it signs, so a web login that cannot (not a member
    of argus_approvals) is named, and so is one that may propose as ARGUS."""
    catalog = _EveryTable({})
    catalog.functions = {f: (True, False, f in roles.APPROVALS_FUNCTIONS)
                         for f in roles._ALL_FUNCTIONS}  # fmt: skip
    catalog.functions[roles.RUNTIME_FUNCTIONS[0]] = (True, True, False)
    engine = cast(AsyncEngine, _Engine(catalog))
    names = [f.partition("(")[0] for f in roles.APPROVALS_FUNCTIONS]
    assert await roles.api_role_problems(engine) == [
        *(f"cannot execute {n}" for n in names),
        "can execute argus_approval_propose",
    ]


@pytest.mark.parametrize(
    ("also", "expected"),
    [
        ((True, True, False), []),
        ((False, False, False), []),  # not a member: its functions say so
        ((True, False, False), ["does not inherit the privileges of argus_approvals"]),
        ((True, True, True), ["can grant argus_approvals to other roles (ADMIN OPTION)"]),
        (None, []),
    ],
)
async def test_doctor_checks_how_the_web_login_belongs_to_argus_approvals(
    also: tuple[bool, bool, bool] | None, expected: list[str]
) -> None:
    """Review F10: ADMIN OPTION on argus_approvals would let the web's login hand approval
    rights to any login."""
    catalog = _EveryTable({})
    catalog.also = also
    assert await roles._membership_problems(
        _conn(catalog), "argus_web", also=("argus_approvals",)
    ) == expected  # fmt: skip


async def test_doctor_checks_every_table_for_the_web_login() -> None:
    extra = {
        "ti_indicators": _Table(owner=False, select=True),
        "signals": _Table(owner=False, select=False),
        "langgraph.checkpoint_blobs": _Table(owner=False, select=False),
    }
    engine = cast(AsyncEngine, _Engine(_EveryTable(extra)))
    assert await roles.api_role_problems(engine) == ["can read ti_indicators"]


async def test_doctor_names_every_privilege_on_a_sequence() -> None:
    """QA2-R4: identity columns need no sequence privilege, so each one held is named."""
    catalog = _EveryTable({})
    catalog.sequences = [
        ("public", "audit_events_id_seq", False, False, True),
        ("langgraph", "s", True, True, False),
        ("public", "quiet_seq", False, False, False),
    ]
    engine = cast(AsyncEngine, _Engine(catalog))
    assert await roles.api_role_problems(engine) == [
        "can UPDATE sequence audit_events_id_seq",
        "can USAGE sequence langgraph.s",
        "can SELECT sequence langgraph.s",
    ]
