"""Adversarial DB-backed tests: secrets in audit rows, database exception text and CLI output.

Only throwaway databases from tests/integration/conftest.py are used. Credential-looking values are
synthetic, except the local Docker passwords (runtime role and owner), which come from the fixtures
and are never printed: checks on them compare booleans, so a failing assertion cannot echo them.
Tests whose docstring starts with "DEFECT" currently fail.
"""

from __future__ import annotations

import io
from collections.abc import Iterator
from pathlib import Path

import psycopg
import pytest
from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, OperationalError
from sqlalchemy.ext.asyncio import AsyncEngine
from typer.testing import CliRunner

from argus.cli import app
from argus.config import DatabaseSettings, load_settings
from argus.db.audit import record_audit
from argus.db.engine import create_engine, session_factory
from argus.observability.logs import configure_logging, get_logger
from argus.observability.redaction import MASK, clear_registered_secrets
from tests.conftest import suite_config
from tests.integration.conftest import TEST_DB_PREFIX, owner_password

runner = CliRunner()
CONFIG = suite_config()  # the shipped config on the suite's site, not this installation's
FAKE_ES_APIKEY = "VnVhQ2ZHY0JDZGJrUW0tZTVhT3g6dWkybHAyYXhUTm1zeWFrdzl0dk5udw=="


@pytest.fixture(autouse=True)
def _clean_global_state() -> Iterator[None]:
    """The CLI registers the real password globally; never let that bleed into other tests."""
    clear_registered_secrets()
    yield
    clear_registered_secrets()
    configure_logging("WARNING", "console", stream=io.StringIO())


async def _write_audit(engine: AsyncEngine, **kwargs: object) -> int:
    async with session_factory(engine)() as session, session.begin():
        event = await record_audit(session, **kwargs)  # type: ignore[arg-type]
        return event.id


async def _stored_row(engine: AsyncEngine, event_id: int) -> str:
    async with engine.connect() as conn:
        row = (
            await conn.execute(
                text(
                    "SELECT actor, action, target_type, target_id, correlation_id, details::text "
                    "FROM audit_events WHERE id = :i"
                ),
                {"i": event_id},
            )
        ).one()
    return " | ".join(str(value) for value in row)


def _point_cli_at(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    db_settings: DatabaseSettings,
    database: str,
    password: str,
    owner: str,
) -> None:
    """Configure the CLI through environment variables only (cwd has no .env)."""
    monkeypatch.chdir(tmp_path)
    values = {
        "HOST": db_settings.host,
        "PORT": str(db_settings.port),
        "USER": db_settings.user,
        "PASSWORD": password,
        "OWNER_USER": db_settings.owner_user,
        "OWNER_PASSWORD": owner,
        "NAME": database,
    }
    for key, value in values.items():
        monkeypatch.setenv(f"ARGUS_DATABASE__{key}", value)
    monkeypatch.setenv("ARGUS_LOGGING__LEVEL", "DEBUG")
    # no units on this host to compare (a CI runner has none): empty runs none
    monkeypatch.setenv("ARGUS_UNITS__RUN", "")
    # an organisation domain, as THROWAWAY_SITE gives: a checkout with no site yet fails doctor
    monkeypatch.setenv("ARGUS_SITE__OWN_DOMAINS", "example.test")
    # Safety: the CLI must only ever touch the throwaway database.
    effective = load_settings(CONFIG).database.name
    assert effective == database
    assert effective.startswith(TEST_DB_PREFIX)


# --------------------------------------------------------------------------- audit trail


async def test_audit_free_text_columns_are_redacted_before_storage(
    migrated_engine: AsyncEngine,
) -> None:
    """DEFECT: record_audit redacts ``details`` only; target_id and correlation_id are stored
    verbatim. audit_events is append-only by trigger, so a credential written there can never
    be removed without a privileged migration."""
    es_password = "fake-es-pw-Adv8812"
    bearer = "fake-bearer-Adv3301x"
    event_id = await _write_audit(
        migrated_engine,
        actor="gateway",
        action="elastic.connect",
        target_type="cluster",
        target_id=f"https://elastic:{es_password}@10.0.0.9:9200",
        correlation_id=f"Bearer {bearer}",
    )
    stored = await _stored_row(migrated_engine, event_id)
    assert es_password not in stored
    assert bearer not in stored
    assert "10.0.0.9:9200" in stored


async def test_audit_details_with_camel_case_secret_keys_are_masked(
    migrated_engine: AsyncEngine,
) -> None:
    """DEFECT (key-name gap, permanent impact): JSON from HTTP APIs is camelCase; values under
    ``accessToken`` / ``newPassword`` are written to the append-only audit trail in clear."""
    event_id = await _write_audit(
        migrated_engine,
        actor="gateway",
        action="token.refresh",
        details={
            "response": {"accessToken": "fake-camel-tok-Adv8807", "expiresIn": 3600},
            "change": {"newPassword": "fake-camel-pw-Adv9908"},
        },
    )
    stored = await _stored_row(migrated_engine, event_id)
    assert "fake-camel-tok-Adv8807" not in stored
    assert "fake-camel-pw-Adv9908" not in stored
    assert "3600" in stored


async def test_audit_details_secret_shapes_are_masked_in_storage(
    migrated_engine: AsyncEngine,
) -> None:
    groq = "gsk_" + "Ab1" * 18
    pem_body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC"
    planted = [
        FAKE_ES_APIKEY,
        "fake-xapikey-Adv2201",
        "fake-secret-dsn-Adv3302",
        "fake-note-pw-Adv4403",
        groq,
        pem_body,
        "fake-batch-tok-Adv5504",
        "fake-nested-Adv6605",
        "fake-secret-es-url-Adv7706",
    ]
    event_id = await _write_audit(
        migrated_engine,
        actor="gateway",
        action="elastic.search",
        details={
            "request": {
                "headers": {
                    "Authorization": f"ApiKey {FAKE_ES_APIKEY}",
                    "X-Api-Key": "fake-xapikey-Adv2201",
                }
            },
            "dsn": "postgresql+psycopg://argus:fake-secret-dsn-Adv3302@db.internal:5432/argus",
            "note": "password=fake-note-pw-Adv4403; retry=3",
            "provider": f"calling groq with {groq}",
            "pem": "-----BEGIN PRIVATE KEY-----"  # fake-secret
            f"\n{pem_body}\n-----END PRIVATE KEY-----",
            "batch": [
                {"token": "fake-batch-tok-Adv5504"},
                ("client_secret", {"secret": "fake-nested-Adv6605"}),
            ],
            "es_url": "https://elastic:fake-secret-es-url-Adv7706@10.0.0.9:9200/_search",
        },
    )
    stored = await _stored_row(migrated_engine, event_id)
    assert [value for value in planted if value in stored] == []
    assert stored.count(MASK) >= len(planted)
    for useful in ("db.internal:5432", "retry=3", "10.0.0.9:9200/_search", "calling groq"):
        assert useful in stored


# --------------------------------------------------------------------------- exception text


async def test_db_errors_do_not_embed_bound_parameter_values(empty_engine: AsyncEngine) -> None:
    """DEFECT: the engine is created without ``hide_parameters=True``, so every DBAPIError carries
    ``[parameters: {...}]`` with raw bound values in str(exc), in tracebacks and in logged
    exceptions. Values with no registered value and no known shape (here an Elasticsearch API
    key; later, raw production alert fields) cannot be caught by redaction afterwards."""
    with pytest.raises(DBAPIError) as info:
        async with empty_engine.connect() as conn:
            await conn.execute(
                text("SELECT CAST(:credential_ref AS text) AS ref, 1 / 0 AS boom"),
                {"credential_ref": FAKE_ES_APIKEY},
            )
    stream = io.StringIO()
    configure_logging("INFO", "json", stream=stream)
    get_logger("argus.test").error("query failed", exc_info=info.value)
    assert "division by zero" in stream.getvalue()
    assert FAKE_ES_APIKEY not in str(info.value)
    assert FAKE_ES_APIKEY not in stream.getvalue()


async def test_connection_failure_text_and_logs_never_contain_the_password(
    db_settings: DatabaseSettings, test_database: str
) -> None:
    wrong = "fake-wrong-pw-Adv7070"
    engine = create_engine(
        db_settings.model_copy(update={"password": SecretStr(wrong)}), database=test_database
    )
    try:
        with pytest.raises(OperationalError) as info:
            async with engine.connect():
                pass
    finally:
        await engine.dispose()
    stream = io.StringIO()
    configure_logging("DEBUG", "json", stream=stream)
    get_logger("argus.test").error("connect failed", exc_info=info.value)
    for rendering in (str(info.value), repr(info.value), str(info.value.orig), stream.getvalue()):
        assert wrong not in rendering
    assert "password authentication failed" in stream.getvalue()


# --------------------------------------------------------------------------- CLI


def test_cli_lifecycle_with_password_from_environment_never_prints_it(
    db_settings: DatabaseSettings,
    test_database: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert db_settings.password is not None
    password = db_settings.password.get_secret_value()
    owner = owner_password(db_settings)
    _point_cli_at(monkeypatch, tmp_path, db_settings, test_database, password, owner)

    steps = [
        (["doctor"], 1),  # not migrated yet
        (["db", "upgrade"], 0),
        (["db", "current"], 0),
        (["db", "check"], 0),
        (["doctor"], 0),
        (["config", "show"], 0),
    ]
    codes: list[int] = []
    leaked: list[str] = []
    for args, _ in steps:
        result = runner.invoke(app, [*args, "-c", str(CONFIG)])
        codes.append(result.exit_code)
        if any(secret in result.output + result.stderr for secret in (password, owner)):
            leaked.append(" ".join(args))
    assert leaked == []
    assert codes == [code for _, code in steps]

    with psycopg.connect(
        host=db_settings.host,
        port=db_settings.port,
        user=db_settings.user,
        password=password,
        dbname=test_database,
    ) as conn:
        rows = conn.execute(
            "SELECT actor, action, target_type, target_id, correlation_id, details::text "
            "FROM audit_events"
        ).fetchall()
    assert len(rows) == 1
    audit_holds_password = any(
        secret in str(value) for row in rows for value in row for secret in (password, owner)
    )
    assert not audit_holds_password

    result = runner.invoke(app, ["db", "downgrade", "base", "--yes", "-c", str(CONFIG)])
    assert result.exit_code == 0
    shown = result.output + result.stderr
    downgrade_printed_password = password in shown or owner in shown
    assert not downgrade_printed_password


@pytest.mark.parametrize(
    "command",
    [["doctor"], ["db", "current"], ["db", "check"], ["db", "upgrade"]],
    ids=["doctor", "db-current", "db-check", "db-upgrade"],
)
def test_cli_with_wrong_password_fails_cleanly_without_echoing_it(
    db_settings: DatabaseSettings,
    test_database: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: list[str],
) -> None:
    wrong = "fake-wrong-pw-Adv6060"  # for both logins: doctor is the runtime role, db the owner
    _point_cli_at(monkeypatch, tmp_path, db_settings, test_database, wrong, wrong)
    result = runner.invoke(app, [*command, "-c", str(CONFIG)])
    output = result.output + result.stderr
    assert result.exit_code == 1, output
    assert "password authentication failed" in output
    assert wrong not in output
    assert "Traceback" not in output
