"""D-297: init's checks of the read key go through the gateway (the ledger, the health state) on
Postgres state, against a scripted SIEM: an API key with ``monitor`` and ``read`` and no write
passes; a key that holds a write canary, lacks a read, or is no API key is named."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.config.settings import DatabaseSettings, Settings, SiemSettings
from argus.gateway.builtin import CANARY_CLUSTER, CANARY_INDEX, REQUIRED_CLUSTER, REQUIRED_INDEX
from argus.install.siem import GatewayReads
from tests.integration.conftest import admin_connect
from tests.integration.gateway.test_service import NODE
from tests.unit.gateway.fakes import FakeTransport, ok

pytestmark = pytest.mark.integration

NAMES = [".alerts-security.alerts-*", ".internal.alerts-security.alerts-*", "logs-*"]


def _held(**overrides: bool) -> dict[str, Any]:
    index = {
        name: {**dict.fromkeys(REQUIRED_INDEX, True), **dict.fromkeys(CANARY_INDEX, False)}
        for name in NAMES
    }
    cluster = {**dict.fromkeys(REQUIRED_CLUSTER, True), **dict.fromkeys(CANARY_CLUSTER, False)}
    for key, value in overrides.items():
        if key in cluster:
            cluster[key] = value
        else:
            index["logs-*"][key] = value
    return {"cluster": cluster, "index": index}


def _settings(db_settings: DatabaseSettings, test_database: str) -> Settings:
    return Settings(
        database=db_settings.model_copy(update={"name": test_database}),
        siem=SiemSettings(url="https://10.20.60.11:9200", api_key=SecretStr("a-test-key-value")),
    )


def _check(settings: Settings, auth: Any, held: Any) -> tuple[list[str], FakeTransport]:
    sender = FakeTransport()
    sender.on("_nodes", ok(NODE)).on("_authenticate", ok(auth)).on("_has_privileges", ok(held))
    return GatewayReads(sender).check_key(settings, NAMES), sender


@pytest.mark.parametrize(
    ("auth", "held", "problems"),
    [
        ({"authentication_type": "api_key"}, _held(), []),
        ({"authentication_type": "realm"}, _held(),
         ["the key does not authenticate as an API key"]),
        ({"authentication_type": "api_key"}, _held(write=True), ["holds write on logs-*"]),
        ({"authentication_type": "api_key"}, _held(read=False), ["lacks read on logs-*"]),
        ({"authentication_type": "api_key"}, _held(manage_security=True),
         ["holds cluster privilege manage_security"]),
    ],
)  # fmt: skip
def test_the_key_check_names_what_is_wrong(
    app_engine: AsyncEngine,
    db_settings: DatabaseSettings,
    test_database: str,
    auth: Any,
    held: Any,
    problems: list[str],
) -> None:
    found, sender = _check(_settings(db_settings, test_database), auth, held)
    assert found == problems
    asked = [call for call in sender.calls if "_has_privileges" in call.path]
    assert len(asked) == 1
    assert '"logs-*"' in asked[0].body.decode()  # type: ignore[union-attr]


def test_the_reads_are_in_the_ledger_and_nothing_is_remembered(
    app_engine: AsyncEngine, db_settings: DatabaseSettings, test_database: str
) -> None:
    settings = _settings(db_settings, test_database)
    found, _ = _check(settings, {"authentication_type": "api_key"}, _held())
    assert found == []
    with admin_connect(db_settings, test_database) as conn:
        rows = conn.execute("SELECT template FROM siem_requests WHERE component = 'init'")
        templates = sorted(str(row[0]) for row in rows.fetchall())
        probes = conn.execute("SELECT count(*) FROM siem_probes").fetchone()
    assert templates == ["health.node_stats", "security.authenticate", "security.has_privileges"]
    assert probes == (0,)  # a partial probe is never saved over the real memory
