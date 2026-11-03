"""The identity lane's settings and ``argus identity check|map|state`` (Q-E1): the timeouts
of plan §5, DQ15's setting, the names refused, getpass only, the dry run sends nothing."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any

import pydantic
import pytest
from pydantic import SecretStr
from typer.testing import CliRunner

from argus.config.settings import IdentitySettings, KibanaSettings, Settings
from argus.gateway.gateway import LaneGate
from argus.gateway.health import HealthMemory
from argus.gateway.state import MemoryStore
from argus.identity import cli as identity_cli
from argus.identity import service
from argus.identity.lane import AdminAccounts, IdentityLane
from argus.identity.names import Reason
from argus.identity.transport import Route
from tests.conftest import suite_checkout
from tests.unit.gateway.fakes import FakeClock
from tests.unit.identity.test_lane import T0, ScriptedIdentity, answer, privileges_body, whoami_body

pytestmark = pytest.mark.unit
SECRET = "correct-horse-battery-staple"


def test_defaults_are_plan_s5s() -> None:
    s = IdentitySettings()
    assert (s.connect_timeout, s.timeout) == (timedelta(seconds=3), timedelta(seconds=5))
    assert s.admin_accounts == "refuse"  # DQ15 (a); (b) is the user's at the cutover
    assert s.refused_names == ()


@pytest.mark.parametrize(
    "values",
    [{"timeout": "6s"}, {"timeout": "0s"}, {"connect_timeout": "4s"}, {"connect_timeout": "0s"},
     {"connect_timeout": "3s", "timeout": "2s"}, {"admin_accounts": "allow"},
     {"refused_names": [""]}, {"unknown": 1}],
)  # fmt: skip
def test_bad_values_are_refused(values: dict[str, Any]) -> None:
    with pytest.raises(pydantic.ValidationError):
        IdentitySettings(**values)


def test_refused_names_from_one_string() -> None:
    s = IdentitySettings(refused_names="argus-canary, tier-test")  # type: ignore[arg-type]
    assert s.refused_names == ("argus-canary", "tier-test")


def test_the_lane_from_the_settings() -> None:
    settings = Settings(
        identity=IdentitySettings(
            admin_accounts="without_custody", refused_names=("svc-x",), timeout=timedelta(seconds=4)
        ),
        kibana=KibanaSettings(service_user="argus-kib"),
    )
    policy = service.names(settings)
    assert policy.refusal("svc-x") == Reason.SERVICE
    assert policy.refusal("ARGUS-KIB") == Reason.SERVICE
    assert policy.refusal("argus") == Reason.SERVICE
    assert service.targets(settings).log_patterns == ("acme-logs-*",)
    assert service.targets(settings).space == "acme-soc"
    store = MemoryStore()
    lane = service.build_identity_lane(settings, store, sender=ScriptedIdentity(FakeClock(T0)))
    assert lane.admin_accounts is AdminAccounts.WITHOUT_CUSTODY
    assert lane.timeout_s == 4
    assert lane.index_check is None
    from argus.config.errors import ConfigError

    missing = Settings(siem={"ca_file": "/nonexistent/ca.crt"})  # type: ignore[arg-type]
    with pytest.raises(ConfigError, match="ca_file"):
        service.transport(missing)


def lane_with(transport: ScriptedIdentity) -> IdentityLane:
    store = MemoryStore(memory=HealthMemory(probed_at=T0))
    return IdentityLane(transport, store, LaneGate(store), clock=lambda: T0)


def invoke(monkeypatch: pytest.MonkeyPatch, *args: str, password: str = SECRET,
           tty: bool = True, transport: ScriptedIdentity | None = None) -> Any:  # fmt: skip
    from argus.cli import app

    monkeypatch.chdir(suite_checkout(Path.cwd()))  # the test's own folder (tests/unit)
    monkeypatch.setenv("ARGUS_DATABASE__PASSWORD", "identity-cli-unit")  # fake-secret: no database
    asked: list[str] = []

    def read_password(prompt: str) -> SecretStr:
        asked.append(prompt)
        return SecretStr(password)

    monkeypatch.setattr(identity_cli, "read_password", read_password)
    monkeypatch.setattr(identity_cli, "_at_a_terminal", lambda: tty)
    if transport is not None:
        monkeypatch.setattr(service, "build_identity_lane",
                            lambda *a, **k: lane_with(transport))  # fmt: skip
    result = CliRunner().invoke(app, ["identity", *args])
    result.asked = asked  # type: ignore[attr-defined]
    return result


def test_check_has_no_password_option() -> None:
    import inspect

    params = inspect.signature(identity_cli.identity_check).parameters
    assert set(params) == {"user", "dry_run", "config"}


def test_the_dry_run_sends_nothing_and_asks_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    result = invoke(monkeypatch, "check", "--user", "devuser", "--dry-run")
    assert result.exit_code == 0, result.output
    assert "GET https://" in result.output
    assert "/_security/_authenticate (as devuser)" in result.output
    assert '"argus:approve"' in result.output
    assert "dry run: nothing was sent" in result.output
    assert result.asked == []


@pytest.mark.parametrize("name", ["elastic", "argus", "kibana_system", "bad:name"])
def test_refused_names_ask_for_nothing(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    result = invoke(monkeypatch, "check", "--user", name)
    assert result.exit_code == 1
    assert "refused before any request" in result.output
    assert result.asked == []


def test_only_at_a_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    result = invoke(monkeypatch, "check", "--user", "devuser", tty=False)
    assert result.exit_code == 2
    assert "terminal" in result.output
    assert result.asked == []


def test_a_good_check_prints_the_capabilities(monkeypatch: pytest.MonkeyPatch) -> None:
    transport = ScriptedIdentity(FakeClock(T0))
    transport.on(Route.WHOAMI, answer(whoami_body()))
    transport.on(Route.VERIFY, answer(privileges_body(alerts=("read", "index", "maintenance"))))
    result = invoke(monkeypatch, "check", "--user", "devuser", transport=transport)
    assert result.exit_code == 0, result.output
    assert result.asked == ["ELK password for devuser: "]
    assert "devuser: a native ELK account" in result.output
    assert "use ARGUS" in result.output
    assert "review:" in result.output
    assert SECRET not in result.output
    from pathlib import Path

    for name in ("cmdline", "environ"):  # never on the command line or in the environment
        assert SECRET.encode() not in Path(f"/proc/self/{name}").read_bytes()
    from argus.observability.redaction import redact_text

    assert SECRET not in redact_text(f"a log line holding {SECRET}")  # registered for masking


@pytest.mark.parametrize(
    ("whoami", "code", "text"),
    [
        (
            answer({"error": {"type": "security_exception"}}, 403),
            1,
            "denied by Elasticsearch (forbidden)",
        ),
        (
            answer({"error": {"type": "security_exception"}}, 401),
            3,
            "could not tell (security_index)",
        ),
        (answer({}, 403), 3, "could not tell (not_elasticsearch)"),
        (answer({}, 503), 3, "could not tell (http_503)"),
        (answer(whoami_body(metadata={})), 1, "refused by ARGUS (no_argus_uid)"),
    ],
)
def test_outcomes_and_exit_codes(
    monkeypatch: pytest.MonkeyPatch, whoami: Any, code: int, text: str
) -> None:
    transport = ScriptedIdentity(FakeClock(T0)).on(Route.WHOAMI, whoami)
    result = invoke(monkeypatch, "check", "--user", "devuser", transport=transport)
    assert result.exit_code == code, result.output
    assert text in result.output
    assert SECRET not in result.output


def test_a_short_password_is_refused_with_no_request(monkeypatch: pytest.MonkeyPatch) -> None:
    transport = ScriptedIdentity(FakeClock(T0))
    result = invoke(monkeypatch, "check", "--user", "devuser", password="short",
                    transport=transport)  # fmt: skip
    assert result.exit_code == 1
    assert "short_password" in result.output
    assert transport.calls == []


def test_the_map(monkeypatch: pytest.MonkeyPatch) -> None:
    result = invoke(monkeypatch, "map")
    assert result.exit_code == 0, result.output
    assert "capability map v1 (Kibana 8.19.12, siemV2, securitySolutionCasesV3)" in result.output
    assert "view: Kibana login:, ui:siemV2/show; read on the alerts" in result.output
    assert "refused: superusers" in result.output


def test_a_database_error_is_short(monkeypatch: pytest.MonkeyPatch) -> None:
    from sqlalchemy.exc import OperationalError

    transport = ScriptedIdentity(FakeClock(T0)).on(Route.WHOAMI, answer(whoami_body()))
    lane = lane_with(transport)

    async def broken(now: Any) -> Any:
        raise OperationalError("SELECT", {}, Exception("connection refused"))

    lane.state.identity_reach_admit = broken  # type: ignore[method-assign]
    monkeypatch.setattr(service, "build_identity_lane", lambda *a, **k: lane)
    result = invoke(monkeypatch, "check", "--user", "devuser")
    assert result.exit_code == 2, result.output
    assert "error:" in result.output
    assert "Traceback" not in result.output
