"""Q-A2's settings: every secret registered for redaction (the writer key was missed when they
were listed by hand), the web's own login, recorded key expiries, the web certificate's pin and
the backups, each default and bound written out."""

from __future__ import annotations

import os
import typing
from datetime import date
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import BaseModel, SecretStr, ValidationError

from argus.config import ConfigError, DatabaseSettings, Settings, load_settings
from argus.config.settings import (
    POSTGRES_IMAGE,
    BackupSettings,
    CaseTeamSettings,
    KibanaSettings,
    NoticesSettings,
    OutsideSettings,
    SiemSettings,
    WebSettings,
)
from argus.ops.backup import Tools
from tests.conftest import REPO_ROOT

pytestmark = pytest.mark.unit

SECRETS = {
    ("database", "password"): "Synthetic-Runtime-11",
    ("database", "owner_password"): "Synthetic-Owner-22",
    ("database", "api_password"): "Synthetic-Web-33",
    ("database", "writer_password"): "Synthetic-DbWriter-99",  # Q-D4
    ("siem", "api_key"): "Synthetic-Reader-44",
    ("siem", "writer_api_key"): "Synthetic-Writer-55",
    ("outside", "virustotal_api_key"): "Synthetic-VirusTotal-12",  # AR3
    ("outside", "shodan_api_key"): "Synthetic-Shodan-13",
    ("outside", "censys_api_key"): "Synthetic-Censys-14",
    ("kibana", "reader_api_key"): "Synthetic-KibanaReader-66",  # Q-D2
    ("kibana", "cases_writer_api_key"): "Synthetic-CasesWriter-77",
    ("kibana", "alert_writer_api_key"): "Synthetic-AlertWriter-88",
    ("case_team", "lead_api_key"): "Synthetic-TeamLead-31",  # AR8
    ("case_team", "evidence_api_key"): "Synthetic-TeamEvidence-32",
    ("case_team", "intel_api_key"): "Synthetic-TeamIntel-33",
    ("case_team", "responder_api_key"): "Synthetic-TeamResponder-34",
    ("case_team", "hunter_api_key"): "Synthetic-TeamHunter-35",
    ("case_team", "reporter_api_key"): "Synthetic-TeamReporter-36",
    ("case_team", "visualiser_api_key"): "Synthetic-TeamVisualiser-37",  # AR10
    ("notices", "password"): "Synthetic-Relay-11",  # Q-H4
}


def secret_fields(model: type[BaseModel], prefix: tuple[str, ...] = ()) -> list[tuple[str, ...]]:
    """Every SecretStr field, found from the annotations alone (independent of the code under
    test, which walks values)."""
    found = []
    for name, info in model.model_fields.items():
        annotation = info.annotation
        args = typing.get_args(annotation)
        if annotation is SecretStr or SecretStr in args:
            found.append((*prefix, name))
        elif isinstance(annotation, type) and issubclass(annotation, BaseModel):
            found += secret_fields(annotation, (*prefix, name))
    return found


def test_every_secret_setting_is_known_to_this_test() -> None:
    """A new SecretStr setting fails here until it is added to SECRETS (and so registered)."""
    assert set(secret_fields(Settings)) == set(SECRETS)


def test_every_secret_is_registered_for_redaction() -> None:
    sections: dict[str, dict[str, Any]] = {}
    for (section, field), value in SECRETS.items():
        sections.setdefault(section, {})[field] = SecretStr(value)
    settings = Settings(
        database=DatabaseSettings(**sections["database"]),
        siem=SiemSettings(**sections["siem"]),
        kibana=KibanaSettings(**sections["kibana"]),
        case_team=CaseTeamSettings(**sections["case_team"]),
        notices=NoticesSettings(**sections["notices"]),
        outside=OutsideSettings(**sections["outside"]),
    )
    assert settings.secret_values() == list(SECRETS.values())  # declaration order


def test_the_writer_key_from_dotenv_is_registered(tmp_path: Path) -> None:
    """DEFECT (Q-A2): secret_values listed the database passwords and the reader key by hand and
    left the writer key out, so it was never masked in logs."""
    dotenv = tmp_path / "secret.env"
    dotenv.write_text("ARGUS_SIEM__WRITER_API_KEY=Synthetic-Writer-66\n")
    config = tmp_path / "argus.yaml"
    config.write_text("environment: dev\n")
    settings = load_settings(config, env_file=dotenv)
    assert "Synthetic-Writer-66" in settings.secret_values()


def test_empty_secrets_are_not_registered() -> None:
    settings = Settings(database=DatabaseSettings(password=SecretStr("")))
    assert settings.secret_values() == []


def test_the_new_defaults() -> None:
    database = DatabaseSettings()
    assert (database.api_user, database.api_password) == ("argus_api", None)
    siem = SiemSettings()
    assert (siem.api_key_expires, siem.writer_api_key_expires) == (None, None)
    web = WebSettings()
    assert (web.database_role, web.tls_pin_sha256) == ("app", None)
    b = BackupSettings()
    assert (b.dir, b.keep_nightly, b.keep_verified, b.keep_migration, b.keep_manual) == (
        Path("data/backups"), 7, 4, 5, 5)  # fmt: skip
    assert (b.before_migration, b.tools, b.image) == (False, "image", POSTGRES_IMAGE)


@pytest.mark.parametrize(
    ("field", "low", "high"),
    [("keep_nightly", 1, 90), ("keep_verified", 1, 52), ("keep_migration", 1, 50),
     ("keep_manual", 1, 50)],
)  # fmt: skip
def test_the_backup_bounds_are_inclusive(field: str, low: int, high: int) -> None:
    for good in (low, high):
        BackupSettings.model_validate({field: good})
    for bad in (low - 1, high + 1):
        with pytest.raises(ValidationError):
            BackupSettings.model_validate({field: bad})


@pytest.mark.parametrize(
    "image",
    [
        "postgres:17-alpine",  # a tag alone moves
        "postgres@sha256:" + "a" * 64,  # no tag
        "postgres:17-alpine@sha256:" + "a" * 63,
        "postgres:17-alpine@sha256:" + "A" * 64,
        "postgres:17 alpine@sha256:" + "a" * 64,
    ],
)
def test_the_backup_image_must_be_pinned_by_digest(image: str) -> None:
    with pytest.raises(ValidationError):
        BackupSettings(image=image)


def test_the_backup_image_is_the_one_docker_compose_pins() -> None:
    compose = yaml.safe_load((REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    assert compose["services"]["db"]["image"] == POSTGRES_IMAGE


def test_the_committed_configuration_never_dumps_through_a_container(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """QA2-R1: every checkout loads config/argus.yaml, and docker-compose.yml names its project
    ``argus``, so ``docker compose exec db`` from any stream's worktree reaches production's
    container argus-db. The committed file switches no dump on and leaves the tools at
    ``image``: production turns the dump before migrations on in its own .env (a production
    step), and no checkout builds a ``docker compose ... exec db`` command unless its .env asks."""
    for name in list(os.environ):
        if name.upper().startswith("ARGUS_BACKUP__"):
            monkeypatch.delenv(name)
    data = yaml.safe_load((REPO_ROOT / "config" / "argus.yaml").read_text(encoding="utf-8"))
    assert "before_migration" not in (data.get("backup") or {})
    assert "tools" not in (data.get("backup") or {})
    settings = load_settings(REPO_ROOT / "config" / "argus.yaml", env_file=None)
    assert (settings.backup.before_migration, settings.backup.tools) == (False, "image")
    tools = Tools(settings.backup, settings.database)
    for command in (tools.dump("argus_p3_x", "snap"), tools.restore("x"), tools.version()):
        assert command[:3] == ["docker", "run", "--rm"], command
        assert "compose" not in command
        assert "exec" not in command


@pytest.mark.parametrize(
    "pin", ["a" * 63, "a" * 65, "A" * 64, "g" * 64, "aa:" * 21 + "a", " " + "a" * 63]
)
def test_the_web_certificate_pin_is_64_lowercase_hex(pin: str) -> None:
    with pytest.raises(ValidationError):
        WebSettings(tls_pin_sha256=pin)
    assert WebSettings(tls_pin_sha256="0" * 64).tls_pin_sha256 == "0" * 64


def test_the_web_uses_one_of_two_logins() -> None:
    assert WebSettings(database_role="api").database_role == "api"
    with pytest.raises(ValidationError):
        WebSettings(database_role="owner")  # type: ignore[arg-type]


@pytest.mark.parametrize("name", ["argus_app", "argus"])
def test_the_web_login_is_a_role_of_its_own(name: str) -> None:
    with pytest.raises(ValidationError, match="api_user must be a role of its own"):
        DatabaseSettings(api_user=name)


def test_the_web_login_url_and_its_missing_password() -> None:
    database = DatabaseSettings(api_password=SecretStr("Synthetic-Web-77"))
    url = database.url(role="api")
    assert (url.username, url.password) == ("argus_api", "Synthetic-Web-77")
    with pytest.raises(ConfigError) as missing:
        DatabaseSettings().url(role="api")
    assert str(missing.value) == (
        "the web's database password is not set; put ARGUS_DATABASE__API_PASSWORD in .env and"
        " run `argus db bootstrap` (it makes the login)"
    )
    unusable = DatabaseSettings().model_copy(update={"api_password": SecretStr("a\x00b")})
    with pytest.raises(ConfigError, match=r"^database\.api_password must not contain a NUL"):
        unusable.url(role="api")


def test_key_expiries_are_days(tmp_path: Path) -> None:
    config = tmp_path / "argus.yaml"
    config.write_text("siem:\n  api_key_expires: 2027-01-10\n  writer_api_key_expires: null\n")
    siem = load_settings(config, env_file=None).siem
    assert (siem.api_key_expires, siem.writer_api_key_expires) == (date(2027, 1, 10), None)
    config.write_text("siem:\n  api_key_expires: soon\n")
    with pytest.raises(ConfigError, match=r"siem\.api_key_expires"):
        load_settings(config, env_file=None)


@pytest.mark.parametrize("group", ["argus_runtime", "argus_web"])
def test_the_owner_may_not_be_one_of_argus_group_roles(group: str) -> None:
    """Bootstrap puts a group role back to NOLOGIN: an owner of that name would be locked out."""
    from argus.db import roles

    settings = DatabaseSettings(owner_user=group, password=SecretStr("Synthetic-Runtime-11"))
    with pytest.raises(ConfigError, match=f"database.owner_user may not be {group}"):
        roles.check_bootstrap_settings(settings)


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        ("argus_app", "must be a role of its own"),
        ("argus", "must be a role of its own"),
        ("argus_runtime", "may not be argus_runtime"),
        ("argus_web", "may not be argus_web"),
        ("pg_web", "may not be pg_web"),
        ("public", "may not be public"),
        ("Argus_Api", "must be lowercase letters"),
        ("9api", "must be lowercase letters"),
    ],
)
def test_the_web_login_name_must_be_its_own_plain_name(name: str, reason: str) -> None:
    from argus.db import roles

    base = DatabaseSettings(api_password=SecretStr("Synthetic-Web-33"))
    with pytest.raises(ConfigError, match=reason):
        roles.check_api_settings(base.model_copy(update={"api_user": name}))
    roles.check_api_settings(base)  # argus_api: fine
    for bad in (None, SecretStr(""), SecretStr("a\x00b")):
        with pytest.raises(ConfigError, match=r"(?i)api_password"):
            roles.check_api_settings(base.model_copy(update={"api_password": bad}))
