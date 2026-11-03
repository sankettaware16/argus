"""Q-A5's code side: secrets from systemd's credential directory, and under custody each account
holds only its own (the owner's password never reaches a service, a writer key only the writer).
Both layouts: without ``custody.role`` nothing changes."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.config import ConfigError, load_settings
from argus.config.settings import CUSTODY_SECRETS, Settings, secret_settings
from argus.config.sources import MAX_CREDENTIALS, credentials_layer
from argus.llm.providers import KEYS_CREDENTIAL, load_keys
from argus.observability.redaction import clear_registered_secrets

pytestmark = pytest.mark.unit

VALUES = {
    "database.password": "Synthetic-Runtime-11",
    "database.owner_password": "Synthetic-Owner-22",
    "database.api_password": "Synthetic-Web-33",
    "database.writer_password": "Synthetic-DbWriter-99",
    "siem.api_key": "Synthetic-Reader-44",
    "siem.writer_api_key": "Synthetic-Writer-55",
    "kibana.reader_api_key": "Synthetic-KibanaReader-66",
    "kibana.cases_writer_api_key": "Synthetic-CasesWriter-77",
    "kibana.alert_writer_api_key": "Synthetic-AlertWriter-88",
    "case_team.lead_api_key": "Synthetic-TeamLead-31",  # AR8
    "case_team.evidence_api_key": "Synthetic-TeamEvidence-32",
    "case_team.intel_api_key": "Synthetic-TeamIntel-33",
    "case_team.responder_api_key": "Synthetic-TeamResponder-34",
    "case_team.hunter_api_key": "Synthetic-TeamHunter-35",
    "case_team.reporter_api_key": "Synthetic-TeamReporter-36",
    "case_team.visualiser_api_key": "Synthetic-TeamVisualiser-37",  # AR10
    "notices.password": "Synthetic-Relay-11",
    "outside.virustotal_api_key": "Synthetic-VirusTotal-12",  # AR3
    "outside.shodan_api_key": "Synthetic-Shodan-13",
    "outside.censys_api_key": "Synthetic-Censys-14",
}


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    for key in list(os.environ):
        if key.upper().startswith("ARGUS_") or key == "CREDENTIALS_DIRECTORY":
            monkeypatch.delenv(key)
    monkeypatch.chdir(tmp_path)
    clear_registered_secrets()
    yield
    clear_registered_secrets()


def credentials(tmp_path: Path, names: dict[str, str | bytes]) -> Path:
    folder = tmp_path / "creds"
    folder.mkdir(exist_ok=True)
    for name, value in names.items():
        data = value if isinstance(value, bytes) else value.encode()
        (folder / name).write_bytes(data)
    return folder


def load(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, folder: Path | None, **env: str):  # type: ignore[no-untyped-def]
    config = tmp_path / "argus.yaml"
    config.write_text("", encoding="utf-8")
    if folder is not None:
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(folder))
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    return load_settings(config, env_file=tmp_path / ".env")


# --------------------------------------------------------------------------- the credential layer


def test_a_credential_sets_its_secret_without_the_final_line_break(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    folder = credentials(
        tmp_path,
        {
            "database.password": "pw-one\n",
            "siem.api_key": "key two\r\n",
            "database.api_password": "kept\n\n",  # only one line break goes
            "web-tls.key": "Synthetic-TLS-Key\n",  # a file credential: not read here
            "llm-api-keys.env": "GROQ_API_KEY=x\n",
        },
    )
    s = load(tmp_path, monkeypatch, folder)
    assert s.database.password is not None
    assert s.database.password.get_secret_value() == "pw-one"
    assert s.siem.api_key is not None
    assert s.siem.api_key.get_secret_value() == "key two"
    assert s.database.api_password is not None
    assert s.database.api_password.get_secret_value() == "kept\n"
    assert "pw-one" in s.secret_values()


def test_credentials_beat_the_environment_and_dotenv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / ".env").write_text("ARGUS_DATABASE__PASSWORD=from-dotenv\n")
    folder = credentials(tmp_path, {"database.password": "from-credential"})
    s = load(tmp_path, monkeypatch, folder, ARGUS_DATABASE__PASSWORD="from-env")
    assert s.database.password is not None
    assert s.database.password.get_secret_value() == "from-credential"
    # without a credential directory: as before Q-A5
    monkeypatch.delenv("CREDENTIALS_DIRECTORY")
    s = load(tmp_path, monkeypatch, None)
    assert s.database.password is not None
    assert s.database.password.get_secret_value() == "from-env"


@pytest.mark.parametrize(
    ("name", "message"),
    [
        ("history.window", "credential history.window is not a secret setting (it is not secret)"),
        ("database.host", "credential database.host is not a secret setting (it is not secret)"),
        ("database.pasword", "credential database.pasword is not a secret setting"),
        ("nosuch.thing", "credential nosuch.thing is not a secret setting"),
    ],
)
def test_a_credential_named_like_another_setting_is_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, message: str
) -> None:
    folder = credentials(tmp_path, {name: "Synthetic-Value-77"})
    with pytest.raises(ConfigError) as error:
        load(tmp_path, monkeypatch, folder)
    assert message in str(error.value)
    assert "Synthetic-Value-77" not in str(error.value)


def test_an_empty_credential_is_an_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    folder = credentials(tmp_path, {"database.password": "\n"})
    with pytest.raises(ConfigError, match=r"credential database\.password is empty"):
        load(tmp_path, monkeypatch, folder)


def test_a_credential_that_is_no_file_or_not_text_is_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    folder = credentials(tmp_path, {})
    (folder / "database.password").mkdir()
    with pytest.raises(ConfigError, match="it is a directory"):
        load(tmp_path, monkeypatch, folder)
    (folder / "database.password").rmdir()
    (folder / "database.password").write_bytes(b"\xff\xfe-not-utf8")
    with pytest.raises(ConfigError, match=r"credential database\.password is not UTF-8"):
        load(tmp_path, monkeypatch, folder)


def test_a_missing_or_crowded_credential_directory_is_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(ConfigError, match=r"\(CREDENTIALS_DIRECTORY\) does not exist"):
        load(tmp_path, monkeypatch, tmp_path / "nowhere")
    folder = credentials(tmp_path, {f"file-{i}": "x" for i in range(MAX_CREDENTIALS + 1)})
    with pytest.raises(ConfigError, match="holds more than 64 files"):
        credentials_layer(folder, Settings)
    assert credentials_layer(None, Settings) is None


def test_an_empty_credentials_variable_means_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", "")
    assert load(tmp_path, monkeypatch, None).database.password is None


_SECRET_TEXT = st.text(
    st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00"), min_size=1
).filter(lambda v: v.strip("\r\n") == v and v.strip() != "")


@given(value=_SECRET_TEXT, newline=st.sampled_from(["", "\n", "\r\n"]))
def test_any_secret_round_trips_through_a_credential(value: str, newline: str) -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as raw:
        folder = Path(raw)
        (folder / "siem.api_key").write_bytes((value + newline).encode())
        layer = credentials_layer(folder, Settings)
    assert layer is not None
    assert layer.problems == []
    assert layer.data["siem"]["api_key"].get_secret_value() == value
    assert layer.origins[("siem", "api_key")] == "credential siem.api_key"


# --------------------------------------------------------------------------- custody roles


def test_every_secret_setting_has_an_account_and_the_dangerous_ones_only_theirs() -> None:
    held = set().union(*CUSTODY_SECRETS.values())
    assert set(secret_settings()) == held, "a new secret needs an account (CUSTODY_SECRETS)"
    assert [r for r, s in CUSTODY_SECRETS.items() if "database.owner_password" in s] == ["owner"]
    assert [r for r, s in CUSTODY_SECRETS.items() if "siem.writer_api_key" in s] == ["writer"]
    assert set(CUSTODY_SECRETS) == {"svc", "web", "writer", "owner"}


@pytest.mark.parametrize("role", ["svc", "web", "writer", "owner"])
def test_each_account_starts_with_exactly_its_own_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, role: str
) -> None:
    folder = credentials(tmp_path, {name: VALUES[name] for name in CUSTODY_SECRETS[role]})
    env = {"ARGUS_CUSTODY__ROLE": role}
    if role == "web":
        env["ARGUS_WEB__DATABASE_ROLE"] = "api"
    s = load(tmp_path, monkeypatch, folder, **env)
    assert s.custody.role == role


@pytest.mark.parametrize(
    ("role", "secret"),
    [
        (role, secret)
        for role, allowed in CUSTODY_SECRETS.items()
        for secret in secret_settings()
        if secret not in allowed
    ],
)
def test_a_secret_an_account_must_not_hold_stops_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, role: str, secret: str
) -> None:
    folder = credentials(tmp_path, {secret: VALUES[secret]})
    env = {"ARGUS_CUSTODY__ROLE": role, "ARGUS_WEB__DATABASE_ROLE": "api"}
    with pytest.raises(ConfigError) as error:
        load(tmp_path, monkeypatch, folder, **env)
    text = str(error.value)
    assert f"{secret} is given to the {role} account, which must not hold it (Q-A5)" in text
    assert VALUES[secret] not in text


@pytest.mark.parametrize("where", ["environment", "dotenv", "yaml"])
def test_under_custody_a_secret_comes_only_from_its_credential(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, where: str
) -> None:
    folder = credentials(tmp_path, {})
    env = {"ARGUS_CUSTODY__ROLE": "svc"}
    if where == "environment":
        env["ARGUS_SIEM__API_KEY"] = VALUES["siem.api_key"]
        origin = "environment variable ARGUS_SIEM__API_KEY"
    elif where == "dotenv":
        (tmp_path / ".env").write_text(f"ARGUS_SIEM__API_KEY={VALUES['siem.api_key']}\n")
        origin = "ARGUS_SIEM__API_KEY in .env line 1"
    else:
        (tmp_path / "argus.yaml").write_text(f"siem:\n  api_key: {VALUES['siem.api_key']}\n")
        origin = "argus.yaml line 2"
    config = tmp_path / "argus.yaml"
    if where != "yaml":
        config.write_text("", encoding="utf-8")
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(folder))
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    with pytest.raises(ConfigError) as error:
        load_settings(config, env_file=tmp_path / ".env")
    text = str(error.value)
    assert f"siem.api_key is set by {origin}" in text
    assert "comes only from its credential" in text
    assert VALUES["siem.api_key"] not in text


def test_the_owner_password_in_the_shared_env_stops_a_service(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The plan's case: the shared .env every process loads holds the owner password."""
    (tmp_path / ".env").write_text(
        f"ARGUS_DATABASE__OWNER_PASSWORD={VALUES['database.owner_password']}\n"
    )
    folder = credentials(tmp_path, {"database.password": VALUES["database.password"]})
    with pytest.raises(ConfigError) as error:
        load(tmp_path, monkeypatch, folder, ARGUS_CUSTODY__ROLE="svc")
    text = str(error.value)
    assert "database.owner_password is given to the svc account" in text
    assert "only owner may" in text
    assert "database.owner_password is set by ARGUS_DATABASE__OWNER_PASSWORD in .env" in text


def test_the_web_under_custody_logs_in_as_its_own_login(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    folder = credentials(tmp_path, {"database.api_password": VALUES["database.api_password"]})
    with pytest.raises(ConfigError, match=r"web.database_role: api"):
        load(tmp_path, monkeypatch, folder, ARGUS_CUSTODY__ROLE="web")


def test_without_a_role_nothing_changes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The shared layout: every secret from .env, as today."""
    (tmp_path / ".env").write_text(
        "".join(f"ARGUS_{k.replace('.', '__').upper()}={v}\n" for k, v in VALUES.items())
    )
    s = load(tmp_path, monkeypatch, None)
    assert s.custody.role is None
    assert sorted(s.secret_values()) == sorted(VALUES.values())


def test_an_unknown_role_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ConfigError, match=r"custody\.role"):
        load(tmp_path, monkeypatch, None, ARGUS_CUSTODY__ROLE="root")


# --------------------------------------------------------------------------- LLM keys


def test_llm_keys_come_from_the_credential_under_custody(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    checkout_file = tmp_path / "keys.env"
    checkout_file.write_text("GROQ_API_KEY=from-checkout\n")
    assert load_keys(checkout_file, {"GROQ_API_KEY"})["GROQ_API_KEY"].get_secret_value() == (
        "from-checkout"
    )
    folder = credentials(tmp_path, {})
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(folder))
    assert load_keys(checkout_file, {"GROQ_API_KEY"}) == {}  # never the checkout's file
    (folder / KEYS_CREDENTIAL).write_text("GROQ_API_KEY=from-credential\nOTHER=x\n")
    keys = load_keys(checkout_file, {"GROQ_API_KEY"})
    assert {k: v.get_secret_value() for k, v in keys.items()} == {"GROQ_API_KEY": "from-credential"}
