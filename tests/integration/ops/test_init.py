"""P4-D2: ``argus init`` end to end on a throwaway database, from an answers file, with the SIEM,
Kibana, TLS and systemd faked (tests/unit/install/fakes.py): .env, bootstrap and migrations for
real, the SIEM's addresses and trust, the keys, discovery written to config/site.yaml, the LLM
step, the units rendered and installed into a temporary unit directory, and doctor with no
failure on the fresh install. A rerun keeps everything. The web's login is a throwaway one: the
configured login is cluster-wide and may be production's."""

from __future__ import annotations

import base64
import os
import secrets
import shutil
import time
from collections.abc import Iterator
from datetime import date
from pathlib import Path
from typing import Any

import pytest
import yaml
from psycopg import sql

from argus.config.settings import DatabaseSettings
from argus.install.answers import ScriptedAnswers, load_answers
from argus.install.run import BACKUPS, Host, Options, run_init
from argus.ops import units
from tests.conftest import REPO_ROOT, hide_in_reports
from tests.integration.conftest import TEST_ROLE_PATTERN, TEST_ROLE_PREFIX, admin_connect
from tests.unit.install.fakes import Commands, FakeSiem, FakeTls, make_pki

pytestmark = pytest.mark.integration

UV = "/opt/uv/bin/uv"


@pytest.fixture
def checkout(
    tmp_path: Path,
    db_settings: DatabaseSettings,
    test_database: str,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[Path]:
    """A fresh checkout (the shipped config/argus.yaml and docker-compose.yml, nothing else) whose
    .env names the local server's owner and runtime logins and a throwaway web login."""
    root = tmp_path / "argus"
    (root / "config").mkdir(parents=True)
    shutil.copy(REPO_ROOT / "config" / "argus.yaml", root / "config" / "argus.yaml")
    shutil.copy(REPO_ROOT / "docker-compose.yml", root / "docker-compose.yml")
    api_user = f"{TEST_ROLE_PREFIX}{int(time.time())}_{secrets.token_hex(4)}"
    assert TEST_ROLE_PATTERN.fullmatch(api_user)
    assert db_settings.password is not None
    assert db_settings.owner_password is not None
    lines = {
        "ARGUS_DATABASE__OWNER_USER": db_settings.owner_user,
        "ARGUS_DATABASE__OWNER_PASSWORD": db_settings.owner_password.get_secret_value(),
        "ARGUS_DATABASE__USER": db_settings.user,
        "ARGUS_DATABASE__PASSWORD": db_settings.password.get_secret_value(),
        "ARGUS_DATABASE__HOST": db_settings.host,
        "ARGUS_DATABASE__PORT": str(db_settings.port),
        "ARGUS_DATABASE__API_USER": api_user,
        # an existing .env never gets the web's password from init (D-299): this one has it
        "ARGUS_DATABASE__API_PASSWORD": secrets.token_urlsafe(24),
    }
    hide_in_reports(lines["ARGUS_DATABASE__API_PASSWORD"])
    env = root / ".env"
    env.write_text("".join(f"{k}={v}\n" for k, v in lines.items()), encoding="utf-8")
    env.chmod(0o600)
    monkeypatch.chdir(root)
    monkeypatch.setenv("ARGUS_DATABASE__NAME", test_database)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.delenv("ARGUS_SIEM__API_KEY", raising=False)  # this checkout's .env holds one
    try:
        yield root
    finally:
        with admin_connect(db_settings, test_database) as conn:
            if conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (api_user,)).fetchone():
                conn.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(api_user)))
                conn.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(api_user)))


def _answers(tmp_path: Path, tls: FakeTls, **extra: Any) -> Path:
    keys = {}
    for name in ("siem", "kibana"):
        key = tmp_path / f"{name}.key"
        raw = f"{name}-key:" + secrets.token_urlsafe(24)  # id:api_key, as Kibana's "encoded"
        value = base64.b64encode(raw.encode()).decode()
        hide_in_reports(value)
        key.write_text(value + "\n", encoding="utf-8")
        key.chmod(0o600)
        keys[name] = key
    data: dict[str, Any] = {
        "database": {"compose": False},
        "siem": {
            "url": "https://siem.example.org:9200",
            "trust": "chain",
            "fingerprint": tls.pki.ca_fingerprint,
            "api_key_file": str(keys["siem"]),
            "api_key_expires": "2027-02-01",
        },
        "kibana": {
            "url": "https://siem.example.org:5601",
            "api_key_file": str(keys["kibana"]),
            "api_key_expires": "2027-02-02",
        },
        "organisation": {
            "name": "Example Corp",
            "short_name": "Example SOC",
            "own_domains": ["example.org"],
            "own_networks": ["192.0.2.0/24"],
            "timezone": "Europe/Berlin",
            "incident_id_prefix": "SOC-IR",
            "space": "soc",
        },
        "llm": {"keys_file": "none"},
        "units": {"install": True, "start": False},
    }
    for dotted, value in extra.items():
        section, _, key = dotted.partition("__")
        data.setdefault(section, {})[key] = value
    path = tmp_path / "answers.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def _init(
    root: Path, answers: Path, tls: FakeTls, siem: FakeSiem, **options: Any
) -> tuple[int, str, list[str]]:
    said: list[str] = []
    calls: list[str] = []

    def systemctl(argv: list[str]) -> int:
        calls.append(" ".join(argv))
        return 0

    host = Host(
        say=said.append,
        run=Commands(),
        tls=tls,
        siem=siem,
        systemctl=systemctl,
        uv=lambda: UV,
    )
    opts = Options(
        root=root,
        config=root / "config" / "argus.yaml",
        compose=False,
        llm_file=root / "config" / "llm.local.yaml",
        **options,
    )
    asker = ScriptedAnswers(load_answers(answers), answers)
    code = run_init(opts, asker, host)
    return code, "\n".join(said), calls


def test_init_sets_up_a_fresh_checkout_and_doctor_finds_no_failure(
    checkout: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    tls, siem = FakeTls(make_pki()), FakeSiem()
    answers = _answers(tmp_path, tls)
    code, said, systemctl = _init(checkout, answers, tls, siem)
    doctor = capsys.readouterr().out
    assert code == 0, said + "\n" + doctor
    assert "FAIL" not in doctor, doctor
    # the steps, the secrets never shown
    env = (checkout / ".env").read_text()
    for name in ("ARGUS_SIEM__API_KEY", "ARGUS_KIBANA__READER_API_KEY",
                 "ARGUS_DATABASE__API_PASSWORD", "REPLICA_ELASTIC_PASSWORD"):  # fmt: skip
        assert f"{name}=" in env
    assert oct(os.stat(checkout / ".env").st_mode & 0o777) == "0o600"
    for line in env.splitlines():
        name, _, value = line.partition("=")
        if name.endswith(("PASSWORD", "KEY")):
            assert value not in said, name
            assert value not in doctor, name
    local = yaml.safe_load((checkout / "config" / "local.yaml").read_text())
    assert local["siem"]["url"] == "https://siem.example.org:9200"
    assert local["siem"]["ca_file"] == "data/certs/siem-ca.crt"
    assert local["kibana"] == {
        "url": "https://siem.example.org:5601",
        "ca_file": "data/certs/siem-ca.crt",  # the SIEM's CA verifies Kibana: one pin
        "enabled": True,
        "reader_api_key_expires": date(2027, 2, 2),
    }
    assert local["web"] == {"database_role": "api"}
    assert local["units"] == {"root": str(checkout), "uv": UV, "run": []}
    assert (checkout / "data" / "certs" / "siem-ca.crt").read_text() == tls.pki.ca_pem
    site = yaml.safe_load((checkout / "config" / "site.yaml").read_text())["site"]
    assert site["space"] == "soc"
    assert site["families"] == [{"role": "proxy", "pattern": "corp-logs-proxy-*"}]
    assert site["organisation"] == {"name": "Example Corp", "short_name": "Example SOC"}
    assert site["own_domains"] == ["example.org"]
    assert site["incident_id_prefix"] == "SOC-IR"
    assert yaml.safe_load((checkout / "config" / "llm.local.yaml").read_text()) == {
        "keys_file": None
    }
    assert siem.calls == ["check_key", "discover", "selftest", "kibana_check"]
    installed = tmp_path / "xdg" / "systemd" / "user"
    assert sorted(p.name for p in installed.iterdir()) == sorted(units.MANIFEST)
    web = (installed / "argus-web.service").read_text()
    assert f"WorkingDirectory={checkout}\n" in web
    assert f"ExecStart={UV} run argus web\n" in web
    assert "ARGUS_WEB__HOST" not in web
    assert "10.130" not in web
    assert systemctl == ["daemon-reload"]  # nothing enabled or started
    assert "WARN  service units" not in doctor
    assert "none runs yet" in doctor
    assert "WARN  Kibana reader key expiry" not in doctor

    # a rerun keeps everything and changes no file
    before = {p: p.read_bytes() for p in checkout.rglob("*") if p.is_file()}
    code, again, systemctl = _init(checkout, answers, tls, siem)
    capsys.readouterr()
    assert code == 0, again
    assert {p: p.read_bytes() for p in checkout.rglob("*") if p.is_file()} == before
    assert "kept" in again
    assert systemctl == []  # nothing new to reload


def test_init_starts_the_services_only_when_asked(
    checkout: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    tls, siem = FakeTls(make_pki()), FakeSiem()
    answers = _answers(tmp_path, tls, units__start=True)
    code, said, systemctl = _init(checkout, answers, tls, siem)
    capsys.readouterr()
    local = yaml.safe_load((checkout / "config" / "local.yaml").read_text())
    # Kibana is set up, so its read-back starts too, and the nightly backups with it
    wanted = [*units.CORE, "argus-kibana-sync.service", *BACKUPS]
    assert local["units"]["run"] == wanted
    assert systemctl == ["daemon-reload", "enable --now " + " ".join(wanted)]
    assert "loginctl enable-linger" in said
    assert code in (0, 1)  # the fake systemctl enabled nothing: doctor may say so
