"""Q-A5's layout: the system units, the owner wrapper and the install script agree with
argus.ops.custody (and with the user units they replace), and each unit's configuration loads
under its account with exactly its credentials."""

from __future__ import annotations

import os
import re
import shlex
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest
from typer.testing import CliRunner

from argus.cli import app
from argus.config import ConfigError, load_settings
from argus.config.settings import secret_settings
from argus.observability.redaction import clear_registered_secrets
from argus.ops import custody, units
from argus.ops.units import Role
from tests.conftest import REPO_ROOT

pytestmark = pytest.mark.unit

CUSTODY = REPO_ROOT / "deploy" / "custody"
UNIT_DIR = CUSTODY / "units"
USER_UNITS = REPO_ROOT / "deploy" / "systemd"
ARGUS = "/opt/argus/current/.venv/bin/argus"
# The user units as an installation renders them (D-295): a made-up checkout and uv.
PARAMS = units.UnitParams(Path("/srv/argus"), "/usr/local/bin/uv", {"WEB_CLASSIC": "fallback"})
RENDERED = units.rendered_units(PARAMS, USER_UNITS)


def body(path: Path | str) -> dict[str, dict[str, list[str]]]:
    """A unit file's sections (a path, or a unit's text): key -> every value, in order."""
    sections: dict[str, dict[str, list[str]]] = {}
    current = ""
    text = path if isinstance(path, str) else path.read_text(encoding="utf-8")
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            sections.setdefault(current, {})
            continue
        key, _, value = line.partition("=")
        sections[current].setdefault(key, []).append(value)
    return sections


def one(unit: dict[str, dict[str, list[str]]], key: str, section: str = "Service") -> str | None:
    values = unit.get(section, {}).get(key, [])
    assert len(values) <= 1, key
    return values[0] if values else None


def environment(unit: dict[str, dict[str, list[str]]]) -> dict[str, str]:
    found: dict[str, str] = {}
    for value in unit.get("Service", {}).get("Environment", []):
        for word in shlex.split(value):
            name, _, setting = word.partition("=")
            found[name] = setting
    return found


def loads(unit: dict[str, dict[str, list[str]]]) -> list[str]:
    return [v.partition(":")[0] for v in unit.get("Service", {}).get("LoadCredential", [])]


# --------------------------------------------------------------------------- the manifest


def test_the_manifest_names_every_unit_file_and_every_user_unit() -> None:
    assert sorted(p.name for p in UNIT_DIR.iterdir()) == sorted(custody.UNITS)
    assert set(custody.UNITS) == set(units.MANIFEST), "every user unit has its system unit"
    for name, (_account, role) in custody.UNITS.items():
        # custody runs what an installation may choose to run (D-295)
        user_role = units.MANIFEST[name][0]
        assert role is (Role.RUN if user_role is Role.CHOICE else user_role), name


def test_credential_names_are_settings_or_file_credentials() -> None:
    assert custody.credential_name_problems(custody.all_credentials()) == []
    assert set(secret_settings()) <= set(custody.all_credentials())
    assert set(custody.REQUIRED) <= set(custody.all_credentials())
    assert custody.holders("database.owner_password") == ["owner"]
    assert custody.holders("siem.writer_api_key") == ["writer"]
    assert custody.SERVICE_USERS == ("argus-svc", "argus-web", "argus-writer")


@pytest.mark.parametrize("name", sorted(custody.UNITS))
def test_each_system_unit_runs_its_user_unit_as_its_account(name: str) -> None:
    account, _role = custody.UNITS[name]
    unit, user = body(UNIT_DIR / name), body(RENDERED[name])
    if name.endswith(".timer"):
        assert unit["Timer"] == user["Timer"]
        assert unit["Install"] == {"WantedBy": ["timers.target"]}
        return
    assert account is not None
    owner = custody.ACCOUNTS[account]
    service = unit["Service"]
    if owner.user == "root":
        assert "User" not in service
        assert one(unit, "ProtectHome") == "tmpfs"
        assert one(unit, "ReadWritePaths") == "/var/lib/argus-backups"
    else:
        assert one(unit, "User") == owner.user
        assert one(unit, "Group") == owner.user
        assert one(unit, "SupplementaryGroups") == "argus"
        assert one(unit, "ProtectHome") == "yes"  # reference/ and every checkout out of sight
        assert "ReadWritePaths" not in service
        assert one(unit, "CapabilityBoundingSet") == ""
    assert one(unit, "WorkingDirectory") == "/opt/argus/current"
    assert one(unit, "EnvironmentFile") == "/etc/argus/argus.env"
    env = environment(unit)
    assert env["ARGUS_CUSTODY__ROLE"] == account
    assert set(env) - {"PYTHONDONTWRITEBYTECODE", "DOCKER_CONTEXT"} <= custody.UNIT_SET
    for key, value in (("NoNewPrivileges", "yes"), ("ProtectSystem", "strict"),
                       ("PrivateTmp", "yes"), ("UMask", "0077")):  # fmt: skip
        assert one(unit, key) == value, key
    # the same command, the same limits as the user unit it replaces
    start = one(unit, "ExecStart")
    assert start is not None
    assert start.startswith(f"{ARGUS} ")
    user_start = one(user, "ExecStart")
    assert user_start is not None
    assert user_start.endswith(" argus " + start.removeprefix(f"{ARGUS} "))
    for key in ("Restart", "RestartSec", "Nice", "Type"):
        assert one(unit, key) == one(user, key), key
    if name != "argus-backup-drill.service":  # the drill's cap was heavy.sh's
        assert one(unit, "MemoryMax") == one(user, "MemoryMax")
    else:
        assert one(unit, "MemoryMax") == "2G"
    if one(user, "ExecCondition"):
        user_condition = one(user, "ExecCondition", "Service")
        assert user_condition is not None
        assert one(unit, "ExecCondition") == re.sub(r"\S+/uv run argus", ARGUS, user_condition)
    assert ("Install" in unit) == ("Install" in user)
    if "Install" in unit:
        assert unit["Install"] == {"WantedBy": ["multi-user.target"]}


@pytest.mark.parametrize("name", sorted(n for n in custody.UNITS if n.endswith(".service")))
def test_each_unit_loads_its_accounts_credentials_and_no_other(name: str) -> None:
    account = custody.UNITS[name][0]
    assert account is not None
    unit = body(UNIT_DIR / name)
    loaded = loads(unit)
    for value in unit["Service"]["LoadCredential"]:
        credential, _, source = value.partition(":")
        assert source == f"/etc/argus/credentials/{credential}"
    if account == "owner":
        assert loaded == ["database.owner_password"]  # backups need only the owner's login
    elif name in custody.UNIT_CREDENTIALS:  # its own list, all of it its account's (D-214)
        assert loaded == list(custody.unit_credentials(name))
        assert set(loaded) <= set(custody.ACCOUNTS[account].credentials)
    else:
        assert loaded == list(custody.unit_credentials(name))
        extra = set(custody.UNIT_EXTRA_CREDENTIALS.get(name, ()))
        held = custody.ACCOUNTS[account]
        # a key minted at a later canary is not in a unit file: a missing credential file fails
        # LoadCredential= and the whole unit with it (Q-D4 review)
        required = [c for c in held.credentials if c not in held.optional]
        assert loaded == [*required, *sorted(extra)]
        assert not set(loaded) & set(held.optional)


def test_only_the_kibana_sync_of_the_svc_units_loads_the_kibana_reader_key() -> None:
    """Q-D3: the read-back gets the reader key; the collector's units never depend on it."""
    for path in sorted(UNIT_DIR.glob("*.service")):
        loaded = loads(body(path))
        if custody.UNITS[path.name][0] == "svc":
            assert ("kibana.reader_api_key" in loaded) == (path.name == "argus-kibana-sync.service")


def test_the_writers_later_keys_do_not_stop_the_unit_that_has_no_use_for_them_yet() -> None:
    """Q-D4 review (deployment risk): a key minted at a later canary must not be named by the
    unit of the cases schedule (a missing credential file fails the unit), nor stop
    ``argus-owner`` from running the cases canary in the writer's account."""
    writer = custody.ACCOUNTS["writer"]
    assert set(writer.optional) == {
        "siem.writer_api_key",
        "kibana.alert_writer_api_key",
        *custody.TEAM_KEYS,  # AR8: the case team's six keys wait for its own canary
        *custody.OPTIONAL_TEAM_KEYS,  # AR10: the seventh waits for its user
    }
    unit = (UNIT_DIR / "argus-writer.service").read_text()
    for name in writer.optional:
        assert f"LoadCredential={name}:" not in unit
    for name in (
        "database.writer_password",
        "kibana.cases_writer_api_key",
        "kibana.reader_api_key",
    ):
        assert f"LoadCredential={name}:" in unit  # what the cases schedule needs is still required
    wrapper = (CUSTODY / "argus-owner").read_text()
    assert "OPTIONAL[$role]" in wrapper  # a missing optional credential is skipped, any account


def test_only_the_writer_loads_a_writer_key_and_only_the_owner_the_owner_password() -> None:
    for path in sorted(UNIT_DIR.glob("*.service")):
        loaded = loads(body(path))
        # no unit names it until the step that mints it does (a missing credential file fails
        # LoadCredential= and the unit with it); then only the writer's
        assert "siem.writer_api_key" not in loaded or path.name == "argus-writer.service"
        if "database.owner_password" in loaded:
            assert custody.UNITS[path.name][0] == "owner"
        text = path.read_text()
        assert "ARGUS_SIEM__WRITER_API_KEY" not in text
        assert "PASSWORD=" not in text.upper().replace("ARGUS_DATABASE__", "")


# --------------------------------------------------------------------------- contracts


@pytest.fixture
def isolated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[Path]:
    for key in list(os.environ):
        if key.upper().startswith("ARGUS_") or key == "CREDENTIALS_DIRECTORY":
            monkeypatch.delenv(key)
    monkeypatch.chdir(tmp_path)
    clear_registered_secrets()
    yield tmp_path
    clear_registered_secrets()


@pytest.mark.parametrize("name", sorted(n for n in custody.UNITS if n.endswith(".service")))
def test_each_units_configuration_loads_under_custody(
    name: str, isolated: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A unit's Environment=, an argus.env as the import writes it and the unit's credentials
    (the web's key in its credential folder) load without a problem: the unit would start."""
    unit = body(UNIT_DIR / name)
    folder = isolated / "credentials"
    folder.mkdir()
    for credential in loads(unit):
        (folder / credential).write_text(f"Synthetic-{credential}\n")
    report = custody.Report()
    argus_env = custody.env_file_text({"ARGUS_DATABASE__NAME": "argus"}, report)
    for line in argus_env.decode().splitlines():
        if line and not line.startswith("#"):
            key, _, value = line.partition("=")
            monkeypatch.setenv(key, value.strip("'"))
    for key, value in environment(unit).items():
        monkeypatch.setenv(key, value.replace(f"/run/credentials/{name}", str(folder)))
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(folder))
    # the installation's (config/local.yaml's web section): the custody unit leaves them to it
    monkeypatch.setenv("ARGUS_WEB__ALLOWED_HOSTS", "argus.example.org")
    monkeypatch.setenv("ARGUS_WEB__ALLOWED_NETWORKS", "192.0.2.0/24")
    settings = load_settings(REPO_ROOT / "config" / "argus.yaml", env_file=isolated / ".env")
    assert settings.custody.role == custody.UNITS[name][0]
    held = {
        s for s in secret_settings()
        if getattr(getattr(settings, s.split(".")[0]), s.split(".")[1]) is not None
    }  # fmt: skip
    assert held == {c for c in loads(unit) if c in set(secret_settings())}  # Q-D2's Kibana keys too
    assert str(settings.siem.ca_file) == "/etc/argus/certs/siem-ca.crt"
    assert str(settings.assets.map_path) == "/etc/argus/data/asset_map.yaml"


def test_a_service_account_cannot_resume_a_switch(
    isolated: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Under custody no service holds the owner's password, so a resume stops before any
    database connection, and says how to run it."""
    folder = isolated / "credentials"
    folder.mkdir()
    (folder / "database.password").write_text("Synthetic-Runtime\n")
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(folder))
    monkeypatch.setenv("ARGUS_CUSTODY__ROLE", "svc")
    config = isolated / "argus.yaml"
    config.write_text("")
    result = CliRunner().invoke(app, ["siem", "resume", "-c", str(config)])
    assert result.exit_code == 2
    assert "sudo argus-owner siem resume --component global" in result.output + result.stderr
    result = CliRunner().invoke(app, ["llm", "resume", "-c", str(config)])
    assert result.exit_code == 2
    assert "sudo argus-owner llm resume" in result.output + result.stderr


# --------------------------------------------------------------------------- the scripts


def _bash_table(text: str, name: str) -> dict[str, str]:
    block = re.search(rf"declare -A {name}=\((.*?)\)\n", text, re.S)
    assert block is not None, name
    return dict(re.findall(r'\[([\w-]+)\]="?([^"\]\n]*?)"?(?=\s+\[|\s*$)', block.group(1).strip()))


def test_the_owner_wrapper_knows_the_accounts_as_the_layout_does() -> None:
    text = (CUSTODY / "argus-owner").read_text()
    users = _bash_table(text, "USERS")
    assert users == {role: account.user for role, account in custody.ACCOUNTS.items()}
    creds = _bash_table(text, "CREDS")
    assert {role: value.split() for role, value in creds.items()} == {
        role: list(account.credentials) for role, account in custody.ACCOUNTS.items()
    }
    optional = _bash_table(text, "OPTIONAL")
    assert {role: tuple(value.split()) for role, value in optional.items()} == {
        role: account.optional for role, account in custody.ACCOUNTS.items() if account.optional
    }


def test_the_install_script_makes_the_layouts_users() -> None:
    text = (CUSTODY / "install.sh").read_text()
    users = re.search(r"^USERS=\(([^)]*)\)", text, re.M)
    assert users is not None
    assert tuple(users.group(1).split()) == custody.SERVICE_USERS
    roles = _bash_table(text, "ROLE_OF")
    assert roles == {
        a.user: r for r, a in custody.ACCOUNTS.items() if a.user != "root"
    }  # fmt: skip
    for group in custody.ROOT_EQUIVALENT_GROUPS:
        assert group in text
    for folder in ("/etc/argus/credentials 755 root:root", "/var/lib/argus-backups 700"):
        assert f"folder {folder}" in text


def _dry_run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        ["/usr/bin/bash", str(CUSTODY / "argus-owner"), "--dry-run", *args],
        capture_output=True,
        text=True,
        check=False,
        stdin=subprocess.DEVNULL,
    )


@pytest.mark.parametrize("role", ["svc", "web", "writer", "owner"])
def test_the_wrapper_runs_each_account_with_its_credentials_only(role: str) -> None:
    done = _dry_run("--as", role, "backup", "list")
    assert done.returncode == 0, done.stderr
    words = shlex.split(done.stdout)
    assert words[0] == "systemd-run"
    assert words[-3:] == [ARGUS, "backup", "list"]
    props = [words[i + 1] for i, w in enumerate(words) if w == "-p"]
    loaded = [p.removeprefix("LoadCredential=").partition(":")[0] for p in props
              if p.startswith("LoadCredential=")]  # fmt: skip
    account = custody.ACCOUNTS[role]
    if role == "owner":
        # optional ones only when present: none here (no /etc/argus on a test machine)
        assert set(account.credentials) - set(account.optional) <= set(loaded)
        assert "ProtectHome=tmpfs" in props
        assert not any(p.startswith("User=") for p in props)
    else:
        # the optional ones (the writer's later keys) only when present: none on this machine
        assert loaded == [c for c in account.credentials if c not in account.optional]
        assert f"User={account.user}" in props
        assert "ProtectHome=yes" in props
        # the units' hardening for a service account (review: the transient units had less)
        for prop in ("CapabilityBoundingSet=", "AmbientCapabilities=", "PrivateDevices=yes",
                     "ProtectKernelTunables=yes", "ProtectKernelModules=yes",
                     "ProtectControlGroups=yes", "RestrictNamespaces=yes"):  # fmt: skip
            assert prop in props, prop
    assert "database.owner_password" not in loaded or role == "owner"
    assert "siem.writer_api_key" not in loaded or role == "writer"
    assert f"ARGUS_CUSTODY__ROLE={role}" in words
    assert "--pipe" in words  # no terminal here
    for prop in ("NoNewPrivileges=yes", "ProtectSystem=strict", "UMask=0077",
                 "EnvironmentFile=/etc/argus/argus.env"):  # fmt: skip
        assert prop in props


def _dry_run_as(user: str | None, *args: str) -> list[str]:
    env = {k: v for k, v in os.environ.items() if k != "SUDO_USER"}
    if user is not None:
        env["SUDO_USER"] = user
    done = subprocess.run(  # noqa: S603
        ["/usr/bin/bash", str(CUSTODY / "argus-owner"), "--dry-run", *args],
        capture_output=True, text=True, check=False, stdin=subprocess.DEVNULL, env=env,
    )  # fmt: skip
    assert done.returncode == 0, done.stderr
    return shlex.split(done.stdout)


def test_the_wrapper_tells_the_command_who_ran_it() -> None:
    """Q-D4 review R12: the process runs in a service account, so the records a run, a ramp
    step or a skip make would name that account; the wrapper passes ``SUDO_USER`` on."""
    words = _dry_run_as("asha", "--as", "writer", "kibana", "run", "--class", "W1")
    assert "ARGUS_CUSTODY__OPERATOR=asha" in words
    assert not any(
        w.startswith("ARGUS_CUSTODY__OPERATOR") for w in _dry_run_as(None, "db", "upgrade")
    )
    for hostile in ("a b", "x;rm", "-e", "", "a" * 70, "$(id)"):
        assert not any(
            w.startswith("ARGUS_CUSTODY__OPERATOR") for w in _dry_run_as(hostile, "db", "upgrade")
        ), hostile


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["--as", "root", "db", "upgrade"], "--as is one of svc, web, writer, owner"),
        ([], "usage: sudo argus-owner"),
        (["--as"], "usage: sudo argus-owner"),
    ],
)
def test_the_wrapper_refuses_what_it_does_not_know(args: list[str], message: str) -> None:
    done = _dry_run(*args)
    assert done.returncode == 2
    assert message in done.stderr


def test_the_wrapper_needs_root_unless_it_only_prints() -> None:
    if os.geteuid() == 0:
        pytest.skip("runs as root")
    done = subprocess.run(  # noqa: S603
        ["/usr/bin/bash", str(CUSTODY / "argus-owner"), "db", "upgrade"],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    assert done.returncode == 2
    assert "run it with sudo" in done.stderr


def test_unit_roles_follow_custody_for_the_moved_user_units(tmp_path: Path) -> None:
    """The Q-A2 user-unit check under custody: a moved unit's user copy must be off."""
    installed = tmp_path / "user"
    wants = installed / "default.target.wants"
    wants.mkdir(parents=True)
    for name in units.MANIFEST:
        (installed / name).write_text(RENDERED[name])
    (wants / "argus-web.service").symlink_to(installed / "argus-web.service")
    states, _, _ = units.unit_states(
        USER_UNITS, installed, moved={"argus-web.service"}, params=PARAMS
    )
    web = next(s for s in states if s.name == "argus-web.service")
    assert web.role is Role.OFF
    assert units.problems(web) == (f"enabled before its production step ({units.MOVED})", False)
    collector = next(s for s in states if s.name == "argus-collector.service")
    assert collector.role is Role.RUN


def test_configuration_without_custody_is_unchanged(isolated: Path) -> None:
    config = isolated / "argus.yaml"
    config.write_text("")
    assert load_settings(config, env_file=None).custody.role is None
    with pytest.raises(ConfigError):
        load_settings(config, env_file=None, custody={"role": "nobody"})


def test_a_unit_names_only_its_own_credential_folder() -> None:
    """systemd puts a system unit's credentials in /run/credentials/<unit>; a path into another
    unit's folder would be empty, or worse, another's."""
    for path in sorted(UNIT_DIR.glob("*.service")):
        for value in environment(body(path)).values():
            if "/run/credentials/" in value:
                assert value.startswith(f"/run/credentials/{path.name}/"), (path.name, value)
                credential = value.removeprefix(f"/run/credentials/{path.name}/")
                assert credential in loads(body(path)), (path.name, credential)


def test_doctor_finds_the_web_certificate_of_the_custody_unit(isolated: Path) -> None:
    from argus.config import Settings
    from argus.ops.checks import web_certificate

    unit = isolated / "argus-web.service"
    unit.write_bytes((UNIT_DIR / "argus-web.service").read_bytes())
    path, where, port = web_certificate(Settings(), system_unit=unit)
    assert path == Path("/etc/argus/tls/argus.crt")
    assert where == "argus-web.service (custody)"
    assert port == 8765
