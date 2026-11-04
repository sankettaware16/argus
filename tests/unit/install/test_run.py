"""P4-D2: ``argus init``'s steps with every side effect faked (no docker, no network, no
database, no systemd): an answers file sets up a fresh checkout; a missing answer stops with
its name; a rerun keeps everything; the keys are never printed; --force-key replaces one; a key
that is not read-only stops; the person can refuse the proposal; no keys file means no model."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest
import yaml

from argus.install.answers import ScriptedAnswers, TerminalAnswers
from argus.install.run import Host, Options, run_init
from argus.ops import units
from tests.conftest import REPO_ROOT
from tests.unit.install.fakes import DOCKER_OK, Commands, FakeSiem, FakeTls, make_pki

pytestmark = pytest.mark.unit

SIEM_KEY = "c2llbS1rZXktZm9yLWEtdGVzdDp2YWx1ZQ=="
KIBANA_KEY = "a2liYW5hLWtleS1mb3ItYS10ZXN0OnZhbHVl"


class Run:
    """One init run's fakes and what they saw."""

    def __init__(self, tmp_path: Path, *, doctor: int = 0, compose: bool = False) -> None:
        self.root = tmp_path / "argus"
        (self.root / "config").mkdir(parents=True, exist_ok=True)
        shutil.copy(REPO_ROOT / "config" / "argus.yaml", self.root / "config" / "argus.yaml")
        (self.root / "docker-compose.yml").touch()
        self.tls = FakeTls(make_pki())
        self.siem = FakeSiem()
        self.commands = Commands(dict(DOCKER_OK))
        self.said: list[str] = []
        self.systemctl: list[str] = []
        self.db: list[str] = []
        self.doctor = doctor
        self.compose = compose
        self.units = tmp_path / "units"
        self.tmp = tmp_path
        self.people: list[tuple[str, str, str]] = []

    def host(self) -> Host:
        def systemctl(argv: list[str]) -> int:
            self.systemctl.append(" ".join(argv))
            return 0

        return Host(
            say=self.said.append, run=self.commands, which=lambda _: "/usr/bin/x",
            port_free=lambda _h, _p: True, disk_free=lambda _p: 100 * 2**30,
            sleep=lambda _s: None, tls=self.tls, siem=self.siem, unit_dir=self.units,
            systemctl=systemctl, bootstrap=lambda _c: self.db.append("bootstrap"),
            upgrade=lambda _c: self.db.append("upgrade"), doctor=lambda _c: self.doctor,
            uv=lambda: "/usr/bin/uv", local_ip=lambda _t: "192.0.2.10",
            people=lambda _c: len(self.people),
            add_person=lambda _c, u, n, pw: self.people.append((u, n, pw)), user=lambda: "argus",
        )  # fmt: skip

    def options(self, **kw: Any) -> Options:
        return Options(
            root=self.root,
            config=self.root / "config" / "argus.yaml",
            compose=self.compose,
            llm_file=self.root / "config" / "llm.local.yaml",
            **kw,
        )

    def answers(self, **given: Any) -> ScriptedAnswers:
        keys = {}
        for name, value in (("siem", SIEM_KEY), ("kibana", KIBANA_KEY)):
            path = self.tmp / f"{name}.key"
            path.write_text(value)
            path.chmod(0o600)
            keys[name] = str(path)
        data = {
            "siem.url": "https://es.example.org:9200",
            "siem.trust": "chain",
            "siem.fingerprint": self.tls.pki.ca_fingerprint,
            "siem.api_key_file": keys["siem"],
            "kibana.url": "https://es.example.org:5601",
            "kibana.api_key_file": keys["kibana"],
            "organisation.name": "Example Corp",
            "organisation.short_name": "Example SOC",
            "organisation.own_domains": ["example.org"],
            "organisation.timezone": "Europe/Berlin",
            "organisation.incident_id_prefix": "SOC-IR",
            "organisation.space": "soc",
            "llm.keys_file": "none",
        }
        data.update(given)
        return ScriptedAnswers({k: v for k, v in data.items() if v is not ...}, self.tmp / "a.yml")

    def go(self, asker: Any, **options: Any) -> int:
        self.said.clear()
        return run_init(self.options(**options), asker, self.host())

    @property
    def text(self) -> str:
        return "\n".join(self.said)

    def local(self) -> dict[str, Any]:
        loaded: dict[str, Any] = yaml.safe_load((self.root / "config" / "local.yaml").read_text())
        return loaded


def test_an_answers_file_sets_up_a_fresh_checkout(tmp_path: Path) -> None:
    run = Run(tmp_path, doctor=0)
    assert run.go(run.answers()) == 0, run.text
    assert run.db == ["bootstrap", "upgrade"]
    assert run.siem.calls == ["check_key", "discover", "selftest", "kibana_check"]
    assert run.siem.names[0] == [".alerts-security.alerts-*", ".internal.alerts-security.alerts-*",
                                 "logs-*"]  # fmt: skip
    env = (run.root / ".env").read_text()
    assert f"ARGUS_SIEM__API_KEY={SIEM_KEY}\n" in env
    assert f"ARGUS_KIBANA__READER_API_KEY={KIBANA_KEY}\n" in env
    for secret in (SIEM_KEY, KIBANA_KEY):
        assert secret not in run.text
    for line in env.splitlines():
        if "PASSWORD=" in line:
            assert line.partition("=")[2] not in run.text
    assert run.local()["units"] == {"root": str(run.root), "uv": "/usr/bin/uv", "run": []}
    assert sorted(p.name for p in run.units.iterdir()) == sorted(units.MANIFEST)
    assert run.systemctl == ["daemon-reload"]
    assert "POST /_security/api_key" in run.text
    assert "init: done; ARGUS is set up but not started: argus init --start starts it" in run.text
    assert "no one can sign in yet" in run.text  # scripted, no web.person: nobody is made
    site = yaml.safe_load((run.root / "config" / "site.yaml").read_text())["site"]
    assert site["timezone"] == "Europe/Berlin"
    assert "own_networks" not in site  # none given


def test_an_existing_env_never_gets_a_web_password(tmp_path: Path) -> None:
    """A checkout whose .env exists may keep the web's password in a credential folder: a new one
    in .env would make the bootstrap replace the login's password."""
    run = Run(tmp_path)
    (run.root / ".env").write_text("ARGUS_DATABASE__PASSWORD=existing-value-123\n")
    assert run.go(run.answers()) == 0, run.text
    env = (run.root / ".env").read_text()
    assert "ARGUS_DATABASE__API_PASSWORD" not in env
    assert "ARGUS_DATABASE__PASSWORD=existing-value-123\n" in env
    assert "web" not in run.local()


def test_a_env_with_only_composes_names_is_a_new_installation(tmp_path: Path) -> None:
    """A second ARGUS on the machine sets its compose names first (D-300): its web still gets
    its own login."""
    run = Run(tmp_path)
    (run.root / ".env").write_text("COMPOSE_PROJECT_NAME=argus2\nCOMPOSE_DB_CONTAINER=argus2-db\n")
    assert run.go(run.answers()) == 0, run.text
    env = (run.root / ".env").read_text()
    assert "ARGUS_DATABASE__API_PASSWORD=" in env
    assert "COMPOSE_PROJECT_NAME=argus2\n" in env


def test_init_refuses_a_machine_under_custody(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from argus.ops import custody

    monkeypatch.setattr(custody, "marker", lambda *a: {"tag": "x"})
    run = Run(tmp_path)
    assert run.go(run.answers()) == 1
    assert "custody is installed here" in run.text
    assert not (run.root / ".env").exists()


def test_inits_exit_code_is_doctors(tmp_path: Path) -> None:
    run = Run(tmp_path, doctor=1)
    assert run.go(run.answers()) == 1
    assert "doctor found a failure" in run.text


def test_a_missing_answer_stops_init_with_its_name(tmp_path: Path) -> None:
    run = Run(tmp_path)
    assert run.go(run.answers(**{"siem.url": ...})) == 2
    assert f"error: {tmp_path / 'a.yml'} does not answer siem.url (the SIEM's" in run.text
    assert run.siem.calls == []
    run = Run(tmp_path / "2")
    (tmp_path / "2").mkdir(exist_ok=True)
    assert run.go(run.answers(**{"organisation.own_domains": []})) == 2
    assert "organisation.own_domains: at least one is needed" in run.text
    assert not (run.root / "config" / "site.yaml").exists()


def test_a_bad_answer_is_named_as_the_site_checks_it(tmp_path: Path) -> None:
    run = Run(tmp_path)
    assert run.go(run.answers(**{"organisation.timezone": "Mars/Base"})) == 2
    assert "organisation.timezone:" in run.text


def test_a_rerun_with_no_answers_keeps_everything(tmp_path: Path) -> None:
    run = Run(tmp_path)
    assert run.go(run.answers()) == 0
    files = {p: p.read_bytes() for p in run.root.rglob("*") if p.is_file()}
    run.siem.calls.clear()
    again = ScriptedAnswers({}, tmp_path / "empty.yml")
    assert run.go(again) == 0, run.text
    assert {p: p.read_bytes() for p in run.root.rglob("*") if p.is_file()} == files
    assert "SIEM key: kept (in .env)" in run.text
    assert "kept config/site.yaml" in run.text
    assert "kept config/llm.local.yaml (keys_file: none)" in run.text
    assert run.siem.calls == ["check_key", "selftest", "kibana_check"]  # verified, not redone
    assert run.siem.names[-1][:2] == [".alerts-security.alerts-soc",
                                      ".internal.alerts-security.alerts-soc-*"]  # fmt: skip
    assert '"logs-*"' not in run.text  # no starting role: the key was kept


def test_force_key_replaces_the_key_and_nothing_else(tmp_path: Path) -> None:
    run = Run(tmp_path)
    assert run.go(run.answers()) == 0
    newer = tmp_path / "newer.key"
    newer.write_text("bmV3ZXIta2V5LWZvci1hLXRlc3Q6dmFsdWU=")
    newer.chmod(0o600)
    asker = ScriptedAnswers(
        {"siem.api_key_file": str(newer), "kibana.api_key_file": "none"}, tmp_path / "f.yml"
    )
    assert run.go(asker, force_key=True) == 0, run.text
    env = (run.root / ".env").read_text()
    assert env.count("ARGUS_SIEM__API_KEY=") == 1
    assert "ARGUS_SIEM__API_KEY=bmV3ZXIta2V5LWZvci1hLXRlc3Q6dmFsdWU=" in env
    assert f"ARGUS_KIBANA__READER_API_KEY={KIBANA_KEY}" in env  # none given: kept
    assert '".alerts-security.alerts-soc"' in run.text  # the exact role for the site


def test_a_key_that_is_not_read_only_stops_init(tmp_path: Path) -> None:
    run = Run(tmp_path)
    run.siem.key_problems = ["holds write on logs-*"]
    assert run.go(run.answers()) == 1
    assert "the SIEM key is not what ARGUS needs: holds write on logs-*" in run.text
    assert not (run.root / "config" / "site.yaml").exists()


def test_a_selftest_problem_stops_init_with_the_exact_role(tmp_path: Path) -> None:
    run = Run(tmp_path)
    run.siem.selftest_problems = ["lacks read on corp-logs-proxy-*"]
    assert run.go(run.answers()) == 1
    assert "the SIEM self-test failed: lacks read on corp-logs-proxy-*" in run.text
    assert '"corp-logs-proxy-*"' in run.text


def test_a_kibana_check_its_lane_cannot_take_now_is_left_to_later(tmp_path: Path) -> None:
    """Found by the public proof: discovery's Kibana reads spend the paced kibana_read lane's
    minute; the key's check then waits past its deadline. Init goes on and says how to check."""
    run = Run(tmp_path)
    run.siem.kibana_problems = None
    assert run.go(run.answers()) == 0
    assert "Kibana key: not checked now" in run.text
    assert "argus kibana selftest" in run.text


def test_the_person_may_refuse_the_proposal(tmp_path: Path) -> None:
    run = Run(tmp_path)
    assert run.go(run.answers(**{"discovery.accept": False})) == 1
    assert "nothing written" in run.text
    assert not (run.root / "config" / "site.yaml").exists()


def test_a_space_that_kibana_does_not_have_is_refused(tmp_path: Path) -> None:
    run = Run(tmp_path)
    assert run.go(run.answers(**{"organisation.space": "nope"})) == 2
    assert "organisation.space is one of soc, default" in run.text


def test_without_kibana_there_is_no_kibana_key_or_check(tmp_path: Path) -> None:
    run = Run(tmp_path)
    assert run.go(run.answers(**{"kibana.url": "none", "kibana.api_key_file": ...})) == 0
    assert "ARGUS_KIBANA__READER_API_KEY" not in (run.root / ".env").read_text()
    assert "kibana" not in run.local()
    assert "kibana_check" not in run.siem.calls


def test_a_kibana_key_left_out_keeps_kibana_off(tmp_path: Path) -> None:
    run = Run(tmp_path)
    assert run.go(run.answers(**{"kibana.api_key_file": "none"})) == 0
    assert run.local()["kibana"] == {
        "url": "https://es.example.org:5601", "ca_file": "data/certs/siem-ca.crt",
    }  # fmt: skip
    assert "Kibana key: none" in run.text


def test_a_keys_file_names_the_providers_it_holds_keys_for(tmp_path: Path) -> None:
    keys = tmp_path / "llm.env"
    keys.write_text("GROQ_API_KEY=gsk-test-value\n")
    keys.chmod(0o600)
    run = Run(tmp_path)
    assert run.go(run.answers(**{"llm.keys_file": str(keys)})) == 0, run.text
    assert "keys for groq" in run.text
    assert "gsk-test-value" not in run.text
    overlay = yaml.safe_load((run.root / "config" / "llm.local.yaml").read_text())
    assert overlay == {"keys_file": str(keys)}
    keys.chmod(0o644)
    loose = Run(tmp_path / "x")
    (tmp_path / "x").mkdir(exist_ok=True)
    assert loose.go(loose.answers(**{"llm.keys_file": str(keys)})) == 2
    assert "readable by others" in loose.text


def test_units_left_out_run_nothing(tmp_path: Path) -> None:
    run = Run(tmp_path)
    assert run.go(run.answers(**{"units.install": False})) == 0
    assert run.local()["units"] == {"run": []}
    assert not run.units.exists()
    assert run.systemctl == []


def test_start_enables_the_four_services_and_the_backups(tmp_path: Path) -> None:
    run = Run(tmp_path)
    assert run.go(run.answers(), start=True) == 0
    wanted = [*units.CORE, "argus-kibana-sync.service", "argus-backup.timer",
              "argus-backup-drill.timer"]  # fmt: skip
    assert run.systemctl == ["daemon-reload", "enable --now " + " ".join(wanted)]
    assert run.local()["units"]["run"] == wanted
    assert "sudo loginctl enable-linger argus" in run.text
    # the read-back's unit reads these two: made for it, empty (Kibana's key stays in .env)
    assert (run.root / "local" / "creds-sync").is_dir()
    switches = run.root / "local" / "argus-kibana-read.env"
    assert switches.stat().st_mode & 0o777 == 0o600


def test_start_starts_every_unit_the_installation_runs(tmp_path: Path) -> None:
    run = Run(tmp_path)
    extra = ["argus-kibana-sync.service", "argus-case-team.timer"]
    (run.root / "config" / "local.yaml").write_text(yaml.safe_dump({"units": {"run": extra}}))
    run.commands.table[("loginctl",)] = (0, "Linger=yes\n")
    assert run.go(run.answers(**{"units.backups": False}), start=True) == 0
    assert run.systemctl[-1] == "enable --now " + " ".join([*extra, *units.CORE])
    assert "enable-linger" not in run.text


def test_compose_brings_the_database_up_and_waits_for_it(tmp_path: Path) -> None:
    run = Run(tmp_path, compose=True)
    run.commands.table[("docker", "inspect")] = (0, "starting\n")
    calls = iter(["starting\n", "starting\n", "healthy\n"])

    def inspect(argv: list[str]) -> Any:
        import subprocess

        run.commands.ran.append(argv)
        if argv[:2] == ["docker", "inspect"]:
            return subprocess.CompletedProcess(argv, 0, next(calls), "")
        return Commands(dict(DOCKER_OK))(argv)

    host = run.host()
    host.run = inspect
    assert run_init(run.options(), run.answers(), host) == 0, run.text
    assert ["docker", "compose", "up", "-d", "db"] in run.commands.ran
    assert sum(1 for a in run.commands.ran if a[:2] == ["docker", "inspect"]) == 3


def test_a_failed_compose_stops_init(tmp_path: Path) -> None:
    run = Run(tmp_path, compose=True)
    run.commands.table = {**DOCKER_OK, ("docker", "compose", "up"): (1, "")}
    assert run.go(run.answers()) == 1
    assert "`docker compose up -d db` failed" in run.text
    assert run.db == []


def test_a_person_at_the_terminal_is_asked_and_a_bad_value_is_asked_again(
    tmp_path: Path,
) -> None:
    run = Run(tmp_path)
    replies = {
        "Elasticsearch address": ["https://es.example.org:9200"],
        "trust https://es.example.org:9200": ["chain"],
        "Kibana's address": ["none"],
        "index patterns": ["corp-logs-*"],
        "Paste the SIEM key": [SIEM_KEY],
        "SIEM key expire": ["2027-03-01"],
        "organisation's name": ["Example Corp"],
        "security team's name": ["Example SOC"],
        "kind of organisation": ["company"],
        "own domains": ["example.org"],
        "public networks": ["not-a-network", "192.0.2.0/24"],
        "time zone": ["UTC"],
        "labelled": ["none"],
        "prefix of incident": ["soc-ir", "SOC-IR"],
        "Kibana space": ["soc"],
        "keys file": ["none"],
        "address people open": ["none"],
        "sign-in name": ["none"],
    }
    asked: list[str] = []

    def prompt(question: str, **kw: Any) -> str:
        asked.append(question)
        for part, answers in replies.items():
            if part in question and answers:
                return answers.pop(0)
        raise AssertionError(f"not expected: {question}")

    terminal = TerminalAnswers(prompt=prompt, confirm=lambda q, default: True if "Trust" in q
                               else default)  # fmt: skip
    assert run.go(terminal) == 0, run.text
    assert "not taken:" in run.text  # the network and the prefix were asked again
    site = yaml.safe_load((run.root / "config" / "site.yaml").read_text())["site"]
    assert site["own_networks"] == ["192.0.2.0/24"]
    assert site["incident_id_prefix"] == "SOC-IR"
    assert site["organisation"]["kind"] == "company"
    assert run.local()["siem"]["api_key_expires"].isoformat() == "2027-03-01"
    assert run.siem.names[0][-1] == "corp-logs-*"
    assert not [q for q in asked if "Start" in q]  # a confirm, answered by its default: no
    assert run.systemctl == ["daemon-reload"]
