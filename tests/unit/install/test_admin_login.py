"""Init with an Elastic administrator's login (D-330): ARGUS's read-only keys are made with it
(the same requests a person would paste, for a year), the case team's users when asked; the
login is never written or printed, and a login that may not make keys stops init with why."""

from __future__ import annotations

import dataclasses
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from argus.caseteam import provision
from argus.caseteam.provision import Answer
from argus.install.run import KEY_DAYS, run_init
from tests.unit.install.test_run import Run

PASSWORD = "admin-pass-not-to-be-seen"
MADE = {"argus-reader": "bWFkZS1zaWVtLWtleTp2YWx1ZQ==",
        "argus-kibana-reader": "bWFkZS1raWJhbmEta2V5OnZhbHVl"}  # fmt: skip


class AdminSiem:
    def __init__(self, status: int = 200) -> None:
        self.status = status
        self.calls: list[tuple[str, str, Any]] = []
        self.login: tuple[str, str] | None = None

    def call(self, method: str, path: str, body: Any = None, **_: Any) -> Answer:
        self.calls.append((method, path, body))
        if self.status != 200:
            return Answer(self.status, {})
        return Answer(200, {"encoded": MADE[body["name"]]})


def go(run: Run, admin: AdminSiem, **given: Any) -> int:
    secret = run.tmp / "admin.pw"
    secret.write_text(PASSWORD)
    secret.chmod(0o600)

    def connect(url: str, ca: Path, user: str, password: str, say: Any) -> AdminSiem:
        admin.login = (user, password)
        return admin

    answers = run.answers(**{"siem.api_key_file": ..., "kibana.api_key_file": ...,
                             "elastic.admin_user": "elastic",
                             "elastic.admin_password_file": str(secret), **given})  # fmt: skip
    run.said.clear()
    host = dataclasses.replace(run.host(), admin_siem=connect)
    return run_init(run.options(), answers, host)


def test_the_keys_are_made_with_the_login_and_the_login_kept_nowhere(tmp_path: Path) -> None:
    run, admin = Run(tmp_path), AdminSiem()
    assert go(run, admin) == 0, run.text
    assert admin.login == ("elastic", PASSWORD)
    made = [body for method, path, body in admin.calls if path == "/_security/api_key"]
    assert [b["name"] for b in made] == ["argus-reader", "argus-kibana-reader"]
    assert made[0]["expiration"] == f"{KEY_DAYS}d"
    assert made[0]["role_descriptors"]["argus_reader"]["cluster"] == ["monitor"]
    env = (run.root / ".env").read_text()
    assert f"ARGUS_SIEM__API_KEY={MADE['argus-reader']}" in env
    assert f"ARGUS_KIBANA__READER_API_KEY={MADE['argus-kibana-reader']}" in env
    until = datetime.now(UTC).date() + timedelta(days=KEY_DAYS)
    assert run.local()["siem"]["api_key_expires"] in (until, str(until))
    for place in [run.text, env, *(p.read_text() for p in (run.root / "config").glob("*.yaml"))]:
        assert PASSWORD not in place
        assert MADE["argus-reader"] not in run.text
    assert "made with the administrator's login" in run.text


def test_a_login_that_may_not_make_keys_stops_init_with_why(tmp_path: Path) -> None:
    run = Run(tmp_path)
    assert go(run, AdminSiem(403)) != 0
    assert "may not make API keys" in run.text
    assert PASSWORD not in run.text


def test_the_case_team_is_made_when_asked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run, admin = Run(tmp_path), AdminSiem()
    seen: list[Any] = []

    def apply(plan: Any, siem: Any, *, say: Any, **_: Any) -> provision.Outcome:
        seen.append((plan, siem))
        return provision.Outcome(made=["argus-lead"], expires=date(2027, 11, 17))

    monkeypatch.setattr(provision, "apply", apply)
    assert go(run, admin, **{"case_team.provision": True}) == 0, run.text
    [(plan, siem)] = seen
    assert siem is admin
    assert plan.credentials == run.root / "local" / "creds-writer"
    assert run.local()["case_team"]["keys_expire"] in (date(2027, 11, 17), "2027-11-17")
    assert "posting stays off" in run.text
    run2, admin2 = Run(tmp_path / "again"), AdminSiem()
    seen.clear()
    assert go(run2, admin2) == 0
    assert seen == []  # not asked: no case team


def test_an_address_with_a_trailing_slash_is_the_same_address(tmp_path: Path) -> None:
    run = Run(tmp_path)
    assert run.go(run.answers(**{"siem.url": "https://es.example.org:9200/"})) == 0, run.text
    assert run.local()["siem"]["url"] == "https://es.example.org:9200"
