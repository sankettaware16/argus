"""``argus init --web-setup`` (D-327): only this machine's part — the database, the web's
certificate, the web and argus-admin started — and a one-time link for the first administrator;
no question about the SIEM, its keys, the organisation or the AI providers (the app asks them)."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus.install.answers import ScriptedAnswers
from tests.unit.install.test_run import Run

pytestmark = pytest.mark.unit


def test_the_host_part_starts_the_web_and_admin_and_prints_a_link(tmp_path: Path) -> None:
    run = Run(tmp_path)
    answers = ScriptedAnswers({"web.address": "192.0.2.10", "database.compose": False},
                              tmp_path / "a.yml")  # fmt: skip
    # the answers name no SIEM: a question about it would stop init (does not answer siem.url)
    assert run.go(answers, web_setup=True) == 0, run.text
    assert run.db == ["bootstrap", "upgrade"]
    assert "enable --now argus-web.service argus-admin.service" in run.systemctl
    local = run.local()
    assert local["units"]["run"] == ["argus-web.service", "argus-admin.service"]
    assert local["units"]["web"]["public_url"] == "https://192.0.2.10:8765"
    assert "siem" not in local
    assert run.welcomed == ["admin"]
    assert "https://192.0.2.10:8765/welcome?token=tok-123" in run.text


def test_a_second_run_makes_no_second_administrator(tmp_path: Path) -> None:
    run = Run(tmp_path)
    run.people.append(("admin", "Administrator", "x"))
    answers = ScriptedAnswers({"web.address": "192.0.2.10", "database.compose": False},
                              tmp_path / "a.yml")  # fmt: skip
    assert run.go(answers, web_setup=True) == 0, run.text
    assert run.welcomed == []
    assert "a card on Today leads to it" in run.text
