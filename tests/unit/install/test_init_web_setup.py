"""``argus init --web-setup`` (D-327): only this machine's part — the database, the web's
certificate, the web and argus-admin started — and a one-time link for the first administrator;
no question about the SIEM, its keys, the organisation or the AI providers (the app asks them)."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus.install.answers import ScriptedAnswers, TerminalAnswers
from tests.unit.install.test_run import Run

pytestmark = pytest.mark.unit


def test_the_host_part_starts_the_web_and_admin_and_prints_a_link(tmp_path: Path) -> None:
    run = Run(tmp_path)
    answers = ScriptedAnswers({"web.address": "192.0.2.10", "database.compose": False},
                              tmp_path / "a.yml")  # fmt: skip
    # the answers name no SIEM: a question about it would stop init (does not answer siem.url)
    assert run.go(answers, web_setup=True) == 0, run.text
    assert run.db == ["bootstrap", "upgrade"]
    assert "enable argus-web.service argus-admin.service" in run.systemctl
    assert "restart argus-web.service argus-admin.service" in run.systemctl  # a rerun: new code
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
    assert "the setup opens by itself" in run.text


def test_install_sh_asks_nothing_at_the_terminal(tmp_path: Path) -> None:
    """``./install.sh`` on a fresh machine: this machine's address, a self-signed certificate,
    the address's networks, no first person; every choice is the browser's (Settings changes
    them later). A question at the terminal fails the test."""
    run = Run(tmp_path, compose=True)

    def no_question(question: str, **_kw: object) -> str:
        raise AssertionError(f"asked at the terminal: {question}")

    terminal = TerminalAnswers(prompt=no_question, confirm=lambda q, default: default)
    assert run.go(terminal, web_setup=True) == 0, run.text
    web = run.local()["units"]["web"]
    assert web["public_url"] == "https://192.0.2.10:8765"  # the fake host's address
    assert web["allowed_networks"]
    assert run.people == []  # the administrator comes with the one-time link
    assert run.welcomed == ["admin"]
    assert "https://192.0.2.10:8765/welcome?token=tok-123" in run.text
    assert "argus user add" not in run.text
