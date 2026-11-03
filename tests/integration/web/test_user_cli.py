"""Q-A1: local accounts' capabilities at the terminal: ``argus user grant``, ``revoke``,
``list`` and ``add --capability``, each audited, each refusing an unknown name."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

from argus.config import DatabaseSettings
from argus.web import auth
from tests.integration.test_cli_db import _connect, _invoke, cli_env  # noqa: F401

pytestmark = pytest.mark.integration


def accounts(settings: DatabaseSettings, name: str) -> dict[str, list[str]]:
    with _connect(settings, name) as conn:
        return {u: list(c) for u, c in conn.execute("SELECT username, capabilities FROM users")}


def audited(settings: DatabaseSettings, name: str) -> list[tuple[Any, ...]]:
    with _connect(settings, name) as conn:
        return conn.execute(
            "SELECT action, target_id, details FROM audit_events WHERE action LIKE 'user.%'"
            " ORDER BY id"
        ).fetchall()


@pytest.fixture
def ready(cli_env: Path, db_settings: DatabaseSettings, test_database: str) -> Path:  # noqa: F811
    code, out = _invoke("db", "upgrade", "-c", str(cli_env))
    assert code == 0, out
    with _connect(db_settings, test_database) as conn:
        conn.execute(
            "INSERT INTO users (username, display_name, password_hash) VALUES ('asha', 'Asha', %s)",
            (auth.hash_password("correct horse battery"),),
        )
        conn.commit()
    return cli_env


def test_grant_revoke_and_list(ready: Path, db_settings: DatabaseSettings,
                               test_database: str) -> None:  # fmt: skip
    config = str(ready)
    assert accounts(db_settings, test_database) == {
        "asha": ["view", "see_logs", "review", "answer_gold"]
    }  # what every account had
    code, out = _invoke("user", "grant", "asha", "approve", "-c", config)
    assert code == 0, out
    assert "asha may: view, see_logs, review, answer_gold" in out
    assert "note: approve counts only with manage_cases" in out
    code, out = _invoke("user", "grant", "asha", "manage_cases", "reopen", "-c", config)
    assert "asha may: view, see_logs, review, answer_gold, manage_cases, reopen, approve" in out
    code, out = _invoke("user", "revoke", "asha", "review", "-c", config)
    assert code == 0, out
    assert "note: answer_gold counts only with review" in out
    assert accounts(db_settings, test_database)["asha"] == [
        "view",
        "see_logs",
        "answer_gold",
        "manage_cases",
        "reopen",
        "approve",
    ]
    code, out = _invoke("user", "list", "-c", config)
    assert code == 0, out
    assert "asha (Asha), never seen; may: view, see_logs, manage_cases, reopen, approve" in out
    code, out = _invoke("user", "grant", "asha", "root", "-c", config)
    assert code == 2
    assert "unknown capability root" in out
    code, out = _invoke("user", "grant", "nobody", "view", "-c", config)
    assert code == 1
    assert "no user nobody" in out
    assert [(a, t, d["capabilities"]) for a, t, d in audited(db_settings, test_database)] == [
        ("user.grant", "asha", ["approve"]),
        ("user.grant", "asha", ["manage_cases", "reopen"]),
        ("user.revoke", "asha", ["review"]),
    ]


def test_adding_an_account_with_chosen_capabilities(
    ready: Path, db_settings: DatabaseSettings, test_database: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    import argus.web.cli as web_cli

    class Terminal:
        stdin = type("In", (), {"isatty": staticmethod(lambda: True)})()

    monkeypatch.setattr(web_cli, "sys", Terminal)
    monkeypatch.setattr(web_cli.typer, "prompt", lambda *a, **k: "a long pass phrase 1")
    code, out = _invoke("user", "add", "vera", "--name", "Vera", "--capability", "view",
                        "-c", str(ready))  # fmt: skip
    assert code == 0, out
    code, out = _invoke("user", "add", "omar", "-c", str(ready))
    assert code == 0, out
    assert accounts(db_settings, test_database) == {
        "asha": ["view", "see_logs", "review", "answer_gold"], "vera": ["view"],
        "omar": ["view", "see_logs", "review", "answer_gold"]}  # fmt: skip
    code, out = _invoke("user", "add", "zed", "--capability", "everything", "-c", str(ready))
    assert code == 2
    assert "unknown capability everything" in out
    assert sys.stdin is not None  # the real one, untouched
