"""The ``notified`` settings (AR4b, D-169, D-176): every day and limit of the known infection is a
setting with D-169's number as its default, an unknown key is an error, and the rules the pass
runs by are built from them."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from argus.cases import knownrun
from argus.cases.known import Rules
from argus.config import load_settings
from argus.config.settings import NotifiedSettings, Settings

ROOT = Path(__file__).resolve().parents[3]


def test_the_defaults_are_the_numbers_of_d_169() -> None:
    s = NotifiedSettings()
    assert (s.renotify_days, s.network_days, s.quiet_days) == (7, 21, 14)
    assert s.move_window == timedelta(hours=72)
    assert s.managed_types == ("lab", "computer-room")
    assert Settings().notified == s


def test_the_rules_come_from_the_settings() -> None:
    s = NotifiedSettings(
        renotify_days=2, network_days=5, quiet_days=9, active_days=1,
        move_window=timedelta(hours=24), move_gap=timedelta(hours=1), move_similarity=0.5,
        volume_factor=4, managed_types=("Server", "datacentre"), reopen_days=10,
    )  # fmt: skip
    rules = knownrun.rules_of(s)
    assert rules == Rules(
        renotify_days=2, network_days=5, quiet_days=9, active_days=1,
        move_window=timedelta(hours=24), move_gap=timedelta(hours=1), move_similarity=0.5,
        volume_factor=4, managed_types=frozenset({"server", "datacentre"}), reopen_days=10,
    )  # fmt: skip


@pytest.mark.parametrize(
    "bad",
    [
        {"renotify_days": 0},
        {"network_days": 400},
        {"quiet_days": -1},
        {"active_days": 0},
        {"move_similarity": 0},
        {"move_similarity": 1.5},
        {"volume_factor": 1},
        {"per_pass": 5},
        {"renotify_days": 10, "network_days": 7},  # the network-side reminder comes later
        {"move_gap": timedelta(days=5), "move_window": timedelta(days=2)},
        {"move_window": timedelta(minutes=5)},
        {"unknown_key": 1},
    ],
)
def test_a_bad_setting_is_an_error(bad: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        NotifiedSettings(**bad)  # type: ignore[arg-type]


def test_the_environment_and_the_yaml_set_them(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ARGUS_NOTIFIED__QUIET_DAYS", "30")
    monkeypatch.setenv("ARGUS_NOTIFIED__MANAGED_TYPES", "server, datacentre")
    settings = load_settings(ROOT / "config" / "argus.yaml", env_file=ROOT / "nonexistent.env")
    assert settings.notified.quiet_days == 30
    assert settings.notified.managed_types == ("server", "datacentre")
    assert settings.notified.renotify_days == 7  # the repository's file says what the code says


def test_the_repository_file_holds_the_defaults() -> None:
    settings = load_settings(ROOT / "config" / "argus.yaml", env_file=ROOT / "nonexistent.env")
    assert settings.notified == NotifiedSettings()
