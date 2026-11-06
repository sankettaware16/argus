"""The confirm dialog's Kibana sentence follows the case team's own switches file (D-214): its
unit reads posting on/off and the day's cap there, not from the shared configuration the web
reads, so the web reads that file too (read only)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from argus.web import decisions

pytestmark = pytest.mark.unit


@dataclass
class Team:
    post: bool = False
    per_day: int = 5


def _switches(root: Path, text: str) -> Path:
    (root / "local").mkdir()
    (root / "local" / "argus-writer.env").write_text(text, encoding="utf-8")
    return root


def test_without_the_file_the_webs_own_settings_say(tmp_path: Path) -> None:
    assert decisions.team_switches(Team(), tmp_path) == (False, 5)
    assert decisions.team_switches(Team(post=True, per_day=3), tmp_path) == (True, 3)
    assert decisions.team_switches(None, tmp_path) == (False, 0)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("ARGUS_CASE_TEAM__POST=true\n", (True, 5)),
        ("ARGUS_CASE_TEAM__POST=false\nARGUS_CASE_TEAM__PER_DAY=2\n", (False, 2)),
        ("ARGUS_CASE_TEAM__POST=on\nARGUS_CASE_TEAM__PER_DAY=x\n", (True, 5)),
        ("# only a comment\n", (False, 5)),
    ],
)
def test_the_case_teams_file_overrides(
    tmp_path: Path, text: str, expected: tuple[bool, int]
) -> None:
    assert decisions.team_switches(Team(), _switches(tmp_path, text)) == expected
