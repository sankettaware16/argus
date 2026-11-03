"""short_db_error: one line, with the server's hint when it gives one."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from sqlalchemy.exc import ProgrammingError

from argus.db.errors import short_db_error


def _error(message: str, hint: object) -> ProgrammingError:
    original = Exception(message)
    original.sqlstate = "42704"  # type: ignore[attr-defined]
    original.diag = SimpleNamespace(message_hint=hint)  # type: ignore[attr-defined]
    return ProgrammingError("UPGRADE ...", None, original)


@pytest.mark.parametrize(
    ("hint", "suffix"),
    [
        ('run "argus db bootstrap" first', ' (hint: run "argus db bootstrap" first)'),
        ("first line\nsecond  line\n", " (hint: first line second line)"),
        ("   ", ""),
        ("", ""),
        (None, ""),
    ],
    ids=["hint", "multi-line", "blank", "empty", "none"],
)
def test_the_server_hint_is_kept_on_the_same_line(hint: object, suffix: str) -> None:
    line = short_db_error(_error('role "argus_runtime" does not exist', hint), "upgrade")
    assert line == f'upgrade failed: role "argus_runtime" does not exist{suffix}'
    assert "\n" not in line


def test_a_hint_is_redacted_like_the_rest() -> None:
    line = short_db_error(_error("refused", "password=fake-hint-secret-1234"), "bootstrap")
    assert "fake-hint-secret-1234" not in line
