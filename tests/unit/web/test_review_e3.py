"""Independent review of Q-E3 (unit repros; each fails on the reviewed head)."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from argus.web import cutover

pytestmark = pytest.mark.unit


class _Result:
    def __init__(self, row: Any) -> None:
        self._row = row

    def first(self) -> Any:
        return self._row


class _Conn:
    """A connection whose only answer is one person account with its local password off."""

    async def execute(self, *_a: Any, **_k: Any) -> _Result:
        return _Result(SimpleNamespace(id=1, kind="person", disabled=False, password_on=False))


async def test_r1_enable_local_with_a_too_long_password_is_a_refusal_in_words() -> None:
    # auth.hash_password allows 10..256 characters and raises ValueError above: enable_local only
    # checks the minimum, so the terminal command ends in a traceback instead of an error line
    with pytest.raises(cutover.CutoverError):
        await cutover.enable_local(_Conn(), "asha", "x" * 300, operator="op")  # type: ignore[arg-type]
    with pytest.raises(cutover.CutoverError, match="at most 256"):
        await cutover.enable_local(_Conn(), "asha", "x" * 9, operator="op")  # type: ignore[arg-type]


def test_r5_status_does_not_show_a_sign_in_date_for_an_account_it_calls_waiting() -> None:
    from datetime import UTC, datetime

    # an account linked by hand (no `user.link` row) that has an `elk_first_signin_at`: the line
    # reads "ELK sign-in 2026-10-20 ..." and "waiting for their first ELK sign-in" together
    seen = datetime(2026, 10, 20, 9, 0, tzinfo=UTC)
    account = cutover.Account("asha", "Asha", "person", "Asha.Rao", False, True, None, None, seen)
    line = next(
        ln for ln in cutover.render([account], cutover.Glass(False, None, None, None),
                                    elk_mode=True) if ln.startswith("  asha")
    )  # fmt: skip
    assert "waiting for their first ELK sign-in" not in line or "not yet" in line, line


def test_r5_a_hand_linked_account_is_named_and_shows_no_date() -> None:
    from datetime import UTC, datetime

    seen = datetime(2026, 10, 20, 9, 0, tzinfo=UTC)
    account = cutover.Account("asha", "Asha", "person", "Asha.Rao", False, True, None, None, seen)
    assert account.state == "waiting"
    assert account.seen is None
    assert "linked outside the tool" in account.reason
    assert "argus identity link asha --elk Asha.Rao" in account.reason
    born = cutover.Account("new", "New", "person", "New.Person", False, False, None, None, seen)
    assert born.state == "done"
    assert born.seen == seen


def test_r7_the_ready_count_says_it_waits_for_the_gate_when_elk_sign_in_is_off() -> None:
    from datetime import UTC, datetime

    at = datetime(2026, 10, 20, 9, 0, tzinfo=UTC)
    ready = cutover.Account("asha", "Asha", "person", "Asha.Rao", False, True, at, at, at)
    nobody = cutover.Glass(False, None, None, None)
    off = cutover.render([ready], nobody, elk_mode=False)[1]
    on = cutover.render([ready], nobody, elk_mode=True)[1]
    assert "1 ready to switch off (waits for web.elk_signin)" in off
    assert "waits for" not in on
