"""Independent review of Q-E3 (integration repros; each failed on the reviewed head)."""

# ruff: noqa: F811, F401

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.identity import cli as identity_cli
from tests.integration.test_cli_db import cli_env
from tests.integration.web.elk_rig import Rig
from tests.integration.web.test_elk_cli import elk_on, rig, run
from tests.integration.web.test_elk_cutover import (
    line_of,
    link,
    local_app_login,
    signed_in_elk,
    status,
)

pytestmark = pytest.mark.integration
LONG = "p" * 300


@pytest.fixture(autouse=True)
def at_a_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(identity_cli, "_at_a_terminal", lambda: True)


async def _switched_off(rig: Rig, elk_on: Path) -> None:
    await link(elk_on, "asha", "Asha.Rao")
    await signed_in_elk(rig, "Asha.Rao")
    assert (await run(elk_on, "identity", "disable-local", "asha"))[0] == 0


async def test_r1_enable_local_with_a_too_long_password_ends_in_words(
    rig: Rig,
    elk_on: Path,
) -> None:
    await _switched_off(rig, elk_on)
    code, out = await run(elk_on, "identity", "enable-local", "asha", text_in=f"{LONG}\n{LONG}\n")
    assert code == 1
    assert "at most 256" in out
    assert await rig.scalar("SELECT password_hash IS NULL FROM users WHERE username = 'asha'")


async def test_r2_enable_local_for_an_account_that_began_with_elk_is_not_a_false_success(
    rig: Rig,
    elk_on: Path,
    web_engine: AsyncEngine,
) -> None:
    # an ELK-born account has no capabilities of its own ('{}'): a local password alone cannot
    # sign it in ("no access"), yet the command says "a local password is on again"
    await signed_in_elk(rig, "New.Person")
    code, out = await run(elk_on, "identity", "enable-local", "new.person",
                          text_in="newpass-12345\nnewpass-12345\n")  # fmt: skip
    assert await local_app_login(web_engine, "new.person", "newpass-12345") != 200
    assert code == 1
    assert "began with ELK" in out
    assert await rig.scalar("SELECT password_hash IS NULL FROM users WHERE username = 'new.person'")


async def test_r3_linking_to_the_elk_name_that_is_another_local_handle_is_flagged(
    rig: Rig,
    elk_on: Path,
) -> None:
    # 'ravi' is another person's local handle; asha linked to the ELK name 'ravi' hands ravi's
    # own ELK sign-in asha's account, and then `disable-local asha` passes on ravi's sign-in
    code, out = await run(elk_on, "identity", "link", "asha", "--elk", "ravi")
    assert code == 1, out
    assert "another account (ravi)" in out, out
    assert await rig.scalar("SELECT elk_username IS NULL FROM users WHERE username = 'asha'")
    code, out = await run(
        elk_on, "identity", "link", "asha", "--elk", "ravi", "--yes-different-person"
    )
    assert code == 0, out
    assert await rig.scalar("SELECT elk_username FROM users WHERE username = 'asha'") == "ravi"


async def test_r4_disable_local_does_not_act_on_a_disabled_account(
    rig: Rig,
    elk_on: Path,
) -> None:
    # `disable_local` never reads `users.disabled`: a closed account is switched off and audited
    # as if it were a live cut-over (status calls the same account "closed")
    await link(elk_on, "asha", "Asha.Rao")
    await signed_in_elk(rig, "Asha.Rao")
    assert (await run(elk_on, "user", "disable", "asha"))[0] == 0
    code, out = await run(elk_on, "identity", "disable-local", "asha")
    assert code == 1, out
    assert "is disabled" in out, out
    assert not await rig.scalar("SELECT password_hash IS NULL FROM users WHERE username = 'asha'")
    assert (
        await rig.scalar("SELECT count(*) FROM audit_events WHERE action = 'user.local_disabled'")
        == 0
    )


async def test_r5_r6_a_hand_linked_account_is_linked_again_with_the_command(
    rig: Rig,
    elk_on: Path,
) -> None:
    async with rig.owner.begin() as conn:
        await conn.execute(
            text(
                "UPDATE users SET elk_username = 'Asha.Rao', realm = 'native'"
                " WHERE username = 'asha'"
            )
        )
    out = await status(elk_on)
    asha = line_of(out, "asha")
    assert "linked outside the tool" in asha
    assert "waiting for" not in asha
    assert "not yet" in asha
    code, out = await run(elk_on, "identity", "link", "asha", "--elk", "Other.Name")
    assert code == 1
    assert "already linked to 'Asha.Rao'" in out
    code, out = await run(elk_on, "identity", "link", "asha", "--elk", "Asha.Rao")
    assert code == 0, out
    code, out = await run(elk_on, "identity", "link", "asha", "--elk", "Asha.Rao")
    assert code == 1
    assert "already linked" in out
    assert "waiting for their first ELK sign-in" in line_of(await status(elk_on), "asha")
    by = await rig.scalar("SELECT details->>'by' FROM audit_events WHERE action = 'user.link'")
    assert by  # the operator is recorded like disable/enable
