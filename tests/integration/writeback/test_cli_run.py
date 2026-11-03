"""``argus writeback run`` end to end below the terminal: the operator's check through the
identity lane (a fake lane here; the local tier and the user prove the real one), the sender, and
the exit codes. The prompt and getpass are the terminal's; this drives what follows them."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncEngine

from argus import writeback, writeback_cli
from argus.config.settings import Settings
from argus.identity.lane import Access, Checked, Identity, IdentityDeniedError
from argus.identity.names import Credential
from argus.web.capabilities import Capability
from tests.integration.writeback.kit import Rig, rig
from tests.integration.writeback.test_writeback import alerts, plan, review, rows

pytestmark = pytest.mark.integration


class Lane:
    transport = None

    def __init__(self, *caps: Capability, deny: bool = False) -> None:
        self.caps, self.deny, self.checked = frozenset(caps), deny, []
        self.now = lambda: datetime.now(UTC)

    async def check(self, credential: Credential, *, deadline: datetime) -> Checked:
        self.checked.append(credential.username)
        if self.deny:
            raise IdentityDeniedError("denied")
        now = self.now()
        return Checked(
            Identity(credential.username, "uid-1", None, None),
            Access(credential.username, self.caps, False, 1, now),
        )


def wire(monkeypatch: pytest.MonkeyPatch, r: Rig, lane: Lane) -> Settings:
    """The command's pieces are the rig's: its gateways, its clock, the lane given."""
    lane.now = lambda: r.clock.now
    sender = writeback_cli.AlertSender
    monkeypatch.setattr(
        writeback_cli,
        "AlertSender",
        lambda *a, **k: sender(*a, clock=r.clock, sleep=r.clock.sleep, **k),
    )
    monkeypatch.setattr("argus.gateway.service.build_gateway", lambda *a, **k: (r.es, r.lane))
    monkeypatch.setattr(
        "argus.gateway.kibana.service.build_kibana_gateway", lambda *a, **k: r.gateway
    )
    monkeypatch.setattr("argus.identity.service.build_identity_lane", lambda *a, **k: lane)
    return Settings.model_validate({"writeback": {"enabled": True}})


async def test_a_run_without_an_operator_sends_what_needs_none(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:  # fmt: skip
    r = rig(migrated_engine, writer_engine)
    s = wire(monkeypatch, r, Lane())
    await alerts(app_engine, 3)
    await review(app_engine, "benign_expected", ready=True)
    await plan(app_engine)
    await r.seed_world()
    r.healthy()
    code = await writeback_cli._run(s, r.engine, None, None)
    out = capsys.readouterr()
    assert code == 0, out
    assert "3 alerts changed in 1 calls" in out.out


async def test_an_operator_with_the_alert_status_privileges_sends_earlier_reviews(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:  # fmt: skip
    r = rig(migrated_engine, writer_engine)
    lane = Lane(Capability.VIEW, Capability.REVIEW)
    s = wire(monkeypatch, r, lane)
    await alerts(app_engine, 3)
    await review(app_engine, "benign_expected", ready=False)
    async with app_engine.begin() as conn:
        await writeback.plan(conn, older=True)
    await r.seed_world()
    r.healthy()
    credential = Credential("ravi", SecretStr("pw"))
    code = await writeback_cli._run(s, r.engine, credential, None)
    assert code == 0
    assert lane.checked == ["ravi"]
    assert "signed in as ravi" in capsys.readouterr().out
    assert [tuple(x) for x in await rows(app_engine)] == [("sent", "closed", 3)]
    assert (await r.row()).operator == "ravi"


@pytest.mark.parametrize(
    ("lane", "says"),
    [
        (Lane(Capability.VIEW), "may not change alert status"),
        (Lane(deny=True), "operator check failed (denied)"),
    ],
    ids=["no alert-status privileges", "denied by Elasticsearch"],
)
async def test_an_operator_who_may_not_write_sends_nothing(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], lane: Lane, says: str,
) -> None:  # fmt: skip
    r = rig(migrated_engine, writer_engine)
    s = wire(monkeypatch, r, lane)
    await alerts(app_engine, 3)
    await review(app_engine, "benign_expected", ready=False)
    async with app_engine.begin() as conn:
        await writeback.plan(conn, older=True)
    await r.seed_world()
    r.healthy()
    code = await writeback_cli._run(s, r.engine, Credential("ravi", SecretStr("pw")), None)
    assert code == 2
    assert says in capsys.readouterr().err
    assert r.world.calls == []
    assert (await r.row()).state == "planned"


async def test_a_paused_run_exits_1_and_says_why(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:  # fmt: skip
    r = rig(migrated_engine, writer_engine)
    s = wire(monkeypatch, r, Lane())
    await alerts(app_engine, 3)
    await review(app_engine, "benign_expected", ready=True)
    await plan(app_engine)
    await r.seed_world()
    r.lane.stopped.add("writeback")
    r.healthy()
    assert await writeback_cli._run(s, r.engine, None, None) == 1
    assert "stopped by the kill switch" in capsys.readouterr().out
