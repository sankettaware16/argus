"""Q-E2 on the local Kibana tier (plan §5 gate): a disable, a password change or a role removal
in Elasticsearch 8.19.12 ends reading within 5 minutes plus one read and refuses changes after 30
seconds, through ARGUS's own identity lane (the real one, on the tier's recorded clients) and
the real web app on a throwaway database. D-109: the SIEM is never contacted.

Recorded with the tier up (docs/runbooks/kibana-tier.md): ``KIBANA_TIER_RECORD=new uv run pytest
tests/integration/web/test_elk_tier.py``; replayed from tests/kibana/cassettes afterwards. Until a
cassette exists, and without the tier, each test skips (the session rules themselves are proved
with a fake lane in test_elk_sessions.py).
"""

# ruff: noqa: F811
from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.web.app import create_app
from tests.integration.web.conftest import BASE, SAME_ORIGIN
from tests.integration.web.elk_rig import elk_settings, form_token
from tests.kibana import kit
from tests.kibana.conftest import kibana_tier, kt  # noqa: F401 - fixtures
from tests.kibana.test_identity_lane import lane as tier_lane
from tests.kibana.tier import Tier, seed

pytestmark = pytest.mark.integration
CASSETTES = Path(__file__).resolve().parents[2] / "kibana" / "cassettes"


@pytest.fixture(autouse=True)
def _needs_the_tier_or_a_cassette(request: pytest.FixtureRequest, kibana_tier: Tier) -> None:
    module = request.node.module.__name__.rsplit(".", 1)[-1].removeprefix("test_")
    name = f"{module}__{request.node.name}"
    recorded = (CASSETTES / f"{name}.json").exists() or any(
        CASSETTES.glob(f"{module}__{request.node.originalname}*.json")
    )
    if not kibana_tier.live and not recorded:
        pytest.skip("needs the local Kibana tier, or its cassette (KIBANA_TIER_RECORD=new)")


@pytest.fixture
async def web(
    kt: Tier,
    web_engine: AsyncEngine,
) -> tuple[object, ...]:
    identity, transport, _store, clock = tier_lane(kt)
    app = create_app(web_engine, elk_settings(), clock=clock, lane=identity, lane_clock=clock)
    return app, transport, clock


async def browser_for(
    app: object, transport: object, principal: str
) -> tuple[httpx.AsyncClient, str]:
    credential = transport.credential(principal)  # type: ignore[attr-defined]
    http = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),  # type: ignore[arg-type]
        base_url=BASE, headers=SAME_ORIGIN,
    )  # fmt: skip
    form = await http.get("/signin")
    made = await http.post("/signin", data={
        "username": credential.username, "password": credential.password.get_secret_value(),
        "signin_token": form_token(form.text),
    })  # fmt: skip
    assert made.status_code == 303, made.text
    return http, (await http.get("/api/v1/session")).json()["csrf_token"]


def revoke(kt: Tier, change: str, suffix: str, name: str) -> None:
    es = kt.es("elastic")
    if change == "disable":
        assert es.put(f"/_security/user/{name}/_disable").status == 200
    elif change == "password":
        assert es.post(f"/_security/user/{name}/_password",
                       {"password": kt.password()}).status == 200  # fmt: skip
    else:  # role removal: no role left, so no access to the space
        body = {"roles": [], "full_name": f"Run {suffix}",
                "metadata": {"argus_uid": seed.argus_uid(suffix)}}  # fmt: skip
        assert es.put(f"/_security/user/{name}", body).status == 200


@pytest.mark.parametrize("change", ["disable", "password", "roles"])
async def test_a_removal_in_elk_ends_reading_within_five_minutes_plus_one_read(
    kt: Tier,
    web: tuple[object, ...],
    change: str,
) -> None:
    app, transport, clock = web
    suffix = f"rd-{change}"
    principal = kit.make_user(kt, suffix, ["acme_reviewer"],
                              metadata={"argus_uid": seed.argus_uid(suffix)})  # fmt: skip
    http, _csrf = await browser_for(app, transport, principal)
    assert (await http.get("/api/investigations")).status_code in (200, 403)  # the page is served
    revoke(kt, change, suffix, kt.name(suffix))
    clock.advance(timedelta(minutes=4, seconds=59))  # type: ignore[attr-defined]
    assert (await http.get("/api/v1/session")).status_code == 200  # not yet re-checked
    clock.advance(timedelta(seconds=1))  # type: ignore[attr-defined]
    assert (await http.get("/api/v1/session")).status_code == 200  # the read that finds out
    await app.state.elk.settle()  # type: ignore[attr-defined]
    assert (await http.get("/api/v1/session")).status_code == 401  # reading has ended
    await http.aclose()


@pytest.mark.parametrize("change", ["disable", "password", "roles"])
async def test_a_removal_in_elk_refuses_changes_after_thirty_seconds(
    kt: Tier, web: tuple[object, ...], seeded: AsyncEngine, change: str
) -> None:
    app, transport, clock = web
    suffix = f"ch-{change}"
    principal = kit.make_user(kt, suffix, ["acme_reviewer"],
                              metadata={"argus_uid": seed.argus_uid(suffix)})  # fmt: skip
    http, csrf = await browser_for(app, transport, principal)

    async def review() -> httpx.Response:
        first = (await http.get("/api/investigations", params={"view": "all"})).json()[0]
        return await http.post(
            f"/api/investigations/{first['id']}/reviews",
            json={"action": "note", "note": "seen", "seen_review": first["latest_review"],
                  "seen_version": first["version"]},
            headers={"X-CSRF-Token": csrf},
        )  # fmt: skip

    revoke(kt, change, suffix, kt.name(suffix))
    clock.advance(timedelta(seconds=30))  # type: ignore[attr-defined]
    assert (await review()).status_code == 201  # 30 s after the check: still the snapshot
    clock.advance(timedelta(seconds=1))  # type: ignore[attr-defined]
    assert (await review()).status_code == 401  # a live check finds out: nothing is written
    await http.aclose()
