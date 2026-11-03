"""P4-D1 part 2, step 5 (D-284): the first run's and the live check's subjects remember which of the
site's families the alert's rule reads, so the request names that family when the site has two or
more of the role; on a one-family site (ACME) the subjects and the requests are what they were."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from argus import site
from argus.context import batch1, live_check
from argus.site import LogFamily, Role, SiteSettings

pytestmark = pytest.mark.unit
NOW = datetime(2026, 10, 20, 16, 20, tzinfo=UTC)
TWO_PROXIES = SiteSettings(
    families=(
        LogFamily(name="edge", role=Role.PROXY, pattern="proxy-edge-*"),
        LogFamily(name="office", role=Role.PROXY, pattern="proxy-office-*"),
        LogFamily(name="www", role=Role.WEB, pattern="web-a-*"),
        LogFamily(name="shop", role=Role.WEB, pattern="web-b-*"),
    )
)


class Conn:
    """What ``batch1.subjects`` and ``live_check.subjects`` read: raw alerts, newest first."""

    def __init__(self, raws: list[dict[str, Any]]) -> None:
        self.raws = raws

    async def execute(self, *_: Any, **__: Any) -> Any:
        class Row:
            def __init__(self, raw: dict[str, Any]) -> None:
                self.raw, self.normalized = raw, None
                self.src = (raw.get("source") or {}).get("ip")
                self.dst = (raw.get("destination") or {}).get("ip")
                self.indices = ",".join(raw.get("kibana.alert.rule.indices", []))

        return [Row(raw) for raw in self.raws]


def alert(index: str, src: str, dst: str, **more: Any) -> dict[str, Any]:
    return {
        "kibana.alert.rule.indices": [index],
        "source": {"ip": src},
        "destination": {"ip": dst},
        **more,
    }


async def test_a_one_family_site_remembers_no_source() -> None:
    conn = Conn([alert("acme-logs-squid-*", "10.8.0.5", "45.9.9.9")])
    who = await batch1.subjects(conn)  # type: ignore[arg-type]
    assert set(who) == {"host", "destination", "pair", "web", "alert"}
    assert who["pair"] == ("10.8.0.5", "45.9.9.9")
    sent: list[Any] = []

    async def run(template: Any, params: Any) -> Any:
        sent.append(params)
        raise RuntimeError

    task = batch1.first_task("proxy.pair", who, NOW)
    assert not isinstance(task, batch1.Refusal)
    assert task.params.source is None  # type: ignore[union-attr]
    assert "source" not in task.params.model_dump(exclude_none=True)  # type: ignore[union-attr]


async def test_a_two_family_site_asks_the_family_the_rule_reads() -> None:
    conn = Conn([alert("proxy-office-*", "10.8.0.5", "45.9.9.9")])
    with site.using(TWO_PROXIES):
        who = await batch1.subjects(conn)  # type: ignore[arg-type]
        assert who["pair_source"] == "office"
        assert who["destination_source"] == "office"
        pair = batch1.first_task("proxy.pair", who, NOW)
        contact = batch1.first_task("proxy.contact", who, NOW)
        assert not isinstance(pair, batch1.Refusal)
        assert not isinstance(contact, batch1.Refusal)
        assert pair.params.source == "office"  # type: ignore[union-attr]
        assert contact.params.source == "office"  # type: ignore[union-attr]


async def test_a_web_subject_keeps_the_rules_indices_for_its_family() -> None:
    web = {
        "kibana.alert.rule.indices": ["web-b-*"],
        "source": {"ip": "203.0.113.5"},
        "url": {"domain": "shop.example.org", "path": "/.env"},
    }
    with site.using(TWO_PROXIES):
        who = await batch1.subjects(Conn([web]))  # type: ignore[arg-type]
        assert who["web_source"] == "shop"
        task = batch1.first_task("web.path_outcomes", who, NOW)
        assert not isinstance(task, batch1.Refusal)
        assert task.params.source == "shop"  # type: ignore[union-attr]
    who = await batch1.subjects(Conn([{**web, "kibana.alert.rule.indices": ["acme-logs-nginx-*"]}]))  # type: ignore[arg-type]
    assert "web_source" not in who  # ACME: one web family


async def test_the_live_check_remembers_the_family_only_when_there_are_several() -> None:
    conn = Conn([alert("proxy-edge-*", "10.8.0.5", "45.9.9.9")])
    with site.using(TWO_PROXIES):
        who = await live_check.subjects(conn)  # type: ignore[arg-type]
        assert (who["host"], who["destination"]) == ("10.8.0.5", "45.9.9.9")
        assert who["host_source"] == "edge"
        assert who["destination_source"] == "edge"
    acme = await live_check.subjects(
        Conn([alert("acme-logs-squid-*", "10.8.0.5", "45.9.9.9")])  # type: ignore[arg-type]
    )
    assert acme == {"host": "10.8.0.5", "destination": "45.9.9.9", "client": None}
