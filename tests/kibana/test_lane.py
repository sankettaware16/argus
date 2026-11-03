"""Q-D2's Kibana lane on the local tier: ARGUS's own templates, validator, gateway, response
checks and key self-test against Kibana 8.19.12 Basic (D-109: the SIEM is never contacted).

The lane's requests go through ``TierKibana``, which sends them with the tier's recorded clients
(so the cassettes hold them and replay proves them without the tier); the real HTTPS transport
(pinned CA, ``kbn-xsrf``, no redirects) is proven live only, at the end. The gateway runs on a
fake clock set inside the write window, its state in memory.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from argus.gateway.budget import BudgetConfig
from argus.gateway.errors import TemplateRejectedError
from argus.gateway.gateway import Gateway, Targets
from argus.gateway.health import HealthMemory
from argus.gateway.kibana import models, selftest
from argus.gateway.kibana.gateway import KibanaGateway, KibanaTargets, WriteContext
from argus.gateway.kibana.templates import (
    AlertCases,
    AlertParams,
    AttachAlerts,
    AttachParams,
    CaseAlerts,
    CaseComments,
    CaseGet,
    CasePageParams,
    CaseParams,
    CasesConfigure,
    CasesFind,
    CaseUserActions,
    CloseCase,
    CommentOnCase,
    CommentParams,
    CreateCase,
    FindParams,
    KeyRole,
    KibanaStatus,
    KibanaTemplate,
    NoParams,
    UpdateCase,
)
from argus.gateway.kibana.transport import KResponse, KWire, wire_refusal
from argus.gateway.kibana.writes import WriteClass
from argus.gateway.state import MemoryStore
from argus.gateway.transport import WireRequest, WireResponse
from tests.kibana import kit
from tests.kibana.tier import SPACE, Tier
from tests.unit.gateway.fakes import FakeClock

T0 = datetime(2026, 10, 23, 10, 0, tzinfo=UTC)  # inside the write window
ROLES = {
    KeyRole.READER: "key:argus-kibana-reader",
    KeyRole.CASES: "key:argus-cases-writer-actions",  # DQ3 (a)'s preferred writer
    KeyRole.ALERTS: "key:argus-alert-writer",
}
ALL = frozenset({WriteClass.W1, WriteClass.W2, WriteClass.W3})


@dataclass
class TierKibana:
    """The lane's transport through the tier's recorded clients, with the real transport's
    route guard; a role is a seeded key."""

    kt: Tier
    roles: Mapping[KeyRole, str] = field(default_factory=lambda: dict(ROLES))
    sent: list[KWire] = field(default_factory=list)

    def refusal(self, request: KWire) -> TemplateRejectedError | None:
        why = wire_refusal(request, SPACE)
        if why is not None:
            return TemplateRejectedError("route_refused", why)
        return None if request.key in self.roles else TemplateRejectedError("no_key", "no key")

    async def send(self, request: KWire) -> KResponse:
        refused = self.refusal(request)
        if refused is not None:
            raise refused
        names = [name for name, _ in request.params]
        assert len(names) == len(set(names)), "the recorded client takes one value a name"
        self.sent.append(request)
        client = self.kt.kibana if request.target == "kibana" else self.kt.es
        reply = client(self.roles[request.key]).call(
            request.method,
            request.path,
            None if request.body is None else json.loads(request.body),
            params=dict(request.params),
            keep=steady_status if request.path.endswith("/api/status") else None,
        )
        return KResponse(reply.status, json.dumps(reply.body).encode(), 5.0, None)


def steady_status(body: Any) -> Any:
    """``api/status`` without its metrics and plugin statuses (they change from run to run):
    what the lane reads of it, in the shape Kibana answers."""
    return {"name": body["name"], "version": body["version"],
            "status": {"overall": body["status"]["overall"]}}  # fmt: skip


@dataclass
class TierElasticsearch:
    """The Elasticsearch gateway's transport through the tier, as the runbook's reader key."""

    kt: Tier

    async def send(self, request: WireRequest) -> WireResponse:
        reply = self.kt.es("key:argus-reader").call(
            request.method,
            request.path,
            None if request.body is None else json.loads(request.body),
            params=dict(request.params),
        )
        return WireResponse(reply.status, json.dumps(reply.body).encode(), 5.0)


def lane(
    kt: Tier, classes: frozenset[WriteClass] = frozenset(), roles: Mapping[KeyRole, str] = ROLES
) -> tuple[KibanaGateway, TierKibana, MemoryStore, FakeClock]:
    clock = FakeClock(T0)
    store = MemoryStore(memory=HealthMemory(probed_at=T0), budget_config=BudgetConfig())
    es = Gateway(TierElasticsearch(kt), store, targets=Targets(), clock=clock, sleep=clock.sleep)
    transport = TierKibana(kt, roles)
    gateway = KibanaGateway(
        transport, store, targets=KibanaTargets(space=SPACE), classes=classes, es_gateway=es,
        clock=clock, sleep=clock.sleep,
    )  # fmt: skip
    return gateway, transport, store, clock


def argus_case_tag(kt: Tier) -> str:
    """This test's own ARGUS case id (a new one each run, the same placeholder in cassettes)."""
    return f"argus:case:{uuid.uuid5(uuid.NAMESPACE_URL, f'{kt.run}-{kit.test_key(kt)}')}"


def forget_case(kt: Tier, case_id: str) -> None:
    def delete() -> None:
        admin = kt.admin("kibana")
        try:
            admin.request("DELETE", f"/s/{SPACE}/api/cases", params={"ids": json.dumps([case_id])},
                          ok=(204, 404))  # fmt: skip
        finally:
            admin.close()

    kt.on_finish(delete)


def later(clock: FakeClock, seconds: float, store: MemoryStore) -> None:
    clock.advance(timedelta(seconds=seconds))
    store.memory = HealthMemory(probed_at=clock.now)  # the probe keeps running meanwhile


async def write(
    gateway: KibanaGateway, run: Any, template: KibanaTemplate, params: Any, cls: WriteClass,
    clock: FakeClock, *, outbox: str, approval: str | None = None,
) -> Any:  # fmt: skip
    context = WriteContext(cls, outbox, gateway.payload_hash(template, params), approval)
    return await gateway.write(template, params, run=run, context=context, component="tier",
                               deadline=clock.now + timedelta(minutes=5))  # fmt: skip


async def test_every_class_through_the_lane(kt: Tier) -> None:
    """W1 (create, comment, attach), W2 (severity and an owner tag, status), W3 (close with
    reason tags, then the comment), then a reopen (W2): each answer passes its check, Kibana
    shows ARGUS's key owner as author, Sync alerts stays off, every alert's case ids follow."""
    alert = kit.make_alerts(kt, "lane", 1)[0]
    gateway, transport, store, clock = lane(kt, ALL)
    run = await gateway.start_run(component="tier", deadline=clock.now + timedelta(minutes=1))
    assert (run.version, run.licence, run.creates_blocked) == (
        "8.19.12",
        ("basic", "active"),
        False,
    )

    tag = argus_case_tag(kt)
    created = await write(gateway, run, CreateCase(), models.CaseCreate(
        title="[ARGUS 9] C2 beacon from 1 campus host",
        description="ARGUS opened this case; decisions are made in ARGUS.",
        tags=("argus", tag, "argus:owner:argus", "argus:state:open"), severity="medium",
    ), WriteClass.W1, clock, outbox="o-create")  # fmt: skip
    case = created.body
    forget_case(kt, case["id"])
    assert case["created_by"]["username"] == "argus"
    assert case["settings"] == {"syncAlerts": False}

    later(clock, 60, store)
    await write(gateway, run, CommentOnCase(), CommentParams(
        case_id=case["id"], comment="Opened by ARGUS: decisions are made in ARGUS."),
        WriteClass.W1, clock, outbox="o-comment")  # fmt: skip
    later(clock, 60, store)
    attached = await write(gateway, run, AttachAlerts(), AttachParams(
        case_id=case["id"], alerts=((alert["id"], alert["index"]),)),
        WriteClass.W1, clock, outbox="o-attach")  # fmt: skip
    assert attached.body["totalAlerts"] == 1

    later(clock, 60, store)
    tags = (*case["tags"], "argus:owner:tier-analyst")
    tagged = await write(gateway, run, UpdateCase(), models.UpdatePatch(cases=(models.CaseChange(
        id=case["id"], version=attached.body["version"], severity="high", tags=tags),)),
        WriteClass.W2, clock, outbox="o-tag")  # fmt: skip
    later(clock, 60, store)
    taken = await write(gateway, run, UpdateCase(), models.UpdatePatch(cases=(models.CaseChange(
        id=case["id"], version=tagged.body["version"], status="in-progress"),)),
        WriteClass.W2, clock, outbox="o-take")  # fmt: skip
    assert taken.body["status"] == "in-progress"

    later(clock, 60, store)
    keep = [t for t in taken.body["tags"] if not t.startswith(("argus:state:", "argus:owner:"))]
    closing = (*keep, "argus:state:closed", "argus:closed", "argus:reason:rule_false_positive")
    closed = await write(gateway, run, CloseCase(), models.ClosePatch(cases=(models.CaseChange(
        id=case["id"], version=taken.body["version"], status="closed", tags=closing),)),
        WriteClass.W3, clock, outbox="o-close", approval="approval-1")  # fmt: skip
    assert closed.body["status"] == "closed"
    later(clock, 60, store)
    await write(gateway, run, CommentOnCase(), CommentParams(
        case_id=case["id"], comment="Closed by ARGUS on the approval of Tier Approver."),
        WriteClass.W3, clock, outbox="o-closing-comment", approval="approval-1")  # fmt: skip

    later(clock, 60, store)
    current = await gateway.read(CaseGet(), CaseParams(case_id=case["id"]), component="tier",
                                 deadline=clock.now + timedelta(minutes=1))  # fmt: skip
    reopened = await write(gateway, run, UpdateCase(), models.UpdatePatch(cases=(models.CaseChange(
        id=case["id"], version=current.body["version"], status="open"),)),
        WriteClass.W2, clock, outbox="o-reopen")  # fmt: skip
    assert reopened.body["status"] == "open"

    writes = [w for w in transport.sent if w.method != "GET" and w.target == "kibana"]
    assert len(writes) == 8  # each sent once
    assert {w.key for w in writes} == {KeyRole.CASES}
    kibana_rows = [e for e in store.ledger if e.target == "kibana"]
    assert [e.outcome for e in kibana_rows] == ["ok"] * len(kibana_rows)
    assert [e.write_class for e in kibana_rows if e.write_class] == [
        "W1", "W1", "W1", "W2", "W2", "W3", "W3", "W2"]  # fmt: skip
    assert all(e.lane == "kibana_write" for e in kibana_rows if e.write_class)
    linked = kit.alert_state(kt, alert, "kibana.alert.case_ids")
    assert linked == {"kibana.alert.case_ids": [case["id"]]}


async def test_every_read_through_the_lane(kt: Tier) -> None:
    alert = kit.make_alerts(kt, "lane-reads", 1)[0]
    case: dict[str, Any] = kit.create_case(kt, ROLES[KeyRole.CASES], "[ARGUS 1] lane reads").body
    kt.kibana(ROLES[KeyRole.CASES]).post(
        f"/s/{SPACE}/api/cases/{case['id']}/comments",
        {"type": "user", "comment": "Opened by ARGUS.", "owner": "securitySolution"},
        keep=kit.case_summary,
    )
    kit.attach(kt, ROLES[KeyRole.CASES], case["id"], alert)
    gateway, transport, store, clock = lane(kt)
    deadline = clock.now + timedelta(minutes=1)

    async def read(template: KibanaTemplate, params: Any) -> Any:
        later(clock, 30, store)
        return (await gateway.read(template, params, component="tier", deadline=deadline + (
            clock.now - T0))).body  # fmt: skip

    assert await read(KibanaStatus(), NoParams()) == ("8.19.12", "available")
    found = await read(CasesFind(), FindParams(tags=(kit.run_tag(kt),), per_page=10))
    assert [c["id"] for c in found["cases"]] == [case["id"]]
    assert (await read(CaseGet(), CaseParams(case_id=case["id"])))["totalAlerts"] == 1
    actions = await read(CaseUserActions(), CasePageParams(case_id=case["id"]))
    assert [a["type"] for a in actions["userActions"]] == ["create_case", "comment", "comment"]
    comments = await read(CaseComments(), CasePageParams(case_id=case["id"]))
    assert [c["comment"] for c in comments["comments"]] == ["Opened by ARGUS."]  # people's text
    configuration = await read(CasesConfigure(), NoParams())
    assert not CasesConfigure.blocks_creates(configuration)
    assert [a["id"] for a in await read(CaseAlerts(), CaseParams(case_id=case["id"]))] == [
        alert["id"]]  # fmt: skip
    assert [c["id"] for c in await read(AlertCases(), AlertParams(alert_id=alert["id"]))] == [
        case["id"]]  # fmt: skip
    assert {w.key for w in transport.sent} == {KeyRole.READER}
    assert all(w.path.startswith(f"/s/{SPACE}/api/") for w in transport.sent)
    assert all(e.lane == "kibana_read" for e in store.ledger if e.target == "kibana")


async def test_the_elasticsearch_reads_through_the_gateway(kt: Tier) -> None:
    """``alerts.case_links`` (both forms), ``cluster.license`` and ``health.security_index``
    with the runbook's reader key, through ARGUS's Elasticsearch gateway and its validator."""
    from argus.gateway.builtin import (
        AlertCaseLinks,
        CaseLinksParams,
        ClusterLicense,
        SecurityIndexHealth,
    )
    from argus.gateway.templates import NoParams as EsNoParams
    from argus.gateway.templates import Purpose

    alert = kit.make_alerts(kt, "lane-links", 2)
    case: dict[str, Any] = kit.create_case(kt, ROLES[KeyRole.CASES], "[ARGUS 2] lane links").body
    kit.attach(kt, ROLES[KeyRole.CASES], case["id"], alert[0])
    gateway, _, store, clock = lane(kt)
    es = gateway.es_gateway
    assert es is not None
    deadline = clock.now + timedelta(minutes=1)
    by_case = await es.run(
        AlertCaseLinks(), CaseLinksParams(case_ids=(case["id"],)),
        purpose=Purpose.KIBANA_READ, component="tier", deadline=deadline,
    )  # fmt: skip
    hits = by_case.body["hits"]["hits"]
    assert [h["_id"] for h in hits] == [alert[0]["id"]]
    assert hits[0]["_source"]["kibana.alert.case_ids"] == [case["id"]]
    by_alert = await es.run(
        AlertCaseLinks(), CaseLinksParams(alert_ids=(alert[0]["id"], alert[1]["id"])),
        purpose=Purpose.KIBANA_READ, component="tier", deadline=deadline,
    )  # fmt: skip
    assert [h["_id"] for h in by_alert.body["hits"]["hits"]] == [alert[0]["id"]]
    lic = await es.run(ClusterLicense(), EsNoParams(), purpose=Purpose.KIBANA_READ,
                       component="tier", deadline=deadline)  # fmt: skip
    assert ClusterLicense.summary(lic.body) == ("basic", "active")
    health = await es.run(SecurityIndexHealth(), EsNoParams(), purpose=Purpose.IDENTITY,
                          component="tier", deadline=deadline)  # fmt: skip
    assert SecurityIndexHealth.usable(health.body)
    assert [e.lane for e in store.ledger] == ["kibana_read"] * 3 + ["identity"]


@pytest.mark.parametrize(
    ("role", "principal", "problems"),
    [
        (KeyRole.READER, "key:argus-kibana-reader", ()),
        (KeyRole.CASES, "key:argus-cases-writer-actions", ()),
        (KeyRole.ALERTS, "key:argus-alert-writer", ()),
        # DQ3's fallback writer, Cases All + Security Read: the residual the plan records
        (KeyRole.CASES, "key:argus-cases-writer", "fallback"),
    ],
)
async def test_the_keys_self_tests(kt: Tier, role: KeyRole, principal: str, problems: Any) -> None:
    gateway, transport, _, clock = lane(kt, roles={**ROLES, role: principal})
    version, verdict = await selftest.run_selftest(
        gateway, role, deadline=clock.now + timedelta(minutes=1)
    )
    assert version == "8.19.12"
    if problems == "fallback":
        held = {p.removeprefix("holds ") for p in verdict.problems}
        assert "api:rac" in held
        assert "cases:securitySolution/deleteCase" in held
        assert all(p.startswith("holds ") for p in verdict.problems)
        accepted = selftest.judge(role, SPACE, transport_answer(transport), held)
        assert accepted.problems == ()
    else:
        assert verdict.problems == problems


def transport_answer(transport: TierKibana) -> Any:
    """The last self-check's answer, read again through the recorded client (replayable)."""
    request = transport.sent[-1]
    assert request.body is not None
    reply = transport.kt.es(transport.roles[request.key]).call(
        request.method, request.path, json.loads(request.body)
    )
    return reply.body


async def test_the_real_transport_on_the_tier(live_kt: Tier) -> None:
    """Live only: ARGUS's HTTPS transport with the tier's CA pinned, the reader key, the space
    path, no redirects; a DELETE never leaves."""
    from pydantic import SecretStr

    from argus.gateway.kibana.transport import HttpxKibanaTransport
    from argus.gateway.transport import pinned_context

    settings = live_kt.settings
    keys = {
        role: SecretStr(str(live_kt.data["api_keys"][name.removeprefix("key:")]["encoded"]))
        for role, name in ROLES.items()
    }
    real = HttpxKibanaTransport(
        settings.kibana_url, settings.es_url, pinned_context(settings.paths.ca_crt), keys,
        space=SPACE,
    )  # fmt: skip
    clock = FakeClock(T0)
    store = MemoryStore(memory=HealthMemory(probed_at=T0))
    gateway = KibanaGateway(real, store, targets=KibanaTargets(space=SPACE), clock=clock,
                            sleep=clock.sleep)  # fmt: skip
    try:
        status = await gateway.read(KibanaStatus(), NoParams(), component="tier",
                                    deadline=clock.now + timedelta(minutes=1))  # fmt: skip
        assert status.body == ("8.19.12", "available")
        assert status.date  # Kibana's Date header, for Q-D3's clock offset
        found = await gateway.read(CasesFind(), FindParams(tags=("tier-seed",)), component="tier",
                                   deadline=clock.now + timedelta(minutes=1))  # fmt: skip
        assert found.body["total"] == 2
        verdict = selftest.judge(KeyRole.READER, SPACE, (await gateway.key_privileges(
            KeyRole.READER, selftest.request_body(KeyRole.READER, SPACE), component="tier",
            deadline=clock.now + timedelta(minutes=1))).body)  # fmt: skip
        assert verdict.problems == ()
        with pytest.raises(TemplateRejectedError, match="route_refused"):
            await real.send(KWire("kibana", KeyRole.READER, "DELETE", f"/s/{SPACE}/api/cases",
                                  (), None, "argus-tier/x@1", 5))  # fmt: skip
    finally:
        await real.aclose()
