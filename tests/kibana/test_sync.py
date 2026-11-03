"""Q-D3's read-back on the local tier (Kibana 8.19.12 Basic; D-109: the SIEM is never contacted).

People change one of ARGUS's cases in Kibana as the seeded analyst would (a comment, their
own tag, ARGUS's owner tag, the status, the title, Sync alerts), ARGUS's own key makes a
comment no outbox row explains, an admin deletes a case, and a person's own case holds an
alert ARGUS knows: the read-back (the real ``Syncer``, the Kibana lane with the reader key,
``alerts.case_links`` with the runbook's Elasticsearch reader key) finds each as §7.1 says,
from Kibana's own user actions. The finds are narrowed to this test's cases (its run tag) so
other runs' cases on the tier are not read.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from argus.gateway.budget import BudgetConfig
from argus.gateway.gateway import Gateway, Targets
from argus.gateway.health import HealthMemory
from argus.gateway.kibana.gateway import KibanaGateway, KibanaTargets
from argus.gateway.kibana.transport import KResponse, KWire
from argus.gateway.state import MemoryStore
from argus.kibana_sync.cycle import Syncer
from argus.kibana_sync.model import Kind, SentWrite
from argus.kibana_sync.store import MemorySyncStore
from tests.kibana import kit
from tests.kibana.test_lane import TierElasticsearch, TierKibana
from tests.kibana.tier import SPACE, S, Tier
from tests.unit.gateway.fakes import FakeClock

WRITER = "key:argus-cases-writer-actions"
PERSON = "user:tier-analyst"  # the Tier API names a seeded person as user:<name>
CREATE = SentWrite("create", frozenset(), 1)
# Before every time Kibana answers, live (now) or replayed (the cassettes' stand-in time,
# 2000-01-01): every case the change poll returns is fresh in both modes, so a replay sends
# exactly the recorded requests.
T0 = datetime(1999, 12, 31, 12, 0, tzinfo=UTC)


@dataclass
class RunCases(TierKibana):
    """The lane's transport, its finds narrowed to this test's cases (the run tag)."""

    tag: str = ""

    async def send(self, request: KWire) -> KResponse:
        if request.path.endswith("/api/cases/_find"):
            request = KWire(
                request.target,
                request.key,
                request.method,
                request.path,
                (*request.params, ("tags", self.tag)),
                request.body,
                request.opaque_id,
                request.timeout_s,
            )
        return await super().send(request)


def syncer(kt: Tier) -> tuple[Syncer, MemorySyncStore, MemoryStore, FakeClock]:
    clock = FakeClock(T0)
    lane = MemoryStore(
        memory=HealthMemory(probed_at=T0 + timedelta(days=1)), budget_config=BudgetConfig()
    )
    es = Gateway(TierElasticsearch(kt), lane, targets=Targets(), clock=clock, sleep=clock.sleep)
    transport = RunCases(kt, tag=kit.run_tag(kt))
    gateway = KibanaGateway(
        transport,
        lane,
        targets=KibanaTargets(space=SPACE),
        es_gateway=es,
        clock=clock,
        sleep=clock.sleep,
    )
    store = MemorySyncStore()
    return Syncer(gateway, store, lane, es=es, clock=clock, sleep=clock.sleep), store, lane, clock


async def cycle(s: Syncer, clock: FakeClock, minutes: int = 10) -> None:
    clock.advance(timedelta(minutes=minutes))
    record = await s.cycle(deadline=clock.now + timedelta(minutes=9))
    assert record.outcome == "complete", record.reason


def found(store: MemorySyncStore) -> list[Kind]:
    return [f.kind for _, f in sorted(store.findings.values(), key=lambda x: x[1].dedupe_key)]


def argus_case(kt: Tier, store: MemorySyncStore) -> tuple[str, uuid.UUID]:
    """A case ARGUS's writer key made, whose create the outbox sent."""
    case = uuid.uuid5(uuid.NAMESPACE_URL, f"{kt.run}-{kit.test_key(kt)}")
    store.sent[case] = [CREATE]
    reply = kit.create_case(
        kt,
        WRITER,
        "[ARGUS 7] read-back",
        tags=["argus", f"argus:case:{case}", "argus:owner:argus", "argus:state:open"],
    )
    assert reply.status == 200, reply.body
    assert reply.body["created_by"]["username"] == "argus"
    return reply.body["id"], case


def patch(kt: Tier, principal: str, case_id: str, **fields: object) -> None:
    version = kit.case(kt, case_id)["version"]
    reply = kit.patch_case(kt, principal, case_id, version, **fields)
    assert reply.status == 200, reply.body


async def test_peoples_changes_on_the_tier_are_classified_from_kibanas_user_actions(
    kt: Tier,
) -> None:
    s, store, lane, clock = syncer(kt)
    kid, case = argus_case(kt, store)
    await cycle(s, clock)
    assert store.mirror[kid].case_id == case, "adopted through its sent create"
    assert found(store) == []
    people = kt.kibana(PERSON)
    reply = people.post(
        f"{S}/api/cases/{kid}/comments",
        {"type": "user", "comment": "Called the host's owner.", "owner": kit.OWNER},
        keep=kit.case_summary,
    )
    assert reply.status == 200, reply.body
    tags = kit.case(kt, kid)["tags"]
    patch(kt, PERSON, kid, tags=[*tags, "phishing"])
    await cycle(s, clock)
    assert sorted(found(store)) == [Kind.PERSON_COMMENTED, Kind.PERSON_EDITED]
    assert store.mirror[kid].paused_reason is None
    tags = [t for t in kit.case(kt, kid)["tags"] if t != "argus:owner:argus"]
    patch(kt, PERSON, kid, tags=[*tags, "argus:owner:tier-analyst"], title="Anita's title")
    patch(kt, PERSON, kid, status="closed")
    await cycle(s, clock)
    kinds = found(store)
    assert Kind.ARGUS_TAGS_CHANGED in kinds
    assert Kind.CLOSED_IN_KIBANA in kinds
    assert store.mirror[kid].paused_reason is not None
    assert "title" in store.mirror[kid].unmanaged
    patch(kt, PERSON, kid, status="open")
    patch(kt, PERSON, kid, settings={"syncAlerts": True})
    await cycle(s, clock)
    kinds = found(store)
    assert Kind.REOPENED_IN_KIBANA in kinds
    assert Kind.SETTINGS_CHANGED in kinds
    assert not (await lane.kibana_lane()).paused, "people's changes pause no write class"
    # ARGUS's own key comments with no outbox row: an alarm, every write class paused
    reply = kt.kibana(WRITER).post(
        f"{S}/api/cases/{kid}/comments",
        {"type": "user", "comment": "unplanned", "owner": kit.OWNER},
        keep=kit.case_summary,
    )
    assert reply.status == 200, reply.body
    await cycle(s, clock)
    assert Kind.UNEXPLAINED_ARGUS_ACTION in found(store)
    assert set((await lane.kibana_lane()).paused) == {"W1", "W2", "W3", "WA"}


async def test_a_deletion_on_the_tier_is_found_and_confirmed_by_a_404(kt: Tier) -> None:
    s, store, _, clock = syncer(kt)
    kid, _ = argus_case(kt, store)
    await cycle(s, clock)
    admin = kt.kibana("elastic")
    reply = admin.call("DELETE", f"{S}/api/cases", params={"ids": f'["{kid}"]'})
    assert reply.status == 204, reply.body
    await cycle(s, clock)
    assert found(store) == [Kind.DELETED_IN_KIBANA]
    assert store.mirror[kid].deleted_at is not None


async def test_a_persons_case_holding_a_known_alert_is_found_read_only(kt: Tier) -> None:
    alert = kit.make_alerts(kt, "people", 1)[0]
    s, store, _, clock = syncer(kt)
    store.alerts = [(clock.now, alert["id"])]
    reply = kit.create_case(kt, PERSON, "Anita's own case")
    assert reply.status == 200, reply.body
    theirs = reply.body["id"]
    attached = kit.attach(kt, PERSON, theirs, alert)
    assert attached.status == 200, attached.body
    await cycle(s, clock)
    assert found(store) == [Kind.PEOPLE_CASE]
    assert store.people[theirs].known_alerts == (alert["id"],)
    assert store.people[theirs].created_by == PERSON.removeprefix("user:")  # Kibana's username
    assert theirs not in store.mirror


async def test_a_closed_case_deleted_on_the_tier_is_found_by_the_closed_probe(kt: Tier) -> None:
    """Review D3-R5: the daily closed listing ran at the first cycle; two cycles later the
    deletion is found from one ``cases.find`` of one closed case (its ``total``), not by
    listing every closed case."""
    s, store, _, clock = syncer(kt)
    kid, _ = argus_case(kt, store)
    await cycle(s, clock)
    patch(kt, PERSON, kid, status="closed")
    await cycle(s, clock)
    assert found(store) == [Kind.CLOSED_IN_KIBANA]
    admin = kt.kibana("elastic")
    reply = admin.call("DELETE", f"{S}/api/cases", params={"ids": f'["{kid}"]'})
    assert reply.status == 204, reply.body
    await cycle(s, clock)
    assert found(store) == [Kind.CLOSED_IN_KIBANA, Kind.DELETED_IN_KIBANA]
    assert store.mirror[kid].deleted_at is not None


async def test_a_person_deleting_arguss_comment_and_attachment_is_a_deletion(kt: Tier) -> None:
    """Review D3-R9: Kibana records a ``comment`` action ``delete`` whose payload is the
    removed comment; it is a person's deletion, never a comment or an alarm."""
    s, store, lane, clock = syncer(kt)
    kid, case = argus_case(kt, store)
    store.sent[case] = [
        CREATE,
        SentWrite("comment", frozenset(), 1),
        SentWrite("attach", frozenset(), 1),
    ]
    alert = kit.make_alerts(kt, "read-back-delete", 1)[0]
    reply = kt.kibana(WRITER).post(
        f"{S}/api/cases/{kid}/comments",
        {"type": "user", "comment": "ARGUS opened this case.", "owner": kit.OWNER},
        keep=kit.case_summary,
    )
    assert reply.status == 200, reply.body
    attached = kit.attach(kt, WRITER, kid, alert)
    assert attached.status == 200, attached.body
    await cycle(s, clock)
    assert found(store) == [], "ARGUS's own comment and attachment are explained"
    for comment in kit.case(kt, kid)["comments"]:
        gone = kt.kibana(PERSON).delete(f"{S}/api/cases/{kid}/comments/{comment['id']}")
        assert gone.status == 204, gone.body
    await cycle(s, clock)
    assert found(store) == [Kind.PERSON_DELETED, Kind.PERSON_DELETED]
    assert {f.details["what"] for _, f in store.findings.values()} == {
        "comment",
        "alert attachment",
    }
    assert "alerts" in store.mirror[kid].unmanaged
    assert not (await lane.kibana_lane()).paused, "a person's deletion pauses no write class"
