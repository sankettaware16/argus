"""A synthetic incident day for Q-F2's proofs: four investigations through the real collector
store, grouper, context worker (the generic pack with every remote module on) and agent@1,
against a deterministic fake the SIEM and a scripted model behind the real LLM gateway.

- **c2**: a campus host (an asset) talks to an outside address through the proxy, every 30
  minutes; acme-threat-intel lists the address;
- **web**: an outside client attacks a hosted site (traversal, a scanner) and then gets two
  successful answers;
- **c2b**: another asset reaches a abuse-listed C2; its proxy check times out once;
- **mail**: a mail server's alert with nothing to look up remotely.

Everything is synthetic (documentation, private and reserved address space, invented names);
nothing reaches a network. The model's answers are a function of what it is sent, so a strict
cassette replays them only for byte-identical requests.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.context.packs import PackRegistry, default_registry
from argus.gateway.errors import TimedOutError
from argus.gateway.gateway import Result
from argus.gateway.templates import Params, Purpose, Template
from argus.llm.gateway import LlmGateway, MemoryLlmStore
from argus.llm.privacy import Privacy, load_policy
from argus.llm.providers import LlmConfig
from argus.llm.wire import LlmReply, LlmTransport, LlmWire
from argus.reference import store as reference
from argus.reference.templates import LookupParams
from tests.integration.context.test_generic import alert
from tests.integration.grouping.test_grouping import ingest
from tests.integration.reference.sources import mirror_source
from tests.integration.reference.test_reference import FakeTI
from tests.unit.llm.conftest import ASSETS, CAMPUS_PREFIX

NOW = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)  # the alerts' "now" (tests.integration.context)
LATER = NOW + timedelta(days=1)  # when the packs and the agent run: every window is complete
C2 = "45.9.9.9"  # on acme-threat-intel (remote lookup)
LISTED = "77.221.155.150"  # on the abuse-ioc mirror
ATTACKER = "185.220.101.5"
HOST, OTHER, MAILER = "10.20.3.4", "10.20.9.9", "10.30.1.8"  # assets of the test asset map

NOTE = """### Investigation Steps
1. Identify the internal host (`source.ip`) and its owner.
2. Reputation-check `destination.ip` (VirusTotal, threat intel).
3. How many internal hosts reach `destination.ip`?
4. Check periodicity: regular intervals suggest a beacon.
5. Pivot on `source.ip` for the last 24h: how many destinations?
6. If confirmed, block the destination and notify the owner.
"""
WEB_NOTE = """### Investigation Steps
1. Review the `url.path` list and the user agent (`user_agent.original`).
2. Check the access logs: did `source.ip` get 200 responses afterwards?
3. Reputation-check `source.ip`.
"""
MAIL_NOTE = """### Investigation Steps
1. Check `source.ip` and `user.name`.
2. Contact the owner if the volume is unusual.
"""
SQUID = ["acme-logs-squid-*"]
NGINX = ["acme-logs-nginx-*"]
POSTFIX = ["acme-logs-postfix-*"]
ABUSE = [
    {
        "@timestamp": "2026-10-09T00:00:00Z",
        "threat": {"indicator": {"type": "ipv4-addr", "ip": LISTED, "description": "PS1Bot C2"}},
    }
]
ACME_ROWS = [
    {"ioc_type": "ip", "ioc_value": C2, "intel_source": "feodo",
     "@timestamp": "2026-10-08T10:00:00Z", "malware": "QakBot"},
]  # fmt: skip


def _alert(n: int, rule: str, note: str, indices: list[str], host: str, **fields: Any) -> Any:
    d = alert(n, rule=rule, note=note, **{"kibana.alert.rule.indices": indices}, **fields)
    d["_source"]["source"]["ip"] = host
    return d


def alerts() -> list[dict[str, Any]]:
    out = [
        _alert(n, "c2", NOTE, SQUID, HOST, destination={"ip": C2},
               url={"domain": "update-check.example", "path": "/gate.php"})
        for n in (1, 2, 3, 4)
    ]  # fmt: skip
    out += [
        _alert(n, "web", WEB_NOTE, NGINX, ATTACKER,
               url={"path": p, "domain": "library.example"},
               user_agent={"original": "sqlmap/1.7.2#stable"})
        for n, p in ((11, "/../../etc/passwd"), (12, "/.env"), (13, "/admin/%252e%252e/x"))
    ]  # fmt: skip
    out += [_alert(n, "c2b", NOTE, SQUID, OTHER, destination={"ip": LISTED}) for n in (21, 22)]
    out += [_alert(31, "mail", MAIL_NOTE, POSTFIX, MAILER, user={"name": "relay-svc"})]
    return out


async def prepare(engine: AsyncEngine) -> None:
    await ingest(engine, alerts())
    async with engine.begin() as conn:
        await reference.refresh_rules(conn, NOW, hold=timedelta(0))
        await reference.sync_mirror(conn, FakeTI(ABUSE, []).run, NOW, mirror_source())


def privacy() -> Privacy:
    return Privacy.build(load_policy(), ASSETS, (CAMPUS_PREFIX,))


def packs(p: Privacy) -> PackRegistry:
    return default_registry(
        p.classifier, remote_ti=True, log_queries=True, proxy_aggregations=True,
        clock=lambda: LATER,
    )  # fmt: skip


def _ms(at: datetime) -> int:
    return int(at.timestamp() * 1000)


@dataclass
class FakeSiem:
    """Answers the evidence templates deterministically by their parameters. The first proxy
    check of ``OTHER`` times out; later ones answer."""

    calls: list[tuple[str, str]] = field(default_factory=list)
    timed_out: set[str] = field(default_factory=set)

    async def run(
        self,
        template: Template,
        params: Params,
        *,
        purpose: Purpose,
        component: str,
        deadline: datetime,
    ) -> Result:
        assert purpose is Purpose.ENRICH
        name = template.name
        dump = params.model_dump(mode="json")
        self.calls.append((name, json.dumps(dump, sort_keys=True)))
        if name == "ti.lookup":
            assert isinstance(params, LookupParams)
            rows = [
                {"_index": "acme-threat-intel", "_id": f"t{n}", "_source": r}
                for n, r in enumerate(ACME_ROWS)
                if r["ioc_value"] in params.values
            ]
            return Result({"hits": {"total": {"value": len(rows)}, "hits": rows}}, 4,
                          ("acme-threat-intel",))  # fmt: skip
        ip = str(dump.get("ip"))
        start = datetime.fromisoformat(str(dump["start"]))
        end = datetime.fromisoformat(str(dump["end"]))
        if name == "proxy.host":
            if ip == OTHER and ip not in self.timed_out:
                self.timed_out.add(ip)
                raise TimedOutError()
            slots = int((end - start) / timedelta(minutes=10))
            buckets = [
                {"key": _ms(start + timedelta(minutes=10 * i)), "doc_count": 4 if i % 3 == 0 else 0}
                for i in range(slots)
            ]
            aggs = {
                "destinations": {"buckets": [{"key": C2, "doc_count": 48},
                                             {"key": "93.184.216.34", "doc_count": 3}]},
                "destination_count": {"value": 2},
                "bytes": {"value": 182_330},
                "statuses": {"buckets": [{"key": 200, "doc_count": 49},
                                         {"key": 403, "doc_count": 2}]},
                "actions": {"buckets": [{"key": "TCP_MISS", "doc_count": 51}]},
                "timeline": {"buckets": buckets},
            }  # fmt: skip
            return Result({"aggregations": aggs, "hits": {"hits": []}}, 612,
                          ("acme-logs-squid-2026.10.09",))  # fmt: skip
        if name == "proxy.destination":
            aggs = {
                "host_count": {"value": 1},
                "hosts": {"buckets": [{"key": HOST if ip == C2 else OTHER, "doc_count": 48}]},
                "urls": {"buckets": [{"key": f"http://{ip}/gate.php?id=7", "doc_count": 48}]},
            }
            return Result({"aggregations": aggs, "hits": {"hits": []}}, 705,
                          ("acme-logs-squid-2026.10.09",))  # fmt: skip
        if name == "web.followups":
            rows = []
            if ip == ATTACKER:
                rows = [
                    {"_index": "acme-logs-nginx-2026.10.09", "_id": f"w{n}",
                     "_source": {"@timestamp": (start + timedelta(minutes=20 + n)).isoformat(),
                                 "url": {"domain": "library.example", "path": path},
                                 "http": {"response": {"status_code": 200},
                                          "request": {"method": "GET"}}}}
                    for n, path in enumerate(("/admin/login.php", "/backup.zip"))
                ]  # fmt: skip
            return Result({"hits": {"hits": rows}}, 9, ("acme-logs-nginx-2026.10.09",))
        raise AssertionError(f"unexpected template {name}")


# ----------------------------------------------------------------------------- the model

_PSEUDONYM = re.compile(r"I1\.IP_\d+")
_PUBLIC = re.compile(r"(?<![\d.])(?:45\.9\.9\.9|185\.220\.101\.5|77\.221\.155\.150)(?![\d.])")


def _reply(answer: dict[str, Any]) -> LlmReply:
    body = {
        "choices": [{"message": {"content": json.dumps(answer, sort_keys=True)}}],
        "usage": {"prompt_tokens": 900, "completion_tokens": 120},
    }
    return LlmReply(200, json.dumps(body, sort_keys=True).encode(), 7.0)


class ScriptedModel:
    """A model whose answer depends only on the request: the coordinator's first look asks for
    evidence (and consults the proxy specialist when the item has proxy facts); once it has
    asked (its instructions list earlier asks) it decides, citing one line of the item."""

    async def send(self, wire: LlmWire, key: SecretStr) -> LlmReply:
        body = json.loads(wire.body)
        system, user = body["messages"][0]["content"], body["messages"][1]["content"]
        if system.startswith("You are a ") and "specialist" in system[:40]:
            return _reply({"notes": "The proxy traffic is steady and small.", "cites": [],
                           "ask": []})  # fmt: skip
        lines = [line for line in user.splitlines() if line.strip()]
        cite = next((line for line in lines if line.startswith("Alerts:")), lines[0])
        if "Earlier asks in this investigation" in system or "Rule mail" in user:
            return _reply({
                "outcome": "benign_expected" if "Rule mail" in user else "true_positive",
                "confidence": 0.75,
                "reason": "The host keeps reaching the address the threat list names.",
                "hypotheses": [{"name": "a beacon", "for": [cite], "against": []},
                               {"name": "an update check", "for": [], "against": [cite]}],
                "cites": [cite], "consult": [], "ask": [],
            })  # fmt: skip
        asks = []
        pseudonym = _PSEUDONYM.search(user)
        public = _PUBLIC.search(user)
        if pseudonym:
            asks.append({"tool": "web.followups", "entity": pseudonym.group(0)})
            asks.append({"tool": "proxy.host", "entity": pseudonym.group(0)})
        if public:
            asks.append({"tool": "proxy.destination", "entity": public.group(0)})
        return _reply({
            "outcome": "inconclusive", "confidence": 0.3, "reason": "More evidence is needed.",
            "hypotheses": [], "cites": [], "consult": ["proxy"] if "proxy" in user else [],
            "ask": asks,
        })  # fmt: skip


def llm(transport: LlmTransport) -> LlmGateway:
    config = LlmConfig.model_validate({
        "providers": [{
            "name": "cassette", "base_url": "https://llm.invalid/v1", "keys": ["CASSETTE_KEY"],
            "models": {"small": {"name": "m-small"}, "medium": {"name": "m-medium"}},
        }],
    })  # fmt: skip
    keys = {"CASSETTE_KEY": SecretStr("not-a-key")}  # fake-secret
    return LlmGateway(config, keys, transport, MemoryLlmStore(), clock=lambda: LATER)


async def dossiers(engine: AsyncEngine) -> list[Any]:
    async with engine.connect() as conn:
        rows = await conn.execute(
            text(
                "SELECT investigation_id, version, pack, dossier_hash, body FROM dossiers"
                " ORDER BY investigation_id, version, pack"
            )
        )
        return list(rows.all())


def rule_of(row: Any) -> str:
    return str(row.body["facts"]["rule_id"])


def by_rule(rows: Sequence[Any]) -> dict[str, Any]:
    return {rule_of(r): r for r in rows}


# ----------------------------------------------------------------------------- the whole day

ENGINE_AT = LATER + timedelta(minutes=10)  # the decision engine assesses first
AGENT_AT = LATER + timedelta(hours=1)  # then agent@1, where the engine found no decision


@dataclass
class Day:
    privacy: Privacy
    packs: PackRegistry
    siem: FakeSiem


async def collect(engine: AsyncEngine, saver: Any) -> Day:
    """The alerts, their dossiers (the worker with every remote module on)."""
    from argus.context.worker import Worker

    await prepare(engine)
    p = privacy()
    day = Day(p, packs(p), FakeSiem())
    worker = Worker(engine, saver, packs=day.packs, gateway=day.siem, clock=lambda: LATER)
    while await worker.run_once(limit=10):
        pass
    return day


async def assess(engine: AsyncEngine, day: Day, transport: LlmTransport) -> None:
    """The engine, then agent@1 on what it left undecided, through the assessment queue
    (as ``argus assess`` runs them); the model answers from ``transport``."""
    from argus.agent import service
    from argus.agent.agent import Agent
    from argus.assess import engine as decision
    from argus.assess import runner
    from tests.unit.agent.parity import frozen

    async with engine.connect() as conn:
        learned = await decision.learn(conn)
    judge = decision.Engine(learned, ENGINE_AT)
    async with engine.begin() as conn:
        await runner.schedule(conn, day.privacy, judge.name, ENGINE_AT)
    while sum((await runner.run_once(engine, judge, "test", lambda: ENGINE_AT)).values()):
        pass
    fetch, snapshots = service.evidence(engine, day.siem, day.packs, lambda: AGENT_AT)
    # the cassette holds the exact prompts of Q-H1's files (coordinator@3, specialist@1): the
    # frozen copy replays it; AR3's coordinator@4 adds two tools (D-165) and so other bytes
    agent = Agent(day.privacy, llm(transport).complete, day.packs, fetch, snapshots,
                  day.privacy.classifier, clock=lambda: AGENT_AT, monotonic=lambda: 0.0,
                  agents=frozen())  # fmt: skip
    async with engine.begin() as conn:
        await runner.schedule(conn, day.privacy, agent.name, AGENT_AT, after=judge.name)
    while sum((await runner.run_once(engine, agent, "test", lambda: AGENT_AT)).values()):
        pass
