"""A demo installation for the documentation's screenshots (D-329): synthetic, neutral data in a
throwaway database, never production's. Alerts are made from the committed sanitized fixture's
shape with their own rules, hosts in 10.20.0.0/16, outside addresses only from the documentation
ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and names under example.net; the incident
engine runs over them as it does in production; argus-admin's published state (the settings, the
AI providers and agents, the threat-intel usage, the services, a heartbeat) and a month of AI calls
are written as argus-admin and the gateway would."""

from __future__ import annotations

import copy
import json
import random
import uuid
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.web import auth
from argus.web.capabilities import Capability
from tests.integration.collector.fake_es import INDEX
from tests.integration.web.conftest import PASSWORD
from tests.unit.normalize.alerts import QUERY, fixture

C = Capability
TEMPLATE = fixture(QUERY)["_source"]
C2 = {"framework": "MITRE ATT&CK", "tactic": {"id": "TA0011", "name": "Command and Control",
      "reference": "https://attack.mitre.org/tactics/TA0011/"}}  # fmt: skip
ACCESS = {"framework": "MITRE ATT&CK", "tactic": {"id": "TA0001", "name": "Initial Access",
          "reference": "https://attack.mitre.org/tactics/TA0001/"}}  # fmt: skip
CRED = {"framework": "MITRE ATT&CK", "tactic": {"id": "TA0006", "name": "Credential Access",
        "reference": "https://attack.mitre.org/tactics/TA0006/"}}  # fmt: skip
RECON = {"framework": "MITRE ATT&CK", "tactic": {"id": "TA0043", "name": "Reconnaissance",
         "reference": "https://attack.mitre.org/tactics/TA0043/"}}  # fmt: skip

PEOPLE: list[tuple[str, str, list[Capability]]] = [
    ("asha", "Asha Menon", list(Capability)),
    ("ravi", "Ravi Kumar", [C.VIEW, C.SEE_LOGS, C.REVIEW, C.ANSWER_GOLD]),
    ("mina", "Mina Shah", [C.VIEW, C.SEE_LOGS, C.REVIEW, C.MANAGE_CASES, C.REOPEN, C.APPROVE]),
    ("leo", "Leo Fernandes", [C.VIEW, C.SEE_LOGS, C.REVIEW, C.MANAGE_CASES]),
    ("priya", "Priya Nair", [C.VIEW]),
]


@dataclass(frozen=True)
class Rule:
    rule_id: str
    name: str
    severity: str
    risk: int
    family: str
    threat: tuple[dict[str, Any], ...]
    about: str


RULES = [
    Rule(
        "demo-c2-beacon",
        "Possible C2 beacon",
        "high",
        73,
        "squid",
        (C2,),
        "Regular, small HTTPS requests from one internal host to the same outside address.",
    ),
    Rule(
        "demo-ssh-brute",
        "SSH brute force from outside",
        "medium",
        47,
        "sso",
        (CRED,),
        "Many failed SSH sign-ins from one outside address against an internal server.",
    ),
    Rule(
        "demo-malware-download",
        "Malware download blocked",
        "high",
        73,
        "squid",
        (ACCESS,),
        "The proxy blocked a download that the antivirus engine flagged.",
    ),
    Rule(
        "demo-raw-ip-post",
        "Plain HTTP POST to a raw IP address",
        "medium",
        47,
        "squid",
        (C2,),
        "An internal host sent data over plain HTTP straight to an outside address.",
    ),
    Rule(
        "demo-sqli-blocked",
        "Web attack blocked: SQL injection",
        "medium",
        47,
        "nginx",
        (ACCESS,),
        "The web application firewall blocked an injection payload.",
    ),
    Rule(
        "demo-port-scan",
        "Port scan from outside",
        "low",
        21,
        "nginx",
        (RECON,),
        "One outside address touched many ports of internal servers.",
    ),
    Rule(
        "demo-blocked-burst",
        "Excessive blocked requests from one host",
        "low",
        21,
        "squid",
        (C2,),
        "One internal host made many requests the proxy refused.",
    ),
]


def alert_doc(n: int, rule: Rule, at: datetime, src: str, dst: str, port: int,
              host: str | None = None, domain: str | None = None) -> dict[str, Any]:  # fmt: skip
    """An alert of ``rule``: the fixture's shape, its own values, nothing of the fixture's own."""
    alert_id = uuid.UUID(int=n + 1).hex + f"{n:08x}"
    source = copy.deepcopy(TEMPLATE)
    for key in list(source):
        if key in ("squid", "process", "service", "service_name", "observer") or (
            "original_event.original" in key or ".meta." in key
        ):
            del source[key]
    source["event"].pop("original", None)
    source["event"].pop("ingested", None)
    stamp = at.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    params = source["kibana.alert.rule.parameters"]
    params.pop("meta", None)
    for key, value in {
        "@timestamp": stamp, "kibana.alert.original_time": stamp,
        "kibana.alert.intended_timestamp": stamp, "kibana.alert.start": stamp,
        "kibana.alert.last_detected": stamp, "kibana.alert.uuid": alert_id,
        "kibana.alert.rule.rule_id": rule.rule_id, "kibana.alert.rule.uuid": str(
            uuid.uuid5(uuid.NAMESPACE_URL, rule.rule_id)),
        "kibana.alert.rule.name": rule.name, "kibana.alert.severity": rule.severity,
        "kibana.alert.rule.severity": rule.severity, "kibana.alert.risk_score": rule.risk,
        "kibana.alert.rule.risk_score": rule.risk, "kibana.alert.rule.description": rule.about,
        "kibana.alert.rule.note": f"### Investigation steps\n1. {rule.about}",
        "kibana.alert.rule.threat": list(rule.threat),
        "kibana.alert.rule.tags": ["Demo", rule.family],
        "kibana.alert.rule.indices": [f"acme-logs-{rule.family}-*"],
        "kibana.alert.rule.author": ["Northwind SOC"],
        "kibana.alert.reason": f"{rule.name}: {src} to {dst}:{port}",
    }.items():  # fmt: skip
        source[key] = value
    params.update(rule_id=rule.rule_id, severity=rule.severity, risk_score=rule.risk,
                  description=rule.about, note=source["kibana.alert.rule.note"],
                  threat=list(rule.threat), index=[f"acme-logs-{rule.family}-*"],
                  author=["Northwind SOC"])  # fmt: skip
    source["source"] = {"ip": src, "port": 40000 + n % 20000}
    source["destination"] = {"ip": dst, "port": port}
    source["host"] = {"name": host or "proxy-01"}
    if domain:
        source["url"] = {"domain": domain, "original": f"https://{domain}/"}
    source["kibana.alert.ancestors"] = [{"depth": 0, "id": f"demo-event-{n}", "type": "event",
                                         "index": f"acme-logs-{rule.family}-demo"}]  # fmt: skip
    return {"_index": INDEX, "_id": alert_id, "found": True, "_source": source}


def demo_docs(now: datetime) -> list[dict[str, Any]]:
    """About two hundred alerts over the last five days, in alert groups a person would see."""
    rng = random.Random(20261117)  # the same pictures every run
    by = {r.rule_id: r for r in RULES}
    out: list[dict[str, Any]] = []

    def add(
        rule: str, src: str, dst: str, port: int, hours: float, count: int, **more: Any
    ) -> None:
        for _ in range(count):
            at = now - timedelta(hours=hours, minutes=rng.randint(0, 50))
            out.append(alert_doc(len(out), by[rule], at, src, dst, port, **more))

    add(
        "demo-c2-beacon",
        "10.20.4.17",
        "203.0.113.45",
        443,
        1,
        9,
        host="ops-ws-17",
        domain="update-check.example.net",
    )
    add(
        "demo-c2-beacon",
        "10.20.4.23",
        "203.0.113.45",
        443,
        3,
        6,
        host="ops-ws-23",
        domain="update-check.example.net",
    )
    add("demo-raw-ip-post", "10.20.4.17", "203.0.113.45", 80, 2, 4, host="ops-ws-17")
    add(
        "demo-malware-download",
        "10.20.7.88",
        "198.51.100.23",
        80,
        5,
        3,
        host="depot-pc-88",
        domain="files.example.org",
    )
    add("demo-raw-ip-post", "10.20.8.40", "192.0.2.200", 80, 7, 5, host="office-pc-40")
    add(
        "demo-malware-download",
        "10.20.12.5",
        "198.51.100.150",
        80,
        9,
        2,
        host="ops-ws-5",
        domain="cdn-files.example.net",
    )
    add("demo-c2-beacon", "10.20.15.9", "203.0.113.77", 443, 2, 8, host="research-ws-9")
    add("demo-ssh-brute", "198.51.100.77", "10.20.1.10", 22, 4, 12, host="git-server")
    add("demo-ssh-brute", "192.0.2.150", "10.20.1.11", 22, 30, 8, host="mail-relay")
    add("demo-sqli-blocked", "192.0.2.61", "10.20.2.5", 443, 6, 7, host="www")
    add("demo-sqli-blocked", "203.0.113.9", "10.20.2.6", 443, 50, 5, host="library-web")
    add("demo-port-scan", "198.51.100.200", "10.20.2.7", 8080, 8, 6, host="intranet")
    add("demo-port-scan", "192.0.2.33", "10.20.1.12", 3389, 70, 4, host="build-01")
    for i, h in enumerate((10, 20, 44, 60, 90, 100)):
        add(
            "demo-blocked-burst",
            f"10.20.{10 + i}.{30 + i * 7}",
            f"198.51.100.{120 + i}",
            443,
            h,
            5,
            host=f"ops-ws-{30 + i * 7}",
        )
    for i, h in enumerate((12, 36, 80)):
        add(
            "demo-c2-beacon",
            f"10.20.{20 + i}.{60 + i}",
            f"203.0.113.{101 + i}",
            443,
            h,
            3,
            host=f"office-pc-{60 + i}",
        )
    return out


async def add_people(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        for username, name, caps in PEOPLE:
            await auth.add_user(conn, username, name, PASSWORD, capabilities=caps)


async def raise_flags(owner: AsyncEngine, now: datetime) -> None:
    """The flags an outside lookup and a threat list put on the worst groups (what the
    investigator's raise check stores), so the engine has the reasons production has."""
    flags = {"203.0.113.45": ["flagged by outside threat intel", "on a threat list"],
             "198.51.100.23": ["flagged by outside threat intel"],
             "192.0.2.200": ["flagged by outside threat intel"],
             "198.51.100.150": ["flagged by outside threat intel"],
             "203.0.113.77": ["flagged by outside threat intel"],
             "198.51.100.77": ["flagged by outside threat intel"]}  # fmt: skip
    async with owner.begin() as conn:
        rows = await conn.execute(text(
            "SELECT DISTINCT i.id, i.version, i.last_event_at, e.value FROM investigations i"
            " JOIN investigation_entities e ON e.investigation_id = i.id"
            " WHERE e.value = ANY(:v)"), {"v": list(flags)})  # fmt: skip
        for r in list(rows):
            await conn.execute(
                text("INSERT INTO investigation_raises (investigation_id, version, dossier_hash,"
                     " flags, evaluated_at) VALUES (:i, :v, :h, CAST(:f AS jsonb), :at)"
                     " ON CONFLICT DO NOTHING"),
                {"i": r.id, "v": r.version, "h": "0" * 64, "f": json.dumps(flags[r.value]),
                 "at": r.last_event_at},
            )  # fmt: skip


async def plant_dossiers(app: AsyncEngine, now: datetime) -> None:
    """Every alert group's dossier (the generic pack, nothing asked of the SIEM), as the
    context worker builds it, at the demo's own time."""
    from langgraph.checkpoint.memory import InMemorySaver

    from argus.context.packs import default_registry
    from argus.context.worker import Worker

    worker = Worker(app, InMemorySaver(), packs=default_registry(),
                    clock=lambda: now + timedelta(hours=1))  # fmt: skip
    while await worker.run_once(limit=50):
        pass


async def reports(app: AsyncEngine, root: Path, now: datetime) -> None:
    """The incident report of the confirmed case and the last days' summaries, as ARGUS's own
    passes write them."""
    from argus.config.settings import load_settings
    from argus.incident import run as incident_run
    from argus.reporter import build, store
    from argus.reporter.build import default_days

    settings = load_settings(root / "config" / "argus.yaml")
    done = await incident_run.run_pass(app, settings, now)
    print("incident reports:", done)
    for kind in ("daily", "weekly"):
        for day in default_days(kind, now)[-3:]:
            numbers, body = await build.make(app, kind, day, now)
            async with app.begin() as conn:
                await store.save(conn, numbers, body)


async def run_engine(app: AsyncEngine, now: datetime) -> str:
    from argus.risk import present
    from argus.risk import run as risk_run
    from tests.integration.risk.test_incidents import linked

    report = await risk_run.step(app, replace(linked(), presenter=present.Options(True, 10)), now)
    return report.line()


async def health_state(owner: AsyncEngine, now: datetime) -> None:
    """The SIEM measured a minute ago and normal, the collector current, Kibana read back."""
    from argus.gateway.health import HealthMemory
    from argus.gateway.pgstore import health_to_json

    memory = HealthMemory(since=now - timedelta(days=6), probed_at=now - timedelta(minutes=1))
    async with owner.begin() as conn:
        await conn.execute(
            text("INSERT INTO siem_state (name, state) VALUES ('health', CAST(:s AS jsonb))"
                 " ON CONFLICT (name) DO UPDATE SET state = EXCLUDED.state"),
            {"s": json.dumps(health_to_json(memory))},
        )  # fmt: skip
        for name, back in (("live", 1), ("backfill", 30)):
            await conn.execute(
                text("INSERT INTO collector_cursors (name, at) VALUES (:n, :at)"
                     " ON CONFLICT (name) DO UPDATE SET at = EXCLUDED.at"),
                {"n": name, "at": now - timedelta(minutes=back)},
            )  # fmt: skip
        await conn.execute(
            text("INSERT INTO kibana_sync_cycles (started_at, finished_at, outcome, reads,"
                 " changed, findings, stale) VALUES (:s, :f, 'complete', 4, 0, 0, false)"),
            {"s": now - timedelta(minutes=3), "f": now - timedelta(minutes=3, seconds=-2)},
        )  # fmt: skip


async def work_the_cases(app: AsyncEngine, now: datetime) -> None:
    """What people did with the engine's possible incidents: one confirmed and taken by Mina,
    its owner told; one closed as a scan; the rest wait in Needs you."""
    from argus.cases.machine import Confirm, Dismiss, Notify, Take
    from argus.cases.model import LOCAL_CAPABILITIES, Actor
    from argus.cases.service import CaseService

    async with app.connect() as conn:
        rows = list(await conn.execute(text(
            "SELECT c.id, c.title FROM cases c JOIN risk_incidents r ON r.case_id = c.id"
            " ORDER BY r.band, r.priority DESC")))  # fmt: skip
        mina = (
            await conn.execute(text("SELECT id FROM users WHERE username = 'mina'"))
        ).scalar_one()
    who = Actor.person(int(mina), LOCAL_CAPABILITIES, via="demo")
    titles = {r.id: r.title for r in rows}
    ids = [r.id for r in rows]
    confirm = ids[1] if len(ids) > 2 else None
    dismiss = ids[-1] if len(ids) > 3 else None
    async with app.begin() as conn:
        service = await CaseService.start(conn)
        if confirm is not None:
            await service.apply(who, confirm, Confirm(), expected_version=None)
            await service.apply(who, confirm, Take(), expected_version=None)
            await service.apply(who, confirm, Notify("The depot's IT team", "email"),
                                expected_version=None)  # fmt: skip
        if dismiss is not None:
            await service.apply(who, dismiss, Dismiss("attempt_no_impact", "Blocked at the edge."),
                                expected_version=None)  # fmt: skip
    print("cases:", titles)


# --------------------------------------------------------------------------- argus-admin's state


def admin_snapshot(root: Path) -> dict[str, Any]:
    """argus-admin's snapshot of the suite's checkout, set up as a running installation is:
    the SIEM and Kibana connected, two AI providers with a key, one threat-intel key."""
    import shutil

    from argus.admin.applier import snapshot

    shipped = Path(__file__).resolve().parents[3] / "config"
    shutil.copy(shipped / "llm.yaml", root / "config" / "llm.yaml")
    shutil.copytree(shipped / "agents", root / "config" / "agents", dirs_exist_ok=True)
    snap = snapshot(root)
    settings = snap["settings"]

    def put(key: str, **item: Any) -> None:
        settings.setdefault(key, {"homes": [], "in_app": False}).update(item)

    put("siem.url", value="https://siem.example.org:9200", homes=["set in the app"], in_app=True)
    put("siem.api_key", set=True, homes=["in .env"])
    put("kibana.url", value="https://siem.example.org:5601", homes=["set in the app"], in_app=True)
    put("kibana.reader_api_key", set=True, homes=["in .env"])
    put("outside.virustotal_api_key", set=True, homes=["set in the app"], in_app=True)
    put("history.window", value=432000, homes=["set in the app"], in_app=True)
    put("risk.reading", value=True)
    for name in ("lead", "evidence", "intel", "responder"):
        put(f"case_team.{name}_api_key", set=True, homes=["in .env"])
    put("case_team.keys_expire", value="2027-05-31")
    llm = snap["llm"]
    shown = ("groq", "openrouter", "gemini", "openai")  # the demo's providers
    llm["providers"] = [p for p in llm.get("providers", []) if p["name"] in shown]
    for provider in llm["providers"]:
        for key in provider["keys"]:
            key["set"] = provider["name"] in ("groq", "openrouter", "openai") and not key[
                "name"
            ].endswith("_2")
        if provider["name"] == "openai":
            provider.update(monthly_cap_usd=5.0, daily_cap_usd=0.5)
    for own in (llm.get("purposes") or {}).values():
        if own.get("providers"):
            own["providers"] = [p for p in own["providers"] if p in shown] or ["openai", "groq"]
    llm.update(monthly_cap_usd=10.0, daily_cap_usd=0.5)
    snap["problem"] = None
    return snap


def usage_state(now: datetime) -> dict[str, Any]:
    """Thirty-one days of the threat-intel sources' lookups, as argus-admin counts them."""
    rng = random.Random(7)
    sources: list[dict[str, Any]] = []
    plans: list[tuple[str, int, list[tuple[str, int]], bool]] = [
        ("virustotal", 180, [("minute", 3), ("day", 400)], True),
        ("shodan", 40, [("minute", 30), ("day", 200)], False),
        ("censys", 0, [("day", 10), ("month", 50)], False),
    ]
    for name, base, plan, key in plans:
        limits = [{"window": w, "maximum": m} for w, m in plan]
        days: list[dict[str, Any]] = []
        for back in range(30, -1, -1):
            day = (now - timedelta(days=back)).date()
            weekend = day.weekday() >= 5
            n = (
                0
                if base == 0
                else max(0, int(base * (0.55 if weekend else 1) + rng.randint(-25, 40)))
            )
            if back == 0:
                n = n // 2
            days.append({"day": day.isoformat(), "requests": n})
        month = sum(d["requests"] for d in days if d["day"][:7] == now.date().isoformat()[:7])
        sources.append({
            "source": name, "key_set": key, "enabled": key or name == "shodan",
            "today": days[-1]["requests"], "month": month,
            "answered_month": int(month * 0.97), "limits": limits, "days": days,
        })  # fmt: skip
    return {"at": now.isoformat(), "sources": sources}


def services_state() -> dict[str, Any]:
    from argus.admin import services
    from argus.ops.units import CORE, MANIFEST

    run = [
        *CORE,
        "argus-risk.timer",
        "argus-risk-check.timer",
        "argus-backup.timer",
        "argus-backup-drill.timer",
        "argus-purge.timer",
        "argus-report-daily.timer",
        "argus-report-weekly.timer",
        "argus-incident-report.timer",
    ]
    run = [u for u in run if u in MANIFEST]
    running = set(run)
    return {"units": services.listing(run, lambda unit: unit in running)}


async def publish(owner: AsyncEngine, name: str, state: dict[str, Any], at: datetime) -> None:
    from argus.admin import catalogue

    async with owner.begin() as conn:
        await conn.execute(
            text("INSERT INTO admin_state (name, state, updated_at) VALUES (:n, CAST(:s AS jsonb),"
                 " :at) ON CONFLICT (name) DO UPDATE SET state = EXCLUDED.state,"
                 " updated_at = EXCLUDED.updated_at"),
            {"n": name, "s": json.dumps(catalogue._json(dict(state))), "at": at},
        )  # fmt: skip


PROVIDERS = (  # name, model, tier, cost of a call (paid ones only), calls a day
    ("groq", "openai/gpt-oss-120b", "medium", 0.0, 34),
    ("openrouter", "google/gemma-4-31b-it:free", "small", 0.0, 12),
    ("openai", "gpt-5.4-mini", "medium", 0.012, 9),
)


async def ai_calls(owner: AsyncEngine, now: datetime) -> tuple[float, float, dict[str, float],
                                                                dict[str, float]]:  # fmt: skip
    """About a month of the gateway's ledger across three providers; returns the paid spend."""
    rng = random.Random(11)
    rows = []
    month, today = 0.0, 0.0
    by_month: dict[str, float] = {}
    by_day: dict[str, float] = {}
    for back in range(30, -1, -1):
        day = (now - timedelta(days=back)).replace(hour=0, minute=0, second=0, microsecond=0)
        for name, model, tier, cost, per_day in PROVIDERS:
            calls = max(0, per_day + rng.randint(-per_day // 3, per_day // 2))
            span = 24 * 60 - 1
            if back == 0:
                span = max(1, int((now - day).total_seconds() // 60) - 1)
                calls = max(2, calls * span // (24 * 60))
            for _ in range(calls):
                at = day + timedelta(minutes=rng.randint(0, span))
                if at > now:
                    continue
                purpose = rng.choice(["assess", "assess", "story", "story", "opinion"])
                tokens_in, tokens_out = rng.randint(2500, 9000), rng.randint(300, 1200)
                price = round(cost * rng.uniform(0.6, 1.8), 5)
                ok = rng.random() > 0.04
                rows.append({"at": at, "call_id": uuid.uuid4(), "attempt": 0, "provider": name,
                             "model": model, "tier": tier, "purpose": purpose,
                             "priority": "normal", "outcome": "ok" if ok else "error",
                             "http_status": 200 if ok else 503, "input_tokens": tokens_in,
                             "output_tokens": tokens_out if ok else 0,
                             "cost_usd": price if ok else 0.0, "latency_ms": rng.randint(400, 4000),
                             "request_bytes": tokens_in * 4, "request_sha256": ""})  # fmt: skip
                if ok and price and at.month == now.month:
                    month += price
                    by_month[name] = by_month.get(name, 0.0) + price
                    if at.date() == now.date():
                        today += price
                        by_day[name] = by_day.get(name, 0.0) + price
    async with owner.begin() as conn:
        await conn.execute(
            text("INSERT INTO llm_calls (at, call_id, attempt, provider, model, tier, purpose,"
                 " priority, outcome, http_status, input_tokens, output_tokens, cost_usd,"
                 " latency_ms, request_bytes, request_sha256) VALUES (:at, :call_id, :attempt,"
                 " :provider, :model, :tier, :purpose, :priority, :outcome, :http_status,"
                 " :input_tokens, :output_tokens, :cost_usd, :latency_ms, :request_bytes,"
                 " :request_sha256)"),
            rows,
        )  # fmt: skip
    return month, today, by_month, by_day


async def gateway_state(owner: AsyncEngine, now: datetime, spent: tuple[float, float,
                        dict[str, float], dict[str, float]]) -> None:  # fmt: skip
    from argus.llm import budget

    month, today, by_month, by_day = spent
    state = budget.State(month=budget.month_of(now), spent_usd=month, day=now.date().isoformat(),
                         day_spent_usd=today, provider_spent_usd=by_month,
                         provider_day_spent_usd=by_day)  # fmt: skip
    async with owner.begin() as conn:
        await conn.execute(
            text("INSERT INTO llm_state (name, state) VALUES ('gateway', CAST(:s AS jsonb))"
                 " ON CONFLICT (name) DO UPDATE SET state = EXCLUDED.state"),
            {"s": json.dumps(budget.to_json(state))},
        )  # fmt: skip


async def admin_state(owner: AsyncEngine, root: Path, now: datetime) -> None:
    await publish(owner, "snapshot", admin_snapshot(root), now)
    await publish(owner, "heartbeat", {"at": now.isoformat()}, now)
    await publish(owner, "usage", usage_state(now), now - timedelta(minutes=3))
    await publish(owner, "services", services_state(), now - timedelta(minutes=2))
    await gateway_state(owner, now, await ai_calls(owner, now))
