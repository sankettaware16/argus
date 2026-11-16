"""R10 gate: every investigation gets a dossier from the generic pack; the rule's own note
steps are traced 100% (answered, deferred with a reason, manual, unknown); field facts agree
with a brute-force count; the Inbox shows it; hostile note text stays inert."""

from __future__ import annotations

from collections import Counter
from datetime import timedelta
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.context.display import entry
from argus.context.generic import field_facts
from argus.context.packs import default_registry
from argus.context.worker import Worker
from argus.gateway.templates import CostClass
from argus.reference import store as reference
from tests.integration.context.conftest import NOW
from tests.integration.grouping.test_grouping import doc, ingest

pytestmark = pytest.mark.integration

NOTE = """### Investigation Steps
1. Identify the internal host (`source.ip`) and owner.
2. Check `destination.ip` and `destination.as.organization.name`.
3. Review the `url.path` list.
4. Reputation-check the IP (VirusTotal).
5. Volume from one IP = scanner; block the IP.
"""


def alert(n: int, rule: str = "r1", note: str = NOTE, **fields: Any) -> dict[str, Any]:
    d = doc(n, rule, "10.0.0.1", NOW - timedelta(minutes=50 - n))
    d["_source"].update(
        {
            "kibana.alert.rule.note": note,
            "kibana.alert.rule.revision": 1,
            "kibana.alert.rule.name": f"Rule {rule}",
            **fields,
        }
    )
    return d


async def dossiers(engine: AsyncEngine) -> list[Any]:
    async with engine.connect() as conn:
        rows = await conn.execute(
            text("SELECT investigation_id, pack, body FROM dossiers ORDER BY investigation_id")
        )
        return list(rows.all())


async def run(engine: AsyncEngine, saver: AsyncPostgresSaver) -> None:
    async with engine.begin() as conn:
        await reference.refresh_rules(conn, NOW, hold=timedelta(0))
    worker = Worker(engine, saver, packs=default_registry(), clock=lambda: NOW)
    while await worker.run_once(limit=10):
        pass


async def test_every_step_of_the_note_is_traced(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    docs = [
        alert(n, destination={"ip": f"8.8.8.{n % 2}", "as": {"organization": {"name": "G"}}})
        for n in range(3)
    ]
    await ingest(app_engine, docs)
    await run(app_engine, saver)
    (d,) = await dossiers(app_engine)
    assert d.pack == "generic@12"
    steps = d.body["report"]["steps"]
    assert [s["status"] for s in steps] == ["answered", "answered", "unknown", "deferred", "manual"]
    assert all(s["sentence"] for s in steps)  # 100%: every step an outcome and a sentence
    assert steps[2]["sentence"] == "Could not check: no alert has url.path."
    assert "a threat-intelligence lookup" in steps[3]["sentence"]
    fields = d.body["context"]["pack"]["fields"]
    assert fields["destination.ip"] == {
        "alerts": 3,
        "distinct": 2,
        "top": [["8.8.8.0", 2], ["8.8.8.1", 1]],
    }
    assert fields["destination.as.organization.name"]["top"] == [["G", 3]]
    signals = {s["name"]: s["value"] for s in [*d.body["local_signals"], *d.body["signals"]]}
    assert (
        signals["steps.answered"],
        signals["steps.deferred"],
        signals["steps.manual"],
        signals["steps.unknown"],
    ) == (2, 1, 1, 1)
    assert all(entry(name) is not None for name in signals), "a signal without a display entry"
    assert d.body["report"]["complete"] is True
    assert d.body["report"]["alerts_read"] == 3


async def test_aggregating_rules_answer_through_stand_ins(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    await ingest(app_engine, [alert(1, attempted_paths=["/wp-admin", "/.env"])])
    await run(app_engine, saver)
    (d,) = await dossiers(app_engine)
    step = d.body["report"]["steps"][2]
    assert (step["status"], step["shown"]) == ("answered", ["url.path"])
    fact = d.body["context"]["pack"]["fields"]["url.path"]
    assert fact["from"] == "attempted_paths"
    assert fact["distinct"] == 2


async def test_a_rule_without_a_note_and_a_new_pack_version(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver, migrated_engine: AsyncEngine
) -> None:
    await ingest(app_engine, [alert(1, note="")])
    await run(app_engine, saver)
    (d,) = await dossiers(app_engine)
    assert d.body["report"]["steps"] == []
    assert d.body["report"]["has_note"] is False
    async with migrated_engine.begin() as conn:  # as if an older pack had written it
        await conn.execute(text("DELETE FROM signals"))
        await conn.execute(text("UPDATE dossiers SET pack = 'stub@1'"))
    from argus.context.cli import queue_rederive

    assert await queue_rederive(app_engine, "generic@12") == 1
    async with migrated_engine.begin() as conn:  # queued at the database's time; due by ours
        await conn.execute(
            text("UPDATE jobs SET run_after = :t WHERE status = 'queued'"), {"t": NOW}
        )
    await run(app_engine, saver)
    assert sorted(r.pack for r in await dossiers(app_engine)) == ["generic@12", "stub@1"]
    assert await queue_rederive(app_engine, "generic@12") == 0


DOCS = st.lists(
    st.one_of(
        st.fixed_dictionaries(
            {
                "source": st.fixed_dictionaries(
                    {"ip": st.sampled_from(["1.1.1.1", "2.2.2.2", "3.3.3.3"])}
                )
            }
        ),
        st.fixed_dictionaries({"source.ip": st.sampled_from(["1.1.1.1", "4.4.4.4"])}),
        st.fixed_dictionaries(
            {
                "source": st.fixed_dictionaries(
                    {"ip": st.lists(st.sampled_from(["1.1.1.1", "5.5.5.5"]), max_size=3)}
                )
            }
        ),
        st.just({}),
    ),
    max_size=30,
)


@settings(suppress_health_check=[HealthCheck.too_slow])
@given(DOCS)
def test_field_facts_agree_with_a_brute_force_count(docs: list[dict[str, Any]]) -> None:
    def brute(d: dict[str, Any]) -> set[str]:
        nested = d.get("source", {}).get("ip") if isinstance(d.get("source"), dict) else None
        found = nested if isinstance(nested, list) else [nested] if nested else []
        return {str(v) for v in [*found, d.get("source.ip")] if v}

    expected: Counter[str] = Counter()
    for d in docs:
        expected.update(brute(d))
    got = field_facts(docs, ["source.ip"])["source.ip"]
    assert got["distinct"] == len(expected)
    assert got["alerts"] == sum(1 for d in docs if brute(d))
    assert (
        got["top"]
        == [list(t) for t in sorted(expected.items(), key=lambda kv: (-kv[1], kv[0]))][:8]
    )


# ----------------------------------------------------------------- exact (mutation testing)

RICH = {
    "destination": {"ip": "45.9.9.7", "port": 443, "domain": "d.example",
                    "geo": {"country_name": "India"}, "as": {"organization": {"name": "AS1"}}},
    "url": {"domain": "u.example", "path": "/p", "original": "http://u.example/p",
            "full": "http://u.example/p?q"},
    "user_agent": {"original": "curl/8"}, "host": {"name": "pc1", "ip": "10.0.0.9"},
    "user": {"name": "asha"}, "http": {"request": {"method": "GET"},
                                       "response": {"status_code": 200}},
    "event": {"action": "TCP_MISS"}, "client": {"ip": "10.0.0.8"}, "server": {"ip": "10.0.0.7"},
    "file": {"hash": {"sha256": "a" * 64, "sha1": "b" * 40, "md5": "c" * 32}},
}  # fmt: skip


async def test_the_pack_context_exactly(app_engine: AsyncEngine, saver: AsyncPostgresSaver) -> None:
    from argus.assets.classify import IpClassifier
    from argus.context import generic

    note = "### Investigation Steps\n" + "\n".join(
        f"{n}. Check `extra.f{n}`." for n in range(1, 13)
    )  # twelve named fields first, then the base set, 24 in all
    docs = [alert(n, note=note, **RICH, extra={f"f{k}": f"v{k}" for k in range(1, 13)})
            for n in range(1, 4)]  # fmt: skip
    await ingest(app_engine, docs)
    async with app_engine.begin() as conn:
        await reference.refresh_rules(conn, NOW, hold=timedelta(0))
    pack = generic.GenericPack(IpClassifier(None))
    worker = Worker(app_engine, saver, packs=default_registry(classifier=IpClassifier(None)),
                    clock=lambda: NOW)  # fmt: skip
    while await worker.run_once(limit=10):
        pass
    (d,) = [d for d in await dossiers(app_engine) if d.pack.startswith("generic@")]
    ctx = d.body["context"]["pack"]
    expected = {f"extra.f{n}" for n in range(1, 13)} | set(generic.BASE_FIELDS[:12])
    assert set(ctx["fields"]) == expected  # JSONB keeps no key order
    assert len(generic.BASE_FIELDS) == 19
    assert generic.MAX_FIELDS == 24
    assert ctx["fields"]["source.ip"] == {"alerts": 3, "distinct": 1, "top": [["10.0.0.1", 3]]}
    assert (ctx["alerts_read"], ctx["complete"], ctx["has_note"]) == (3, True, True)
    assert ctx["note_hash"] is not None
    assert ctx["ips"] == {"10.0.0.1": {"class": "internal", "asset": None},
                          "45.9.9.7": {"class": "public", "asset": None}}  # fmt: skip
    assert any("squid" in i for i in ctx["indices"])  # a proxy rule: its hints, no web ones
    assert ctx["web"] == {}
    assert ctx["heuristics"] == {"port_classes": {"web": 3}, "ports_shown": "exact",
                                 "nat_hint": False, "agents": 1}  # fmt: skip
    report = d.body["report"]
    assert set(report) == {"steps", "summary", "has_note", "note_hash", "complete", "alerts_read"}
    assert (report["has_note"], report["complete"], report["alerts_read"]) == (True, True, 3)
    assert report["note_hash"] == ctx["note_hash"]
    names = {s["name"] for s in d.body["signals"]}
    assert not any(n.startswith("web.") for n in names)
    assert {"ports.risky", "proxy.denied", "nat.hint"} <= names
    assert {"steps.answered", "steps.deferred", "steps.manual", "steps.unknown"} <= names
    assert pack.plan(1, {}, {"pack": ctx}, {}) == []  # nothing remote without the live checks
    assert pack.plan(2, {}, {"pack": ctx}, {}) == ()
    assert (generic.ALERTS, generic.TOP, generic.VALUE_CHARS) == (1000, 8, 100)
    assert generic.IP_FIELDS == ("source.ip", "destination.ip", "client.ip", "server.ip",
                                 "host.ip")  # fmt: skip
    assert generic.GenericPack.budget == {CostClass.LIGHT: 4, CostClass.MEDIUM: 1,
                                          CostClass.HEAVY: 2}  # fmt: skip
    assert (pack.max_waves, generic.GenericPack(remote_ti=True).max_waves,
            generic.GenericPack(log_queries=True).max_waves) == (0, 1, 1)  # fmt: skip
    assert generic.GenericPack(proxy_aggregations=True).max_waves == 1


def test_ips_and_owners_from_the_facts() -> None:
    from argus.assets.classify import IpClassifier
    from argus.context import generic

    fields = {f: {"top": [[v, 1]]} for f, v in (("source.ip", "10.0.0.1"),
              ("client.ip", "10.0.0.1"), ("server.ip", "8.8.8.8"), ("host.ip", "x"))}  # fmt: skip
    got = generic.GenericPack(IpClassifier(None))._ips(fields)
    assert got == {"10.0.0.1": {"class": "internal", "asset": None},
                   "8.8.8.8": {"class": "public", "asset": None},
                   "x": {"class": "invalid", "asset": None}}  # fmt: skip
    assert generic.GenericPack()._ips(fields) == {}  # no asset map: nothing to say
    owner_step = {"number": 1, "text": "Find the owner.", "fields": []}
    context = {"pack": {"fields": {"source.ip": {"distinct": 1, "top": [["10.0.0.1", 1]]}},
                        "ips": {"10.0.0.1": {"class": "asset", "asset": "pc1"}},
                        "steps": [owner_step]}}  # fmt: skip
    (step,) = generic.GenericPack()._outcomes(context)
    assert step["status"] == "answered"
    context["pack"]["ips"] = {"10.0.0.1": {"class": "internal", "asset": None}}
    (step,) = generic.GenericPack()._outcomes(context)
    assert step["status"] == "manual"


def test_field_facts_cut_values_and_skip_empty_ones() -> None:
    docs = [{"a": "x" * 150}, {"a": ""}, {"a": None}, {"a": ["y", "y"]}, {}]
    facts = field_facts(docs, ["a"])  # type: ignore[arg-type]
    assert facts == {"a": {"alerts": 2, "distinct": 2, "top": [["x" * 100, 1], ["y", 1]]}}
