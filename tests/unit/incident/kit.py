"""Synthetic cases for the incident report's tests: facts as the gatherer would read them, made
by hand, so the pure writer is tested without a database. Two shapes: the Amadey host (one
campus device beaconing to four flagged servers, found by two rules over five days) and the Git
collection (a scout, a collector and a prober against campus web directories). Every address is
a documentation or private one; nothing here is a real alert."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from argus.incident import discover
from argus.incident import gather as g
from argus.incident.build import Context

D0 = datetime(2026, 10, 23, 4, 30, tzinfo=UTC)  # 10:00 AM IST
AS_AT = D0 + timedelta(days=6, hours=3)
HOST = "10.201.7.11"
SERVERS = ("77.221.155.150", "77.221.155.151", "77.221.155.152", "77.221.155.153")
BEACON = "regular traffic, like a beacon"
OUTSIDE = "flagged by outside threat intel"
CFG = discover.Config(kibana_url="https://kibana.example", space="acme-soc")
CASE_ID = uuid.UUID("11111111-1111-4111-8111-111111111111")
SCOUT, COLLECTOR, PROBER = "203.0.113.10", "203.0.113.20", "203.0.113.30"


def at(day: int, hour: int = 0, minute: int = 0) -> datetime:
    return D0 + timedelta(days=day, hours=hour, minutes=minute)


def ist_day(when: datetime) -> str:
    return (when + timedelta(hours=5, minutes=30)).date().isoformat()


def ctx(**more: Any) -> Context:
    values: dict[str, Any] = {"cfg": CFG, "as_at": AS_AT}
    values.update(more)
    return Context(**values)


def inv_id(n: int) -> uuid.UUID:
    return uuid.UUID(int=0xA0000 + n)


def case_row(**more: Any) -> g.CaseRow:
    values: dict[str, Any] = {
        "id": CASE_ID,
        "number": 7,
        "title": "Regular beaconing from a campus host",
        "state": "open",
        "severity": "high",
        "version": 3,
        "cause": "person",
        "created_at": at(3, 2),
        "opened_at": at(3, 2),
        "notified_at": None,
        "blocked_at": None,
        "cause_assessment_id": None,
    }
    values.update(more)
    return g.CaseRow(**values)


def vt(ip: str, bad: int = 7, engines: int = 94, *, day: int = 3) -> g.OutsideRow:
    answer = {"malicious": bad, "suspicious": 0, "engines": engines, "owner": "Example Hosting AB"}
    return g.OutsideRow("virustotal", "ip", ip, "found", answer, at(day))


def pair_snapshot(requests: int, nbytes: int = 480_000) -> dict[str, Any]:
    return {
        "aggregations": {
            "requests": {"value": requests},
            "bytes": {"value": nbytes},
            "first": {"value": 0},
            "last": {"value": 0},
        }
    }


def pair_row(inv: uuid.UUID, server: str, requests: int, day: int) -> g.EvidenceRow:
    start = at(day, 0)
    params = {
        "host": HOST,
        "destination": server,
        "start": start.isoformat(),
        "end": (start + timedelta(hours=6)).isoformat(),
    }
    status = "ok" if requests else "empty"
    return g.EvidenceRow(
        inv, "proxy.pair", 1, params, status, requests, pair_snapshot(requests), at(day, 7)
    )


def merge(days: list[g.DayRule]) -> list[g.DayRule]:
    """One row for each (day, rule), as the gatherer's GROUP BY gives."""
    merged: dict[tuple[str, str], g.DayRule] = {}
    for d in days:
        key = (d.day, d.rule)
        old = merged.get(key)
        if old is None:
            merged[key] = d
        else:
            merged[key] = g.DayRule(
                d.day, d.rule, old.alerts + d.alerts, min(old.first, d.first), max(old.last, d.last)
            )
    return sorted(merged.values(), key=lambda d: (d.day, d.rule))


def amadey(
    *, devices: int = 1, notified: bool = False, assessed: bool = True, state: str = "open"
) -> g.CaseFacts:
    """The Amadey host in miniature: 5 investigations (a download rule on days 0 and 2, a beacon
    rule on days 1, 3 and 4), 35 alerts, four flagged servers, VirusTotal's answers, the pair
    checks that ran, and (assessed) the AI investigator's true-positive proposal."""
    hosts = [HOST] + [f"10.198.{37 + i // 200}.{i % 200 + 10}" for i in range(devices - 1)]
    rules = [("download", 0), ("beacon", 1), ("download", 2), ("beacon", 3), ("beacon", 4)]
    members: list[g.MemberRow] = []
    entities: list[g.EntityRow] = []
    inv_days: list[g.InvDay] = []
    days: list[g.DayRule] = []
    evidence: list[g.EvidenceRow] = []
    for n, (rule, day) in enumerate(rules):
        inv = inv_id(n)
        flags = (BEACON, OUTSIDE)
        members.append(
            g.MemberRow(
                inv, f"Rule {rule}", f"rule-{rule}", "low", 7, at(day, 1), at(day, 20), 1, "actor",
                None, flags, (),
            )
        )  # fmt: skip
        entities += [g.EntityRow(inv, "ip", h) for h in hosts]
        entities += [g.EntityRow(inv, "ip", s) for s in SERVERS]
        day_key = ist_day(at(day, 1))
        inv_days.append(g.InvDay(inv, day_key, 7))
        days.append(g.DayRule(day_key, f"Rule {rule}", 7, at(day, 1), at(day, 20)))
        evidence.append(pair_row(inv, SERVERS[n % 4], 40 + n, day))
    indicators = [g.IndicatorRow("ip", h, "actor", "investigation") for h in hosts]
    indicators += [g.IndicatorRow("ip", s, "c2", "threat_intel") for s in SERVERS]
    assessments: list[g.AssessmentRow] = []
    if assessed:
        answer = [{"answer": {"outcome": "true_positive", "confidence": 0.8}}]
        for n in range(5):
            assessments.append(
                g.AssessmentRow(
                    100 + n, inv_id(n), "agent@1", "proposed", "true_positive", 0.8, answer, at(5)
                )
            )
    return g.CaseFacts(
        case=case_row(state=state, notified_at=at(4, 3) if notified else None),
        members=tuple(members),
        members_total=5,
        days=tuple(merge(days)),
        alerts_total=35,
        docs=(),
        entities=tuple(entities),
        inv_days=tuple(inv_days),
        indicators=tuple(indicators),
        indicators_total=len(indicators),
        evidence=tuple(evidence),
        assessments=tuple(assessments),
        outside=tuple(vt(s, 7 + i) for i, s in enumerate(SERVERS)),
        known=None,
        notices=(),
        reminders=(),
        actions=(),
        advice=frozenset({"c2_indicator"}),
        order=1,
    )


def nginx_doc(
    inv: uuid.UUID, ip: str, when: datetime, agent: str, path: str = "/~hostel5/.git/config"
) -> g.AlertDoc:
    fields = {
        "source.ip": (ip,),
        "url.path": (path,),
        "url.domain": ("home.example.edu",),
        "user_agent.original": (agent,),
        "source.as.organization.name": ("Example Cloud LLC",),
        "source.geo.country_name": ("Netherlands",),
    }
    return g.AlertDoc(f"a-{inv.hex[-4:]}", inv, "Web probe", when, fields)


def git(*, volumes: tuple[int, int, int] = (3, 14683, 5)) -> g.CaseFacts:
    """The Git collection: a scout (few requests, first), a collector (the volume) and a prober
    (few requests, last) against a campus web directory."""
    who = (SCOUT, COLLECTOR, PROBER)
    starts = [at(0, 1), at(0, 8), at(2, 3)]
    members: list[g.MemberRow] = []
    entities: list[g.EntityRow] = []
    inv_days: list[g.InvDay] = []
    days: list[g.DayRule] = []
    evidence: list[g.EvidenceRow] = []
    docs: list[g.AlertDoc] = []
    for n, (ip, start, volume) in enumerate(zip(who, starts, volumes, strict=True)):
        inv = inv_id(10 + n)
        alerts = max(volume // 1000, 1) + 2
        flags = ("successful answers after the alert",)
        members.append(
            g.MemberRow(
                inv, "Web scan", "rule-web", "high", alerts, start, start + timedelta(hours=10),
                1, "actor", None, flags, (),
            )
        )  # fmt: skip
        entities.append(g.EntityRow(inv, "ip", ip))
        day_key = ist_day(start)
        inv_days.append(g.InvDay(inv, day_key, alerts))
        days.append(g.DayRule(day_key, "Web scan", alerts, start, start + timedelta(hours=10)))
        snapshot = {
            "aggregations": {
                "requests": {"value": volume},
                "answered": {"value": volume},
                "paths": {"buckets": []},
            }
        }
        params = {
            "ip": ip,
            "site": "home.example.edu",
            "paths": ["/~hostel5/.git/config"],
            "start": start.isoformat(),
            "end": (start + timedelta(hours=1)).isoformat(),
        }
        evidence.append(
            g.EvidenceRow(
                inv,
                "web.path_outcomes",
                1,
                params,
                "ok",
                None,
                snapshot,
                start + timedelta(hours=12),
            )
        )
        agent = "git-dumper/1.0" if ip == COLLECTOR else "curl/8.0"
        docs.append(nginx_doc(inv, ip, start, agent))
    indicators = [g.IndicatorRow("ip", w, "actor", "investigation") for w in who]
    return g.CaseFacts(
        case=case_row(
            title="Git repositories collected from campus directories",
            cause="proposal",
            state="suspected",
            opened_at=None,
        ),
        members=tuple(members),
        members_total=3,
        days=tuple(merge(days)),
        alerts_total=sum(x.alerts for x in members),
        docs=tuple(docs),
        entities=tuple(entities),
        inv_days=tuple(inv_days),
        indicators=tuple(indicators),
        indicators_total=3,
        evidence=tuple(evidence),
        assessments=(),
        outside=(),
        known=None,
        notices=(),
        reminders=(),
        actions=(),
        advice=frozenset({"sensitive_file_served"}),
        served=frozenset({"/~hostel5/.git/config"}),
        order=2,
    )


RULE_SERVED = "Web: Sensitive, Backup or Config File Served Successfully"
SITES = ("home.example.edu", "lab.example.edu")
SERVER = "10.20.30.40"  # a campus web server
PROBERS = tuple(f"203.0.113.{n}" for n in range(101, 117))  # sixteen outside addresses


def followup_snapshot(site: str, path: str = "/.env", total: int = 2) -> dict[str, Any]:
    """A stored ``web.followups`` answer: the client's successful (2xx) answers after the alert."""
    hit = {"url": {"path": path, "domain": site}, "http": {"response": {"status_code": 200}}}
    return {
        "total": total,
        "rows": [{"_index": "acme-logs-nginx-2026.10.24", "_id": "x", "_source": hit}],
        "aggregations": None,
    }


def scanners(*, checks: bool = True, count: int = len(PROBERS)) -> g.CaseFacts:
    """Case 1's shape: sixteen outside addresses probing campus web servers for ``.env`` files.
    Each address is an investigation of its own; the alerts record the path, the site and the
    server (and, for an address with a stored web check, ARGUS holds the successful answers);
    two addresses are on a local threat list, three have a VirusTotal answer, and one look-up of
    two values found 236 records. ``checks`` False: no web check was stored (the shape the
    production case had: the advice facts then come from the alerts alone). ``count``: how many
    outside addresses (the first sixteen are the ones above; more follow in the same /24)."""
    probers = tuple(f"203.0.113.{n}" for n in range(101, 101 + count))
    members: list[g.MemberRow] = []
    entities: list[g.EntityRow] = []
    inv_days: list[g.InvDay] = []
    days: list[g.DayRule] = []
    evidence: list[g.EvidenceRow] = []
    docs: list[g.AlertDoc] = []
    for n, ip in enumerate(probers):
        inv = inv_id(100 + n)
        start = at(1, 2, n)
        site = SITES[n % 2]
        members.append(
            g.MemberRow(
                inv, RULE_SERVED, "rule-served", "high", 3 + n % 3, start,
                start + timedelta(hours=2), 1, "actor", None,
                ("successful answers after the alert",), (ip,) if n < 2 else (),
            )
        )  # fmt: skip
        entities += [g.EntityRow(inv, "ip", ip), g.EntityRow(inv, "domain", site)]
        key = ist_day(start)
        inv_days.append(g.InvDay(inv, key, 3 + n % 3))
        days.append(g.DayRule(key, RULE_SERVED, 3 + n % 3, start, start + timedelta(hours=2)))
        fields = {
            "source.ip": (ip,), "url.path": ("/.env",), "url.domain": (site,),
            "destination.ip": (SERVER,), "user_agent.original": ("Mozilla/5.0",),
            "source.as.organization.name": ("Example Cloud LLC",),
        }  # fmt: skip
        docs.append(g.AlertDoc(f"a-{n}", inv, RULE_SERVED, start, fields))
        if checks and n < 6:
            params = {
                "ip": ip,
                "start": start.isoformat(),
                "end": (start + timedelta(hours=6)).isoformat(),
            }
            evidence.append(
                g.EvidenceRow(inv, "web.followups", 1, params, "ok", 2,
                              followup_snapshot(site), start + timedelta(hours=7))
            )  # fmt: skip
    if checks:
        values = [PROBERS[0], PROBERS[1]]
        evidence.append(
            g.EvidenceRow(
                inv_id(100),
                "ti.lookup",
                1,
                {"values": values},
                "ok",
                236,
                {"total": 236, "rows": [], "aggregations": None},
                at(1, 9),
            )
        )
        evidence.append(
            g.EvidenceRow(
                inv_id(101),
                "ti.lookup",
                1,
                {"values": [PROBERS[2]]},
                "ok",
                3,
                {"total": 3, "rows": [], "aggregations": None},
                at(1, 10),
            )
        )
    indicators = [g.IndicatorRow("ip", ip, "actor", "investigation") for ip in probers]
    from argus.responder import facts as responder_facts

    advice = responder_facts.from_parts(
        [(i.kind, i.value, i.role) for i in indicators],
        [{k: list(v) for k, v in d.fields.items()} for d in docs],
        [],
        responder_facts.answered_by_followups(followup_snapshot(SITES[0])) if checks else [],
    )
    return g.CaseFacts(
        case=case_row(
            title="Probing for .env secrets files by 16 outside addresses — config files served",
            cause="raised",
            state="suspected",
            opened_at=None,
        ),
        members=tuple(members),
        members_total=len(members),
        days=tuple(merge(days)),
        alerts_total=sum(x.alerts for x in members),
        docs=tuple(docs),
        entities=tuple(entities),
        inv_days=tuple(inv_days),
        indicators=tuple(indicators),
        indicators_total=len(indicators),
        evidence=tuple(evidence),
        assessments=(),
        outside=tuple(vt(ip, 7 + n) for n, ip in enumerate(probers[:3])),
        known=None,
        notices=(),
        reminders=(),
        actions=(),
        advice=advice.present,
        served=frozenset(p for paths in advice.paths.values() for p in paths),
        order=1,
    )


def synthetic(
    *,
    members: int,
    alerts_each: int,
    hosts: int,
    servers: int,
    counts: list[int],
    notified: bool = False,
    flagged: bool = True,
    state: str = "open",
) -> g.CaseFacts:
    """A case of any size: ``members`` investigations (alternating two rules, one a day),
    ``alerts_each`` alerts in each, ``hosts`` campus devices, ``servers`` servers, and a pair
    check for each investigation whose stored count is taken from ``counts`` in turn."""
    host_list = [f"10.30.{i // 250}.{i % 250 + 1}" for i in range(hosts)]
    server_list = [f"198.51.100.{i + 1}" for i in range(servers)]
    rows: list[g.MemberRow] = []
    entities: list[g.EntityRow] = []
    inv_days: list[g.InvDay] = []
    days: list[g.DayRule] = []
    evidence: list[g.EvidenceRow] = []
    for n in range(members):
        inv = inv_id(500 + n)
        rule = f"Rule {'ab'[n % 2]}"
        day = n
        rows.append(
            g.MemberRow(
                inv, rule, rule.lower(), "low", alerts_each, at(day, 1), at(day, 9), 1, "actor",
                None, (BEACON,) if n % 2 else (), (),
            )
        )  # fmt: skip
        entities += [g.EntityRow(inv, "ip", h) for h in host_list[:3]]
        entities += [g.EntityRow(inv, "ip", s) for s in server_list]
        key = ist_day(at(day, 1))
        inv_days.append(g.InvDay(inv, key, alerts_each))
        days.append(g.DayRule(key, rule, alerts_each, at(day, 1), at(day, 9)))
        if server_list and host_list:
            count = counts[n % len(counts)]
            params = {
                "host": host_list[0],
                "destination": server_list[0],
                "start": at(day, 0).isoformat(),
                "end": (at(day, 0) + timedelta(hours=6)).isoformat(),
            }
            evidence.append(
                g.EvidenceRow(
                    inv, "proxy.pair", 1, params, "ok" if count else "empty", count,
                    pair_snapshot(count), at(day, 7),
                )
            )  # fmt: skip
    indicators = [g.IndicatorRow("ip", h, "actor", "investigation") for h in host_list]
    indicators += [g.IndicatorRow("ip", s, "c2", "threat_intel") for s in server_list]
    outside = tuple(vt(s, 5 + i) for i, s in enumerate(server_list)) if flagged else ()
    return g.CaseFacts(
        case=case_row(state=state, notified_at=at(0, 3) if notified else None),
        members=tuple(rows),
        members_total=members,
        days=tuple(merge(days)),
        alerts_total=members * alerts_each,
        docs=(),
        entities=tuple(entities),
        inv_days=tuple(inv_days),
        indicators=tuple(indicators),
        indicators_total=len(indicators),
        evidence=tuple(evidence),
        assessments=(),
        outside=outside,
        known=None,
        notices=(),
        reminders=(),
        actions=(),
        advice=frozenset({"c2_indicator"} if servers else ()),
        order=1,
    )
