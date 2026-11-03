"""The deterministic writer: :class:`argus.incident.gather.CaseFacts` in, the
:class:`argus.incident.model.IncidentReport` out. Pure: no database, no clock, no network, no model;
the same facts always give the same report, which keeps a case's report stable until its evidence
changes. Every sentence is **a fact's own sentence** or a short connective sentence that cites facts
and adds no number (:mod:`argus.incident.book`); a model (:mod:`argus.incident.prose`) only rewords
the summary. Numbers come from SQL and stored answers; the writer never estimates. The parts are in
:mod:`argus.incident.verdict`, :mod:`argus.incident.parts` and :mod:`argus.incident.story`; this
module adds the header: the incident id and the Kibana case's tags."""

from __future__ import annotations

import re

from argus import site
from argus.incident import model as m
from argus.incident import parts, story, targets, verdict
from argus.incident.book import Book, cut
from argus.incident.gather import CaseFacts
from argus.incident.scene import Context, Scene, top
from argus.incident.words import VERDICT_TAG

__all__ = ["Context", "build", "incident_id"]

OPENED = {
    "verdict": "opened on a person's verdict",
    "person": "opened by a person",
    "proposal": "suggested by ARGUS from its proposal",
    "raised": "suggested by ARGUS from its own evidence",
    "watch": "reopened by the still-active watch",
}
PHASE = {"suspected": "triage", "closed": "resolved", "contained": "contained"}


def incident_id(f: CaseFacts) -> str:
    """``<prefix>-<yyyy>-<mmdd>-<nn>``: the day (in the site's zone) the case was made, and its
    rank among that day's cases. The prefix is ``site.incident_id_prefix`` (``IR`` by default;
    for example ``IR-2026-1027-01``)."""
    local = f.case.created_at.astimezone(site.zone())
    return f"{site.incident_prefix()}-{local:%Y}-{local:%m%d}-{f.order:02d}"


def _families(scene: Scene) -> list[str]:
    from argus.responder import facts as responder_facts

    cat = scene.ctx.catalogue
    if cat is None or not scene.f.advice:
        return []
    found = responder_facts.match(cat, responder_facts.Facts(frozenset(scene.f.advice)))
    return [fam.key for fam in found]


def _zone(scene: Scene) -> str | None:
    """The site zone of the first internal device, from the asset map (``site.zone``)."""
    cls = scene.ctx.classifier
    if cls is None or not scene.devices:
        return None
    match = cls.classify(scene.devices[0]).asset
    for entry in () if match is None else match.entries:
        for key in ("site.zone", "zone"):
            zone = entry.fields.get(key)
            if zone and re.fullmatch(r"[A-Za-z0-9_-]{1,40}", zone):
                return zone.lower()
    return None


def _mitre(scene: Scene) -> list[str]:
    found: list[str] = []
    for doc in scene.f.docs:
        for key in ("kibana.alert.rule.threat.technique.id", "threat.technique.id"):
            found += [v for v in doc.fields.get(key, ()) if re.fullmatch(r"T\d{4}(?:\.\d{3})?", v)]
    return top(found, 4)


def _phase(scene: Scene) -> str:
    case = scene.f.case
    if case.state in PHASE:
        return PHASE[case.state]
    return "monitoring" if case.notified_at is not None else "containment-pending"


def tags(scene: Scene, ident: str, outcome: str | None) -> tuple[str, ...]:
    """The Kibana case's ``key:value`` tags, the incident
    id first. The case team sends them; the report only says them."""
    found = [ident, "incident"]
    if outcome in VERDICT_TAG:
        found.append(VERDICT_TAG[outcome])
    families = _families(scene)
    if families:
        found.append("category:" + families[0].replace("_", "-"))
    zone = _zone(scene)
    if zone:
        found.append(f"zone:{zone}")
    found += [f"mitre:{t}" for t in _mitre(scene)]
    found += [f"ioc:{v}" for v in scene.servers[:3]]
    found += [f"status:{_phase(scene)}", "source:argus-lead"]
    return tuple(dict.fromkeys(t for t in found if len(t) <= 100))


def build(facts: CaseFacts, ctx: Context) -> m.IncidentReport:
    """The report for ``facts`` (pure)."""
    scene = Scene.of(facts, ctx)
    book = Book()
    case = facts.case
    ident = incident_id(facts)
    said = verdict.resolve(scene, book)
    time = parts.timeline(scene, book)
    actors, outsiders_total = parts.actors(scene, book)
    assets, assets_total = parts.assets(scene)
    hit, hit_total = targets.targets(scene)
    lines, queries = parts.evidence_lines(scene, book, ident)
    indicators, indicators_total = parts.indicators(scene)
    hypotheses = story.hypotheses(scene, book, said)
    actions = story.actions(scene, book)
    summary = story.summary(scene, book, said)
    rules = sorted(scene.rules.items(), key=lambda kv: (-kv[1][0], kv[0]))
    detected = "Rules: " + "; ".join(f"{name} ({n} alerts)" for name, (n, _, _) in rules[:6])
    if len(rules) > 6:
        detected += f"; and {len(rules) - 6} more"
    scope = book.say(
        "case",
        "ARGUS reads alerts and logs only: it has no endpoint data, so what runs on a device "
        "is not known.",
        "ARGUS's scope",
    )
    accounts = parts.users(scene, book)  # last: the facts above keep their numbers
    opened = OPENED.get(case.cause, case.cause) + "; "
    if case.opened_at is not None:
        opened += "confirmed as a case by a person"
    elif said.kind == "person":  # a person reviewed the report: not "unconfirmed"
        opened += f"a person reviewed the report ({said.words})"
    else:
        opened += "no person has confirmed it yet"
    header = m.ReportHeader(
        incident_id=ident,
        title=cut(f"{ident} · {case.title}", 300),
        case_number=case.number,
        case_id=str(case.id),
        case_state=case.state,
        severity=case.severity,
        opened_in=cut(opened, 160),
        detected_by=cut(detected, 500),
        first_alert_at=scene.first,
        last_alert_at=scene.last,
        tags=tags(scene, ident, said.outcome),
    )
    meta = m.ReportMeta(
        as_at=ctx.as_at,
        catalogue_version=None if ctx.catalogue is None else ctx.catalogue.version,
        alerts_read=len(facts.docs),
        alerts_total=scene.alerts,
        limits=tuple(dict.fromkeys(scene.limits)),
    )
    return m.IncidentReport(
        header=header,
        summary=summary,
        verdict=said,
        timeline=time,
        actors=actors,
        outsiders_total=outsiders_total,
        assets=assets,
        assets_total=assets_total,
        targets=hit,
        targets_total=hit_total,
        users=accounts,
        evidence=lines,
        hypotheses=hypotheses,
        indicators=indicators,
        indicators_total=indicators_total,
        actions=actions,
        queries=queries,
        out_of_scope=(scope,),
        facts=tuple(book.facts),
        meta=meta,
    )
