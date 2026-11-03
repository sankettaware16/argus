"""The Visualiser's comment, "Incident at a glance": a plain numbers row that always renders, and
live Kibana charts under it (:mod:`argus.caseteam.lens`) over the alerts tagged with the incident
ID. Posted by ``argus-visualiser`` right after the evidence comment; pure. The numbers and charts
come from :func:`argus.incident.glance.glance_of`, the same data as the one-page dashboard, so they
cannot disagree. Charts are dropped from the end until the comment fits Kibana's limit, the numbers
row never; no name of a person is in it."""

from __future__ import annotations

from collections.abc import Sequence

from argus import site
from argus.caseteam import lens
from argus.caseteam.model import Author, Step, unit_hash
from argus.gateway.kibana.models import utf16_len
from argus.incident import glance as g
from argus.incident import model as m
from argus.incident.words import count, ist_moment, plural
from argus.writer.render import fence

PART = "glance"
TITLE = "Incident at a glance"
KEY = "comment:glance:1"
FIT = 28_000  # UTF-16 units: under Kibana's 30,000 with room for the heading and the numbers
SKIPPED = "no visualiser key"  # why the poster skips the step when the user's key is not installed


def _when(at: object) -> str:
    return "not known" if at is None else ist_moment(at)  # type: ignore[arg-type]


def numbers(glance: g.Glance) -> str:
    """The numbers row, as a table of one row (always rendered, whatever Kibana does with the
    charts below)."""
    head = [
        "Alerts",
        "Actors",
        "Targets",
        "On threat lists",
        f"First alert ({site.zone_label()})",
        f"Last alert ({site.zone_label()})",
        "Rules",
    ]
    row = [
        count(glance.alerts),
        g.more(glance.actors, glance.actors_more),
        plural(glance.targets, glance.targets_word),
        plural(glance.listed, "indicator"),
        _when(glance.first),
        _when(glance.last),
        g.more(glance.rules, glance.rules_more),
    ]
    return "| " + " | ".join(head) + " |\n|" + "---|" * len(head) + "\n| " + " | ".join(row) + " |"


def scope_of(report: m.IncidentReport, space: str) -> lens.Scope | None:
    """What the charts are over; None when the report cannot say (no alert time) or the incident
    ID is not plain enough for a block (a chart is then left out, never the numbers)."""
    h = report.header
    if h.first_alert_at is None or h.last_alert_at is None:
        return None
    if not lens.SAFE.fullmatch(h.incident_id) or not lens.SPACE.fullmatch(space):
        return None
    return lens.Scope(space, h.incident_id, h.first_alert_at, h.last_alert_at)


def charts(glance: g.Glance, scope: lens.Scope) -> list[tuple[str, str]]:
    """(caption, block) for each chart this case has, in the order they are shown."""
    shape = glance.shape
    out: list[tuple[str, str]] = []
    if glance.layers or glance.alerts:
        out.append(("Alerts over time, by rule", lens.block(scope, lens.alerts_over_time(scope))))
    if shape.actors_field and glance.top_actors:
        attrs = lens.top_values(scope, shape.actors_title, shape.actors_field)
        out.append((shape.actors_title, lens.block(scope, attrs)))
    if shape.targets_field and glance.top_targets:
        attrs = lens.top_values(scope, shape.targets_title, shape.targets_field)
        out.append((shape.targets_title, lens.block(scope, attrs)))
    if glance.rule_rows:
        out.append(("Rules that raised the alerts", lens.block(scope, lens.rules_table(scope))))
    return out


def body(report: m.IncidentReport, space: str) -> str:
    """Everything under the heading. Two reports that say the same give the same body, so the
    poster can tell whether an earlier "Incident at a glance" still holds (its hash is the step's
    unit)."""
    glance = g.glance_of(report)
    scope = scope_of(report, space)
    ident = report.header.incident_id
    intro = (
        f"ARGUS counted this from the case's stored alerts. The charts are live Kibana charts"
        f" over the alerts tagged {fence(ident)} only; if one does not draw, the numbers and the"
        " one-page dashboard in the Files tab say the same."
    )
    table = numbers(glance)
    shown: list[tuple[str, str]] = [] if scope is None else charts(glance, scope)
    note = "" if scope is not None else "No alert time is known, so no chart is drawn."
    while True:
        parts = [intro, table]
        parts += [f"**{caption}**\n\n{blk}" for caption, blk in shown]
        if note:
            parts.append(note)
        text = "\n\n".join(parts)
        if utf16_len(text) <= FIT or not shown:
            return text
        shown.pop()


def comment(report: m.IncidentReport, space: str, *, update: bool = False) -> tuple[str, str]:
    """(the whole comment, its body). ``update``: it follows an earlier one for this case."""
    text = body(report, space)
    title = f"Update: {TITLE}" if update else TITLE
    return f"## {title}\n\n{text}", text


def steps(report: m.IncidentReport, space: str, *, update: bool = False) -> list[Step]:
    """The step that posts the glance: one comment by the visualiser."""
    whole, text = comment(report, space, update=update)
    return [
        Step(
            KEY,
            "comment",
            Author.VISUALISER,
            PART,
            text=whole,
            units=(unit_hash(text),),
        )
    ]


def due(report: m.IncidentReport, space: str, posted: Sequence[str] | frozenset[str]) -> bool:
    """Whether the glance as it is now was not posted yet (``posted``: the hashes of the glances
    the case already holds)."""
    return unit_hash(body(report, space)) not in posted
