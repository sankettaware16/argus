"""The Visualiser's comment, "Incident at a glance": **one living comment** per case, posted by
``argus-visualiser`` right after the evidence comment and, in each later round, edited in place
(:func:`argus.caseteam.plan.glance_step`), never posted again. Pure.

Under the heading: what a person decides on first (the severity, the call and whose it is, still
active or quiet, the dwell), a numbers row that always renders, what is new since the glance
before it, and live Kibana charts (:mod:`argus.caseteam.lens`) over the alerts attached to the
case and tagged with its incident ID, with how many of the case's alerts that is. The numbers and
the charts come from :func:`argus.incident.glance.glance_of`, the same data as the one-page
dashboard. A panel of one item, or over a field most of the case's alerts do not hold, is a short
list from the report instead of a chart (an empty chart would read as "nothing"). Charts are
dropped from the end until the comment fits Kibana's limit, the numbers never; no name of a
person is in it.

What a round compares is the comment's **core**: everything but the line that says what is new.
Its hash is the step's unit, so the same report gives the same core and a round edits the glance
only when the core moved."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any

from argus import site
from argus.caseteam import lens, render
from argus.caseteam.model import Author, Step, unit_hash
from argus.gateway.kibana.models import utf16_len
from argus.incident import glance as g
from argus.incident import model as m
from argus.incident.words import count, ist_moment, plural
from argus.writer.render import escape, fence

PART = "glance"
TITLE = "Incident at a glance"
KEY = "comment:glance:1"
FIT = 28_000  # UTF-16 units: under Kibana's 30,000 with room for the heading and the numbers
NEWS_ROOM = 600  # kept free for the line that says what is new, so the charts never depend on it
SKIPPED = "no visualiser key"  # why the poster skips the step when the user's key is not installed
LISTED_AT = 5  # items a list that stands in for a chart shows
INTRO = (
    "ARGUS counted this from the case's stored alerts and edits this comment in place when the"
    " case changes, so it always shows the newest report. The one-page dashboard in the Files tab"
    " draws the same."
)


@dataclass(frozen=True)
class Seen:
    """What a posted glance showed: the report version it was made for and its counts, what
    the next glance says is new against (kept in the glance step's payload). ``targets_title``
    names the list its targets were counted from ("Campus sites reached", "Servers reached"):
    a count of another list is not compared with it ("" in an older payload: not known)."""

    version: int
    alerts: int
    actors: int
    targets: int
    listed: int
    rules: int
    standing: str = "unknown"
    targets_title: str = ""

    def dump(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def load(cls, raw: object) -> Seen | None:
        """The counts a step's payload holds; None when it holds none to trust."""
        if not isinstance(raw, Mapping):
            return None
        numbers: dict[str, int] = {}
        for name in ("version", "alerts", "actors", "targets", "listed", "rules"):
            value = raw.get(name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                return None
            numbers[name] = value
        standing = raw.get("standing")
        title = raw.get("targets_title")
        return cls(
            **numbers,
            standing=standing if standing in g.ACTIVITY else "unknown",
            targets_title=title[:200] if isinstance(title, str) else "",
        )


def seen_of(report: m.IncidentReport, version: int) -> Seen:
    glance = g.glance_of(report)
    return Seen(
        version,
        glance.alerts,
        glance.actors,
        glance.targets,
        glance.listed,
        glance.rules,
        glance.standing,
        glance.shape.targets_title,
    )


def _when(at: object) -> str:
    return "not known" if at is None else ist_moment(at)  # type: ignore[arg-type]


def _table(head: list[str], row: list[str]) -> str:
    return render.row(*head) + "\n|" + "---|" * len(head) + "\n" + render.row(*row)


def status(glance: g.Glance) -> str:
    """What a person decides on first, as a table of one row."""
    return _table(
        ["Severity", "Call", "Activity", "Dwell (first to last alert)"],
        [escape(v) for v in (glance.severity, glance.call, glance.activity, glance.dwell)],
    )


def numbers(glance: g.Glance) -> str:
    """The numbers row, as a table of one row (always rendered, whatever Kibana does with the
    charts below)."""
    n, more, word = glance.targets, glance.targets_more, glance.targets_word
    targets = f"{g.more(n, more)} {word if n == 1 and not more else word + 's'}"
    return _table(
        [
            "Alerts",
            "Actors",
            "Targets",
            "On threat lists",
            f"First alert ({site.zone_label()})",
            f"Last alert ({site.zone_label()})",
            "Rules",
        ],
        [
            count(glance.alerts),
            g.more(glance.actors, glance.actors_more),
            targets,
            plural(glance.listed, "indicator"),
            _when(glance.first),
            _when(glance.last),
            g.more(glance.rules, glance.rules_more),
        ],
    )


def _changed(n: int, one: str, many: str) -> str | None:
    if n == 0:
        return None
    return f"{count(abs(n))} {'more' if n > 0 else 'fewer'} {one if abs(n) == 1 else many}"


def news(glance: g.Glance, before: Seen | None) -> str:
    """What changed since the glance this one replaces (empty when there was none). Targets are
    compared only when both were counted from the same list (sites with sites, never with the
    servers a device reached); a standing that was not known is not said to come back."""
    if before is None:
        return ""
    word = glance.targets_word
    if before.targets_title == glance.shape.targets_title:
        targets = _changed(glance.targets - before.targets, word, word + "s")
    elif before.targets_title:  # another list: said, not compared
        targets = f"targets now counted as {word}s" if glance.targets else "no target named now"
    else:  # an older glance that did not say which list
        targets = None
    said = [
        x
        for x in (
            _changed(glance.alerts - before.alerts, "alert", "alerts"),
            _changed(glance.actors - before.actors, "actor", "actors"),
            targets,
            _changed(
                glance.listed - before.listed,
                "indicator on threat lists",
                "indicators on threat lists",
            ),
            _changed(glance.rules - before.rules, "rule", "rules"),
        )
        if x is not None
    ]
    text = ", ".join(said) if said else "the same counts"
    if glance.standing != before.standing and glance.standing != "unknown":
        if glance.standing == "quiet":
            text += "; now quiet"
        else:
            text += "; still active" if before.standing == "unknown" else "; active again"
    return f"New since report version {before.version}: {text}."


def scope_of(report: m.IncidentReport, space: str) -> lens.Scope | None:
    """What the charts are over: from the first alert to the last, widened to when the alerts
    were made (the charts plot that time, which a rule's lookback or a late run puts after the
    events). None when the report cannot say (no alert time) or the incident ID or the space is
    not plain enough for a block (a chart is then left out, never the numbers)."""
    h = report.header
    if h.first_alert_at is None or h.last_alert_at is None:
        return None
    if not lens.SAFE.fullmatch(h.incident_id) or not lens.SPACE.fullmatch(space):
        return None
    first = min(t for t in (h.first_alert_at, h.first_detected_at) if t is not None)
    last = max(t for t in (h.last_alert_at, h.last_detected_at) if t is not None)
    return lens.Scope(space, h.incident_id, first, last)


def listing(
    glance: g.Glance, field: str, items: tuple[g.Slice, ...], *, charted: bool = True
) -> str:
    """A short list from the report in place of a chart: one item, a field most of the case's
    alerts do not hold, or items a chart over one field would not all hold (``charted`` False:
    servers named by address and by name)."""
    lines: list[str] = []
    if not glance.drawable(field):
        lines.append(
            f"Listed from ARGUS's report: most of the case's alerts do not hold {fence(field)},"
            " so a live chart would be empty."
        )
    elif not charted:
        lines.append(
            "Listed from ARGUS's report: a live chart splits on one field, and these are not all"
            f" named in {fence(field)}."
        )
    for s in items[:LISTED_AT]:
        said = [] if s.value is None else [plural(s.value, "alert")]
        if s.note:
            said.append(render.say(s.note, 200))
        lines.append(f"- {render.val(s.label)}" + (": " + "; ".join(said) if said else ""))
    if len(items) > LISTED_AT:
        lines.append(f"- and {len(items) - LISTED_AT} more (the one-page dashboard lists them)")
    return "\n".join(lines)


def panels(glance: g.Glance, scope: lens.Scope | None) -> list[tuple[str, str]]:
    """(caption, content) for each panel this case has, in the order they are shown: a live
    chart, or a list where a chart would hold one bar or a field the alerts lack. Without a
    scope (no chart can be drawn) only the lists are shown."""
    shape = glance.shape
    out: list[tuple[str, str]] = []
    if scope is not None and (glance.layers or glance.alerts):
        out.append(("Alerts over time, by rule", lens.block(scope, lens.alerts_over_time(scope))))
    for field, title, items, charted in (
        (shape.actors_field, shape.actors_title, glance.top_actors, True),
        (shape.targets_field, shape.targets_title, glance.top_targets, glance.targets_charted),
    ):
        if field is None or not items:
            continue
        live = charted and len(items) >= g.BARS_FROM and glance.drawable(field)
        if scope is not None and live:
            out.append((title, lens.block(scope, lens.top_values(scope, title, field))))
        else:
            out.append((title, listing(glance, field, items, charted=charted)))
    if scope is not None and glance.rule_rows:
        out.append(("Rules that raised the alerts", lens.block(scope, lens.rules_table(scope))))
    return out


def _caption(glance: g.Glance, ident: str, tagged: int | None, left_out: int) -> str:
    """What the live charts count: only the alerts attached to the case and tagged with its ID,
    which may be fewer than the case's own (an attach takes at most a set number, and leaves
    closed alerts out while Sync alerts is on: those are said, never counted)."""
    where = (
        f"Kibana draws them live from the alerts attached to this case and tagged {fence(ident)}."
    )
    if tagged is None:
        return f"The charts count the tagged alerts: {where}"
    of = f"of {count(glance.alerts)}"
    if left_out:
        of += f"; {count(left_out)} more were left unattached while Sync alerts was on"
    if tagged == 0:  # only alerts an attach left out: none is known to be tagged yet
        return f"The charts count the tagged alerts, none yet ({of}): {where}"
    return f"The charts count the {count(tagged)} tagged alerts ({of}): {where}"


def _sections(
    report: m.IncidentReport, space: str, tagged: int | None, left_out: int = 0
) -> tuple[g.Glance, list[str], list[str]]:
    """The glance, and the comment's parts before and after the line that says what is new."""
    glance = g.glance_of(report)
    scope = scope_of(report, space)
    ident = report.header.incident_id
    head = [INTRO, status(glance), numbers(glance)]
    if scope is None:
        note = "No alert time is known, so no live chart is drawn."
    elif tagged == 0 and not left_out:
        note = "No alert is attached to this case yet, so no live chart is drawn."
        scope = None
    else:  # the charts are live: an alert an attach takes later is drawn without an edit
        note = _caption(glance, ident, tagged, left_out)
    shown = panels(glance, scope)
    while True:
        tail = [note, *(f"**{caption}**\n\n{content}" for caption, content in shown)]
        if utf16_len("\n\n".join([*head, *tail])) <= FIT - NEWS_ROOM or not shown:
            return glance, head, tail
        shown.pop()


def core(
    report: m.IncidentReport, space: str, *, tagged: int | None = None, left_out: int = 0
) -> str:
    """Everything under the heading but the line that says what is new: two reports that say the
    same give the same core, so its hash tells a round whether the glance moved."""
    _, head, tail = _sections(report, space, tagged, left_out)
    return "\n\n".join([*head, *tail])


def comment(
    report: m.IncidentReport,
    space: str,
    *,
    tagged: int | None = None,
    left_out: int = 0,
    since: Seen | None = None,
) -> tuple[str, str]:
    """(the whole comment, its core). ``tagged``: the alerts attached and tagged (the charts
    count only those); ``left_out``: the case's alerts an attach left out (closed while Sync
    alerts was on), not among them; ``since``: what the glance this one replaces showed."""
    glance, head, tail = _sections(report, space, tagged, left_out)
    said = news(glance, since)
    text = "\n\n".join([*head, *([said] if said else []), *tail])
    return f"## {TITLE}\n\n{text}", "\n\n".join([*head, *tail])


def unit(
    report: m.IncidentReport, space: str, *, tagged: int | None = None, left_out: int = 0
) -> str:
    """The glance's unit: the hash of its core."""
    return unit_hash(core(report, space, tagged=tagged, left_out=left_out))


def payload(report: m.IncidentReport, version: int | None, since: Seen | None) -> dict[str, Any]:
    """What a glance step keeps besides its text: what it shows and what it compared with."""
    if version is None:
        return {}
    return {
        "seen": seen_of(report, version).dump(),
        "since": None if since is None else since.dump(),
    }


def steps(
    report: m.IncidentReport,
    space: str,
    *,
    tagged: int | None = None,
    left_out: int = 0,
    version: int | None = None,
) -> list[Step]:
    """The step that posts the glance the first time: one comment by the visualiser."""
    whole, said = comment(report, space, tagged=tagged, left_out=left_out)
    return [
        Step(
            KEY,
            "comment",
            Author.VISUALISER,
            PART,
            text=whole,
            payload=payload(report, version, None),
            units=(unit_hash(said),),
        )
    ]
