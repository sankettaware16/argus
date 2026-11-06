"""The one-page picture dashboard of an incident, drawn by code.

The same four panels as the Visualiser's charts (:mod:`argus.caseteam.visual`), made from the same
:class:`argus.incident.glance.Glance` with reportlab's own graphics: alerts per day (per week for
a long case) stacked by rule, every day from the first alert to the last; the top actors and the
targets, as bars from two counted items up and as a short list otherwise; and the table of rules.
Above them, what a person decides on first (severity, the call, active or quiet, dwell) and a row
of numbers. It is the second part of the incident PDF and, alone, the one-page file
``<incident>_dashboard.pdf`` with the same foot. Rendered from the stored report only; the same
report gives the same bytes. A series is never identified by colour alone, and names of people
are never drawn."""

from __future__ import annotations

import io
from collections.abc import Sequence
from math import ceil, log10
from typing import Any

from reportlab.graphics.charts.barcharts import HorizontalBarChart, VerticalBarChart
from reportlab.graphics.charts.legends import Legend
from reportlab.graphics.shapes import Drawing, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import Flowable, SimpleDocTemplate, Spacer, Table, TableStyle

from argus import site
from argus.incident import files
from argus.incident import glance as g
from argus.incident import model as m
from argus.incident.words import count, day_label, ist_moment

SERIES = ("#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4")  # categorical slots 1 to 5
OTHER = "#898781"  # "Other rules": the muted ink, not a series colour
INK = "#0b0b0b"
MUTED = "#52514e"
GRID = "#e1e0d9"
AXIS = "#c3c2b7"
LABEL_AT = 30  # characters of a bar's label before it is cut
LIST_LABEL_AT = 36  # and of a list's (two lines of its column)
LIST_ROWS = 6  # rows of a list before "and N more": the page stays one page
RULES_SHOWN = 8  # and of the rules table
TITLE_AT = 120  # characters of the case's title under the heading (two lines)
MAX_DAYS_LABELLED = 12


def _styles() -> files.Styles:
    """The report's paragraph styles and one more: the big figure of the numbers row."""
    st = files._styles()
    _, bold, _ = files._fonts()
    st["BIG"] = ParagraphStyle(
        "BIG", parent=st["P"], fontName=bold, fontSize=15, leading=18, alignment=TA_LEFT
    )
    return st


def dashboard_title(report: m.IncidentReport) -> str:
    return f"{report.header.incident_id} dashboard"


def _hex(value: str) -> Any:
    return colors.HexColor(value)


def _cut(text: str, limit: int = LABEL_AT) -> str:
    text = files._shown(text)
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _nice_step(peak: int) -> int:
    """A whole-number axis step (1, 2, 5, 10, ...) giving about five intervals."""
    raw = max(peak, 1) / 5
    unit = 10 ** int(log10(raw)) if raw >= 1 else 1
    for mult in (1, 2, 5, 10):
        if raw <= unit * mult:
            return int(unit * mult)
    return int(unit * 10)


def _empty(width: float, height: float, why: str) -> Drawing:
    sans, _, _ = files._fonts()
    d = Drawing(width, height)
    d.add(
        String(
            width / 2,
            height / 2,
            why,
            textAnchor="middle",
            fontName=sans,
            fontSize=8,
            fillColor=_hex(MUTED),
        )
    )
    return d


def _axis_style(axis: Any, sans: str, size: float = 6.5) -> None:
    axis.labels.fontName = sans
    axis.labels.fontSize = size
    axis.labels.fillColor = _hex(MUTED)
    axis.strokeColor = _hex(AXIS)


def alerts_over_time(glance: g.Glance, width: float, height: float) -> Drawing:
    """Alerts per local day, stacked by rule (the top rules, then "Other rules")."""
    layers = [layer for layer in glance.layers if any(layer.values)]
    if not glance.days or not layers:
        return _empty(width, height, "No alert times to draw.")
    sans, _, _ = files._fonts()
    d = Drawing(width, height)
    legend_h = 14 + 9 * ((len(layers) + 1) // 2)
    chart = VerticalBarChart()
    chart.x, chart.y = 30, legend_h + 30
    chart.width, chart.height = width - 38, height - legend_h - 38
    chart.data = [list(layer.values) for layer in layers]
    step = max(1, ceil(len(glance.days) / MAX_DAYS_LABELLED))
    chart.categoryAxis.categoryNames = [
        files._shown(day_label(day)) if i % step == 0 else "" for i, day in enumerate(glance.days)
    ]
    chart.categoryAxis.style = "stacked"
    chart.categoryAxis.labels.angle = 30
    chart.categoryAxis.labels.boxAnchor = "ne"
    chart.categoryAxis.labels.dy = -2
    _axis_style(chart.categoryAxis, sans)
    peak = max(sum(layer.values[i] for layer in layers) for i in range(len(glance.days)))
    top = _nice_step(peak)
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueStep = top
    chart.valueAxis.valueMax = top * max(ceil(peak / top), 1)
    chart.valueAxis.labelTextFormat = "%d"
    chart.valueAxis.visibleGrid = True
    chart.valueAxis.gridStrokeColor = _hex(GRID)
    chart.valueAxis.gridStrokeWidth = 0.4
    _axis_style(chart.valueAxis, sans)
    chart.bars.strokeColor = colors.white  # a surface gap between the stacked segments
    chart.bars.strokeWidth = 0.6
    chart.groupSpacing = 3
    shades: list[str] = []
    for i, layer in enumerate(layers):
        shade = OTHER if layer.name == "Other rules" else SERIES[min(i, len(SERIES) - 1)]
        chart.bars[i].fillColor = _hex(shade)
        shades.append(shade)
    d.add(chart)
    legend = Legend()
    legend.x, legend.y = 4, legend_h - 2
    legend.fontName, legend.fontSize = sans, 6.5
    legend.fillColor = _hex(MUTED)
    legend.alignment = "right"
    legend.columnMaximum = (len(layers) + 1) // 2
    legend.deltax, legend.deltay, legend.dxTextSpace = (width - 8) / 2, 9, 4
    legend.boxAnchor = "nw"
    legend.dx = legend.dy = 6
    legend.strokeColor = None
    legend.colorNamePairs = [
        (_hex(shade), _cut(layer.name)) for shade, layer in zip(shades, layers, strict=True)
    ]
    d.add(legend)
    return d


def top_bars(items: Sequence[g.Slice], width: float, height: float, none: str) -> Drawing:
    """Horizontal bars, the biggest on top, each with its count at the end."""
    if not items:
        return _empty(width, height, none)
    sans, _, _ = files._fonts()
    d = Drawing(width, height)
    chart = HorizontalBarChart()
    left = 104
    chart.x, chart.y = left, 6
    chart.width, chart.height = width - left - 26, height - 12
    ordered = list(reversed(items))  # the first category is drawn at the bottom
    chart.data = [[s.value or 0 for s in ordered]]
    chart.categoryAxis.categoryNames = [_cut(s.label) for s in ordered]
    chart.categoryAxis.labels.boxAnchor = "e"
    chart.categoryAxis.labels.dx = -3
    _axis_style(chart.categoryAxis, sans)
    chart.valueAxis.valueMin = 0
    peak = max(s.value or 0 for s in items)
    step = _nice_step(peak)
    chart.valueAxis.valueMax = step * max(ceil(peak / step), 1)
    chart.valueAxis.valueStep = step
    chart.valueAxis.labelTextFormat = "%d"
    chart.valueAxis.visibleGrid = True
    chart.valueAxis.gridStrokeColor = _hex(GRID)
    chart.valueAxis.gridStrokeWidth = 0.4
    chart.valueAxis.visibleAxis = False
    chart.valueAxis.visibleTicks = False
    chart.valueAxis.labels.fontSize = 0.1  # the counts are on the bars: no second set of labels
    chart.valueAxis.labels.fontName = sans
    chart.bars[0].fillColor = _hex(SERIES[0])
    chart.bars[0].strokeColor = None
    band = chart.height / len(items)
    chart.useAbsolute = 1  # points, so one bar is not as thick as the panel
    chart.barWidth = max(min(0.7 * band, 14), 3)
    chart.groupSpacing = band - chart.barWidth
    chart.barLabelFormat = "%d"
    chart.barLabels.fontName = sans
    chart.barLabels.fontSize = 6.5
    chart.barLabels.fillColor = _hex(INK)
    chart.barLabels.boxAnchor = "w"
    chart.barLabels.dx = 3
    d.add(chart)
    return d


def _noun(n: int, word: str) -> str:
    return word if n == 1 else word + "s"


def _row_table(
    cells: Sequence[tuple[Flowable, Flowable]], width: float, shares: Sequence[float] = ()
) -> Table:
    widths = [width * x for x in shares] if shares else [width / len(cells)] * len(cells)
    table = Table([[[a, b] for a, b in cells]], colWidths=widths)
    table.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.4, _hex(AXIS)),
                ("INNERGRID", (0, 0), (-1, -1), 0.4, _hex(GRID)),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def status_row(glance: g.Glance, st: files.Styles, width: float) -> Table:
    """What a person decides on first: the severity, the call and whose it is, whether it is
    still going on, and how long it has lasted."""
    cells = [
        ("Severity", glance.severity),
        ("Call", glance.call),
        ("Activity", glance.activity),
        ("Dwell (first to last alert)", glance.dwell),
    ]
    made = [(files._p(k, st["SM"]), files._p(v, st["B"])) for k, v in cells]
    return _row_table(made, width, (0.16, 0.44, 0.16, 0.24))  # the call is the longest


def _numbers(glance: g.Glance, st: files.Styles, width: float) -> Table:
    cells = [
        (count(glance.alerts), _noun(glance.alerts, "alert")),
        (g.more(glance.actors, glance.actors_more), _noun(glance.actors, "actor")),
        (
            g.more(glance.targets, glance.targets_more),
            f"{_noun(glance.targets, glance.targets_word)} reached",
        ),
        (str(glance.listed), "on threat lists"),
        (g.more(glance.rules, glance.rules_more), _noun(glance.rules, "rule")),
    ]
    return _row_table([(files._p(n, st["BIG"]), files._p(k, st["SM"])) for n, k in cells], width)


def item_list(items: Sequence[g.Slice], st: files.Styles, width: float, none: str) -> Flowable:
    """A short labelled list, for a panel of one item or of items the report names without a
    count: the label, the alerts of the investigations naming it when the report counts them
    (an investigation's alerts may not all name it), and what the report says of it."""
    if not items:
        return files._p(none, st["SM"])
    counted = all(s.value is not None for s in items)
    noted = any(s.note for s in items)
    head = (
        ["Name"]
        + (["Alerts of its investigations"] if counted else [])
        + (["What ARGUS holds"] if noted else [])
    )
    rows = [head]
    for s in items[:LIST_ROWS]:
        row = [_cut(s.label, LIST_LABEL_AT)]
        if counted:
            row.append(count(s.value or 0))
        if noted:
            row.append(_cut(s.note, 48))
        rows.append(row)
    if len(items) > LIST_ROWS:
        rows.append([f"and {len(items) - LIST_ROWS} more"] + [""] * (len(head) - 1))
    if len(head) == 1:
        widths = [width]
    else:
        side = 84.0 if counted else 0.0  # its head, "Alerts of its investigations", in two lines
        rest = width - side
        widths = (
            [rest * 0.45 if noted else rest]
            + ([side] if counted else [])
            + ([rest * 0.55] if noted else [])
        )
    return files._table(rows, widths, st)


def _items(
    items: Sequence[g.Slice], st: files.Styles, width: float, height: float, none: str
) -> tuple[str, Flowable]:
    """A panel's caption ending and its body: bars from two counted items up, else a list (the
    items of counts that overlap are not counted: :func:`argus.incident.glance.counted`)."""
    if g.bars(items):
        return " (alerts of their investigations)", top_bars(items, width, height, none)
    return "", item_list(items, st, width, none)


def _rules(glance: g.Glance, st: files.Styles, width: float) -> Flowable:
    if not glance.rule_rows:
        return files._p("No rule is named.", st["SM"])
    rows = [["Rule", "Alerts"]]
    rows += [[_cut(r.label, 44), count(r.value or 0)] for r in glance.rule_rows[:RULES_SHOWN]]
    if len(glance.rule_rows) > RULES_SHOWN:
        rows.append([f"and {len(glance.rule_rows) - RULES_SHOWN} more", ""])
    return files._table(rows, [width - 44, 44], st)


def _panel(title: str, body: Flowable, st: files.Styles) -> list[Flowable]:
    return [files._p(title, st["B"]), Spacer(1, 2), body]


def panels(report: m.IncidentReport, width: float) -> list[Flowable]:
    """The numbers row and the four panels, as flowables of ``width`` points."""
    st = _styles()
    glance = g.glance_of(report)
    shape = glance.shape
    cell = (width - 6) / 2
    h = 168.0
    left = _panel(
        f"Alerts per {glance.bucket}, by rule ({site.zone_label()})",
        alerts_over_time(glance, cell - 12, h),
        st,
    )
    said, body = _items(glance.top_actors, st, cell - 12, h, "The case names no actor to draw.")
    actors = _panel(shape.actors_title + said, body, st)
    said, body = _items(glance.top_targets, st, cell - 12, h, "The case names no target to draw.")
    targets = _panel(shape.targets_title + said, body, st)
    rules = _panel("Rules that raised the alerts", _rules(glance, st, cell - 12), st)
    grid = Table([[left, actors], [targets, rules]], colWidths=[cell, cell])
    grid.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BOX", (0, 0), (-1, -1), 0.4, _hex(GRID)),
                ("INNERGRID", (0, 0), (-1, -1), 0.4, _hex(GRID)),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    when = []
    if glance.first is not None and glance.last is not None:
        when.append(files._p(f"{ist_moment(glance.first)} to {ist_moment(glance.last)}", st["SM"]))
    return [
        status_row(glance, st, width),
        Spacer(1, 3),
        _numbers(glance, st, width),
        Spacer(1, 3),
        *when,
        Spacer(1, 4),
        grid,
    ]


def section(report: m.IncidentReport, width: float) -> list[Flowable]:
    """The dashboard as the second part of the incident PDF, after its title block."""
    st = _styles()
    return [
        files._p("Incident at a glance", st["H2"]),
        *panels(report, width),
    ]


def pdf(report: m.IncidentReport) -> bytes:
    """The dashboard alone, on one A4 page: the file ``<incident>_dashboard.pdf``, with the same
    foot as the incident report's pages (the incident, the organisation, the handling mark, the
    page)."""
    st = _styles()
    width = A4[0] - 36 * mm
    h = report.header
    story: list[Flowable] = [
        files._p(f"Incident at a glance: {h.incident_id}", st["H1"]),
        files._p(_cut(h.title.split(" · ", 1)[-1], TITLE_AT), st["H2"]),
        *panels(report, width),
        Spacer(1, 6),
        files._p(
            "Drawn by ARGUS from the incident report's stored figures. The same charts are live"
            f" in the Kibana case, over the alerts tagged with the incident ID. Times are"
            f" {site.zone_label()}.",
            st["SM"],
        ),
    ]
    footer = files.page_footer(report)
    buffer = io.BytesIO()
    template = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=18 * mm,
        title=files._shown(dashboard_title(report)),
        author=files.pdf_author(),
        invariant=1,
    )
    template.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()
