"""The one-page picture dashboard of an incident (AR10, D-250), drawn by code.

The same four panels as the Visualiser's charts in the Kibana case (:mod:`argus.caseteam.visual`),
made from the same :class:`argus.incident.glance.Glance` with reportlab's own graphics (no new
dependency): alerts per day stacked by rule, the top actors, the targets, and the table of rules,
under a row of numbers. It is the second part of the incident PDF (after the title block) and,
on its own page, the file ``<incident>_dashboard.pdf`` in the case's Files tab.

Rendered from the stored report only: no database, no network, no model. The same report gives the
same bytes (reportlab's ``invariant`` mode). Colours are the dataviz palette's categorical order,
light surface; a series is never identified by colour alone (the legend names it, and the numbers
are in the table beside it). Names of people are never drawn.
"""

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
    """Alerts per IST day, stacked by rule (the top rules, then "Other rules")."""
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
        (_hex(shade), _cut(layer.name, 44)) for shade, layer in zip(shades, layers, strict=True)
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
    chart.data = [[s.value for s in ordered]]
    chart.categoryAxis.categoryNames = [_cut(s.label) for s in ordered]
    chart.categoryAxis.labels.boxAnchor = "e"
    chart.categoryAxis.labels.dx = -3
    _axis_style(chart.categoryAxis, sans)
    chart.valueAxis.valueMin = 0
    peak = max(s.value for s in items)
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


def _numbers(glance: g.Glance, st: files.Styles, width: float) -> Table:
    cells = [
        (count(glance.alerts), _noun(glance.alerts, "alert")),
        (g.more(glance.actors, glance.actors_more), _noun(glance.actors, "actor")),
        (str(glance.targets), f"{_noun(glance.targets, glance.targets_word)} reached"),
        (str(glance.listed), "on threat lists"),
        (g.more(glance.rules, glance.rules_more), _noun(glance.rules, "rule")),
    ]
    row = [[files._p(n, st["BIG"]), files._p(label, st["SM"])] for n, label in cells]
    table = Table([row], colWidths=[width / len(cells)] * len(cells))
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


def _rules(glance: g.Glance, st: files.Styles, width: float) -> Flowable:
    if not glance.rule_rows:
        return files._p("No rule is named.", st["SM"])
    rows = [["Rule", "Alerts"]]
    rows += [[_cut(r.label, 70), count(r.value)] for r in glance.rule_rows[:12]]
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
        f"Alerts per day, by rule ({site.zone_label()})", alerts_over_time(glance, cell - 12, h), st
    )
    actors = _panel(
        shape.actors_title + " (alerts)",
        top_bars(glance.top_actors, cell - 12, h, "The case names no actor to draw."),
        st,
    )
    targets = _panel(
        shape.targets_title + " (alerts)",
        top_bars(glance.top_targets, cell - 12, h, "The case names no target to draw."),
        st,
    )
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
    return [_numbers(glance, st, width), Spacer(1, 3), *when, Spacer(1, 4), grid]


def section(report: m.IncidentReport, width: float) -> list[Flowable]:
    """The dashboard as the second part of the incident PDF, after its title block."""
    st = _styles()
    return [
        files._p("Incident at a glance", st["H2"]),
        *panels(report, width),
    ]


def pdf(report: m.IncidentReport) -> bytes:
    """The dashboard alone, on one A4 page: the file ``<incident>_dashboard.pdf``."""
    sans, _, _ = files._fonts()
    st = _styles()
    width = A4[0] - 36 * mm
    h = report.header
    story: list[Flowable] = [
        files._p(f"Incident at a glance: {h.incident_id}", st["H1"]),
        files._p(h.title.split(" · ", 1)[-1], st["H2"]),
        *panels(report, width),
        Spacer(1, 6),
        files._p(
            "Drawn by ARGUS from the incident report's stored figures. The same charts are live"
            f" in the Kibana case, over the alerts tagged with the incident ID. Times are"
            f" {site.zone_label()}.",
            st["SM"],
        ),
    ]

    def footer(canvas: Any, doc: Any) -> None:
        canvas.saveState()
        canvas.setFont(sans, 7.5)
        canvas.setFillColor(_hex("#6b7280"))
        canvas.drawString(18 * mm, 10 * mm, files._shown(f"{h.incident_id} · {files.FOOTER}"))
        canvas.restoreState()

    buffer = io.BytesIO()
    template = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=18 * mm,
        title=files._shown(dashboard_title(report)),
        author="ARGUS",
        invariant=1,
    )
    template.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()
