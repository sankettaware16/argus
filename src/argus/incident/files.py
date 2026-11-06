"""The report's files: the incident report as a PDF, and the indicators and the affected devices
as CSV, in the layout of a hand-made incident case's files. The case team sends them to the Kibana
case's Files tab; a person downloads them from the case page.

Rendered from the stored report only, by code; the same report gives the same PDF (reportlab's
``invariant`` mode). Every value goes in as text: XML-escaped in the PDF, neutralised in the CSV (a
cell starting with ``=``, ``+``, ``-`` or ``@`` is prefixed so a spreadsheet never reads it as a
formula), and the CSV begins with a UTF-8 byte order mark. The font is DejaVu Sans when the machine
has it, else the Bitstream Vera that reportlab ships; a missing character is shown as ``?``."""

from __future__ import annotations

import csv
import io
from collections.abc import Callable, Sequence
from functools import lru_cache
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFError, TTFont
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from argus import site
from argus.cases.blocklist import BOM, safe_cell
from argus.incident import model as m
from argus.incident.words import day_label, ist_day, ist_moment

INDICATOR_COLUMNS = ("indicator", "type", "role", "evidence")
AFFECTED_COLUMNS = ("device_ip", "domain", "days_with_alert", "first_day_ist", "last_day_ist")
ACCOUNT_COLUMNS = (
    "account",
    "device_ip",
    "state",
    "sign_ins",
    "failed",
    "first_seen_ist",
    "last_seen_ist",
    "days",
    "browser",
)
ROLE_SHORT = {"actor": "actor", "c2": "command-and-control", "indicator": "indicator"}
DEJAVU = Path("/usr/share/fonts/truetype/dejavu")
FOOTER = "TLP:AMBER (internal: contains {noun} addresses)"  # ``site.say`` tokens
DEVICES_SHOWN = 25
ACCOUNTS_SHOWN = 10  # accounts of one device in the PDF's table
ACCOUNT_ROWS = 40  # rows of that table
INDICATORS_SHOWN = 60
CODE_WIDTH = 110  # characters of a query line in the PDF, then it wraps
LANGUAGE = {"kql": "KQL", "esql": "ES|QL"}
STATUS = {"kept": "Kept", "ruled_out": "Ruled out", "open": "Open"}
Styles = dict[str, ParagraphStyle]


def pdf_name(report: m.IncidentReport) -> str:
    return f"{report.header.incident_id}_Incident_Report.pdf"


def dashboard_name(report: m.IncidentReport) -> str:
    """The one-page picture dashboard, also the PDF's second part."""
    return f"{report.header.incident_id}_dashboard.pdf"


def indicators_name(report: m.IncidentReport) -> str:
    return f"{report.header.incident_id}_indicators.csv"


def affected_name(report: m.IncidentReport) -> str:
    return f"{report.header.incident_id}_affected_devices.csv"


def accounts_name(report: m.IncidentReport) -> str:
    return f"{report.header.incident_id}_affected_accounts.csv"


def has_accounts(report: m.IncidentReport) -> bool:
    """Whether the report names an account that signed in from a device."""
    return any(d.accounts for d in report.users.devices)


def _csv(columns: Sequence[str], rows: Sequence[Sequence[object]]) -> str:
    out = io.StringIO()
    out.write(BOM)
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(columns)
    for row in rows:
        writer.writerow([safe_cell(str(cell)) for cell in row])
    return out.getvalue()


def indicators_csv(report: m.IncidentReport) -> str:
    """One row for each indicator of the case, as the case holds them."""
    return _csv(
        INDICATOR_COLUMNS,
        [(i.value, i.kind, ROLE_SHORT.get(i.role, i.role), i.evidence) for i in report.indicators],
    )


def affected_csv(report: m.IncidentReport) -> str:
    """One row for each affected device (an internal address): the name it reached, the days with
    an alert and the first and last day, in IST."""
    return _csv(
        AFFECTED_COLUMNS,
        [
            (
                a.value,
                a.label or "",
                a.days,
                "" if a.first_seen is None else ist_day(a.first_seen),
                "" if a.last_seen is None else ist_day(a.last_seen),
            )
            for a in report.assets
            if a.kind == "device"
        ],
    )


def accounts_csv(report: m.IncidentReport) -> str:
    """One row for each account that signed in from an affected device: the probable
    users of a device, or those seen so far, with the device's state ("likely", "possible", ...),
    the sign-ins and failures, the first and last time (IST) and the browser. Personal data: the
    files route gives it only to an account that may read the logs. A lead, not proof."""
    rows: list[Sequence[object]] = []
    for d in report.users.devices:
        for a in d.accounts:
            rows.append(
                (
                    a.name, a.device, d.state, a.signins, a.failed, ist_moment(a.first_seen),
                    ist_moment(a.last_seen), a.days, "; ".join(a.browsers),
                )
            )  # fmt: skip
    return _csv(ACCOUNT_COLUMNS, rows)


@lru_cache(maxsize=1)
def _fonts() -> tuple[str, str, str]:
    """(regular, bold, mono) font names, registered once."""
    try:
        regular, bold = DEJAVU / "DejaVuSans.ttf", DEJAVU / "DejaVuSans-Bold.ttf"
        if not (regular.is_file() and bold.is_file()):
            raise OSError("DejaVu is not installed")
        pdfmetrics.registerFont(TTFont("ArgusSans", str(regular)))
        pdfmetrics.registerFont(TTFont("ArgusSansBold", str(bold)))
    except (OSError, TTFError):
        import reportlab

        base = Path(reportlab.__file__).parent / "fonts"
        pdfmetrics.registerFont(TTFont("ArgusSans", str(base / "Vera.ttf")))
        pdfmetrics.registerFont(TTFont("ArgusSansBold", str(base / "VeraBd.ttf")))
    pdfmetrics.registerFontFamily(
        "ArgusSans",
        normal="ArgusSans",
        bold="ArgusSansBold",
        italic="ArgusSans",
        boldItalic="ArgusSansBold",
    )
    return "ArgusSans", "ArgusSansBold", "Courier"


def _shown(text: str, mono: bool = False) -> str:
    """Text the PDF can draw: control characters dropped, a character the font lacks a ``?``."""
    face = getattr(pdfmetrics.getFont("ArgusSans"), "face", None)
    cmap = getattr(face, "charToGlyph", None)
    out = []
    for ch in text:
        if ch in "\n\t":
            out.append(" ")
        elif not ch.isprintable():
            continue
        elif (mono and ord(ch) > 255) or (not mono and cmap is not None and ord(ch) not in cmap):
            out.append("?")
        else:
            out.append(ch)
    return "".join(out)


def _styles() -> Styles:
    sans, bold, mono = _fonts()
    base = getSampleStyleSheet()
    ink = colors.HexColor("#1f2937")
    grey = colors.HexColor("#4b5563")
    p = ParagraphStyle(
        "P", parent=base["BodyText"], fontName=sans, fontSize=9, leading=12.5, alignment=TA_LEFT
    )
    cell = ParagraphStyle("CELL", parent=p, fontSize=8, leading=10.5)
    return {
        "H1": ParagraphStyle(
            "H1", parent=base["Heading1"], fontName=bold, fontSize=16, spaceAfter=6, textColor=ink
        ),
        "H2": ParagraphStyle(
            "H2",
            parent=base["Heading2"],
            fontName=bold,
            fontSize=12,
            spaceBefore=10,
            spaceAfter=4,
            textColor=ink,
        ),
        "P": p,
        "B": ParagraphStyle("B", parent=p, fontName=bold),
        "SM": ParagraphStyle("SM", parent=p, fontSize=8, leading=10.5, textColor=grey),
        "CODE": ParagraphStyle(
            "CODE",
            parent=p,
            fontName=mono,
            fontSize=7.5,
            leading=10,
            backColor=colors.HexColor("#f3f4f6"),
            borderPadding=4,
        ),
        "CELL": cell,
        "CELLB": ParagraphStyle("CELLB", parent=cell, fontName=bold),
    }


def _p(text: str, style: ParagraphStyle) -> Paragraph:
    return Paragraph(escape(_shown(text)), style)


def _table(
    rows: Sequence[Sequence[str]], widths: Sequence[float], st: Styles, head: bool = True
) -> Table:
    data = [
        [_p(str(c), st["CELLB"] if head and i == 0 else st["CELL"]) for c in r]
        for i, r in enumerate(rows)
    ]
    table = Table(data, colWidths=list(widths), repeatRows=1 if head else 0)
    style = [
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d1d5db")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]
    if head:
        style.append(("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef2f7")))
    table.setStyle(TableStyle(style))
    return table


def _code(text: str, st: Styles) -> Paragraph:
    """A query as a block: wrapped at :data:`CODE_WIDTH` so a long line never leaves the page."""
    shown = _shown(text, mono=True)
    wrapped = "\n".join(shown[i : i + CODE_WIDTH] for i in range(0, len(shown), CODE_WIDTH))
    return Paragraph(escape(wrapped).replace("\n", "<br/>"), st["CODE"])


def _opt(at: Any, fmt: Any, empty: str = "-") -> str:
    return empty if at is None else str(fmt(at))


def _head(report: m.IncidentReport, st: Styles, width: float) -> list[Any]:
    h, v = report.header, report.verdict
    sure = ""
    if v.confidence is not None:
        sure = f" (confidence {v.confidence_words}, {round(v.confidence * 100)}%)"
    rows = [
        ["Incident ID", h.incident_id],
        ["ARGUS case", f"{h.case_number} ({h.case_state}; {h.opened_in})"],
        ["Severity", h.severity.capitalize()],
        ["Verdict", f"{v.words.capitalize()}{sure} — {v.source}"],
        ["Still going on", report.summary.standing_words],
        ["First alert", _opt(h.first_alert_at, ist_moment)],
        ["Latest alert", _opt(h.last_alert_at, ist_moment)],
        ["Detected by", h.detected_by],
        ["Investigated by", "ARGUS (automatic, read-only: it queried nothing for this report)"],
        ["Report written", ist_moment(report.meta.as_at)],
    ]
    return [
        _p(f"Incident Report {h.incident_id}", st["H1"]),
        _p(h.title.split(" · ", 1)[-1], st["H2"]),
        _table(rows, [38 * mm, width - 38 * mm], st, head=False),
    ]


def _summary(report: m.IncidentReport, st: Styles) -> list[Any]:
    out: list[Any] = [_p("1. Summary", st["H2"])]
    words = report.summary.prose or report.summary.sentences
    for sentence in words:
        out += [_p(sentence.text, st["P"]), Spacer(1, 2)]
    if report.summary.prose:
        out.append(
            _p(
                "The wording above was written by a model from the report's verified facts and "
                "checked by ARGUS; the facts themselves are in this report.",
                st["SM"],
            )
        )
    if report.summary.notice is not None:
        out.append(_p(report.summary.notice.line, st["P"]))
    said = {sentence.text for sentence in words}
    out += [_p(s.text, st["SM"]) for s in report.verdict.sentences if s.text not in said]
    return out


def _timeline(report: m.IncidentReport, st: Styles, width: float) -> list[Any]:
    t = report.timeline
    out: list[Any] = [_p(f"2. Timeline ({site.zone_label()})", st["H2"])]
    if t.dwell_words:
        out.append(_p(f"Dwell time: {t.dwell_words}.", st["P"]))
    if t.days:
        rows = [[f"Date ({site.zone_label()})", *t.columns, "Total"]]
        for d in t.days:
            rows.append([day_label(d.day), *[str(c) if c else "-" for c in d.counts], str(d.total)])
        first = 32 * mm
        rest = (width - first) / (len(rows[0]) - 1)
        out.append(_table(rows, [first] + [rest] * (len(rows[0]) - 1), st))
    out += [_p(p.sentence.text, st["SM"]) for p in t.phases]
    out += [_p(n.text, st["SM"]) for n in t.notes]
    if report.users.signins:
        out.append(
            _p(
                "Sign-ins from the affected devices, as context (one line for each account and"
                " day, from the SSO logs):",
                st["SM"],
            )
        )
        out += [_p(f"{ist_moment(s.at)}: {s.text}", st["SM"]) for s in report.users.signins]
    return out


def _actors(report: m.IncidentReport, st: Styles, width: float) -> list[Any]:
    out: list[Any] = [_p("3. Actors and roles", st["H2"])]
    if not report.actors:
        return [*out, _p("The case names no actor.", st["P"])]
    rows = [["Actor", "Role", "Network / country", "User agents", "Alerts"]]
    for a in report.actors:
        where = " / ".join(x for x in (a.network, a.country) if x) or "-"
        rows.append([a.value, a.role, where, "; ".join(a.user_agents) or "-", str(a.alerts)])
    out.append(_table(rows, [34 * mm, 24 * mm, 40 * mm, width - 112 * mm, 14 * mm], st))
    out += [_p(f"{a.value}: {a.role_words}", st["SM"]) for a in report.actors if a.role_words]
    return out


def _indicators(report: m.IncidentReport, st: Styles, width: float) -> list[Any]:
    out: list[Any] = [_p("4. Indicators", st["H2"])]
    if not report.indicators:
        return [*out, _p("The case holds no indicator.", st["P"])]
    rows = [["Indicator", "Type", "Role", "Evidence"]]
    for i in report.indicators[:INDICATORS_SHOWN]:
        rows.append([i.value, i.kind, ROLE_SHORT.get(i.role, i.role), i.evidence])
    out.append(_table(rows, [42 * mm, 13 * mm, 28 * mm, width - 83 * mm], st))
    if report.indicators_total > INDICATORS_SHOWN:
        more = report.indicators_total - INDICATORS_SHOWN
        out.append(_p(f"… and {more} more in the indicators CSV.", st["SM"]))
    return out


def _evidence(report: m.IncidentReport, st: Styles) -> list[Any]:
    out: list[Any] = [_p("5. Evidence", st["H2"])]
    facts = {f.id: f for f in report.facts}
    for line in report.evidence:
        q = line.query
        ran = "" if line.at is None else f", run {ist_moment(line.at)}"
        out.append(
            KeepTogether(
                [
                    _p(f"{line.id} · {line.title}", st["B"]),
                    _p(facts[line.fact].text, st["P"]),
                    _p(
                        f"Source: {line.source}. Check: {q.template}{ran}. Status: {line.status}.",
                        st["SM"],
                    ),
                    _p(f"Query ({LANGUAGE[q.language]}) on {q.index}:", st["SM"]),
                    _code(q.text, st),
                    Spacer(1, 4),
                ]
            )
        )
    return out


def _hypotheses(report: m.IncidentReport, st: Styles, width: float) -> list[Any]:
    rows = [["Hypothesis", "Result", "Why"]]
    for hy in report.hypotheses:
        rows.append([hy.name, STATUS[hy.status], " ".join(w.text for w in hy.why[:3])])
    table = _table(rows, [55 * mm, 20 * mm, width - 75 * mm], st)
    return [_p("6. Hypotheses", st["H2"]), table]


def _assets(report: m.IncidentReport, st: Styles) -> list[Any]:
    out: list[Any] = [_p("7. Affected assets", st["H2"])]
    devices = [a for a in report.assets if a.kind == "device"]
    others = [a for a in report.assets if a.kind != "device"]
    if devices:
        out.append(
            _p(
                f"From the alerts; days counts {site.zone_label()} days with an alert."
                " The full list of devices is the affected-devices CSV.",
                st["SM"],
            )
        )
        rows = [["Device", "Reached", "Days", "First", "Last"]]
        for a in devices[:DEVICES_SHOWN]:
            rows.append(
                [
                    a.value,
                    a.label or "-",
                    str(a.days),
                    _opt(a.first_seen, ist_day),
                    _opt(a.last_seen, ist_day),
                ]
            )
        out.append(_table(rows, [32 * mm, 52 * mm, 14 * mm, 26 * mm, 26 * mm], st))
        if len(devices) > DEVICES_SHOWN:
            out.append(_p(f"… and {len(devices) - DEVICES_SHOWN} more in the CSV.", st["SM"]))
    if others:
        rows = [["Kind", "Asset", "Where", "Alerts"]]
        rows += [[a.kind, a.value, a.label or "-", str(a.alerts)] for a in others[:40]]
        out.append(_table(rows, [24 * mm, 70 * mm, A4[0] - 36 * mm - 108 * mm, 14 * mm], st))
    if not devices and not others:
        out.append(_p("The case names no affected asset.", st["P"]))
    out += _accounts(report, st)
    return out


def _accounts(report: m.IncidentReport, st: Styles) -> list[Any]:
    """Accounts that signed in from the affected devices: a lead, not proof."""
    users = report.users
    if not users.devices:
        return []
    out: list[Any] = [_p("Accounts that signed in from the affected devices", st["B"])]
    out.append(_p(f"{users.lead} From the SSO logs; the full list is the accounts CSV.", st["SM"]))
    zone = site.zone_label()
    rows = [
        ["Account", "Device", "State", "Sign-ins", f"First ({zone})", f"Last ({zone})", "Browser"]
    ]
    for d in users.devices:
        for a in d.accounts[:ACCOUNTS_SHOWN]:
            rows.append(
                [
                    a.name, a.device, d.state.replace("_", " "), str(a.signins),
                    ist_moment(a.first_seen), ist_moment(a.last_seen), "; ".join(a.browsers) or "-",
                ]
            )  # fmt: skip
    if len(rows) > 1:
        widths = [26 * mm, 24 * mm, 17 * mm, 14 * mm, 31 * mm, 31 * mm, 31 * mm]
        out.append(_table(rows[: ACCOUNT_ROWS + 1], widths, st))
        if len(rows) - 1 > ACCOUNT_ROWS:
            out.append(
                _p(f"… and {len(rows) - 1 - ACCOUNT_ROWS} more in the accounts CSV.", st["SM"])
            )
    out += [_p(d.sentence.text, st["SM"]) for d in users.devices if not d.accounts][:30]
    return out


def _actions(report: m.IncidentReport, st: Styles, width: float) -> list[Any]:
    out: list[Any] = [_p("8. Recommended actions", st["H2"])]
    a = report.actions
    if a.lines:
        rows = [["#", "Action", "Owner", "Status"]]
        for n, line in enumerate(a.lines, 1):
            state = line.state.replace("_", " ").capitalize()
            rows.append([str(n), f"{line.title}. {line.say}", line.owner, state])
        out.append(_table(rows, [8 * mm, width - 68 * mm, 32 * mm, 28 * mm], st))
    if a.note:
        out.append(_p(a.note, st["P"]))
    if a.close_when is not None:
        out += [Spacer(1, 3), _p(a.close_when.text, st["P"])]
    return out


def _queries(report: m.IncidentReport, st: Styles) -> list[Any]:
    out: list[Any] = [
        _p("9. Queries to verify (read-only; the time range is set in the link)", st["H2"])
    ]
    for q in report.queries:
        label = f"{q.template} · {q.index} ({LANGUAGE[q.language]})"
        out.append(KeepTogether([_p(label, st["B"]), _code(q.text, st), Spacer(1, 5)]))
    return out


def _limits(report: m.IncidentReport, st: Styles) -> list[Any]:
    out: list[Any] = [_p("10. Scope and limits", st["H2"])]
    out += [_p(s.text, st["P"]) for s in report.out_of_scope]
    out += [_p(f"Limit: {limit}.", st["SM"]) for limit in report.meta.limits]
    return out


def pdf(report: m.IncidentReport) -> bytes:
    """The incident report as a PDF (A4), with the parts of the hand-made one: summary, timeline,
    actors, indicators, evidence, hypotheses, affected assets, actions, queries, limits."""
    from argus.incident import dashboard  # borrows this module's fonts and styles: no cycle

    st = _styles()
    width = A4[0] - 36 * mm
    story: list[Any] = [
        *_head(report, st, width),
        *dashboard.section(report, width),
        *_summary(report, st),
        *_timeline(report, st, width),
        *_actors(report, st, width),
        *_indicators(report, st, width),
        *_evidence(report, st),
        *_hypotheses(report, st, width),
        *_assets(report, st),
        *_actions(report, st, width),
        *_queries(report, st),
        *_limits(report, st),
    ]
    ident = report.header.incident_id
    footer = page_footer(report)
    buffer = io.BytesIO()
    template = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=18 * mm,
        title=_shown(f"{ident} incident report"),
        author=pdf_author(),
        invariant=1,
    )
    template.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()


def footer_text(report: m.IncidentReport) -> str:
    """The line at the foot of every page of both PDFs: the incident, who made it and its
    handling mark, in the site's words (never a ``{token}``)."""
    org = site.organisation()
    return _shown(
        f"{report.header.incident_id} · {org.short_name}, {org.name} · {site.say(FOOTER)}"
    )


def pdf_author() -> str:
    org = site.organisation()
    return f"{org.short_name} {org.name} (ARGUS)"


def page_footer(report: m.IncidentReport) -> Callable[[Any, Any], None]:
    """What reportlab draws on each page: :func:`footer_text` on the left, the page on the right."""
    sans, _, _ = _fonts()
    line = footer_text(report)

    def footer(canvas: Any, doc: Any) -> None:
        canvas.saveState()
        canvas.setFont(sans, 7.5)
        canvas.setFillColor(colors.HexColor("#6b7280"))
        canvas.drawString(18 * mm, 10 * mm, line)
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()

    return footer


def bundle(report: m.IncidentReport) -> dict[str, bytes]:
    """The files by name: the PDF, the one-page dashboard, the indicators CSV and the
    affected devices CSV, and the accounts CSV when the report names an account."""
    from argus.incident import dashboard

    made = {
        pdf_name(report): pdf(report),
        dashboard_name(report): dashboard.pdf(report),
        indicators_name(report): indicators_csv(report).encode("utf-8"),
        affected_name(report): affected_csv(report).encode("utf-8"),
    }
    if has_accounts(report):
        made[accounts_name(report)] = accounts_csv(report).encode("utf-8")
    return made
