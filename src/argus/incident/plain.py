"""The incident report as plain text for the terminal (``argus case report``). Every value is
shown with unprintable characters escaped, so a log value can never write to the operator's
terminal (the same rule as the other ``argus case`` commands)."""

from __future__ import annotations

from argus import site
from argus.incident import model as m
from argus.incident.words import day_label, ist_moment, times


def printable(value: object) -> str:
    return "".join(
        char if char.isprintable() else char.encode("unicode_escape").decode("ascii")
        for char in str(value)
    )


def lines(report: m.IncidentReport) -> list[str]:
    """The report's parts in order, one line each (queries and links in full)."""
    h, v, t = report.header, report.verdict, report.timeline
    facts = {f.id: f for f in report.facts}
    sure = (
        ""
        if v.confidence is None
        else f", confidence {v.confidence_words} ({round(v.confidence * 100)}%)"
    )
    out = [
        h.title,
        f"case {h.case_number} ({h.case_state}; {h.opened_in}), severity {h.severity}",
        f"verdict: {v.words}{sure}; by {v.source}",
        f"still going on: {report.summary.standing_words}",
        f"tags: {', '.join(h.tags)}",
        "",
        "SUMMARY",
    ]
    out += [f"  {s.text}" for s in (report.summary.prose or report.summary.sentences)]
    if report.summary.notice is not None:
        out.append(f"  {report.summary.notice.line}")
    out += ["", "VERDICT", *[f"  {s.text}" for s in v.sentences]]
    out += ["", f"TIMELINE ({site.zone_label()})"]
    if t.dwell_words:
        out.append(f"  dwell time: {t.dwell_words}")
    if t.columns:
        out.append("  date            " + "  ".join(c[:16] for c in t.columns))
        out += [f"  {day_label(d.day):<14}  " + "  ".join(str(c) for c in d.counts)
                + f"   (total {d.total})" for d in t.days]  # fmt: skip
    out += [f"  {p.sentence.text}" for p in t.phases]
    out += ["", "ACTORS"]
    out += [f"  {a.value} [{a.role}] {a.role_words}" for a in report.actors] or ["  none"]
    out += ["", f"AFFECTED ASSETS ({report.assets_total})"]
    out += [f"  {a.kind}: {a.value}" + (f" -> {a.label}" if a.label else "")
            + f" ({a.alerts} alerts, {a.days} days)"
            for a in report.assets[:25]] or ["  none"]  # fmt: skip
    if report.users.devices:
        out += [
            "",
            "ACCOUNTS THAT SIGNED IN FROM THE DEVICES (personal data)",
            f"  {report.users.lead}",
        ]
        for d in report.users.devices:
            out.append(f"  {d.sentence.text}")
            out += [
                f"      {a.name}: {a.signins} sign-ins, {ist_moment(a.first_seen)} to"
                f" {ist_moment(a.last_seen)}, {'; '.join(a.browsers) or 'unknown browser'}"
                for a in d.accounts
            ]
    out += ["", f"INDICATORS ({report.indicators_total})"]
    out += [f"  {i.value} [{i.kind}, {i.role}] {i.evidence}" for i in report.indicators[:25]] or [
        "  none"
    ]
    out += ["", "EVIDENCE"]
    for e in report.evidence:
        out += [
            f"  {e.id} {e.title}: {facts[e.fact].text}",
            *([f"      {e.shows or 'What the stored answer showed'}:"] if e.details else []),
            *[
                f"        {d.text}" + ("" if d.count is None else f" ({times(d.count)})")
                for d in e.details
            ],
            f"      query ({e.query.language}, {e.query.index}, {ist_moment(e.query.time_from)}"
            f" to {ist_moment(e.query.time_to)}): {e.query.text}",
            f"      link: {e.query.url}",
        ]
    out += ["", "HYPOTHESES"]
    for hy in report.hypotheses:
        out.append(f"  [{hy.status}] {hy.name}")
        out += [f"      {s.text}" for s in hy.why[:3]]
    out += ["", "RECOMMENDED ACTIONS"]
    out += [f"  {a.title} (owner: {a.owner}; {a.state})" for a in report.actions.lines] or [
        f"  {report.actions.note or 'none'}"
    ]
    if report.actions.close_when is not None:
        out.append(f"  {report.actions.close_when.text}")
    if report.meta.limits:
        out += ["", "LIMITS", *[f"  {x}" for x in report.meta.limits]]
    return [printable(x) for x in out]
