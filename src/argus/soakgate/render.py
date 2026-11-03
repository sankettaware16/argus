"""The soak gate's report as a table for a person, in ``argus doctor``'s style: a verdict, a name
and a detail on each line, with each line's checks under it."""

from __future__ import annotations

from argus.observability.redaction import redact_text
from argus.soakgate.model import Report, Verdict

LEGEND = (
    "PASS: measured, inside the limit. FAIL: measured, outside it. PENDING: not enough data yet"
    " (the check says what is missing). OPEN: only a person can say."
)


def printable(value: str) -> str:
    """``value`` with control characters escaped, so a label from the data cannot forge or hide
    a line of the report."""
    return "".join(
        char if char.isprintable() else char.encode("unicode_escape").decode("ascii")
        for char in value
    )


def render(report: Report) -> list[str]:
    w = report.window
    out = [
        f"{report.gate} gate: {w.since:%Y-%m-%d %H:%M} to {w.until:%Y-%m-%d %H:%M} UTC"
        f" ({w.days():.2f} days)",
        "",
    ]
    width = max((len(c.id) for line in report.lines for c in line.checks), default=2)
    for line in report.lines:
        out.append(f"{line.verdict.value:<8} {line.number:>2}  {line.title}")
        for c in line.checks:
            n = "" if c.n is None else f" [n={c.n}]"
            out.append(f"  {c.verdict.value:<8} {c.id.ljust(width)}  {c.title}{n}")
            out.append(f"  {'':<8} {'':<{width}}  {c.detail}")
            if c.needs and c.verdict in (Verdict.PENDING, Verdict.OPEN):
                out.append(f"  {'':<8} {'':<{width}}  needs: {c.needs}")
    summary = report.summary()
    out += ["", ", ".join(f"{k} {summary[k]}" for k in ("PASS", "FAIL", "PENDING", "OPEN"))]
    out += [f"note: {note}" for note in report.notes]
    out.append(LEGEND)
    return [printable(redact_text(line)) for line in out]
