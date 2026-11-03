"""Charts as inline SVG, drawn on the server. No script, and no style attribute (the
CSP allows neither): shapes are SVG attributes, and colours come from the stylesheet's classes,
so light and dark follow the system like the rest of the Inbox. Every chart has a text
alternative, and its numbers are on the page as a table."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime

from markupsafe import Markup, escape

from argus import site
from argus.web import render

W, H = 960, 220  # the viewBox; the SVG scales to its box
PAD_L, PAD_B, PAD_T = 44, 26, 10


STEPS = (1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10)


def _nice(top: int) -> int:
    """A round number at or above ``top`` for the axis: a step of 1, 1.2, … 10 of its power
    of ten (``top`` is below ten of them, so a step always fits)."""
    top = max(top, 5)
    power = 10 ** (len(str(top)) - 1)
    return int(next(m for m in STEPS if top <= m * power) * power)


def stacked(
    series: Sequence[tuple[datetime, dict[str, int]]],
    order: Sequence[str],
    label: str,
    hourly: bool,
) -> Markup:
    """A stacked bar per bucket (``order`` from the bottom), with a tooltip per bar."""
    totals = [sum(v.values()) for _, v in series]
    top = _nice(max(totals, default=0))
    n = max(len(series), 1)
    plot_w, plot_h = W - PAD_L - 8, H - PAD_B - PAD_T
    slot = plot_w / n
    bar = max(min(slot * 0.72, 48), 1.5)
    parts = [f'<svg class="chart" viewBox="0 0 {W} {H}" role="img" aria-label="{escape(label)}">']
    for k in range(5):  # grid lines and the axis
        value = top * k / 4
        y = PAD_T + plot_h - plot_h * k / 4
        parts.append(f'<line class="grid" x1="{PAD_L}" x2="{W - 8}" y1="{y:.1f}" y2="{y:.1f}"/>')
        parts.append(f'<text class="axis" x="{PAD_L - 6}" y="{y + 4:.1f}" text-anchor="end">'
                     f"{int(value):,}</text>")  # fmt: skip
    every = max(1, round(n / 12))
    for i, (at, values) in enumerate(series):
        x = PAD_L + slot * i + (slot - bar) / 2
        y = PAD_T + plot_h
        when = f"{at:%d %b} {render.hour12(at)}" if hourly else at.strftime("%a %d %b")
        tip = f"{when} {site.zone_label(at)}: {totals[i]:,} alerts" + "".join(
            f", {values[s]:,} {s}" for s in order if values.get(s)
        )
        parts.append(f"<g><title>{escape(tip)}</title>")
        for sev in order:
            count = values.get(sev, 0)
            if not count:
                continue
            h = plot_h * count / top
            y -= h
            parts.append(f'<rect class="bar-{escape(sev)}" x="{x:.1f}" y="{y:.1f}" '
                         f'width="{bar:.1f}" height="{h:.1f}"/>')  # fmt: skip
        if not totals[i]:  # an empty bucket still has a target for its tooltip
            parts.append(f'<rect class="bar-empty" x="{x:.1f}" y="{PAD_T}" width="{bar:.1f}" '
                         f'height="{plot_h}"/>')  # fmt: skip
        parts.append("</g>")
        if i % every == 0:
            tick = render.hour12(at) if hourly else at.strftime("%d %b")
            parts.append(f'<text class="axis" x="{x + bar / 2:.1f}" y="{H - 8}" '
                         f'text-anchor="middle">{tick}</text>')  # fmt: skip
    parts.append("</svg>")
    return Markup("".join(parts))  # noqa: S704 - every value above is a number or escaped


def parts(
    counts: Mapping[str, int], titles: Mapping[str, str], prefix: str
) -> list[tuple[str, int, str]]:
    """``split``'s parts from counts, largest first; each part's class is ``prefix-key``."""
    ordered = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return [(titles.get(k, k.replace("_", " ")), n, f"{prefix}-{k}") for k, n in ordered]


def split(parts: Sequence[tuple[str, int, str]], label: str) -> Markup:
    """One bar split into ``(name, count, css class)`` parts, for a share at a glance."""
    total = sum(n for _, n, _ in parts)  # only a part above zero is drawn, so never 0 there
    x = 0.0
    out = [f'<svg class="split" viewBox="0 0 1000 18" preserveAspectRatio="none" role="img" '
           f'aria-label="{escape(label)}">']  # fmt: skip
    for name, n, css in parts:
        if not n:
            continue
        w = 1000 * n / total
        out.append(f'<rect class="{escape(css)}" x="{x:.2f}" y="0" width="{w:.2f}" height="18">'
                   f"<title>{escape(name)}: {n:,}</title></rect>")  # fmt: skip
        x += w
    out.append("</svg>")
    return Markup("".join(out))  # noqa: S704 - every value above is a number or escaped
