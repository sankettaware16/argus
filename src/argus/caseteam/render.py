"""Rendering an incident report into the Kibana case: pure functions of the stored report.

The case has a description (summary, verdict, facts table) and one comment for each part, by the
user that owns it (evidence and devices, threat intel when an outside answer exists, recommended
actions, queries, the files' listing, the verdict last). Counts, times and lists are filled in by
code. A **sentence** has the address, domain or URL it names written plain in a code span and the
rest escaped for Kibana's Markdown; a **value** is cleaned and fenced in a code span no backtick
can close; a **query** is code in a fence. Kibana's reader is not CommonMark: no code span is
ever inside bold, a pipe in a table cell value is U+2223, and spans that touch are one. Every
finished text then goes through :mod:`argus.caseteam.guard`. A comment never exceeds Kibana's
limit: a part is made of units that are never cut and is split between units into numbered
comments."""

from __future__ import annotations

import itertools
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from argus import site
from argus.caseteam import guard
from argus.caseteam.model import VERDICT_ENDING, Author, unit_hash
from argus.gateway.kibana.models import MAX_TEXT, MAX_TITLE, utf16_len
from argus.incident import model as m
from argus.incident.words import day_label, ist_day, ist_moment, plural, size
from argus.writer.render import clean, escape, fence, join, link, log_value, pieces

SPLIT_AT = 28_000  # UTF-16 units a comment may hold (Kibana's limit is 30,000)
DESCRIPTION_AT = 28_500
MAX_COMMENTS = 6  # comments of one part; what does not fit is left to the files
MAX_UNIT = 17_000  # characters of one unit (a query with its other form and link is the biggest)
SENTENCE = 700
LANGUAGE = {"kql": "KQL", "esql": "ES|QL"}
OUTCOME = {
    "true_positive": "true positive",
    "benign_expected": "benign (expected activity)",
    "benign_policy": "benign (allowed by policy)",
    "rule_false_positive": "false positive (the rule was wrong)",
    "inconclusive": "inconclusive",
}
ALERT_TAG = {
    "true_positive": "incident:true-positive",
    "benign_expected": "incident:benign",
    "benign_policy": "incident:benign",
    "rule_false_positive": "incident:false-positive",
    "inconclusive": "incident:under-review",
}
HYPOTHESIS = {"kept": "Kept", "ruled_out": "Ruled out", "open": "Open"}
_URL = re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]*://[^\s]+")
_IPV4 = re.compile(r"(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d])")
_DOMAIN = re.compile(r"\b(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}\b")
# a path as one token: from a "/" that starts a word (or follows an opening bracket or quote) to
# the next space; an address or a domain keeps the path that follows it
_PATH = re.compile(r"(?<![^\s(\[{\"'])/[^\s]*")
_TAIL = r"(?:/[^\s]*)?"
_ADDRESS = re.compile(
    f"{_PATH.pattern}|{_URL.pattern}|{_IPV4.pattern}{_TAIL}|{_DOMAIN.pattern}{_TAIL}"
)
_TRAILING = ".,;:!?)'\""  # punctuation after a URL belongs to the sentence
_ALNUM = re.compile(r"[A-Za-z0-9]")
_UNDERLINE = re.compile(r"=+")
PIPE = "\u2223"  # DIVIDES: the look-alike of a pipe, for a pipe inside a value in a table cell


@dataclass(frozen=True)
class Context:
    """What rendering needs besides the report: ARGUS's public address (its one link) and the
    other address prefixes a link may have (Kibana's Discover)."""

    link_base: str
    kibana_prefixes: tuple[str, ...] = ()

    @property
    def allowed(self) -> tuple[str, ...]:
        return (f"{self.link_base}/go/case/", *self.kibana_prefixes)


@dataclass(frozen=True)
class Part:
    """One comment's worth of content, as units that are never cut."""

    name: str
    author: Author
    title: str
    intro: tuple[str, ...]
    units: tuple[str, ...]
    head: tuple[str, ...] = ()  # a table's head, repeated in every comment that starts with rows
    sep: str = "\n\n"  # between units ("\n" for table rows)
    outro: tuple[str, ...] = ()


def say(text: object, limit: int = SENTENCE) -> str:
    """A sentence of the report: cleaned, with each URL, address, domain and path it names
    written plain in a code span (nothing acts inside one), and the rest escaped for
    Kibana's Markdown. Fenced words that touch are one code span."""
    text_ = clean(text, limit * 2)
    if _UNDERLINE.fullmatch(text_):
        return fence(text_, limit)
    parts: list[tuple[str, bool]] = []
    at = 0
    for found in _ADDRESS.finditer(text_):
        value = found.group(0).rstrip(_TRAILING)
        if not _ALNUM.search(value):  # a lone "/" is no path
            continue
        parts += pieces(text_[at : found.start()])
        parts.append((value, True))
        at = found.start() + len(value)
    parts += pieces(text_[at:])
    return join(parts, limit)


def val(value: object) -> str:
    """A value from a log, an alert or the case: cleaned and fenced, written plain."""
    return log_value(value)


def _code_end(markup: str, start: int) -> int:
    """Where the code span that opens at ``start`` ends (after its closing run of as many
    backticks), or -1 when no run of that length closes it."""
    n = len(markup)
    end = start
    while end < n and markup[end] == "`":
        end += 1
    size, at = end - start, end
    while True:
        at = markup.find("`", at)
        if at < 0:
            return -1
        stop = at
        while stop < n and markup[stop] == "`":
            stop += 1
        if stop - at == size:
            return stop
        at = stop


def cell(markup: str) -> str:
    """Inline markup inside a table cell. Kibana ends a cell at every pipe that no backslash
    protects, a pipe inside a code span included, and ``\\|`` is an escaped backslash and then a
    pipe. So a pipe in plain text is escaped once (text from :func:`say` or :func:`escape` has
    its pipes escaped already: an escaped pair is left alone), and a pipe inside a value in a code
    span becomes the look-alike U+2223 (a backslash would show in the code)."""
    out: list[str] = []
    i, n = 0, len(markup)
    while i < n:
        char = markup[i]
        if char == "\\" and i + 1 < n:
            out.append(markup[i : i + 2])
            i += 2
        elif char == "`":
            end = _code_end(markup, i)
            if end < 0:
                end = i + 1
            out.append(markup[i:end].replace("|", PIPE))
            i = end
        elif char == "|":
            out.append("\\|")
            i += 1
        else:
            out.append(char)
            i += 1
    return "".join(out)


def row(*cells: object) -> str:
    """A table row: every cell goes through :func:`cell`, so no pipe inside one splits it."""
    return "| " + " | ".join(cell(str(c)) for c in cells) + " |"


def bold(markup: str) -> str:
    """``**markup**`` unless it holds a code span. Kibana's parser looks for the ``**`` that
    closes bold by scanning the raw characters, code spans included, so a value that contains
    ``**`` could cut the bold short and leave the rest as live Markdown: a fence is
    never put inside bold."""
    return markup if "`" in markup else f"**{markup}**"


def labelled(label: str, words: str) -> str:
    """``**label words**``; when the words hold a value in a code span only the label is bold."""
    return f"**{label} {words}**" if "`" not in words else f"**{label}** {words}"


def code_block(code: str, limit: int = 4_000) -> str:
    """A fenced block whose fence no backtick in the code can close. Lines are kept (a pasted
    ES|QL pipeline reads better); control and invisible characters are not. The fence has no
    language tag: Kibana highlights a tagged one with a registry that throws on a language it
    does not know."""
    lines = [clean(line, limit) for line in code.replace("\r", "").split("\n")]
    body = "\n".join(line for line in lines if line)[:limit] or "(empty)"
    longest = max((len(r) for r in re.findall(r"`+", body)), default=0)
    ticks = "`" * max(3, longest + 1)
    return f"{ticks}\n{body}\n{ticks}"


def _cut_line(line: str, room: int) -> str:
    """The longest start of a one-line markup within ``room`` UTF-16 units that ends at a space
    outside every code span and not after a backslash (``""`` when there is none)."""
    best = used = i = 0
    n = len(line)
    while i < n:
        char = line[i]
        if char == "\\" and i + 1 < n:
            j = i + 2
        elif char == "`":
            j = _code_end(line, i)
            if j < 0:
                break
        else:
            j = i + 1
        used += utf16_len(line[i:j])
        if used > room:
            break
        if char == " ":
            best = i
        i = j
    return line[:best].rstrip()


def _cap(unit: str) -> str:
    """A unit within ``MAX_UNIT`` UTF-16 units, cut at a line boundary and never inside a code
    span or a fence (a fence the cut leaves open is closed). Whole units are the rule; this is
    the last resort for one that is still too long."""
    if utf16_len(unit) <= MAX_UNIT:
        return unit
    mark = "…"
    lines = unit.split("\n")
    while len(lines) > 1 and utf16_len("\n".join(lines) + "\n" + mark) > MAX_UNIT:
        lines.pop()
    if len(lines) == 1 and utf16_len(lines[0]) + 2 > MAX_UNIT:
        lines = [_cut_line(lines[0], MAX_UNIT - 2)]
    opened = ""
    for line in lines:
        found = re.match(r"^ {0,3}(`{3,})", line)
        if found is None:
            continue
        if not opened:
            opened = found.group(1)
        elif line.strip() == found.group(1) and len(found.group(1)) >= len(opened):
            opened = ""
    if opened:
        lines.append(opened)
    body = "\n".join(lines)
    return f"{body}\n{mark}" if body.strip() else mark


def when(at: object) -> str:
    return "not known" if at is None else ist_moment(at)  # type: ignore[arg-type]


def number(value: float) -> str:
    return f"{value:.2f}".rstrip("0").rstrip(".")


_PERCENT = {"(": "%28", ")": "%29", "'": "%27", "[": "%5B", "]": "%5D"}


def link_target(url: str) -> str | None:
    """A Discover link as a Markdown link target: the characters that end or open a link
    (parentheses, quotes, brackets) are percent-encoded (the URL means the same). None for a URL
    with a space, an angle bracket, a backslash, a backtick or a double quote."""
    if not url or len(url) > 8_000 or re.search(r"[\s<>\"`\\]", url):
        return None
    return "".join(_PERCENT.get(c, c) for c in url)


def argus_link(ctx: Context, case_id: str) -> str:
    return f"[Open this case in ARGUS]({link(ctx.link_base, case_id)})"


def _asked(values: Sequence[str], shown: int = 3) -> str:
    """The values a check asked about, in code spans (``a``, ``b`` and 2 more)."""
    if not values:
        return ""
    more = len(values) - shown
    tail = f" and {more} more" if more > 0 else ""
    return ", ".join(val(v) for v in values[:shown]) + tail


def evidence_part(report: m.IncidentReport) -> Part:
    facts = {f.id: f for f in report.facts}
    units: list[str] = []
    for line in report.evidence:
        ran = "" if line.at is None else f" · run {escape(ist_moment(line.at))}"
        text = facts[line.fact].text if line.fact in facts else ""
        about = f" — {_asked(line.asked)}" if line.asked else ""
        heading = bold(f"{escape(line.id)} · {escape(line.title, 200)}")
        units.append(
            _cap(
                f"{heading}{about}\n"
                f"{say(text)}\n"
                f"Source: {fence(line.source)} · check {fence(line.query.template)}"
                f" · status {fence(line.status)}{ran}"
            )
        )
    if not units:
        units.append("No stored check ran for this case yet, so there is no evidence line.")
    if report.hypotheses:
        units.append(_cap(hypotheses_table(report)))
    return Part(
        "evidence",
        Author.EVIDENCE,
        "Evidence",
        (
            "What ARGUS saw, one line for each check that ran. The query behind every line is in"
            " the Queries comment; counts and times come from stored checks, not from a model.",
        ),
        tuple(units),
    )


def hypotheses_table(report: m.IncidentReport) -> str:
    """The hypotheses as the hand-made case showed them: one row each with what ARGUS did with it
    and its own reason (the first sentence of the report's reason, which names the facts in short
    words; the facts themselves are in the report and the PDF)."""
    rows = ["\n### Hypotheses (kept or ruled out)", "| Hypothesis | Kept? | Why |", "|---|---|---|"]
    for h in report.hypotheses:
        by = "" if h.by == "argus" else " (the AI investigator's)"
        why = say(h.why[0].text, 600) if h.why else "-"
        rows.append(row(f"{say(h.name, 300)}{by}", f"**{HYPOTHESIS[h.status]}**", why))
    return "\n".join(rows)


def _answers(answered: int | None, served: Sequence[str], exact: bool = True) -> str:
    """A table cell for the successful (2xx) answers a stored record shows. A count read from a
    sample that hit its cap is said as ``20+``, not as if it were exact."""
    if answered is None:
        return "not checked"
    text = "none seen" if answered == 0 else f"yes ({answered}{'' if exact else '+'})"
    if served:
        text += ": " + ", ".join(val(p) for p in served)
    return text


def targets_head() -> tuple[str, str]:
    zone = site.zone_label()
    return (
        f"| Target | Kind | Alerts | Outside addresses | First ({zone}) | Last ({zone})"
        " | Successful answers |",
        "|---|---|---|---|---|---|---|",
    )


def actors_head() -> tuple[str, str]:
    zone = site.zone_label()
    return (
        f"| Address | Role | Alerts | First ({zone}) | Last ({zone}) | Threat list | Outside intel"
        " | Successful answers |",
        "|---|---|---|---|---|---|---|---|",
    )


def table_units(title: str, head: tuple[str, str], rows: Sequence[str]) -> list[str]:
    """A titled table as units, one for each row: the first carries the title and the head, so a
    comment that begins at a later row repeats the head (:func:`head_for`) and no table is ever
    cut in the middle of a row or a code span."""
    if not rows:
        return []
    return [f"\n### {title}\n{head[0]}\n{head[1]}\n{rows[0]}", *rows[1:]]


def targets_units(report: m.IncidentReport) -> list[str]:
    """The internal sites and hosts the outside actors went against, one unit a row."""
    rows: list[str] = []
    for t in report.targets:
        kind = t.kind if t.label is None else f"{t.kind} ({say(t.label, 80)})"
        rows.append(
            row(
                val(t.value),
                kind,
                t.alerts,
                t.actors,
                escape(when(t.first_seen)),
                escape(when(t.last_seen)),
                _answers(t.answered, t.served, t.answered_exact),
            )
        )
    units = table_units(site.say("{Own:targets}"), targets_head(), rows)
    more = report.targets_total - len(report.targets)
    if units and more > 0:
        units.append(
            f"\n{more} more are not listed (the {len(report.targets)} with the most alerts are)."
        )
    return units


def actors_units(report: m.IncidentReport) -> list[str]:
    """The outside actors: address, alerts, first and last, whether a local threat list names it,
    what outside services say, and whether it got successful answers, one unit a row."""
    rows: list[str] = []
    for a in report.actors:
        if a.inside or a.kind != "ip":
            continue
        intel = say(a.intel, 300) if a.intel else "no outside record"
        rows.append(
            row(
                val(a.value),
                escape(a.role, 40),
                a.alerts,
                escape(when(a.first_seen)),
                escape(when(a.last_seen)),
                "listed" if a.listed else "not listed",
                intel,
                _answers(a.answered, a.served, a.answered_exact),
            )
        )
    units = table_units("Outside actors", actors_head(), rows)
    if units and report.outsiders_total > len(rows):
        units.append(
            f"\n{len(rows)} of {report.outsiders_total} outside addresses are shown; the"
            f" other {report.outsiders_total - len(rows)} are not listed."
        )
    return units


def devices_part(report: m.IncidentReport) -> Part:
    """The comment about who and what was affected. Internal devices get the hand-made case's
    table; a case of outside addresses against internal servers lists the internal targets and the
    outside actors instead: there is no affected *device* to list."""
    devices = [a for a in report.assets if a.kind == "device"]
    others = [a for a in report.assets if a.kind != "device"]
    outside = any(not a.inside and a.kind == "ip" for a in report.actors)
    rows: list[str] = []
    for a in devices:
        first = "-" if a.first_seen is None else ist_day(a.first_seen)
        last = "-" if a.last_seen is None else ist_day(a.last_seen)
        label = val(a.label) if a.label else "-"
        rows.append(row(val(a.value), label, a.days, first, last))
    units = list(rows)
    units += targets_units(report)
    if outside:
        units += actors_units(report)
    if others:
        units.append("\n### Other assets")
    for a in others:
        where = f" → {val(a.label)}" if a.label else ""
        units.append(
            f"- {escape(a.kind)}: {val(a.value)}{where} ({a.alerts} alerts, {a.days} days)"
        )
    if not units:
        units.append("The case names no affected asset.")
    hidden = max(report.assets_total - len(report.assets), 0)
    outro: tuple[str, ...] = ()
    if hidden:
        outro = (f"{hidden} more affected assets are in the affected-devices CSV (Files tab).",)
    if devices or not (report.targets or outside):
        title = "Affected devices"
        intro = (
            f"Devices that alerted, from the alerts ({plural(report.assets_total, 'asset')} in"
            f" all). Days counts {site.zone_label()} days with an alert.",
        )
    else:
        title = site.say("{Own:targets} and outside actors")
        intro = (
            "Who acted and what they went against, from the alerts and the web checks ARGUS"
            f" stored. Times are {site.zone_label()}; a successful answer is a 2xx status in the"
            " web server's log.",
        )
    return Part(
        "devices",
        Author.EVIDENCE,
        title,
        intro,
        tuple(units),
        head=(
            f"| Device | Reached | Days | First ({site.zone_label()})"
            f" | Last ({site.zone_label()}) |",
            "|---|---|---|---|---|",
        )
        if rows
        else (),
        sep="\n",
        outro=outro,
    )


def accounts_part(report: m.IncidentReport) -> Part | None:
    """The accounts that signed in from the affected devices: the table an
    escalation report needs ("accounts affected"), posted by ``argus-evidence``. A lead and not
    proof, and personal data: the Kibana case is the team's. None when the report names no account
    and no device state, and then nothing is posted."""
    users = report.users
    if not users.devices:
        return None
    rows: list[str] = []
    for d in users.devices:
        for a in d.accounts:
            rows.append(
                row(
                    val(a.name),
                    val(a.device),
                    escape(d.state.replace("_", " ")),
                    escape(ist_moment(a.first_seen)),
                    escape(ist_moment(a.last_seen)),
                    a.signins,
                    escape("; ".join(a.browsers) or "unknown browser", 120),
                )
            )
    others = [
        f"- {say(d.sentence.text)}"
        for d in users.devices
        if not d.accounts
    ][:20]  # fmt: skip
    units = [*rows, *others]
    intro = (
        escape(users.lead, 300),
        "From the SSO sign-in logs, for the internal addresses of the affected devices, as ARGUS"
        f" kept them. Times are {site.zone_label()}. A shared address names no one.",
    )
    return Part(
        "accounts",
        Author.EVIDENCE,
        "Accounts affected",
        intro,
        tuple(units),
        head=(
            f"| Account | Device | State | First ({site.zone_label()}) | Last ({site.zone_label()})"
            " | Sign-ins | Browser |",
            "|---|---|---|---|---|---|---|",
        )
        if rows
        else (),
        sep="\n",
    )


def intel_part(report: m.IncidentReport) -> Part | None:
    """Outside answers (VirusTotal, Shodan, Censys) the report holds; None when there are none,
    and then nothing is posted ("nothing to add" is not a comment)."""
    found = [f for f in report.facts if f.kind == "intel"]
    if not found:
        return None
    units = [f"- {say(f.text)} (source: {fence(f.source, 120)})" for f in found]
    return Part(
        "intel",
        Author.INTEL,
        "Threat intel",
        (
            "What outside services say about an indicator ARGUS's own data did not settle."
            " Only looked-up answers are quoted here; nothing is added by a model.",
        ),
        tuple(units),
        sep="\n",
    )


def actions_part(report: m.IncidentReport) -> Part:
    a = report.actions
    rows = [
        row(
            n,
            f"{say(line.title, 200)}. {say(line.say, 400)}",
            say(line.owner, 100),
            escape(line.state.replace("_", " ").capitalize(), 30),
        )
        for n, line in enumerate(a.lines, 1)
    ]
    units = list(rows)
    # a blank line before a paragraph after the table rows, so it is not read as one more row
    if not units:
        units.append(say(a.note or "No action is recommended yet."))
    elif a.note:
        units.append("\n" + say(a.note))
    if a.close_when is not None:
        units.append("\n**Close this case when:** " + say(a.close_when.text))
    return Part(
        "actions",
        Author.RESPONDER,
        "Recommended actions",
        ("From the responder's catalogue, with the owner of each and where it stands.",),
        tuple(units),
        head=("| # | Action | Owner | Status |", "|---|---|---|---|") if rows else (),
        sep="\n",
    )


def queries_part(report: m.IncidentReport, ctx: Context) -> Part:
    units: list[str] = []
    for q in report.queries:
        head = (
            f"{bold(f'{escape(q.template, 100)} · {escape(q.index, 150)}')}"
            f" ({LANGUAGE[q.language]})"
            f" · {escape(ist_moment(q.time_from))} to {escape(ist_moment(q.time_to))}"
        )
        blocks = [head, code_block(q.text)]
        if q.other:
            other = "esql" if q.language == "kql" else "kql"
            blocks += [f"The same in {LANGUAGE[other]}:", code_block(q.other)]
        target = link_target(q.url)
        if target is not None and guard.link_allowed(target, ctx.kibana_prefixes):
            blocks.append(f"[Open in Discover]({target})")
        units.append(_cap("\n\n".join(blocks)))
    if not units:
        units.append("No query was recorded for this case.")
    return Part(
        "queries",
        Author.HUNTER,
        "Queries to check it yourself",
        (
            "Read-only. Paste a query into Discover; the time range of each is in its heading."
            " Nothing here changes anything.",
        ),
        tuple(units),
    )


def parts_of(report: m.IncidentReport, ctx: Context) -> list[Part]:
    """The comment parts in the case's order; Threat intel only when there is something."""
    out = [evidence_part(report), devices_part(report)]
    accounts = accounts_part(report)
    if accounts is not None:
        out.append(accounts)
    intel = intel_part(report)
    if intel is not None:
        out.append(intel)
    return [*out, actions_part(report), queries_part(report, ctx)]


_ALIGN = re.compile(r"^\|(?:\s*:?-+:?\s*\|)+$")


def own_head(unit: str) -> tuple[str, ...]:
    """The table head a unit carries (a header row and its alignment row), else ``()``."""
    lines = unit.split("\n")
    for above, below in itertools.pairwise(lines):
        if above.startswith("|") and _ALIGN.match(below):
            return (above, below)
    return ()


def head_for(part: Part, unit: str) -> tuple[str, ...]:
    """The head a comment needs when it begins at ``unit``, a table row: that of the table the
    row belongs to (the unit that starts the run of rows, which carries its own head), else the
    part's own."""
    try:
        at = part.units.index(unit)
    except ValueError:
        return part.head
    for earlier in reversed(part.units[: at + 1]):
        found = own_head(earlier)
        if found:
            return found
        if not earlier.startswith("|"):
            break
    return part.head


def comments_of(
    part: Part,
    units: Sequence[str] | None = None,
    *,
    heading: str | None = None,
    intro: Sequence[str] | None = None,
) -> tuple[list[str], int]:
    """The comments a part is posted as, and how many units did not fit (left to the files).
    ``units`` limits the part to some of its units (an update); ``heading`` and ``intro`` replace
    the part's own (an update says what changed)."""
    chosen = list(part.units if units is None else units)
    title = heading or part.title
    lead = list(part.intro if intro is None else intro)
    reserve = utf16_len(f"## {title} (99 of 99)") + sum(utf16_len(x) + 2 for x in lead)
    heads = [part.head, *(own_head(u) for u in part.units)]
    reserve += max(sum(utf16_len(x) + 2 for x in h) for h in heads)
    reserve += sum(utf16_len(x) + 2 for x in part.outro)
    room = max(SPLIT_AT - reserve - 64, 2_000)
    chunks: list[list[str]] = []
    now: list[str] = []
    used = 0
    for unit in chosen:
        cost = utf16_len(unit) + len(part.sep)
        if now and used + cost > room:
            chunks.append(now)
            now, used = [], 0
        now.append(unit)
        used += cost
    if now:
        chunks.append(now)
    left = 0
    if len(chunks) > MAX_COMMENTS:
        left = sum(len(c) for c in chunks[MAX_COMMENTS:])
        chunks = chunks[:MAX_COMMENTS]
    texts: list[str] = []
    for i, chunk in enumerate(chunks, 1):
        lines = [f"## {title}" + (f" ({i} of {len(chunks)})" if len(chunks) > 1 else "")]
        if i == 1:
            lines += lead
        body = part.sep.join(chunk).lstrip("\n")
        if chunk[0].startswith("|"):
            head = head_for(part, chunk[0])
            if head:
                body = "\n".join(head) + "\n" + body
        lines.append(body)
        if i == len(chunks):
            tail = list(part.outro)
            if left:
                tail.append(f"{left} more lines did not fit here and are not shown.")
            lines += tail
        texts.append("\n\n".join(lines))
    return texts, left


def unit_hashes(part: Part) -> tuple[str, ...]:
    return tuple(unit_hash(u) for u in part.units)


def title_of(report: m.IncidentReport) -> str:
    """The case's title, within Kibana's 160 characters (counted as Kibana counts them): one line
    of plain characters, never blank (the incident ID stands in). ARGUS's certainty word is left
    out (naming v2: only confirmed cases are posted; the ID and the tags carry the rest), and a
    person's title is kept as they wrote it."""
    from argus.cases import naming

    header = report.header
    ident, sep, rest = header.title.partition(" · ")
    if sep and header.certainty:
        rest = naming.without_certainty(rest, header.certainty)
    text = clean(f"{ident}{sep}{rest}" if sep else header.title, 300)
    while utf16_len(text) > MAX_TITLE:
        text = text[: len(text) - 2].rstrip() + "…" if len(text) > 2 else text[:1]
    return text or report.header.incident_id


def tags_of(report: m.IncidentReport) -> tuple[str, ...]:
    """The case's ``key:value`` tags: the incident ID first, ``incident``, the report's own tags
    (any the case would refuse is left out) and ``source:argus-lead`` last. The required ones are
    always there, whatever the report's tags hold."""
    from argus.gateway.kibana.models import TEAM_TAG

    ident = report.header.incident_id
    own = [
        t
        for t in report.header.tags
        if TEAM_TAG.fullmatch(t)
        and not t.startswith("argus")
        and t not in (ident, "incident", "source:argus-lead")
    ]
    found = [ident, "incident", *own, "source:argus-lead"]
    return tuple(dict.fromkeys(found))[:200]


def alert_tags_of(report: m.IncidentReport) -> tuple[str, ...]:
    """What goes on each attached alert: the incident ID and ``incident:<verdict>``."""
    outcome = report.verdict.outcome
    return (report.header.incident_id, ALERT_TAG.get(outcome or "", "incident:under-review"))


def case_words(report: m.IncidentReport) -> str:
    """The ARGUS case's number, its state, how it began and whether a person confirmed the report
    (``opened_in`` says it as the case's record and the reviews do)."""
    h = report.header
    return escape(f"{h.case_number} ({h.case_state}; {h.opened_in})", 200)


def affected_words(report: m.IncidentReport) -> str:
    """Who and what was affected, in words: internal devices, the internal sites and hosts attacked
    and the outside addresses that attacked them; the assets' count when nothing else is known."""
    devices = sum(1 for a in report.assets if a.kind == "device")
    listed = sum(1 for a in report.actors if not a.inside and a.kind == "ip")
    outsiders = max(report.outsiders_total, listed)  # the report lists at most 25 of them
    by = plural(outsiders, "outside address", "outside addresses")
    parts: list[str] = []
    if devices:
        parts.append(plural(devices, site.own("device"), site.own("devices")))
    if report.targets_total:
        sites = plural(report.targets_total, site.own("site or host"), site.own("sites and hosts"))
        parts.append(f"{sites} attacked" + (f" by {by}" if outsiders else ""))
    elif outsiders and not devices:
        parts.append(f"{by} (the alerts name no {site.own('target')})")
    return "; ".join(parts) or plural(report.assets_total, "asset")


def description(report: m.IncidentReport, ctx: Context, *, attached: int) -> str:
    """The case's description: summary, verdict, facts table, what is not part of it."""
    h, v, s = report.header, report.verdict, report.summary
    kind = "verdict" if v.kind in ("person", "proposal", "case") else "reading"
    sentences = list(s.prose or s.sentences)
    sure = (
        ""
        if v.confidence is None
        else f", confidence {escape(v.confidence_words or '')} ({round(v.confidence * 100)}%)"
    )
    facts = [
        ("Incident ID", fence(h.incident_id)),
        ("ARGUS case", case_words(report)),
        ("Severity", escape(h.severity.capitalize())),
        ("Detected by", say(h.detected_by, 500)),
        ("Alerts", f"{report.meta.alerts_total} in ARGUS; {attached} attached to this case"),
        ("First alert", escape(when(h.first_alert_at))),
        ("Latest alert", escape(when(h.last_alert_at))),
        ("Still going on", say(s.standing_words, 300)),
        ("Affected", affected_words(report)),
    ]
    marks = report.indicators[:8]
    if marks:
        shown = ", ".join(val(i.value) for i in marks)
        more = report.indicators_total - len(marks)
        facts.append(("Indicators", shown + (f" and {more} more" if more > 0 else "")))
    mitre = [t.removeprefix("mitre:") for t in h.tags if t.startswith("mitre:")]
    if mitre:
        facts.append(("MITRE", ", ".join(fence(t, 30) for t in mitre)))
    status = [t.removeprefix("status:") for t in h.tags if t.startswith("status:")]
    if status:
        facts.append(("Status", fence(status[0], 40)))

    def build(summary: list[m.ReportSentence], scope: Sequence[m.ReportSentence]) -> str:
        blocks = ["## Summary", *[say(x.text) for x in summary]]  # the notice's line is one
        blocks += [
            "## Verdict",
            labelled(f"ARGUS's {kind}:", say(v.words, 300))
            + f"{sure}. Source: {say(v.source, 200)}.",
            *[say(x.text) for x in v.sentences],
            "## Facts",
            "| | |\n|---|---|\n" + "\n".join(row(k, x) for k, x in facts),
        ]
        if scope:
            blocks += ["## Not part of this incident", *[say(x.text) for x in scope]]
        blocks += [
            "Written by ARGUS from its stored data; every line is tied to evidence in the"
            " comments below. " + argus_link(ctx, h.case_id)
        ]
        return "\n\n".join(blocks)

    text = build(sentences, list(report.out_of_scope))
    if utf16_len(text) > DESCRIPTION_AT:
        text = build(sentences[:6], list(report.out_of_scope)[:2])
    while utf16_len(text) > DESCRIPTION_AT and len(facts) > 4:
        facts.pop()
        text = build(sentences[:6], [])
    return text


def verdict_comment(
    report: m.IncidentReport, ctx: Context, *, update_of: m.ReportVerdict | None = None
) -> str:
    """The lead's last comment: ARGUS's verdict and how a person answers it. It always ends with
    ``Confirm or reject in a comment.``"""
    v = report.verdict
    word = OUTCOME.get(v.outcome or "", "none yet")
    sure = "" if v.confidence is None else f" ({number(v.confidence)})"
    kind = "verdict" if v.kind in ("person", "proposal", "case") else "reading"
    if update_of is None:
        head = f"**ARGUS's {kind}: {word}{sure}.**"
    else:
        before = OUTCOME.get(update_of.outcome or "", "none yet")
        was = "" if update_of.confidence is None else f" ({number(update_of.confidence)})"
        head = f"**Update: ARGUS's {kind} is now {word}{sure}; it was {before}{was}.**"
    body = [head, *[say(s.text) for s in v.sentences]]
    body.append(f"Source: {say(v.source, 200)}.")
    body.append(
        "To record yours, comment `Verdict: true positive` or `Verdict: false positive: <your"
        " reason>` from your own account. ARGUS records it as a label and learns from it;"
        " closing the case stays a person's approval in ARGUS. "
        + argus_link(ctx, report.header.case_id)
    )
    body.append(VERDICT_ENDING)
    return "\n\n".join(body)


def has_accounts(report: m.IncidentReport) -> bool:
    return any(d.accounts for d in report.users.devices)


def files_comment(
    report: m.IncidentReport, files: Sequence[tuple[str, str, int, str]], *, update: bool = False
) -> str:
    """The reporter's comment listing the files: (name, what it is, bytes, sha-256)."""
    rows = [
        row(val(name), escape(what, 80), size(nbytes), fence(digest[:16]))
        for name, what, nbytes, digest in files
    ]
    title = "Update: new files" if update else "Files"
    return "\n\n".join(
        [
            f"## {title}",
            f"ARGUS attached the files of incident {fence(report.header.incident_id)} to this"
            " case's Files tab, rendered from the same report as these comments"
            f" (written {escape(ist_moment(report.meta.as_at))}).",
            "| File | What it is | Size | SHA-256 (start) |\n|---|---|---|---|\n" + "\n".join(rows),
            "The PDF is the full report."
            + (
                " The dashboard is its one-page picture."
                if any(what.startswith("Dashboard") for _, what, _, _ in files)
                else ""
            )
            + " The indicators CSV is for block lists; the"
            " affected-devices CSV is for contacting the owners"
            + (
                "; the affected-accounts CSV lists who signed in from them."
                if has_accounts(report)
                else "."
            ),
        ]
    )


BENIGN_OUTCOMES = frozenset({"benign_expected", "benign_policy", "rule_false_positive"})


@dataclass(frozen=True)
class Effect:
    """What the review path did with a person's verdict (stored with the comment it read): the
    note says exactly this and claims nothing more."""

    decision: str = ""  # confirmed | rejected
    labelled: int = 0  # investigations that got a new label
    already: int = 0  # investigations that already carried this outcome
    kept: int = 0  # investigations whose earlier, different review stands (a confirm keeps it)
    kept_by: tuple[str, ...] = ()
    conflicts: int = 0  # investigations that moved while it was recorded


def effect_of(counts: Mapping[str, Any]) -> Effect | None:
    """The effect stored with a verdict comment; None for one read before it was stored."""
    if not counts:
        return None

    def number(name: str) -> int:
        value = counts.get(name)
        return value if isinstance(value, int) and not isinstance(value, bool) else 0

    names = counts.get("kept_by")
    return Effect(
        str(counts.get("decision") or ""),
        number("labelled"),
        number("already"),
        number("kept"),
        tuple(str(n) for n in names) if isinstance(names, list) else (),
        number("conflicts"),
    )


def _by(names: Sequence[str]) -> str:
    return f" by {', '.join(fence(n, 60) for n in names)}" if names else ""


def closing_comment(
    ctx: Context,
    case_id: str,
    *,
    who: str,
    outcome: str,
    effect: Effect | None = None,
) -> str:
    """The lead's note after a person's ``Verdict:`` comment was read. It says what the review
    path did and nothing more: "recorded as a label" only when it wrote one; otherwise what
    happened ("kept: an earlier review by X stands"). It claims no closing proposal: closing
    stays a person's approval in ARGUS, which for a benign verdict a person may do."""
    word = OUTCOME.get(outcome, outcome)
    lines = [f"ARGUS read the verdict {fence(who, 80)} wrote in this case: {escape(word)}."]
    if effect is None:
        lines.append("ARGUS recorded the verdict.")
    elif effect.labelled:
        done = f"ARGUS recorded it as a label on {plural(effect.labelled, 'investigation')}."
        lines.append(f"{done} ARGUS's engine learns from it.")
        if effect.kept:
            lines.append(
                f"Kept: an earlier review{_by(effect.kept_by)} stands on"
                f" {plural(effect.kept, 'investigation')}."
            )
    elif effect.kept:
        lines.append(
            f"Kept: an earlier review{_by(effect.kept_by)} stands on"
            f" {plural(effect.kept, 'investigation')}, so this verdict replaced nothing and no"
            " label was written."
        )
    elif effect.already:
        lines.append(
            "No new label was written: the investigations of this case already carry this outcome."
        )
    else:
        lines.append("No label was written.")
    if effect is not None and effect.conflicts:
        lines.append(
            f"{plural(effect.conflicts, 'investigation')} changed while it was recorded and"
            " were left as they were."
        )
    close = (
        "A person may close this case in ARGUS; closing stays a person's approval there."
        if outcome in BENIGN_OUTCOMES
        else "Closing the case stays a person's approval in ARGUS."
    )
    lines.append(f"{close} {argus_link(ctx, case_id)}")
    return "\n\n".join(lines)


def conflict_comment(ctx: Context, case_id: str, verdicts: Sequence[tuple[str, str]]) -> str:
    """The lead's note when people's verdicts disagree: who said what. Each was recorded through
    the review path, which keeps a person's earlier review where a confirm would override it."""
    said = "; ".join(
        f"{fence(who, 80)} said {escape(OUTCOME.get(outcome, outcome))}"
        for who, outcome in verdicts
    )
    return "\n\n".join(
        [
            f"People disagree on this case: {said}.",
            "ARGUS recorded each verdict through its review path (a verdict that agrees with"
            " the report confirms it and keeps a person's own earlier review; one that does not"
            " rejects it with the reason given). A person decides in ARGUS which stands. "
            + argus_link(ctx, case_id),
        ]
    )


def untagged_comment(ctx: Context, case_id: str, *, named: int, gone: int, untagged: int) -> str:
    """The lead's note when a tag call could not tag every alert it named."""
    lines = []
    if gone:
        lines.append(
            f"{plural(gone, 'alert')} of the {named} one tag call named no longer exists in"
            " Kibana's alerts index (index lifecycle removed it): left out, not tagged."
            " It stays listed in this case's attachments."
        )
    if untagged:
        lines.append(
            f"{plural(untagged, 'alert')} of the {named} one tag call named could not be tagged:"
            " Kibana was rewriting them, and a second try met the same. They are attached to"
            " this case without the incident tag."
        )
    lines.append("The tags are on every other alert of the case. " + argus_link(ctx, case_id))
    return "\n\n".join(lines)


def comment_limit_ok(text: str) -> bool:
    return utf16_len(text) <= MAX_TEXT


def human_day(day: str) -> str:
    return day_label(day)
