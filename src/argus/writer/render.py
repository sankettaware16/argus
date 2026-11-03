"""Markdown-safe text for Kibana: deterministic text only.

Everything the writer puts into a Kibana case is built here from fixed sentences and values: a
value from the logs or a person is cleaned (control and zero-width characters removed, one line, cut
at 200 characters) and **fenced** in a code span no backtick can close; a person's name is escaped
for Kibana's Markdown; the only link is ARGUS's own; no text of a model, a log line or a person's
comment. The same payload and context always give the same text, which is what lets the writer find
its own comment again after an unknown outcome. An unknown template or parameter is an error."""

from __future__ import annotations

import re
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from argus import site

MAX_VALUE = 200  # characters of one value
MAX_LISTED = 20  # hosts or indicators named in a description
# Control, bidirectional, zero-width and invisible-filler characters: U+0080-9F and soft hyphen,
# combining grapheme joiner, Arabic letter mark, Hangul fillers, Khmer inherent vowels, Mongolian
# variation selectors and vowel separator, the line/paragraph separators, zero-width and
# directional marks, every code point of U+2060-206F (invisible operators, deprecated format
# characters, the unassigned ones among them), variation selectors, the byte-order mark,
# interlinear annotations, and the tag characters (U+E0000-E007F) and variation selectors
# supplement that hide text from a reader.
_UNSAFE = re.compile(
    "[\x00-\x1f\x7f-\x9f\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f"
    "\u200b-\u200f\u2028-\u202e\u2060-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0\ufff9-\ufffb"
    "\ud800-\udfff\U000e0000-\U000e007f\U000e0100-\U000e01ef]"
)
# Kibana's Markdown (EUI, legacy remark-parse with gfm) honours a backslash only before these
# characters; before anything else it shows the backslash.
_ESCAPABLE = re.compile(r"([\\`*_{}\[\]()#+\-.!>~|])")
# A whitespace-separated word that could act without a backslash: a URL, an address with a scheme,
# ``www.``, a mail or ``@mention``, a script target (a colon cannot be escaped in Kibana). An
# underscore is no boundary here: it is written ``\_`` and the guardian reads that as a space, so
# ``_www.x`` must be fenced as ``www.x`` after a space is.
_ACTIVE = re.compile(
    r"://|(?<![A-Za-z0-9])www\.|(?<![A-Za-z0-9])(?:mailto|javascript|vbscript|data):|@",
    re.IGNORECASE,
)
_BACKTICKS = re.compile(r"`+")
_UNDERLINE = re.compile(r"=+")  # a line of these under a paragraph line makes it a heading
_BASE = re.compile(r"https?://[a-z0-9.-]{1,253}(:[0-9]{1,5})?")
REASONS = {
    "remediated_verified": "fixed, and a quiet window was verified",
    "remediated_unverified": "fixed according to its owner",
    "risk_accepted": "left as it is, by decision",
    "attempt_no_impact": "an attempt that did not succeed",
    "rule_false_positive": "the rule was wrong",
    "benign_expected": "expected activity",
    "benign_policy": "allowed by policy",
    "duplicate": "merged into another case",
    "created_in_error": "opened by mistake",
    "stopped_after_notice": "the activity stopped after the owner was told",
}
SEVERITIES = frozenset({"low", "medium", "high", "critical"})


class RenderError(ValueError):
    """The payload names a template or a value the renderer does not write."""


@dataclass(frozen=True)
class Approver:
    name: str
    username: str


@dataclass(frozen=True)
class Context:
    """What the renderer needs besides the payload: ARGUS's public address (for its one link),
    people's names by ``user:<id>``, the approvers and time of a closure, and the reference
    line that ends every comment (the row's idempotency key)."""

    link_base: str
    people: Mapping[str, str] = field(default_factory=dict)
    approvers: Sequence[Approver] = ()
    approved_at: datetime | None = None
    reference: str = ""


def clean(value: object, limit: int = MAX_VALUE) -> str:
    """One line without control, bidirectional or zero-width characters, cut at ``limit``."""
    text = " ".join(_UNSAFE.sub(" ", str(value)).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def pieces(text: str) -> list[tuple[str, bool]]:
    """Already-clean text as pieces ``(text, fenced)``: whitespace and the words that are safe
    once escaped, and the words that could act without a backslash (a URL, ``www.``, a mail
    address, an ``@mention``, a script target) as raw text still to be fenced (see
    :func:`join`)."""
    out: list[tuple[str, bool]] = []
    for word in re.split(r"(\s+)", text):
        if not word:
            continue
        if word.isspace():
            out.append((word, False))
        elif _ACTIVE.search(word):
            out.append((word, True))
        else:
            safe = word.replace("&", "&amp;").replace("<", "&lt;")
            out.append((_ESCAPABLE.sub(r"\\\1", safe), False))
    return out


def join(parts: Sequence[tuple[str, bool]], limit: int | None = None) -> str:
    """Pieces as Kibana text. Each maximal run of fenced pieces with nothing between them is ONE
    code span (``alice@`` and ``example.edu`` side by side are one span, not two that Kibana would
    read as a single span with a pair of backticks inside), so two code spans are never next to
    each other. ``limit`` cuts a span's value (None: whole)."""
    out: list[str] = []
    run: list[str] = []

    def flush() -> None:
        if run:
            raw = "".join(run)
            out.append(fence(raw, len(raw) if limit is None else limit))
            run.clear()

    for chunk, fenced in parts:
        if fenced:
            run.append(chunk)
        elif chunk:
            flush()
            out.append(chunk)
    flush()
    return "".join(out)


def plain(text: str) -> str:
    """Already-clean text made safe for Kibana's Markdown. Each word is escaped with a
    backslash before the characters Kibana honours one before (see ``_ESCAPABLE``) and nothing
    else, since a backslash before any other character would show; ``&`` and ``<`` are written
    as the entities ``&amp;`` and ``&lt;`` (no HTML, no autolink bracket); and a word that could
    act without a backslash (a URL, ``www.``, a mail address, an ``@mention``, a script target:
    a colon cannot be escaped) is put in a code span that no backtick in it can close. Text that
    is only ``=`` signs (Kibana would read it as the underline of a heading above it, and has no
    backslash for ``=``) is put in a code span."""
    if _UNDERLINE.fullmatch(text):
        return fence(text, len(text))
    return join(pieces(text))


def escape(value: object, limit: int = MAX_VALUE) -> str:
    """Plain text for Kibana's Markdown (:func:`plain`): nothing in it acts as Markdown, HTML, a
    mention or a link, and no backslash shows in Kibana."""
    return plain(clean(value, limit))


_SCHEME = re.compile(r"\b([A-Za-z][A-Za-z0-9+.-]*)://")
_DEFANGED = {"http": "hxxp", "https": "hxxps", "ftp": "fxp"}


def defang(value: str) -> str:
    """A URL or address made harmless to copy: ``hxxps://example[.]com``. A scheme becomes
    ``hxxp``, ``hxxps`` or ``fxp`` (any other keeps its name and loses its ``://``), and a dot
    between letters or digits becomes ``[.]``."""

    def scheme(found: re.Match[str]) -> str:
        name = found.group(1)
        safe = _DEFANGED.get(name.lower())
        return f"{safe}://" if safe else f"{name}[://]"

    return re.sub(r"(?<=[A-Za-z0-9])\.(?=[A-Za-z0-9])", "[.]", _SCHEME.sub(scheme, value))


def fence(value: object, limit: int = MAX_VALUE) -> str:
    """A value in an inline code span that no backtick in it can close."""
    text = clean(value, limit)
    if not text:
        return "(empty)"
    ticks = "`" * (max((len(m) for m in _BACKTICKS.findall(text)), default=0) + 1)
    return f"{ticks} {text} {ticks}"


def log_value(value: object) -> str:
    """A value from the logs or the case's indicators: cleaned and fenced. An address, a domain
    or a URL is written plain in the code span, where nothing acts."""
    return fence(value)


def link(base: str, case_id: uuid.UUID | str) -> str:
    """ARGUS's own link to a case: the configured address and ``/go/case/<uuid>``."""
    if not _BASE.fullmatch(base):
        raise RenderError("web.public_url is not an address a link can use")
    try:
        parsed = uuid.UUID(str(case_id))
    except ValueError:
        raise RenderError("a link names a case by its uuid") from None
    return f"{base}/go/case/{parsed}"


def _case_link(params: Mapping[str, Any], ctx: Context) -> str:
    case = _uuid(params.get("case"))
    if params.get("link") != f"/go/case/{case}":
        raise RenderError("the payload's link is not this case's")
    return f"[Open this case in ARGUS]({link(ctx.link_base, case)})"


def _uuid(value: object) -> uuid.UUID:
    try:
        return uuid.UUID(str(value))
    except ValueError:
        raise RenderError("a template needs a case uuid") from None


def _int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise RenderError(f"{name} is a count")
    return value


def _strings(value: object, name: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise RenderError(f"{name} is a list of values")
    return list(value)


def _when(value: object) -> str:
    if value is None:
        return "not known"
    try:
        at = datetime.fromisoformat(str(value))
    except ValueError:
        raise RenderError("a time is an ISO time") from None
    if at.tzinfo is None:
        raise RenderError("a time has a time zone")
    local = at.astimezone(site.zone())
    return f"{local:%Y-%m-%d %H:%M} {site.zone_label(local)}"


def _person(who: object, ctx: Context) -> str:
    key = clean(who, 80)
    name = ctx.people.get(key)
    return f"{escape(name)} ({fence(key)})" if name else fence(key)


def _listed(label: str, values: list[str], more: int) -> str:
    if not values:
        return f"{label}: none recorded."
    shown = ", ".join(log_value(v) for v in values[:MAX_LISTED])
    rest = len(values) - MAX_LISTED if len(values) > MAX_LISTED else 0
    tail = f" and {rest + more} more" if rest + more else ""
    return f"{label} ({len(values) + more}): {shown}{tail}."


def description(params: Mapping[str, Any], ctx: Context) -> str:
    """The case's description (W1): what happened, which hosts and indicators, the first and
    latest alert, that decisions are made in ARGUS, and ARGUS's link."""
    known = {
        "case",
        "link",
        "what",
        "hosts",
        "more_hosts",
        "indicators",
        "more_indicators",
        "investigations",
        "first_alert",
        "latest_alert",
    }
    _only(params, known)
    hosts = _strings(params.get("hosts"), "hosts")
    marks = _strings(params.get("indicators"), "indicators")
    lines = [
        "**ARGUS opened this case.** Decisions about it are made in ARGUS, not in Kibana.",
        f"What happened: {escape(params.get('what'), 160)}.",
        _listed("Hosts", hosts, _int(params.get("more_hosts"), "more_hosts")),
        _listed("Indicators", marks, _int(params.get("more_indicators"), "more_indicators")),
        f"Investigations: {_int(params.get('investigations'), 'investigations')}."
        f" First alert: {_when(params.get('first_alert'))}."
        f" Latest alert: {_when(params.get('latest_alert'))}.",
        _case_link(params, ctx),
        "What logs showed stays in ARGUS: see logs there. Changes made here are kept, but they"
        " are not ARGUS's decisions.",
    ]
    return "\n\n".join(lines)


def _only(params: Mapping[str, Any], known: set[str]) -> None:
    extra = sorted(set(params) - known)
    if extra:
        raise RenderError(f"the template takes no {', '.join(extra)}")


def _by(params: Mapping[str, Any], ctx: Context, *names: str) -> list[str]:
    _only(params, set(names))
    missing = [n for n in names if n not in params]
    if missing:
        raise RenderError(f"the template needs {', '.join(missing)}")
    return [_person(params[n], ctx) for n in names]


def _taken(params: Mapping[str, Any], ctx: Context) -> str:
    (by,) = _by(params, ctx, "by")
    return f"Taken in ARGUS by {by}. They own the case now."


def _assigned(params: Mapping[str, Any], ctx: Context) -> str:
    to, by = _by(params, ctx, "to", "by")
    return f"Assigned in ARGUS to {to} by {by}."


def _released(params: Mapping[str, Any], ctx: Context) -> str:
    (by,) = _by(params, ctx, "by")
    return f"Released in ARGUS by {by}. ARGUS owns the case again."


def _contained(params: Mapping[str, Any], ctx: Context) -> str:
    (by,) = _by(params, ctx, "by")
    return f"Marked as contained in ARGUS by {by}, after a quiet window."


def _reopened(params: Mapping[str, Any], ctx: Context) -> str:
    (by,) = _by(params, ctx, "by")
    return f"Reopened in ARGUS by {by}."


def _new_activity(params: Mapping[str, Any], ctx: Context) -> str:
    _only(params, set())
    return "New activity was seen in ARGUS, so the case is open again."


def _severity(params: Mapping[str, Any], ctx: Context) -> str:
    _only(params, {"severity"})
    severity = params.get("severity")
    if severity not in SEVERITIES:
        raise RenderError("a severity is low, medium, high or critical")
    return f"ARGUS changed the severity to {severity}."


def _merged_in(params: Mapping[str, Any], ctx: Context) -> str:
    _only(params, {"source"})
    source = _uuid(params.get("source"))
    return (
        f"Another case ({fence(source)}) was merged into this one in ARGUS. Its alerts and"
        " indicators belong here now."
    )


def _closed(params: Mapping[str, Any], ctx: Context) -> str:
    _only(params, {"reason"})
    reason = params.get("reason")
    if reason not in REASONS:
        raise RenderError("a closure has one of the nine reasons")
    if not ctx.approvers or ctx.approved_at is None:
        raise RenderError("a closing comment names who approved it and when")
    names = " and ".join(f"{escape(a.name)} ({fence(a.username)})" for a in ctx.approvers)
    at = _when(ctx.approved_at.isoformat())
    return (
        f"Closed by ARGUS on the approval of {names}, {at}. Reason: {REASONS[reason]}"
        f" ({fence(reason)})."
    )


def _opened(params: Mapping[str, Any], ctx: Context) -> str:
    _only(params, {"case", "link", "alerts", "investigations"})
    return (
        f"ARGUS opened this case. {_int(params.get('alerts'), 'alerts')} alerts of"
        f" {_int(params.get('investigations'), 'investigations')} investigations are attached as"
        " examples (the first and the latest of each); the full record is in ARGUS."
        f" Decisions are made in ARGUS: {_case_link(params, ctx)}"
    )


def _corrected(params: Mapping[str, Any], ctx: Context) -> str:
    _only(params, {"what", "of"})
    what = params.get("what")
    if what not in ("update", "close"):
        raise RenderError("a correction undoes an update or a closure")
    ref = clean(params.get("of"), 120)
    approvers = " and ".join(f"{escape(a.name)} ({fence(a.username)})" for a in ctx.approvers)
    by = f" on the approval of {approvers}" if approvers else ""
    return (
        f"ARGUS corrected the earlier {'closure' if what == 'close' else 'change'}"
        f" ({fence(ref)}){by}: the case is as it was before it. The earlier comment stays."
    )


COMMENTS: dict[str, Callable[[Mapping[str, Any], Context], str]] = {
    "opened": _opened,
    "taken": _taken,
    "assigned": _assigned,
    "released": _released,
    "contained": _contained,
    "new_activity": _new_activity,
    "severity": _severity,
    "merged_in": _merged_in,
    "reopened": _reopened,
    "closed": _closed,
    "corrected": _corrected,
}


def comment(template: object, params: Mapping[str, Any], ctx: Context) -> str:
    """A comment: the template's fixed sentence, then the reference line."""
    build = COMMENTS.get(str(template))
    if build is None:
        raise RenderError(f"no comment template {clean(template, 40)!r}")
    text = build(params, ctx)
    if ctx.reference:
        text += f"\n\nARGUS reference: {fence(ctx.reference)}"
    return text
