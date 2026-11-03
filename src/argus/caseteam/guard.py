"""The guardian of an outgoing comment (AR8, D-158): the last check before a word reaches Kibana.

The renderers (:mod:`argus.caseteam.render`) already make every value safe: a value from a log, a
report or a person is cleaned, defanged and fenced in a code span, and a sentence is escaped
(every ASCII punctuation character backslash-escaped). This check does not trust that: it reads
the finished text the way a Markdown reader would and **refuses** it (nothing is sent, the step is
held for a person) if anything outside a code span could act:

* a control, bidirectional or zero-width character (tab and newline are text);
* a length over Kibana's limit (counted in UTF-16 units, as Kibana counts);
* an HTML tag or entity-opening ``<``, a block quote, a raw ``[`` or ``]``;
* a link or an image whose target is not one of the addresses ARGUS builds (its own link, Kibana's
  Discover), a URL scheme, ``www.`` or a ``javascript:`` target in plain text;
* an ``@mention``;
* a code span or a fence that is not closed (it would swallow what follows);
* a code span inside ``**bold**``, ``__bold__`` or ``~~strike~~``: Kibana's parser (remark-parse 8,
  not CommonMark) finds the end of those by scanning raw characters, code spans included, so a
  value in a span could end the bold early and leave the rest of the span live (D-244);
* a table row whose cells are not as many as the table's header: Kibana ends a cell at every pipe
  that no backslash protects, one inside a code span included (D-244);
* a line of ``=`` or ``-`` signs alone (the underline of a heading, or a rule).

One thing is let through whole: a line that is exactly one embedded chart (AR10, ``!{lens{...}}``)
that :func:`argus.caseteam.lens.problems` accepts (plain strings only, one ad hoc data view over a
space's alerts index, a filter on the incident's tag). A ``!{lens`` anywhere else is refused.

Counts, times and lists are filled in by code (the renderers' inputs are the stored report's
fields), so the guardian has no number to check: what it holds is the text's safety.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from urllib.parse import urlsplit

from argus.caseteam import lens
from argus.gateway.kibana.models import MAX_TEXT, utf16_len
from argus.writer.render import _UNSAFE

LIMIT = MAX_TEXT  # Kibana's comment limit; renderers keep under SPLIT_AT with room to spare
_PUNCT = frozenset("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")  # what a backslash may escape
_LINK = re.compile(r"(!?)\[([^\]\n]{0,300})\]\(([^)\s]{1,8000})\)")
# A fence of backticks takes no backtick in the rest of its line (Kibana's reader: a line that
# opens with three or more and holds another is a paragraph with a code span, as a value of ARGUS's
# with two backticks in it makes).
_FENCE = re.compile(r"^ {0,3}(`{3,}(?=[^`]*$)|~{3,})")
_MENTION = re.compile(r"(?<![\w\\])@[A-Za-z0-9_]")
_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://|\bwww\.|\b(?:javascript|vbscript|data):", re.I)
_ALIGN = re.compile(r"^:?-+:?$")  # a cell of a table's alignment row
_RULE = re.compile(r"(?m)^ {0,3}(?:=+|-{2,}|\*{3,}|_{3,})[ \t]*$")  # a heading underline or a rule


def _origin(url: str) -> tuple[str, str, int, str] | None:
    """(scheme, host, port, path) of an http(s) address with no user information, else None
    (the port is the scheme's default when the address names none; a port that is not a number
    is no address)."""
    try:
        parts = urlsplit(url)
        port = parts.port
        host = parts.hostname
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not host or "@" in parts.netloc:
        return None
    return parts.scheme, host.lower(), port or (443 if parts.scheme == "https" else 80), parts.path


def link_allowed(target: str, allowed: Sequence[str]) -> bool:
    """Whether ``target`` is an address ARGUS builds: the scheme, host and port of one of the
    ``allowed`` addresses exactly (parsed, never compared as text: ``:5601.evil.com``, ``@evil.com``
    and ``:56010`` are other addresses), and a path under that address's path."""
    got = _origin(target)
    if got is None:
        return False
    for prefix in allowed:
        want = _origin(prefix) if prefix else None
        if want is None or got[:3] != want[:3]:
            continue
        base = want[3]
        if base.endswith("/"):  # a directory: the path is under it (not the directory itself)
            under = got[3].startswith(base)
        else:
            under = got[3] == base or got[3].startswith(base + "/")
        if under:
            return True
    return False


class GuardRefusal(ValueError):  # noqa: N818 - a refusal, not an error
    """The text must not be sent; ``reasons`` say why, in words."""

    def __init__(self, reasons: Sequence[str]) -> None:
        super().__init__("; ".join(reasons))
        self.reasons = tuple(reasons)


def _unfenced(text: str, problems: list[str]) -> list[str]:
    """The lines of the text outside fenced blocks (what is inside them is data), with an
    embedded chart checked whole; a fence that is not closed is a problem."""
    kept: list[str] = []
    fence: str | None = None
    for line in text.split("\n"):
        found = _FENCE.match(line)
        if fence is None:
            if found is not None:
                fence = found.group(1)
                continue
            if line.startswith(lens.PREFIX):  # AR10: an embedded chart is checked whole, or refused
                problems.extend(lens.problems(line))
                continue
            kept.append(line)
        elif (
            found is not None
            and found.group(1)[0] == fence[0]
            and len(found.group(1)) >= len(fence)
            and line.strip() == found.group(1)
        ):
            fence = None
    if fence is not None:
        problems.append("a code fence is not closed")
    return kept


def _code_end(text: str, start: int) -> int:
    """Where the inline code span that opens at ``start`` (a backtick) ends, after its closing
    run of as many backticks; -1 when no run of that length closes it."""
    n = len(text)
    end = start
    while end < n and text[end] == "`":
        end += 1
    size, k = end - start, end
    while True:
        k = text.find("`", k)
        if k < 0:
            return -1
        e = k
        while e < n and text[e] == "`":
            e += 1
        if e - k == size:
            return e
        k = e


def _scan(line: str, problems: list[str]) -> str:
    """One line as a Markdown reader sees it outside code: a backslash and the punctuation it
    escapes are dropped (an escaped backtick opens nothing), and an inline code span is dropped
    with its content; a run of backticks with no closing run of its own length is a problem."""
    out: list[str] = []
    i, n = 0, len(line)
    while i < n:
        c = line[i]
        if c == "\\" and i + 1 < n and line[i + 1] in _PUNCT:
            out.append("  ")
            i += 2
        elif c == "`":
            end = _code_end(line, i)
            if end < 0:
                problems.append("a code span is not closed")
                while i < n and line[i] == "`":
                    i += 1
            else:
                out.append(" ")
                i = end
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _closer(text: str, start: int, mark: str) -> int:
    """Where remark-parse 8 ends ``**``, ``__`` or ``~~`` that opened just before ``start``: the
    next two of the mark, found by scanning raw characters (code spans are not skipped; a
    backslash skips a character in bold, not in strike-through); -1 when none."""
    n, j = len(text), start
    while j < n:
        if (
            text[j] == mark
            and text[j + 1 : j + 2] == mark
            and (mark == "~" or text[j + 2 : j + 3] != mark)
        ):
            return j
        if mark != "~" and text[j] == "\\":
            j += 1
        j += 1
    return -1


def _span_in_emphasis(text: str) -> bool:
    """Whether a code span lies between an unfenced ``**``, ``__`` or ``~~`` and the place
    Kibana ends it: then the span could be cut, or a ``**`` inside it could end the bold."""
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "\\" and i + 1 < n:
            i += 2
        elif c == "`":
            end = _code_end(text, i)
            while i < n and text[i] == "`":
                i += 1
            if end > 0:
                i = end
        elif c in "*_~" and text[i + 1 : i + 2] == c and (c == "~" or text[i + 2 : i + 3] != c):
            close = _closer(text, i + 2, c)
            if close < 0:
                i += 2
            elif "`" in text[i + 2 : close]:
                return True
            else:
                i = close + 2
        else:
            i += 1
    return False


def _cells(row: str) -> list[str]:
    """The cells of a table row as remark-parse 8 splits it: every pipe that no backslash
    protects ends a cell (a backslash takes the next character with it; a pipe inside a code span
    is still a pipe); a leading pipe starts the row; text after the last pipe is one more cell."""
    cells: list[str] = []
    now: list[str] = []
    started, i, n = False, 0, len(row)
    while i < n:
        c = row[i]
        if c == "\\" and i + 1 < n:
            now.append(row[i : i + 2])
            i += 2
            continue
        if c == "|":
            if started:
                cells.append("".join(now).strip())
            started = True
            now = []
        elif c not in " \t" or now:
            started = True
            now.append(c)
        i += 1
    if "".join(now).strip():
        cells.append("".join(now).strip())
    return cells


def _tables(lines: list[str], problems: list[str]) -> tuple[list[list[str]], set[int]]:
    """The cells of every table row in the lines, and which lines are rows. A row of another
    width than the table's header is a problem (a pipe in a value, or one that no backslash
    protects, would split it). A line that follows a table's rows and holds a pipe is a row too:
    Kibana reads it as one."""
    found: list[list[str]] = []
    rows: set[int] = set()
    i = 0
    while i < len(lines):
        head = _cells(lines[i]) if "|" in lines[i] else []
        under = _cells(lines[i + 1]) if i + 1 < len(lines) and "|" in lines[i + 1] else []
        if not head or not under or not all(_ALIGN.match(c) for c in under):
            i += 1
            continue
        width = len(head)
        if len(under) != width:
            problems.append("a table whose header and alignment rows differ in width")
        found.append(head)
        rows.update((i, i + 1))
        i += 2
        while i < len(lines) and "|" in lines[i][1:]:
            cells = _cells(lines[i])
            if not lines[i].startswith("|"):
                problems.append("a line right after a table that Kibana would read as a row of it")
            elif len(cells) != width:
                problems.append(f"a table row of {len(cells)} cells under a header of {width}")
            found.append(cells)
            rows.add(i)
            i += 1
    return found, rows


def _emphasis(
    lines: list[str], tables: list[list[str]], rows: set[int], problems: list[str]
) -> None:
    """Refuse a code span inside bold or strike-through. Each paragraph is read whole (Kibana
    may end bold on a later line of it) and each table cell on its own."""
    units = [cell for cells in tables for cell in cells if cell]
    paragraph: list[str] = []
    for i, line in enumerate([*lines, ""]):
        if i in rows or line.strip() == "":
            if paragraph:
                units.append("\n".join(paragraph))
            paragraph = []
        else:
            paragraph.append(line)
    if any(_span_in_emphasis(u) for u in units):
        problems.append("a code span inside bold or strike-through (Kibana would cut it)")


def check(text: str, allowed: Sequence[str] = ()) -> None:
    """Raise :class:`GuardRefusal` unless ``text`` is safe to send as a case comment (or a
    description). ``allowed``: the address prefixes a link may point to."""
    problems: list[str] = []
    if not text.strip():
        raise GuardRefusal(["the text is empty"])
    if utf16_len(text) > LIMIT:
        problems.append(f"{utf16_len(text)} characters is over Kibana's {LIMIT}")
    if any(ch not in "\n\t" and _UNSAFE.match(ch) for ch in text):
        problems.append("a control, bidirectional or zero-width character")
    lines = _unfenced(text, problems)
    tables, rows = _tables(lines, problems)
    _emphasis(lines, tables, rows, problems)
    if _RULE.search("\n".join(lines)):
        problems.append("a line of '=' or '-' signs alone (a heading underline or a rule)")
    body = "\n".join(_scan(line, problems) for line in lines)

    def link(found: re.Match[str]) -> str:
        target = found.group(3)
        if found.group(1):
            problems.append("an image")
        elif not link_allowed(target, allowed):
            problems.append("a link to an address ARGUS does not build")
        elif any(c in target for c in "<>\"'`\\"):
            problems.append("a link target with a character that can break out of it")
        return " "

    body = _LINK.sub(link, body)
    if "<" in body:
        problems.append("a raw '<' (HTML)")
    if re.search(r"(?m)^ {0,3}>", body):
        problems.append("a block quote")
    if "[" in body or "]" in body:
        problems.append("a raw bracket (a link or a reference outside a code span)")
    if _MENTION.search(body):
        problems.append("an @mention outside a code span")
    if _SCHEME.search(body):
        problems.append("a URL, 'www.' or a script target in plain text")
    if lens.PREFIX in body:
        problems.append("a chart block that is not alone on its line")
    if problems:
        raise GuardRefusal(list(dict.fromkeys(problems)))
