"""Runbooks derived from the rules' own notes: no per-rule configuration.

A note's ``Investigation Steps`` (a numbered list) become steps. Each step names fields in
backticks and asks a kind of question: the stored alerts answer it (**answered**), a capability a
pack brings (**deferred**), a person (**manual**), or nothing because a named field is in none of
the alerts (**unknown**). Every step gets exactly one status and one plain sentence. Pure.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass

MAX_STEPS = 12
STEP_CHARS = 600
_HEADER = re.compile(r"^\s*(#{1,6}\s*|\*\*)?\s*investigation steps\b", re.IGNORECASE)
_OTHER_HEADER = re.compile(r"^\s*#{1,6}\s+\S")
_SUBHEADING = re.compile(r"^\s*\*\*[^*]+\*\*:?\s*$")  # a bold line between steps: skipped
_ITEM = re.compile(r"^\s*(\d{1,2})[.)]\s+(.*)$")
_FIELD = re.compile(r"`(@timestamp|[a-z_][a-z0-9_]*(?:\.[a-z0-9_]+)+)(?::[^`]*)?`")

# What answers a kind of question, if not the stored alerts. (capability, pack that brings it)
CAPABILITIES: dict[str, str] = {
    "reputation": "a threat-intelligence lookup",  # plain words for a reviewer
    "prevalence": "proxy-log statistics",
    "timeline": "proxy-log statistics",
    "log_pivot": "a search of the web and proxy logs",
}
_NEEDS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "reputation",
        re.compile(r"reputation|virustotal|abuseipdb|greynoise|threat.?intel|\bioc", re.IGNORECASE),
    ),
    ("timeline", re.compile(r"periodic|interval|beacon|regular|cadence|every \d", re.IGNORECASE)),
    (
        "prevalence",
        re.compile(
            r"how many|distinct|other (internal )?hosts|fan.?out|same (url|ip)", re.IGNORECASE
        ),
    ),
    (
        "log_pivot",
        re.compile(
            r"pivot|last \d+ ?h|filter the index|access log|\blogs?\b|200|"
            r"respon[sd]|returned",
            re.IGNORECASE,
        ),
    ),
)
_ACTION = re.compile(
    r"^\s*(\*\*)?\s*action\b|\b(block|notify|request|escalate|contact|tune|whitelist|"
    r"report it|add (it|them|known)|treat as|disable)\b",
    re.IGNORECASE,
)
_OWNER = re.compile(r"\bowner\b|\bwho\b|identify the (internal )?host", re.IGNORECASE)


# Top-level field sets of ECS and of this SIEM's sources: a backticked word under another root
# (``config.php.bak``) is text, unless the investigation's alerts have that root.
ROOTS = frozenset(
    {
        "agent",
        "client",
        "cloud",
        "container",
        "destination",
        "dns",
        "ecs",
        "email",
        "error",
        "event",
        "file",
        "group",
        "host",
        "http",
        "log",
        "network",
        "observer",
        "process",
        "related",
        "rule",
        "server",
        "service",
        "source",
        "threat",
        "tls",
        "url",
        "user",
        "user_agent",
        "vulnerability",
        "nginx",
        "squid",
        "postfix",
        "kibana",
    }
)


@dataclass(frozen=True)
class Step:
    number: int
    text: str
    fields: tuple[str, ...]


def note_hash(note: str | None) -> str:
    return hashlib.sha256((note or "").encode("utf-8")).hexdigest()


def steps(note: str | None, roots: frozenset[str] = frozenset()) -> list[Step]:
    """The numbered investigation steps of a note (under its ``Investigation Steps`` header,
    or every numbered line if it has none), numbered in order. A step continues on its
    following lines. Fields: backticked dotted names under ``ROOTS`` or ``roots``."""
    if not note:
        return []
    lines = note.splitlines()
    start = next((i + 1 for i, line in enumerate(lines) if _HEADER.match(line)), None)
    body = lines[start:] if start is not None else lines
    found: list[tuple[int, list[str]]] = []
    for line in body:
        if start is not None and _OTHER_HEADER.match(line) and not _ITEM.match(line):
            break
        if _SUBHEADING.match(line):
            continue
        item = _ITEM.match(line)
        if item:
            found.append((int(item.group(1)), [item.group(2)]))
        elif found and line.strip():
            found[-1][1].append(line.strip())
    known = ROOTS | roots
    result = []
    for position, (_, parts) in enumerate(found[:MAX_STEPS], start=1):
        text = " ".join(" ".join(parts).split())[:STEP_CHARS]
        names = (m.group(1) for m in _FIELD.finditer(text))
        fields = tuple(dict.fromkeys(n for n in names if n.split(".", 1)[0] in known))
        result.append(Step(position, text, fields))
    return result


def needs(text: str) -> list[str]:
    return [name for name, pattern in _NEEDS if pattern.search(text)]


def outcome(
    step: Step,
    facts: Mapping[str, Mapping[str, object]],
    answers: Mapping[str, str] | None = None,
    owner_known: bool = False,
) -> dict[str, object]:
    """The status and sentence of one step. ``facts`` maps field → {"distinct", "top"};
    ``answers`` maps a capability a module answered for this run to its sentence."""
    told = answers or {}
    shown = [f for f in step.fields if facts.get(f, {}).get("distinct")]
    missing = [f for f in step.fields if f not in shown]
    needed = needs(step.text)
    wanted = [n for n in needed if n not in told]
    module = [told[n] for n in needed if n in told]
    if wanted:
        status = "deferred"
        waits = sorted({CAPABILITIES[n] for n in wanted})
        sentence = "Not checked yet: needs " + " and ".join(waits) + "."
        if module:
            sentence += " " + " ".join(module)
    elif module:
        status, sentence = "answered", " ".join(module)
    elif _ACTION.search(step.text) and not shown:
        status, sentence = "manual", "For a person to decide or do."
    elif missing and not (owner_known and _OWNER.search(step.text)):
        status = "unknown"
        sentence = "Could not check: no alert has " + ", ".join(missing) + "."
    elif shown or (owner_known and _OWNER.search(step.text)):
        status = "answered"
        sentence = "Answered from the alerts" + (": see " + ", ".join(shown) if shown else "") + "."
    else:  # an action without a shown field was taken above
        status, sentence = "manual", "No field to check: for a person."
    return {
        "number": step.number,
        "text": step.text,
        "fields": list(step.fields),
        "shown": shown,
        "status": status,
        "sentence": sentence,
        "needs": wanted,
    }
