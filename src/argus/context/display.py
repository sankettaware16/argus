"""The display registry and the digest (plan §5.4, D-058).

``config/signals.yaml`` says how each signal reads: a label, a sentence, one line on how to
read it. The digest is a bounded, deterministic text of a dossier: what the Inbox shows
first and, in Phase 2, the only input a model gets. It is computed when shown, from the
dossier and the registry, so rewording a label never changes a dossier's hash.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

from argus import site

REGISTRY = Path(__file__).resolve().parents[3] / "config" / "signals.yaml"
DIGEST_CHARS = 4800  # ≈ 1,200 tokens


class Entry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    label: str = Field(min_length=1, max_length=80)
    sentence: str = Field(min_length=1, max_length=200)
    how_to_read: str = Field(min_length=1, max_length=300)

    def title(self, part: str = "values") -> str:
        """The label for a family's last name part; ``{lookups}`` is the site's looked-up
        threat-intel sources, by index."""
        return self.label.format(part=PARTS.get(part, part), lookups=lookup_words())

    def said(self, value: Any) -> str:
        return self.sentence.format(value=value, lookups=lookup_words())


def lookup_words() -> str:
    """The site's looked-up threat-intel sources by index, for a label or a sentence."""
    return ", ".join(s.index for s in site.active().ti_lookups) or "the threat-intel lookup"


# What a family's last name part (``entities.ip``) is called in a label: "{part}".
PARTS = {"ip": "IP addresses", "domain": "domains", "host": "host names", "user": "users",
         "url": "URLs", "hash": "file hashes"}  # fmt: skip


@lru_cache(maxsize=4)
def registry(path: Path = REGISTRY) -> dict[str, Entry]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {str(name): Entry.model_validate(entry) for name, entry in raw.items()}


def entry(name: str, entries: Mapping[str, Entry] | None = None) -> Entry | None:
    found = registry() if entries is None else entries
    if name in found:
        return found[name]
    family = name.rsplit(".", 1)[0] + ".*" if "." in name else None
    return found.get(family) if family else None


def sentence(signal: Mapping[str, Any], entries: Mapping[str, Entry] | None = None) -> str:
    """One plain line for a signal; an unknown one says it could not be told."""
    name = str(signal["name"])
    e = entry(name, entries)
    part = name.rsplit(".", 1)[-1]
    label = e.title(part) if e else name
    if signal.get("status") != "known":
        reason = str(signal.get("unknown_reason") or "unknown").replace("_", " ")
        return f"{label}: could not be told ({reason})"
    value = signal.get("value")
    shown = "yes" if value is True else "no" if value is False else value
    text = e.said(shown) if e else f"{shown}"
    if signal.get("completeness") == "lower_bound":
        text = "at least " + text
    return f"{label}: {text}"


def digest(dossier: Mapping[str, Any], entries: Mapping[str, Entry] | None = None) -> str:
    """The dossier in plain text, at most ``DIGEST_CHARS``: headline, steps, facts, signals."""
    body = dossier.get("body", dossier)
    facts = body.get("facts", {})
    report = body.get("report", {})
    pack = body.get("context", {}).get("pack", {})
    lines = [
        f"Rule: {facts.get('rule_name') or facts.get('rule_id')}",
        f"{facts.get('alert_count')} alerts from {facts.get('first_event_at')} to"
        f" {facts.get('last_event_at')} (UTC); key {facts.get('group_key')}",
        f"Severity {facts.get('severity')}, risk {facts.get('risk_score')}",
    ]
    steps = report.get("steps") or []
    if steps:
        lines.append("What ARGUS checked (the rule's investigation steps):")
        for step in steps:
            lines.append(f"{step['number']}. [{step['status']}] {step['text'][:160]}")
            lines.append(f"   {step['sentence']}")
    elif report:
        lines.append("The rule's note has no investigation steps.")
    fields = pack.get("fields", {})
    if fields:
        lines.append("Key facts:")
        for path, fact in list(fields.items())[:12]:
            top = ", ".join(f"{v} ({n})" for v, n in fact["top"][:4])
            lines.append(f"- {path}: {fact['distinct']} distinct: {top}")
    for signal in [*body.get("local_signals", []), *body.get("signals", [])]:
        lines.append("- " + sentence(signal, entries))
    text = "\n".join(lines)
    return text if len(text) <= DIGEST_CHARS else text[: DIGEST_CHARS - 1] + "…"


FEW = 3  # a named field enters a pattern's signature only with at most this many values


def signature(
    rule_id: str, key_fields: Sequence[str], body: Mapping[str, Any]
) -> tuple[tuple[Any, ...], list[tuple[str, list[str]]]]:
    """What an investigation has in common with others it can be decided with (plan §5.4):
    the rule, each step's outcome, a threat-list hit, and the values of the fields the rule's
    own steps name (when an investigation has few of them), not counting its grouping key
    (D-072). Returns the signature and the shared values, to show."""
    report = body.get("report") or {}
    steps = report.get("steps") or []
    statuses = tuple((s.get("number"), s.get("status")) for s in steps)
    signals = [*body.get("local_signals", []), *body.get("signals", [])]
    listed = any(s.get("name") == "ti.listed" and (s.get("value") or 0) > 0 for s in signals)
    facts = ((body.get("context") or {}).get("pack") or {}).get("fields") or {}
    named = sorted({f for s in steps for f in s.get("fields", [])} - set(key_fields))
    common = []
    for name in named:
        fact = facts.get(name) or {}
        values = sorted(str(v) for v, _ in fact.get("top", []))
        if values and fact.get("distinct", 0) <= FEW:
            common.append((name, values))
    return (rule_id, statuses, listed, tuple((f, tuple(v)) for f, v in common)), common
