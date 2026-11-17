"""From what ``argus discover`` read to a proposed ``site`` section: pure, so the same
inputs give the same proposal and the tests need no Elasticsearch.

``Inputs`` holds the answers (None where a read was not made or failed, with the reason among
the warnings); ``propose`` classifies each candidate family (``classify``), names the fields,
works out the retention and the alerts index of each Kibana space, and returns a ``Proposal``
that renders as YAML (``render_yaml``) and as a report with the evidence (``render_text``).
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import yaml

from argus.discover import classify
from argus.discover.classify import Candidate, Confidence, Retention, Typed, Verdict
from argus.site import (
    ALERTS_INDEX_DEFAULT,
    DEFAULT_IGNORE_ABOVE,
    FIELD_ROLES,
    MAX_TI_SOURCES,
    MIN_IGNORE_ABOVE,
    KibanaFeatures,
    LicenceFacts,
    LogFamily,
    Role,
    SiteSettings,
    TiSource,
    VersionRange,
    feature_ids,
    parse_version,
    strip_keyword,
)

ALERTS_PREFIX = ".alerts-security.alerts-"
MAX_UNCLASSIFIED = 25  # names listed of the candidates that look like no role
MAX_SHOWN = 5  # names listed of the candidates left out as unreadable
_SPACE_ID = re.compile(r"[a-z0-9_-]{1,64}")


def safe(text: object, limit: int = 120) -> str:
    """Text from the SIEM made fit to print and to put in a YAML comment: control characters
    (an escape sequence, a carriage return, a newline) and other invisible ones become ``?``,
    and it is cut at ``limit`` characters. Index names and versions are the SIEM's, not ours."""
    cleaned = "".join(
        "?" if unicodedata.category(char).startswith("C") or char in "\u2028\u2029" else char
        for char in str(text)
    )
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 1] + "…"


@dataclass(frozen=True)
class Inputs:
    """What the reads returned. A part that was not read is None (and a warning says why)."""

    elastic_version: str | None = None
    kibana_version: str | None = None
    licence: tuple[str, str] | None = None
    data: Mapping[str, Any] | None = None  # discover.indices, scope data
    alerts: Mapping[str, Any] | None = None  # discover.indices, scope alerts
    spaces: Sequence[Mapping[str, str]] | None = None  # kibana.spaces
    features: Sequence[Mapping[str, str]] | None = None  # kibana.features
    mappings: Mapping[str, Mapping[str, Typed]] = field(default_factory=dict)  # by pattern
    ilm: Mapping[str, Any] | None = None  # discover.ilm
    warnings: tuple[str, ...] = ()
    requests: int = 0
    now: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True)
class FamilyProposal:
    """One proposed family with what decided it."""

    family: LogFamily
    confidence: Confidence
    score: int
    evidence: tuple[str, ...]
    notes: tuple[str, ...]
    retention: Retention
    kind: str  # daily, stream or alias


@dataclass(frozen=True)
class TiProposal:
    """One proposed threat-intel source with what decided it."""

    source: TiSource
    evidence: tuple[str, ...]
    notes: tuple[str, ...]


@dataclass(frozen=True)
class Proposal:
    families: tuple[FamilyProposal, ...]
    unclassified: tuple[str, ...]
    unclassified_count: int
    space: str | None
    space_evidence: str
    alerts_aliases: tuple[str, ...]
    spaces: tuple[str, ...]
    features: KibanaFeatures | None
    elastic_version: str | None
    kibana_version: str | None
    licence: LicenceFacts | None
    history_window: str | None  # a suggestion for history.window (days), not part of site
    warnings: tuple[str, ...]
    requests: int
    now: datetime
    listing_read: bool = True  # False: the index listing failed, there is nothing to propose from
    ti_sources: tuple[TiProposal, ...] = ()

    def site(self) -> SiteSettings:
        """The proposal as a site profile (what the settings would load from the YAML)."""
        return SiteSettings.model_validate(self.section())

    def section(self) -> dict[str, Any]:
        """The ``site`` section as plain data, only what differs from the defaults."""
        out: dict[str, Any] = {}
        if self.space is not None and self.space != SiteSettings().space:
            out["space"] = self.space
        if self.features is not None and self.features != KibanaFeatures():
            out["kibana_features"] = {
                "security": self.features.security,
                "cases": self.features.cases,
            }
        out["families"] = [family_entry(p.family) for p in self.families]
        if self.ti_sources:
            out["ti_sources"] = [ti_entry(t.source) for t in self.ti_sources]
        return out


def ti_entry(source: TiSource) -> dict[str, str]:
    """A threat-intel source as the YAML entry that makes it."""
    return {"index": source.index, "schema": source.schema_, "mode": source.mode}


def family_entry(family: LogFamily) -> dict[str, Any]:
    """A family as the YAML entry that makes it (default values left out)."""
    entry: dict[str, Any] = {"role": family.role.value}
    if family.name != family.role.value:
        entry["name"] = family.name
    entry["pattern"] = family.pattern
    if family.time_field != "@timestamp":
        entry["time_field"] = family.time_field
    if not family.watch:
        entry["watch"] = False
    if family.fields:
        entry["fields"] = dict(family.fields)
    if family.ignore_above != DEFAULT_IGNORE_ABOVE:
        entry["ignore_above"] = family.ignore_above
    return entry


# ----------------------------------------------------------------------------- the proposal


def _unique_name(role: Role, pattern: str, taken: set[str]) -> str:
    """The role's name for the first family of a role; the best product word of the pattern
    (``nginx``) or ``<role>_<n>`` for the next ones."""
    if role.value not in taken:
        return role.value
    hints = classify.NAME_HINTS.get(role, {})
    for word in sorted(classify.words(pattern), key=lambda w: (-hints.get(w, 0), w)):
        if hints.get(word) and re.fullmatch(r"[a-z][a-z0-9_]{0,31}", word) and word not in taken:
            return word
    n = 2
    while f"{role.value}_{n}" in taken:
        n += 1
    return f"{role.value}_{n}"


def _limit(mapped: Mapping[str, Typed] | None, entries: Mapping[str, str], role: Role) -> int:
    """The family's ``ignore_above``: the smallest limit the mapping gives the keyword fields the
    evidence queries (the fields of the proposal and the role's defaults); none when it gives none
    or the same as the default."""
    if not mapped:
        return DEFAULT_IGNORE_ABOVE
    queried = {strip_keyword(name) for name in {**FIELD_ROLES[role], **entries}.values()}
    limits = [t.ignore_above for path, t in mapped.items() if path in queried and t.ignore_above]
    return max(min(limits, default=DEFAULT_IGNORE_ABOVE), MIN_IGNORE_ABOVE)


def _present(mapped: Mapping[str, Typed]) -> set[str]:
    return set(mapped)


def _delete_after(candidate: Candidate, ilm: Mapping[str, Any] | None) -> str | None:
    """The delete age of the ILM policy that manages the candidate's stream or indices."""
    if not ilm:
        return None
    names = {candidate.pattern, *candidate.backing, *candidate.indices}
    for policy in ilm.values():
        if not isinstance(policy, Mapping):
            continue
        used = {*policy.get("data_streams", ()), *policy.get("indices", ())}
        if names & used and policy.get("delete_after"):
            return str(policy["delete_after"])
    return None


def _days_of(age: str | None) -> int | None:
    match = re.fullmatch(r"(\d+)([dhm])", age or "")
    if match is None:
        return None
    n, unit = int(match[1]), match[2]
    return n if unit == "d" else max(n // 24, 1) if unit == "h" else None


def propose(inputs: Inputs) -> Proposal:
    warnings = list(inputs.warnings)
    examined = dict(inputs.mappings)
    proposals: list[FamilyProposal] = []
    unclassified: list[str] = []
    taken: set[str] = set()
    if inputs.data is None:
        warnings.append("no index listing was read: no log family can be proposed")
    skipped: list[str] = []
    found = classify.candidates(inputs.data or {}, skipped)
    ti_found, consumed = _threat_intel(found, examined, warnings)
    for candidate in found:
        if candidate.pattern in consumed:
            continue
        mapped = examined.get(candidate.pattern)
        verdict: Verdict = classify.classify(candidate.pattern, _present(mapped or {}))
        if verdict.role is None:
            unclassified.append(candidate.pattern)
            continue
        entries, notes = classify.field_names(verdict.role, mapped or {})
        assert verdict.best is not None
        if mapped is not None and verdict.best.field_points == 0:
            notes = [
                f"the mapping has none of the fields a {verdict.role.value} family usually has:"
                " the field names are the ECS ones, check them",
                *notes,
            ]
        if mapped is None:
            notes = ["the mapping was not read: the field names are the ECS ones", *notes]
            time, why = (candidate.time_field or "@timestamp"), "the mapping was not read"
        else:
            time, why = classify.time_field(candidate, mapped)
        name = _unique_name(verdict.role, candidate.pattern, taken)
        try:
            family = LogFamily(
                name=name,
                role=verdict.role,
                pattern=candidate.pattern,
                time_field=time,
                fields=entries,
                watch=verdict.role is not Role.AUTH,
                ignore_above=_limit(mapped, entries, verdict.role),
            )
        except ValueError as exc:
            warnings.append(
                f"{safe(candidate.pattern, 60)}: left out, {safe(str(exc).splitlines()[0], 100)}"
            )
            continue
        taken.add(name)
        retention = classify.retention_of(candidate, _delete_after(candidate, inputs.ilm))
        proposals.append(
            FamilyProposal(
                family,
                verdict.confidence,
                verdict.best.total,
                (*verdict.evidence, f"event time: {time} ({why})"),
                tuple(notes),
                retention,
                candidate.kind,
            )
        )
    if skipped:
        shown = ", ".join(safe(name, 60) for name in skipped[:MAX_SHOWN])
        more = f" and {len(skipped) - MAX_SHOWN} more" if len(skipped) > MAX_SHOWN else ""
        warnings.append(
            f"{len(skipped)} names were left out: not a name a log family can have (lowercase"
            f" letters, digits and . _ + -, daily ones with a real date): {shown}{more}"
        )
    proposals.sort(key=lambda p: (-classify.RANK[p.confidence], -p.score, p.family.name))
    space, space_why, aliases, spaces = _space(inputs, warnings)
    features = feature_ids(list(inputs.features)) if inputs.features is not None else None
    licence = LicenceFacts(*inputs.licence) if inputs.licence else None
    warnings += _version_warnings(inputs)
    if licence is not None and not licence.active:
        warnings.append(
            f"the licence is {licence.level}/{licence.status}: ARGUS reads, but writes need an"
            " active licence"
        )
    return Proposal(
        families=tuple(proposals),
        unclassified=tuple(unclassified[:MAX_UNCLASSIFIED]),
        unclassified_count=len(unclassified),
        space=space,
        space_evidence=space_why,
        alerts_aliases=aliases,
        spaces=spaces,
        features=features,
        elastic_version=inputs.elastic_version,
        kibana_version=inputs.kibana_version,
        licence=licence,
        history_window=_history_window(proposals),
        warnings=tuple(warnings),
        requests=inputs.requests,
        now=inputs.now,
        listing_read=inputs.data is not None,
        ti_sources=ti_found,
    )


def _threat_intel(
    found: Sequence[Candidate], examined: Mapping[str, Mapping[str, Typed]], warnings: list[str]
) -> tuple[tuple[TiProposal, ...], set[str]]:
    """(the threat-intel sources the mappings show, the candidates they use up). The data streams
    of Elastic's Threat Intel integration are one source, named by their pattern
    (``logs-ti_*``), when the first of them that was examined is an ECS source; any other index
    that maps ``ioc_value`` (or ECS ``threat.indicator.type`` and a name that says threat
    intel) is one source of its own. Every source is asked per value (``lookup``): how big it
    is, a read cannot tell, and a person sets ``mirror`` for a small one."""
    groups: dict[str, list[Candidate]] = {}
    proposals: list[TiProposal] = []
    consumed: set[str] = set()
    for candidate in found:
        group = classify.ti_group(candidate.pattern) if candidate.kind == "stream" else None
        if group is not None:
            groups.setdefault(group, []).append(candidate)
    for group, members in groups.items():
        rep = next((m for m in members if m.pattern in examined), None)
        verdict = classify.ti_verdict(rep.pattern, examined[rep.pattern]) if rep else None
        if rep is None or verdict is None or verdict.schema != "ecs":
            continue
        index = group if len(members) > 1 else rep.pattern
        extra = f"{len(members)} data streams match {group}" if len(members) > 1 else ""
        made = _ti(index, "ecs", (*verdict.evidence, extra), verdict.notes)
        if made is not None:
            proposals.append(made)
            consumed.update(m.pattern for m in members)
    for candidate in found:
        mapped = examined.get(candidate.pattern)
        if mapped is None or candidate.pattern in consumed:
            continue
        verdict = classify.ti_verdict(candidate.pattern, mapped)
        if verdict is None:
            continue
        if verdict.schema is None:
            warnings.append(f"{safe(candidate.pattern, 60)}: {verdict.notes[0]}")
            continue
        made = _ti(candidate.pattern, verdict.schema, verdict.evidence, verdict.notes)
        if made is not None:
            proposals.append(made)
            consumed.add(candidate.pattern)
    if len(proposals) > MAX_TI_SOURCES:
        warnings.append(
            f"{len(proposals)} threat-intel sources were found: the first {MAX_TI_SOURCES} are"
            " proposed (a site names at most that many)"
        )
    return tuple(proposals[:MAX_TI_SOURCES]), consumed


def _ti(
    index: str, schema: str, evidence: Sequence[str], notes: Sequence[str]
) -> TiProposal | None:
    try:
        source = TiSource.model_validate({"index": index, "schema": schema, "mode": "lookup"})
    except ValueError:  # a name the setting does not take (candidates are checked: not expected)
        return None
    return TiProposal(source, tuple(e for e in evidence if e), tuple(notes))


def _space(
    inputs: Inputs, warnings: list[str]
) -> tuple[str | None, str, tuple[str, ...], tuple[str, ...]]:
    """(the space to propose, why, the alerts aliases found, the Kibana spaces)."""
    found = sorted(
        a["name"]
        for a in (inputs.alerts or {}).get("aliases", [])
        if isinstance(a, Mapping)
        and isinstance(a.get("name"), str)
        and a["name"].startswith(ALERTS_PREFIX)
    )
    # a space id is lowercase letters, digits, _ and -: another suffix is no space to propose
    aliases = tuple(a for a in found if _SPACE_ID.fullmatch(a.removeprefix(ALERTS_PREFIX)))
    if len(aliases) < len(found):
        warnings.append(
            f"{len(found) - len(aliases)} alerts aliases were left out: their space id is not"
            " lowercase letters, digits, _ and -"
        )
    # the busiest space first: the one with the most alerts indices (rolled over the most), so a
    # space holding a test rule's few alerts is not proposed over the one the SOC works in
    backing = {
        str(a.get("name")): len(a.get("indices") or [])
        for a in (inputs.alerts or {}).get("aliases", [])
        if isinstance(a, Mapping)
    }
    with_alerts = [
        a.removeprefix(ALERTS_PREFIX)
        for a in sorted(aliases, key=lambda n: (-backing.get(n, 0), n))
    ]
    spaces = tuple(
        s["id"]
        for s in inputs.spaces or []
        if isinstance(s, Mapping) and isinstance(s.get("id"), str) and _SPACE_ID.fullmatch(s["id"])
    )
    if inputs.alerts is None:
        warnings.append("the alerts indices were not read: the space is not proposed")
        return None, "", aliases, spaces
    if not with_alerts:
        warnings.append(f"no {ALERTS_PREFIX}<space> index exists: no Security alerts yet?")
        return None, "no alerts index was found", aliases, spaces
    if spaces:
        count = {a.removeprefix(ALERTS_PREFIX): backing.get(a, 0) for a in aliases}
        # the busiest first; a tie keeps Kibana's own order of the spaces
        both = sorted((s for s in spaces if s in with_alerts), key=lambda s: -count.get(s, 0))
        if not both:
            warnings.append(
                "no Kibana space has a Security alerts index (spaces: " + ", ".join(spaces) + ")"
            )
            return None, "", aliases, spaces
        chosen = both[0]
        why = f"{ALERTS_PREFIX}{chosen} exists and Kibana has the space"
        if len(both) > 1:
            warnings.append(
                f"{len(both)} spaces have alerts ({', '.join(both)}): {chosen}, the one with the"
                " most alerts indices, is proposed; ARGUS reads one space (change it in Settings)"
            )
        return chosen, why, aliases, spaces
    chosen = with_alerts[0]
    why = f"{ALERTS_PREFIX}{chosen} exists (Kibana's spaces were not read)"
    if len(with_alerts) > 1:
        warnings.append(
            f"{len(with_alerts)} alerts indices ({', '.join(with_alerts)}): {chosen} is proposed"
        )
    return chosen, why, aliases, spaces


def _version_warnings(inputs: Inputs) -> list[str]:
    out = []
    default = VersionRange.parse(SiteSettings().elastic_versions)
    for what, version in (
        ("Elasticsearch", inputs.elastic_version),
        ("Kibana", inputs.kibana_version),
    ):
        if version is None:
            continue
        if parse_version(version) is None:
            out.append(f"{what}'s version {version[:20]!r} is not a version number")
        elif not default.allows(version):
            out.append(
                f"{what} {version} is outside {default}, the versions ARGUS is written for: set"
                " site.elastic_versions / site.kibana_versions to accept it"
            )
    return out


def _history_window(proposals: Sequence[FamilyProposal]) -> str | None:
    """A history.window no deeper than the shortest retention found (days), or None."""
    kept = []
    for p in proposals:
        days = _days_of(p.retention.delete_after) or p.retention.days_kept
        if days:
            kept.append(days)
    return f"{min(kept)}d" if kept else None


# ----------------------------------------------------------------------------- rendering


def _indent(text: str, by: int) -> str:
    pad = " " * by
    return "\n".join(pad + line if line else line for line in text.splitlines())


def _dump(data: Any) -> str:
    return yaml.safe_dump(data, default_flow_style=False, sort_keys=False, width=100).rstrip()


def render_yaml(p: Proposal) -> str:
    """The proposed ``site`` section as YAML with the evidence as comments. Loading it gives
    exactly ``Proposal.site()``."""
    source = ", ".join(
        part
        for part in (
            f"Elasticsearch {safe(p.elastic_version, 40)}" if p.elastic_version else "",
            f"Kibana {safe(p.kibana_version, 40)}" if p.kibana_version else "",
        )
        if part
    )
    lines = [
        f"# Proposed by `argus discover` on {p.now:%Y-%m-%d %H:%M} UTC"
        + (f" from {source}" if source else "")
        + ".",
        "# Read it before you keep it: each family says how sure the proposal is and why.",
        "site:",
    ]
    section = p.section()
    for key in ("space", "kibana_features"):
        if key in section:
            if key == "space":
                lines.append(f"  # {safe(p.space_evidence)}")
            lines.append(_indent(_dump({key: section[key]}), 2))
    lines.append("  families:" if p.families else "  families: []")
    for proposal in p.families:
        lines.append(
            f"    # {proposal.family.name}: {proposal.confidence.value} confidence"
            f" ({proposal.score} points)"
        )
        for line in (*proposal.evidence, *proposal.notes):
            lines.append(f"    #   {safe(line)}")
        lines.append(_indent(_dump([family_entry(proposal.family)]), 4))
    if p.ti_sources:
        lines.append("  ti_sources:")
        for ti in p.ti_sources:
            lines.append(f"    # {safe(ti.source.index, 80)}: asked per value (lookup)")
            for line in (*ti.evidence, *ti.notes):
                lines.append(f"    #   {safe(line)}")
            lines.append(_indent(_dump([ti_entry(ti.source)]), 4))
    return "\n".join(lines) + "\n"


def checked_yaml(p: Proposal) -> str:
    """``render_yaml``, proven to load back as exactly this proposal's site profile: a name or a
    version from the SIEM that got into the YAML as structure (a newline, a quote, a ``: ``)
    would load as something else, and then nothing is written (``ValueError``)."""
    text = render_yaml(p)
    try:
        loaded = yaml.safe_load(text)
        same = isinstance(loaded, dict) and SiteSettings.model_validate(loaded["site"]) == p.site()
    except (yaml.YAMLError, ValueError, KeyError, TypeError):
        same = False
    if not same:
        raise ValueError("the proposed YAML does not load back as the proposal")
    return text


def render_text(p: Proposal) -> str:
    """The report: what was found, the proposed families with their evidence, what was left out,
    the warnings. The YAML follows it (``render_yaml``)."""
    out = []
    if p.elastic_version or p.kibana_version:
        es = safe(p.elastic_version, 40) if p.elastic_version else "not read"
        kb = safe(p.kibana_version, 40) if p.kibana_version else "not read"
        out.append(f"Elasticsearch {es}; Kibana {kb}")
    if p.licence is not None:
        out.append(
            f"Licence {p.licence.level} ({p.licence.status}): writes "
            + ("allowed" if p.licence.writes_allowed else "not allowed")
            + "; paid features (case sub-feature privileges, assignment) "
            + ("on" if p.licence.paid else "off")
        )
    out.append(
        "Kibana spaces: "
        + (", ".join(safe(s, 64) for s in p.spaces) if p.spaces else "not read")
        + "; alerts indices: "
        + (", ".join(safe(a) for a in p.alerts_aliases) or "none found")
    )
    if p.space is not None:
        out.append(f"Space proposed: {safe(p.space, 64)} ({safe(p.space_evidence)})")
    if p.features is not None:
        out.append(f"Kibana features: Security {p.features.security}, Cases {p.features.cases}")
    out.append(f"Log families proposed: {len(p.families)}")
    for proposal in p.families:
        family = proposal.family
        out.append(
            f"  {family.name} [{family.role.value}] {family.pattern} -"
            f" {proposal.confidence.value} confidence ({proposal.score} points, {proposal.kind})"
        )
        out += [f"      {safe(line)}" for line in (*proposal.evidence, *proposal.notes)]
        r = proposal.retention
        kept = f"{r.days_kept} days from {r.oldest} to {r.newest}" if r.days_kept else "unknown"
        out.append(
            f"      kept: {kept}"
            + (f"; ILM deletes after {r.delete_after}" if r.delete_after else "")
        )
    out.append(f"Threat-intel sources proposed: {len(p.ti_sources) or 'none'}")
    for ti in p.ti_sources:
        source = ti.source
        out.append(f"  {safe(source.index, 80)} [{source.schema_}, {source.mode}]")
        out += [f"      {safe(line)}" for line in (*ti.evidence, *ti.notes)]
    if not p.ti_sources:
        out.append("  (threat intel stays off until site.ti_sources names a source)")
    if p.unclassified_count:
        shown = ", ".join(safe(name, 80) for name in p.unclassified)
        more = p.unclassified_count - len(p.unclassified)
        out.append(
            f"Looked like no log role ({p.unclassified_count}): {shown}"
            + (f" and {more} more" if more > 0 else "")
        )
    if p.history_window:
        out.append(
            f"Suggestion: history.window {p.history_window} (no deeper than the shortest retention)"
        )
    out += [f"WARNING: {safe(w, 300)}" for w in p.warnings]
    out.append(f"{p.requests} requests were sent.")
    return "\n".join(out) + "\n"


__all__ = [
    "ALERTS_INDEX_DEFAULT",
    "FamilyProposal",
    "Inputs",
    "Proposal",
    "checked_yaml",
    "propose",
    "render_text",
    "render_yaml",
    "safe",
]
