"""report@2 as people read it (Q-F2): plain text, and the view of someone without log access.

``hide_logs`` gives the report a person whose ELK account cannot read the logs sees: nothing
in it depends on what a log check returned. Each log check that got an answer (found
something or nothing alike) is one line, "Hidden: needs log access in ELK.", with what was
asked (template, window); every fact, line, gap, change and event that reads its answer is
dropped, so a positive answer and a zero look the same. The model's words (summary,
hypotheses, the verdict's reasons) are hidden when it read a log answer; ARGUS's own fixed
reasons stay. A log check that failed or did not run stays as it is: no log content in it.
Kept by design (decision 10): the verdict, the evidence strength's counts and the cost.
``text`` writes a report in analyst order, times in India time.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Iterable, Sequence
from datetime import datetime
from typing import Any

from argus import site
from argus.report import facts as fx
from argus.report.build import UNTRUSTED_ONLY, UNVERIFIED
from argus.report.model import (
    HIDDEN,
    Change,
    Check,
    Fact,
    Hypothesis,
    Item,
    Provenance,
    Report,
    Summary,
    WhatsNew,
)

OUTCOMES = {
    "true_positive": "a true positive",
    "benign_expected": "benign: expected activity",
    "benign_policy": "benign: allowed by policy",
    "rule_false_positive": "a false positive of the rule",
    "inconclusive": "inconclusive",
}
STATUSES = {
    "no_decision": "made no proposal",
    "queued": "has not assessed it yet (queued)",
    "running": "is assessing it now",
    "failed": "could not finish",
    "none": "has not assessed it",
}
KINDS = {
    "hidden": "Hidden",
    "new": "New",
    "nothing_found": "Nothing found",
    "could_not_tell": "Could not tell",
    "failed": "Failed",
    "not_checked": "Not checked",
    "still_open": "Still open",
}
# The verdict's reasons in ARGUS's own fixed words (the engine's, agent@1's and this
# module's): kept without log access. Any other reason may repeat the model or the logs.
KEPT_REASONS = frozenset(
    {
        "No assessor has looked at this investigation yet.",
        "no key with enough consistent human labels",
        "the item could not be sent",
        "no usable answer from the model",
        "the agent could not decide",
        UNTRUSTED_ONLY + ", not only quoted text from logs or alerts",
    }
)
# The parts of the floor's reason (assess.engine.floor) that no log answer decides; any
# other part, present or absent, would say what the logs held, so they become one line.
FLOOR_KEPT = frozenset(
    {
        "on a threat list",
        "flagged by outside threat intel",
        "ti.listed not known",
        "ti.listed_remote not known",
        "threat lists not checked",
        "remote-admin, P2P or anonymizer ports",
        "ports.risky not known",
        "severity high",
        "severity critical",
        "an entity seen for the first time",
        "first-seen not known",
        "a volume spike",
        "volume baseline not known",
    }
)
FLOOR = "floor: "
FLOOR_HIDDEN = "what the logs say is hidden (it needs log access in ELK)"


# ----------------------------------------------------------------------------- hiding


def _line(p: Provenance) -> str:
    where = ", ".join(x for x in (p.source, fx.span(p.window_start, p.window_end)) if x)
    return " · ".join(x for x in (p.eid, p.template, where, "result hidden") if x)


def reason(why: str) -> str:
    """One reason of the verdict as a person without log access reads it, when the
    assessor read a log answer."""
    if why in KEPT_REASONS or why == HIDDEN:
        return why
    if why.startswith(UNVERIFIED):  # it quotes the model's cites
        return f"{UNVERIFIED}; the quotes are hidden: {HIDDEN}"
    if why.startswith(FLOOR):
        kept = [p for p in why.removeprefix(FLOOR).split("; ") if p in FLOOR_KEPT]
        return FLOOR + "; ".join([*kept, FLOOR_HIDDEN])
    return HIDDEN


def hide_logs(report: Report) -> Report:
    """The report for a person whose ELK account cannot read the logs (see the module's
    docstring). Hiding twice changes nothing more; ``hidden`` counts the log checks whose
    results are hidden."""
    answered = [p.eid for p in report.provenance
                if p.from_logs and p.status in ("ok", "empty", "hidden")]  # fmt: skip
    told = set(answered)
    if not told:
        return report
    lines = {p.eid: _line(p) for p in report.provenance if p.from_logs}

    def gone(eids: Iterable[str], from_logs: bool) -> bool:
        """It reads a log answer (or may: log content without an E-id)."""
        found = set(eids)
        return from_logs and (bool(found & told) or not found)

    provenance = tuple(_provenance(p, lines, told) for p in report.provenance)
    new = report.found.new
    dropped = {x.key for x in (*new.now_known, *new.changed, *new.steps_answered)
               if gone(x.eids, x.from_logs)}  # fmt: skip
    dropped |= {f.key for f in new.new_facts if gone(f.eids, f.from_logs)}
    hidden_new = WhatsNew(
        new_facts=tuple(f for f in new.new_facts if not gone(f.eids, f.from_logs)),
        now_known=_changes(new.now_known, gone),
        changed=_changes(new.changed, gone),
        steps_answered=_changes(new.steps_answered, gone),
        gaps_closed=tuple(g for g in new.gaps_closed
                          if not gone(g.eids, g.from_logs) and g.key not in dropped),
        gaps_opened=tuple(g for g in new.gaps_opened if not gone(g.eids, g.from_logs)),
        checks=tuple(_check(k, lines, told) for k in new.checks),
    )  # fmt: skip
    items = [Item(kind="hidden", sentence=HIDDEN, eids=(e,), from_logs=True, note=lines[e])
             for e in answered]  # fmt: skip
    for i in report.found.items:
        if i.from_logs and i.kind == "hidden":
            continue  # hidden already: written again above
        if i.from_logs and i.kind not in ("failed", "not_checked") and gone(i.eids, True):
            continue
        items.append(i)
    events = []
    for e in report.timeline:
        if e.from_logs and e.kind == "check" and set(e.eids) & told:
            e = e.model_copy(update={"sentence": HIDDEN, "values": ()})
        elif gone(e.eids, e.from_logs):  # times read from the logs
            continue
        events.append(e)
    summary = report.summary
    if summary is not None:  # the model read what the logs said: its words may repeat it
        summary = Summary(
            text=HIDDEN,
            cites=tuple(x.model_copy(update={"quote": HIDDEN}) for x in summary.cites),
            checked=summary.checked,
            note=summary.note,
        )
    verdict = report.verdict.model_copy(
        update={"why": tuple(reason(w) for w in report.verdict.why)}
    )
    return report.model_copy(
        update={
            "provenance": provenance,
            "found": report.found.model_copy(update={"items": tuple(items), "new": hidden_new}),
            "timeline": tuple(events),
            "evidence": tuple(
                r for r in report.evidence if not gone(r.fact.eids, r.fact.from_logs)
            ),
            "hypotheses": tuple(_hypothesis(h) for h in report.hypotheses),
            "unknowns": tuple(g for g in report.unknowns if not gone(g.eids, g.from_logs)),
            "summary": summary,
            "verdict": verdict,
            "hidden": len(answered),
        }
    )


def _provenance(p: Provenance, lines: dict[str, str], told: set[str]) -> Provenance:
    """A log request's line without its result; what an investigator asked about stays
    only for the dossier's own requests (an ask may name a value the model read in logs)."""
    if p.from_logs:
        return p.model_copy(update={
            "rows": None, "result_hash": None, "truncated": False, "exact": True,
            "line": lines[p.eid], "subject": None,
            "status": "hidden" if p.eid in told else p.status,
        })  # fmt: skip
    if p.origin != "pack" and p.subject:
        line = p.line.replace(f" · about {p.subject}", "", 1)
        return p.model_copy(update={"subject": None, "line": line})
    return p


def _changes(found: Sequence[Change], gone: Any) -> tuple[Change, ...]:
    return tuple(x for x in found if not gone(x.eids, x.from_logs))


def _check(k: Check, lines: dict[str, str], told: set[str]) -> Check:
    if not k.from_logs:
        return k
    if k.eid not in told:  # failed or not run: no log content, only the line is trimmed
        return k.model_copy(update={"line": lines.get(k.eid, HIDDEN)})
    return k.model_copy(
        update={
            "outcome": "hidden",
            "sentence": HIDDEN,
            "why": None,
            "line": lines.get(k.eid, HIDDEN),
        }
    )


def _hypothesis(h: Hypothesis) -> Hypothesis:
    if h.by == "model":  # the model's words: hidden whole
        return Hypothesis(name=HIDDEN, by=h.by)
    support = tuple(r for r in h.support if not r.from_logs)
    against = tuple(r for r in h.against if not r.from_logs)
    return Hypothesis(name=h.name, by=h.by, support=support, against=against)


# ----------------------------------------------------------------------------- text


def visible(value: str) -> str:
    """Text for a terminal: control, format (bidi, zero-width) and separator characters shown
    as U+XXXX in angle quotes, so nothing can reorder or hide what follows."""
    out = []
    for char in value:
        if unicodedata.category(char) in ("Cc", "Cf", "Zl", "Zp", "Co", "Cs") and char != "\n":
            out.append(f"\u2039U+{ord(char):04X}\u203a")
        else:
            out.append(char)
    return "".join(out)


def when(at: datetime | None) -> str:
    if at is None:
        return ""
    local = at.astimezone(site.zone())
    return f"{local:%d %b %H:%M} {site.zone_label(local)}"


def _eids(eids: Sequence[str]) -> str:
    return f" [{', '.join(eids)}]" if eids else ""


def _from(fact: Fact) -> str:
    """Where a fact comes from: its E-ids and the store of ARGUS's it read, else the
    alerts."""
    parts = [*fact.eids, *([fact.source] if fact.source else [])]
    return f" [{', '.join(parts) or 'the alerts'}]"


def _values(values: Sequence[Any], indent: str = "    ") -> list[str]:
    out = []
    for v in values:
        count = f" ({v.count})" if v.count is not None else ""
        out.append(f"{indent}{v.label}: {v.text!r}{count}")
    return out


def _verdict(report: Report) -> str:
    v = report.verdict
    words = OUTCOMES.get(v.outcome or "", v.outcome or "")
    what = f"proposes {words}" if v.status == "proposed" else STATUSES.get(v.status, v.status)
    conf = (
        "" if v.model_confidence is None else f" (the model's confidence {v.model_confidence:.0%})"
    )
    return f"Verdict: {v.source} {what}{conf}"


def _hidden_run(lines: list[str], items: Sequence[Item]) -> None:
    """Items, with each run of hidden ones written as one line."""
    run: list[Item] = []

    def flush() -> None:
        if run:
            eids = sorted({e for i in run for e in i.eids}, key=lambda e: (len(e), e))
            n = len(eids)
            what = "What 1 check found is" if n == 1 else f"What {n} checks found is"
            lines.append(f"- {what} hidden: it needs log access in ELK{_eids(eids)}")
            run.clear()

    for item in items:
        if item.sentence == HIDDEN:
            run.append(item)
            continue
        flush()
        lines.append(f"- {KINDS[item.kind]}: {item.sentence}{_eids(item.eids)}")
        lines += _values(item.values)
        if item.note:
            lines.append(f"    {item.note}")
    flush()


def text(report: Report) -> str:
    """The report as plain text, in analyst order (quoted values are untrusted, shown as
    written)."""
    lines = [f"report@2 for investigation {report.investigation_id} v{report.version}"
             f" ({report.pack})"]  # fmt: skip
    if report.note:
        lines.append(f"Note: {report.note}.")
    if report.summary is not None:
        s = report.summary
        lines += ["", "Summary (the AI investigator's words)", f"  {s.text!r}", f"  {s.note}"]
        lines += [f"  quote {c.quote!r}{_eids(c.eids)}" for c in s.cites]
    lines += ["", _verdict(report)]
    lines += [f"  {w}" for w in report.verdict.why]
    st = report.strength
    lines.append(f"Evidence strength: {st.grade} ({'; '.join(st.reasons)})")
    f = report.found
    lines += ["", f"What ARGUS found with extra SIEM queries: {f.checks} checks,"
              f" {fx.seconds(f.server_ms)} of SIEM server time"]  # fmt: skip
    _hidden_run(lines, f.items)
    lines += ["", "Timeline"]
    for e in report.timeline:
        until = f" to {when(e.until)}" if e.until is not None else ""
        lines.append(f"- {when(e.at)}{until}: {e.sentence}{_eids(e.eids)}")
        lines += _values(e.values)
    lines += ["", f"Evidence, read against {OUTCOMES.get(report.relative_to, report.relative_to)}"]
    for row in report.evidence:
        lines.append(f"- {row.stance}: {row.fact.sentence}{_from(row.fact)}")
        lines += _values(row.fact.values)
    lines += ["", "Hypotheses"]
    for h in report.hypotheses:
        lines.append(f"- {h.name} ({'ARGUS' if h.by == 'argus' else 'the model'})")
        lines += [f"    for: {r.text}{_eids(r.eids)}" for r in h.support]
        lines += [f"    against: {r.text}{_eids(r.eids)}" for r in h.against]
    lines += ["", "Checked and unknown"]
    lines += [f"- {g.what} Why: {g.why}. Who can resolve it: {g.who}.{_eids(g.eids)}"
              for g in report.unknowns] or ["- nothing open"]  # fmt: skip
    lines += ["", "Actions"]
    lines += [f"- {a.text} Who: {a.who}." + (f" Why: {a.why}." if a.why else "")
              for a in report.actions]  # fmt: skip
    co = report.cost
    model = f"; {co.model_calls} model calls, ${co.model_cost_usd:.4f}" if co.model_calls else ""
    lines += ["", f"Cost: {co.siem_requests} SIEM requests, {fx.seconds(co.siem_server_ms)} of"
              f" server time, {co.reused} answers reused{model}"]  # fmt: skip
    lines += ["", "Provenance"]
    lines += [f"- {p.line}" for p in report.provenance] or ["- no SIEM query"]
    if report.hidden:
        lines += ["", f"The results of {report.hidden} log checks are hidden: they need log"
                  " access in ELK."]  # fmt: skip
    return visible("\n".join(lines)) + "\n"
