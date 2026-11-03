"""report@2 for one assessment, or for a dossier alone (Q-F2, plan §7.3). Pure: the same
inputs give the same report.

Two views of the investigation version are compared:
- **the starting view**: what the alerts alone say (the pack's signals and steps with no
  evidence);
- **the final view**: with the evidence of the version up to the assessment's end,
  recomputed by the same pack: the dossier's own checks, and an assessor's asks where they
  stand in for one (``primary``). A pack reads one subject per template (the investigation's
  host, client, destination), so a second request of a template about another subject (an
  investigator's ask about another host) is shown as a check of its own, with its
  observations and its subject named, never read as the investigation's.
Their diff is what every SIEM query found ("What ARGUS found with extra SIEM queries"). When
the dossier's pack is not deployed here the stored dossier stands for the final view and the
starting view keeps only what needs no evidence (``recomputed`` is false).
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from argus.context.evidence import COMPLETE
from argus.context.packs import Pack
from argus.evaluation.harness import BENIGN
from argus.reference.ti import values_of
from argus.report import facts as fx
from argus.report.diff import View, diff, eid_order, view
from argus.report.model import (
    Action,
    Check,
    Cite,
    Cost,
    Event,
    Fact,
    FactRef,
    Found,
    Hypothesis,
    Item,
    Provenance,
    Report,
    Row,
    Stance,
    Strength,
    Summary,
    Verdict,
    WhatsNew,
)

POSITIVE = "true_positive"
STANCES = {"supports": 0, "contradicts": 1, "neutral": 2}  # the evidence table's order
YOU = "you (the reviewer)"
DETAIL = re.compile(r"\d+ rounds, \d+ model calls")  # the agent's run numbers (in its report)
# agent@1's own reasons for withholding an answer (agent.agent.Agent.run)
UNVERIFIED = "a cited fact is not in the item"
UNTRUSTED_ONLY = "a benign answer must cite ARGUS's own words"
OUTCOME_WORDS = {
    "true_positive": "a true positive",
    "benign_expected": "benign: expected activity",
    "benign_policy": "benign: allowed by policy",
    "rule_false_positive": "a false positive of the rule",
    "inconclusive": "inconclusive",
}


@dataclass(frozen=True)
class AssessmentRow:
    id: int
    assessor: str
    status: str
    outcome: str | None
    confidence: float | None
    decided_by: str | None
    reasons: Sequence[Any]
    created_at: datetime | None = None
    finished_at: datetime | None = None


@dataclass(frozen=True)
class Inputs:
    investigation_id: str
    version: int
    pack: str
    dossier_hash: str
    body: Mapping[str, Any]
    evidence: Sequence[fx.EvidenceRow]  # this version's rows (up to the assessment's end)
    requests: Sequence[fx.RequestRow]  # the investigation's E-ids
    ledger: Mapping[str, fx.LedgerRow]  # the ledger row that answered each task key
    assessment: AssessmentRow | None = None


# ----------------------------------------------------------------------------- views


@dataclass(frozen=True)
class State:
    signals: list[dict[str, Any]]  # local and derived, by name
    report: Mapping[str, Any]


def _sorted(signals: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return sorted((dict(s) for s in signals), key=lambda s: str(s.get("name")))


def states(
    pack: Pack | None, body: Mapping[str, Any], rows: Sequence[fx.EvidenceRow]
) -> tuple[State, State, bool, str | None]:
    """(starting, final, recomputed, note)."""
    local = list(body.get("local_signals") or [])
    stored = State(_sorted([*local, *(body.get("signals") or [])]), body.get("report") or {})
    alone = [s for s in body.get("signals") or [] if not s.get("evidence")]
    fallback = State(_sorted([*local, *alone]), body.get("report") or {})
    if pack is None:
        return fallback, stored, False, "this ARGUS no longer has the pack that made the dossier"
    if any(r.purged for r in rows):
        return (
            fallback,
            stored,
            False,
            "the log rows behind its evidence were deleted after ARGUS's retention period, so"
            " its findings are shown as they were stored",
        )
    facts, context = body.get("facts") or {}, body.get("context") or {}
    try:
        none = [s.as_dict() for s in pack.signals(facts, context, {}, {})]
        start = State(_sorted([*local, *none]), pack.report(facts, context, {}, _sorted(none)))
        refs = {r.task_key: r.ref() for r in rows}
        snaps = {r.task_key: r.snapshot for r in rows if r.status in COMPLETE}
        every = [s.as_dict() for s in pack.signals(facts, context, refs, snaps)]
        final = State(_sorted([*local, *every]), pack.report(facts, context, refs, _sorted(every)))
    except Exception as exc:  # a stored body the pack cannot read: shown as stored
        return (
            fallback,
            stored,
            False,
            f"the pack could not read the dossier ({type(exc).__name__})",
        )
    return start, final, True, None


@dataclass(frozen=True)
class Side:
    view: View
    signals: dict[str, Fact]
    raw: dict[str, Mapping[str, Any]]
    steps: list[Fact]


def side(
    state: State,
    body: Mapping[str, Any],
    keys: fx.Keys,
    checks: Sequence[Check] = (),
    observed: Sequence[Fact] = (),
) -> Side:
    raw: dict[str, Mapping[str, Any]] = {str(s.get("name")): s for s in state.signals}
    signals = {n: fx.signal_fact(s, keys) for n, s in raw.items()}
    steps = [fx.step_fact(s, signals) for s in state.report.get("steps") or []]
    gaps = [g for n, s in raw.items() if (g := fx.signal_gap(s, signals[n])) is not None]
    gaps += [g for s, f in zip(state.report.get("steps") or [], steps, strict=True)
             if (g := fx.step_gap(s, f)) is not None]  # fmt: skip
    every = [*signals.values(), *steps, *fx.alert_facts(body.get("facts") or {}), *observed]
    return Side(view(every, checks, gaps), signals, raw, steps)


# ----------------------------------------------------------------------------- the parts


def _items(new: WhatsNew, after: Side) -> list[Item]:
    """The lines of "What ARGUS found with extra SIEM queries": the new and the newly
    known first (reasons to look before the rest), then each check that found nothing,
    could not tell, failed or did not run, then what is still open."""
    rank = {"suspicious": 0, "reassuring": 1, "neutral": 2}
    changed = [after.view.facts[c.key] for c in (*new.now_known, *new.changed,
                                                   *new.steps_answered)
               if c.key in after.view.facts]  # fmt: skip
    # a finding names the checks it comes from; a count that moved with them is not one, and
    # a count of nothing is a check's outcome (below), never a finding
    new_facts = [*new.new_facts, *(f for f in changed if f.status == "known" and f.eids
                                   and not _none(f, after))]  # fmt: skip
    out = [
        Item(kind="new", sentence=f.sentence, eids=f.eids, from_logs=f.from_logs,
             values=f.values)
        for f in sorted(new_facts, key=lambda f: (rank[f.leaning], f.key))
    ]  # fmt: skip
    told = {e for f in new_facts for e in f.eids}
    kinds = {"nothing_found": "nothing_found", "could_not_tell": "could_not_tell",
             "failed": "failed", "not_run": "not_checked"}  # fmt: skip
    for c in new.checks:
        if c.outcome == "found":
            if c.eid not in told:  # found something no fact reads: still accounted for
                out.append(Item(kind="new", sentence=c.sentence, eids=(c.eid,),
                                from_logs=c.from_logs, note=c.line))  # fmt: skip
            continue
        out.append(Item(kind=kinds[c.outcome], sentence=c.sentence,  # type: ignore[arg-type]
                        eids=(c.eid,), from_logs=c.from_logs, note=c.line))  # fmt: skip
    for gap in sorted(after.view.gaps.values(), key=lambda g: (not g.floor, g.key)):
        out.append(Item(kind="still_open", sentence=f"{gap.what} Why: {gap.why}."
                        f" Who can resolve it: {gap.who}.", eids=gap.eids,
                        from_logs=gap.from_logs))  # fmt: skip
    return out


def _none(fact: Fact, side: Side) -> bool:
    raw = side.raw.get(fact.name) if fact.kind == "signal" else None
    return raw is not None and fact.name in fx.NONE_COUNTS and raw.get("value") == 0


def _capital(text: str) -> str:
    return text[:1].upper() + text[1:]


def _source(assessor: str | None) -> str:
    if assessor is None:
        return "nobody yet"
    return "the AI investigator" if assessor.startswith("agent") else "the decision engine"


def _agent_report(a: AssessmentRow | None) -> Mapping[str, Any] | None:
    if a is None:
        return None
    return next((r for r in a.reasons if isinstance(r, Mapping)), None)


def _answer(report: Mapping[str, Any] | None) -> Mapping[str, Any]:
    answer = (report or {}).get("answer")
    return answer if isinstance(answer, Mapping) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _number(value: Any) -> float | None:
    ok = isinstance(value, int | float) and not isinstance(value, bool)
    return float(value) if ok and value == value and abs(value) != float("inf") else None


def _verdict(a: AssessmentRow | None) -> Verdict:
    if a is None:
        return Verdict(status="none", source=_source(None),
                       why=("No assessor has looked at this investigation yet.",))  # fmt: skip
    agent = a.assessor.startswith("agent")
    plain = tuple(str(r)[:600] for r in a.reasons
                  if not isinstance(r, Mapping) and not DETAIL.match(str(r)))[:8]  # fmt: skip
    return Verdict(
        status=a.status,
        outcome=a.outcome,
        assessor=a.assessor,
        source=_source(a.assessor),
        decided_by=a.decided_by,
        model_confidence=a.confidence if agent else None,
        why=plain,
        at=a.finished_at,
    )


def _normal(text: str) -> str:
    return " ".join(text.replace('"', " ").replace("'", " ").split()).lower()


def matching(quote: str, facts: Sequence[Fact]) -> tuple[str, ...]:
    """The E-ids of the facts a quote of the item restates (a fact's sentence holds the
    quote, or the quote holds the sentence)."""
    q = _normal(quote)
    if len(q) < 4:
        return ()
    found: set[str] = set()
    for f in facts:
        s = _normal(f.sentence)
        if (q in s) or (len(s) >= 12 and s in q):
            found.update(f.eids)
    return tuple(sorted(found, key=eid_order))


def _summary(a: AssessmentRow | None, known: Sequence[Fact]) -> Summary | None:
    report = _agent_report(a)
    if a is None or report is None:
        return None
    answer = _answer(report)
    text = str(answer.get("explanation") or "")
    quotes = [str(c) for c in _list(answer.get("cites"))][:12]
    cites = tuple(Cite(quote=fx.cap(q, 300), eids=matching(q, known)) for q in quotes)
    reasons = " ".join(str(r) for r in a.reasons if not isinstance(r, Mapping))
    if answer.get("outcome") in (None, "inconclusive"):
        checked, note = False, "The model did not decide, so its quotes were not checked."
    elif UNVERIFIED in reasons:
        checked, note = False, "A quote was not in what the model read: ARGUS withheld its answer."
    elif UNTRUSTED_ONLY in reasons:
        checked, note = False, "It quoted only text from logs or alerts: ARGUS withheld it."
    elif not quotes:
        checked, note = False, "It quoted nothing."
    else:
        checked, note = True, "Every quote was found in what the model read."
    return Summary(text=fx.cap(text, 2000), cites=cites, checked=checked, note=note)


def _strength(
    after: Side,
    rows: Mapping[str, fx.EvidenceRow],
    eid_key: Mapping[str, str],
    checks: Sequence[Check],
    body: Mapping[str, Any],
) -> Strength:
    floor = [f for n, f in after.signals.items() if n in fx.FLOOR]
    floor_known = sum(f.status == "known" for f in floor)
    done = [rows.get(eid_key[c.eid]) for c in checks]
    complete = sum(1 for r in done if r is not None and r.status in COMPLETE)
    answered = sum(f.status == "known" for f in after.steps)
    manual = sum(f.why == fx.STEP_WORDS["manual"] for f in after.steps)
    open_steps = len(after.steps) - answered - manual
    report = body.get("report") or {}
    facts = body.get("facts") or {}
    read = int(report.get("alerts_read") or 0)
    total = int(facts.get("alert_count") or 0)
    reasons = [
        f"{floor_known} of {len(floor)} of the signals that block a benign proposal are known",
        f"{complete} of {len(checks)} SIEM checks complete",
        f"{answered} of {len(after.steps)} of the rule's steps answered"
        + (f" ({manual} for a person)" if manual else ""),
        f"{read} of {total} alerts read" if read < total else f"all {total} alerts read",
    ]
    if (floor and floor_known * 2 < len(floor)) or (checks and complete == 0):
        grade = "weak"
    elif floor_known == len(floor) and complete == len(checks) and read >= total and not open_steps:
        grade = "strong"
    else:
        grade = "moderate"
    return Strength(
        grade=grade,  # type: ignore[arg-type]
        floor_known=floor_known,
        floor_total=len(floor),
        checks_complete=complete,
        checks_total=len(checks),
        steps_answered=answered,
        steps_total=len(after.steps),
        alerts_read=read,
        alerts_total=total,
        reasons=tuple(reasons),
    )


def relative(verdict: Verdict) -> str:
    out = verdict.outcome
    return out if out in OUTCOME_WORDS and out != "inconclusive" else POSITIVE


def stance(fact: Fact, against: str) -> Stance:
    if fact.leaning == "neutral":
        return "neutral"
    threat = fact.leaning == "suspicious"
    if against == POSITIVE:
        return "supports" if threat else "contradicts"
    if against in BENIGN:
        return "contradicts" if threat else "supports"
    return "neutral"


def _ref(f: Fact) -> FactRef:
    return FactRef(key=f.key, text=f.sentence, eids=f.eids, from_logs=f.from_logs)


def _hypotheses(known: Sequence[Fact], report: Mapping[str, Any] | None) -> list[Hypothesis]:
    threat = [_ref(f) for f in known if f.leaning == "suspicious"]
    calm = [_ref(f) for f in known if f.leaning == "reassuring"]
    out = [
        Hypothesis(name="A real threat: malicious activity or a compromise (a true positive)",
                   by="argus", support=tuple(threat), against=tuple(calm)),
        Hypothesis(name="Expected or harmless activity (benign)", by="argus",
                   support=tuple(calm), against=tuple(threat)),
    ]  # fmt: skip
    for h in _list(_answer(report).get("hypotheses"))[:4]:
        if not isinstance(h, Mapping) or not str(h.get("name") or "").strip():
            continue

        def refs(quotes: Any) -> tuple[FactRef, ...]:
            return tuple(
                FactRef(key="quote", text=fx.cap(q, 300), eids=matching(str(q), known))
                for q in (quotes if isinstance(quotes, list) else [])[:4]
            )

        name = fx.cap(h.get("name"), 200)
        out.append(Hypothesis(name=name, by="model", support=refs(h.get("for")),
                              against=refs(h.get("against"))))  # fmt: skip
    return out


def _timeline(
    body: Mapping[str, Any],
    after: Side,
    checks: Sequence[Check],
    rows: Mapping[str, fx.EvidenceRow],
    eid_key: Mapping[str, str],
    verdict: Verdict,
) -> list[Event]:
    facts = body.get("facts") or {}
    out: list[Event] = []
    first, last = fx._when(facts.get("first_event_at")), fx._when(facts.get("last_event_at"))
    if first is not None:
        out.append(Event(at=first, kind="alert", sentence="The first alert."))
    if last is not None and last != first:
        out.append(Event(at=last, kind="alert", sentence="The last alert."))
    for f in after.view.facts.values():
        if f.at is not None:
            out.append(Event(at=f.at, until=f.until, sentence=f"{f.when}." if f.when
                             else f.sentence, eids=f.eids, from_logs=f.from_logs,
                             values=f.values[:3]))  # fmt: skip
    for c in checks:
        row = rows.get(eid_key.get(c.eid, ""))
        if row is not None and row.collected_at is not None:
            word = {"found": "found something", "nothing_found": "found nothing",
                    "could_not_tell": "could not tell", "failed": "failed",
                    "not_run": "did not run"}[c.outcome]  # fmt: skip
            out.append(Event(at=row.collected_at, kind="check", eids=(c.eid,),
                             sentence=f"ARGUS's check {c.eid} {word}.",
                             from_logs=c.from_logs))  # fmt: skip
    if verdict.at is not None:
        what = (f"proposed {OUTCOME_WORDS.get(verdict.outcome or '', verdict.outcome)}"
                if verdict.status == "proposed" else "made no proposal")  # fmt: skip
        out.append(Event(at=verdict.at, kind="verdict",
                         sentence=f"{_capital(verdict.source)} {what}."))  # fmt: skip
    return sorted(out, key=lambda e: (e.at, e.sentence))


def _actions(verdict: Verdict, after: Side, checks: Sequence[Check]) -> list[Action]:
    out = []
    if verdict.status == "proposed":
        what = OUTCOME_WORDS.get(verdict.outcome or "", verdict.outcome)
        out.append(Action(text="Confirm the proposal or choose another outcome.", who=YOU,
                          why=f"{_capital(verdict.source)} proposes {what}"))  # fmt: skip
    else:
        out.append(Action(text="Decide this investigation.", who=YOU,
                          why="ARGUS has no proposal for it"))  # fmt: skip
    for step in after.steps:
        if step.why == fx.STEP_WORDS["manual"]:
            out.append(Action(text=f"Do {step.name} of the rule's note.", who=YOU,
                              why="it is for a person to decide or do"))  # fmt: skip
    for c in checks:
        if c.outcome in ("failed", "not_run"):
            out.append(Action(text=f"Check {c.eid} again.",
                              who="ARGUS, on its next run or when a person asks for an assessment",
                              why=c.why))  # fmt: skip
    return out


def _cost(rows: Sequence[fx.EvidenceRow], report: Mapping[str, Any] | None) -> Cost:
    fresh = [r for r in rows if r.reused_from_version is None]
    sent = [r for r in fresh if r.status in ("ok", "empty", "timeout", "failed")]
    run = report or {}
    calls, cost = _number(run.get("calls")), _number(run.get("cost_usd"))
    return Cost(
        siem_requests=len(sent),
        siem_server_ms=sum(r.took_ms or 0 for r in sent),
        reused=len(rows) - len(fresh),
        model_calls=max(int(calls), 0) if calls is not None else 0,
        model_cost_usd=max(cost, 0.0) if cost is not None else 0.0,
        models=tuple(fx.cap(m, 120) for m in _list(run.get("models"))[:8]),
        seconds=_number(run.get("seconds")),
    )


# ----------------------------------------------------------------------------- evidence


def primary(
    rows: Sequence[fx.EvidenceRow], own: set[str], order: Mapping[str, int]
) -> tuple[list[fx.EvidenceRow], dict[str, bool]]:
    """The rows the pack reads for the final view, and every other row with whether it asks
    about another subject than the rows read of its template. Per template: the dossier's own
    rows when one of them is complete; else an asked complete row about the same subject (a
    retry), or, when the dossier has none of the template, the first asked complete one; else
    the dossier's own rows, or the first asked. ``order``: task key -> E-id number."""
    by: dict[str, list[fx.EvidenceRow]] = {}
    for r in sorted(rows, key=lambda r: (order.get(r.task_key, 1 << 62), r.task_key)):
        by.setdefault(r.template, []).append(r)
    fed: list[fx.EvidenceRow] = []
    others: dict[str, bool] = {}
    for group in by.values():
        mine = [r for r in group if r.task_key in own]
        asked = [r for r in group if r.task_key not in own]
        if any(r.status in COMPLETE for r in mine):
            chosen = mine
        else:
            same = {fx.identity(r.params) for r in mine}
            done = [r for r in asked if r.status in COMPLETE
                    and (not mine or fx.identity(r.params) in same)]  # fmt: skip
            chosen = done[:1] or mine or asked[:1]
        fed += chosen
        read = {fx.identity(r.params) for r in chosen}
        keys = {r.task_key for r in chosen}
        others.update({r.task_key: fx.identity(r.params) not in read
                       for r in group if r.task_key not in keys})  # fmt: skip
    return sorted(fed, key=lambda r: r.task_key), others


def _threat_lists(
    body: Mapping[str, Any], rows: Sequence[fx.EvidenceRow]
) -> tuple[dict[str, frozenset[str]], tuple[str, ...]]:
    """(each complete lookup's task key -> the investigation's indicators it lists, the
    threat lists ARGUS's stored answers find one of them on)."""
    ti = ((body.get("context") or {}).get("pack") or {}).get("ti") or {}
    pairs = ti.get("values") if isinstance(ti, Mapping) else None
    wanted = {str(p[1]) for p in pairs or [] if isinstance(p, list | tuple) and len(p) == 2}
    holds = {}
    for r in rows:
        if r.template != "ti.lookup" or r.status not in COMPLETE:
            continue
        if not isinstance(r.snapshot, Mapping):
            continue
        try:
            found = {v for x in fx._rows(r.snapshot) for v in values_of(x)}
        except Exception:  # a damaged stored answer lists nothing
            found = set()
        holds[r.task_key] = frozenset(found & wanted)
    listed = ti.get("listed") if isinstance(ti, Mapping) else None
    hits = {str(v) for v in listed or [] if isinstance(v, str)}
    local: set[str] = set()
    answers = ti.get("answers") if isinstance(ti, Mapping) else None
    for a in answers or []:
        sources = a.get("sources") if isinstance(a, Mapping) else None
        if not isinstance(sources, Mapping) or a.get("value") not in hits:
            continue
        local.update(str(n) for n, x in sources.items() if isinstance(x, Mapping) and "match" in x)
    return holds, tuple(sorted(local))


# ----------------------------------------------------------------------------- the report


def _unanswered(request: fx.RequestRow, version: int, until: datetime | None) -> bool:
    """A request of this version with no row (nothing was stored: the SIEM was not
    available), made before the assessment ended."""
    if request.first_version != version:
        return False
    made = request.created_at
    return until is None or (made is not None and made <= until)


def build(inputs: Inputs, pack: Pack | None) -> Report:
    body = inputs.body
    rows = {r.task_key: r for r in inputs.evidence}
    requests = {r.task_key: r for r in inputs.requests}
    until = inputs.assessment.finished_at if inputs.assessment else None
    asked = [r for k, r in requests.items() if k in rows or _unanswered(r, inputs.version, until)]
    asked.sort(key=lambda r: r.eid)
    eid_key = {r.label: r.task_key for r in asked}
    own = {str(e.get("task_key")) for e in body.get("evidence") or [] if isinstance(e, Mapping)}
    fed, others = primary(list(rows.values()), own, {r.task_key: r.eid for r in asked})
    holds, local = _threat_lists(body, fed)
    keys = fx.Keys(
        eid={r.task_key: r.label for r in asked},
        template={r.task_key: r.template for r in asked},
        logs=frozenset(r.task_key for r in asked if fx.is_log(r.template, r.template_version)),
        status={k: r.status for k, r in rows.items()},
        holds=holds,
        local=local,
    )
    fresh = fx.lookups_fresh(body)
    start, final, recomputed, note = states(pack, body, fed)
    provenance: list[Provenance] = []
    checks: list[Check] = []
    observed: list[Fact] = []
    for r in asked:
        row = rows.get(r.task_key)
        prov = fx.provenance(r, row, inputs.ledger.get(r.task_key))
        citing = [s for s in final.signals if r.task_key in fx.reads(s, keys)]
        other = others.get(r.task_key, False)
        provenance.append(prov)
        checks.append(fx.check(r, row, citing, prov, keys, fresh, other))
        if row is not None:
            observed += fx.observations(r, row, other)
    before = side(start, body, keys)
    after = side(final, body, keys, checks, observed)
    new = diff(before.view, after.view)
    verdict = _verdict(inputs.assessment)
    known = [f for f in after.view.facts.values() if f.status == "known" and f.kind != "step"]
    known.sort(key=lambda f: f.key)
    against = relative(verdict)
    agent = _agent_report(inputs.assessment)
    sent = [rows[eid_key[c.eid]] for c in checks if eid_key[c.eid] in rows]
    cost = _cost(sent, agent)
    return Report(
        investigation_id=inputs.investigation_id,
        version=inputs.version,
        pack=inputs.pack,
        dossier_hash=inputs.dossier_hash,
        assessment_id=inputs.assessment.id if inputs.assessment else None,
        recomputed=recomputed,
        note=note,
        summary=_summary(inputs.assessment, known),
        verdict=verdict,
        strength=_strength(after, rows, eid_key, checks, body),
        found=Found(
            checks=cost.siem_requests,
            server_ms=cost.siem_server_ms,
            items=tuple(_items(new, after)),
            new=new,
        ),
        timeline=tuple(_timeline(body, after, checks, rows, eid_key, verdict)),
        relative_to=against,
        evidence=tuple(
            sorted(
                (Row(fact=f, stance=stance(f, against)) for f in known),
                key=lambda r: (STANCES[r.stance], r.fact.key),
            )
        ),
        hypotheses=tuple(_hypotheses(known, agent)),
        unknowns=tuple(sorted(after.view.gaps.values(), key=lambda g: (not g.floor, g.key))),
        actions=tuple(_actions(verdict, after, checks)),
        cost=cost,
        provenance=tuple(provenance),
    )
