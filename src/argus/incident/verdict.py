"""ARGUS's verdict on a case, with its confidence and what it rests on.

The verdict is read, never decided here, in this order: people's reviews of the case's
investigations; else the proposals the AI investigator or the decision engine made on them; else
ARGUS's readings; else the case itself (a person confirmed it); else "no verdict yet". The outcome
most investigations hold wins; the confidence is the mean of the AI's own. What it rests on is
counted from the stored flags and answers, never estimated."""

from __future__ import annotations

import uuid
from collections import Counter
from collections.abc import Mapping
from typing import Any

from argus.agent import reading as agent_reading
from argus.incident import model as m
from argus.incident.book import Book
from argus.incident.scene import Scene, top
from argus.incident.words import OUTCOME_WORDS, confidence_words, plural
from argus.outside import facts as outside_facts

Best = tuple[str, float | None, str, str, int]  # outcome, confidence, who, kind, investigations


def intel_sentence(scene: Scene, book: Book) -> m.ReportSentence:
    """What VirusTotal flags among the case's indicators, and the strongest."""
    flagged = scene.flagged
    best = max(flagged, key=lambda v: (outside_facts.malicious(scene.vt_answer(v)), v))
    answer = scene.vt_answer(best)
    bad = outside_facts.malicious(answer)
    engines = outside_facts.number(answer.get("engines")) or 0
    many = plural(len(flagged), "indicator")
    return book.say(
        "intel",
        f"VirusTotal flags {many} of the case; the strongest, {best}, is flagged by "
        f"{bad} of {engines} engines.",
        "VirusTotal (ARGUS's cached answer)",
        (len(flagged), bad, engines),
        safe=f"VirusTotal flags {many} of the case; the strongest is flagged by "
        f"{bad} of {engines} engines.",
    )


def basis(scene: Scene, book: Book) -> tuple[m.ReportSentence, ...]:
    """The evidence flags, threat-list hits and outside detections the verdict rests on."""
    out: list[m.ReportSentence] = []
    for flag, n in sorted(scene.flag_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:4]:
        text = f'ARGUS\'s evidence flagged "{flag}" on {plural(n, "investigation")}.'
        out.append(book.say("verdict", text, "ARGUS's evidence flags", (n,), safe=text))
    if scene.listed:
        text = (
            f"{plural(len(scene.listed), 'indicator')} of the case are on the local threat lists."
        )
        out.append(
            book.say("intel", text, "the local threat lists", (len(scene.listed),), safe=text)
        )
    if scene.flagged:
        out.append(intel_sentence(scene, book))
    return tuple(out)


def _best(scene: Scene) -> Best | None:
    """The outcome most investigations hold in ARGUS's answers (proposals, else readings)."""
    per_member: dict[uuid.UUID, tuple[tuple[int, int, int], str, float | None, str, str]] = {}
    for a in scene.f.assessments:
        agent = a.assessor.startswith("agent")
        if a.status == "proposed" and a.outcome:
            rank = (2, int(agent), 0 if a.shared else 1)
            outcome, conf, kind = a.outcome, a.confidence if agent else None, "proposal"
        else:
            report = next((r for r in a.reasons if isinstance(r, Mapping)), None)
            reasons = [r for r in a.reasons if isinstance(r, str)]
            got = agent_reading.of(report, reasons)
            if got is None or got.outcome not in OUTCOME_WORDS:
                continue
            rank = (1, int(agent), 0 if a.shared else 1)
            outcome, conf, kind = got.outcome, got.confidence, "reading"
        who = "the AI investigator" if agent else "the decision engine"
        held = per_member.get(a.investigation_id)
        if held is None or rank > held[0]:
            per_member[a.investigation_id] = (rank, outcome, conf, who, kind)
    if not per_member:
        return None
    proposals = {k: v for k, v in per_member.items() if v[4] == "proposal"}
    pool = proposals or per_member
    tally = Counter(v[1] for v in pool.values())
    outcome = sorted(tally.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
    chosen = [v for v in pool.values() if v[1] == outcome]
    confs = [v[2] for v in chosen if v[2] is not None]
    who = top((v[3] for v in chosen), 1)[0]
    kind = "proposal" if proposals else "reading"
    return (outcome, sum(confs) / len(confs) if confs else None, who, kind, len(chosen))


def _upper(text: str) -> str:
    return text[:1].upper() + text[1:]


def resolve(scene: Scene, book: Book) -> m.ReportVerdict:
    """The case's verdict (see the module's order), with how many of the case's investigations
    people reviewed: a verdict of people's reviews is the whole case's only when they reviewed
    every one (the investigations not read count as not reviewed)."""
    f = scene.f
    counts = {
        "reviewed": sum(1 for x in f.members if x.reviewed_outcome),
        "investigations": max(f.members_total, len(f.members)),
    }
    return _resolve(scene, book).model_copy(update=counts)


def _resolve(scene: Scene, book: Book) -> m.ReportVerdict:
    f = scene.f
    total = len(f.members)
    reviewed = Counter(x.reviewed_outcome for x in f.members if x.reviewed_outcome)
    if reviewed:
        outcome, n = sorted(reviewed.items(), key=lambda kv: (-kv[1], kv[0]))[0]
        said = sum(reviewed.values())
        text = (
            f"People reviewed {plural(said, 'investigation')} of this case "
            f"({n} as {OUTCOME_WORDS.get(outcome, outcome)})."
        )
        s = book.say("verdict", text, "reviews by people", (said, n), safe=text)
        return _verdict(outcome, "person", None, "people's reviews", (s, *basis(scene, book)))
    best = _best(scene)
    if best is not None:
        outcome, confidence, who, kind, n = best
        word = OUTCOME_WORDS.get(outcome, outcome)
        how = "proposed" if kind == "proposal" else "read it as (it did not propose)"
        sure = f" with confidence {round(confidence * 100)}%" if confidence is not None else ""
        body = f"{_upper(who)} {how} {word}"
        count = f"for {plural(n, 'investigation')} of {total}."
        numbers: list[float] = [n, total]
        if confidence is not None:
            numbers.append(round(confidence * 100))
        s = book.say("verdict", f"{body}{sure} {count}", who, numbers, safe=f"{body} {count}")
        return _verdict(outcome, kind, confidence, who, (s, *basis(scene, book)))
    if f.case.opened_at is not None:
        text = "A person confirmed this case as a real problem."
        s = book.say("verdict", text, "the case record", safe=text)
        return _verdict(
            "true_positive", "case", None, "the person who confirmed the case",
            (s, *basis(scene, book)),
        )  # fmt: skip
    text = "ARGUS has no verdict on this case yet."
    s = book.say("verdict", text, "the case record", safe=text)
    return _verdict(None, "none", None, "nobody yet", (s, *basis(scene, book)))


def _verdict(
    outcome: str | None,
    kind: str,
    confidence: float | None,
    source: str,
    sentences: tuple[m.ReportSentence, ...],
) -> m.ReportVerdict:
    words = OUTCOME_WORDS.get(outcome, outcome) if outcome else "no verdict yet"
    fields: dict[str, Any] = {
        "outcome": outcome,
        "words": words,
        "kind": kind,
        "confidence": confidence,
        "confidence_words": confidence_words(confidence),
        "source": source,
        "sentences": sentences,
    }
    return m.ReportVerdict(**fields)
