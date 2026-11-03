"""The report's reading of the case: hypotheses with why each was kept or ruled out, the
recommended actions from the responder's catalogue, and the summary with the notice state.

A hypothesis is judged from counts and flags alone; the AI investigator's own hypotheses are listed
beside, as it wrote them, never judged. The actions are the catalogue's (``config/actions.yaml``)
for the families the case's facts match; ARGUS invents none."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import timedelta

from argus import site
from argus.incident import model as m
from argus.incident.book import Book, cut
from argus.incident.scene import Scene
from argus.incident.verdict import intel_sentence
from argus.incident.words import dwell, ist_date, ist_moment, plural
from argus.responder import facts as responder_facts

WATCH_QUIET_DAYS = 3  # argus.cases.watch.QUIET_DAYS: whole UTC days of no activity
KIND = ("threat", "benign", "rule")


@dataclass(frozen=True)
class Basis:
    """A fact that bears on the case as a threat, with the short words a hypothesis's reason uses
    for it (``label``) and whether it stands apart from the rule's own alerts (``independent``:
    ARGUS's evidence flags are read from the alerts' content; the others are not)."""

    id: str
    label: str
    independent: bool


def _support(scene: Scene, book: Book) -> list[Basis]:
    """The facts that bear on the case as a threat: outside detections, threat-list hits,
    ARGUS's evidence flags, an attacked path that was served."""
    out: list[Basis] = []
    if scene.flagged:
        label = f"{plural(len(scene.flagged), 'indicator')} flagged by outside threat intel"
        out.append(Basis(intel_sentence(scene, book).cites[0], label, True))
    if scene.listed:
        many = plural(len(scene.listed), "indicator")
        text = f"{many} of the case are on the local threat lists."
        ident = book.add("intel", text, "the local threat lists", (len(scene.listed),))
        out.append(Basis(ident, f"{many} on the local threat lists", True))
    for flag, n in sorted(scene.flag_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:3]:
        text = f'ARGUS\'s evidence flagged "{flag}" on {plural(n, "investigation")}.'
        ident = book.add("verdict", text, "ARGUS's evidence flags", (n,))
        out.append(
            Basis(ident, f'the evidence flag "{flag}" on {plural(n, "investigation")}', False)
        )
    served = scene.f.served
    if served:
        many = plural(len(served), "attacked path")
        text = f"{many} got a successful answer from the web server."
        ident = book.add(
            "evidence", text, "the web server logs (stored checks)", (len(served),),
            from_logs=True,
        )  # fmt: skip
        out.append(Basis(ident, f"{many} that got a successful answer", True))
    return out


def _each(book: Book, ids: Sequence[str]) -> tuple[m.ReportSentence, ...]:
    return tuple(book.repeat(i) for i in dict.fromkeys(ids))


# The hypothesis each outcome names; an inconclusive outcome names none.
NAMED_BY = {
    "true_positive": "threat",
    "benign_expected": "benign",
    "benign_policy": "benign",
    "rule_false_positive": "rule",
}
NOT_SETTLED = "Not settled by what ARGUS holds"


def judge(pro: Sequence[str], con: Sequence[str]) -> m.HypothesisStatus:
    """A hypothesis is ``kept`` only when facts of its own support it and none counts against it,
    ``ruled_out`` only when facts of its own count against it and none supports it, and ``open``
    otherwise (no fact either way, or facts on both sides): it is never settled by the verdict
    alone."""
    if pro and not con:
        return "kept"
    if con and not pro:
        return "ruled_out"
    return "open"


def _named(ids: Sequence[str], labels: Mapping[str, str]) -> str:
    """The facts' short words, one after the other (``a; b``)."""
    return "; ".join(dict.fromkeys(labels[i] for i in ids if i in labels))


def _why(
    book: Book,
    status: m.HypothesisStatus,
    pro: Sequence[str],
    con: Sequence[str],
    *,
    rests: str,
    ruled: str,
    nothing: str,
    labels: Mapping[str, str] | None = None,
) -> tuple[m.ReportSentence, ...]:
    """The reason, worded from the status and the facts it was judged from (never the reverse),
    so the reason cannot contradict the status. The first sentence names the facts in short
    words, so each hypothesis's reason reads as its own (the Kibana case shows only that one)."""
    words = labels or {}

    def says(lead: str, ids: Sequence[str]) -> str:
        named = _named(ids, words)
        return f"{lead} {named}." if named else lead

    if status == "kept":
        return (book.because(says(rests, pro), *pro), *_each(book, pro))
    if status == "ruled_out":
        return (book.because(says(ruled, con), *con), *_each(book, con))
    if pro or con:
        said = f"{NOT_SETTLED}: some facts support it and some count against it."
        if words:
            for_it, against = _named(pro, words) or "none", _named(con, words) or "none"
            said += f" For it: {for_it}. Against it: {against}."
        return (book.because(said, *pro, *con), *_each(book, [*pro, *con]))
    none = book.add("case", "ARGUS found no fact that settles it yet.", "the case record")
    return (book.because(f"{NOT_SETTLED}: {nothing}", none),)


def _verdict_fact(verdict: m.ReportVerdict) -> tuple[str | None, str | None]:
    """(the hypothesis the verdict names, the fact that says so) when **a person** holds the
    verdict: the people's review, or a person who confirmed the case as a real problem. The
    fact is the verdict's own first sentence. It supports the hypothesis it names and rules
    nothing else out. An AI investigator's or the engine's proposal, or a reading, is an opinion
    of ARGUS's about the facts, not a fact: it names no hypothesis here (the report's verdict
    says it)."""
    if verdict.kind not in ("person", "case") or verdict.outcome is None:
        return None, None
    named = NAMED_BY.get(verdict.outcome)
    if named is None or not verdict.sentences:
        return None, None
    return named, verdict.sentences[0].cites[0]


def hypotheses(
    scene: Scene, book: Book, verdict: m.ReportVerdict
) -> tuple[m.ReportHypothesis, ...]:
    """Each hypothesis is judged from facts of its own (:func:`judge`): the threat reading by the
    outside detections, threat-list hits, evidence flags and served paths; the harmless and the
    rule-fault readings are counted against by those same facts; "one device" by the spread. A
    person's verdict (the people's review, a confirmed case) supports the hypothesis it names and
    rules no other out on its own; a proposal of the AI or the engine is not a fact. A
    successful answer to an attacker does not rule out research scanning."""
    basis = _support(scene, book)
    support = [b.id for b in basis]
    words = {b.id: b.label for b in basis}
    named, said = _verdict_fact(verdict)
    pro: dict[str, list[str]] = {k: [] for k in ("threat", "benign", "one", "rule", "research")}
    con: dict[str, list[str]] = {k: [] for k in pro}
    pro["threat"] += support
    con["benign"] += support
    con["rule"] += support
    if len(scene.devices) >= 3:
        many = plural(len(scene.devices), site.own("device"), site.own("devices"))
        ident = book.add(
            "entity",
            f"{many} are named in the case.",
            "the case's indicators",
            (len(scene.devices),),
        )
        con["one"].append(ident)
        words[ident] = f"{many} named, more than one person's experiment"
    if named is not None and said is not None:
        pro[named].append(said)
        words[said] = "the people's review"
    # the rule's own alerts are not evidence beyond the rule: its reason names what stands apart
    own = {b.id for b in basis if not b.independent}
    apart = {i: w for i, w in words.items() if i not in own} if len(own) < len(basis) else words
    by_review = verdict.kind == "person"
    out: list[m.ReportHypothesis] = []

    def add(
        key: str, name: str, *, rests: str, ruled: str, nothing: str, show: bool = True
    ) -> None:
        if not show:
            return
        status = judge(pro[key], con[key])
        if by_review and key == named and said in pro[key]:
            rests = "The people's review says so" + (
                " and facts support it:" if len(pro[key]) > 1 else ":"
            )
        why = _why(
            book, status, pro[key], con[key], rests=rests, ruled=ruled, nothing=nothing,
            labels=apart if key == "rule" else words,
        )  # fmt: skip
        out.append(m.ReportHypothesis(name=name, status=status, by="argus", why=why))

    add(
        "threat",
        "A real threat: malicious activity or a compromise (a true positive)",
        rests="It rests on:",
        ruled="Ruled out by:",
        nothing="ARGUS found no fact for or against it yet.",
    )
    add(
        "benign",
        "Expected or harmless activity (benign)",
        rests="It rests on:",
        ruled="Ruled out by facts a harmless explanation does not account for:",
        nothing="ARGUS found no fact for or against it yet.",
    )
    add(
        "one",
        "One device or one person's experiment",
        rests="It rests on:",
        ruled="Ruled out by the spread:",
        nothing="only a few devices are named, so this cannot be ruled out.",
        show=bool(scene.devices),
    )
    add(
        "rule",
        "A fault in the detection rule (a false positive)",
        rests="A person or ARGUS read it as the rule's fault:",
        ruled="Ruled out: the activity is backed by facts beyond the rule:",
        nothing="nothing found shows the rule is at fault.",
    )
    add(
        "research",
        "Internet research or measurement scanning",
        rests="It rests on:",
        ruled="Ruled out by:",
        nothing=(
            "a successful answer shows what the scan reached, not who ran it, so ARGUS cannot"
            " rule out a researcher's scan from the alerts alone."
            if scene.f.served
            else "ARGUS cannot rule out a researcher's scan from the alerts alone."
        ),
        show=bool(scene.outsiders),
    )
    return (*out, *_investigator(scene, book))


def _investigator(scene: Scene, book: Book) -> list[m.ReportHypothesis]:
    """The hypotheses the AI investigator weighed, by name, as it wrote them (not judged here)."""
    seen: set[str] = set()
    out: list[m.ReportHypothesis] = []
    for a in scene.f.assessments:
        if not a.assessor.startswith("agent"):
            continue
        report = next((r for r in a.reasons if isinstance(r, Mapping)), None)
        answer = report.get("answer") if isinstance(report, Mapping) else None
        raw = answer.get("hypotheses") if isinstance(answer, Mapping) else None
        for h in (raw if isinstance(raw, list) else [])[:4]:
            name = h.get("name") if isinstance(h, Mapping) else None
            if not isinstance(name, str) or not name.strip():
                continue
            name = cut(name, 200)
            if name.lower() in seen:
                continue
            seen.add(name.lower())
            fact = book.add(
                "verdict",
                "The AI investigator weighed this hypothesis; its name is shown as it wrote it.",
                "the AI investigator's stored answer",
            )
            why = (book.because("Weighed by the AI investigator.", fact),)
            out.append(m.ReportHypothesis(name=name, status="open", by="investigator", why=why))
        if len(out) >= 4:
            break
    return out


def actions(scene: Scene, book: Book) -> m.ReportActions:
    """The catalogue's actions for the families the case's facts match, then ARGUS's open
    reminders (notify the owner again, ask for network-side action), then when to close."""
    cat = scene.ctx.catalogue
    lines: list[m.ReportActionLine] = []
    held = {a.action: a.state for a in scene.f.actions}
    note = None
    if cat is not None:
        facts = responder_facts.Facts(frozenset(scene.f.advice))
        families = responder_facts.match(cat, facts)
        for family in families:
            for action in family.actions:
                lines.append(
                    m.ReportActionLine(
                        id=action.id,
                        title=action.title,
                        say=action.say,
                        owner=cat.owners[action.owner].name,
                        state=held.get(action.id, "recommended"),
                        family=family.key,
                        rank=action.rank,
                    )
                )
        if not families:
            note = (
                "No action in the responder's catalogue applies to this case yet; a person "
                "decides what to ask for."
            )
    for rem in scene.f.reminders:
        again = rem.kind == "notify_again"
        lines.append(
            m.ReportActionLine(
                id=f"reminder.{rem.kind}",
                title="Notify the owner again" if again else "Ask for network-side action",
                say=cut(rem.why, 400),
                owner=site.organisation().short_name if again else "Network team",
                state="suggested",
                family=None,
                rank=100 + len(lines),
            )
        )
    if scene.f.case.notified_at is not None:
        quiet = scene.ctx.quiet_days
        fact = book.add(
            "case",
            f'ARGUS proposes closing a notified case as "stopped after notice" after {quiet} days '
            "with no matching activity.",
            "the case rules (D-169)",
            (quiet,),
        )
        close = book.because("A person approves the closure; ARGUS only proposes it.", fact)
    else:
        fact = book.add(
            "case",
            f"The still-active watch calls a case quiet after {WATCH_QUIET_DAYS} whole UTC days "
            "without activity.",
            "the case rules (Q-C2)",
            (WATCH_QUIET_DAYS,),
        )
        close = book.because(
            "Close the case when the actions above are done and the case has been quiet; "
            "closing needs a person's approval.",
            fact,
        )
    return m.ReportActions(lines=tuple(lines), close_when=close, note=note)


def notice(scene: Scene) -> m.ReportNotice | None:
    """The notice state: the owner was told, the alerts since, still active or not."""
    case = scene.f.case
    if case.notified_at is None:
        return None
    k = scene.f.known
    told = tuple(
        dict.fromkeys(
            cut(n.told, 100) for n in scene.f.notices if n.kind == "owner" and not n.withdrawn
        )
    )
    since = k.alerts if k is not None else 0
    last = k.last_alert_at if k is not None else None
    active = bool(last and scene.ctx.as_at - last <= timedelta(days=scene.ctx.active_days))
    line = f"The owner was told on {ist_date(case.notified_at)}"
    if told:
        line += f" ({told[0]})"
    if case.blocked_at is not None:
        line += f"; a network block was recorded on {ist_date(case.blocked_at)}"
    if active and last is not None:
        line += (
            f". Since then {plural(since, 'more alert')} arrived, the last at {ist_moment(last)}: "
            "the device is still active."
        )
    elif since:
        line += f". Since then {plural(since, 'more alert')} arrived, and none recently."
    else:
        line += ". No alert has arrived since."
    return m.ReportNotice(
        notified_at=case.notified_at,
        told=told,
        blocked_at=case.blocked_at,
        alerts_since=since,
        last_alert_at=last,
        still_active=active,
        changes=len(k.changes) if k is not None else 0,
        line=cut(line, 500),
    )


STANDING_WORDS = {
    "ongoing": "The activity is still going on: the last alert is recent.",
    "quiet": "The activity looks quiet: no alert has come for several days.",
    "unknown": "ARGUS cannot tell yet whether it is still going on.",
}


def summary(scene: Scene, book: Book, verdict: m.ReportVerdict) -> m.ReportSummary:
    """What happened, to what, since when, whether it is still going on, with the notice state
    and ARGUS's verdict."""
    n_dev, n_srv, n_out = len(scene.devices), len(scene.servers), len(scene.outsiders)
    alerts, n_rules = plural(scene.alerts, "alert"), plural(len(scene.rules), "rule")
    if n_dev and n_srv:
        what = (
            f"{plural(n_dev, site.own('device'), site.own('devices'))} contacted "
            f"{plural(n_srv, 'server or name', 'servers or names')} that the case lists as "
            f"command-and-control, raising {alerts} from {n_rules}."
        )
        numbers = [n_dev, n_srv, scene.alerts, len(scene.rules)]
    elif n_out:
        what = (
            f"{plural(n_out, 'outside address', 'outside addresses')} acted against "
            f"{site.where()} systems, raising {alerts} from {n_rules}."
        )
        numbers = [n_out, scene.alerts, len(scene.rules)]
    else:
        what = f"{alerts} from {n_rules} are in this case."
        numbers = [scene.alerts, len(scene.rules)]
    sentences = [
        book.say(
            "alerts", what, "ARGUS's stored alerts and the case's indicators", numbers, safe=what
        )
    ]
    if scene.first and scene.last:
        apart = dwell(scene.last - scene.first)
        text = (
            f"The first alert was at {ist_moment(scene.first)} and the last at "
            f"{ist_moment(scene.last)}, {apart} apart."
        )
        safe = f"The first and the last alert are {apart} apart."
        sentences.append(book.say("alerts", text, "ARGUS's stored alerts", safe=safe))
    words = STANDING_WORDS[scene.standing]
    sentences.append(book.say("alerts", words, "ARGUS's stored alerts", safe=words))
    said = notice(scene)
    if said is not None:
        sentences.append(
            book.say(
                "notice",
                said.line,
                "the case record and ARGUS's known-infection count",
                [said.alerts_since],
            )
        )
    if scene.flagged:
        sentences.append(intel_sentence(scene, book))
    sentences.append(verdict.sentences[0])
    title = f"{verdict.words[:1].upper()}{verdict.words[1:]}: {scene.f.case.title}"
    return m.ReportSummary(
        headline=cut(title, 400),
        standing=scene.standing,
        standing_words=words,
        sentences=tuple(sentences),
        notice=said,
    )
