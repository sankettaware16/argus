"""The report for a person whose ELK account cannot read the logs.

A fact derived from log content reads ``Hidden: needs log access in ELK.`` in the fact, in every
sentence that cites it, in the evidence line's count and details and in the actor's request count;
the query itself stays. Accounts named in the alerts are left out of the assets and the accounts
that signed in from the case's devices are dropped, leaving each device's state and count. Hiding
twice changes nothing more."""

from __future__ import annotations

from argus.incident import model as m


def hide_logs(report: m.IncidentReport) -> m.IncidentReport:
    """``report`` without what the logs said."""
    hidden = {f.id for f in report.facts if f.from_logs}
    answers = any(a.answered is not None or a.served for a in report.actors) or any(
        t.answered is not None or t.served for t in report.targets
    )
    if (
        not hidden
        and not answers
        and report.brief is None
        and not any(a.kind == "account" for a in report.assets)
    ):
        return report

    def sentence(s: m.ReportSentence) -> m.ReportSentence:
        if set(s.cites) & hidden:
            return s.model_copy(update={"text": m.HIDDEN})
        return s

    facts = tuple(
        f.model_copy(update={"text": m.HIDDEN, "numbers": (), "safe": None})
        if f.id in hidden
        else f
        for f in report.facts
    )
    summary = report.summary.model_copy(
        update={
            "sentences": tuple(sentence(s) for s in report.summary.sentences),
            "prose": tuple(sentence(s) for s in report.summary.prose),
        }
    )
    verdict = report.verdict.model_copy(
        update={"sentences": tuple(sentence(s) for s in report.verdict.sentences)}
    )
    timeline = report.timeline.model_copy(
        update={
            "phases": tuple(
                p.model_copy(update={"sentence": sentence(p.sentence)})
                for p in report.timeline.phases
            ),
            "notes": tuple(sentence(s) for s in report.timeline.notes),
        }
    )
    actors = tuple(
        a.model_copy(
            update={
                "requests": None if a.sentence and set(a.sentence.cites) & hidden else a.requests,
                "sentence": sentence(a.sentence) if a.sentence else None,
                "answered": None,  # what the web server answered is read from the logs
                "served": (),
            }
        )
        for a in report.actors
    )
    targets = tuple(t.model_copy(update={"answered": None, "served": ()}) for t in report.targets)
    hypotheses = tuple(
        h.model_copy(update={"why": tuple(sentence(s) for s in h.why)}) for h in report.hypotheses
    )
    evidence = tuple(
        e.model_copy(update={"count": None, "shows": None, "details": ()}) if e.from_logs else e
        for e in report.evidence
    )
    assets = tuple(a for a in report.assets if a.kind != "account")
    users = report.users.model_copy(
        update={
            "devices": tuple(
                d.model_copy(update={"sentence": sentence(d.sentence), "accounts": ()})
                for d in report.users.devices
            ),
            "signins": (),
            "same": sentence(report.users.same) if report.users.same else None,
        }
    )  # the accounts are personal data from the logs
    actions = report.actions.model_copy(
        update={
            "close_when": sentence(report.actions.close_when) if report.actions.close_when else None
        }
    )
    return report.model_copy(
        update={
            "facts": facts,
            "summary": summary,
            "verdict": verdict,
            "timeline": timeline,
            "actors": actors,
            "targets": targets,
            "hypotheses": hypotheses,
            "evidence": evidence,
            "assets": assets,
            "users": users,
            "actions": actions,
            # the brief is a reading of what the logs said
            "brief": None,
            "brief_note": m.HIDDEN if report.brief is not None else report.brief_note,
            "out_of_scope": tuple(sentence(s) for s in report.out_of_scope),
        }
    )
