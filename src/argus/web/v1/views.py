"""From ARGUS's records to the ``/api/v1`` models (Q-A1).

Every function reads what the classic pages read (``queries``, ``assessed``, ``dashboard``,
the gold and tuning stores) and keeps only what the models name. Stored JSON (dossiers, the
investigator's runs, tuning reports) is years of versions of ARGUS's own output: a field of
an unexpected type is left out or read as empty, never a 500 (a property test feeds these
functions arbitrary JSON)."""

from __future__ import annotations

import math
import uuid
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from typing import Any, Literal, cast, get_args

from argus.agent import reading as readings
from argus.report.model import HIDDEN
from argus.report.render import FLOOR_HIDDEN, FLOOR_KEPT
from argus.report.render import reason as hidden_reason
from argus.web import assessed, dashboard, queries, stance
from argus.web.render import plain
from argus.web.v1 import models as m

OUTCOMES = frozenset(get_args(m.Outcome))
STATUSES = frozenset(get_args(m.AssessmentStatus))
STATES = frozenset(get_args(m.HumanState))
STEP_STATUSES = frozenset({"answered", "deferred", "manual", "unknown"})
AI_KINDS = frozenset({"proposed_tp", "proposed_other", "no_proposal", "working", "none"})
LIST_CAP = 500  # items of any stored list kept (the pages show fewer)


# --------------------------------------------------------------------------- reading JSON


def _dict(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _list(value: Any) -> list[Any]:
    return list(value[:LIST_CAP]) if isinstance(value, list | tuple) else []


def _text(value: Any) -> str:
    if isinstance(value, str):
        return value
    return "" if value is None or isinstance(value, dict | list) else str(value)


def _opt_text(value: Any) -> str | None:
    return None if value is None or isinstance(value, dict | list) else _text(value)


def _texts(value: Any) -> list[str]:
    return [_text(v) for v in _list(value) if v is not None and not isinstance(v, dict | list)]


def _int(value: Any, default: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return default
    if isinstance(value, float) and not math.isfinite(value):
        return default
    return int(value)


def _opt_int(value: Any) -> int | None:
    return None if isinstance(value, bool) or not isinstance(value, int | float) else _int(value)


def _float(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def _outcome(value: Any) -> m.Outcome | None:
    return value if isinstance(value, str) and value in OUTCOMES else None  # type: ignore[return-value]


def _uuid(value: Any) -> uuid.UUID | None:
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except (ValueError, TypeError, AttributeError):
        return None


def _key_fields(pairs: Iterable[Any]) -> list[m.KeyField]:
    out = []
    for pair in pairs:
        if isinstance(pair, list | tuple) and len(pair) == 2:
            out.append(m.KeyField(field=_text(pair[0]), value=pair[1]))
    return out


# --------------------------------------------------------------------------- investigations


def ai_verdict(found: Mapping[str, Any] | None) -> m.AiVerdictOut | None:
    if not found:
        return None
    status = found.get("status")
    if not isinstance(status, str) or status not in STATUSES:
        return None
    return m.AiVerdictOut(
        assessor=_text(found.get("assessor")),
        source=_text(found.get("source")),
        status=status,  # type: ignore[arg-type]
        outcome=_outcome(found.get("outcome")),
        confidence=_float(found.get("confidence")),
    )


def _known(s: queries.Summary) -> m.KnownRefOut | None:
    if s.known_case is None or s.known_case_id is None:
        return None
    if s.known_outcome not in ("known", "changed"):
        return None
    # a case that ended (or whose notice was withdrawn) keeps what it decided known: frozen, so
    # ``notified_at`` is None then (D-181)
    return m.KnownRefOut(
        case_id=s.known_case_id,
        case_number=s.known_case,
        outcome=s.known_outcome,  # type: ignore[arg-type]
        why=s.known_why,
        notified_at=s.known_since,
    )


def investigation(s: queries.Summary, ai: Mapping[str, Any] | None = None) -> m.InvestigationOut:
    return m.InvestigationOut(
        id=s.id,
        rule_id=s.rule_id,
        rule_name=s.rule_name,
        key_fields=_key_fields(s.key_fields),
        bucket_start=s.bucket_start,
        alert_count=s.alert_count,
        duplicate_count=s.duplicate_count,
        first_event_at=s.first_event_at,
        last_event_at=s.last_event_at,
        severity=s.severity,
        risk_score=_float(s.risk_score),
        version=s.version,
        created_at=s.created_at,
        continues_id=s.continues_id,
        human_state=s.human_state,
        latest_review=s.latest_review,
        new_since_review=s.new_since_review,
        last_outcome=_outcome(s.last_outcome),
        last_reviewed_at=s.last_reviewed_at,
        last_reviewer=s.last_reviewer,
        reasons=list(s.reasons),
        ai=ai_verdict(ai),
        known=_known(s),
    )


def coverage(banners: Sequence[Mapping[str, Any]]) -> list[m.CoverageOut]:
    out = []
    for b in banners:
        runs = [m.CoverageRunOut(start_at=r["start_at"], detail=_opt_text(r.get("detail")))
                for r in b.get("runs", []) if isinstance(r.get("start_at"), datetime)]  # fmt: skip
        out.append(
            m.CoverageOut(
                kind=_text(b.get("kind")),
                start_at=b["start_at"],
                end_at=b.get("end_at"),
                text=_text(b.get("text")),
                runs=runs,
            )
        )
    return out


def _fact(name: str, fact: Mapping[str, Any]) -> m.FieldFactOut:
    top = []
    for pair in _list(fact.get("top")):
        if isinstance(pair, list | tuple) and len(pair) == 2:
            top.append(m.ValueCount(value=pair[0], count=_int(pair[1])))
    return m.FieldFactOut(field=name, stand_in=_opt_text(fact.get("from")), top=top,
                          distinct=_int(fact.get("distinct"), len(top)))  # fmt: skip


def dossier(found: Mapping[str, Any] | None) -> m.DossierOut | None:
    """The investigation page's "Overview" and "What ARGUS checked" from the newest dossier."""
    if found is None:
        return None
    body = _dict(found.get("body"))
    report = _dict(found.get("report"))
    fields = _dict(found.get("fields"))
    pack = _dict(_dict(body.get("context")).get("pack"))
    steps = []
    for s in _list(report.get("steps")):
        step = _dict(s)
        status = step.get("status")
        shown = [_fact(f, _dict(fields.get(f))) for f in _texts(step.get("shown"))
                 if isinstance(fields.get(f), Mapping)]  # fmt: skip
        steps.append(m.StepOut(
            number=_opt_int(step.get("number")), text=_text(step.get("text")),
            status=cast(m.StepStatus, status)
            if isinstance(status, str) and status in STEP_STATUSES
            else "other",
            sentence=plain(_text(step.get("sentence"))), shown=shown,
        ))  # fmt: skip
    addresses = [
        m.AddressOut(address=_text(ip), kind=_text(_dict(info).get("class")),
                     asset=_opt_text(_dict(info).get("asset")))
        for ip, info in list(_dict(found.get("ips")).items())[:LIST_CAP]
    ]  # fmt: skip
    related = []
    for r in _list(found.get("related")):
        row = _dict(r)
        inv = _uuid(row.get("investigation_id"))
        if inv is None:
            continue
        related.append(m.RelatedOut(
            investigation_id=inv, rule_id=_opt_text(row.get("rule_id")),
            rule_name=_opt_text(row.get("rule_name")),
            key_fields=_key_fields(_list(row.get("key_fields"))),
            bucket_start=_opt_text(row.get("bucket_start")), shared=_int(row.get("shared")),
        ))  # fmt: skip
    has_note = report.get("has_note")
    return m.DossierOut(
        version=_int(found.get("version")),
        pack=_text(found.get("pack")),
        status=_text(found.get("status")),
        partial_reason=_opt_text(found.get("partial_reason")),
        created_at=found["created_at"],
        facts=[*_texts(report.get("summary")), *_texts(found.get("sentences"))],
        decoded_paths=_texts(_dict(pack.get("web")).get("decoded_paths")),
        addresses=addresses,
        related=related,
        steps=steps,
        has_note=has_note if isinstance(has_note, bool) else None,
        complete=report.get("complete", True) is not False,
        alerts_read=_int(report.get("alerts_read")),
    )


def run(report: Mapping[str, Any] | None, *, hide_logs: bool = False) -> m.RunOut | None:
    """The AI investigator's stored run (agent@1's report), as the page shows it. For an
    account without log access (``hide_logs``) everything the model or a check read from the
    logs is the report's "Hidden: needs log access in ELK." (the explanation, the cited
    facts, the hypotheses, each check's result, the specialists' notes); what was asked, the
    rounds, the calls and the cost stay (report@2's own rule, ``render.hide_logs``)."""
    if not isinstance(report, Mapping):
        return None
    answer = report.get("answer")
    out_answer = None
    if isinstance(answer, Mapping):
        hypotheses = [
            m.HypothesisOut(name=_text(_dict(h).get("name")),
                            evidence_for=_texts(_dict(h).get("for")),
                            evidence_against=_texts(_dict(h).get("against")))
            for h in _list(answer.get("hypotheses")) if isinstance(h, Mapping)
        ]  # fmt: skip
        explanation, cites = _opt_text(answer.get("explanation")), _texts(answer.get("cites"))
        if hide_logs:
            explanation = HIDDEN if explanation is not None else None
            cites = [HIDDEN] if cites else []
            hypotheses = [m.HypothesisOut(name=HIDDEN, evidence_for=[], evidence_against=[])
                          for _ in hypotheses]  # fmt: skip
        out_answer = m.AnswerOut(
            outcome=_outcome(answer.get("outcome")), confidence=_float(answer.get("confidence")),
            explanation=explanation, hypotheses=hypotheses, cites=cites,
        )  # fmt: skip
    checks = [m.CheckOut(tool=_text(_dict(c).get("tool")), value=_text(_dict(c).get("value")),
                         result=HIDDEN if hide_logs else _text(_dict(c).get("result")))
              for c in _list(report.get("checks")) if isinstance(c, Mapping)]  # fmt: skip
    specialists = [m.SpecialistOut(domain=_text(_dict(x).get("domain")),
                                   notes=HIDDEN if hide_logs else _text(_dict(x).get("notes")))
                   for x in _list(report.get("specialists")) if isinstance(x, Mapping)]  # fmt: skip
    return m.RunOut(answer=out_answer, checks=checks, specialists=specialists,
                    rounds=_opt_int(report.get("rounds")), calls=_opt_int(report.get("calls")),
                    models=_texts(report.get("models")), cost_usd=_float(report.get("cost_usd")),
                    seconds=_float(report.get("seconds")))  # fmt: skip


def reading(r: readings.Reading | None, *, hide_logs: bool = False) -> m.ReadingOut | None:
    """ARGUS's reading of a run that proposed nothing. For an account without log access
    (``hide_logs``) the model's reason and quotes are hidden, as in ``run``, and the floor's
    parts are the ones ``render.reason`` keeps."""
    if r is None:
        return None
    blocked = None
    if hide_logs:
        blocked = [*(p for p in r.blocked if p in FLOOR_KEPT), FLOOR_HIDDEN]
    reason = r.reason if not hide_logs or r.reason is None else HIDDEN
    return m.ReadingOut(
        kind=r.kind,  # type: ignore[arg-type]
        outcome=r.outcome,  # type: ignore[arg-type]
        confidence=r.confidence, headline=r.headline(blocked), why=r.why(blocked), reason=reason,
        facts=[] if hide_logs else [m.ReadingFactOut(text=f.text, checked=f.checked)
                                    for f in r.facts],
    )  # fmt: skip


def assessment(d: assessed.Detail, *, hide_logs: bool = False) -> m.AssessmentOut | None:
    """One assessor's newest assessment. For an account without log access (``hide_logs``) the
    investigator's own reasons are cut to ARGUS's fixed words (``render.reason``, as the
    report's verdict does) and its run is hidden (``run``)."""
    if d.status not in STATUSES:
        return None
    model_words = hide_logs and (d.report is not None or assessed.is_agent(d.assessor))
    return m.AssessmentOut(
        id=d.assessment_id, assessor=d.assessor, source=d.source, status=d.status,  # type: ignore[arg-type]
        outcome=_outcome(d.outcome), confidence=_float(d.confidence), decided_by=d.key,
        reasons=[hidden_reason(r) for r in d.reasons] if model_words else list(d.reasons),
        run=run(d.report, hide_logs=hide_logs), reading=reading(d.reading, hide_logs=hide_logs),
        created_at=d.created_at, finished_at=d.finished_at,
    )  # fmt: skip


def same_pattern(s: assessed.Shared, *, hide_logs: bool = False) -> m.SamePatternOut | None:
    """The investigator's run on another investigation of the pattern (AR2), as the run's own
    assessment is shown, for an account with or without log access."""
    shown = assessment(s.detail, hide_logs=hide_logs)
    if shown is None:
        return None
    return m.SamePatternOut(investigation_id=s.source, earlier=s.earlier, assessment=shown)


def stance_out(
    found: stance.Choice | None,
    *,
    hide_logs: bool = False,
    acceptable_id: int | None = None,
    size: tuple[int, int] | None = None,
) -> m.StanceOut:
    """What ARGUS thinks of an investigation (AR4): a recommendation, a reading, or nothing.
    ``acceptable_id``: the investigation's own current proposal, which ``/accept`` takes; a
    pattern's run and a reading are never acceptable. ``size``: how many investigations (and
    alerts) the run stands for."""
    shown = None if found is None else assessment(found.detail, hide_logs=hide_logs)
    if found is None or shown is None:
        return m.StanceOut(kind="none", outcome=None, confidence=None, source=None, why=None,
                           assessment_id=None, from_investigation_id=None, acceptable=False,
                           pattern_investigations=None, pattern_alerts=None)  # fmt: skip
    if found.proposed:
        kind: Literal["recommends", "reading"] = "recommends"
        outcome, sure, why = shown.outcome, shown.confidence, None
    else:
        read = shown.reading
        kind = "reading"
        outcome = read.outcome if read is not None else None
        sure = read.confidence if read is not None else None
        why = read.why if read is not None else None
    return m.StanceOut(
        kind=kind, outcome=outcome, confidence=sure, source=found.detail.source, why=why,
        assessment_id=found.detail.assessment_id,
        from_investigation_id=found.source,
        acceptable=found.proposed and found.source is None and acceptable_id == shown.id,
        pattern_investigations=None if size is None else size[0],
        pattern_alerts=None if size is None else size[1],
    )  # fmt: skip


def gold_item(row: Any) -> m.GoldItemOut | None:
    if row is None:
        return None
    suggestion = _dict(row.suggestion)
    return m.GoldItemOut(
        split=row.split, why=list(row.why),
        suggestion=m.GoldSuggestionOut(outcome=_opt_text(suggestion.get("outcome")),
                                       source=_opt_text(suggestion.get("source")),
                                       reasons=_texts(suggestion.get("reasons"))),
        outcome=_outcome(row.outcome), note=row.note, answered_by=row.answered_by,
        answered_at=row.answered_at,
    )  # fmt: skip


def review(row: Mapping[str, Any]) -> m.ReviewOut:
    return m.ReviewOut(id=row["id"], action=row["action"], outcome=_outcome(row["outcome"]),
                       note=row["note"], version=row["version"], alert_count=row["alert_count"],
                       created_at=row["created_at"], reviewer=row["display_name"])  # fmt: skip


def alerts(rows: Sequence[Mapping[str, Any]], total: int, columns: list[str]) -> m.AlertsOut:
    items = []
    for a in rows:
        entities = [m.EntityOut(kind=_text(_dict(e).get("kind")), value=_dict(e).get("value"))
                    for e in _list(a.get("entities")) if isinstance(e, Mapping)]  # fmt: skip
        items.append(m.AlertOut(
            alert_id=a["alert_id"], detected_at=a["detected_at"], event_time=a["event_time"],
            status=a["status"], workflow_status=a["workflow_status"],
            duplicate_of=a["duplicate_of"], late_arrival=bool(a["late_arrival"]),
            severity=_opt_text(a.get("severity")), entities=entities,
            cells={k: _text(v) for k, v in _dict(a.get("cols")).items()},
        ))  # fmt: skip
    return m.AlertsOut(total=total, columns=columns, items=items)


# --------------------------------------------------------------------------- the other pages


def proposal_groups(groups: Sequence[assessed.Group]) -> list[m.ProposalGroupOut]:
    def one(p: assessed.Proposal) -> m.ProposalOut:
        return m.ProposalOut(assessment_id=p.assessment_id, investigation_id=p.investigation_id,
                             rule=p.rule, alerts=p.alerts, bucket_start=p.bucket_start,
                             reason=p.reason)  # fmt: skip

    return [
        m.ProposalGroupOut(
            group=g.group,
            source=g.source,
            decided_by=g.key,
            outcome=_outcome(g.outcome),
            rule=g.rule,
            models=sorted(g.models),
            size=len(g.items),
            items=[one(p) for p in g.items],
            sample=[one(p) for p in g.sample],
        )
        for g in groups
    ]


def patterns(
    groups: Sequence[Mapping[str, Any]],
    advice: Mapping[int, stance.Recommendation] | None = None,
) -> list[m.PatternOut]:
    """The Patterns page's groups. ``advice`` maps a group's place in ``groups`` to ARGUS's
    recommendation for it (AR4), when it has one."""
    out = []
    for place, g in enumerate(groups):
        members = [m.PatternMemberOut(investigation_id=uuid.UUID(str(x["id"])),
                                      version=int(x["version"]), latest_review=x.get("latest"))
                   for x in g["members"]]  # fmt: skip
        common = [m.PatternCommonOut(field=_text(f), values=_texts(values))
                  for f, values in g.get("common", [])]  # fmt: skip
        out.append(
            m.PatternOut(
                rule_id=g["rule_id"],
                rule_name=g.get("rule_name"),
                steps=_texts(g.get("steps")),
                listed=bool(g.get("listed")),
                common=common,
                alerts=_int(g.get("alerts")),
                members=members,
                recommendation=recommendation(advice.get(place) if advice else None),
            )
        )
    return out


def recommendation(r: stance.Recommendation | None) -> m.PatternRecommendationOut | None:
    if r is None or r.outcome not in OUTCOMES:
        return None
    return m.PatternRecommendationOut(
        outcome=r.outcome,  # type: ignore[arg-type]
        confidence=_float(r.confidence), source=r.source, members=list(r.members),
        covered=len(r.members), total=r.total,
    )  # fmt: skip


def rules(rows: Sequence[Mapping[str, Any]]) -> list[m.RuleOut]:
    return [
        m.RuleOut(
            rule_id=r["rule_id"],
            rule_name=r["rule_name"],
            investigations=int(r["investigations"]),
            open=int(r["open"]),
            alerts=int(r["alerts"] or 0),
            last_event_at=r["last_event_at"],
            type=r["type"],
            revision=r["revision"],
            interval=r["interval"],
            max_signals=r["max_signals"],
            execution_status=r["execution_status"],
            truncated=int(r["truncated"] or 0),
        )
        for r in rows
    ]


def entities(rows: Sequence[Mapping[str, Any]]) -> list[m.EntityRowOut]:
    return [m.EntityRowOut(kind=r["kind"], value=r["value"], investigations=r["investigations"],
                           supernode=bool(r["supernode"])) for r in rows]  # fmt: skip


def health(h: Mapping[str, Any]) -> m.HealthOut:
    run = h.get("last_reconciliation")
    return m.HealthOut(
        siem_state=h["siem_state"], siem_reasons=[str(r) for r in h["siem_reasons"]],
        siem_probed_at=h["siem_probed_at"], live_cursor=h["live_cursor"],
        backfill_cursor=h["backfill_cursor"],
        open_gaps=[m.GapOut(kind=g["kind"], subject=g["subject"], start_at=g["start_at"],
                            detail=g["detail"]) for g in h["open_gaps"]],
        last_reconciliation=None if run is None else m.ReconciliationOut(
            finished_at=run["finished_at"], hours=run["hours"],
            hours_mismatched=run["hours_mismatched"], recovered=run["recovered"],
            outcome=run["outcome"]),
        alerts=h["alerts"], quarantined=h["quarantined"], investigations=h["investigations"],
        jobs_waiting=h["jobs_waiting"], jobs_deferred=h["jobs_deferred"],
        jobs_failed=h["jobs_failed"], dossiers=h["dossiers"],
        checkpoint_threads=h["checkpoint_threads"], checkpoint_bytes=h["checkpoint_bytes"],
    )  # fmt: skip


def cost(c: Mapping[str, Any]) -> m.CostOut:
    return m.CostOut(
        month_usd=c["month_usd"], today_usd=c["today_usd"], cap_usd=c["cap_usd"],
        paid_until_usd=c["paid_until_usd"], daily_cap_usd=c["daily_cap_usd"],
        calls_today=c["calls_today"],
        providers=[m.ProviderCostOut(provider=p, today_usd=v["today_usd"], calls=v["calls"])
                   for p, v in c["providers"].items()],
        stopped=c["stopped"], at=datetime.fromisoformat(c["at"]),
    )  # fmt: skip


def metrics(x: assessed.Metrics, quota: Sequence[tuple[str, str]], stopped: bool) -> m.MetricsOut:
    return m.MetricsOut(
        validator_blocks=x.validator_blocks,
        calls=[m.ProviderCallsOut(provider=p, attempts=n, ok=ok, cost_usd=c)
               for p, (n, ok, c) in x.calls.items()],
        fallbacks=x.fallbacks, floor_hits=x.floor_hits,
        backlog=[m.BacklogOut(assessor=a, waiting=n,
                              oldest_wait_s=None if w is None else w.total_seconds())
                 for a, (n, w) in x.backlog.items()],
        outcomes=[m.OutcomeCountOut(assessor=a, label=label, count=n)
                  for a, counts in x.outcomes.items() for label, n in counts.items()],
        month_cost_usd=x.month_cost,
        quota=[m.QuotaOut(bucket=b, usage=u) for b, u in quota], stopped=stopped,
    )  # fmt: skip


def tuning(rows: Sequence[Mapping[str, Any]]) -> list[m.TuningReportOut]:
    out = []
    for r in rows:
        report = _dict(r.get("report"))
        labels = {_text(k): _int(v) for k, v in _dict(report.get("labels")).items()}
        suggestions = [
            m.SuggestionOut(kind=_text(_dict(s).get("kind")), path=_opt_text(_dict(s).get("path")),
                            value=_opt_text(_dict(s).get("value")),
                            change=_text(_dict(s).get("change")), why=_text(_dict(s).get("why")),
                            risk=_text(_dict(s).get("risk")),
                            evidence=_texts(_dict(s).get("evidence")))
            for s in _list(r.get("suggestions")) if isinstance(s, Mapping)
        ]  # fmt: skip
        out.append(m.TuningReportOut(
            rule=r["rule"], week_end=r["week_end"], alerts=_opt_int(report.get("alerts")),
            investigations=_opt_int(report.get("investigations")),
            runs=_opt_int(report.get("runs")), runs_at_limit=_opt_int(report.get("runs_at_limit")),
            max_signals=_opt_int(report.get("max_signals")), labels=labels,
            suggestions=suggestions, dropped=_texts(r.get("dropped")),
            model=_opt_text(r.get("model")), cost_usd=_float(r.get("cost_usd")),
            created_at=r["created_at"],
        ))  # fmt: skip
    return out


def gold_set(rows: Sequence[Any], progress: Mapping[str, int]) -> m.GoldSetOut:
    items = [m.GoldRowOut(investigation_id=r.investigation_id, rule_name=r.rule_name,
                          split=r.split, why=list(r.why), outcome=_outcome(r.outcome),
                          answered_by=r.answered_by, answered_at=r.answered_at)
             for r in rows]  # fmt: skip
    by_split = {k.removesuffix("_answered"): v for k, v in progress.items()
                if k.endswith("_answered")}  # fmt: skip
    return m.GoldSetOut(items=items, progress=m.GoldProgressOut(
        items=progress["items"], answered=progress["answered"], by_split=by_split))  # fmt: skip


def _brief(c: dashboard.Case) -> m.InvestigationBrief:
    return m.InvestigationBrief(
        id=uuid.UUID(c.id), rule=c.rule, severity=c.severity, alert_count=c.alert_count,
        last_event_at=c.last_event_at, state=c.state if c.state in STATES else "unreviewed",  # type: ignore[arg-type]
        verdict=c.verdict, ai=c.ai if c.ai in AI_KINDS else "none",  # type: ignore[arg-type]
        key_fields=_key_fields(c.key_fields),
    )  # fmt: skip


def dashboard_out(d: dashboard.Dashboard) -> m.DashboardOut:
    f = d.filters
    k = d.kpis
    return m.DashboardOut(
        filters=m.DashboardFiltersOut(
            range=f.range, start=f.start, end=f.end, severity=list(f.severity),  # type: ignore[arg-type]
            state=list(f.state), verdict=list(f.verdict), ai=list(f.ai), rule=f.rule,
            kind=f.kind, value=f.value),
        start=d.start, end=d.end, bucket=d.bucket,  # type: ignore[arg-type]
        kpis=m.DashboardKpis(
            investigations=k["cases"], open=k["open"], attention=k["attention"], known=k["known"],
            follow_up=k["follow_up"], incidents=k["incidents"], suspected=k["suspected"],
            reviewed=k["reviewed"], assessed=k["assessed"], open_critical=k["open_critical"],
            alerts=k["alerts"], alerts_before=k["alerts_before"],
            median_review_s=k["median_review_s"]),
        series=[m.SeriesPoint(at=at, counts=dict(counts)) for at, counts in d.series],
        states=dict(d.states), severities=dict(d.severities), verdicts=dict(d.verdicts),
        ai=dict(d.ais),
        rules=[m.RuleShare(rule_id=r["rule_id"], rule=str(r["rule"]),
                           investigations=int(r["cases"]), alerts=int(r["alerts"] or 0),
                           open=int(r["open"]), incidents=int(r["incidents"]),
                           suspected=int(r["suspected"]), severity=r["severity"])
               for r in d.rules],
        entities={kind: [m.EntityShare(kind=e["kind"], value=e["value"],
                                       investigations=int(e["cases"]),
                                       alerts=int(e["alerts"] or 0), open=int(e["open"]))
                         for e in rows] for kind, rows in d.entities.items()},
        incidents=[_brief(c) for c in d.incidents],
        open_investigations=[_brief(c) for c in d.open_cases],
        rule_choices=[m.RuleChoice(rule_id=rid, rule=str(name)) for rid, name in d.rule_choices],
        notified=[m.NotifiedBrief(case_id=c.case_id, case_number=c.number, title=c.title,
                                  notified_at=c.notified_at,
                                  days=c.days, alerts=c.alerts, trend=c.trend,
                                  blocked=c.blocked_at is not None,
                                  reminders=[r.kind for r in c.reminders])  # type: ignore[misc]
                  for c in d.notified],
    )  # fmt: skip


def threat_tile(t: dashboard.ThreatTile) -> m.ThreatTileOut:
    return m.ThreatTileOut(
        examined=t.examined, on_a_list=t.on_a_list, clear=t.clear,
        could_not_tell=t.could_not_tell, not_checked=t.not_checked,
        listed=[_brief(c) for c in t.listed],
    )  # fmt: skip


def since_out(at: datetime | None, found: Mapping[str, int]) -> m.SinceOut:
    return m.SinceOut(
        since=at, cap=queries.SINCE_CAP, new_investigations=found["new_investigations"],
        new_severe=found["new_severe"], reviewed_by_others=found["reviewed_by_others"],
        new_proposals=found["new_proposals"],
    )  # fmt: skip
