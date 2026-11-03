import { Link } from "@tanstack/react-router";
import type { AssessmentOut, InvestigationDetail, SamePatternOut } from "../../client/types.gen";
import { outcomeLabel } from "../../lib/labels";
import { own } from "../../lib/site";
import { Time } from "../Time";
import { UntrustedText } from "../UntrustedText";
import { Badge } from "../ui/badge";
import { DataTable } from "../ui/table";
import { AcceptAction, AskAction, NeedsCapability, useCan } from "./actions";
import { Reading } from "./Reading";

function capital(text: string): string {
  return text.charAt(0).toUpperCase() + text.slice(1);
}

/** "The AI investigator: proposes True positive (75%)" and the other states, as the classic page says them. */
export function assessmentTitle(a: Pick<AssessmentOut, "source" | "status" | "outcome" | "confidence">): string {
  const who = capital(a.source);
  switch (a.status) {
    case "proposed": {
      const sure = a.confidence === null ? "" : ` (${Math.round(a.confidence * 100)}%)`;
      return `${who}: proposes ${outcomeLabel(a.outcome)}${sure}`;
    }
    case "no_decision":
      return `${who}: no proposal`;
    case "queued":
    case "running":
      return `${who}: working on it`;
    default:
      return `${who}: could not finish`;
  }
}

function AssessmentCard({ a, detail }: { a: AssessmentOut; detail: InvestigationDetail }) {
  const canReview = useCan("review");
  const run = a.run;
  const answer = run?.answer ?? null;
  const reading = a.status === "no_decision" ? a.reading : null;
  const acceptable = detail.acceptable_assessment_id === a.id;
  return (
    <article aria-label={assessmentTitle(a)} className="flex flex-col gap-2 rounded-card border border-border bg-surface p-3">
      <h3 className="m-0 text-base font-semibold">{assessmentTitle(a)}</h3>
      {(a.status === "queued" || a.status === "running") && (
        <p className="m-0 text-sm text-muted">
          Asked <Time value={a.created_at} />; this page reads again by itself every 15 seconds.
        </p>
      )}
      {reading ? (
        <Reading reading={reading} />
      ) : (
        <>
          {answer?.explanation ? (
            <p className="m-0 text-sm">
              <strong>Explanation.</strong> <UntrustedText value={answer.explanation} limits={{ maxChars: 2000, maxLines: 30 }} />
            </p>
          ) : a.reasons.length > 0 ? (
            <p className="m-0 text-sm">
              <strong>Why.</strong> <UntrustedText value={a.reasons[0]} limits={{ maxChars: 600, maxLines: 6 }} />
            </p>
          ) : null}
          {(a.status === "no_decision" || a.status === "failed") && a.reasons.length > 1 && (
            <p className="m-0 text-sm">
              <strong>Why no proposal.</strong> <UntrustedText value={a.reasons.slice(1).join("; ")} limits={{ maxChars: 1200, maxLines: 12 }} />
            </p>
          )}
          {answer?.outcome && a.status === "no_decision" && (
            <p className="m-0 text-xs text-muted">The model&apos;s own answer was {outcomeLabel(answer.outcome)}; ARGUS did not propose it for the reason above.</p>
          )}
        </>
      )}
      {answer && answer.hypotheses.length > 0 && (
        <>
          <h4 className="m-0 text-sm font-semibold">Hypotheses it weighed</h4>
          <DataTable
            caption="Hypotheses the AI investigator weighed"
            rows={answer.hypotheses}
            rowKey={(h, i) => `${h.name}:${i}`}
            columns={[
              { key: "h", header: "Hypothesis", cell: (h) => <UntrustedText value={h.name} limits={{ maxChars: 200, maxLines: 2 }} /> },
              { key: "for", header: "For it", cell: (h) => (h.evidence_for.length === 0 ? "—" : h.evidence_for.map((f, i) => <div key={i}><UntrustedText value={f} limits={{ maxChars: 300, maxLines: 3 }} /></div>)) },
              { key: "against", header: "Against it", cell: (h) => (h.evidence_against.length === 0 ? "—" : h.evidence_against.map((f, i) => <div key={i}><UntrustedText value={f} limits={{ maxChars: 300, maxLines: 3 }} /></div>)) },
            ]}
          />
        </>
      )}
      {answer && answer.cites.length > 0 && !reading && (
        <>
          <h4 className="m-0 text-sm font-semibold">Facts it cited (each checked against the evidence)</h4>
          <ul className="m-0 pl-5 text-sm">
            {answer.cites.map((c, i) => (
              <li key={i}>
                <q>
                  <UntrustedText value={c} limits={{ maxChars: 300, maxLines: 3 }} />
                </q>
              </li>
            ))}
          </ul>
        </>
      )}
      {run && run.checks.length > 0 ? (
        <>
          <h4 className="m-0 text-sm font-semibold">What it checked in the SIEM</h4>
          <ul className="m-0 pl-5 text-sm">
            {run.checks.map((c, i) => (
              <li key={i}>
                <span className="font-mono"><UntrustedText value={c.tool} limits={{ maxChars: 40, maxLines: 1 }} /></span> on{" "}
                <span className="font-mono"><UntrustedText value={c.value} limits={{ maxChars: 120, maxLines: 1 }} /></span>: <UntrustedText value={c.result} limits={{ maxChars: 200, maxLines: 2 }} />
              </li>
            ))}
          </ul>
        </>
      ) : run ? (
        <p className="m-0 text-xs text-muted">It needed no extra SIEM checks: it judged from the evidence ARGUS had already collected.</p>
      ) : null}
      {run && run.specialists.length > 0 && (
        <>
          <h4 className="m-0 text-sm font-semibold">Specialists consulted</h4>
          <ul className="m-0 pl-5 text-sm">
            {run.specialists.map((s, i) => (
              <li key={i}>
                <strong>{capital(s.domain)}:</strong> <UntrustedText value={s.notes} limits={{ maxChars: 1000, maxLines: 10 }} />
              </li>
            ))}
          </ul>
        </>
      )}
      <p className="m-0 text-xs text-muted">
        {run && a.status !== "queued" && a.status !== "running" && (
          <>
            {run.rounds} {run.rounds === 1 ? "round" : "rounds"}, {run.calls} model {run.calls === 1 ? "call" : "calls"} (<UntrustedText value={run.models.join(", ") || "none"} limits={{ maxChars: 200, maxLines: 1 }} />), ${(run.cost_usd ?? 0).toFixed(4)}, {run.seconds} s ·{" "}
          </>
        )}
        {a.status !== "queued" && a.status !== "running" && (
          <>
            decided by <UntrustedText value={a.decided_by} limits={{ maxChars: 200, maxLines: 1 }} />
          </>
        )}
        {a.finished_at && (
          <>
            {" "}
            · <Time value={a.finished_at} />
          </>
        )}
      </p>
      {acceptable && a.status === "proposed" && (
        <div className="flex flex-col items-start gap-1">
          {canReview ? (
            <>
              <AcceptAction investigationId={detail.investigation.id} assessment={a} />
              <p className="m-0 text-xs text-muted">To override, choose another outcome in the review form: your verdict is a label ARGUS learns from.</p>
            </>
          ) : (
            <NeedsCapability what="accepting a proposal" capability="review" />
          )}
        </div>
      )}
    </article>
  );
}

/** AR2: the investigator reads one investigation of each pattern a day; this is its run on another, shown here as a link and its headline. Never a proposal for this investigation. */
function SamePattern({ pattern }: { pattern: SamePatternOut }) {
  const a = pattern.assessment;
  const reading = a.status === "no_decision" ? a.reading : null;
  return (
    <p className="m-0 text-sm" data-testid="same-pattern">
      {pattern.earlier ? (
        "This investigation, before it changed: "
      ) : (
        <>
          Same pattern as{" "}
          <Link to="/investigations/$id" params={{ id: pattern.investigation_id }} className="font-mono">
            {pattern.investigation_id}
          </Link>
          :{" "}
        </>
      )}
      <strong>{reading ? reading.headline : assessmentTitle(a)}</strong>. It is not a proposal for this investigation and cannot be accepted here.
    </p>
  );
}

/** The AI assessment tab: each assessor's newest, the investigator first; and the way to ask the AI investigator. */
export function Assessments({ detail }: { detail: InvestigationDetail }) {
  const canReview = useCan("review");
  const canSeeLogs = useCan("see_logs");
  const inv = detail.investigation;
  // a member of a pattern always has the decision engine's own "no proposal"; only a run of the AI investigator on this investigation replaces the shared reading
  const ownRun = detail.assessments.some((a) => a.assessor.startsWith("agent"));
  return (
    <div className="flex flex-col gap-3">
      <p className="m-0 text-sm text-muted">
        What ARGUS proposes for this investigation, and why. The <strong>decision engine</strong> proposes only what people&apos;s past verdicts on the same kind of alert support; the <strong>AI investigator</strong> reads the evidence (with {own("names")} hidden), may check the SIEM, weighs hypotheses and must quote the facts it relies on. You decide.
      </p>
      {!canSeeLogs && detail.assessments.some((a) => a.run !== null) && (
        <p className="m-0 text-sm text-muted" data-testid="logs-hidden">
          Your account cannot read the logs in ELK, so what the logs said, and the AI investigator&apos;s words about it, are hidden here (as in the report).
        </p>
      )}
      {detail.same_pattern && !ownRun && <SamePattern pattern={detail.same_pattern} />}
      {detail.assessments.length === 0 && !detail.same_pattern && (
        <p className="m-0 text-sm">
          {inv.human_state === "reviewed"
            ? "Not assessed: this investigation was reviewed before ARGUS assessed it. ARGUS assesses on its own only what nobody has reviewed yet."
            : "Not assessed yet. New investigations are assessed within minutes; the AI investigator takes the newest first, up to its daily limit."}
        </p>
      )}
      {detail.assessments.map((a) => (
        <AssessmentCard key={a.id} a={a} detail={detail} />
      ))}
      {detail.ask_available && (
        <div className="flex flex-col items-start gap-1">
          {canReview ? <AskAction investigationId={inv.id} /> : <NeedsCapability what="asking the AI investigator" capability="review" />}
        </div>
      )}
    </div>
  );
}

export function AiBrief({ detail }: { detail: InvestigationDetail }) {
  const canReview = useCan("review");
  const top = detail.assessments[0];
  if (!top) return null;
  const answer = top.run?.answer ?? null;
  const acceptable = detail.acceptable_assessment_id === top.id && top.status === "proposed";
  return (
    <section aria-label="What ARGUS proposes" className="flex flex-col gap-1.5 rounded-card border border-border bg-surface-2 p-3">
      <h3 className="m-0 flex flex-wrap items-center gap-2 text-base font-semibold">
        {assessmentTitle(top)}
        {top.status === "proposed" && <Badge tone="info">a proposal, not a decision</Badge>}
      </h3>
      {top.status === "no_decision" && top.reading && (
        <p className="m-0 text-sm font-semibold" data-testid="reading-brief">
          {top.reading.headline}
        </p>
      )}
      {answer?.explanation ? (
        <p className="m-0 text-sm">
          <UntrustedText value={answer.explanation} limits={{ maxChars: 400, maxLines: 6 }} />
        </p>
      ) : top.reasons[0] ? (
        <p className="m-0 text-sm">
          <UntrustedText value={top.reasons[0]} limits={{ maxChars: 400, maxLines: 6 }} />
        </p>
      ) : null}
      {acceptable && canReview && (
        <div className="self-start">
          <AcceptAction investigationId={detail.investigation.id} assessment={top} />
        </div>
      )}
    </section>
  );
}
