import { Link } from "@tanstack/react-router";
import { useState, type ReactNode } from "react";
import type { CaseDetail, CaseReportOut, IncidentReport } from "../../client/types.gen";
import { bandWords, sidesWithoutEngine, stillFitsLine, type Alternative, type Engine } from "../../lib/engine";
import { reportAlternatives, reportCall } from "../../lib/incident";
import { usePhone } from "../../lib/viewport";
import { plainWords } from "../../lib/plainWords";
import { Loading, Problem } from "../Problem";
import { UntrustedText } from "../UntrustedText";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { AlternativesList, CheckList } from "./CheckList";
import { cisoSent, CisoDraftDialog } from "./Ciso";
import { ChangedStrip, ChipRow } from "./Parts";
import { WhyPoints } from "./WhyPoints";

const SEEN_WORDS: Record<string, string> = { path: "Paths", domain: "Domains", user_agent: "User agent", file: "Files", size: "Size" };

function Region({ name, title, aside, children }: { name: string; title?: string; aside?: ReactNode; children: ReactNode }) {
  return (
    <section data-region={name} aria-label={title} className="flex flex-col gap-1.5">
      {title !== undefined && (
        <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
          <h2 className="m-0 text-base font-semibold">{title}</h2>
          {aside}
        </div>
      )}
      {children}
    </section>
  );
}

/** The report's summary in at most three sentences: the AI's, labelled, or the code's, unlabelled (§7.3 rule 3). */
function WhatHappened({ data, id }: { data: CaseReportOut | undefined; id: string }) {
  const report = (data?.report ?? null) as IncidentReport | null;
  if (report === null) return null;
  const ai = report.summary.prose.length > 0;
  const sentences = (ai ? report.summary.prose : report.summary.sentences).slice(0, 3);
  if (sentences.length === 0) return null;
  return (
    <Region
      name="what-happened"
      title="What happened"
      aside={
        ai ? (
          <span className="text-sm text-muted" data-testid="ai-label" title="Generated from the facts on this page; each sentence is checked against them. ARGUS does not act on it.">
            Written by ARGUS&apos;s AI from the evidence below <span aria-hidden="true">ⓘ</span>
          </span>
        ) : undefined
      }
    >
      <p className="m-0 max-w-[72ch] text-[0.9375rem] leading-relaxed" data-testid="summary">
        {sentences.map((s, i) => (
          <span key={i}>
            <UntrustedText value={plainWords(s.text)} limits={{ maxChars: 600, maxLines: 6 }} />{" "}
          </span>
        ))}
        <Link to="/incidents/$id" params={{ id }} search={{ tab: "report" }} className="text-sm">
          Read the full report
        </Link>
      </p>
    </Region>
  );
}

function Collapsible({ phone, count, children, more }: { phone: boolean; count: number; children: ReactNode; more: ReactNode }) {
  const [open, setOpen] = useState(false);
  if (!phone || count <= 3) return <>{more}</>;
  return (
    <>
      {open ? more : children}
      <Button size="sm" variant="ghost" className="self-start" aria-expanded={open} onClick={() => setOpen(!open)}>
        {open ? "Show fewer" : `Show all ${count}`}
      </Button>
    </>
  );
}

function NextSteps({ detail, engine, report }: { detail: CaseDetail; engine: Engine | null; report: IncidentReport | null }) {
  const [drafting, setDrafting] = useState(false);
  const confirmed = ["open", "assigned", "contained"].includes(detail.case.state);
  const sent = cisoSent(detail);
  const lines = report?.actions.lines ?? [];
  const ciso = confirmed && sent === null;
  if (lines.length === 0 && !ciso) {
    return (
      <Region name="next-steps" title="Next steps">
        <p className="m-0 text-sm text-muted">No ready-made step for this kind of incident yet. See the incident report.</p>
      </Region>
    );
  }
  return (
    <Region name="next-steps" title="Next steps" aside={<span className="text-sm text-muted">from the incident report</span>}>
      <ol className="m-0 flex flex-col gap-2 pl-5 text-sm" data-testid="next-steps">
        {ciso && (
          <li data-testid="ciso-step">
            <span className="font-medium">Report to the CISO:</span> summary, devices, time window, accounts; PDF attached. <span className="text-muted">Who: you</span>{" "}
            <Button size="sm" onClick={() => setDrafting(true)}>
              Draft it…
            </Button>
          </li>
        )}
        {lines.map((l) => (
          <li key={l.id}>
            <span className="font-medium">
              <UntrustedText value={l.title} limits={{ maxChars: 200, maxLines: 2 }} />
            </span>
            {l.say && (
              <>
                : <UntrustedText value={l.say} limits={{ maxChars: 400, maxLines: 4 }} />
              </>
            )}{" "}
            <span className="text-muted">
              Who: <UntrustedText value={l.owner} limits={{ maxChars: 80, maxLines: 1 }} />
            </span>
          </li>
        ))}
      </ol>
      {ciso && <CisoDraftDialog detail={detail} engine={engine} open={drafting} onOpenChange={setDrafting} />}
    </Region>
  );
}

/**
 * The Overview tab (docs/p4f-ui-spec.md §7.3): one order for every incident, in at most two screens
 * — what changed, any disagreement, what happened (and what still fits), why (points that add up),
 * what was seen, what was checked, other explanations, next steps, related incidents, the two
 * sides. No queries, rule ids, member tables or report versions here: the other tabs hold them.
 */
export function Overview({ detail, engine, report }: { detail: CaseDetail; engine: Engine | null; report: { data: CaseReportOut | undefined; isPending: boolean; isError: boolean; error: unknown; refetch: () => unknown } }) {
  const phone = usePhone();
  const body = (report.data?.report ?? null) as IncidentReport | null;
  const fits = stillFitsLine(engine);
  const sides = engine ? engine.objects : sidesWithoutEngine(detail.indicators, body);
  const affected = sides.filter((o) => o.role === "affected");
  const actors = sides.filter((o) => o.role === "actor");
  const alternatives: Alternative[] = engine ? engine.alternatives : reportAlternatives(body);
  const call = reportCall(body?.verdict);
  return (
    <div className="flex flex-col gap-5" data-testid="overview">
      {engine && engine.changed.length > 0 && (
        <div data-region="changed">
          <ChangedStrip changed={engine.changed} testId="overview-changed" />
        </div>
      )}
      {engine?.disagreement && (
        <p data-region="disagreement" className="m-0 rounded-control border border-warn/40 bg-warn-soft px-3 py-2 text-sm text-warn">
          <span aria-hidden="true">⚠ </span>
          <UntrustedText value={engine.disagreement} limits={{ maxChars: 400, maxLines: 3 }} />
        </p>
      )}
      {engine === null && (
        <p className="m-0 text-sm text-muted" data-testid="not-scored">
          {call ? `${call} · not prioritised yet.` : "ARGUS has not prioritised this incident yet."}
        </p>
      )}
      {report.isPending && <Loading what="what happened" />}
      {report.isError && (
        <div data-region="what-happened">
          <Problem error={report.error} what="What happened" onRetry={() => void report.refetch()} />
        </div>
      )}
      <WhatHappened data={report.data} id={detail.case.id} />
      {fits && (
        <p data-region="still-fits" className="-mt-3 m-0 text-sm" data-testid="still-fits-line">
          <UntrustedText value={fits.text} limits={{ maxChars: 400, maxLines: 3 }} />
          {fits.more > 0 && (
            <>
              {" "}
              <a href="#other-explanations">+{fits.more}</a>
            </>
          )}
        </p>
      )}
      {engine && (
        <Region name="why" title="Why ARGUS raised it" aside={<span className="text-sm font-medium tabular-nums" data-testid="priority-heading">Priority {engine.priority} of 100 · {bandWords(engine.band)}</span>}>
          {engine.raised_by_ai && (
            <p className="m-0">
              <Badge tone="info">Raised by ARGUS&apos;s AI</Badge>
            </p>
          )}
          <WhyPoints engine={engine} top={phone ? 3 : undefined} />
        </Region>
      )}
      {engine && engine.seen.length > 0 && (
        <Region name="seen" title="What was seen">
          <dl className="m-0 grid grid-cols-[6.5rem_1fr] gap-x-3 gap-y-1 text-sm" data-testid="seen">
            {Object.keys(SEEN_WORDS)
              .filter((k) => engine.seen.some((s) => s.kind === k))
              .map((k) => (
                <div key={k} className="contents" id={`seen-${k}`}>
                  <dt className="font-medium">{SEEN_WORDS[k]}</dt>
                  <dd className="m-0 min-w-0">
                    {engine.seen
                      .filter((s) => s.kind === k)
                      .slice(0, 3)
                      .map((s, i) => (
                        <span key={i} className="mr-3 break-all">
                          <UntrustedText value={s.value} limits={{ maxChars: 160, maxLines: 1 }} /> <span className="text-muted tabular-nums">×{s.count.toLocaleString("en-US")}</span>
                        </span>
                      ))}
                  </dd>
                </div>
              ))}
          </dl>
          <Link to="/incidents/$id" params={{ id: detail.case.id }} search={{ tab: "evidence" }} className="self-end text-sm">
            All in Evidence ›
          </Link>
        </Region>
      )}
      {engine && engine.checks.length > 0 && (
        <Region name="checked" title="What ARGUS checked">
          <Collapsible phone={phone} count={engine.checks.length} more={<CheckList checks={engine.checks} />}>
            <CheckList checks={engine.checks} limit={3} />
          </Collapsible>
        </Region>
      )}
      {alternatives.length > 0 && (
        <div id="other-explanations">
          <Region name="alternatives" title="Other explanations">
            <Collapsible phone={phone} count={alternatives.length} more={<AlternativesList alternatives={alternatives} />}>
              <AlternativesList alternatives={alternatives} limit={3} />
            </Collapsible>
          </Region>
        </div>
      )}
      <NextSteps detail={detail} engine={engine} report={body} />
      {engine && engine.related.length > 0 && (
        <Region name="related" title="Related incidents">
          <ul className="m-0 flex list-none flex-col gap-1 p-0 text-sm">
            {engine.related.slice(0, 5).map((r) => (
              <li key={r.case_id}>
                <span className="font-medium">#{r.number}</span> <UntrustedText value={r.title} limits={{ maxChars: 160, maxLines: 1 }} /> — <UntrustedText value={r.reason} limits={{ maxChars: 160, maxLines: 1 }} />
              </li>
            ))}
          </ul>
        </Region>
      )}
      {(affected.length > 0 || actors.length > 0) && (
        <Region name="sides">
          <div className="flex flex-col gap-1.5 text-sm" data-testid="sides">
            {affected.length > 0 && <ChipRow objects={affected} max={3} label="Campus side (affected)" />}
            {actors.length > 0 && <ChipRow objects={actors} max={3} label="Other side (actor)" />}
          </div>
        </Region>
      )}
    </div>
  );
}
