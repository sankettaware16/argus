import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useEffect, useRef, type MutableRefObject } from "react";
import type { IncidentReport } from "../../client/types.gen";
import { mergedAlternatives, side, stateWords, ALT_WORDS } from "../../lib/engine";
import { caseOptions, caseReportOptions } from "../../lib/queries";
import { Loading, Problem } from "../Problem";
import { UntrustedText } from "../UntrustedText";
import { Button } from "../ui/button";
import { PossibleButtons } from "../decide/Decide";
import { engineOfDetail, targetOfDetail } from "../decide/target";
import { CheckList } from "../incident/CheckList";
import { ActivityLine, ChipRow, PriorityBadge } from "../incident/Parts";
import { WhyPoints } from "../incident/WhyPoints";

/**
 * The queue's preview pane (docs/p4f-ui-spec.md §6.4), at 1280 px and wider: the header, what
 * happened, why (every point), what was checked, other explanations in a line, the two sides and
 * the same decision buttons as the bar. Read lazily; the next row is read ahead.
 */
export function PreviewPane({
  id,
  nextId,
  onClose,
  onMove,
  confirmRef,
  dismissRef,
}: {
  id: string;
  nextId: string | null;
  onClose: () => void;
  onMove: (step: 1 | -1) => void;
  confirmRef: MutableRefObject<(() => void) | null>;
  dismissRef: MutableRefObject<(() => void) | null>;
}) {
  const found = useQuery(caseOptions(id));
  const report = useQuery(caseReportOptions(id, null));
  const queries = useQueryClient();
  const box = useRef<HTMLElement>(null);
  useEffect(() => {
    if (nextId) void queries.prefetchQuery(caseOptions(nextId));
  }, [nextId, queries]);
  const d = found.data;
  const engine = d ? engineOfDetail(d) : null;
  const body = (report.data?.report ?? null) as IncidentReport | null;
  const summary = body ? (body.summary.prose.length > 0 ? body.summary.prose : body.summary.sentences).slice(0, 3) : [];
  const alt = engine ? mergedAlternatives(engine.alternatives) : [];
  const fits = alt.filter((a) => a.state === "fits");
  return (
    <aside ref={box} aria-label="Preview" data-testid="preview-pane" className="flex max-h-[calc(100vh-6rem)] flex-col gap-3 overflow-auto rounded-card border border-border bg-surface p-4 xl:sticky xl:top-4">
      <div className="flex items-center gap-2">
        {d && <span className="font-semibold tabular-nums">#{d.case.number}</span>}
        <span className="ml-auto flex items-center gap-1">
          <Button size="sm" variant="ghost" aria-label="Previous incident" onClick={() => onMove(-1)}>
            ↑
          </Button>
          <Button size="sm" variant="ghost" aria-label="Next incident" onClick={() => onMove(1)}>
            ↓
          </Button>
          <Link to="/incidents/$id" params={{ id }} className="inline-flex min-h-7 items-center rounded-control border border-border-strong px-2 text-sm text-text no-underline hover:bg-surface-2">
            Open page
          </Link>
          <Button size="sm" variant="ghost" aria-label="Close the preview" onClick={onClose}>
            ✕
          </Button>
        </span>
      </div>
      {found.isPending && <Loading what="the incident" />}
      {found.isError && <Problem error={found.error} what="The incident" onRetry={() => void found.refetch()} />}
      {d && (
        <>
          <p className="m-0 flex flex-wrap items-center gap-2 text-sm">
            <PriorityBadge engine={engine} /> {stateWords({ state: d.case.state, number: null, taken_by: d.case.owner ? { username: d.case.owner.username, name: d.case.owner.display_name } : null })}
          </p>
          <h2 className="m-0 text-lg leading-snug font-semibold" data-testid="preview-title">
            <UntrustedText value={d.case.title} limits={{ maxChars: 240, maxLines: 3 }} />
          </h2>
          {engine && (
            <p className="m-0 text-sm text-muted">
              <ActivityLine engine={engine} capital />
            </p>
          )}
          {summary.length > 0 && (
            <section aria-label="What happened" className="flex flex-col gap-1">
              <h3 className="m-0 text-sm font-semibold">What happened</h3>
              <p className="m-0 text-sm">
                {summary.map((s, i) => (
                  <span key={i}>
                    <UntrustedText value={s.text} limits={{ maxChars: 400, maxLines: 4 }} />{" "}
                  </span>
                ))}
              </p>
            </section>
          )}
          {engine && (
            <section aria-label="Why" className="flex flex-col gap-1">
              <h3 className="m-0 text-sm font-semibold">Why · Priority {engine.priority} of 100</h3>
              <WhyPoints engine={engine} />
            </section>
          )}
          {engine && engine.checks.length > 0 && (
            <section aria-label="Checked" className="flex flex-col gap-1">
              <h3 className="m-0 text-sm font-semibold">Checked</h3>
              <CheckList checks={engine.checks} />
            </section>
          )}
          {alt.length > 0 && (
            <p className="m-0 text-sm">
              <span className="font-semibold">Other explanations: </span>
              {fits.length > 0 ? (
                <>
                  {fits.length} still {fits.length === 1 ? "fits" : "fit"}: <UntrustedText value={fits.map((f) => f.names.join("; ")).join("; ")} limits={{ maxChars: 200, maxLines: 2 }} />
                </>
              ) : (
                alt.map((a) => `${ALT_WORDS[a.state]}: ${a.names.join("; ")}`).join(" · ")
              )}
            </p>
          )}
          {engine && (
            <div className="flex flex-col gap-1 text-sm">
              <ChipRow objects={side(engine, "affected")} label="Campus side" />
              <ChipRow objects={side(engine, "actor")} label="Other side" />
            </div>
          )}
          {d.case.state === "suspected" && d.decision && <PossibleButtons target={targetOfDetail(d)} confirmRef={confirmRef} dismissRef={dismissRef} />}
        </>
      )}
    </aside>
  );
}
