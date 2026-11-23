import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { getPerformance } from "../../client/sdk.gen";
import type { BandOut, KeptOut, OverdueOut, TimesOut } from "../../client/types.gen";
import { unwrap } from "../../lib/call";
import type { Range } from "../../lib/dashboardFilters";
import { count, plural } from "../../lib/format";
import { span } from "../../lib/viz";
import { Loading, Problem } from "../Problem";
import { UntrustedText } from "../UntrustedText";
import { ChartCard, FigureTable, Meter, Stat } from "../viz/kit";

const REFRESH_MS = 60_000;

const mean = (t: TimesOut): string => (t.mean_s === null ? "—" : span(t.mean_s));
const median = (t: TimesOut): string => (t.median_s === null ? "" : `median ${span(t.median_s)}`);

/** "92%", or a dash while nothing is settled. */
export function keptShare(k: KeptOut): string {
  return k.share === null ? "—" : `${Math.round(k.share * 100)}%`;
}

/** "11 of 12 in time · 2 still in time", in words a tile can carry. */
export function keptWords(k: KeptOut, verb: string): string {
  const settled = k.met + k.missed;
  const waiting = k.pending > 0 ? `${count(k.pending)} still in time` : "";
  if (settled === 0) return waiting || `nothing was ${verb} in this span`;
  return [`${count(k.met)} of ${count(settled)} ${verb} within their target`, waiting].filter(Boolean).join(" · ");
}

function BandMeters({ band }: { band: BandOut }) {
  const row = (label: string, k: KeptOut, target: number) => {
    const settled = k.met + k.missed;
    const words = settled === 0 ? (k.pending > 0 ? `${count(k.pending)} still in time` : "none yet") : `${count(k.met)} of ${count(settled)} in time${k.pending > 0 ? ` · ${count(k.pending)} waiting` : ""}`;
    return <Meter label={`${band.band} · ${label} within ${span(target)}`} value={k.met} limit={settled} words={words} good="high" />;
  };
  return (
    <li className="grid gap-x-6 gap-y-2 sm:grid-cols-2" data-testid="band-row">
      {row("decide", band.triage, band.triage_target_s)}
      {row("close", band.resolve, band.resolve_target_s)}
    </li>
  );
}

function OverdueRow({ o }: { o: OverdueOut }) {
  return (
    <li>
      <Link to="/incidents/$id" params={{ id: o.id }} className="-mx-2 flex items-start gap-2.5 rounded-control px-2 py-1.5 text-sm text-text no-underline hover:bg-surface-2" data-testid="overdue-row">
        <span className="mt-0.5 inline-flex min-w-9 shrink-0 justify-center rounded-control border border-border-strong px-1.5 py-px text-xs tabular-nums">{o.band}</span>
        <span className="flex min-w-0 flex-1 flex-col">
          <span className="truncate">
            #{o.number} <UntrustedText value={o.title} limits={{ maxChars: 160, maxLines: 1 }} />
          </span>
          <span className="text-xs text-danger">
            {o.kind === "triage" ? "Not decided" : "Not closed"} for {span(o.waited_s)}; the target is {span(o.target_s)}
          </span>
        </span>
      </Link>
    </li>
  );
}

/**
 * How fast alerts become decisions (D-340), on the Security overview: the mean time to detect,
 * to a person's first decision and to close, the share decided and closed within the site's
 * targets, the targets by priority, and what is past its time now, one click from the incident.
 */
export function Response({ range }: { range: Range }) {
  const perf = useQuery({ queryKey: ["dashboards", "performance", range], queryFn: () => unwrap(getPerformance({ query: { range } })), placeholderData: keepPreviousData, staleTime: 30_000, refetchInterval: REFRESH_MS });
  if (perf.isPending) return <Loading what="the response times" />;
  if (perf.isError) return <Problem error={perf.error} what="The response times" onRetry={() => void perf.refetch()} />;
  const p = perf.data;
  return (
    <section aria-label="Response times" className="flex flex-col gap-3" data-testid="response">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 className="m-0 text-lg font-semibold">Response times</h2>
        <p className="m-0 text-sm text-muted">
          For the {count(p.raised)} {plural(p.raised, "incident")} raised in this span: {count(p.confirmed)} confirmed, {count(p.dismissed)} dismissed, {count(p.waiting)} waiting.
        </p>
      </div>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Stat label="Time to detect (MTTD)" value={mean(p.detect)} note={p.detect.count === 0 ? "ARGUS raised no incident in this span" : `${median(p.detect)} · from the first alert to ARGUS raising the incident`} testId="stat-mttd" />
        <Stat label="Time to a first decision (MTTA)" value={mean(p.triage)} note={p.triage.count === 0 ? "nobody decided one in this span" : `${median(p.triage)} · ${count(p.triage.count)} decided by a person`} testId="stat-mtta" />
        <Stat label="Time to close (MTTR)" value={mean(p.resolve)} note={p.resolve.count === 0 ? "no confirmed incident was closed in this span" : `${median(p.resolve)} · ${count(p.resolve.count)} closed, from confirmation`} testId="stat-mttr" />
        <Stat label="Decided in time (SLA)" value={keptShare(p.triage_kept)} note={keptWords(p.triage_kept, "decided")} testId="stat-sla-triage" />
        <Stat label="Closed in time (SLA)" value={keptShare(p.resolve_kept)} note={keptWords(p.resolve_kept, "closed")} testId="stat-sla-resolve" />
        <Stat label="Past their time now" value={count(p.overdue_total)} note={p.due_soon > 0 ? `${count(p.due_soon)} more with three quarters of their time used` : "none is close to it"} target={{ to: "/incidents", search: { view: "needs-you" } }} testId="stat-overdue" />
      </div>
      <div className="grid gap-3 lg:grid-cols-2">
        <ChartCard
          title="Targets by priority"
          hint={
            <>
              How many were decided, and closed, within the time their priority gives. The times are yours to set in <Link to="/settings">Settings › Response times</Link>.
            </>
          }
          table={<FigureTable caption="Targets by priority" head={["Priority", "Raised", "Decided in time", "Decided late", "Closed in time", "Closed late"]} rows={p.bands.map((b) => [b.band, b.raised, b.triage.met, b.triage.missed, b.resolve.met, b.resolve.missed])} />}
          testId="sla-bands"
        >
          <ul className="m-0 flex list-none flex-col gap-3 p-0">
            {p.bands.map((b) => (
              <BandMeters key={b.band} band={b} />
            ))}
          </ul>
        </ChartCard>
        <ChartCard title="Past their time now" hint="Undecided or unclosed for longer than their priority allows, the furthest past first, whenever they were raised." testId="overdue">
          {p.overdue.length === 0 ? (
            <p className="m-0 text-sm text-muted">Nothing is past its time.</p>
          ) : (
            <ul className="m-0 flex list-none flex-col gap-0.5 p-0">
              {p.overdue.map((o) => (
                <OverdueRow key={`${o.kind}:${o.id}`} o={o} />
              ))}
            </ul>
          )}
          {p.overdue_total > p.overdue.length && <p className="m-0 text-sm text-muted">{count(p.overdue_total - p.overdue.length)} more are not listed.</p>}
        </ChartCard>
      </div>
    </section>
  );
}
