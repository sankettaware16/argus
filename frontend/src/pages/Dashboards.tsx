import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { useMemo, useState, type ReactNode } from "react";
import { getDashboard, listCases } from "../client/sdk.gen";
import type { DashboardOut, EntityShare, HealthOut, MetricsOut, RuleShare, UsageOut } from "../client/types.gen";
import { PriorityBadge } from "../components/incident/Parts";
import { Loading, Problem } from "../components/Problem";
import { Time } from "../components/Time";
import { UntrustedText } from "../components/UntrustedText";
import { Button } from "../components/ui/button";
import { CostsBoard } from "../components/dashboards/CostsBoard";
import { Response } from "../components/dashboards/Response";
import { Columns } from "../components/viz/Columns";
import { ChartCard, FigureTable, Meter, Rank, Share, Stat, type RankRow, type SharePart, type Target } from "../components/viz/kit";
import { unwrap } from "../lib/call";
import { bucketLabel } from "../lib/chart";
import { cn } from "../lib/cn";
import type { Range } from "../lib/dashboardFilters";
import { BOARD_HINTS, BOARD_WORDS, BOARDS, boardOf, RANGE_BEFORE, RANGE_WORDS, rangeOf, type Board, type DashboardsSearch } from "../lib/dashboards";
import { engineOf, isIp, isPrivateIp, stateWords, type Today } from "../lib/engine";
import { count, plural } from "../lib/format";
import { AI_TITLES, SEVERITIES, STATE_TITLES, VERDICT_TITLES } from "../lib/labels";
import { healthPageOptions, metricsOptions } from "../lib/queries";
import { can, useSession } from "../lib/session";
import { own } from "../lib/site";
import { todayOptions } from "../lib/today";
import { usageOptions } from "../lib/usage";
import { change, compact, oneIn, span, total, type Series } from "../lib/viz";

const REFRESH_MS = 60_000;
const RANGE_LIST: readonly Range[] = ["24h", "7d", "30d", "90d"];

// severity, the least severe at the bottom of a column: one hue, the more severe the stronger
const SEVERITY_SERIES: readonly Series[] = [
  { key: "low", label: "Low", fill: "fill-viz-low" },
  { key: "medium", label: "Medium", fill: "fill-viz-medium" },
  { key: "high", label: "High", fill: "fill-viz-high" },
  { key: "critical", label: "Critical", fill: "fill-viz-critical" },
  { key: "unknown", label: "Not rated", fill: "fill-viz-rest" },
];
const SEVERITY_PARTS: Readonly<Record<string, [string, string]>> = {
  critical: ["fill-viz-critical", "bg-viz-critical"],
  high: ["fill-viz-high", "bg-viz-high"],
  medium: ["fill-viz-medium", "bg-viz-medium"],
  low: ["fill-viz-low", "bg-viz-low"],
  unknown: ["fill-viz-rest", "bg-viz-rest"],
};
// identity: the same thing has the same colour on every dashboard, whatever else is shown
const PARTS: readonly [string, string][] = [
  ["fill-viz-1", "bg-viz-1"],
  ["fill-viz-2", "bg-viz-2"],
  ["fill-viz-3", "bg-viz-3"],
  ["fill-viz-4", "bg-viz-4"],
  ["fill-viz-5", "bg-viz-5"],
  ["fill-viz-6", "bg-viz-6"],
];
const STATE_ORDER = ["unreviewed", "follow_up", "changed_since_review", "reviewed"];
const VERDICT_ORDER = ["true_positive", "benign_expected", "benign_policy", "rule_false_positive", "inconclusive", "none"];
const AI_ORDER = ["proposed_tp", "proposed_other", "no_proposal", "working", "none"];

// "nothing yet" is no series of its own: it wears the grey of the rest
const REST: [string, string] = ["fill-viz-rest", "bg-viz-rest"];

function parts(counts: Readonly<Record<string, number>>, order: readonly string[], titles: Readonly<Record<string, string>>, target: (key: string) => Target | undefined): SharePart[] {
  return order.map((key, i) => {
    const [fill, swatch] = key === "none" ? REST : (PARTS[i % PARTS.length] as [string, string]);
    return { key, label: titles[key] ?? key, value: counts[key] ?? 0, fill, swatch, target: target(key) };
  });
}

const groupsOf = (search: Record<string, string>): Target => ({ to: "/search", search: { advanced: "1", ...search } });

// ------------------------------------------------------------------ Security overview

function entityTarget(e: EntityShare): Target {
  const kind = e.kind === "user" ? "account" : e.kind === "domain" ? "site" : e.kind === "ip" && !isPrivateIp(e.value) ? "outside" : "device";
  return { to: "/entities/$kind/$value", params: { kind, value: e.value } };
}

function WaitingForYou() {
  const queue = useQuery({ queryKey: ["dashboards", "queue"], queryFn: () => unwrap(listCases({ query: { view: "queue", limit: 6 } })), staleTime: 30_000, refetchInterval: REFRESH_MS });
  const rows = queue.data?.items ?? [];
  return (
    <ChartCard
      title="Waiting for a person"
      hint="The incidents and possible incidents that need a decision, most urgent first."
      action={
        <Link to="/incidents" search={{ view: "needs-you" }} className="text-sm">
          All of them ›
        </Link>
      }
      testId="waiting"
    >
      {queue.isPending && <Loading what="the queue" />}
      {queue.isError && <Problem error={queue.error} what="The queue" onRetry={() => void queue.refetch()} />}
      {queue.data && rows.length === 0 && <p className="m-0 text-sm text-muted">Nothing is waiting: every incident has been decided.</p>}
      {rows.length > 0 && (
        <ul className="m-0 flex list-none flex-col gap-0.5 p-0">
          {rows.map((c) => (
            <li key={c.id}>
              <Link to="/incidents/$id" params={{ id: c.id }} className="-mx-2 flex items-start gap-2.5 rounded-control px-2 py-1.5 text-sm text-text no-underline hover:bg-surface-2">
                <PriorityBadge engine={engineOf((c as unknown as { engine?: unknown }).engine)} className="mt-0.5" />
                <span className="flex min-w-0 flex-1 flex-col">
                  <span className="line-clamp-2">
                    <UntrustedText value={c.title} limits={{ maxChars: 200, maxLines: 2 }} />
                  </span>
                  <span className="text-xs text-muted">{stateWords({ state: c.state, number: c.number }).split(" · ")[0]}</span>
                </span>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </ChartCard>
  );
}

function Overview({ d, range }: { d: DashboardOut; range: Range }) {
  const hourly = d.bucket === "hour";
  const series = SEVERITY_SERIES.filter((s) => s.key !== "unknown" || d.series.some((b) => (b.counts.unknown ?? 0) > 0));
  const run = d.series.map((b) => total(b, SEVERITY_SERIES));
  const k = d.kpis;
  const funnel: RankRow[] = [
    { key: "alerts", label: "Alerts from the SIEM", value: k.alerts },
    { key: "groups", label: "Alert groups ARGUS made of them", value: k.investigations, note: oneIn(k.investigations, k.alerts), target: { to: "/alerts" } },
    { key: "attention", label: "Alert groups that need attention", value: k.attention, note: oneIn(k.attention, k.investigations), target: { to: "/alerts", search: { state: "attention" } } },
    { key: "possible", label: "Possible incidents, waiting for a person", value: k.possible_incidents, target: { to: "/incidents", search: { view: "needs-you" } } },
    { key: "confirmed", label: "Confirmed incidents, not closed", value: k.incident_cases, target: { to: "/incidents", search: { view: "open" } } },
  ];
  const addresses = [...(d.entities.ip ?? []), ...(d.entities.host ?? [])];
  const inside = addresses.filter((e) => e.kind === "host" || !isIp(e.value) || isPrivateIp(e.value)).sort((a, b) => b.alerts - a.alerts).slice(0, 7);
  const outside = [...(d.entities.ip ?? []).filter((e) => isIp(e.value) && !isPrivateIp(e.value)), ...(d.entities.domain ?? [])].sort((a, b) => b.alerts - a.alerts).slice(0, 7);
  const rank = (e: EntityShare): RankRow => ({ key: `${e.kind}:${e.value}`, label: e.value, value: e.alerts, note: e.open > 0 ? `${count(e.open)} open` : null, target: entityTarget(e) });
  const severity: SharePart[] = [...SEVERITIES, "unknown"].map((key) => {
    const [fill, swatch] = SEVERITY_PARTS[key] as [string, string];
    return { key, label: key === "unknown" ? "Not rated" : key.charAt(0).toUpperCase() + key.slice(1), value: d.severities[key] ?? 0, fill, swatch, target: key === "unknown" ? undefined : { to: "/overview", search: { range, severity: [key] } } };
  });
  return (
    <>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6" data-testid="stats">
        <Stat label="Confirmed incidents, open" value={count(k.incident_cases)} note="now" target={{ to: "/incidents", search: { view: "open" } }} testId="stat-incidents" />
        <Stat label="Possible incidents" value={count(k.possible_incidents)} note="waiting for a person, now" target={{ to: "/incidents", search: { view: "needs-you" } }} testId="stat-possible" />
        <Stat label="Alerts" value={compact(k.alerts)} moved={change(k.alerts, k.alerts_before)} movedNote={RANGE_BEFORE[range]} rising="bad" trend={run} testId="stat-alerts" />
        <Stat label="Alert groups" value={compact(k.investigations)} note={`${compact(k.open)} not reviewed`} target={{ to: "/alerts" }} testId="stat-groups" />
        <Stat label="Need attention" value={count(k.attention)} note={k.open_critical > 0 ? `${count(k.open_critical)} rated critical` : "none rated critical"} target={{ to: "/alerts", search: { state: "attention" } }} testId="stat-attention" />
        <Stat label="Alert-group review time" value={k.median_review_s === null ? "—" : span(k.median_review_s)} note={k.median_review_s === null ? "no alert group was reviewed in this span" : `the median of ${count(k.reviewed)} reviewed`} testId="stat-review" />
      </div>
      <Response range={range} />
      <div className="grid gap-3 xl:grid-cols-3">
        <ChartCard
          className="xl:col-span-2"
          title="Alerts over time"
          hint={`By the severity the rule gives them, a column ${hourly ? "an hour" : "a day"}. Point at a column, or use the arrow keys, to read it.`}
          table={<FigureTable caption="Alerts over time, by severity" head={["When", ...series.map((s) => s.label), "All"]} rows={d.series.map((b) => [bucketLabel(b.at, hourly), ...series.map((s) => b.counts[s.key] ?? 0), total(b, series)])} />}
          testId="alerts-over-time"
        >
          <Columns buckets={d.series} series={series} hourly={hourly} label="Alerts over time" unit="alerts" />
        </ChartCard>
        <ChartCard title="From alerts to incidents" hint="How far ARGUS narrows the SIEM's alerts down before a person is asked." table={<FigureTable caption="From alerts to incidents" head={["Step", "Count"]} rows={funnel.map((r) => [r.label, r.value])} />} testId="funnel">
          <Rank rows={funnel} label="From alerts to incidents" empty="No alerts in this span." top={Math.max(k.alerts, 1)} />
        </ChartCard>
      </div>
      <div className="grid gap-3 lg:grid-cols-3">
        <WaitingForYou />
        <ChartCard title={`Most active ${own("devices")}`} hint="By alerts in this span. A name opens everything ARGUS knows about it." table={<FigureTable caption={`Most active ${own("devices")}`} head={["Device", "Alerts", "Alert groups", "Open"]} rows={inside.map((e) => [e.value, e.alerts, e.investigations, e.open])} />} testId="top-inside">
          <Rank rows={inside.map(rank)} label={`Most active ${own("devices")}`} empty={`No ${own("device")} had an alert in this span.`} />
        </ChartCard>
        <ChartCard title="Outside addresses seen most" hint="The outside addresses and domains the alerts name most." table={<FigureTable caption="Outside addresses seen most" head={["Address", "Alerts", "Alert groups", "Open"]} rows={outside.map((e) => [e.value, e.alerts, e.investigations, e.open])} />} testId="top-outside">
          <Rank rows={outside.map(rank)} fill="fill-viz-2" label="Outside addresses seen most" empty="No outside address was named in this span." />
        </ChartCard>
      </div>
      <div className="grid gap-3 lg:grid-cols-2">
        <ChartCard title="Alert groups by severity" hint="A part opens the alert groups of that severity." testId="by-severity">
          <Share parts={severity.filter((p) => p.key !== "unknown" || p.value > 0)} label="Alert groups by severity" empty="No alert groups in this span." zeros />
        </ChartCard>
        <ChartCard title="Alert groups by review state" hint="What people have looked at, and what still waits." testId="by-state">
          <Share parts={parts(d.states, STATE_ORDER, STATE_TITLES, (key) => ({ to: "/overview", search: { range, state: [key] } }))} label="Alert groups by review state" empty="No alert groups in this span." />
        </ChartCard>
      </div>
    </>
  );
}

// ------------------------------------------------------------------ Detections

type RuleSort = "alerts" | "investigations" | "open" | "incidents" | "suspected";
const RULE_COLUMNS: readonly [RuleSort, string][] = [
  ["alerts", "Alerts"],
  ["investigations", "Alert groups"],
  ["open", "Not reviewed"],
  ["incidents", "Called real"],
  ["suspected", "Suspected"],
];

function RuleTable({ rules }: { rules: readonly RuleShare[] }) {
  const [sort, setSort] = useState<RuleSort>("alerts");
  const [all, setAll] = useState(false);
  const sorted = useMemo(() => [...rules].sort((a, b) => b[sort] - a[sort] || b.alerts - a.alerts), [rules, sort]);
  const shown = all ? sorted : sorted.slice(0, 10);
  const most = Math.max(1, ...rules.map((r) => r.alerts));
  if (rules.length === 0) return <p className="m-0 text-sm text-muted">No rule fired in this span.</p>;
  return (
    <>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[40rem] border-collapse text-sm" data-testid="rule-table">
          <caption className="sr-only">Rules, sorted by {RULE_COLUMNS.find(([k]) => k === sort)?.[1].toLowerCase()}</caption>
          <thead>
            <tr>
              <th scope="col" className="border-b border-border px-2 py-1.5 text-left text-xs font-medium text-muted">
                Rule
              </th>
              {RULE_COLUMNS.map(([key, words]) => (
                <th key={key} scope="col" aria-sort={sort === key ? "descending" : "none"} className="border-b border-border px-2 py-1.5 text-right text-xs font-medium text-muted">
                  <button type="button" onClick={() => setSort(key)} className={cn("cursor-pointer rounded-control border-0 bg-transparent px-1 text-xs", sort === key ? "font-semibold text-text" : "text-muted hover:text-text")}>
                    {words}
                    <span aria-hidden="true">{sort === key ? " ▾" : ""}</span>
                  </button>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {shown.map((r) => (
              <tr key={r.rule_id} className="border-b border-border last:border-b-0 hover:bg-surface-2" data-testid="rule-row">
                <td className="max-w-0 px-2 py-1.5">
                  <Link to="/search" search={{ advanced: "1", view: "all", rule: r.rule_id }} className="block truncate">
                    <UntrustedText value={r.rule} limits={{ maxChars: 200, maxLines: 1 }} />
                  </Link>
                  <svg aria-hidden="true" className="mt-1 block h-1.5 w-full">
                    <rect width={`${Math.max(0.6, (r.alerts / most) * 100).toFixed(2)}%`} height="100%" rx="3" className="fill-viz-1" />
                  </svg>
                </td>
                {RULE_COLUMNS.map(([key]) => (
                  <td key={key} className={cn("w-28 px-2 py-1.5 text-right align-top tabular-nums", key === sort && "font-medium", r[key] === 0 && "text-muted")}>
                    {count(r[key])}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {rules.length > 10 && (
        <div>
          <Button size="sm" variant="ghost" onClick={() => setAll(!all)}>
            {all ? "Show the first 10" : `Show all ${count(rules.length)} rules`}
          </Button>
        </div>
      )}
    </>
  );
}

function Detections({ d, range }: { d: DashboardOut; range: Range }) {
  const rules = d.rules;
  const real = rules.reduce((n, r) => n + r.incidents, 0);
  const fired = rules.filter((r) => r.alerts > 0);
  const found = fired.filter((r) => r.incidents > 0 || r.suspected > 0);
  const loud = fired.filter((r) => r.incidents === 0 && r.suspected === 0).sort((a, b) => b.alerts - a.alerts).slice(0, 6);
  const loudShare = fired.length > 0 ? Math.round((loud.reduce((n, r) => n + r.alerts, 0) / Math.max(1, d.kpis.alerts)) * 100) : 0;
  const productive = [...found].sort((a, b) => b.incidents + b.suspected - (a.incidents + a.suspected)).slice(0, 6);
  return (
    <>
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4" data-testid="stats">
        <Stat label="Rules that fired" value={count(fired.length)} note={`in the last ${RANGE_WORDS[range]}`} testId="stat-rules" />
        <Stat label="Alert groups called real" value={count(real)} note={`by a person or by ARGUS, of ${compact(d.kpis.investigations)}`} target={{ to: "/overview", search: { range, verdict: ["true_positive"] } }} testId="stat-real" />
        <Stat label="Rules that led to something real" value={count(found.length)} note="called real or suspected at least once" testId="stat-productive" />
        <Stat label="Assessed by ARGUS" value={compact(d.kpis.assessed)} note={`of ${compact(d.kpis.investigations)} alert groups`} testId="stat-assessed" />
      </div>
      <ChartCard title="Every rule that fired" hint="Click a column to sort by it. A rule's name opens its alert groups." testId="rules">
        <RuleTable rules={fired} />
      </ChartCard>
      <div className="grid gap-3 lg:grid-cols-2">
        <ChartCard
          title="Loud and never real"
          hint={loud.length > 0 ? `These rules made ${loudShare}% of the alerts and nothing was called real or suspected. They are the first to tune.` : "Rules that fire a lot and never lead to anything real."}
          action={
            <Link to="/tuning" className="text-sm">
              Rule tuning ›
            </Link>
          }
          table={<FigureTable caption="Loud and never real" head={["Rule", "Alerts", "Alert groups"]} rows={loud.map((r) => [r.rule, r.alerts, r.investigations])} />}
          testId="loud"
        >
          <Rank rows={loud.map((r) => ({ key: r.rule_id, label: r.rule, value: r.alerts, note: `${count(r.investigations)} ${plural(r.investigations, "group")}`, target: groupsOf({ view: "all", rule: r.rule_id }) }))} fill="fill-viz-rest" label="Loud and never real" empty="Every rule that fired led to something real or suspected." />
        </ChartCard>
        <ChartCard title="Rules that found something" hint="By the alert groups called real or suspected." table={<FigureTable caption="Rules that found something" head={["Rule", "Called real", "Suspected", "Alerts"]} rows={productive.map((r) => [r.rule, r.incidents, r.suspected, r.alerts])} />} testId="productive">
          <Rank rows={productive.map((r) => ({ key: r.rule_id, label: r.rule, value: r.incidents + r.suspected, note: `${count(r.alerts)} ${plural(r.alerts, "alert")}`, target: groupsOf({ view: "all", rule: r.rule_id }) }))} fill="fill-viz-3" label="Rules that found something" empty="Nothing was called real or suspected in this span." />
        </ChartCard>
      </div>
      <div className="grid gap-3 lg:grid-cols-2">
        <ChartCard title="What people decided" hint="The last decision on each alert group." testId="verdicts">
          <Share parts={parts(d.verdicts, VERDICT_ORDER, VERDICT_TITLES, (key) => ({ to: "/overview", search: { range, verdict: [key] } }))} label="What people decided" empty="No alert groups in this span." />
        </ChartCard>
        <ChartCard title="What ARGUS proposed" hint="Its own assessment of each alert group." testId="proposed">
          <Share parts={parts(d.ai, AI_ORDER, AI_TITLES, (key) => ({ to: "/overview", search: { range, ai: [key] } }))} label="What ARGUS proposed" empty="No alert groups in this span." />
        </ChartCard>
      </div>
    </>
  );
}

// ------------------------------------------------------------------ ARGUS operations

const SIEM_WORDS: Readonly<Record<string, string>> = { normal: "Normal", caution: "Caution", degraded: "Degraded", stopped: "Stopped", unknown: "Not known" };
const SYNC_WORDS: Readonly<Record<string, string>> = { none: "Not set up", ok: "Up to date", partial: "Partly read", failed: "Failed", late: "Late" };

function Spend({ usage }: { usage: UsageOut }) {
  const usd = (n: number) => `$${n.toFixed(2)}`;
  return (
    <ChartCard
      title="AI spend"
      hint={usage.stopped ? "All AI calls are stopped." : "Against its caps. The free providers are asked first."}
      action={
        <Link to="/dashboards" search={{ d: "costs" }} className="text-sm">
          The costs board ›
        </Link>
      }
      testId="spend"
    >
      <Meter label="Spent today" value={usage.today_usd} limit={usage.daily_cap_usd} words={usage.daily_cap_usd === null ? `${usd(usage.today_usd)}, no daily cap` : `${usd(usage.today_usd)} of ${usd(usage.daily_cap_usd)}`} testId="meter-day" />
      <Meter label="Spent this month" value={usage.month_usd} limit={usage.monthly_cap_usd} words={usage.monthly_cap_usd === null ? `${usd(usage.month_usd)}, no monthly cap` : `${usd(usage.month_usd)} of ${usd(usage.monthly_cap_usd)}`} testId="meter-month" />
    </ChartCard>
  );
}

function Operations({ health, metrics, today, usage }: { health: HealthOut; metrics: MetricsOut | undefined; today: Today | null; usage: UsageOut | undefined }) {
  const handled = today?.handled;
  const waiting = (metrics?.backlog ?? []).reduce((n, b) => n + b.waiting, 0);
  const oldest = Math.max(0, ...(metrics?.backlog ?? []).map((b) => b.oldest_wait_s ?? 0));
  const calls = (metrics?.calls ?? []).filter((c) => c.attempts > 0).sort((a, b) => b.attempts - a.attempts);
  return (
    <>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6" data-testid="stats">
        <Stat label="The SIEM, as ARGUS sees it" value={SIEM_WORDS[health.siem_state] ?? health.siem_state} note={health.siem_reasons.length > 0 ? health.siem_reasons.map((r) => r.replaceAll("_", " ")).join(", ") : "ARGUS reads it at its full budget"} target={{ to: "/health" }} testId="stat-siem" />
        <Stat label="Alerts taken in" value={compact(health.alerts)} note={`${compact(health.investigations)} alert groups`} target={{ to: "/alerts" }} testId="stat-taken" />
        <Stat label="Handled by ARGUS alone" value={handled ? compact(handled.count) : "—"} note={handled?.since ? <>since <Time value={handled.since} /></> : handled ? "since your last round" : "Today is not served here"} target={{ to: "/" }} testId="stat-handled" />
        <Stat label="Waiting for an assessment" value={count(waiting)} note={oldest > 0 ? `the oldest for ${span(oldest)}` : "nothing waits"} testId="stat-waiting" />
        <Stat label="Jobs that failed" value={count(health.jobs_failed)} note={`${count(health.jobs_waiting)} waiting, ${count(health.jobs_deferred)} put off`} target={{ to: "/health" }} testId="stat-failed" />
        <Stat label="Gaps in collection" value={count(health.open_gaps.length)} note={health.quarantined > 0 ? `${count(health.quarantined)} alerts ARGUS could not read` : "every alert was read"} target={{ to: "/health" }} testId="stat-gaps" />
      </div>
      <div className="grid gap-3 lg:grid-cols-2">
        <ChartCard
          title="What ARGUS handled alone"
          hint={handled?.since ? <>Since <Time value={handled.since} />: what it closed or kept watching without asking a person.</> : "What it closed or kept watching without asking a person."}
          action={
            <Link to="/" className="text-sm">
              Spot-check on Today ›
            </Link>
          }
          table={handled && <FigureTable caption="What ARGUS handled alone" head={["Kind", "Count"]} rows={handled.categories.map((c) => [c.label, c.count])} />}
          testId="handled"
        >
          <Rank rows={(handled?.categories ?? []).map((c) => ({ key: c.key, label: c.label, value: c.count }))} label="What ARGUS handled alone" empty="Nothing was handled without a person in this span." />
        </ChartCard>
        <ChartCard title="AI calls this month, by provider" hint={metrics ? `${count(metrics.fallbacks)} fell back to another provider · ${count(metrics.validator_blocks)} stopped by the privacy check · ${count(metrics.floor_hits)} held by the safety floor` : undefined} table={<FigureTable caption="AI calls this month, by provider" head={["Provider", "Calls", "Answered"]} rows={calls.map((c) => [c.provider, c.attempts, c.ok])} />} testId="ai-calls">
          <Rank rows={calls.map((c) => ({ key: c.provider, label: c.provider, value: c.attempts, note: `${count(c.ok)} answered` }))} fill="fill-viz-3" label="AI calls this month, by provider" empty="No AI call was made this month: ARGUS decides without a model." />
        </ChartCard>
      </div>
      <div className="grid gap-3 lg:grid-cols-3">
        {usage && <Spend usage={usage} />}
        <ChartCard title="What ARGUS concluded" hint="Its proposed outcomes this month, by who proposed them." table={<FigureTable caption="What ARGUS concluded" head={["Outcome", "Count"]} rows={(metrics?.outcomes ?? []).map((o) => [`${o.label} (${o.assessor})`, o.count])} />} testId="outcomes">
          <Rank rows={(metrics?.outcomes ?? []).slice().sort((a, b) => b.count - a.count).slice(0, 8).map((o) => ({ key: `${o.assessor}:${o.label}`, label: o.label, value: o.count, note: o.assessor }))} fill="fill-viz-5" label="What ARGUS concluded" empty="No outcome was proposed this month." />
        </ChartCard>
        <ChartCard title="Kibana" hint="Whether ARGUS has read the cases back from Kibana." testId="kibana">
          <dl className="m-0 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
            <dt className="text-muted">Read-back</dt>
            <dd className="m-0 font-medium">{SYNC_WORDS[health.kibana_sync.state] ?? health.kibana_sync.state}</dd>
            <dt className="text-muted">Last complete</dt>
            <dd className="m-0">{health.kibana_sync.last_complete_at ? <Time value={health.kibana_sync.last_complete_at} /> : "never"}</dd>
            {health.kibana_sync.last_reason && (
              <>
                <dt className="text-muted">Why</dt>
                <dd className="m-0">
                  <UntrustedText value={health.kibana_sync.last_reason} limits={{ maxChars: 200, maxLines: 2 }} />
                </dd>
              </>
            )}
          </dl>
        </ChartCard>
      </div>
    </>
  );
}

// ------------------------------------------------------------------ the page

function Segments<T extends string>({ label, values, words, value, onChange }: { label: string; values: readonly T[]; words: Readonly<Record<T, string>>; value: T; onChange: (next: T) => void }) {
  return (
    <div role="group" aria-label={label} className="flex flex-wrap gap-1">
      {values.map((v) => (
        <Button key={v} size="sm" variant={v === value ? "primary" : "secondary"} aria-pressed={v === value} onClick={() => onChange(v)}>
          {words[v]}
        </Button>
      ))}
    </div>
  );
}

function Frame({ stale, children }: { stale: boolean; children: ReactNode }) {
  // a new range keeps the old picture, dimmed, until the new one is here: no jump, no flash
  return (
    <div className={cn("flex flex-col gap-3 transition-opacity", stale && "opacity-60")} aria-busy={stale} data-testid="board">
      {children}
    </div>
  );
}

/**
 * Dashboards (the menu's fourth entry): three ready-made boards, each for one question. One row
 * of controls scopes everything under it: the board and the time range, in the address; the
 * figures refresh by themselves every minute, and nearly every figure and mark opens the list
 * behind it.
 */
export function Dashboards({ search }: { search: DashboardsSearch }) {
  const navigate = useNavigate();
  const session = useSession();
  const board = boardOf(search);
  const range = rangeOf(search);
  const set = (patch: { d?: Board; range?: Range }) => {
    const next = { d: patch.d ?? board, range: patch.range ?? range };
    void navigate({ to: "/dashboards", search: { ...(next.d !== "overview" ? { d: next.d } : {}), ...(next.range !== "7d" ? { range: next.range } : {}) }, replace: true });
  };
  const ranged = board === "overview" || board === "detections"; // the boards the time range scopes
  const ops = board === "operations";
  const costs = board === "costs";
  const admin = can(session.data, "admin");
  const dash = useQuery({ queryKey: ["dashboards", "figures", range], queryFn: () => unwrap(getDashboard({ query: { range } })), enabled: ranged, placeholderData: keepPreviousData, staleTime: 30_000, refetchInterval: REFRESH_MS });
  const health = useQuery({ ...healthPageOptions, enabled: ops, refetchInterval: REFRESH_MS });
  const metrics = useQuery({ ...metricsOptions, enabled: !ranged, refetchInterval: REFRESH_MS });
  const today = useQuery({ ...todayOptions(), enabled: ops });
  const usage = useQuery({ ...usageOptions, enabled: !ranged && admin });
  const shown = ops ? health : costs ? usage : dash;
  return (
    <>
      <header className="flex flex-col gap-1">
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <h1 className="m-0 text-3xl font-semibold tracking-tight">Dashboards</h1>
          <p className="m-0 flex items-center gap-2 text-sm text-muted" data-testid="freshness">
            {shown.dataUpdatedAt > 0 && (
              <span>
                Updated <Time value={new Date(shown.dataUpdatedAt).toISOString()} /> · refreshes every minute
              </span>
            )}
            <Button size="sm" variant="ghost" onClick={() => void (ranged ? dash.refetch() : Promise.all([ops ? health.refetch() : usage.refetch(), metrics.refetch(), ops ? today.refetch() : null]))} aria-disabled={shown.isFetching}>
              {shown.isFetching ? "Refreshing…" : "Refresh"}
            </Button>
          </p>
        </div>
        <p className="m-0 max-w-prose text-sm text-muted">{BOARD_HINTS[board]}</p>
      </header>
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2" data-testid="controls">
        <Segments label="Dashboard" values={BOARDS} words={BOARD_WORDS} value={board} onChange={(d) => set({ d })} />
        {ranged && <Segments label="Time range" values={RANGE_LIST} words={RANGE_WORDS} value={range} onChange={(r) => set({ range: r })} />}
      </div>
      {costs && !admin ? (
        <p className="m-0 text-sm text-muted" data-testid="costs-admin-only">
          What ARGUS costs is an administrator&apos;s to see. Ask one, or open another board above.
        </p>
      ) : (
        <>
          {shown.isPending && <Loading what="the dashboard" />}
          {shown.isError && <Problem error={shown.error} what="The dashboard" onRetry={() => void shown.refetch()} />}
        </>
      )}
      {costs && admin && usage.data && (
        <Frame stale={false}>
          <CostsBoard usage={usage.data} metrics={metrics.data} />
        </Frame>
      )}
      {ranged && dash.data && (
        <Frame stale={dash.isPlaceholderData}>
          {board === "overview" ? <Overview d={dash.data} range={range} /> : <Detections d={dash.data} range={range} />}
          <p className="m-0 text-sm text-muted">
            These figures are from ARGUS's own records; opening this page sends nothing to the SIEM.{" "}
            <Link to="/overview" search={{ range }}>
              Explore the same numbers with filters ›
            </Link>
          </p>
        </Frame>
      )}
      {ops && health.data && (
        <Frame stale={false}>
          <Operations health={health.data} metrics={metrics.data} today={today.data?.served ? today.data.today : null} usage={usage.data} />
        </Frame>
      )}
    </>
  );
}

