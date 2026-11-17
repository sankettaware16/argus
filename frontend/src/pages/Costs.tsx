// Costs and usage (D-329): what the AI cost this month and today against its limits, its spend a
// day by provider for the last 31 days and by task this month, and each threat-intel source's
// lookups a day against its daily limit. Read only; the limits are changed on their own pages.
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import type { SourceUseOut, UsageOut } from "../client/types.gen";
import { AdminOnly, Notice } from "../components/admin/common";
import { DailyBars, dayWords, Legend } from "../components/charts/DailyBars";
import { MonthLine } from "../components/charts/MonthLine";
import { Loading, Problem } from "../components/Problem";
import { Time } from "../components/Time";
import { Card, CardTitle } from "../components/ui/card";
import { DataTable } from "../components/ui/table";
import { count } from "../lib/format";
import { useNow } from "../lib/now";
import { againstCap, aiCalls, aiSeries, dayLimit, dayLines, lastDay, lastDays, limitWords, monthToDate, providerOrder, RANGES, SOURCES, sourceSeries, taskLabel, todayUtc, trend, trendWords, usageOptions, usd, type Range } from "../lib/usage";

function Summary({ u, last }: { u: UsageOut; last: string }) {
  const t = trend(u.ai_days, last);
  const m = monthToDate(u.ai_days, last);
  const over = u.monthly_cap_usd !== null && m.projected > u.monthly_cap_usd;
  return (
    <Card aria-label="Summary" data-testid="costs-summary">
      <CardTitle>This month</CardTitle>
      <div className="grid gap-4 lg:grid-cols-[minmax(0,22rem)_1fr]">
        <dl className="m-0 grid content-start gap-x-4 gap-y-1 text-sm sm:grid-cols-[9rem_1fr]">
          <dt className="text-muted">AI this month</dt>
          <dd className="m-0" data-testid="costs-month">
            {againstCap(u.month_usd, u.monthly_cap_usd)}
          </dd>
          <dt className="text-muted">AI today</dt>
          <dd className="m-0" data-testid="costs-today">
            {againstCap(u.today_usd, u.daily_cap_usd)}
          </dd>
          <dt className="text-muted">Last 7 days</dt>
          <dd className="m-0" data-testid="costs-trend">
            {usd(t.now)} <span className={t.percent !== null && t.percent > 0 ? "text-warn" : "text-muted"}>({trendWords(t)})</span>
          </dd>
          <dt className="text-muted">AI calls</dt>
          <dd className="m-0">
            {u.stopped ? (
              <span data-testid="costs-stopped">
                All AI calls are stopped. <Link to="/ai">Resume them in AI and agents</Link>.
              </span>
            ) : (
              <span>
                Allowed. <Link to="/ai">Stop them or change the limits in AI and agents</Link>.
              </span>
            )}
          </dd>
        </dl>
        <div className="flex min-w-0 flex-col gap-1">
          <MonthLine m={m} cap={u.monthly_cap_usd} format={usd} label={`The AI's spend this month to day ${m.today}, and a projection to day ${m.length}`} />
          <p className="m-0 text-xs text-muted" data-testid="costs-projection">
            Projection, not a promise: at this month&apos;s average so far, about <strong className={over ? "text-warn" : "text-text"}>{usd(m.projected)}</strong> by the month&apos;s end
            {u.monthly_cap_usd !== null && (over ? `, over the ${usd(u.monthly_cap_usd)} cap: ARGUS then uses only the free providers` : `, within the ${usd(u.monthly_cap_usd)} cap`)}.
          </p>
        </div>
      </div>
    </Card>
  );
}

function RangeSwitch({ range, onRange }: { range: Range; onRange: (r: Range) => void }) {
  return (
    <div role="group" aria-label="Days shown" className="inline-flex rounded-full border border-border bg-surface-2 p-0.5">
      {RANGES.map((r) => (
        <button key={r} type="button" aria-pressed={range === r} onClick={() => onRange(r)} className={`cursor-pointer rounded-full border-0 px-3 py-0.5 text-sm ${range === r ? "bg-surface font-semibold text-text shadow-card" : "bg-transparent text-muted hover:text-text"}`}>
          {r} days
        </button>
      ))}
    </div>
  );
}

function AiDays({ u, days, range }: { u: UsageOut; days: string[]; range: Range }) {
  const order = useMemo(() => providerOrder(u.ai_days), [u.ai_days]);
  const [hidden, setHidden] = useState<ReadonlySet<string>>(new Set());
  const series = useMemo(() => aiSeries(u.ai_days, days), [u.ai_days, days]);
  const calls = useMemo(() => aiCalls(u.ai_days), [u.ai_days]);
  const shown = order.filter((p) => !hidden.has(p));
  const totals = useMemo(() => {
    const out: Record<string, number> = {};
    for (const p of series) for (const [k, v] of Object.entries(p.counts)) out[k] = (out[k] ?? 0) + v;
    return out;
  }, [series]);
  const rows = series.filter((p) => Object.keys(p.counts).length > 0).reverse();
  const toggle = (name: string) => setHidden((h) => (h.has(name) ? new Set([...h].filter((x) => x !== name)) : new Set([...h, name])));
  return (
    <Card aria-label="The AI's spend a day" data-testid="costs-ai-days">
      <CardTitle>The AI&apos;s spend a day, last {range} days</CardTitle>
      {order.length === 0 ? (
        <p className="m-0 text-sm text-muted">No AI call in the last {range} days.</p>
      ) : (
        <>
          <p className="m-0 mb-1 text-xs text-muted">Press a provider to show or hide it; point at a day, or focus the chart and use the arrow keys, to read it.</p>
          <Legend order={order} totals={totals} format={usd} hidden={hidden} onToggle={toggle} />
          <DailyBars series={series} order={shown} palette={order} label={`The AI's spend a day by provider, last ${range} days`} format={usd} money unit="spent" details={(i) => { const p = series[i]; return p ? dayLines(p, calls.get(p.at.slice(0, 10)) ?? {}, shown) : []; }} />
          <details className="mt-2">
            <summary className="cursor-pointer text-sm font-medium">As a table</summary>
            <DataTable
              reachable
              caption="The AI's spend a day by provider"
              rows={rows}
              rowKey={(r) => r.at}
              columns={[{ key: "day", header: "Day", cell: (r) => dayWords(r.at) }, ...order.map((p) => ({ key: p, header: p, numeric: true, cell: (r: (typeof rows)[number]) => usd(r.counts[p] ?? 0) }))]}
            />
          </details>
        </>
      )}
    </Card>
  );
}

function Tasks({ u }: { u: UsageOut }) {
  return (
    <Card aria-label="By task this month" data-testid="costs-tasks">
      <CardTitle>By task this month</CardTitle>
      <DataTable
        caption="The AI's calls and cost by task this month"
        rows={u.ai_tasks}
        rowKey={(t) => t.task}
        empty="No AI call this month."
        columns={[
          { key: "task", header: "Task", cell: (t) => taskLabel(t.task) },
          { key: "calls", header: "Calls", numeric: true, cell: (t) => count(t.calls) },
          { key: "cost", header: "Cost", numeric: true, cell: (t) => usd(t.cost_usd) },
        ]}
      />
    </Card>
  );
}

function SourceUse({ s, days, range }: { s: SourceUseOut; days: string[]; range: Range }) {
  const name = SOURCES.find((x) => x.key === s.source)?.name ?? s.source;
  const limit = dayLimit(s.limits);
  const series = useMemo(() => sourceSeries(s.days, days), [s.days, days]);
  return (
    <Card aria-label={name} data-testid={`costs-source-${s.source}`}>
      <CardTitle>{name}</CardTitle>
      <p className="m-0 text-sm">
        {count(s.today)} today{limit !== null && ` of ${count(limit)}`}, {count(s.month)} this month
      </p>
      <p className="m-0 mb-1 text-xs text-muted">
        {s.enabled ? "On" : "Off: no key"} · limits {limitWords(s.limits)}
      </p>
      <DailyBars series={series} order={["lookups"]} label={`${name}: lookups a day, last ${range} days`} format={(n) => count(Math.trunc(n))} limit={limit} unit="lookups" />
    </Card>
  );
}

function CostsView() {
  const usage = useQuery(usageOptions);
  const u = usage.data;
  const [range, setRange] = useState<Range>(31);
  const now = useNow(30_000);
  const last = useMemo(() => (u ? lastDay([...u.ai_days.map((d) => d.day.slice(0, 10)), ...u.sources.flatMap((s) => s.days.map((d) => d.day.slice(0, 10)))], todayUtc(now)) : todayUtc(now)), [u, now]);
  const days = useMemo(() => lastDays(last, range), [last, range]);
  if (usage.isPending) return <Loading what="the costs" />;
  if (usage.isError) return <Problem error={usage.error} what="The costs" onRetry={() => void usage.refetch()} />;
  const data = usage.data;
  return (
    <>
      <div className="flex flex-col gap-1">
        <h1 className="m-0 text-2xl font-semibold">Costs and usage</h1>
        <p className="m-0 max-w-prose text-sm text-muted">What the AI cost and how many threat-intel lookups ARGUS made, against their limits. Amounts are in US dollars; days are UTC.</p>
      </div>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <RangeSwitch range={range} onRange={setRange} />
        <p className="m-0 text-xs text-muted" aria-live="polite" data-testid="costs-updated">
          Updated <Time value={new Date(usage.dataUpdatedAt)} relative />; it reads again every minute.
        </p>
      </div>
      <Summary u={data} last={last} />
      <AiDays u={data} days={days} range={range} />
      <Tasks u={data} />
      <section aria-labelledby="sources-title" className="flex flex-col gap-3">
        <h2 id="sources-title" className="m-0 text-lg font-semibold">
          Threat-intel lookups
        </h2>
        {data.sources.length === 0 ? (
          <Notice tone="info">argus-admin has not counted the lookups yet; it does every five minutes.</Notice>
        ) : (
          <>
            {data.sources_at && (
              <p className="m-0 text-xs text-muted">
                Counted <Time value={data.sources_at} relative />. <Link to="/threat-intel">Keys and tests in Threat intel</Link>.
              </p>
            )}
            <div className="grid gap-3 lg:grid-cols-3">
              {data.sources.map((s) => (
                <SourceUse key={s.source} s={s} days={days} range={range} />
              ))}
            </div>
          </>
        )}
      </section>
    </>
  );
}

export function Costs() {
  return (
    <AdminOnly what="Costs and usage">
      <CostsView />
    </AdminOnly>
  );
}
