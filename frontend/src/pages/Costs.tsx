// Costs and usage (D-329): what the AI cost this month and today against its limits, its spend a
// day by provider for the last 31 days and by task this month, and each threat-intel source's
// lookups a day against its daily limit. Read only; the limits are changed on their own pages.
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useMemo } from "react";
import type { SourceUseOut, UsageOut } from "../client/types.gen";
import { AdminOnly, Notice } from "../components/admin/common";
import { DailyBars, Legend } from "../components/charts/DailyBars";
import { Loading, Problem } from "../components/Problem";
import { Time } from "../components/Time";
import { Card, CardTitle } from "../components/ui/card";
import { DataTable } from "../components/ui/table";
import { count } from "../lib/format";
import { againstCap, aiSeries, dayLimit, lastDay, lastDays, limitWords, providerOrder, SOURCES, sourceSeries, taskLabel, todayUtc, usageOptions, usd } from "../lib/usage";

function Summary({ u }: { u: UsageOut }) {
  return (
    <Card aria-label="Summary" data-testid="costs-summary">
      <CardTitle>This month</CardTitle>
      <dl className="m-0 grid gap-x-4 gap-y-1 text-sm sm:grid-cols-[10rem_1fr]">
        <dt className="text-muted">AI this month</dt>
        <dd className="m-0" data-testid="costs-month">
          {againstCap(u.month_usd, u.monthly_cap_usd)}
        </dd>
        <dt className="text-muted">AI today</dt>
        <dd className="m-0" data-testid="costs-today">
          {againstCap(u.today_usd, u.daily_cap_usd)}
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
    </Card>
  );
}

function AiDays({ u, days }: { u: UsageOut; days: string[] }) {
  const order = useMemo(() => providerOrder(u.ai_days), [u.ai_days]);
  const series = useMemo(() => aiSeries(u.ai_days, days), [u.ai_days, days]);
  const totals = useMemo(() => {
    const out: Record<string, number> = {};
    for (const p of series) for (const [k, v] of Object.entries(p.counts)) out[k] = (out[k] ?? 0) + v;
    return out;
  }, [series]);
  const rows = series.filter((p) => Object.keys(p.counts).length > 0).reverse();
  return (
    <Card aria-label="The AI's spend a day" data-testid="costs-ai-days">
      <CardTitle>The AI&apos;s spend a day, last 31 days</CardTitle>
      {order.length === 0 ? (
        <p className="m-0 text-sm text-muted">No AI call in the last 31 days.</p>
      ) : (
        <>
          <Legend order={order} totals={totals} format={usd} />
          <DailyBars series={series} order={order} label="The AI's spend a day by provider, last 31 days" format={usd} money unit="spent" />
          <details className="mt-2">
            <summary className="cursor-pointer text-sm font-medium">As a table</summary>
            <DataTable
              reachable
              caption="The AI's spend a day by provider"
              rows={rows}
              rowKey={(r) => r.at}
              columns={[{ key: "day", header: "Day", cell: (r) => r.at.slice(0, 10) }, ...order.map((p) => ({ key: p, header: p, numeric: true, cell: (r: (typeof rows)[number]) => usd(r.counts[p] ?? 0) }))]}
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

function SourceUse({ s, days }: { s: SourceUseOut; days: string[] }) {
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
      <DailyBars series={series} order={["lookups"]} label={`${name}: lookups a day, last 31 days`} format={(n) => count(Math.trunc(n))} limit={limit} unit="lookups" />
    </Card>
  );
}

function CostsView() {
  const usage = useQuery(usageOptions);
  const u = usage.data;
  const days = useMemo(() => (u ? lastDays(lastDay([...u.ai_days.map((d) => d.day.slice(0, 10)), ...u.sources.flatMap((s) => s.days.map((d) => d.day.slice(0, 10)))], todayUtc())) : []), [u]);
  if (usage.isPending) return <Loading what="the costs" />;
  if (usage.isError) return <Problem error={usage.error} what="The costs" onRetry={() => void usage.refetch()} />;
  const data = usage.data;
  return (
    <>
      <div className="flex flex-col gap-1">
        <h1 className="m-0 text-2xl font-semibold">Costs and usage</h1>
        <p className="m-0 max-w-prose text-sm text-muted">What the AI cost and how many threat-intel lookups ARGUS made, against their limits. Amounts are in US dollars; days are UTC.</p>
      </div>
      <Summary u={data} />
      <AiDays u={data} days={days} />
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
                <SourceUse key={s.source} s={s} days={days} />
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
