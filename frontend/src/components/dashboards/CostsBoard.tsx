import { Link } from "@tanstack/react-router";
import type { MetricsOut, SourceUseOut, UsageOut } from "../../client/types.gen";
import { bucketLabel } from "../../lib/chart";
import { count, plural } from "../../lib/format";
import { dayLimit, lastDay, lastDays, limitWords, monthToDate, SOURCES, taskLabel, todayUtc, trend, usd } from "../../lib/usage";
import type { Change, Series } from "../../lib/viz";
import { Columns } from "../viz/Columns";
import { ChartCard, FigureTable, Meter, Rank, Stat } from "../viz/kit";

// a provider keeps its colour on every chart, whichever others are shown
const PROVIDER_FILL: Readonly<Record<string, string>> = {
  groq: "fill-viz-1",
  openai: "fill-viz-2",
  openrouter: "fill-viz-3",
  gemini: "fill-viz-4",
  anthropic: "fill-viz-5",
  local: "fill-viz-6",
};
const DAYS = 31;

const SLOTS = ["fill-viz-1", "fill-viz-2", "fill-viz-3", "fill-viz-4", "fill-viz-5", "fill-viz-6"];

/** A provider this list does not know takes the first colour no shown provider has, by its name's order; past the six, the grey of the rest. */
export function seriesOf(providers: readonly string[]): Series[] {
  const taken = new Set(providers.map((p) => PROVIDER_FILL[p]).filter(Boolean));
  const spare = SLOTS.filter((s) => !taken.has(s));
  const unknown = providers.filter((p) => PROVIDER_FILL[p] === undefined).sort();
  return providers.map((p) => ({ key: p, label: p, fill: PROVIDER_FILL[p] ?? spare[unknown.indexOf(p)] ?? "fill-viz-rest" }));
}

function moved(percent: number | null, now: number): Change | null {
  if (percent === null) return now > 0 ? { words: "new", direction: "up" } : null;
  if (percent === 0) return { words: "no change", direction: "flat" };
  return { words: `${percent > 0 ? "+" : "−"}${Math.abs(percent)}%`, direction: percent > 0 ? "up" : "down" };
}

function Source({ s }: { s: SourceUseOut }) {
  const name = SOURCES.find((x) => x.key === s.source)?.name ?? s.source;
  const limit = dayLimit(s.limits);
  const state = !s.enabled ? "Off" : s.key_set ? "On" : "On without a key";
  return (
    <li className="flex flex-col gap-2 rounded-control bg-surface-2 p-3" data-testid="source">
      <div className="flex items-baseline justify-between gap-2">
        <span className="font-medium">{name}</span>
        <span className="text-xs text-muted">{state}</span>
      </div>
      <Meter label="Lookups today" value={s.today} limit={limit} words={limit === null ? `${count(s.today)}, no daily limit` : `${count(s.today)} of ${count(limit)}`} />
      <p className="m-0 text-xs text-muted">
        {count(s.month)} this month, {count(s.answered_month)} answered · limit: {limitWords(s.limits)}
      </p>
    </li>
  );
}

/**
 * Costs (the fourth board): what the AI spent and is on course to spend against its caps, where
 * the money goes by day, provider and task, and the threat-intel lookups against their limits.
 * An administrator's figures: the page shows this board to no one else.
 */
export function CostsBoard({ usage, metrics }: { usage: UsageOut; metrics: MetricsOut | undefined }) {
  const today = todayUtc();
  const last = lastDay(usage.ai_days.map((d) => d.day.slice(0, 10)), today);
  const days = lastDays(last, DAYS);
  const month = last.slice(0, 7);
  const inMonth = usage.ai_days.filter((d) => d.day.startsWith(month));
  const calls = inMonth.reduce((n, d) => n + d.calls, 0);
  const answered = inMonth.reduce((n, d) => n + d.ok, 0);
  const free = inMonth.filter((d) => d.cost_usd === 0).reduce((n, d) => n + d.calls, 0);
  const week = trend(usage.ai_days, last);
  const mtd = monthToDate(usage.ai_days, last);
  const over = usage.monthly_cap_usd !== null && mtd.projected > usage.monthly_cap_usd;
  const providers = [...new Set(usage.ai_days.map((d) => d.provider))].sort((a, b) => (Object.keys(PROVIDER_FILL).indexOf(a) + 99) % 99 - ((Object.keys(PROVIDER_FILL).indexOf(b) + 99) % 99) || a.localeCompare(b));
  const series = seriesOf(providers);
  const byDay = (pick: (d: UsageOut["ai_days"][number]) => number) => days.map((day) => ({ at: `${day}T00:00`, counts: Object.fromEntries(providers.map((p) => [p, usage.ai_days.filter((d) => d.day.slice(0, 10) === day && d.provider === p).reduce((n, d) => n + pick(d), 0)])) }));
  const spend = byDay((d) => d.cost_usd);
  const callsByDay = byDay((d) => d.calls);
  const byProvider = providers.map((p) => {
    const rows = inMonth.filter((d) => d.provider === p);
    return { provider: p, calls: rows.reduce((n, d) => n + d.calls, 0), ok: rows.reduce((n, d) => n + d.ok, 0), cost: rows.reduce((n, d) => n + d.cost_usd, 0) };
  });
  const tasks = [...usage.ai_tasks].sort((a, b) => b.cost_usd - a.cost_usd || b.calls - a.calls);
  const proposals = (metrics?.outcomes ?? []).reduce((n, o) => n + o.count, 0);
  const lookups = usage.sources.reduce((n, s) => n + s.today, 0);
  return (
    <>
      {usage.stopped && (
        <p className="m-0 rounded-control border border-warn/40 bg-warn-soft px-3 py-2 text-sm text-warn" role="status" data-testid="costs-stopped">
          All AI calls are stopped. <Link to="/ai">Resume them in AI and agents</Link>.
        </p>
      )}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6" data-testid="stats">
        <Stat label="Spent this month" value={usd(usage.month_usd)} note={usage.monthly_cap_usd === null ? "no monthly cap" : `of a ${usd(usage.monthly_cap_usd)} cap`} moved={moved(week.percent, week.now)} movedNote="last 7 days vs the 7 before" rising="bad" trend={spend.map((b) => series.reduce((n, s) => n + (b.counts[s.key] ?? 0), 0))} testId="stat-month" />
        <Stat label="On course for" value={usd(mtd.projected)} note={usage.monthly_cap_usd === null ? "by the month's end, at this month's daily rate" : over ? `over the ${usd(usage.monthly_cap_usd)} cap: ARGUS then uses only the free providers` : `by the month's end: within the ${usd(usage.monthly_cap_usd)} cap`} testId="stat-projected" />
        <Stat label="Spent today" value={usd(usage.today_usd)} note={usage.daily_cap_usd === null ? "no daily cap" : `of a ${usd(usage.daily_cap_usd)} cap`} testId="stat-today" />
        <Stat label="AI calls this month" value={count(calls)} note={calls === 0 ? "ARGUS decided without a model" : `${count(answered)} answered · ${Math.round((free / calls) * 100)}% on free providers`} testId="stat-calls" />
        <Stat label="Cost of one proposal" value={proposals > 0 ? usd(usage.month_usd / proposals) : "—"} note={proposals > 0 ? `${count(proposals)} proposed ${plural(proposals, "outcome")} this month` : "no outcome was proposed this month"} testId="stat-unit" />
        <Stat label="Threat-intel lookups today" value={count(lookups)} note={`across ${count(usage.sources.filter((s) => s.enabled).length)} sources that are on`} target={{ to: "/threat-intel" }} testId="stat-lookups" />
      </div>
      <div className="grid gap-3 xl:grid-cols-3">
        <ChartCard className="xl:col-span-2" title="Spend a day" hint={`The last ${DAYS} days, by provider. Point at a day, or use the arrow keys, to read it.`} table={<FigureTable caption="Spend a day, by provider" head={["Day", ...series.map((s) => s.label)]} rows={spend.map((b) => [bucketLabel(b.at, false), ...series.map((s) => usd(b.counts[s.key] ?? 0))])} />} testId="spend-days">
          <Columns buckets={spend} series={series} hourly={false} label="Spend a day" unit="" amount={usd} />
        </ChartCard>
        <ChartCard
          title="Against the caps"
          hint="A cap stops the paid providers; the free ones go on."
          action={
            <Link to="/ai" className="text-sm">
              Change the caps ›
            </Link>
          }
          testId="caps"
        >
          <Meter label="Today" value={usage.today_usd} limit={usage.daily_cap_usd} words={usage.daily_cap_usd === null ? `${usd(usage.today_usd)}, no daily cap` : `${usd(usage.today_usd)} of ${usd(usage.daily_cap_usd)}`} testId="meter-day" />
          <Meter label="This month" value={usage.month_usd} limit={usage.monthly_cap_usd} words={usage.monthly_cap_usd === null ? `${usd(usage.month_usd)}, no monthly cap` : `${usd(usage.month_usd)} of ${usd(usage.monthly_cap_usd)}`} testId="meter-month" />
          <Meter label={`On course for, by day ${mtd.length}`} value={mtd.projected} limit={usage.monthly_cap_usd} words={usage.monthly_cap_usd === null ? usd(mtd.projected) : `${usd(mtd.projected)} of ${usd(usage.monthly_cap_usd)}`} testId="meter-projected" />
          <p className="m-0 text-xs text-muted">The projection is this month&apos;s average a day so far, carried to the month&apos;s end: an estimate, not a promise.</p>
        </ChartCard>
      </div>
      <div className="grid gap-3 lg:grid-cols-3">
        <ChartCard title="What the money is for" hint="This month, by the task the AI did." table={<FigureTable caption="Spend by task" head={["Task", "Cost", "Calls"]} rows={tasks.map((t) => [taskLabel(t.task), usd(t.cost_usd), t.calls])} />} testId="tasks">
          <Rank rows={tasks.map((t) => ({ key: t.task, label: taskLabel(t.task), value: t.calls, note: usd(t.cost_usd) }))} fill="fill-viz-5" label="Calls by task" empty="No AI task ran this month." />
        </ChartCard>
        <ChartCard title="Providers this month" hint="Calls, how many were answered, and what they cost." table={<FigureTable caption="Providers this month" head={["Provider", "Calls", "Answered", "Cost"]} rows={byProvider.map((p) => [p.provider, p.calls, p.ok, usd(p.cost)])} />} testId="providers">
          <Rank rows={[...byProvider].sort((a, b) => b.calls - a.calls).map((p) => ({ key: p.provider, label: p.provider, value: p.calls, note: `${p.calls > 0 ? Math.round((p.ok / p.calls) * 100) : 0}% answered · ${usd(p.cost)}`, fill: series.find((s) => s.key === p.provider)?.fill }))} label="Calls by provider" empty="No AI call was made this month." />
        </ChartCard>
        <ChartCard title="Calls a day" hint={`The last ${DAYS} days, by provider.`} table={<FigureTable caption="AI calls a day, by provider" head={["Day", ...series.map((s) => s.label)]} rows={callsByDay.map((b) => [bucketLabel(b.at, false), ...series.map((s) => b.counts[s.key] ?? 0)])} />} testId="calls-days">
          <Columns buckets={callsByDay} series={series} hourly={false} label="AI calls a day" unit="calls" />
        </ChartCard>
      </div>
      <ChartCard
        title="Threat-intel lookups"
        hint="Your own free keys: each source against its daily limit."
        action={
          <Link to="/threat-intel" className="text-sm">
            Keys and limits ›
          </Link>
        }
        testId="sources"
      >
        {usage.sources.length === 0 ? (
          <p className="m-0 text-sm text-muted">ARGUS has not counted the lookups yet.</p>
        ) : (
          <ul className="m-0 grid list-none gap-3 p-0 md:grid-cols-3">
            {usage.sources.map((s) => (
              <Source key={s.source} s={s} />
            ))}
          </ul>
        )}
      </ChartCard>
    </>
  );
}
