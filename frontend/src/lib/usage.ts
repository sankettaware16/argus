/**
 * The cost and usage pages' logic, with no screen in it (D-329): dollars in words, the AI's spend
 * a day as a 31-day series stacked by provider, a source's lookups a day and its limits in words.
 */
import { queryOptions } from "@tanstack/react-query";
import { getUsage } from "../client/sdk.gen";
import type { AiDayOut, SourceDayOut, SourceLimitOut } from "../client/types.gen";
import { unwrap } from "./call";
import type { Point } from "./chart";

export const REFRESH_MS = 60_000;

export const usageOptions = queryOptions({
  queryKey: ["admin", "usage"],
  queryFn: () => unwrap(getUsage()),
  staleTime: 60_000,
  refetchInterval: REFRESH_MS,
});

/** The ranges the costs page offers (the API keeps 31 days). */
export const RANGES = [7, 31] as const;
export type Range = (typeof RANGES)[number];

/** US dollars: two decimals, four under a cent ("$0.0042"), "$0.00" for nothing. */
export function usd(n: number): string {
  const small = n !== 0 && Math.abs(n) < 0.01;
  return new Intl.NumberFormat("en-US", { style: "currency", currency: "USD", minimumFractionDigits: small ? 4 : 2, maximumFractionDigits: small ? 4 : 2 }).format(n);
}

/** "$1.20 of $10.00", or "$1.20 (no limit)". */
export function againstCap(spent: number, cap: number | null | undefined): string {
  return cap === null || cap === undefined ? `${usd(spent)} (no limit)` : `${usd(spent)} of ${usd(cap)}`;
}

/** The `n` days up to and including `last` (YYYY-MM-DD), oldest first. */
export function lastDays(last: string, n = 31): string[] {
  const end = Date.parse(`${last}T00:00:00Z`);
  if (Number.isNaN(end)) return [];
  return Array.from({ length: n }, (_, i) => new Date(end - (n - 1 - i) * 86_400_000).toISOString().slice(0, 10));
}

export function todayUtc(now: number = Date.now()): string {
  return new Date(now).toISOString().slice(0, 10);
}

/** The newest of `today` and every day in the data (a server ahead of this clock still shows its day). */
export function lastDay(days: readonly string[], today: string): string {
  return days.reduce((a, b) => (b > a ? b : a), today);
}

/** Providers by what they cost in the period, the dearest first (ties by name). */
export function providerOrder(rows: readonly AiDayOut[]): string[] {
  const cost = new Map<string, number>();
  for (const r of rows) cost.set(r.provider, (cost.get(r.provider) ?? 0) + r.cost_usd);
  return [...cost.entries()].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1)).map(([p]) => p);
}

/** The AI's spend a day, stacked by provider, every day of the window present (an empty day is zero). */
export function aiSeries(rows: readonly AiDayOut[], days: readonly string[]): Point[] {
  const byDay = new Map<string, Record<string, number>>(days.map((d) => [d, {}]));
  for (const r of rows) {
    const counts = byDay.get(r.day.slice(0, 10));
    if (counts) counts[r.provider] = (counts[r.provider] ?? 0) + r.cost_usd;
  }
  return days.map((d) => ({ at: `${d}T00:00:00`, counts: byDay.get(d) ?? {} }));
}

export function sourceSeries(rows: readonly SourceDayOut[], days: readonly string[]): Point[] {
  const byDay = new Map(rows.map((r) => [r.day.slice(0, 10), r.requests]));
  return days.map((d) => ({ at: `${d}T00:00:00`, counts: { lookups: byDay.get(d) ?? 0 } }));
}

const WINDOW: Record<string, string> = { minute: "a minute", day: "a day", month: "a month" };

/** "3 a minute, 400 a day"; "no limit" when there is none. */
export function limitWords(limits: readonly SourceLimitOut[]): string {
  if (limits.length === 0) return "no limit";
  return limits.map((l) => `${l.maximum.toLocaleString("en-US")} ${WINDOW[l.window] ?? `a ${l.window}`}`).join(", ");
}

export function dayLimit(limits: readonly SourceLimitOut[]): number | null {
  return limits.find((l) => l.window === "day")?.maximum ?? null;
}

const TASKS: Record<string, string> = {
  story: "Incident readings",
  opinion: "Second opinions on P1 incidents",
  assess: "Assessments of alert groups",
  evaluate: "Gold-set evaluations",
  tune: "Rule tuning",
  ping: "Provider checks",
};
export function taskLabel(task: string): string {
  return TASKS[task] ?? task;
}

export const SOURCES: { key: "virustotal" | "shodan" | "censys"; name: string; gives: string; keyless?: string }[] = [
  { key: "virustotal", name: "VirusTotal", gives: "The reputation of a public address or domain name: how many security engines flag it." },
  { key: "shodan", name: "Shodan", gives: "What a public server runs: its open ports, services and known weaknesses.", keyless: "Without a key ARGUS can still ask Shodan's free InternetDB, which gives fewer details." },
  { key: "censys", name: "Censys", gives: "What a public server runs: its services and certificates." },
];

/** A source: on, off, or on through the keyless fallback, in words. */
export function sourceState(hasKey: boolean, keyless: boolean | null): { on: boolean; words: string } {
  if (hasKey) return { on: true, words: "On" };
  if (keyless) return { on: true, words: "On without a key (InternetDB)" };
  return { on: false, words: "Off: no key" };
}

/** Each provider's calls a day (for a bar's tooltip), by day then provider. */
export function aiCalls(rows: readonly AiDayOut[]): Map<string, Record<string, number>> {
  const out = new Map<string, Record<string, number>>();
  for (const r of rows) {
    const day = r.day.slice(0, 10);
    const own = out.get(day) ?? {};
    own[r.provider] = (own[r.provider] ?? 0) + r.calls;
    out.set(day, own);
  }
  return out;
}

/** The lines of one day's tooltip: each shown provider's spend and calls, the dearest first. */
export function dayLines(point: Point, calls: Readonly<Record<string, number>>, order: readonly string[]): string[] {
  const names = order.filter((p) => (point.counts[p] ?? 0) > 0 || (calls[p] ?? 0) > 0);
  if (names.length === 0) return ["No AI call"];
  return names.map((p) => {
    const n = calls[p] ?? 0;
    return `${p}: ${usd(point.counts[p] ?? 0)} · ${n} ${n === 1 ? "call" : "calls"}`;
  });
}

export interface Trend {
  now: number;
  before: number;
  /** the change in percent, rounded; null when the previous period cost nothing */
  percent: number | null;
}

/** The last `days` days' spend (ending with `last`) against the `days` before them. */
export function trend(rows: readonly AiDayOut[], last: string, days = 7): Trend {
  const all = lastDays(last, days * 2);
  const recent = new Set(all.slice(days));
  const earlier = new Set(all.slice(0, days));
  let now = 0;
  let before = 0;
  for (const r of rows) {
    const d = r.day.slice(0, 10);
    if (recent.has(d)) now += r.cost_usd;
    else if (earlier.has(d)) before += r.cost_usd;
  }
  return { now, before, percent: before > 0 ? Math.round(((now - before) / before) * 100) : null };
}

export function trendWords(t: Trend, days = 7): string {
  if (t.percent === null) return t.now > 0 ? `${usd(t.now)} in the last ${days} days; nothing the ${days} before` : `Nothing spent in the last ${days * 2} days`;
  if (t.percent === 0) return `The same as the previous ${days} days`;
  return `${t.percent > 0 ? "↑" : "↓"} ${Math.abs(t.percent)}% vs the previous ${days} days`;
}

export interface MonthToDate {
  /** the month's days, 1 … its length */
  length: number;
  /** today's day of the month */
  today: number;
  /** the spend so far at the end of each day up to today */
  cumulative: number[];
  /** the end of the month at the average rate so far (a projection) */
  projected: number;
}

/** The month so far, day by day, and where it ends at the same daily rate. */
export function monthToDate(rows: readonly AiDayOut[], today: string): MonthToDate {
  const [y, m, d] = today.split("-").map(Number);
  const length = new Date(Date.UTC(y ?? 1970, m ?? 1, 0)).getUTCDate();
  const day = d ?? 1;
  const daily = new Array<number>(day).fill(0);
  const prefix = today.slice(0, 8);
  for (const r of rows) {
    if (!r.day.startsWith(prefix)) continue;
    const n = Number(r.day.slice(8, 10));
    if (n >= 1 && n <= day) daily[n - 1] = (daily[n - 1] ?? 0) + r.cost_usd;
  }
  let run = 0;
  const cumulative = daily.map((v) => (run += v));
  const spent = cumulative[cumulative.length - 1] ?? 0;
  return { length, today: day, cumulative, projected: (spent / day) * length };
}
