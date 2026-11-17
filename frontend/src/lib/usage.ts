/**
 * The cost and usage pages' logic, with no screen in it (D-329): dollars in words, the AI's spend
 * a day as a 31-day series stacked by provider, a source's lookups a day and its limits in words.
 */
import { queryOptions } from "@tanstack/react-query";
import { getUsage } from "../client/sdk.gen";
import type { AiDayOut, SourceDayOut, SourceLimitOut } from "../client/types.gen";
import { unwrap } from "./call";
import type { Point } from "./chart";

export const usageOptions = queryOptions({
  queryKey: ["admin", "usage"],
  queryFn: () => unwrap(getUsage()),
  staleTime: 60_000,
});

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
