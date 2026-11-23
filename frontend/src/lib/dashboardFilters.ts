/**
 * The dashboard's filters (D-103), read from the address and written back to it the way the
 * classic page does (Filters.params in src/argus/web/dashboard.py), with the server's bounds
 * (src/argus/web/params.py): a range, or a custom span of site days (both dates, at most 366
 * days, within 2020 to 2100), then "any of" lists, a rule, and a host/IP/domain/user. Anything
 * invalid is left out, never an error: an old link still opens. Pure (tests/dashboardFilters.test.ts).
 */
import { first, listOf } from "./search";

export type Range = "24h" | "7d" | "30d" | "90d";
export const RANGES: readonly Range[] = ["24h", "7d", "30d", "90d"];
export const DEFAULT_RANGE: Range = "7d";
export const SEVERITY_NAMES = ["critical", "high", "medium", "low"] as const;
export const STATE_NAMES = ["unreviewed", "follow_up", "changed_since_review", "reviewed"] as const;
export const VERDICT_NAMES = ["true_positive", "benign_expected", "benign_policy", "rule_false_positive", "inconclusive", "none"] as const;
export const AI_NAMES = ["proposed_tp", "proposed_other", "no_proposal", "working", "none"] as const;
export const KIND_NAMES = ["ip", "host", "domain", "user"] as const;
export type ListName = "severity" | "state" | "verdict" | "ai";
const LISTS: Record<ListName, readonly string[]> = {
  severity: SEVERITY_NAMES,
  state: STATE_NAMES,
  verdict: VERDICT_NAMES,
  ai: AI_NAMES,
};

export const EARLIEST = "2020-01-01";
export const LATEST = "2100-01-01";
export const MAX_SPAN_DAYS = 366;
export const MAX_RULE = 200;
export const MAX_VALUE = 300;

export interface Filters {
  range: Range;
  start: string | null; // a site day, YYYY-MM-DD; with end, a custom span
  end: string | null;
  severity: string[];
  state: string[];
  verdict: string[];
  ai: string[];
  rule: string | null;
  kind: string | null;
  value: string | null;
}

export const NO_FILTERS: Filters = {
  range: DEFAULT_RANGE,
  start: null,
  end: null,
  severity: [],
  state: [],
  verdict: [],
  ai: [],
  rule: null,
  kind: null,
  value: null,
};

const DAY = /^\d{4}-\d{2}-\d{2}$/;
const DAY_MS = 86_400_000;
const LOW_DAY = Date.parse(`${EARLIEST}T00:00:00Z`) / DAY_MS;
const HIGH_DAY = Date.parse(`${LATEST}T00:00:00Z`) / DAY_MS;

function dayNumber(day: string): number | null {
  if (!DAY.test(day)) return null;
  const at = Date.parse(`${day}T00:00:00Z`);
  if (Number.isNaN(at)) return null;
  return new Date(at).toISOString().slice(0, 10) === day ? at / DAY_MS : null; // 2026-02-31 is not a day
}

function dayText(n: number): string {
  return new Date(n * DAY_MS).toISOString().slice(0, 10);
}

const NO_NUL = (text: string) => !text.includes("\u0000");

/** The custom span the server would use: sorted, within its bounds, at most 366 days (the last days). */
export function span(start: string | null, end: string | null): [string, string] | null {
  const a = start === null ? null : dayNumber(start);
  const b = end === null ? null : dayNumber(end);
  if (a === null || b === null) return null;
  const [x, y] = [a, b].map((n) => Math.min(Math.max(n, LOW_DAY), HIGH_DAY)).sort((p, q) => p - q) as [number, number];
  return [dayText(Math.max(x, y - (MAX_SPAN_DAYS - 1))), dayText(y)];
}

function oneOf(values: unknown, allowed: readonly string[]): string[] {
  return listOf(values).filter((v) => allowed.includes(v)).slice(0, allowed.length);
}

/** Filters from a parsed query string (lib/search.ts); the same bounds as the server's. */
export function parseFilters(search: Record<string, unknown>): Filters {
  const range = first(search.range);
  const custom = span(first(search.start) ?? null, first(search.end) ?? null);
  const rule = first(search.rule);
  const kind = first(search.kind);
  const value = first(search.value);
  const entity =
    kind !== undefined && (KIND_NAMES as readonly string[]).includes(kind) && value !== undefined && value !== "" && value.length <= MAX_VALUE && NO_NUL(value)
      ? { kind, value }
      : null;
  return {
    range: (RANGES as readonly string[]).includes(range ?? "") ? (range as Range) : DEFAULT_RANGE,
    start: custom?.[0] ?? null,
    end: custom?.[1] ?? null,
    severity: oneOf(search.severity, SEVERITY_NAMES),
    state: oneOf(search.state, STATE_NAMES),
    verdict: oneOf(search.verdict, VERDICT_NAMES),
    ai: oneOf(search.ai, AI_NAMES),
    rule: rule !== undefined && rule !== "" && rule.length <= MAX_RULE && NO_NUL(rule) ? rule : null,
    kind: entity?.kind ?? null,
    value: entity?.value ?? null,
  };
}

/** The address's query for these filters: only what differs from the default, as the classic page writes it. */
export function toSearch(f: Filters): Record<string, string | string[]> {
  const out: Record<string, string | string[]> = {};
  if (f.start !== null && f.end !== null) {
    out.start = f.start;
    out.end = f.end;
  } else if (f.range !== DEFAULT_RANGE) out.range = f.range;
  for (const name of ["severity", "state", "verdict", "ai"] as const) {
    if (f[name].length > 0) out[name] = f[name];
  }
  if (f.rule !== null) out.rule = f.rule;
  if (f.kind !== null && f.value !== null) {
    out.kind = f.kind;
    out.value = f.value;
  }
  return out;
}

/** The API's query: the same filters, the range always named. */
export function toQuery(f: Filters) {
  return {
    range: f.range,
    ...(f.start !== null && f.end !== null ? { start: f.start, end: f.end } : {}),
    ...(f.severity.length > 0 ? { severity: f.severity as ("critical" | "high" | "medium" | "low")[] } : {}),
    ...(f.state.length > 0 ? { state: f.state as ("unreviewed" | "follow_up" | "changed_since_review" | "reviewed")[] } : {}),
    ...(f.verdict.length > 0 ? { verdict: f.verdict as (typeof VERDICT_NAMES)[number][] } : {}),
    ...(f.ai.length > 0 ? { ai: f.ai as (typeof AI_NAMES)[number][] } : {}),
    ...(f.rule !== null ? { rule: f.rule } : {}),
    ...(f.kind !== null && f.value !== null ? { kind: f.kind as (typeof KIND_NAMES)[number], value: f.value } : {}),
  };
}

/** The filters also narrowed by one value (a click on a chart part or a row). */
export function adding(f: Filters, name: ListName | "rule" | "entity", value: string, kind?: string): Filters {
  if (name === "rule") return { ...f, rule: value };
  if (name === "entity") return { ...f, kind: kind ?? null, value };
  const have = f[name];
  return { ...f, [name]: have.includes(value) ? have : [...have, value] };
}

export interface Chip {
  /** e.g. "severity: high" */
  name: string;
  value: string;
  without: Filters;
}

/** The active filters, each with the filters that remove it. */
export function chips(f: Filters, titles: Record<ListName, Readonly<Record<string, string>>>): Chip[] {
  const out: Chip[] = [];
  for (const name of ["severity", "state", "verdict", "ai"] as const) {
    for (const v of f[name]) {
      out.push({ name, value: titles[name][v] ?? v.replaceAll("_", " "), without: { ...f, [name]: f[name].filter((x) => x !== v) } });
    }
  }
  if (f.rule !== null) out.push({ name: "rule", value: f.rule, without: { ...f, rule: null } });
  if (f.kind !== null && f.value !== null) out.push({ name: f.kind, value: f.value, without: { ...f, kind: null, value: null } });
  return out;
}

/** Everything but the time span cleared. */
export function cleared(f: Filters): Filters {
  return { ...f, severity: [], state: [], verdict: [], ai: [], rule: null, kind: null, value: null };
}

export function validList(name: ListName): readonly string[] {
  return LISTS[name];
}
