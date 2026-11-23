/**
 * The Dashboards page's address: which of the three ready-made dashboards, and the time range
 * every chart on it is drawn for. Pure (tests/dashboards.test.tsx).
 */
import { DEFAULT_RANGE, RANGES, type Range } from "./dashboardFilters";
import { first } from "./search";

export const BOARDS = ["overview", "detections", "operations", "costs"] as const;
export type Board = (typeof BOARDS)[number];
export const BOARD_WORDS: Readonly<Record<Board, string>> = { overview: "Security overview", detections: "Detections", operations: "ARGUS operations", costs: "Costs" };
export const BOARD_HINTS: Readonly<Record<Board, string>> = {
  overview: "What is happening on your network: the alerts, what they became, and what waits for a person.",
  detections: "Which rules fire, which of them lead to something real, and which are only loud.",
  operations: "Whether ARGUS itself is working: what it takes in, what it handles alone, and what its AI costs.",
  costs: "What the AI costs and where the money goes, against its caps, and the threat-intel lookups against their limits.",
};
export const RANGE_WORDS: Readonly<Record<Range, string>> = { "24h": "24 hours", "7d": "7 days", "30d": "30 days", "90d": "90 days" };
export const RANGE_BEFORE: Readonly<Record<Range, string>> = { "24h": "vs the 24 hours before", "7d": "vs the 7 days before", "30d": "vs the 30 days before", "90d": "vs the 90 days before" };

export interface DashboardsSearch {
  /** left out: the security overview */
  d?: "detections" | "operations" | "costs";
  /** left out: the last 7 days */
  range?: "24h" | "30d" | "90d";
}

export function parseDashboards(raw: Record<string, unknown>): DashboardsSearch {
  const out: DashboardsSearch = {};
  const board = first(raw.d);
  if (board === "detections" || board === "operations" || board === "costs") out.d = board;
  const range = first(raw.range);
  if (range !== undefined && range !== DEFAULT_RANGE && (RANGES as readonly string[]).includes(range)) out.range = range as DashboardsSearch["range"];
  return out;
}

export const boardOf = (s: DashboardsSearch): Board => s.d ?? "overview";
export const rangeOf = (s: DashboardsSearch): Range => s.range ?? DEFAULT_RANGE;
