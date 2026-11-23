/**
 * The Incidents queue's address (docs/p4f-ui-spec.md §6.3): the view tab, every filter and the sort
 * live in the URL; anything invalid is left out, never an error. And the old addresses' new homes
 * (§4.3). Pure (tests/incidents.test.ts).
 */
import type { CaseRowOut } from "../client/types.gen";
import type { CaseViewName } from "./cases";
import { BANDS, byPriority, engineOf, isPrivateIp, outcomeOf, scanReasonBlocked, shownCertainty, type Band, type Engine } from "./engine";
import { first } from "./search";
import { ownCapital } from "./site";

export const INCIDENT_VIEWS = ["needs-you", "mine", "open", "owner-told", "closed", "all"] as const;
export type IncidentView = (typeof INCIDENT_VIEWS)[number];

export const VIEW_TITLES: Readonly<Record<IncidentView, string>> = {
  "needs-you": "Needs you",
  mine: "Mine",
  open: "Open",
  "owner-told": "Owner told",
  closed: "Closed",
  all: "All",
};

/** The API's view for each tab (`GET /cases?view=`). */
export const VIEW_API: Readonly<Record<IncidentView, CaseViewName>> = {
  "needs-you": "queue",
  mine: "mine",
  open: "active",
  "owner-told": "notified",
  closed: "closed",
  all: "all",
};

export const CERTAINTY_FILTERS = ["Likely", "Suspected", "Unclear", "Likely harmless", "Confirmed"] as const;
export const SIDE_FILTERS = ["device", "account", "site"] as const;
export const SIDE_WORDS: Readonly<Record<(typeof SIDE_FILTERS)[number], string>> = {
  device: "Devices",
  account: "Accounts",
  // the site's own word, read when shown
  get site() {
    return ownCapital("sites");
  },
};
export const SORTS = ["priority", "waiting", "activity"] as const;
export const SORT_WORDS: Readonly<Record<(typeof SORTS)[number], string>> = { priority: "Priority", waiting: "Waiting longest", activity: "Last activity" };
export const KIBANA_FILTERS = ["in", "waiting", "failing"] as const;
export const LANE_FILTERS = ["decisive", "burst", "slow", "campaign", "exposure"] as const;

export interface IncidentsSearch {
  view: IncidentView;
  q?: string;
  band?: Band[];
  certainty?: string[];
  side?: string[];
  /** "me", "nobody" or a username */
  taken?: string;
  active?: "1";
  ai?: "1";
  lane?: string;
  kibana?: (typeof KIBANA_FILTERS)[number];
  sort?: (typeof SORTS)[number];
  /** Review together: the incidents' ids */
  together?: string[];
  /** Closed: every closure, not only the last 30 days */
  all_time?: "1";
}

function multi<T extends string>(raw: unknown, known: readonly T[]): T[] | undefined {
  const parts = (Array.isArray(raw) ? raw : typeof raw === "string" ? raw.split(",") : []).filter((x): x is string => typeof x === "string").map((x) => x.trim());
  const kept = known.filter((k) => parts.includes(k));
  return kept.length > 0 ? kept : undefined;
}

const ID = /^[0-9a-f-]{8,64}$/i;

export function parseIncidents(raw: Record<string, unknown>): IncidentsSearch {
  const view = first(raw.view);
  const out: IncidentsSearch = { view: INCIDENT_VIEWS.find((v) => v === view) ?? "needs-you" };
  const q = first(raw.q)?.trim();
  if (q !== undefined && q !== "" && q.length <= 120 && !q.includes("\u0000")) out.q = q;
  const band = multi(raw.band, BANDS);
  if (band) out.band = band;
  const certainty = multi(raw.certainty, CERTAINTY_FILTERS);
  if (certainty) out.certainty = certainty;
  const side = multi(raw.side, SIDE_FILTERS);
  if (side) out.side = side;
  const taken = first(raw.taken)?.trim();
  if (taken && /^[A-Za-z0-9._@-]{1,64}$/.test(taken)) out.taken = taken;
  if (first(raw.active) === "1") out.active = "1";
  if (first(raw.ai) === "1") out.ai = "1";
  const lane = first(raw.lane);
  if (lane && (LANE_FILTERS as readonly string[]).includes(lane)) out.lane = lane;
  const kibana = first(raw.kibana);
  const k = KIBANA_FILTERS.find((x) => x === kibana);
  if (k) out.kibana = k;
  const sort = first(raw.sort);
  const s = SORTS.find((x) => x === sort);
  if (s && s !== "priority") out.sort = s;
  const rawTogether: unknown[] = Array.isArray(raw.together) ? raw.together : typeof raw.together === "string" ? raw.together.split(",") : [];
  const together = rawTogether.filter((x): x is string => typeof x === "string" && ID.test(x)).slice(0, 25);
  if (together.length > 0) out.together = together;
  if (first(raw.all_time) === "1") out.all_time = "1";
  return out;
}

/** The search as the URL writes it (lists joined by commas). */
export function incidentsUrlSearch(s: IncidentsSearch): Record<string, string> {
  const out: Record<string, string> = { view: s.view };
  for (const [k, v] of Object.entries(s)) {
    if (k === "view" || v === undefined) continue;
    out[k] = Array.isArray(v) ? v.join(",") : String(v);
  }
  return out;
}

/** How many filters are set (the phone's "Filters (2)"). */
export function filterCount(s: IncidentsSearch): number {
  return (["band", "certainty", "side", "taken", "active", "ai", "lane", "kibana"] as const).filter((k) => s[k] !== undefined).length;
}

/** The old case list's views (§4.3): their new tab. */
export function viewForOldCases(view: string | undefined): IncidentView {
  switch (view) {
    case "active":
      return "open";
    case "notified":
      return "owner-told";
    case "mine":
    case "closed":
    case "all":
      return view;
    default:
      return "needs-you";
  }
}

// ------------------------------------------------------------------ the loaded rows, filtered and sorted


export interface Row {
  row: CaseRowOut;
  engine: Engine | null;
}

export function rowOf(row: CaseRowOut): Row {
  return { row, engine: engineOf((row as unknown as { engine?: unknown }).engine) };
}

/** The filters of the address, applied to the loaded rows (the server has no filter parameters yet: A10). */
export function filterRows(rows: readonly Row[], s: IncidentsSearch, me: string | null): Row[] {
  return rows.filter(({ row, engine }) => {
    if (s.band && !(engine && s.band.includes(engine.band))) return false;
    if (s.certainty) {
      const c = shownCertainty(row.state, row.closure_reason, engine);
      if (c === null || !s.certainty.includes(c)) return false;
    }
    if (s.side && !(engine && engine.objects.some((o) => o.role === "affected" && s.side?.includes(o.kind)))) return false;
    if (s.taken) {
      const owner = row.owner?.username ?? null;
      if (s.taken === "nobody" ? owner !== null : s.taken === "me" ? owner === null || owner !== me : owner !== s.taken) return false;
    }
    if (s.active === "1" && !engine?.active) return false;
    if (s.ai === "1" && !engine?.raised_by_ai) return false;
    if (s.lane && engine?.lane !== s.lane) return false;
    if (s.kibana === "in" && !row.in_kibana) return false;
    if (s.kibana === "waiting" && (row.in_kibana || row.state === "suspected")) return false;
    if (s.kibana === "failing") return false; // the server does not say yet (A5)
    return true;
  });
}

const last = (r: Row) => r.engine?.last_seen ?? r.row.last_alert_at ?? r.row.updated_at;
const waitingSince = (r: Row) => (r.row as CaseRowOut & { waiting_since?: string | null }).waiting_since ?? r.row.opened_at ?? r.row.updated_at;

export function sortRows(rows: readonly Row[], sort: IncidentsSearch["sort"]): Row[] {
  const out = [...rows];
  if (sort === "activity") return out.sort((a, b) => (last(b) ?? "").localeCompare(last(a) ?? ""));
  if (sort === "waiting") return out.sort((a, b) => (waitingSince(a) ?? "").localeCompare(waitingSince(b) ?? ""));
  return out.sort((a, b) => byPriority({ engine: a.engine, severity: a.row.severity, last: last(a) }, { engine: b.engine, severity: b.row.severity, last: last(b) }));
}

/** The rows whose "Scan or attempt" must not be used (§6.5): their words, for the bulk dialog. */
export function blockedRows(rows: readonly Row[]): Row[] {
  return rows.filter((r) => scanReasonBlocked(r.engine, r.row.title));
}

export function outcomeWords(r: Row): string | null {
  return outcomeOf(r.engine, r.row.title);
}

/**
 * How many outside sources a title names ("by 12 outside addresses", "by 3 outside IPs", "by
 * 203.0.113.5"), or null when it says none: a case without the engine has no other count.
 */
export function titleSources(title: string): number | null {
  const counted = /\bby (\d[\d,]*) outside (?:addresses|address|IPs|IP|sources|source)\b/i.exec(title);
  if (counted) return Number((counted[1] ?? "").replace(/,/g, ""));
  const named = /\bby ((?:\d{1,3}\.){3}\d{1,3})\b/.exec(title);
  return named && !isPrivateIp(named[1] ?? "") ? 1 : null;
}

export interface TogetherRow {
  ours: string;
  outcome: string;
  band: string;
  number: number;
  id: string;
  /** null: not known (no engine, and the title names no count) */
  sources: number | null;
  last: string | null;
  different: boolean;
  blocked: boolean;
}

/**
 * Review together's rows (§6.6): one per own-side object, with what answered; the outside
 * sources last; "Different" on a row whose band or outcome differs from the majority.
 */
export function togetherRows(rows: readonly Row[]): TogetherRow[] {
  const out: TogetherRow[] = [];
  for (const r of rows) {
    const ours = r.engine?.objects.filter((o) => o.role === "affected") ?? [];
    const sources = r.engine ? r.engine.objects.filter((o) => o.role === "actor").length : titleSources(r.row.title);
    const outcome = outcomeWords(r) ?? "not known";
    const blocked = scanReasonBlocked(r.engine, r.row.title);
    for (const c of ours.length > 0 ? ours.map((o) => o.label) : ["not known"]) {
      out.push({ ours: c, outcome, band: r.engine?.band ?? "—", number: r.row.number, id: r.row.id, sources, last: r.engine?.last_seen ?? r.row.last_alert_at, different: false, blocked });
    }
  }
  const tally = (key: (t: TogetherRow) => string) => {
    const n = new Map<string, number>();
    for (const t of out) n.set(key(t), (n.get(key(t)) ?? 0) + 1);
    return [...n.entries()].sort((a, b) => b[1] - a[1])[0]?.[0];
  };
  const band = tally((t) => t.band);
  const outcome = tally((t) => t.outcome);
  return out.map((t) => ({ ...t, different: out.length > 1 && (t.band !== band || t.outcome !== outcome) }));
}
