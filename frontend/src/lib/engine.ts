/**
 * The incident engine's view, as the UI v2 reads it (docs/p4f-ui-spec.md §2, §12.1). The only place
 * that knows the API's engine block and Today card: every component reads the shapes below,
 * never the raw answer. Pure (tests/engine.test.ts). Anything the engine sends that this page
 * does not know is left out, never shown raw; a block without a priority and a band is "not
 * scored yet" (§2.4).
 */
import { aOwn, ownCapital } from "./site";

export type Band = "P1" | "P2" | "P3" | "P4";
export type Lane = "decisive" | "burst" | "slow" | "campaign" | "exposure";
export type Certainty = "Likely" | "Suspected" | "Unclear" | "Likely harmless";
export type Shown = Certainty | "Confirmed";
export type CaseState = "suspected" | "open" | "assigned" | "contained" | "closed";

export const BANDS: readonly Band[] = ["P1", "P2", "P3", "P4"];
export const CERTAINTIES: readonly Certainty[] = ["Likely", "Suspected", "Unclear", "Likely harmless"];
const LANES: readonly Lane[] = ["decisive", "burst", "slow", "campaign", "exposure"];
const STATES: readonly CaseState[] = ["suspected", "open", "assigned", "contained", "closed"];

export interface WhyPoint {
  /** "+" adds points (negative: taken off); "×" multiplies (never shown as points) */
  op: "+" | "×";
  points: number;
  text: string;
}
export interface Check {
  state: "checked" | "ruled_out" | "unknown";
  text: string;
}
export interface Alternative {
  name: string;
  state: "ruled_out" | "fits" | "unknown";
  test: string;
}
export interface EngineObject {
  kind: "device" | "account" | "site";
  label: string;
  role: "affected" | "actor";
}
export interface Seen {
  kind: "path" | "domain" | "user_agent" | "file" | "size";
  value: string;
  count: number;
}
export interface Related {
  case_id: string;
  number: number;
  title: string;
  state: string;
  reason: string;
}
/** One claim of ARGUS AI's reading, and the incident's facts it rests on (D-324). */
export interface AiClaim {
  text: string;
  based_on: string[];
}
export interface AiSection {
  key: string;
  title: string;
  claims: AiClaim[];
}
/** ARGUS AI's reading: text only, it never changes the queue. */
export interface AiReading {
  kind: "story" | "second_opinion";
  model: string;
  written_at: string | null;
  /** it read the incident as it is now (false: an earlier version) */
  current: boolean;
  agrees: boolean;
  incidents: "one" | "two" | "unsure" | null;
  sections: AiSection[];
}
export interface Engine {
  priority: number;
  band: Band;
  lane: Lane | null;
  certainty: Shown;
  why: WhyPoint[];
  checks: Check[];
  alternatives: Alternative[];
  objects: EngineObject[];
  raised_by_ai: boolean;
  active: boolean;
  first_seen: string | null;
  last_seen: string | null;
  version: number;
  changed: string[];
  outcome: { rung: string; words: string } | null;
  similar_key: string | null;
  seen: Seen[];
  related: Related[];
  disagreement: string | null;
  ai_story: AiReading | null;
  ai_second_opinion: AiReading | null;
  team_notified_at: string | null;
  alert_groups: number | null;
  alerts: number | null;
}
export interface Person {
  username: string;
  name: string;
}
export interface Hold {
  by: Person;
  reason: string;
  until: string;
}
export interface Card {
  kind: "incident" | "alert_group";
  /** the case's id, or the alert group's; null while the engine runs in shadow */
  id: string | null;
  number: number | null;
  title: string;
  state: CaseState | null;
  /** the case's (or alert group's) version: sent back as expected_version */
  version: number | null;
  engine: Engine;
  taken_by: Person | null;
  notified_at: string | null;
  in_kibana: boolean;
  kibana_wait: string | null;
  waiting_since: string | null;
  hold: Hold | null;
}
export interface Audit {
  id: string;
  kind: "incident" | "alert_group";
  title: string;
  closed_as: string;
  facts: string[];
  stratum: string | null;
}
export interface Away {
  decided_by_others: { who: string; text: string; case_number: number | null }[];
  went_quiet: { id: string; number: number; title: string }[];
  gaps: { start: string; end: string | null; words: string }[];
}
export interface Today {
  /** "shadow": the engine only watches, its cards are not cases a person can decide */
  mode: "shadow" | "present";
  needs_you: Card[];
  more_waiting: number;
  new_activity: Card[];
  gray: Card[];
  handled: { since: string | null; count: number; categories: { key: string; label: string; count: number }[]; audits: Audit[] };
  audit_score: { days: number; checked: number; wrong: number } | null;
  away: Away | null;
  kibana_waiting: { count: number; oldest_since: string; words: string } | null;
}

// ------------------------------------------------------------------ reading the API's answers

type Raw = Record<string, unknown>;
const obj = (v: unknown): Raw | null => (v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Raw) : null);
const str = (v: unknown): string | null => (typeof v === "string" ? v : null);
const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);
const list = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
function one<T extends string>(v: unknown, known: readonly T[]): T | null {
  return typeof v === "string" && (known as readonly string[]).includes(v) ? (v as T) : null;
}
function each<T>(v: unknown, read: (item: unknown) => T | null): T[] {
  const out: T[] = [];
  for (const item of list(v)) {
    const got = read(item);
    if (got !== null) out.push(got);
  }
  return out;
}

function whyOf(v: unknown): WhyPoint | null {
  const o = obj(v);
  const points = num(o?.points);
  const text = str(o?.text);
  if (o === null || points === null || text === null) return null;
  return { op: o.op === "×" || o.op === "x" || o.op === "*" ? "×" : "+", points, text };
}
function checkOf(v: unknown): Check | null {
  const o = obj(v);
  const state = one(o?.state, ["checked", "ruled_out", "unknown"] as const);
  const text = str(o?.text);
  return state && text !== null ? { state, text } : null;
}
function alternativeOf(v: unknown): Alternative | null {
  const o = obj(v);
  const state = one(o?.state, ["ruled_out", "fits", "unknown"] as const);
  const name = str(o?.name);
  return state && name !== null ? { name, state, test: str(o?.test) ?? "" } : null;
}
function objectOf(v: unknown): EngineObject | null {
  const o = obj(v);
  const kind = one(o?.kind, ["device", "account", "site"] as const);
  const role = one(o?.role, ["affected", "actor"] as const);
  const label = str(o?.label);
  return kind && role && label ? { kind, role, label } : null;
}
function seenOf(v: unknown): Seen | null {
  const o = obj(v);
  const kind = one(o?.kind, ["path", "domain", "user_agent", "file", "size"] as const);
  const value = str(o?.value);
  return kind && value !== null ? { kind, value, count: num(o?.count) ?? 0 } : null;
}
function relatedOf(v: unknown): Related | null {
  const o = obj(v);
  const id = str(o?.case_id);
  const number = num(o?.number);
  return id && number !== null ? { case_id: id, number, title: str(o?.title) ?? "", state: str(o?.state) ?? "", reason: str(o?.reason) ?? "" } : null;
}
function aiClaimOf(v: unknown): AiClaim | null {
  const o = obj(v);
  const text = str(o?.text);
  return text !== null && text.trim() !== "" ? { text, based_on: each(o?.based_on, str) } : null;
}
function aiSectionOf(v: unknown): AiSection | null {
  const o = obj(v);
  const key = str(o?.key);
  const title = str(o?.title);
  const claims = each(o?.claims, aiClaimOf);
  return key && title && claims.length > 0 ? { key, title, claims } : null;
}
/** ARGUS AI's reading, or null: none written, or not of a known kind or with nothing to show. */
export function aiReadingOf(v: unknown): AiReading | null {
  const o = obj(v);
  const kind = one(o?.kind, ["story", "second_opinion"] as const);
  const sections = each(o?.sections, aiSectionOf);
  if (o === null || kind === null || sections.length === 0) return null;
  return {
    kind,
    model: str(o.model) ?? "a model",
    written_at: str(o.written_at),
    current: o.current !== false,
    agrees: o.agrees !== false,
    incidents: one(o.incidents, ["one", "two", "unsure"] as const),
    sections,
  };
}
function personOf(v: unknown): Person | null {
  const o = obj(v);
  const username = str(o?.username);
  if (o === null || username === null) return null;
  return { username, name: str(o.name) ?? str(o.display_name) ?? username };
}
function holdOf(v: unknown): Hold | null {
  const o = obj(v);
  const by = personOf(o?.by);
  const until = str(o?.until);
  return by && until ? { by, reason: str(o?.reason) ?? "", until } : null;
}

/** The engine block of a case or card, or null: not scored yet (§2.4). */
export function engineOf(raw: unknown): Engine | null {
  const o = obj(raw);
  if (o === null) return null;
  const priority = num(o.priority);
  const band = one(o.band, BANDS);
  if (priority === null || band === null) return null;
  const outcome = obj(o.outcome);
  const words = str(outcome?.words);
  return {
    priority: Math.max(0, Math.min(100, Math.round(priority))),
    band,
    lane: one(o.lane, LANES),
    certainty: one(o.certainty, [...CERTAINTIES, "Confirmed"] as const) ?? "Unclear",
    why: each(o.why, whyOf),
    checks: each(o.checks, checkOf),
    alternatives: each(o.alternatives, alternativeOf),
    objects: each(o.objects, objectOf),
    raised_by_ai: o.raised_by_ai === true,
    active: o.active === true,
    first_seen: str(o.first_seen),
    last_seen: str(o.last_seen),
    version: num(o.version) ?? 0,
    // a change may come as words or as {text}
    changed: each(o.changed, (c) => str(c) ?? str(obj(c)?.text)).filter((c) => c.trim() !== ""),
    outcome: words ? { rung: str(outcome?.rung) ?? "", words } : null,
    similar_key: str(o.similar_key),
    seen: each(o.seen, seenOf),
    related: each(o.related, relatedOf),
    disagreement: str(o.disagreement),
    ai_story: aiReadingOf(o.ai_story),
    ai_second_opinion: aiReadingOf(o.ai_second_opinion),
    team_notified_at: str(o.team_notified_at),
    alert_groups: num(o.alert_groups),
    alerts: num(o.alerts),
  };
}

/**
 * A Today card from the API, in the spec's shape (§2.2) or engine builder C's (`case_id`,
 * `case_number`, `case_state`, `case_version`); null when it has no engine block.
 */
export function toCard(raw: unknown): Card | null {
  const o = obj(raw);
  if (o === null) return null;
  const engine = engineOf(o.engine);
  if (engine === null) return null;
  const kind = o.kind === "alert_group" ? "alert_group" : "incident";
  return {
    kind,
    id: str(o.id) ?? str(o.case_id) ?? str(o.investigation_id),
    number: num(o.number) ?? num(o.case_number),
    title: str(o.title) ?? "",
    state: one(o.state, STATES) ?? one(o.case_state, STATES),
    version: num(o.version) ?? num(o.case_version),
    engine,
    taken_by: personOf(o.taken_by),
    notified_at: str(o.notified_at),
    in_kibana: o.in_kibana === true,
    kibana_wait: str(o.kibana_wait),
    waiting_since: str(o.waiting_since),
    hold: holdOf(o.hold),
  };
}

function auditOf(v: unknown): Audit | null {
  const o = obj(v);
  const id = str(o?.id) ?? str(o?.investigation_id);
  if (o === null || id === null) return null;
  const title = str(o.title) ?? str(o.rule_name) ?? "";
  return {
    id,
    kind: o.kind === "incident" ? "incident" : "alert_group",
    title,
    closed_as: str(o.closed_as) ?? str(o.label) ?? "",
    facts: each(o.facts, str),
    stratum: str(o.stratum),
  };
}

function awayOf(v: unknown): Away | null {
  const o = obj(v);
  if (o === null) return null;
  return {
    decided_by_others: each(o.decided_by_others, (d) => {
      const x = obj(d);
      const text = str(x?.text);
      return text ? { who: str(x?.who) ?? "", text, case_number: num(x?.case_number) } : null;
    }),
    went_quiet: each(o.went_quiet, (c) => {
      const x = obj(c);
      const id = str(x?.id);
      const number = num(x?.number);
      return id && number !== null ? { id, number, title: str(x?.title) ?? "" } : null;
    }),
    gaps: each(o.gaps, (g) => {
      const x = obj(g);
      const start = str(x?.start);
      return start ? { start, end: str(x?.end), words: str(x?.words) ?? "" } : null;
    }),
  };
}

/** The Today answer (§2.2); `audits` replaces the single `audit` when the server sends it. */
export function toToday(raw: unknown): Today {
  const o = obj(raw) ?? {};
  const handled = obj(o.handled) ?? {};
  const audits = Array.isArray(o.audits) ? each(o.audits, auditOf) : each([handled.audit], auditOf);
  const score = obj(o.audit_score);
  const kibana = obj(o.kibana_waiting);
  return {
    mode: o.mode === "shadow" ? "shadow" : "present",
    needs_you: each(o.needs_you, toCard),
    more_waiting: Math.max(0, num(o.more_waiting) ?? 0),
    new_activity: each(o.new_activity, toCard),
    gray: each(o.gray, toCard).slice(0, 5),
    handled: {
      since: str(handled.since),
      count: Math.max(0, num(handled.count) ?? 0),
      categories: each(handled.categories, (c) => {
        const x = obj(c);
        const key = str(x?.key);
        return key ? { key, label: str(x?.label) ?? key, count: num(x?.count) ?? 0 } : null;
      }),
      audits,
    },
    audit_score: score && num(score.days) !== null ? { days: num(score.days) ?? 0, checked: num(score.checked) ?? 0, wrong: num(score.wrong) ?? 0 } : null,
    away: awayOf(o.away),
    kibana_waiting: kibana && num(kibana.count) !== null ? { count: num(kibana.count) ?? 0, oldest_since: str(kibana.oldest_since) ?? "", words: str(kibana.words) ?? "" } : null,
  };
}

// ------------------------------------------------------------------ words

/** The time words of a band (§3.1). */
export const BAND_TIME: Readonly<Record<Band, string>> = {
  P1: "look today, before you leave",
  P2: "look within 2 days",
  P3: "look this week",
  P4: "look when you have time",
};

export function bandWords(band: Band): string {
  return `${band}: ${BAND_TIME[band]}`;
}

/** "Priority 82 of 100 · P1: look today, before you leave" (the badge's tooltip). */
export function priorityTip(e: Pick<Engine, "priority" | "band"> | null): string {
  return e === null ? "Not scored yet" : `Priority ${e.priority} of 100 · ${bandWords(e.band)}`;
}

/** The bar's call words (§7.1): never the 0–100 number. */
export function certaintyWords(c: Shown, by?: string | null): string {
  switch (c) {
    case "Likely":
      return "likely real";
    case "Suspected":
      return "suspected";
    case "Unclear":
      return "unclear";
    case "Likely harmless":
      return "likely harmless";
    case "Confirmed":
      return by ? `confirmed by ${by}` : "confirmed";
  }
}

/** The dismissal reasons a person gives on a possible incident (§5.5): never confirmations. */
export const DISMISS_REASONS = ["benign_expected", "attempt_no_impact", "benign_policy", "rule_false_positive", "duplicate", "created_in_error"] as const;

/** The certainty a page shows (§3.2): "Confirmed" once a person confirmed it, else the engine's. */
export function shownCertainty(state: string | null, closure: string | null | undefined, engine: Engine | null): Shown | null {
  if (state === "open" || state === "assigned" || state === "contained") return "Confirmed";
  if (state === "closed" && closure != null && !(DISMISS_REASONS as readonly string[]).includes(closure)) return "Confirmed";
  if (engine === null) return null;
  return engine.certainty === "Confirmed" && state === "suspected" ? "Unclear" : engine.certainty;
}

/** Whether a title already starts with a certainty word (naming v2's titles do; old ones do not). */
export function startsWithCertainty(title: string): boolean {
  const t = title.trimStart().toLowerCase();
  return [...CERTAINTIES, "Confirmed", "Possible"].some((c) => t.startsWith(`${c.toLowerCase()} `));
}

/** The kind of signal in words (§7.3 rule 5: "How the score is built", never on a card). */
export const LANE_WORDS: Readonly<Record<Lane, string>> = {
  decisive: "A strong signal",
  burst: "A sudden burst",
  slow: "A slow build-up",
  campaign: "The same activity on many devices",
  // the site's own word, read when shown (the session sets it after this module loads)
  get exposure() {
    const words = aOwn("site");
    return `${words.charAt(0).toUpperCase()}${words.slice(1)} may be exposed`;
  },
};

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const IPV6 = /^[0-9a-f]*:[0-9a-f:.]*$/i;

export function isIp(value: string): boolean {
  const v = value.trim();
  return IPV4.test(v) || (IPV6.test(v) && v.includes(":") && v.split(":").length >= 3);
}

/** A private, loopback or link-local address: an internal device's, never an outside one. */
export function isPrivateIp(value: string): boolean {
  const v = value.trim().toLowerCase();
  if (IPV4.test(v)) {
    const [a, b] = v.split(".").map(Number) as [number, number];
    return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127);
  }
  return isIp(v) && (v.startsWith("fc") || v.startsWith("fd") || v.startsWith("fe80") || v === "::1");
}

/** The noun of an entity chip (§12.3): an actor is never called "Device", whatever its kind. */
export function nounFor(o: Pick<EngineObject, "kind" | "role" | "label">): string {
  if (o.role === "affected") return o.kind === "device" ? "Device" : o.kind === "account" ? "Account" : ownCapital("site");
  if (o.kind === "account") return "Outside account";
  if (o.kind === "site") return "Outside site";
  return isIp(o.label) ? "Outside address" : "Outside host";
}

/** The entity page's kind for a chip (§4.3: device, account, site or outside). */
export function entityKind(o: Pick<EngineObject, "kind" | "role">): "device" | "account" | "site" | "outside" {
  if (o.role === "actor") return o.kind === "account" ? "account" : "outside";
  return o.kind;
}

/** The title's outcome tail: the text after the first " — ", up to the next one. */
export function titleTail(title: string): string | null {
  const at = title.indexOf(" — ");
  if (at < 0) return null;
  const rest = title.slice(at + 3);
  const end = rest.indexOf(" — ");
  const tail = (end < 0 ? rest : rest.slice(0, end)).trim();
  return tail === "" ? null : tail;
}

/** What answered, in words: the engine's outcome, else the title's tail. */
export function outcomeOf(engine: Engine | null, title: string): string | null {
  return engine?.outcome?.words ?? titleTail(title);
}

// what answered, in the words titles use today: naming v2 ("got HTTP 200, not verified", "a .env
// file served") and the older titles ("— some got successful answers", "… got successful answers")
const ANSWERED = /HTTP 200|\bserved\b|\bsuccessful answers?\b|\bgot 2\d\d\b/i;
const NOTHING_ANSWERED = /only ordinary pages|no HTTP 200|\bno successful answers?\b/i;

/** Whether these words say an own server answered, and do not rule it out. */
function saysAnswered(words: string | null | undefined): boolean {
  return typeof words === "string" && ANSWERED.test(words) && !NOTHING_ANSWERED.test(words);
}

/**
 * Whether "Scan or attempt: no sign it worked" must not be offered (§5.5, F3): the exposure lane,
 * or something answered (an HTTP 200, "served", successful answers) that the words do not rule
 * out, in the engine's outcome or anywhere in the title (an old title has no " — " before it).
 */
export function scanReasonBlocked(engine: Engine | null, title: string): boolean {
  if (engine?.lane === "exposure") return true;
  return saysAnswered(engine?.outcome?.words) || saysAnswered(title);
}

/** The objects of one side, in the engine's order (most at risk first). */
export function side(engine: Engine | null, role: EngineObject["role"]): EngineObject[] {
  return engine === null ? [] : engine.objects.filter((o) => o.role === role);
}

interface OldIndicator {
  kind: string;
  value: string;
  role: string;
}
interface OldReport {
  assets?: readonly { kind: string; value: string }[];
  targets?: readonly { kind: string; value: string }[];
  actors?: readonly { value: string; inside: boolean }[];
}

/**
 * The two sides of a case without the engine (§12.3), from its incident report and indicators: the
 * report's devices, accounts and sites on the own side; the actor and command-server
 * indicators on the other side, except an internal address (a private one, or one the report names
 * as ours), which is a device on the own side and never an outside address.
 */
export function sidesWithoutEngine(indicators: readonly OldIndicator[], report: OldReport | null): EngineObject[] {
  const out: EngineObject[] = [];
  const put = (o: EngineObject) => {
    if (!out.some((x) => x.role === o.role && x.label === o.label)) out.push(o);
  };
  for (const a of report?.assets ?? []) put({ kind: a.kind === "account" ? "account" : "device", label: a.value, role: "affected" });
  for (const t of report?.targets ?? []) put({ kind: t.kind === "site" ? "site" : "device", label: t.value, role: "affected" });
  const inside = new Set((report?.actors ?? []).filter((a) => a.inside).map((a) => a.value));
  for (const i of indicators) {
    if (i.role !== "actor" && i.role !== "c2") continue;
    const ours = isPrivateIp(i.value) || inside.has(i.value) || out.some((o) => o.role === "affected" && o.label === i.value);
    if (ours) put({ kind: "device", label: i.value, role: "affected" });
    else put({ kind: i.kind === "user" ? "account" : "device", label: i.value, role: "actor" });
  }
  return out;
}

// ------------------------------------------------------------------ the points (§7.3 rule 5)

export interface PointRow {
  kind: "point" | "other" | "capped";
  value: number;
  text: string;
}

/**
 * The why points as shown rows, sorted by value (largest first, negatives last), with one row
 * that makes them add up when the stored points do not: "Other factors and limits" (with any
 * multiplier in its words), or "Capped at 100". The visible values always sum to `priority` (I-6).
 */
export function pointsRows(engine: Pick<Engine, "priority" | "why">): PointRow[] {
  const rows: PointRow[] = engine.why
    .filter((w) => w.op === "+")
    .map((w) => ({ kind: "point" as const, value: Math.round(w.points), text: w.text }))
    .filter((r) => r.value !== 0)
    .sort((a, b) => b.value - a.value);
  const factors = engine.why.filter((w) => w.op === "×").map((w) => `×${w.points} ${w.text}`.trim());
  const sum = rows.reduce((total, r) => total + r.value, 0);
  const diff = engine.priority - sum;
  if (diff !== 0) {
    const capped = sum > 100 && engine.priority === 100 && factors.length === 0;
    rows.push(capped ? { kind: "capped", value: diff, text: "Capped at 100" } : { kind: "other", value: diff, text: factors.length > 0 ? `Other factors and limits (${factors.join(" · ")})` : "Other factors and limits" });
  }
  return rows;
}

/** "+50" or "−8" (a true minus sign), as the points are shown. */
export function signed(n: number): string {
  return n < 0 ? `−${Math.abs(n)}` : `+${n}`;
}

/** The `n` points of largest absolute value, as "+50 VirusTotal: 7 of 94 engines", and how many more. */
export function topWhy(engine: Engine, n = 3): { shown: string[]; more: number } {
  const points = engine.why.filter((w) => w.op === "+" && Math.round(w.points) !== 0);
  const top = [...points].sort((a, b) => Math.abs(b.points) - Math.abs(a.points)).slice(0, n);
  return { shown: top.map((w) => `${signed(Math.round(w.points))} ${w.text}`), more: Math.max(0, points.length - top.length) };
}

// ------------------------------------------------------------------ checks and alternatives

export interface StillOpen {
  lines: string[];
  more: number;
}

/**
 * What still argues against confirming (§5.4): every alternative that fits or is not tested, and
 * every unknown check; identical tests merged into one line; at most 4 lines, then "+N more". A
 * case without the engine passes its report's other explanations as `alternatives`, no checks.
 */
export function stillOpen(engine: Pick<Engine, "alternatives" | "checks"> | null, max = 4): StillOpen {
  if (engine === null) return { lines: [], more: 0 };
  const byTest = new Map<string, string[]>();
  const order: string[] = [];
  for (const a of engine.alternatives) {
    if (a.state === "ruled_out") continue;
    const key = a.test.trim();
    if (!byTest.has(key)) {
      byTest.set(key, []);
      order.push(key);
    }
    byTest.get(key)?.push(`${a.state === "fits" ? "still fits" : "not tested"}: ${a.name}`);
  }
  const lines = order.map((test) => {
    const names = (byTest.get(test) ?? []).join("; ");
    const one = `Another explanation ${names}.`;
    return test === "" ? one : `${one} The check that would decide: ${test}`;
  });
  for (const c of engine.checks) if (c.state === "unknown") lines.push(`Not known: ${c.text}`);
  return { lines: lines.slice(0, max), more: Math.max(0, lines.length - max) };
}

export interface AltLine {
  names: string[];
  state: Alternative["state"];
  test: string;
}

/** Other explanations with identical tests merged into one line (lead walk C8.4), in order. */
export function mergedAlternatives(alternatives: readonly Alternative[]): AltLine[] {
  const out: AltLine[] = [];
  for (const a of alternatives) {
    const same = a.test.trim() !== "" ? out.find((l) => l.test === a.test.trim() && l.state === a.state) : undefined;
    if (same) same.names.push(a.name);
    else out.push({ names: [a.name], state: a.state, test: a.test.trim() });
  }
  return out;
}

export const ALT_WORDS: Readonly<Record<Alternative["state"], string>> = { ruled_out: "Ruled out", fits: "Still fits", unknown: "Not tested" };

/** "1 other explanation still fits: <name> (<test>)" (§7.3 rule 4), or null. */
export function stillFitsLine(engine: Engine | null): { text: string; more: number } | null {
  if (engine === null) return null;
  const fits = engine.alternatives.filter((a) => a.state === "fits");
  const pick = fits[0] ?? (engine.certainty === "Unclear" ? engine.alternatives.find((a) => a.state === "unknown") : undefined);
  if (pick === undefined) return null;
  const n = Math.max(1, fits.length);
  const head = `${n} other ${n === 1 ? "explanation still fits" : "explanations still fit"}: ${pick.name}`;
  return { text: pick.test ? `${head} (${pick.test})` : head, more: Math.max(0, fits.length - 1) };
}

// ------------------------------------------------------------------ Today's layout (§5.2)

export type Slot = { kind: "card"; card: Card } | { kind: "similar"; band: Band; cards: Card[]; words: string; outcome: string };

/** The shared title words of similar cards, up to the object (before " of ", " from ", " by "). */
function sharedWords(cards: readonly Card[]): string {
  const first = cards[0]?.title ?? "";
  const head = first.split(" — ")[0] ?? first;
  const cut = head.search(/ (of|from|by|on|against|to) /);
  return (cut > 0 ? head.slice(0, cut) : head).trim();
}

/**
 * Needs you in the order shown: every P1, then every P2 (never capped), then at most `cap` P3/P4
 * slots in the server's order; cards that share a similar key, the band (P3 or P4) and the
 * outcome words collapse into one "N similar" slot. `hidden` counts the P3/P4 cards left out.
 */
export function layoutNeedsYou(cards: readonly Card[], cap = 8): { slots: Slot[]; hidden: number } {
  const urgent = [...cards.filter((c) => c.engine.band === "P1"), ...cards.filter((c) => c.engine.band === "P2")];
  const rest = cards.filter((c) => c.engine.band === "P3" || c.engine.band === "P4");
  const slots: Slot[] = urgent.map((card) => ({ kind: "card", card }));
  const groups = new Map<string, Card[]>();
  for (const c of rest) {
    const outcome = outcomeOf(c.engine, c.title);
    if (c.engine.similar_key === null || outcome === null) continue;
    const key = `${c.engine.similar_key}\u0000${c.engine.band}\u0000${outcome}`;
    groups.set(key, [...(groups.get(key) ?? []), c]);
  }
  const placed = new Set<string>();
  const lower: Slot[] = [];
  for (const c of rest) {
    const outcome = outcomeOf(c.engine, c.title);
    const key = c.engine.similar_key !== null && outcome !== null ? `${c.engine.similar_key}\u0000${c.engine.band}\u0000${outcome}` : null;
    const group = key === null ? undefined : groups.get(key);
    if (key !== null && group !== undefined && group.length >= 2) {
      if (placed.has(key)) continue;
      placed.add(key);
      lower.push({ kind: "similar", band: c.engine.band, cards: group, words: sharedWords(group), outcome: outcome ?? "" });
    } else lower.push({ kind: "card", card: c });
  }
  const shown = lower.slice(0, cap);
  const hidden = lower.slice(cap).reduce((n, s) => n + (s.kind === "card" ? 1 : s.cards.length), 0);
  return { slots: [...slots, ...shown], hidden };
}

/** The Needs-you number (§3.1 term 4): the same on Today, in the nav and on Incidents. */
export function needsYouCount(t: Pick<Today, "needs_you" | "more_waiting">): number {
  return t.needs_you.length + t.more_waiting;
}

export interface SummaryPart {
  text: string;
  strong?: boolean;
}

/** The summary line's parts (§5.2), exact words; zero parts dropped. */
export function summaryParts(t: Today, sinceWords: string | null): SummaryPart[] {
  const urgent = t.needs_you.filter((c) => c.engine.band === "P1").length;
  const total = needsYouCount(t);
  const more = total - urgent;
  const parts: SummaryPart[] = [];
  if (urgent > 0) {
    parts.push({ text: `${urgent} urgent (P1)`, strong: true });
    if (more > 0) parts.push({ text: `${more} more need${more === 1 ? "s" : ""} you` });
  } else if (total > 0) parts.push({ text: `${total} need${total === 1 ? "s" : ""} you`, strong: true });
  else parts.push({ text: "Nothing needs you right now", strong: true });
  const k = t.new_activity.length;
  if (k > 0) parts.push({ text: `${k} with new activity` });
  if (t.handled.count > 0) parts.push({ text: `ARGUS handled ${t.handled.count.toLocaleString("en-US")} since your last round${sinceWords ? ` (${sinceWords})` : ""}` });
  return parts;
}

// ------------------------------------------------------------------ states and queue order

/** A case's state in words (§3.2). */
export function stateWords(c: { state: string | null; number: number | null; taken_by?: Person | null; hold?: Hold | null }): string {
  const n = c.number !== null ? ` #${c.number}` : "";
  switch (c.state) {
    case "suspected":
      return `Possible incident${n}`;
    case "open":
      return `Incident${n} · not taken yet`;
    case "assigned":
      return `Incident${n} · taken by ${c.taken_by?.name ?? "someone"}`;
    case "contained":
      return `Incident${n} · contained`;
    case "closed":
      return `Closed${n}`;
    default:
      return c.number !== null ? `Alert group` : "Alert group";
  }
}

/** Priority order (§6.2): scored rows by priority, then last seen; unscored after every scored one, by severity, then activity. */
const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
export function byPriority<T extends { engine: Engine | null; severity?: string; last?: string | null }>(a: T, b: T): number {
  if (a.engine && b.engine) {
    if (a.engine.priority !== b.engine.priority) return b.engine.priority - a.engine.priority;
    return (b.engine.last_seen ?? "").localeCompare(a.engine.last_seen ?? "");
  }
  if (a.engine) return -1;
  if (b.engine) return 1;
  const s = (SEVERITY_RANK[b.severity ?? ""] ?? 0) - (SEVERITY_RANK[a.severity ?? ""] ?? 0);
  if (s !== 0) return s;
  return (b.last ?? "").localeCompare(a.last ?? "");
}
