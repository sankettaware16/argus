/**
 * The Settings page's logic, with no screen in it (D-327): a setting's value as the form holds it
 * (a draft), the draft turned back into the value the API takes, the change set that sends only
 * what the person edited, the risk of a save and the typed-words gate, the words of an outcome.
 * A key typed into a secret's box lives in a draft until the save and is never part of anything
 * else (no query key, no log, no address).
 */
import type { SectionOut, SettingChangeIn, SettingChangeOut, SettingOut } from "../client/types.gen";

export type Risk = SettingOut["risk"];
/** What a control holds: a switch, a list's items, or text (numbers, durations and dates stay text until sent). */
export type Draft = string | boolean | string[];
export type Built = { ok: true; value: unknown } | { ok: false; why: string };

const UNITS: [string, number][] = [
  ["d", 86_400],
  ["h", 3_600],
  ["m", 60],
];
const UNIT_WORDS: Record<string, [string, string]> = { d: ["day", "days"], h: ["hour", "hours"], m: ["minute", "minutes"], s: ["second", "seconds"] };
export const DURATION_HELP = "A length of time such as 90s, 15m, 36h or 5d.";

/** Seconds as the shortest exact text: 432000 → "5d", 129600 → "36h", 90 → "90s". */
export function formatDuration(seconds: number): string {
  const whole = Math.trunc(seconds);
  for (const [unit, size] of UNITS) if (whole !== 0 && whole % size === 0) return `${whole / size}${unit}`;
  return `${whole}s`;
}

/** Text such as "5d" or "36 h" as seconds; null when it is not a length of time. */
export function parseDuration(text: string): number | null {
  const m = /^(\d{1,9})\s*([smhd])$/i.exec(text.trim());
  if (m === null) return null;
  const size = { s: 1, m: 60, h: 3_600, d: 86_400 }[(m[2] ?? "s").toLowerCase()] ?? 1;
  return Number(m[1]) * size;
}

/** "5 days", "36 hours": the same length in words. */
export function durationWords(seconds: number): string {
  const text = formatDuration(seconds);
  const unit = text.slice(-1);
  const n = Number(text.slice(0, -1));
  const [one, many] = UNIT_WORDS[unit] ?? ["second", "seconds"];
  return `${n} ${n === 1 ? one : many}`;
}

/** A list of entries (objects, such as the log families): shown as it is, changed in the files. */
export function entryList(s: SettingOut): boolean {
  return s.kind === "list" && Array.isArray(s.value) && s.value.some((x) => typeof x === "object" && x !== null);
}

export function toDraft(s: SettingOut): Draft {
  const v = s.value;
  switch (s.kind) {
    case "bool":
      return v === true;
    case "list":
      return Array.isArray(v) ? v.map((x) => (typeof x === "object" && x !== null ? JSON.stringify(x) : String(x))) : [];
    case "duration":
      return typeof v === "number" ? formatDuration(v) : "";
    case "secret":
      return "";
    default:
      return v === null || v === undefined ? "" : typeof v === "object" ? JSON.stringify(v) : String(v);
  }
}

function items(draft: Draft): string[] {
  return (Array.isArray(draft) ? draft : []).map((x) => x.trim()).filter((x) => x !== "");
}

/** Whether two drafts of one setting mean the same ("36h" and "36 h" do; a list ignores blank rows). */
export function sameDraft(s: SettingOut, a: Draft, b: Draft): boolean {
  if (s.kind === "list") return JSON.stringify(items(a)) === JSON.stringify(items(b));
  if (s.kind === "duration" && typeof a === "string" && typeof b === "string") {
    const x = parseDuration(a);
    const y = parseDuration(b);
    return x !== null && y !== null ? x === y : a.trim() === b.trim();
  }
  if (typeof a === "string" && typeof b === "string") return a.trim() === b.trim();
  return a === b;
}

/** A draft as the API takes it, or the plain reason it cannot be sent. */
export function fromDraft(s: SettingOut, draft: Draft): Built {
  const text = typeof draft === "string" ? draft.trim() : "";
  const empty = (): Built => (s.optional ? { ok: true, value: null } : { ok: false, why: "This cannot be left empty." });
  switch (s.kind) {
    case "bool":
      return { ok: true, value: draft === true };
    case "int":
    case "float": {
      if (text === "") return empty();
      const whole = s.kind === "int";
      if (whole ? !/^-?\d+$/.test(text) : !/^-?(\d+\.?\d*|\.\d+)$/.test(text)) return { ok: false, why: whole ? "A whole number." : "A number." };
      const n = Number(text);
      if (s.minimum !== null && n < s.minimum) return { ok: false, why: `At least ${s.minimum}.` };
      if (s.maximum !== null && n > s.maximum) return { ok: false, why: `At most ${s.maximum}.` };
      return { ok: true, value: n };
    }
    case "duration": {
      if (text === "") return empty();
      const seconds = parseDuration(text);
      return seconds === null ? { ok: false, why: DURATION_HELP } : { ok: true, value: formatDuration(seconds) };
    }
    case "choice":
      if (text === "") return empty();
      return s.choices.includes(text) ? { ok: true, value: text } : { ok: false, why: "Choose one of the listed values." };
    case "date":
      if (text === "") return empty();
      return /^\d{4}-\d{2}-\d{2}$/.test(text) ? { ok: true, value: text } : { ok: false, why: "A date, year-month-day." };
    case "list": {
      const numeric = Array.isArray(s.value) && s.value.length > 0 && s.value.every((x) => typeof x === "number");
      const list = items(draft);
      if (numeric) {
        if (list.some((x) => !/^-?\d+(\.\d+)?$/.test(x))) return { ok: false, why: "Every item is a number." };
        return { ok: true, value: list.map(Number) };
      }
      return { ok: true, value: list };
    }
    case "secret":
      if (text === "") return { ok: false, why: "Type the new key." };
      return typeof draft === "string" && /[\r\n]/.test(draft.trim()) ? { ok: false, why: "One line only." } : { ok: true, value: text };
    default:
      return text === "" && s.optional ? { ok: true, value: null } : { ok: true, value: text };
  }
}

export interface ChangeSet {
  changes: SettingChangeIn[];
  errors: Record<string, string>;
  risk: Risk;
}

const ORDER: Risk[] = ["normal", "sensitive", "siem_write"];
export function worst(a: Risk, b: Risk): Risk {
  return ORDER.indexOf(a) >= ORDER.indexOf(b) ? a : b;
}

/**
 * What a save sends: only the settings the person edited (a draft that differs from the value
 * shown, a secret with a typed key) and those marked "back to the file's value". A secret's
 * empty box is no change; a setting the app may not change is never sent.
 */
export function buildChanges(settings: readonly SettingOut[], drafts: Readonly<Record<string, Draft>>, resets: ReadonlySet<string>): ChangeSet {
  const out: ChangeSet = { changes: [], errors: {}, risk: "normal" };
  for (const s of settings) {
    if (!s.editable || entryList(s)) continue;
    if (resets.has(s.key) && s.in_app && s.kind !== "secret") {
      out.changes.push({ key: s.key, reset: true });
      out.risk = worst(out.risk, s.risk);
      continue;
    }
    const draft = drafts[s.key];
    if (draft === undefined) continue;
    if (s.kind === "secret" ? draft === "" : sameDraft(s, draft, toDraft(s))) continue;
    const built = fromDraft(s, draft);
    if (!built.ok) {
      out.errors[s.key] = built.why;
      continue;
    }
    out.changes.push({ key: s.key, value: built.value });
    out.risk = worst(out.risk, s.risk);
  }
  return out;
}

/** The typed confirmation (the server compares the same way: spaces folded, case ignored). */
export function confirmOk(typed: string, words: string): boolean {
  const fold = (t: string) => t.split(/\s+/).filter(Boolean).join(" ").toLowerCase();
  return fold(words) !== "" && fold(typed) === fold(words);
}

export const RISK_NOTE: Record<Risk, string | null> = {
  normal: null,
  sensitive: "Needs your password again",
  siem_write: "Lets ARGUS write to the SIEM: needs your password and a typed confirmation",
};

/** Settings whose label, key or help hold every word of `query` (all of them when it is blank). */
export function searchSettings(sections: readonly SectionOut[], query: string): { section: SectionOut; settings: SettingOut[] }[] {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  const found = sections.map((section) => ({
    section,
    settings: words.length === 0 ? section.settings : section.settings.filter((s) => words.every((w) => `${s.label} ${s.key} ${s.help}`.toLowerCase().includes(w))),
  }));
  return found.filter((f) => f.settings.length > 0);
}

/** A long help text as its first sentence and the rest ("More"). */
export function splitHelp(help: string): { short: string; more: string | null } {
  const text = help.trim();
  if (text.length <= 160) return { short: text, more: null };
  const end = /[.!?](\s|$)/.exec(text);
  let cut = end !== null && end.index + 1 <= 220 ? end.index + 1 : -1;
  if (cut < 0) cut = Math.max(text.lastIndexOf(" ", 160), 40);
  const more = text.slice(cut).trim();
  return { short: text.slice(0, cut).trim(), more: more === "" ? null : more };
}

/** The setting a 422's sentence is about (it starts with the setting's label), or null. */
export function fieldFor(detail: string, among: readonly SettingOut[]): string | null {
  const hit = among.filter((s) => detail.startsWith(`${s.label}:`) || detail.startsWith(`${s.label} `) || detail.includes(s.key));
  return hit.length === 1 ? (hit[0]?.key ?? null) : null;
}

export type ChangeState = SettingChangeOut["state"];
export function settled(state: ChangeState): boolean {
  return state === "applied" || state === "refused" || state === "rolled_back";
}

/** What happened to a change, in a sentence. */
export function outcomeWords(c: Pick<SettingChangeOut, "state" | "outcome">): string {
  const why = c.outcome ? ` ${c.outcome}` : "";
  switch (c.state) {
    case "pending":
      return "Waiting for argus-admin to apply it.";
    case "applying":
      return "Being applied now.";
    case "applied":
      return c.outcome ? `Applied. ${c.outcome}` : "Applied.";
    case "refused":
      return `Not applied.${why || " argus-admin refused it."}`;
    case "rolled_back":
      return `Rolled back: the change did not work, so the files were put back.${why}`;
  }
}

/** How a value is said when it is not editable here. */
export function valueWords(s: SettingOut): string {
  const v = s.value;
  if (s.kind === "secret") return s.is_set ? "Set" : "Not set";
  if (v === null || v === undefined || v === "") return "Not set";
  if (typeof v === "boolean") return v ? "On" : "Off";
  if (s.kind === "duration" && typeof v === "number") return durationWords(v);
  if (Array.isArray(v)) return v.length === 0 ? "Empty" : v.join(", ");
  return typeof v === "object" ? JSON.stringify(v) : String(v);
}
