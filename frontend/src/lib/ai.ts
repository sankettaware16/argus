/**
 * The "AI and agents" page's logic, with no screen in it (D-328): the page's read, money and
 * spend in words, a provider's and an AI task's own settings out of the page's list, the models
 * by size, and the change set (a task's empty provider list is sent as "all", not as no provider).
 */
import { queryOptions } from "@tanstack/react-query";
import { getAi } from "../client/sdk.gen";
import type { AiOut, AiProviderOut, SettingOut } from "../client/types.gen";
import { unwrap } from "./call";
import type { ChangeSet } from "./settings";

export const aiOptions = queryOptions({
  queryKey: ["admin", "ai"],
  queryFn: () => unwrap(getAi()),
  staleTime: 15_000,
});

const MONEY = new Intl.NumberFormat("en-US", { style: "currency", currency: "USD" });
export function money(n: number): string {
  return MONEY.format(n);
}

/** "$1.20 of $10.00", or "$1.20 (no limit of its own)". */
export function spendWords(spent: number, cap: number | null | undefined, none = "no limit of its own"): string {
  return cap === null || cap === undefined ? `${money(spent)} (${none})` : `${money(spent)} of ${money(cap)}`;
}

export const SIZES = ["small", "medium", "large"] as const;

/** A provider's models, smallest first; a size ARGUS does not know comes last. */
export function modelsBySize(models: Readonly<Record<string, string>>): [string, string][] {
  const rank = (t: string) => {
    const i = (SIZES as readonly string[]).indexOf(t);
    return i < 0 ? SIZES.length : i;
  };
  return Object.entries(models).sort(([a], [b]) => rank(a) - rank(b) || a.localeCompare(b));
}

export function byKey(settings: readonly SettingOut[]): Map<string, SettingOut> {
  return new Map(settings.map((s) => [s.key, s]));
}

/** A provider's switch, its two limits and its keys' settings (those the page was given). */
export function providerSettings(all: ReadonlyMap<string, SettingOut>, p: Pick<AiProviderOut, "name" | "keys">) {
  const base = `llm.providers.${p.name}`;
  return {
    enabled: all.get(`${base}.enabled`),
    monthly: all.get(`${base}.monthly_cap_usd`),
    daily: all.get(`${base}.daily_cap_usd`),
    keys: p.keys.map((k) => ({ key: k, setting: all.get(k.setting) })),
  };
}

export function purposeSettings(all: ReadonlyMap<string, SettingOut>, task: string) {
  const base = `llm.purposes.${task}`;
  return { calls: all.get(`${base}.calls_per_day`), providers: all.get(`${base}.providers`), tier: all.get(`${base}.tier`) };
}

/** The readings switch: `risk.reading` as Settings has it when that is loaded, else made from the page's own value. */
export function readingSetting(on: boolean, fromSettings?: SettingOut): SettingOut {
  return {
    key: "risk.reading",
    label: "ARGUS AI readings",
    help: "ARGUS AI writes its reading of each presented incident: what happened, the case against it and the next steps.",
    kind: "bool",
    risk: "normal",
    editable: true,
    optional: false,
    choices: [],
    minimum: null,
    maximum: null,
    default: null,
    homes: [],
    in_app: false,
    ...fromSettings,
    value: on,
  };
}

/** A change set as the AI's settings take it: a task's emptied provider list means "all" (null). */
export function aiChanges(built: ChangeSet, settings: readonly SettingOut[]): ChangeSet {
  const lists = new Set(settings.filter((s) => s.kind === "list" && s.optional).map((s) => s.key));
  return { ...built, changes: built.changes.map((c) => (lists.has(c.key) && Array.isArray(c.value) && c.value.length === 0 ? { key: c.key, value: null } : c)) };
}

/** The page's opening sentence: is the AI on, and with what. */
export function aiSummary(ai: Pick<AiOut, "any_key" | "stopped" | "providers">): string {
  const on = ai.providers.filter((p) => p.enabled);
  const ready = on.filter((p) => p.keys.some((k) => k.is_set));
  if (ai.stopped) return "All AI calls are stopped. ARGUS still works; nothing is sent to any provider until you resume.";
  if (!ai.any_key) return "The AI is off: add a key for at least one provider below. ARGUS still works without it.";
  const n = ready.length;
  if (n === 0) return "The AI is on.";
  return `The AI is on: ${n} ${n === 1 ? "provider is" : "providers are"} switched on with a key (${ready.map((p) => p.name).join(", ")}).`;
}

export function callsWords(ok: number, total: number): string {
  if (total === 0) return "No calls this month";
  return `${total} ${total === 1 ? "call" : "calls"} this month, ${ok} answered`;
}

/** Each AI setting's label as the outcome and history say it: "groq: On", "Second opinion: Calls a day". */
export function aiLabels(ai: Pick<AiOut, "settings" | "purposes">): Map<string, string> {
  const tasks = new Map(ai.purposes.map((p) => [p.task, p.label]));
  return new Map(
    ai.settings.map((s) => {
      const [, group, name] = s.key.split(".");
      if (group === "providers" && name !== undefined) return [s.key, `${name}: ${s.label}`];
      if (group === "purposes" && name !== undefined) return [s.key, `${tasks.get(name) ?? name}: ${s.label}`];
      return [s.key, s.label];
    }),
  );
}
