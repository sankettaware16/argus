/**
 * The Search page's address and its type guess (docs/p4f-ui-spec.md §10.2). Pure
 * (tests/v2-search.test.tsx). `advanced=1` is today's Inbox, its own parameters kept.
 */
import type { InboxSearch } from "./inboxQuery";
import { isIp, isPrivateIp } from "./engine";
import { first } from "./search";
import { own, ownCapital } from "./site";

export const GUESSES = ["number", "ir", "device", "outside", "domain", "name", "words"] as const;
export type Guess = (typeof GUESSES)[number];

export const GUESS_WORDS: Readonly<Record<Guess, string>> = {
  number: "an incident number",
  ir: "an IR number",
  device: "a device address",
  outside: "an outside address",
  // the site's own word, read when shown
  get domain() {
    return `a domain or ${own("site")}`;
  },
  name: "a host or account",
  words: "words (titles, rule names)",
};

export type SearchSearch = { advanced?: "1"; q?: string; guess?: Guess } & Partial<Omit<InboxSearch, "view">> & { view?: InboxSearch["view"] };

export function parseSearchPage(raw: Record<string, unknown>): SearchSearch {
  const out: SearchSearch = {};
  const q = first(raw.q)?.trim();
  if (q !== undefined && q !== "" && q.length <= 200 && !q.includes("\u0000")) out.q = q;
  const guess = first(raw.guess);
  const g = GUESSES.find((x) => x === guess);
  if (g) out.guess = g;
  return out;
}

/** What the box's text looks like (§10.2). */
export function guessOf(text: string): Guess {
  const t = text.trim();
  if (/^#?\d{1,7}$/.test(t)) return "number";
  if (/-IR-\d{4}-\d{4}-\d{2}$/i.test(t) || /^IR-/i.test(t)) return "ir";
  if (isIp(t)) return isPrivateIp(t) ? "device" : "outside";
  if (/\.[A-Za-z]{2,}$/.test(t) && /^[A-Za-z0-9.-]+$/.test(t)) return "domain";
  if (/^[A-Za-z0-9._@-]{2,64}$/.test(t)) return "name";
  return "words";
}

/** The alert-group search's kind for a guess, or null (incidents only). */
export function kindsFor(guess: Guess): ("ip" | "host" | "domain" | "user")[] {
  switch (guess) {
    case "device":
    case "outside":
      return ["ip"];
    case "domain":
      return ["domain"];
    case "name":
      return ["host", "user"];
    default:
      return [];
  }
}

/** The entity pages a guess points at (§9): kind and value. */
export function entitiesFor(guess: Guess, value: string): { kind: "device" | "account" | "site" | "outside"; noun: string }[] {
  switch (guess) {
    case "device":
      return [{ kind: "device", noun: "Device" }];
    case "outside":
      return [{ kind: "outside", noun: "Outside address" }];
    case "domain":
      return [{ kind: "site", noun: ownCapital("site") }];
    case "name":
      return [
        { kind: "device", noun: "Device" },
        { kind: "account", noun: "Account" },
      ];
    default:
      void value;
      return [];
  }
}

const RECENT_KEY = "argus.search.recent";

/** The last searches, kept in this browser only (a convenience: it may be empty, or unavailable). */
export function recentSearches(): string[] {
  try {
    const raw = window.localStorage.getItem(RECENT_KEY);
    const list: unknown = raw ? JSON.parse(raw) : [];
    return Array.isArray(list) ? list.filter((x): x is string => typeof x === "string").slice(0, 5) : [];
  } catch {
    return [];
  }
}

export function rememberSearch(q: string): void {
  try {
    const list = [q, ...recentSearches().filter((x) => x !== q)].slice(0, 5);
    window.localStorage.setItem(RECENT_KEY, JSON.stringify(list));
  } catch {
    // browser storage is a convenience: without it nothing is remembered
  }
}
