/**
 * The address's query string, the way the classic pages write it: `?severity=high&severity=low`
 * (a repeated name is a list), not a JSON string. Filters stay readable and sharable, and the
 * classic dashboard's addresses mean the same here. Pure (tests/search.test.ts).
 */
export type SearchValue = string | string[];
export type SearchObject = Record<string, SearchValue>;

const MAX_KEYS = 60;
const MAX_VALUE = 2_000;
const UNSAFE = new Set(["__proto__", "constructor", "prototype"]);

export function parseSearch(query: string): SearchObject {
  const found = new URLSearchParams(query.startsWith("?") ? query.slice(1) : query);
  const out: SearchObject = {};
  for (const [key, raw] of found) {
    if (UNSAFE.has(key) || key === "") continue;
    const known = Object.hasOwn(out, key);
    if (!known && Object.keys(out).length >= MAX_KEYS) continue;
    const value = raw.slice(0, MAX_VALUE);
    const old = known ? out[key] : undefined;
    if (old === undefined) out[key] = value;
    else if (Array.isArray(old)) {
      if (old.length < MAX_KEYS) old.push(value);
    } else out[key] = [old, value];
  }
  return out;
}

type Writable = string | number | boolean | readonly (string | number | boolean)[] | null | undefined;

export function stringifySearch(search: Record<string, unknown>): string {
  const out = new URLSearchParams();
  for (const [key, value] of Object.entries(search)) {
    const list: Writable = value as Writable;
    if (list === undefined || list === null) continue;
    if (Array.isArray(list)) {
      for (const item of list) out.append(key, String(item));
    } else {
      out.append(key, String(list));
    }
  }
  const text = out.toString();
  return text === "" ? "" : `?${text}`;
}

/** One value of a parsed search as a string (the first of a list), or undefined. */
export function first(value: unknown): string | undefined {
  if (typeof value === "string") return value;
  if (Array.isArray(value) && typeof value[0] === "string") return value[0];
  return undefined;
}

/** A parsed search value as a list of strings, without repeats; anything else is empty. */
export function listOf(value: unknown): string[] {
  const items = typeof value === "string" ? [value] : Array.isArray(value) ? value : [];
  return [...new Set(items.filter((x): x is string => typeof x === "string"))];
}
