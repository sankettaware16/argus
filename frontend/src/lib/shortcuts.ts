/**
 * The Inbox's keys (plan §5 Q-B2): arrows, Home, End and Page keys move through the list and
 * Enter opens (standard grid keys, always on while the list has the focus); j, k and ? are
 * single-character shortcuts, which a person can switch off (WCAG 2.1.4), kept in this browser
 * only. Pure apart from the storage it is handed (tests/shortcuts.test.ts).
 */
export type Move = "next" | "previous" | "first" | "last" | "pageDown" | "pageUp";
export type Act = { move: Move } | "open" | "help";

export interface KeyInfo {
  key: string;
  ctrlKey: boolean;
  metaKey: boolean;
  altKey: boolean;
  shiftKey: boolean;
}

const KEYS: Record<string, Move> = {
  ArrowDown: "next",
  ArrowUp: "previous",
  Home: "first",
  End: "last",
  PageDown: "pageDown",
  PageUp: "pageUp",
};

export function actionFor(e: KeyInfo, shortcuts: boolean): Act | null {
  if (e.ctrlKey || e.metaKey || e.altKey) return null;
  const moved = KEYS[e.key];
  if (moved !== undefined && !e.shiftKey) return { move: moved };
  if (e.key === "Enter" && !e.shiftKey) return "open";
  if (!shortcuts) return null;
  if (e.key === "j") return { move: "next" };
  if (e.key === "k") return { move: "previous" };
  if (e.key === "?") return "help";
  return null;
}

/** The new cursor row after a move: none yet (-1) starts at the first; always inside the loaded rows. */
export function moveCursor(at: number, move: Move, count: number, page: number): number {
  if (count <= 0) return -1;
  const last = count - 1;
  const step = Math.max(1, page);
  const target =
    move === "first" ? 0
    : move === "last" ? last
    : move === "next" ? (at < 0 ? 0 : at + 1)
    : move === "previous" ? (at < 0 ? 0 : at - 1)
    : move === "pageDown" ? (at < 0 ? 0 : at + step)
    : at < 0 ? 0 : at - step;
  return Math.min(Math.max(target, 0), last);
}

const KEY = "argus-shortcuts";

export function loadShortcuts(storage: Pick<Storage, "getItem"> | null): boolean {
  try {
    return storage?.getItem(KEY) !== "off";
  } catch {
    return true;
  }
}

export function saveShortcuts(storage: Pick<Storage, "setItem"> | null, on: boolean): void {
  try {
    storage?.setItem(KEY, on ? "on" : "off");
  } catch {
    // a browser that refuses storage keeps the choice for this page only
  }
}

export function browserStorage(): Storage | null {
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}
