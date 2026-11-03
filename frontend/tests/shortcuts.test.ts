// The Inbox's keys (lib/shortcuts.ts): arrows and Enter always, j k ? only while switched on.
import fc from "fast-check";
import { describe, expect, it, vi } from "vitest";
import { actionFor, browserStorage, loadShortcuts, moveCursor, saveShortcuts, type KeyInfo } from "../src/lib/shortcuts";

const key = (k: string, more: Partial<KeyInfo> = {}): KeyInfo => ({ key: k, ctrlKey: false, metaKey: false, altKey: false, shiftKey: false, ...more });

describe("actionFor", () => {
  it("moves with the arrows, Home, End and the Page keys, and opens with Enter, with shortcuts on or off", () => {
    for (const on of [true, false]) {
      expect(actionFor(key("ArrowDown"), on)).toEqual({ move: "next" });
      expect(actionFor(key("ArrowUp"), on)).toEqual({ move: "previous" });
      expect(actionFor(key("Home"), on)).toEqual({ move: "first" });
      expect(actionFor(key("End"), on)).toEqual({ move: "last" });
      expect(actionFor(key("PageDown"), on)).toEqual({ move: "pageDown" });
      expect(actionFor(key("PageUp"), on)).toEqual({ move: "pageUp" });
      expect(actionFor(key("Enter"), on)).toBe("open");
    }
  });

  it("takes j, k and ? only while the single-key shortcuts are on", () => {
    expect(actionFor(key("j"), true)).toEqual({ move: "next" });
    expect(actionFor(key("k"), true)).toEqual({ move: "previous" });
    expect(actionFor(key("?", { shiftKey: true }), true)).toBe("help");
    for (const k of ["j", "k", "?"]) expect(actionFor(key(k), false)).toBeNull();
  });

  it("leaves a key with Ctrl, Cmd or Alt to the browser, and any other key alone", () => {
    for (const mod of ["ctrlKey", "metaKey", "altKey"] as const) {
      for (const k of ["j", "k", "Enter", "ArrowDown", "?"]) expect(actionFor(key(k, { [mod]: true }), true)).toBeNull();
    }
    expect(actionFor(key("x"), true)).toBeNull();
    expect(actionFor(key("J"), true)).toBeNull();
    expect(actionFor(key("Enter", { shiftKey: true }), true)).toBeNull();
    expect(actionFor(key("ArrowDown", { shiftKey: true }), true)).toBeNull();
  });
});

describe("moveCursor", () => {
  it("starts at the first row, steps by one, and stays inside the rows", () => {
    expect(moveCursor(-1, "next", 5, 3)).toBe(0);
    expect(moveCursor(-1, "previous", 5, 3)).toBe(0);
    expect(moveCursor(0, "previous", 5, 3)).toBe(0);
    expect(moveCursor(4, "next", 5, 3)).toBe(4);
    expect(moveCursor(2, "next", 5, 3)).toBe(3);
    expect(moveCursor(2, "previous", 5, 3)).toBe(1);
    expect(moveCursor(1, "first", 5, 3)).toBe(0);
    expect(moveCursor(1, "last", 5, 3)).toBe(4);
    expect(moveCursor(1, "pageDown", 9, 3)).toBe(4);
    expect(moveCursor(7, "pageUp", 9, 3)).toBe(4);
    expect(moveCursor(-1, "pageDown", 9, 3)).toBe(0);
    expect(moveCursor(-1, "pageUp", 9, 3)).toBe(0);
    expect(moveCursor(3, "pageDown", 9, 0)).toBe(4);
    expect(moveCursor(0, "next", 0, 3)).toBe(-1);
  });

  it("always lands on a row when there are rows", () => {
    fc.assert(fc.property(fc.integer({ min: -1, max: 50 }), fc.constantFrom("next", "previous", "first", "last", "pageDown", "pageUp"), fc.integer({ min: 1, max: 50 }), fc.integer({ min: -3, max: 20 }), (at, move, rows, page) => {
      const to = moveCursor(Math.min(at, rows - 1), move, rows, page);
      expect(to).toBeGreaterThanOrEqual(0);
      expect(to).toBeLessThan(rows);
    }));
  });
});

describe("the off switch", () => {
  const memory = () => {
    const data = new Map<string, string>();
    return { getItem: (k: string) => data.get(k) ?? null, setItem: (k: string, v: string) => void data.set(k, v) };
  };

  it("is on until a person switches it off, and remembers that in this browser", () => {
    const store = memory();
    expect(loadShortcuts(store)).toBe(true);
    saveShortcuts(store, false);
    expect(loadShortcuts(store)).toBe(false);
    saveShortcuts(store, true);
    expect(loadShortcuts(store)).toBe(true);
  });

  it("writes what it means to the storage, word for word", () => {
    const written: Record<string, string> = {};
    saveShortcuts({ setItem: (k, v) => void (written[k] = v) }, true);
    expect(written).toEqual({ "argus-shortcuts": "on" });
    saveShortcuts({ setItem: (k, v) => void (written[k] = v) }, false);
    expect(written).toEqual({ "argus-shortcuts": "off" });
    expect(loadShortcuts({ getItem: (k) => (k === "argus-shortcuts" ? "on" : "off") })).toBe(true);
    expect(loadShortcuts({ getItem: (k) => (k === "argus-shortcuts" ? "off" : "on") })).toBe(false);
  });

  it("works without storage, or with storage that throws", () => {
    expect(loadShortcuts(null)).toBe(true);
    const broken = { getItem: () => { throw new Error("blocked"); }, setItem: () => { throw new Error("blocked"); } };
    expect(loadShortcuts(broken)).toBe(true);
    expect(() => saveShortcuts(broken, false)).not.toThrow();
    expect(() => saveShortcuts(null, false)).not.toThrow();
  });

  it("finds the browser's storage, or none when the browser refuses it", () => {
    expect(browserStorage()).toBe(window.localStorage);
    const spy = vi.spyOn(window, "localStorage", "get").mockImplementation(() => { throw new Error("blocked"); });
    expect(browserStorage()).toBeNull();
    spy.mockRestore();
  });
});
