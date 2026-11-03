// AR4: C confirms, 1 to 5 choose an outcome, N goes on; never while typing, with a modifier, in a
// dialog, or when the person switched the single-key shortcuts off (WCAG 2.1.4).
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { KEYED_OUTCOMES } from "../src/lib/verdict";
import { dialogOpen, isTyping, verdictAct, type PressInfo } from "../src/lib/verdictKeys";

const press = (key: string, more: Partial<PressInfo> = {}): PressInfo => ({ key, ctrlKey: false, metaKey: false, altKey: false, shiftKey: false, target: document.body, ...more });
/** An element made from "tag" or "tag key=value ..." (no markup from strings). */
const field = (spec: string): Element => {
  const [tag = "div", ...attrs] = spec.split(" ");
  const made = document.createElement(tag);
  for (const a of attrs) {
    const [key = "", value = ""] = a.split("=");
    made.setAttribute(key, value);
  }
  made.append("x");
  return made;
};

describe("the keys", () => {
  it("C confirms, N goes on, 1 to 5 choose the five outcomes in order", () => {
    expect(verdictAct(press("c"), true)).toEqual({ kind: "confirm" });
    expect(verdictAct(press("n"), true)).toEqual({ kind: "next" });
    for (const [i, outcome] of KEYED_OUTCOMES.entries()) expect(verdictAct(press(String(i + 1)), true)).toEqual({ kind: "outcome", outcome });
  });

  it("leave every other key alone", () => {
    for (const key of ["0", "6", "9", "a", "j", "k", "Enter", "Escape", "ArrowDown", " ", "Tab", "cc", "10"]) expect(verdictAct(press(key), true)).toBeNull();
  });

  it("are off when the person switched them off", () => {
    for (const key of ["c", "n", "1", "5", "?"]) expect(verdictAct(press(key), false)).toBeNull();
  });

  it("? asks for the list of keys (D-184), from the page, not from a field", () => {
    expect(verdictAct(press("?", { shiftKey: true }), true)).toEqual({ kind: "help" }); // the shift that types it
    expect(verdictAct(press("?"), true)).toEqual({ kind: "help" });
    expect(verdictAct(press("?", { target: field("textarea") }), true)).toBeNull();
    expect(verdictAct(press("?"), true, true)).toBeNull(); // not under a dialog
    expect(verdictAct(press("?", { ctrlKey: true }), true)).toBeNull();
    expect(verdictAct(press("?"), true, false, false)).toEqual({ kind: "help" }); // an account that cannot review may read the list
  });

  it("only the plain lower-case letter counts: Shift+C and Shift+N, or Caps Lock, do nothing (AR4 review)", () => {
    for (const key of ["C", "N"]) {
      expect(verdictAct(press(key, { shiftKey: true }), true), `${key} with Shift`).toBeNull();
      expect(verdictAct(press(key), true), `${key} from Caps Lock`).toBeNull();
    }
    expect(verdictAct(press("c", { shiftKey: true }), true)).toBeNull(); // Shift held, a letter that did not change
    expect(verdictAct(press("n", { shiftKey: true }), true)).toBeNull();
  });

  it("do nothing for an account that cannot review, but N and ? still work for it", () => {
    for (const key of ["c", "1", "2", "3", "4", "5"]) expect(verdictAct(press(key), true, false, false), key).toBeNull();
    expect(verdictAct(press("n"), true, false, false)).toEqual({ kind: "next" });
    expect(verdictAct(press("?"), true, false, false)).toEqual({ kind: "help" });
    expect(verdictAct(press("c"), true, false, true)).toEqual({ kind: "confirm" });
  });

  it("are not ours with Ctrl, Meta or Alt held (a browser's own: Ctrl+C copies), and a shifted digit is a symbol", () => {
    for (const mod of ["ctrlKey", "metaKey", "altKey"] as const) expect(verdictAct(press("c", { [mod]: true }), true)).toBeNull();
    expect(verdictAct(press("1", { shiftKey: true }), true)).toBeNull(); // "!" on many keyboards
  });

  it("never fire while a person is typing", () => {
    const places = ["input type=text", "input", "input type=search", "textarea", "select", "div contenteditable=true", "div role=textbox", "div role=combobox", "div role=searchbox", "span contenteditable=plaintext-only"];
    for (const html of places) {
      const target = field(html);
      document.body.append(target);
      for (const key of ["c", "n", "1", "4"]) expect(verdictAct(press(key, { target }), true), `${html} ${key}`).toBeNull();
      expect(isTyping(target), html).toBe(true);
      target.remove();
    }
  });

  it("do fire from a button, a link or the page itself", () => {
    for (const html of ["button", "a href=#x", "div tabindex=0", "div contenteditable=false", "input type=checkbox", "input type=radio", "input type=submit", "input type=range"]) {
      const target = field(html);
      expect(isTyping(target)).toBe(false);
      expect(verdictAct(press("c", { target }), true)).toEqual({ kind: "confirm" });
    }
    expect(isTyping(null)).toBe(false);
    expect(isTyping(window)).toBe(false);
  });

  it("stay quiet while a dialog is open and while an input method is composing", () => {
    expect(verdictAct(press("c"), true, true)).toBeNull();
    expect(verdictAct(press("c", { isComposing: true }), true)).toBeNull();
    expect(dialogOpen()).toBe(false);
    const dialog = document.createElement("div");
    dialog.setAttribute("role", "alertdialog");
    document.body.append(dialog);
    expect(dialogOpen()).toBe(true);
    dialog.remove();
    const other = document.createElement("div");
    other.setAttribute("role", "dialog");
    document.body.append(other);
    expect(dialogOpen()).toBe(true);
    other.remove();
  });

  it("answer to nothing but those eight keys, whatever key is pressed, and never to a capital", () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 12 }), fc.boolean(), fc.boolean(), fc.boolean(), (key, shift, on, review) => {
        const act = verdictAct(press(key, { shiftKey: shift }), on, false, review);
        if (act !== null) {
          expect(on).toBe(true);
          expect(["c", "n", "1", "2", "3", "4", "5", "?"]).toContain(key);
          if (key !== "?") expect(shift).toBe(false);
          if (["c", "1", "2", "3", "4", "5"].includes(key)) expect(review).toBe(true);
        }
      }),
    );
  });
});
