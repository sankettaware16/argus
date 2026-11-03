/**
 * The keys of the investigation page (AR4, D-182): C confirms ARGUS's recommendation, 1 to 5
 * choose an outcome, N goes to the next item of the queue. Single-character shortcuts (WCAG
 * 2.1.4): the person can switch them off with the same box as the Inbox's, and they never fire
 * while a person is typing in a field, while a dialog is open, or with a modifier key held.
 * Pure apart from the document it is handed (tests/verdictKeys.test.ts).
 */
import { KEYED_OUTCOMES } from "./verdict";

export type VerdictAct = { kind: "confirm" } | { kind: "outcome"; outcome: string } | { kind: "next" } | { kind: "help" };

export interface PressInfo {
  key: string;
  ctrlKey: boolean;
  metaKey: boolean;
  altKey: boolean;
  shiftKey: boolean;
  isComposing?: boolean;
  target: EventTarget | null;
}

const NO_TEXT = new Set(["checkbox", "radio", "button", "submit", "reset", "image", "file", "range", "color"]);

/** Whether the event came from a place a person types in: a field, a select, an editable element. */
export function isTyping(target: EventTarget | null): boolean {
  if (typeof Element === "undefined" || !(target instanceof Element)) return false;
  const tag = target.tagName;
  if (tag === "TEXTAREA" || tag === "SELECT") return true;
  // a box, a radio or a button takes no text: the focus left on one (the shortcuts' own box) must not stop the keys
  if (tag === "INPUT") return !NO_TEXT.has((target as HTMLInputElement).type);
  if ((target as HTMLElement).isContentEditable || target.closest('[contenteditable]:not([contenteditable="false"])') !== null) return true;
  const role = target.getAttribute("role");
  return role === "textbox" || role === "combobox" || role === "searchbox" || role === "spinbutton";
}

/** Whether a dialog is open: the keys belong to it. */
export function dialogOpen(doc: Pick<Document, "querySelector"> = document): boolean {
  return doc.querySelector('[role="alertdialog"], [role="dialog"]') !== null;
}

/**
 * The act a key press asks for, or null (not ours, switched off, typing, or a dialog is open).
 * Only the plain lower-case letter counts (AR4 review, D-186): Shift+C and Shift+N are not C and
 * N, and with Caps Lock on the key arrives as "C", which a person did not mean as a shortcut
 * (Caps Lock is often on by accident, and C confirms). `canReview`: an account that cannot review
 * has no use for C and 1 to 5, and they do nothing; N and ? still work.
 */
export function verdictAct(e: PressInfo, shortcuts: boolean, dialog: boolean = false, canReview: boolean = true): VerdictAct | null {
  if (!shortcuts || dialog || e.isComposing) return null;
  if (e.ctrlKey || e.metaKey || e.altKey) return null;
  if (isTyping(e.target)) return null;
  const key = e.key;
  if (key === "?") return { kind: "help" };
  if (key.length === 1 && key !== key.toLowerCase()) return null; // a capital: Shift, or Caps Lock
  if (e.shiftKey) return null;
  if (key === "n") return { kind: "next" };
  if (!canReview) return null;
  if (key === "c") return { kind: "confirm" };
  if (/^[1-5]$/.test(key)) {
    const outcome = KEYED_OUTCOMES[Number(key) - 1];
    return outcome === undefined ? null : { kind: "outcome", outcome };
  }
  return null;
}
