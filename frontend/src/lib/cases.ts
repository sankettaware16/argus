/**
 * The words and addresses of the case pages (Q-B3, plan §7.1): a case's states, the reasons a
 * closure is asked for, what a request's standing is called, and what the case list's address
 * says. Pure (tests/cases.test.ts). A value this version does not know is said so, never shown raw.
 */
import { first } from "./search";
import type { Tone } from "../components/ui/badge";

export const CASE_VIEWS = ["active", "queue", "notified", "attention", "mine", "suspected", "closed", "all"] as const;
export type CaseViewName = (typeof CASE_VIEWS)[number];

export const CASE_VIEW_TITLES: Readonly<Record<CaseViewName, string>> = {
  queue: "Needs a person",
  active: "Open cases",
  notified: "Notified, still active",
  attention: "Needs attention",
  mine: "Mine",
  suspected: "Suspected",
  closed: "Closed",
  all: "All",
};

export const CASE_VIEW_HINTS: Readonly<Record<CaseViewName, string>> = {
  queue: "The cases of Home's queue: suggested, changed since the owner was told, flagged, nobody's, or holding new work",
  active: "Confirmed cases that are open, assigned or contained, apart from the notified ones",
  notified: "Cases whose owner was told: tracked quietly, back in the queue only when something changes",
  attention: "Cases ARGUS wants a person to look at, or that wait for an approval",
  mine: "Cases you own",
  suspected: "Cases ARGUS suspects from its own proposals; a person's true-positive verdict confirms one",
  closed: "Cases that were closed",
  all: "Every case",
};

export const CASE_STATE_WORDS: Readonly<Record<string, string>> = {
  suspected: "Suspected",
  open: "Open",
  assigned: "Assigned",
  contained: "Contained",
  closed: "Closed",
};

export const CASE_STATE_TONE: Readonly<Record<string, Tone>> = {
  suspected: "neutral",
  open: "warn",
  assigned: "info",
  contained: "ok",
  closed: "neutral",
};

/** What each state means, in a sentence (the case page's summary). */
export const CASE_STATE_MEANING: Readonly<Record<string, string>> = {
  suspected: "ARGUS suspects it; nobody has confirmed it, and Kibana has nothing.",
  open: "A person confirmed it and nobody owns it yet.",
  assigned: "A person owns it.",
  contained: "A person confirmed it is contained, with 72 quiet hours behind it.",
  closed: "It was closed.",
};

export const REASON_LABELS: Readonly<Record<string, string>> = {
  remediated_verified: "Fixed, and shown quiet",
  remediated_unverified: "Fixed, as its owner says",
  risk_accepted: "Left as it is, by decision",
  attempt_no_impact: "An attempt that did not work",
  rule_false_positive: "The rule was wrong",
  benign_expected: "Benign: expected activity",
  benign_policy: "Benign: allowed by policy",
  duplicate: "A duplicate",
  created_in_error: "Opened by mistake",
  stopped_after_notice: "Stopped after the owner was told",
};

export function caseStateWord(state: string): string {
  return CASE_STATE_WORDS[state] ?? "A state this page does not know";
}

export function reasonLabel(reason: string | null | undefined): string {
  if (reason == null) return "No reason";
  return REASON_LABELS[reason] ?? "A reason this page does not know";
}

export const APPROVAL_STATUS_WORDS: Readonly<Record<string, string>> = {
  pending: "Waiting",
  approved: "Approved",
  rejected: "Rejected",
  expired: "Expired",
  stale: "Out of date",
};

export const APPROVAL_STATUS_TONE: Readonly<Record<string, Tone>> = {
  pending: "warn",
  approved: "ok",
  rejected: "danger",
  expired: "neutral",
  stale: "neutral",
};

export interface CasesSearch {
  view: CaseViewName;
  /** a word of the title, or a case number */
  q?: string;
}

/** What the list's address says; anything invalid is left out, never an error. */
export function parseCases(raw: Record<string, unknown>): CasesSearch {
  const view = first(raw.view);
  const q = first(raw.q)?.trim();
  const out: CasesSearch = { view: CASE_VIEWS.find((known) => known === view) ?? "active" };
  if (q !== undefined && q !== "" && q.length <= 120 && !q.includes("\u0000")) out.q = q;
  return out;
}

/** The API's query for a search: a number alone finds that case; anything else is a word of the title. */
export function casesQuery(s: CasesSearch): { view: CaseViewName; number?: number; q?: string } {
  if (s.q === undefined) return { view: s.view };
  if (/^#?\d{1,9}$/.test(s.q)) {
    const number = Number(s.q.replace("#", ""));
    if (number >= 1) return { view: "all", number };
  }
  return { view: s.view, q: s.q };
}

/** A case's own address inside the app. */
export function casePath(id: string): string {
  return `/cases/${id}`;
}

/** The words for a request in the approvals queue by the kind of write it asks for. */
export const APPROVAL_KIND_HINTS: Readonly<Record<string, string>> = {
  closure: "Closing the case",
  merge: "Merging the case into another",
  compensating: "Undoing a change ARGUS made in Kibana",
  resend: "Sending a Kibana change again, after its first try left no answer",
  reconfirm: "Confirming a closure again, because something changed before it was sent",
};

/** One planned Kibana write in a line: its class and operation, and what it sets. Pure; the line is
 * ARGUS's own words around the payload's values, which are shown as untrusted text. */
export function describeWrite(write: unknown): string {
  if (write === null || typeof write !== "object") return "A write this page cannot read";
  const w = write as { class?: unknown; op?: unknown; payload?: unknown };
  const head = `${typeof w.class === "string" ? w.class : "?"} ${typeof w.op === "string" ? w.op : "?"}`;
  const p = w.payload !== null && typeof w.payload === "object" ? (w.payload as Record<string, unknown>) : {};
  const parts: string[] = [];
  if (typeof p.status === "string") parts.push(`status ${p.status}`);
  if (typeof p.severity === "string") parts.push(`severity ${p.severity}`);
  if (Array.isArray(p.argus_tags)) parts.push(`ARGUS tags ${p.argus_tags.filter((t): t is string => typeof t === "string").join(", ")}`);
  if (typeof p.template === "string") parts.push(`the comment “${p.template}”`);
  if (typeof p.title === "string") parts.push(`title ${p.title}`);
  return parts.length > 0 ? `${head}: ${parts.join("; ")}` : head;
}
