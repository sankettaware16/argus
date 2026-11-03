/**
 * report@2 as people read it (Q-F2's contract, plan §7.3): the words for each line of "What ARGUS
 * found with extra SIEM queries", the verdict and evidence strength sentences, and where a fact
 * came from. Pure (tests/report.test.ts). Texts that came from logs or models are not made here:
 * pages show them only through UntrustedText.
 */
import type { Cost, Fact, Item, Strength, Verdict } from "../client/types.gen";
import { count, plural, serverTime } from "./format";
import { outcomeLabel } from "./labels";

export type LineKind = Item["kind"];

export const LINE_LABEL: Record<LineKind, string> = {
  new: "New",
  nothing_found: "Nothing found",
  could_not_tell: "Could not tell",
  failed: "Failed",
  not_checked: "Not checked",
  still_open: "Still open",
  hidden: "Hidden",
};

export type LineTone = "info" | "ok" | "warn" | "danger" | "neutral";
export const LINE_TONE: Record<LineKind, LineTone> = {
  new: "info",
  nothing_found: "ok",
  could_not_tell: "warn",
  failed: "danger",
  not_checked: "neutral",
  still_open: "warn",
  hidden: "neutral",
};

/** "3 checks, 2.1 s of SIEM server time" */
export function foundHeading(checks: number, serverMs: number): string {
  return `${count(checks)} ${plural(checks, "check")}, ${serverTime(serverMs)} of SIEM server time`;
}

/** "E3, E4" (the evidence requests behind a line). */
export function eidText(eids: readonly string[] | undefined): string {
  return (eids ?? []).join(", ");
}

const STATUS_PHRASE: Record<string, string> = {
  no_decision: "made no proposal",
  queued: "has not assessed it yet",
  running: "is assessing it now",
  failed: "could not finish",
};

function capital(text: string): string {
  return text.charAt(0).toUpperCase() + text.slice(1);
}

/** "The AI investigator proposes True positive", "The decision engine made no proposal". */
export function verdictSentence(v: Verdict): string {
  const who = capital(v.source);
  if (v.status === "none") return "Nobody has assessed this investigation yet";
  if (v.status === "proposed") return `${who} proposes ${outcomeLabel(v.outcome)}`;
  return `${who} ${STATUS_PHRASE[v.status] ?? v.status.replaceAll("_", " ")}`;
}

export function confidenceText(v: Verdict): string | null {
  return v.model_confidence === null || v.model_confidence === undefined ? null : `the model's confidence ${Math.round(v.model_confidence * 100)}%`;
}

export const GRADE_LABEL = { strong: "Strong", moderate: "Moderate", weak: "Weak" } as const;

/** What the evidence strength counts, in order (numbers by code, apart from any confidence). */
export function strengthCounts(s: Strength): { label: string; known: number; of: number }[] {
  return [
    { label: "Facts that decide a benign proposal", known: s.floor_known, of: s.floor_total },
    { label: "SIEM checks that completed", known: s.checks_complete, of: s.checks_total },
    { label: "Investigation steps answered", known: s.steps_answered, of: s.steps_total },
    { label: "Alerts read", known: s.alerts_read, of: s.alerts_total },
  ];
}

export const STANCE_LABEL = { supports: "Supports", contradicts: "Contradicts", neutral: "Neutral" } as const;

/** Where a fact came from: its E-numbers and the store of ARGUS's it comes from, else the alerts. */
export function factSource(fact: Pick<Fact, "eids" | "source">): string {
  const parts = [eidText(fact.eids), fact.source ?? ""].filter((p) => p !== "");
  return parts.length > 0 ? parts.join(", ") : "the alerts";
}

/** "2 SIEM requests, 1,420 ms of server time, 3 answers reused from an earlier version; 4 model calls, $0.0123" */
export function costSentence(c: Cost): string {
  const base = `${count(c.siem_requests)} SIEM ${plural(c.siem_requests, "request")}, ${count(c.siem_server_ms)} ms of server time, ${count(c.reused)} ${plural(c.reused, "answer")} reused from an earlier version`;
  const calls = c.model_calls ?? 0;
  return calls > 0 ? `${base}; ${count(calls)} model ${plural(calls, "call")}, $${(c.model_cost_usd ?? 0).toFixed(4)}` : base;
}

/** The tab label of one assessor's report. */
export function reportTab(source: string): string {
  return capital(source);
}
