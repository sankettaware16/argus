/**
 * The incident report's small rules, pure (AR7, D-190): what a rejection needs before it can be
 * asked for, the bodies a decision sends, the only links the page follows, and the words for a
 * hypothesis's result and a confidence. The server states the same limits and has the last word.
 */
import type { ReportHypothesis } from "../client/types.gen";
import type { Tone } from "../components/ui/badge";

export const REASON_MIN = 3;
export const REASON_MAX = 4000;

/** What is wrong with a rejection's reason now, in plain words, or null when it can be asked for. */
export function reasonProblem(reason: string): string | null {
  const said = reason.trim();
  if (said.length === 0) return "Say why the report is wrong: the reason is what ARGUS learns from.";
  if (said.length < REASON_MIN) return "Say why in a few more words.";
  if (reason.length > REASON_MAX) return `The reason is at most ${REASON_MAX} characters.`;
  // eslint-disable-next-line no-control-regex
  if (/\u0000/.test(reason)) return "The reason holds a character that cannot be saved.";
  return null;
}

/** What a rejection is missing, or null. The outcome is the one the person holds instead. */
export function rejectProblem(outcome: string, reason: string): string | null {
  if (outcome === "") return "Choose the outcome you hold instead.";
  return reasonProblem(reason);
}

export function confirmBody(version: number): { expected_version: number } {
  return { expected_version: version };
}

export function rejectBody(version: number, outcome: string, reason: string) {
  return { expected_version: version, outcome, reason: reason.trim() };
}

/** A link the report may follow: an http(s) address from the server's own configuration; anything else is not a link. */
export function safeLink(url: string): string | null {
  try {
    const parsed = new URL(url);
    return parsed.protocol === "https:" || parsed.protocol === "http:" ? parsed.toString() : null;
  } catch {
    return null;
  }
}

export const HYPOTHESIS_WORDS: Readonly<Record<ReportHypothesis["status"], string>> = {
  kept: "Kept",
  ruled_out: "Ruled out",
  open: "Open",
};

export const HYPOTHESIS_TONE: Readonly<Record<ReportHypothesis["status"], Tone>> = {
  kept: "high",
  ruled_out: "ok",
  open: "neutral",
};

export const STANDING_TONE: Readonly<Record<"ongoing" | "quiet" | "unknown", Tone>> = {
  ongoing: "warn",
  quiet: "ok",
  unknown: "neutral",
};

export const STANDING_TITLE: Readonly<Record<"ongoing" | "quiet" | "unknown", string>> = {
  ongoing: "Still going on",
  quiet: "Quiet",
  unknown: "Not known",
};

export const FILE_KINDS: Readonly<Record<string, string>> = {
  pdf: "PDF",
  indicators_csv: "CSV",
  affected_csv: "CSV",
  accounts_csv: "CSV",
};

/** "Thu 15 Oct" for an IST day the report gives as 2026-10-15. */
export function dayLabel(day: string): string {
  const at = new Date(`${day}T12:00:00Z`);
  if (Number.isNaN(at.getTime())) return day;
  return at.toLocaleDateString("en-GB", { weekday: "short", day: "2-digit", month: "short", timeZone: "UTC" });
}

/** "80% (medium-high)" or null when ARGUS gives none. */
export function confidenceText(value: number | null | undefined, words: string | null | undefined): string | null {
  if (value === null || value === undefined) return null;
  return `${Math.round(value * 100)}%${words ? ` (${words})` : ""}`;
}
