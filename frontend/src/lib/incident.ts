/**
 * The incident report's small rules, pure (AR7, D-190): what a rejection needs before it can be
 * asked for, the bodies a decision sends, the only links the page follows, and the words for a
 * hypothesis's result and a confidence. The server states the same limits and has the last word.
 */
import type { CaseDetail, HistoryItemOut, IncidentReport, ReportHypothesis, ReportVerdict } from "../client/types.gen";
import type { Tone } from "../components/ui/badge";
import { caseStateWord } from "./cases";
import { certaintyWords, shownCertainty, type Alternative, type Engine } from "./engine";
import { OUTCOMES } from "./labels";
import { plainWords } from "./plainWords";

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

/**
 * The report's header line (P4-F U3): the case's state and ARGUS's call, apart. A possible
 * incident is never called "a true positive" here, whatever ARGUS's call; the case's title is the
 * page's own heading.
 */
export function reportHeadline(state: string, outcome: string | null | undefined, confidence: string | null): string {
  const call = outcome ? `${OUTCOMES[outcome] ?? "a call this page does not know"}${confidence ? ` (${confidence})` : ""}` : "no call yet";
  return `${caseStateWord(state)} · ARGUS's call: ${call}`;
}

// ------------------------------------------------------------------ a case without the engine (§2.4)

const HYPOTHESIS_STATE: Readonly<Record<ReportHypothesis["status"], Alternative["state"]>> = { kept: "fits", ruled_out: "ruled_out", open: "unknown" };
const THREAT_READING = /^A real threat\b/i; // the report's own first hypothesis: what confirming says

/** The report's hypotheses as other explanations: kept still fits, open is not tested (the Overview's list). */
export function reportAlternatives(report: Pick<IncidentReport, "hypotheses"> | null): Alternative[] {
  return (report?.hypotheses ?? []).map((h) => ({ name: plainWords(h.name), state: HYPOTHESIS_STATE[h.status], test: plainWords(h.why.map((w) => w.text).join(" ")) }));
}

/**
 * What argues against confirming, from the report (§5.4, F15): every hypothesis but the threat
 * reading itself, with no check (the report's reasons are not a check that would decide).
 */
export function againstConfirming(report: Pick<IncidentReport, "hypotheses"> | null): Alternative[] {
  return (report?.hypotheses ?? []).filter((h) => !(h.by === "argus" && THREAT_READING.test(h.name))).map((h) => ({ name: plainWords(h.name), state: HYPOTHESIS_STATE[h.status], test: "" }));
}

/**
 * Who confirmed the case, from its history (newest first): the person a true-positive verdict
 * names, else the person who confirmed or opened it; null when the history kept does not say.
 */
export function confirmedBy(history: readonly Pick<HistoryItemOut, "kind" | "text" | "by">[]): string | null {
  for (const h of history) {
    if (h.kind !== "event") continue;
    const verdict = /^A true-positive verdict by (.+) confirmed the case$/.exec(h.text);
    const name = verdict ? (verdict[1] ?? null) : / (confirmed|opened) the case( with .*)?$/.test(h.text) ? h.by : null;
    if (name !== null && name.trim() !== "" && !/^ARGUS\b/.test(name)) return name;
  }
  return null;
}

/** "ARGUS's call: Real: act on it" from the report's verdict (no confidence: it is not a priority), or null. */
export function reportCall(verdict: Pick<ReportVerdict, "outcome"> | null | undefined): string | null {
  const outcome = verdict?.outcome;
  return outcome ? `ARGUS's call: ${OUTCOMES[outcome] ?? "a call this page does not know"}` : null;
}

/**
 * The call in words (§7.1, F5), apart from the band: "Confirmed by <person>" once a person
 * confirmed it (never "ARGUS: confirmed"); the engine's certainty; for a case without the engine,
 * the report's call; "ARGUS: no call yet" when there is none.
 */
export function callWords(d: Pick<CaseDetail, "case" | "history">, engine: Engine | null, verdict: Pick<ReportVerdict, "outcome"> | null | undefined): string {
  const shown = shownCertainty(d.case.state, d.case.closure_reason, engine);
  if (shown === "Confirmed") return `Confirmed by ${confirmedBy(d.history) ?? "a person"}`;
  if (engine !== null) return `ARGUS: ${certaintyWords(shown ?? engine.certainty, null)}`;
  return reportCall(verdict) ?? "ARGUS: no call yet";
}

/** The decision bar's call (§7.1, F5): the call and the band, never the 0–100 number; "not prioritised yet" without the engine. */
export function callText(d: Pick<CaseDetail, "case" | "history">, engine: Engine | null, verdict: Pick<ReportVerdict, "outcome"> | null | undefined): string {
  return `${callWords(d, engine, verdict)} · ${engine ? `Priority ${engine.band}` : "not prioritised yet"}`;
}
