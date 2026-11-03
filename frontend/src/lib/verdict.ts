/**
 * The words of the verdict-first page (AR4, D-182): ARGUS's recommendation or reading as one line,
 * the three to five facts behind it, the size of its pattern, and the keys of the outcomes.
 * Pure (tests/verdict.test.ts). Texts that came from logs or models are not made here: the pages
 * show them only through UntrustedText.
 */
import type { InvestigationOut, KnownRefOut, Report, StanceOut } from "../client/types.gen";
import { count, plural } from "./format";
import { OUTCOME_KEYS, outcomeLabel } from "./labels";

/** The outcome each of the keys 1 to 5 chooses, in the order the pages list them. */
export const KEYED_OUTCOMES: readonly string[] = OUTCOME_KEYS;

export function surePart(confidence: number | null | undefined): string {
  return confidence === null || confidence === undefined ? "" : ` (${Math.round(confidence * 100)}%)`;
}

/** What ARGUS thinks, as the top card's first line. */
export function stanceHeadline(s: StanceOut): string {
  if (s.kind === "recommends") return `ARGUS recommends: ${outcomeLabel(s.outcome)}${surePart(s.confidence)}`;
  if (s.kind === "reading") {
    const because = s.why ? `, not proposed because ${s.why}` : ", not proposed";
    return `ARGUS's reading: ${outcomeLabel(s.outcome)}${surePart(s.confidence)}${because}`;
  }
  return "ARGUS has no reading of this yet";
}

/** Where the recommendation comes from, in a sentence under the headline. */
export function stanceSource(s: StanceOut): string | null {
  if (s.kind === "none" || !s.source) return null;
  const who = s.source.charAt(0).toUpperCase() + s.source.slice(1);
  if (s.from_investigation_id) return `${who} read another investigation of the same pattern; it is not a proposal for this one on its own.`;
  return s.kind === "recommends" ? `From ${s.source}. A proposal, not a decision.` : `From ${s.source}. A reading is not a proposal: nothing is closed from it.`;
}

/** "14 investigations, 230 alerts" for the run's pattern, or null when it is not known or is this alone. */
export function patternSize(s: StanceOut): string | null {
  const n = s.pattern_investigations;
  if (n === null || n === undefined) return null;
  const alerts = s.pattern_alerts ?? 0;
  if (n <= 1) return "This pattern: only this investigation so far";
  return `This pattern: ${count(n)} ${plural(n, "investigation")}, ${count(alerts)} ${plural(alerts, "alert")}`;
}

export interface KeyFact {
  text: string;
  /** the first E-number behind it: its rows are in the report's sources, else in the alerts */
  eid: string | null;
}

export const MIN_FACTS = 3;
export const MAX_FACTS = 5;

/**
 * Three to five facts in ARGUS's own words, in the order a person wants them: what the extra SIEM
 * queries found that the alerts alone did not say, then the known facts that bear on the verdict,
 * then the dossier's key facts. A sentence once. Fewer when ARGUS has fewer.
 */
export function keyFacts(report: Report | undefined, dossierFacts: readonly string[] | undefined): KeyFact[] {
  const out: KeyFact[] = [];
  const seen = new Set<string>();
  const add = (text: string | undefined, eids: readonly string[] | undefined) => {
    const t = (text ?? "").trim();
    if (t === "" || seen.has(t) || out.length >= MAX_FACTS) return;
    seen.add(t);
    out.push({ text: t, eid: eids?.[0] ?? null });
  };
  for (const item of report?.found.items ?? []) if (item.kind === "new") add(item.sentence, item.eids);
  for (const row of report?.evidence ?? []) if (row.stance !== "neutral" && row.fact.status === "known") add(row.fact.sentence, row.fact.eids);
  for (const line of dossierFacts ?? []) add(line, undefined);
  return out;
}

/** A fact's raw rows: the report's sources for an E-number, else the alerts. */
export function factLink(fact: KeyFact): { tab: "report" | "alerts"; hash: string | undefined } {
  return fact.eid === null ? { tab: "alerts", hash: undefined } : { tab: "report", hash: `eid-${fact.eid}` };
}

/** AR4b on an investigation: the sentence for a known or changed one. */
export function knownSentence(k: KnownRefOut): string {
  if (k.outcome === "changed") return `Changed since the owner was told${k.why ? `: ${k.why}` : ""}`;
  return k.notified_at ? "Known: the owner of this device was told; ARGUS counts these alerts and does not raise them" : "Known: part of a case that is no longer notified; ARGUS decided before that this belongs to it";
}

/** Whether a person still has this one to review (the card offers Confirm and Change only then). */
export function needsReview(inv: Pick<InvestigationOut, "human_state">): boolean {
  return inv.human_state !== "reviewed";
}
