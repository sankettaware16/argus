import type { AiVerdictOut } from "../client/types.gen";
import { outcomeLabel, stateLabel } from "../lib/labels";
import { Badge, type Tone } from "./ui/badge";

const STATE_TONE: Record<string, Tone> = { unreviewed: "neutral", follow_up: "warn", changed_since_review: "warn", reviewed: "ok" };

export function StateChip({ state }: { state: string }) {
  return <Badge tone={STATE_TONE[state] ?? "neutral"}>{stateLabel(state)}</Badge>;
}

const OUTCOME_TONE: Record<string, Tone> = {
  true_positive: "critical",
  benign_expected: "ok",
  benign_policy: "ok",
  rule_false_positive: "low",
  inconclusive: "neutral",
};

export function OutcomeChip({ outcome, children }: { outcome: string | null | undefined; children?: string }) {
  return <Badge tone={OUTCOME_TONE[outcome ?? ""] ?? "neutral"}>{children ?? outcomeLabel(outcome)}</Badge>;
}

/** What ARGUS's newest assessment says, in a few words (the list's AI column). */
export function AiChip({ ai }: { ai: AiVerdictOut | null | undefined }) {
  if (!ai) return <span className="text-xs text-muted">not assessed</span>;
  if (ai.status === "proposed") {
    const sure = ai.confidence === null || ai.confidence === undefined ? "" : ` ${Math.round(ai.confidence * 100)}%`;
    return <OutcomeChip outcome={ai.outcome}>{`AI: ${outcomeLabel(ai.outcome)}${sure}`}</OutcomeChip>;
  }
  if (ai.status === "no_decision") return <span className="text-xs text-muted">AI: no proposal</span>;
  if (ai.status === "queued" || ai.status === "running") return <span className="text-xs text-muted">AI: working</span>;
  return <span className="text-xs text-muted">AI: failed</span>;
}
