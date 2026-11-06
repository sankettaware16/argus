/**
 * The words the pages use for ARGUS's states and outcomes. The outcomes are a person's decision in
 * plain words (P4-F U7), "Real" first, over the review model's own values (unchanged): a true
 * positive is "Real: act on it", an expected benign "Real but harmless", a rule false positive
 * "Wrong alert", an inconclusive "Can't tell yet". The keys 1 to 5 follow this order.
 */

export const OUTCOMES: Readonly<Record<string, string>> = {
  true_positive: "Real: act on it",
  benign_expected: "Real but harmless",
  benign_policy: "Allowed by policy",
  rule_false_positive: "Wrong alert",
  inconclusive: "Can't tell yet",
};
export const OUTCOME_KEYS = Object.keys(OUTCOMES);

/** What each outcome means, in a line (the decision bar's hints). */
export const OUTCOME_HINTS: Readonly<Record<string, string>> = {
  true_positive: "An attack or a compromise that needs action. It may open an incident or join one.",
  benign_expected: "It happened, and it is harmless: an attempt that failed, or activity that is expected.",
  benign_policy: "It happened, and the policy allows it.",
  rule_false_positive: "The rule fired on something it should not have.",
  inconclusive: "There is not enough to decide yet. Keep it for a follow-up, or close it as undecided.",
};

export const STATE_TITLES: Readonly<Record<string, string>> = {
  unreviewed: "Not reviewed",
  follow_up: "Follow-up",
  changed_since_review: "Changed since review",
  reviewed: "Reviewed",
};

export const AI_TITLES: Readonly<Record<string, string>> = {
  proposed_tp: "Calls it real",
  proposed_other: "Calls it not an attack",
  no_proposal: "No proposal",
  working: "Working on it",
  none: "Not assessed",
};

export const VERDICT_TITLES: Readonly<Record<string, string>> = { ...OUTCOMES, none: "No decision yet" };

export const VIEW_TITLES: Readonly<Record<string, string>> = {
  attention: "Needs attention",
  open: "Not reviewed yet",
  reviewed: "Reviewed",
  all: "All",
  known: "Notified, still active",
};

export const SORT_TITLES: Readonly<Record<string, string>> = {
  newest: "newest first",
  oldest: "oldest first",
  urgent: "most urgent first",
  queue: "queue order (what needs a person first)",
  reviewed: "newest decision first",
};

export const RANGE_TITLES: Readonly<Record<string, string>> = {
  "24h": "Last 24 hours",
  "7d": "Last 7 days",
  "30d": "Last 30 days",
  "90d": "Last 90 days",
};

export const SEVERITIES = ["critical", "high", "medium", "low"] as const;
export const KIND_TITLES: Readonly<Record<string, string>> = { ip: "IP address", host: "Host", domain: "Domain", user: "User" };

/** An outcome in words; a value this version does not know is said so, never shown raw. */
export function outcomeLabel(outcome: string | null | undefined): string {
  if (outcome == null) return "No outcome";
  return OUTCOMES[outcome] ?? "An outcome this page does not know";
}

export function stateLabel(state: string): string {
  return STATE_TITLES[state] ?? state.replaceAll("_", " ");
}
