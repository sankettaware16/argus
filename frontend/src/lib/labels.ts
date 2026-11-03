/** The words the pages use for ARGUS's states and outcomes: the classic pages' words (DQ23). */

export const OUTCOMES: Readonly<Record<string, string>> = {
  benign_expected: "Benign: expected activity",
  benign_policy: "Benign: allowed by policy",
  rule_false_positive: "Rule false positive",
  true_positive: "True positive",
  inconclusive: "Inconclusive",
};
export const OUTCOME_KEYS = Object.keys(OUTCOMES);

export const STATE_TITLES: Readonly<Record<string, string>> = {
  unreviewed: "Not reviewed",
  follow_up: "Follow-up",
  changed_since_review: "Changed since review",
  reviewed: "Reviewed",
};

export const AI_TITLES: Readonly<Record<string, string>> = {
  proposed_tp: "Proposes true positive",
  proposed_other: "Proposes benign",
  no_proposal: "No proposal",
  working: "Working on it",
  none: "Not assessed",
};

export const VERDICT_TITLES: Readonly<Record<string, string>> = { ...OUTCOMES, none: "No verdict yet" };

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
