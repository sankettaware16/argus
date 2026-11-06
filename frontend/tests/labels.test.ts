// The words the pages use (lib/labels.ts): a change is a decision. The outcomes are a person's
// decision in plain words (P4-F U7), "Real" first, over the review model's own values.
import { describe, expect, it } from "vitest";
import { AI_TITLES, KIND_TITLES, OUTCOME_KEYS, OUTCOMES, outcomeLabel, RANGE_TITLES, SEVERITIES, SORT_TITLES, STATE_TITLES, stateLabel, VERDICT_TITLES, VIEW_TITLES } from "../src/lib/labels";

describe("the tables of words", () => {
  it("name every outcome, state, assessment, view, sort and span", () => {
    expect(OUTCOMES).toEqual({
      true_positive: "Real: act on it",
      benign_expected: "Real but harmless",
      benign_policy: "Allowed by policy",
      rule_false_positive: "Wrong alert",
      inconclusive: "Can't tell yet",
    });
    expect(OUTCOME_KEYS).toEqual(["true_positive", "benign_expected", "benign_policy", "rule_false_positive", "inconclusive"]);
    expect(STATE_TITLES).toEqual({ unreviewed: "Not reviewed", follow_up: "Follow-up", changed_since_review: "Changed since review", reviewed: "Reviewed" });
    expect(AI_TITLES).toEqual({ proposed_tp: "Calls it real", proposed_other: "Calls it not an attack", no_proposal: "No proposal", working: "Working on it", none: "Not assessed" });
    expect(VERDICT_TITLES).toEqual({ ...OUTCOMES, none: "No decision yet" });
    expect(VIEW_TITLES).toEqual({ attention: "Needs attention", open: "Not reviewed yet", reviewed: "Reviewed", all: "All", known: "Notified, still active" });
    expect(SORT_TITLES).toEqual({ newest: "newest first", oldest: "oldest first", urgent: "most urgent first", queue: "queue order (what needs a person first)", reviewed: "newest decision first" });
    expect(RANGE_TITLES).toEqual({ "24h": "Last 24 hours", "7d": "Last 7 days", "30d": "Last 30 days", "90d": "Last 90 days" });
    expect(KIND_TITLES).toEqual({ ip: "IP address", host: "Host", domain: "Domain", user: "User" });
    expect(SEVERITIES).toEqual(["critical", "high", "medium", "low"]);
  });
});

describe("outcomeLabel and stateLabel", () => {
  it("say an outcome in words, say when there is none, and never show a value the page does not know as it is", () => {
    expect(outcomeLabel("true_positive")).toBe("Real: act on it");
    expect(outcomeLabel(null)).toBe("No outcome");
    expect(outcomeLabel(undefined)).toBe("No outcome");
    expect(outcomeLabel("<img src=x>")).toBe("An outcome this page does not know");
    expect(outcomeLabel("")).toBe("An outcome this page does not know");
  });

  it("names a state, or writes an unknown one with spaces", () => {
    expect(stateLabel("changed_since_review")).toBe("Changed since review");
    expect(stateLabel("on_hold_for_now")).toBe("on hold for now");
  });
});
