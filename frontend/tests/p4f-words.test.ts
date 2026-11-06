// P4-F Track 2A, the pure parts: the five decisions in plain words ("Real" first, over the review
// model's own values), the quiet System word and its one banner, the next step a case asks for,
// and each finding said once. Property tests (fast-check) hold the invariants.
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import type { HealthOut } from "../src/client/types.gen";
import { CASE_TABS, CASE_VIEW_TITLES, DEFAULT_CASE_VIEW, nextStep, parseCases } from "../src/lib/cases";
import { OUTCOME_HINTS, OUTCOME_KEYS, OUTCOMES } from "../src/lib/labels";
import { distinctLines } from "../src/lib/report";
import { STALE_HOURS, systemWord } from "../src/lib/system";
import { KEYED_OUTCOMES, patternSize, stanceHeadline, stanceWhy } from "../src/lib/verdict";
import { stanceOf } from "./helpers";

const NOW = new Date("2026-11-06T09:00:00Z");

function health(more: Partial<HealthOut> = {}): HealthOut {
  return {
    siem_state: "normal", siem_reasons: [], siem_probed_at: "2026-11-06T08:59:00Z", live_cursor: "2026-11-06T08:55:00Z", backfill_cursor: null,
    open_gaps: [], last_reconciliation: null, alerts: 10, quarantined: 0, investigations: 4, jobs_waiting: 0, jobs_deferred: 0, jobs_failed: 0,
    dossiers: 4, checkpoint_threads: 0, checkpoint_bytes: 0,
    kibana_sync: { state: "ok", last_cycle_at: null, last_outcome: null, last_reason: null, last_complete_at: null },
    ...more,
  };
}

describe("the five decisions (U7)", () => {
  it("are plain words over the review model's own values, Real first, keys 1 to 5 in the same order", () => {
    expect(OUTCOME_KEYS).toEqual(["true_positive", "benign_expected", "benign_policy", "rule_false_positive", "inconclusive"]);
    expect(Object.values(OUTCOMES)).toEqual(["Real: act on it", "Real but harmless", "Allowed by policy", "Wrong alert", "Can't tell yet"]);
    expect(KEYED_OUTCOMES).toEqual(OUTCOME_KEYS);
    expect(Object.keys(OUTCOME_HINTS).sort()).toEqual([...OUTCOME_KEYS].sort());
  });

  it("say ARGUS's call, and put the machine's reason for not proposing behind Details", () => {
    expect(stanceHeadline(stanceOf({ kind: "recommends", outcome: "true_positive", confidence: 0.85 }))).toBe("ARGUS's call: Real: act on it (85%)");
    const reading = stanceOf({ kind: "reading", outcome: "rule_false_positive", confidence: 0.82, why: "it quoted something that is not in the evidence" });
    expect(stanceHeadline(reading)).toBe("ARGUS leans to: Wrong alert (82%), but did not propose it");
    expect(stanceHeadline(reading)).not.toContain("quoted");
    expect(stanceWhy(reading)).toBe("Not proposed because it quoted something that is not in the evidence.");
    expect(stanceHeadline(stanceOf({ kind: "none" }))).toBe("ARGUS has made no call on this yet");
    expect(patternSize(stanceOf({ kind: "recommends", outcome: "benign_expected", pattern_investigations: 1, pattern_alerts: 3 }))).toBeNull();
  });
});

describe("the System word and its banner (U8)", () => {
  it("is a quiet OK when all is well, with no banner", () => {
    expect(systemWord(health(), NOW)).toEqual({ tone: "ok", word: "System: OK", banner: null, notes: [] });
  });

  it("raises a banner only when the queue itself may be wrong", () => {
    expect(systemWord(health({ siem_state: "stop" }), NOW).banner).toContain("not reading the SIEM now");
    expect(systemWord(health({ siem_state: "degraded" }), NOW).banner).toContain("very little");
    expect(systemWord(health({ live_cursor: "2026-11-04T09:00:00Z" }), NOW).banner).toBe("ARGUS has not read new alerts from the SIEM for 2 days: new incidents may be missing.");
    const busy = systemWord(health({ siem_state: "caution", jobs_failed: 2, kibana_sync: { state: "failed", last_cycle_at: null, last_outcome: null, last_reason: null, last_complete_at: null } }), NOW);
    expect(busy.banner).toBeNull();
    expect(busy.word).toBe("System: check");
    expect(busy.notes).toHaveLength(3);
  });

  it("property: a banner exactly when ARGUS stopped reading or what it read is older than the limit", () => {
    fc.assert(
      fc.property(fc.constantFrom("normal", "caution", "degraded", "stop"), fc.integer({ min: 0, max: 10 * 24 * 60 }), (state, minutes) => {
        const cursor = new Date(NOW.getTime() - minutes * 60_000).toISOString();
        const said = systemWord(health({ siem_state: state, live_cursor: cursor }), NOW);
        const stale = minutes * 60_000 > STALE_HOURS * 3_600_000;
        expect(said.banner !== null).toBe(state === "stop" || state === "degraded" || stale);
        expect(said.tone === "danger").toBe(said.banner !== null);
        expect(said.word.startsWith("System")).toBe(true);
      }),
    );
  });
});

describe("the case list (U12)", () => {
  it("opens on Needs a decision, with six tabs", () => {
    expect(DEFAULT_CASE_VIEW).toBe("queue");
    expect(parseCases({}).view).toBe("queue");
    expect(parseCases({ view: "bogus" }).view).toBe("queue");
    expect(parseCases({ view: "suspected" }).view).toBe("suspected");
    expect(CASE_TABS.map((v) => CASE_VIEW_TITLES[v])).toEqual(["Needs a decision", "Mine", "Open", "Owner told", "Closed", "All"]);
  });

  it("names the next step a case asks for", () => {
    const row = { state: "open", owner: null, notified_at: null, needs_attention: false, waiting_for_approval: 0 };
    expect(nextStep({ ...row, state: "suspected" })).toBe("Confirm or dismiss");
    expect(nextStep({ ...row, waiting_for_approval: 1 })).toBe("Waiting for an approval");
    expect(nextStep({ ...row, needs_attention: true })).toBe("Look at what changed");
    expect(nextStep(row)).toBe("Assign an owner");
    expect(nextStep({ ...row, owner: { id: 1 } })).toBeNull();
    expect(nextStep({ ...row, state: "closed" })).toBeNull();
  });
});

describe("each finding once (U18)", () => {
  it("drops a repeated sentence and counts those shown above", () => {
    const items = [{ sentence: "1 internal host reached the destination." }, { sentence: "No threat list names it." }, { sentence: "1 internal host reached the destination." }];
    expect(distinctLines(items, ["1 internal host reached the destination."])).toEqual({ items: [{ sentence: "No threat list names it." }], above: 1 });
    expect(distinctLines(items, []).items.map((i) => i.sentence)).toEqual(["1 internal host reached the destination.", "No threat list names it."]);
  });

  it("property: every sentence is either shown once or counted above, never both, never twice", () => {
    fc.assert(
      fc.property(fc.array(fc.constantFrom("a", "b", "c", "d", " a "), { maxLength: 12 }), fc.array(fc.constantFrom("a", "c", "x"), { maxLength: 3 }), (sentences, shown) => {
        const { items, above } = distinctLines(sentences.map((sentence) => ({ sentence })), shown);
        const kept = items.map((i) => i.sentence.trim());
        expect(new Set(kept).size).toBe(kept.length);
        expect(kept.some((k) => (shown as string[]).includes(k))).toBe(false);
        const distinct = new Set(sentences.map((s) => s.trim()));
        expect(kept.length + above).toBe(distinct.size);
      }),
    );
  });
});
