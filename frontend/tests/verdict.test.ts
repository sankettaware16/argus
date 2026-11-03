// AR4: the words of the verdict-first card: the headline for a recommendation, a reading and nothing,
// where it comes from, the pattern's size, and the three to five facts in the order a person wants them.
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import type { KnownRefOut, Report, StanceOut } from "../src/client/types.gen";
import { factLink, keyFacts, knownSentence, KEYED_OUTCOMES, MAX_FACTS, needsReview, patternSize, stanceHeadline, stanceSource, surePart } from "../src/lib/verdict";
import { NO_STANCE, REPORT, stanceOf } from "./helpers";

const stance = (more: Partial<StanceOut>): StanceOut => stanceOf(more);

describe("the headline", () => {
  it("says what ARGUS recommends, with its confidence", () => {
    expect(stanceHeadline(stance({ kind: "recommends", outcome: "true_positive", confidence: 0.8 }))).toBe("ARGUS recommends: True positive (80%)");
    expect(stanceHeadline(stance({ kind: "recommends", outcome: "benign_policy", confidence: null }))).toBe("ARGUS recommends: Benign: allowed by policy");
    expect(stanceHeadline(stance({ kind: "recommends", outcome: "benign_expected", confidence: 0.755 }))).toBe("ARGUS recommends: Benign: expected activity (76%)");
  });

  it("says a reading is not proposed, and why", () => {
    const s = stance({ kind: "reading", outcome: "true_positive", confidence: 0.7, why: "it quoted something that is not in the evidence" });
    expect(stanceHeadline(s)).toBe("ARGUS's reading: True positive (70%), not proposed because it quoted something that is not in the evidence");
    expect(stanceHeadline(stance({ kind: "reading", outcome: "inconclusive", confidence: null, why: null }))).toBe("ARGUS's reading: Inconclusive, not proposed");
  });

  it("says when ARGUS has nothing", () => {
    expect(stanceHeadline(NO_STANCE)).toBe("ARGUS has no reading of this yet");
  });

  it("never shows an outcome it does not know as raw text", () => {
    expect(stanceHeadline(stance({ kind: "recommends", outcome: "<script>" as StanceOut["outcome"], confidence: 0.5 }))).toBe("ARGUS recommends: An outcome this page does not know (50%)");
  });

  it("rounds a confidence to a whole percent, and shows none when there is none", () => {
    expect(surePart(0)).toBe(" (0%)");
    expect(surePart(1)).toBe(" (100%)");
    expect(surePart(undefined)).toBe("");
    fc.assert(
      fc.property(fc.double({ min: 0, max: 1, noNaN: true }), (c) => {
        const text = surePart(c);
        const n = Number(/\((\d+)%\)/.exec(text)?.[1]);
        expect(n).toBeGreaterThanOrEqual(0);
        expect(n).toBeLessThanOrEqual(100);
      }),
    );
  });
});

describe("where it comes from", () => {
  it("names the source and says a proposal is not a decision and a reading is not a proposal", () => {
    expect(stanceSource(stance({ kind: "recommends", source: "the AI investigator" }))).toBe("From the AI investigator. A proposal, not a decision.");
    expect(stanceSource(stance({ kind: "reading", source: "the AI investigator" }))).toBe("From the AI investigator. A reading is not a proposal: nothing is closed from it.");
    expect(stanceSource(stance({ kind: "recommends", source: "the AI investigator", from_investigation_id: "x" }))).toMatch(/^The AI investigator read another investigation of the same pattern/);
    expect(stanceSource(NO_STANCE)).toBeNull();
  });
});

describe("the pattern's size", () => {
  it("says how many investigations and alerts the run stands for", () => {
    expect(patternSize(stance({ pattern_investigations: 14, pattern_alerts: 230 }))).toBe("This pattern: 14 investigations, 230 alerts");
    expect(patternSize(stance({ pattern_investigations: 2, pattern_alerts: 1 }))).toBe("This pattern: 2 investigations, 1 alert");
    expect(patternSize(stance({ pattern_investigations: 1, pattern_alerts: 4 }))).toBe("This pattern: only this investigation so far");
    expect(patternSize(NO_STANCE)).toBeNull();
  });
});

describe("the key facts", () => {
  it("start with what the extra SIEM queries found, then the known facts that bear on the verdict, then the dossier's", () => {
    const facts = keyFacts(REPORT, ["Two alerts from 10.0.0.1."]);
    expect(facts).toEqual([
      { text: "Host H1 reached the C2 every 300 s, 59 times.", eid: "E3" },
      { text: "Two more campus hosts reached the same C2 today.", eid: "E4" },
      { text: "Contacts at a fixed interval.", eid: "E3" },
      { text: "Two alerts from 10.0.0.1.", eid: null },
    ]);
  });

  it("leaves out the neutral, the unknown, the repeated and the blank, and never more than five", () => {
    const report = { ...REPORT, found: { ...REPORT.found, items: [] }, evidence: [] } as Report;
    expect(keyFacts(report, ["a", "a", "  ", "b"])).toEqual([
      { text: "a", eid: null },
      { text: "b", eid: null },
    ]);
    expect(keyFacts(undefined, undefined)).toEqual([]);
    expect(keyFacts(undefined, ["1", "2", "3", "4", "5", "6", "7"])).toHaveLength(MAX_FACTS);
    fc.assert(fc.property(fc.array(fc.string(), { maxLength: 30 }), (lines) => {
      const got = keyFacts(undefined, lines);
      expect(got.length).toBeLessThanOrEqual(MAX_FACTS);
      expect(new Set(got.map((f) => f.text)).size).toBe(got.length);
      for (const f of got) expect(f.text).toBe(f.text.trim());
    }));
  });

  it("link to the rows behind them: the report's sources for an E-number, the alerts otherwise", () => {
    expect(factLink({ text: "x", eid: "E3" })).toEqual({ tab: "report", hash: "eid-E3" });
    expect(factLink({ text: "x", eid: null })).toEqual({ tab: "alerts", hash: undefined });
  });
});

describe("known and changed since the notice", () => {
  const known = (more: Partial<KnownRefOut>): KnownRefOut => ({ case_id: "c", case_number: 12, outcome: "known", why: null, notified_at: "2026-10-20T04:00:00Z", ...more });

  it("says a known one is counted and not raised, and a changed one what changed", () => {
    expect(knownSentence(known({}))).toMatch(/^Known: the owner of this device was told/);
    expect(knownSentence(known({ notified_at: null }))).toMatch(/no longer notified/);
    expect(knownSentence(known({ outcome: "changed", why: "a new flagged destination: 203.0.113.9" }))).toBe("Changed since the owner was told: a new flagged destination: 203.0.113.9");
    expect(knownSentence(known({ outcome: "changed", why: null }))).toBe("Changed since the owner was told");
  });
});

describe("the keys of the outcomes", () => {
  it("are the five outcomes in the order the pages list them", () => {
    expect(KEYED_OUTCOMES).toEqual(["benign_expected", "benign_policy", "rule_false_positive", "true_positive", "inconclusive"]);
  });

  it("offer a review only for what is not reviewed", () => {
    expect(needsReview({ human_state: "unreviewed" })).toBe(true);
    expect(needsReview({ human_state: "follow_up" })).toBe(true);
    expect(needsReview({ human_state: "changed_since_review" })).toBe(true);
    expect(needsReview({ human_state: "reviewed" })).toBe(false);
  });
});
