// The numbers behind the dashboards' charts: round axis ticks, compact figures, the change
// against the span before and a funnel's "1 in N".
import { describe, expect, it } from "vitest";
import { change, compact, oneIn, span, ticks, total } from "../src/lib/viz";

describe("figures", () => {
  it("are whole below ten thousand and compact above", () => {
    expect([0, 7, 1284, 9999].map(compact)).toEqual(["0", "7", "1,284", "9,999"]);
    expect([12_940, 40_364, 100_000, 4_200_000, 2_500_000_000].map(compact)).toEqual(["12.9K", "40.4K", "100K", "4.2M", "2.5B"]);
  });

  it("say a span of seconds as people do", () => {
    expect([45, 720, 3600, 5400, 12_600, 259_200].map(span)).toEqual(["45 s", "12 min", "1 h", "1.5 h", "3.5 h", "3 days"]);
  });

  it("say how a figure moved against the span before", () => {
    expect(change(117, 100)).toEqual({ words: "+17%", direction: "up" });
    expect(change(96, 100)).toEqual({ words: "−4%", direction: "down" });
    expect(change(100, 100)).toEqual({ words: "no change", direction: "flat" });
    expect(change(5, 0)).toEqual({ words: "new", direction: "up" });
    expect(change(0, 0)).toBeNull();
  });

  it("say how much of the step before a step keeps", () => {
    expect(oneIn(545, 7514)).toBe("1 in 14");
    expect(oneIn(24, 118)).toBe("1 in 5");
    expect(oneIn(90, 100)).toBe("nearly all");
    expect(oneIn(0, 100)).toBeNull();
    expect(oneIn(7, 3)).toBeNull();
  });
});

describe("an axis", () => {
  it("has round ticks from zero to the first one at or above the top", () => {
    expect(ticks(33)).toEqual([0, 10, 20, 30, 40]);
    expect(ticks(41)).toEqual([0, 20, 40, 60]);
    expect(ticks(7514)).toEqual([0, 2000, 4000, 6000, 8000]);
    expect(ticks(3)).toEqual([0, 1, 2, 3]);
    expect(ticks(0)).toEqual([0, 1]);
  });

  it("never has a tick that is not a whole number of things", () => {
    for (const top of [1, 2, 3, 5, 9, 12, 47, 380, 9_999, 123_456]) {
      const got = ticks(top);
      expect(got.every((t) => Number.isInteger(t)), String(top)).toBe(true);
      expect(got[got.length - 1], String(top)).toBeGreaterThanOrEqual(top);
      expect(got.length, String(top)).toBeLessThanOrEqual(7);
    }
  });

  it("adds a bucket's series up, and only those shown", () => {
    const series = [
      { key: "low", label: "Low", fill: "fill-viz-low" },
      { key: "high", label: "High", fill: "fill-viz-high" },
    ];
    expect(total({ at: "2026-11-18T00:00", counts: { low: 9, high: 2, unknown: 5 } }, series)).toBe(11);
  });
});
