// The chart geometry (lib/chart.ts) is the classic charts' (src/argus/web/charts.py): the axis
// numbers below come from its `_nice` run on the same inputs.
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { must } from "./helpers";
import { bucketLabel, geometry, H, niceMax, PAD_B, PAD_L, PAD_T, shares, sum, tickLabel, W } from "../src/lib/chart";

describe("niceMax", () => {
  it("is the classic page's axis top", () => {
    const python: Record<number, number> = { 0: 5, 1: 5, 4: 5, 5: 5, 6: 6, 7: 8, 9: 10, 10: 10, 11: 12, 12: 12, 13: 15, 16: 20, 17: 20, 25: 25, 26: 30, 99: 100, 100: 100, 101: 120, 1234: 1500, 9999: 10000, 10000: 10000, 123456: 150000 };
    for (const [from, to] of Object.entries(python)) expect(niceMax(Number(from))).toBe(to);
  });

  it("is never below the top and never more than a third above it (above the floor of 5)", () => {
    fc.assert(fc.property(fc.integer({ min: 0, max: 10_000_000 }), (n) => {
      const top = niceMax(n);
      expect(top).toBeGreaterThanOrEqual(Math.max(n, 5));
      expect(top).toBeLessThanOrEqual(Math.max((n * 4) / 3, 5) + 1e-9);
    }));
  });
});

const SERIES: { at: string; counts: Record<string, number> }[] = [
  { at: "2026-10-09T00:00:00+05:30", counts: { low: 2, critical: 1 } },
  { at: "2026-10-10T00:00:00+05:30", counts: {} },
  { at: "2026-10-11T00:00:00+05:30", counts: { high: 4, unknown: 1 } },
];

describe("geometry", () => {
  const g = geometry(SERIES, ["low", "medium", "high", "critical", "unknown"]);

  it("stacks each bar from the bottom in the given order, inside the plot", () => {
    const plotH = H - PAD_B - PAD_T;
    expect(g.top).toBe(5);
    expect(g.bars).toHaveLength(3);
    const first = must(g.bars[0]);
    const [low, critical] = [must(first.parts[0]), must(first.parts[1])];
    expect(first.total).toBe(3);
    expect(first.parts.map((p) => p.name)).toEqual(["low", "critical"]);
    expect(low).toMatchObject({ count: 2, height: (plotH * 2) / 5, y: PAD_T + plotH - (plotH * 2) / 5 });
    expect(critical.y + critical.height).toBeCloseTo(low.y);
    expect(must(g.bars[1]).parts).toEqual([]);
    expect(must(g.bars[1]).total).toBe(0);
    expect(must(g.bars[2]).parts.map((p) => p.name)).toEqual(["high", "unknown"]);
  });

  it("has five grid lines from 0 to the top, bars within the width, and a label every n bars", () => {
    expect(g.grid.map((l) => l.value)).toEqual([0, 1.25, 2.5, 3.75, 5]);
    for (const bar of g.bars) {
      expect(bar.x).toBeGreaterThanOrEqual(PAD_L);
      expect(bar.x + bar.width).toBeLessThanOrEqual(W);
      expect(bar.width).toBeLessThanOrEqual(48);
    }
    expect(g.every).toBe(1);
    expect(geometry(Array.from({ length: 90 }, (_, i) => ({ at: `2026-01-01T${String(i % 24).padStart(2, "0")}:00:00+05:30`, counts: { low: 1 } })), ["low"]).every).toBe(8);
  });

  it("never draws a bar taller than the plot, for any counts", () => {
    const plotH = H - PAD_B - PAD_T;
    fc.assert(fc.property(fc.array(fc.record({ low: fc.nat(500), high: fc.nat(500) }), { maxLength: 40 }), (counts) => {
      const gg = geometry(counts.map((c, i) => ({ at: `2026-10-${String((i % 28) + 1).padStart(2, "0")}T00:00:00+05:30`, counts: c })), ["low", "high"]);
      for (const bar of gg.bars) {
        const heights = bar.parts.reduce((a, p) => a + p.height, 0);
        expect(heights).toBeLessThanOrEqual(plotH + 1e-6);
      }
    }));
  });
});

describe("shares and labels", () => {
  it("splits one bar by share, largest first (ties by name), skipping zeros", () => {
    const got = shares({ b: 1, a: 1, c: 2, z: 0 });
    expect(got.map((p) => p.key)).toEqual(["c", "a", "b"]);
    expect(got.map((p) => p.width)).toEqual([500, 250, 250]);
    expect(got.map((p) => p.x)).toEqual([0, 500, 750]);
    expect(shares({})).toEqual([]);
    fc.assert(fc.property(fc.dictionary(fc.string({ minLength: 1, maxLength: 3 }), fc.nat(1000)), (counts) => {
      const parts = shares(counts);
      if (parts.length > 0) expect(parts.reduce((a, p) => a + p.width, 0)).toBeCloseTo(1000, 6);
      expect(sum(parts.map((p) => p.count))).toBe(sum(Object.values(counts)));
    }));
  });

  it("breaks ties by name whichever way the names are met, and sorts by count first", () => {
    expect(shares({ c: 2, a: 2, b: 2 }).map((p) => p.key)).toEqual(["a", "b", "c"]);
    expect(shares({ a: 2, b: 2, c: 2 }).map((p) => p.key)).toEqual(["a", "b", "c"]);
    expect(shares({ z: 3, a: 1, m: 2 }).map((p) => p.key)).toEqual(["z", "m", "a"]);
    expect(shares({ a: 1, m: 2, z: 3 }).map((p) => p.key)).toEqual(["z", "m", "a"]);
  });

  it("puts the bars and the grid where the classic chart does", () => {
    const g = geometry([{ at: "2026-10-09T00:00:00+05:30", counts: { low: 5 } }, { at: "2026-10-10T00:00:00+05:30", counts: { low: 5 } }], ["low"]);
    const plotW = W - PAD_L - 8;
    const plotH = H - PAD_B - PAD_T;
    const slot = plotW / 2;
    const width = Math.max(Math.min(slot * 0.72, 48), 1.5);
    expect(width).toBe(48);
    expect(must(g.bars[0]).x).toBeCloseTo(PAD_L + (slot - 48) / 2);
    expect(must(g.bars[1]).x).toBeCloseTo(PAD_L + slot + (slot - 48) / 2);
    expect(g.grid.map((l) => l.y)).toEqual([PAD_T + plotH, PAD_T + plotH * 0.75, PAD_T + plotH * 0.5, PAD_T + plotH * 0.25, PAD_T]);
    expect(must(g.bars[0]).width).toBe(48);
    const many = geometry(Array.from({ length: 1000 }, (_, i) => ({ at: `2026-01-01T00:00:0${i % 10}+05:30`, counts: { low: 1 } })), ["low"]);
    expect(must(many.bars[0]).width).toBe(1.5); // never thinner than a line
    expect(geometry([], ["low"]).bars).toEqual([]);
  });

  it("labels buckets by their IST fields as the server wrote them", () => {
    expect(bucketLabel("2026-10-09T14:00:00+05:30", true)).toBe("09 Oct 2 PM");
    expect(bucketLabel("2026-10-09T00:00:00+05:30", false)).toBe("Fri 09 Oct");
    expect(tickLabel("2026-10-09T14:00:00+05:30", true)).toBe("2 PM");
    expect(tickLabel("2026-10-09T00:00:00+05:30", false)).toBe("09 Oct");
    expect(bucketLabel("garbage", true)).toBe("garbage");
    expect(bucketLabel("x2026-10-09T14:00:00+05:30", true)).toBe("x2026-10-09T14:00:00+05:30");
    expect(bucketLabel("2026-10-09T14:00", true)).toBe("09 Oct 2 PM");
    expect(bucketLabel("2026-10-09T00:00", true)).toBe("09 Oct 12 AM");
    expect(tickLabel("2026-10-09T12:00:00+05:30", true)).toBe("12 PM");
    expect(tickLabel("x2026-10-09T14:00:00+05:30", true)).toBe("x2026-10-09T14:00:00+05:30");
    expect(tickLabel("garbage", false)).toBe("garbage");
  });
});
