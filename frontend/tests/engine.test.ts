// The UI v2's pure rules (docs/p4f-ui-spec.md §2, §5, §7, §12): reading the engine block and the
// Today card in either shape, the nouns of entity chips (G-5), points that always add up (I-6),
// the "Scan or attempt" guard (T-9), Needs you's layout (T-3, T-6) and the summary's words (T-4).
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  engineOf,
  isPrivateIp,
  layoutNeedsYou,
  mergedAlternatives,
  needsYouCount,
  nounFor,
  outcomeOf,
  pointsRows,
  scanReasonBlocked,
  shownCertainty,
  stillFitsLine,
  stillOpen,
  summaryParts,
  titleTail,
  toCard,
  toToday,
  topWhy,
  type Card,
  type Engine,
} from "../src/lib/engine";
import { card, engineBlock, lowCards, p1bCard, p1Card, p1Engine, p2ExposureCard, today } from "./v2Fixtures";

const engine = (raw: Record<string, unknown>): Engine => {
  const e = engineOf(raw);
  if (e === null) throw new Error("no engine");
  return e;
};

describe("reading the engine block", () => {
  it("is null without a priority and a band: not scored yet", () => {
    expect(engineOf(null)).toBeNull();
    expect(engineOf({ band: "P1" })).toBeNull();
    expect(engineOf({ priority: 50, band: "P9" })).toBeNull();
  });

  it("maps changes sent as objects to words and drops what it does not know", () => {
    const e = engine({ ...p1Engine(), changed: [{ text: "a new destination" }, "", 5], checks: [{ state: "bogus", text: "x" }, { state: "unknown", text: "who" }] });
    expect(e.changed).toEqual(["a new destination"]);
    expect(e.checks).toEqual([{ state: "unknown", text: "who" }]);
  });

  it("reads a card in the spec's shape and in engine builder C's", () => {
    const spec = toCard(p1Card());
    expect(spec?.id).toBe(p1Card().id);
    expect(spec?.number).toBe(31);
    const c = toCard({ case_id: "x-1", case_number: 9, case_state: "suspected", case_version: 4, title: "T", engine: p1Engine() });
    expect(c).toMatchObject({ id: "x-1", number: 9, state: "suspected", version: 4, kind: "incident" });
    expect(toCard({ id: "y", engine: null })).toBeNull();
  });

  it("property: never throws and never yields a band it does not know", () => {
    fc.assert(
      fc.property(fc.anything(), (raw) => {
        const e = engineOf(raw);
        if (e !== null) {
          expect(["P1", "P2", "P3", "P4"]).toContain(e.band);
          expect(e.priority).toBeGreaterThanOrEqual(0);
          expect(e.priority).toBeLessThanOrEqual(100);
        }
        toCard(raw);
        toToday(raw);
      }),
    );
  });
});

describe("the noun of an entity chip (G-5)", () => {
  it("never calls an actor a Device", () => {
    expect(nounFor({ kind: "device", role: "actor", label: "203.0.113.40" })).toBe("Outside address");
    expect(nounFor({ kind: "device", role: "actor", label: "bad.example" })).toBe("Outside host");
    expect(nounFor({ kind: "account", role: "actor", label: "x" })).toBe("Outside account");
    expect(nounFor({ kind: "site", role: "actor", label: "x" })).toBe("Outside site");
    expect(nounFor({ kind: "device", role: "affected", label: "lab-pc-17" })).toBe("Device");
    expect(nounFor({ kind: "site", role: "affected", label: "www.dept.example.ac.in" })).toBe("Campus site");
  });

  it("property: an actor's noun is never Device", () => {
    fc.assert(
      fc.property(fc.constantFrom("device", "account", "site" as const), fc.string(), (kind, label) => {
        expect(nounFor({ kind, role: "actor", label })).not.toBe("Device");
      }),
    );
  });

  it("knows private addresses", () => {
    expect(isPrivateIp("10.0.12.17")).toBe(true);
    expect(isPrivateIp("192.168.1.4")).toBe(true);
    expect(isPrivateIp("203.0.113.40")).toBe(false);
  });
});

describe("the points (I-6)", () => {
  it("are sorted, negatives last, and add up when the stored points do", () => {
    const rows = pointsRows(engine(p1Engine()));
    expect(rows.map((r) => r.value)).toEqual([50, 20, 12, 8, -8]);
    expect(rows.every((r) => r.kind === "point")).toBe(true);
  });

  it("add a row worded by sign when they do not", () => {
    const rows = pointsRows(engine(p1Engine({ why: [{ op: "+", points: 44, text: "a" }, { op: "+", points: 30, text: "b" }] })));
    expect(rows.at(-1)).toEqual({ kind: "other", value: 8, text: "Other factors and limits" });
    const capped = pointsRows({ priority: 100, why: [{ op: "+", points: 80, text: "a" }, { op: "+", points: 40, text: "b" }] });
    expect(capped.at(-1)).toEqual({ kind: "capped", value: -20, text: "Capped at 100" });
    const factor = pointsRows({ priority: 60, why: [{ op: "+", points: 50, text: "a" }, { op: "×", points: 1.2, text: "still active" }] });
    expect(factor.at(-1)?.text).toBe("Other factors and limits (×1.2 still active)");
  });

  it("property: the visible values always sum to the priority", () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 0, max: 100 }),
        fc.array(fc.record({ op: fc.constantFrom("+" as const, "×" as const), points: fc.double({ min: -200, max: 200, noNaN: true }), text: fc.string() }), { maxLength: 8 }),
        (priority, why) => {
          const rows = pointsRows({ priority, why });
          expect(rows.reduce((s, r) => s + r.value, 0)).toBe(priority);
        },
      ),
    );
  });

  it("show the top three on a card, then how many more", () => {
    expect(topWhy(engine(p1Engine()))).toEqual({ shown: ["+50 VirusTotal: 7 of 94 engines flag 203.0.113.40", "+20 Regular timing, like a beacon (98 of 100)", "+12 Five campus devices, same destination"], more: 2 });
  });
});

describe("the Scan-or-attempt guard (T-9, F3)", () => {
  it("blocks the exposure lane and an unverified 200", () => {
    const x = toCard(p2ExposureCard()) as Card;
    expect(scanReasonBlocked(x.engine, x.title)).toBe(true);
    expect(scanReasonBlocked(engine(engineBlock("P3", 30)), "Scan of a site — got HTTP 200, not verified")).toBe(true);
    expect(scanReasonBlocked(engine(engineBlock("P3", 30)), "Scan of a site — no HTTP 200 after the alerts")).toBe(false);
    expect(scanReasonBlocked(engine(engineBlock("P3", 30)), "Scan of a site — served only ordinary pages")).toBe(false);
    expect(scanReasonBlocked(null, "Plain title")).toBe(false);
  });

  it("reads the outcome from the engine first, else the title's tail", () => {
    expect(titleTail("A — b c — d")).toBe("b c");
    expect(titleTail("No tail")).toBeNull();
    expect(outcomeOf(engine(engineBlock("P3", 30, { outcome: { rung: "x", words: "served a file" } })), "A — other")).toBe("served a file");
  });
});

describe("what still argues against confirming (§5.4)", () => {
  it("lists fits and not-tested alternatives and unknown checks, merging identical tests", () => {
    const e = engine(p1Engine());
    const open = stillOpen(e);
    expect(open.lines).toHaveLength(4);
    expect(open.lines[0]).toContain("still fits: A remote-management tool the lab installed");
    expect(open.lines[0]).toContain("The check that would decide: ask the lab admin");
    expect(open.lines.filter((l) => l.startsWith("Not known"))).toHaveLength(2);
    const merged = stillOpen(engine(p1Engine({ checks: [], alternatives: [{ name: "a", state: "fits", test: "same" }, { name: "b", state: "unknown", test: "same" }] })));
    expect(merged.lines).toHaveLength(1);
    expect(stillOpen(engine(p1Engine({ checks: [], alternatives: [] })))).toEqual({ lines: [], more: 0 });
  });

  it("merges identical tests in Other explanations", () => {
    expect(mergedAlternatives([{ name: "a", state: "fits", test: "t" }, { name: "b", state: "fits", test: "t" }, { name: "c", state: "ruled_out", test: "t" }])).toEqual([
      { names: ["a", "b"], state: "fits", test: "t" },
      { names: ["c"], state: "ruled_out", test: "t" },
    ]);
  });

  it("says what still fits under the summary", () => {
    expect(stillFitsLine(engine(p1Engine()))?.text).toBe("1 other explanation still fits: A remote-management tool the lab installed (ask the lab admin whether such a tool runs)");
    expect(stillFitsLine(engine(engineBlock("P3", 30)))).toBeNull();
  });
});

describe("certainty shown (§3.2)", () => {
  it("is Confirmed once a person confirmed it, else the engine's", () => {
    const e = engine(p1Engine());
    expect(shownCertainty("suspected", null, e)).toBe("Likely");
    expect(shownCertainty("open", null, e)).toBe("Confirmed");
    expect(shownCertainty("closed", "attempt_no_impact", e)).toBe("Likely");
    expect(shownCertainty("closed", "remediated_verified", e)).toBe("Confirmed");
    expect(shownCertainty("suspected", null, null)).toBeNull();
  });
});

describe("Needs you's layout (T-3, T-6)", () => {
  const cards = toToday(today()).needs_you;

  it("shows every P1 and P2, at most 8 lower slots, and collapses the 3 similar into one", () => {
    const { slots, hidden } = layoutNeedsYou(cards);
    const urgent = slots.filter((s) => s.kind === "card" && (s.card.engine.band === "P1" || s.card.engine.band === "P2"));
    expect(urgent).toHaveLength(4);
    const similar = slots.filter((s) => s.kind === "similar");
    expect(similar).toHaveLength(1);
    expect(similar[0]?.kind === "similar" && similar[0].cards).toHaveLength(3);
    const lower = slots.length - urgent.length;
    expect(lower).toBeLessThanOrEqual(8);
    expect(hidden).toBe(0); // 6 cards + 1 similar row = 7 lower slots
  });

  it("property: never caps P1 or P2, never collapses them, and loses no card", () => {
    const bands = ["P1", "P2", "P3", "P4"];
    fc.assert(
      fc.property(fc.array(fc.record({ band: fc.constantFrom(...bands), key: fc.option(fc.constantFrom("a", "b")), tail: fc.constantFrom("x", "y") }), { maxLength: 30 }), (spec) => {
        const cs = spec.map((s, i) => toCard(card(`id-${i}`, i, `T ${i} — ${s.tail}`, engineBlock(s.band, 50, { similar_key: s.key }))) as Card);
        const { slots, hidden } = layoutNeedsYou(cs);
        const shown = slots.reduce((n, s) => n + (s.kind === "card" ? 1 : s.cards.length), 0);
        expect(shown + hidden).toBe(cs.length);
        const urgentCards = slots.filter((s) => s.kind === "card" && ["P1", "P2"].includes(s.card.engine.band)).length;
        expect(urgentCards).toBe(cs.filter((c) => ["P1", "P2"].includes(c.engine.band)).length);
        for (const s of slots) {
          if (s.kind === "similar") {
            expect(["P3", "P4"]).toContain(s.band);
            expect(new Set(s.cards.map((c) => outcomeOf(c.engine, c.title))).size).toBe(1);
          }
        }
        expect(slots.filter((s) => !(s.kind === "card" && ["P1", "P2"].includes(s.card.engine.band))).length).toBeLessThanOrEqual(8);
      }),
    );
  });

  it("collapses nothing without a similar key", () => {
    const plain = lowCards().map((c) => toCard({ ...c, engine: { ...(c.engine as object), similar_key: null } }) as Card);
    expect(layoutNeedsYou(plain).slots.every((s) => s.kind === "card")).toBe(true);
  });
});

describe("the summary line (T-4)", () => {
  it("starts with the urgent count and counts the rest as need you", () => {
    const t = toToday(today());
    expect(needsYouCount(t)).toBe(17);
    const parts = summaryParts(t, "Tue 4:10 PM");
    expect(parts.map((p) => p.text)).toEqual(["2 urgent (P1)", "15 more need you", "1 with new activity", "ARGUS handled 1,140 since your last round (Tue 4:10 PM)"]);
    expect(parts[0]?.strong).toBe(true);
  });

  it("says nothing needs you when nothing does, dropping zero parts", () => {
    const t = toToday({ needs_you: [], more_waiting: 0, new_activity: [], gray: [], handled: { since: null, count: 0, categories: [], audit: null } });
    expect(summaryParts(t, null).map((p) => p.text)).toEqual(["Nothing needs you right now"]);
  });

  it("without a P1: M need you", () => {
    const t = toToday({ needs_you: [p2ExposureCard()], more_waiting: 2, new_activity: [], gray: [], handled: { since: null, count: 0, categories: [], audit: null } });
    expect(summaryParts(t, null)[0]).toEqual({ text: "3 need you", strong: true });
    expect(toToday({ needs_you: [p1bCard()] }).needs_you).toHaveLength(1);
  });
});
