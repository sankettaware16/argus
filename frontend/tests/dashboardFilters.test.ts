// The dashboard's filters (lib/dashboardFilters.ts): the classic page's bounds, in the address.
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { adding, chips, cleared, NO_FILTERS, parseFilters, span, toQuery, toSearch, type Filters } from "../src/lib/dashboardFilters";
import { parseSearch, stringifySearch } from "../src/lib/search";

describe("parseFilters", () => {
  it("is the default for an empty address", () => {
    expect(parseFilters({})).toEqual(NO_FILTERS);
  });

  it("reads each filter and drops what is not valid, never failing", () => {
    const got = parseFilters({ range: "30d", severity: ["high", "bogus", "high", "low"], state: "reviewed", verdict: ["none", "x"], ai: ["proposed_tp"], rule: "r-1", kind: "ip", value: "10.0.0.1" });
    expect(got).toEqual({ range: "30d", start: null, end: null, severity: ["high", "low"], state: ["reviewed"], verdict: ["none"], ai: ["proposed_tp"], rule: "r-1", kind: "ip", value: "10.0.0.1" });
    expect(parseFilters({ range: "5y" }).range).toBe("7d");
    expect(parseFilters({ range: ["24h", "90d"] }).range).toBe("24h");
  });

  it("needs a kind and a value together, within the server's bounds", () => {
    expect(parseFilters({ kind: "ip" }).kind).toBeNull();
    expect(parseFilters({ value: "x" }).value).toBeNull();
    expect(parseFilters({ kind: "phone", value: "x" })).toMatchObject({ kind: null, value: null });
    expect(parseFilters({ kind: "host", value: "x".repeat(300) }).value).toHaveLength(300);
    expect(parseFilters({ kind: "host", value: "x".repeat(301) }).value).toBeNull();
    expect(parseFilters({ kind: "host", value: "a\u0000b" }).value).toBeNull();
    expect(parseFilters({ rule: "r".repeat(200) }).rule).toHaveLength(200);
    expect(parseFilters({ rule: "r".repeat(201) }).rule).toBeNull();
    expect(parseFilters({ rule: "" }).rule).toBeNull();
    expect(parseFilters({ rule: "a\u0000" }).rule).toBeNull();
  });
});

describe("the custom span (the server's rules)", () => {
  it("needs both days, written YYYY-MM-DD and real", () => {
    expect(span("2026-10-01", null)).toBeNull();
    expect(span("2026-10-01", "yesterday")).toBeNull();
    expect(span("2026-02-31", "2026-03-01")).toBeNull();
    expect(span("2026-10-1", "2026-10-02")).toBeNull();
    expect(span("2026-10-01", "2026-10-03")).toEqual(["2026-10-01", "2026-10-03"]);
  });

  it("sorts the days, keeps them within 2020 to 2100 and at most 366 days (the last ones)", () => {
    expect(span("2026-10-03", "2026-10-01")).toEqual(["2026-10-01", "2026-10-03"]);
    expect(span("2019-05-05", "2020-01-10")).toEqual(["2020-01-01", "2020-01-10"]);
    expect(span("2099-12-01", "2101-01-01")).toEqual(["2099-12-01", "2100-01-01"]);
    expect(span("2024-01-01", "2026-01-01")).toEqual(["2025-01-01", "2026-01-01"]);
    expect(span("2025-01-01", "2026-01-01")).toEqual(["2025-01-01", "2026-01-01"]); // 366 days exactly stays
  });

  it("wins over the range, and the address writes the span, not the range", () => {
    const f = parseFilters({ range: "90d", start: "2026-10-01", end: "2026-10-03" });
    expect(f).toMatchObject({ range: "90d", start: "2026-10-01", end: "2026-10-03" });
    expect(toSearch(f)).toEqual({ start: "2026-10-01", end: "2026-10-03" });
    expect(toQuery(f)).toMatchObject({ range: "90d", start: "2026-10-01", end: "2026-10-03" });
  });
});

describe("the address", () => {
  it("writes only what differs from the default, as the classic page does", () => {
    expect(toSearch(NO_FILTERS)).toEqual({});
    expect(toSearch({ ...NO_FILTERS, range: "7d" })).toEqual({});
    expect(toSearch({ ...NO_FILTERS, range: "24h", severity: ["high"], rule: "r", kind: "ip", value: "1.2.3.4" })).toEqual({ range: "24h", severity: ["high"], rule: "r", kind: "ip", value: "1.2.3.4" });
  });

  it("round-trips any filters through the query string", () => {
    const list = (names: string[]) => fc.subarray(names);
    const arbitrary = fc.record({
      range: fc.constantFrom("24h", "7d", "30d", "90d"),
      severity: list(["critical", "high", "medium", "low"]),
      state: list(["unreviewed", "follow_up", "changed_since_review", "reviewed"]),
      verdict: list(["true_positive", "benign_expected", "none"]),
      ai: list(["proposed_tp", "working", "none"]),
      rule: fc.option(fc.string({ minLength: 1, maxLength: 30 }).filter((s) => !s.includes("\u0000")), { nil: null }),
      entity: fc.option(fc.tuple(fc.constantFrom("ip", "host", "domain", "user"), fc.string({ minLength: 1, maxLength: 30 }).filter((s) => !s.includes("\u0000"))), { nil: null }),
    });
    fc.assert(
      fc.property(arbitrary, (a) => {
        const f: Filters = { range: a.range as Filters["range"], start: null, end: null, severity: a.severity, state: a.state, verdict: a.verdict, ai: a.ai, rule: a.rule, kind: a.entity?.[0] ?? null, value: a.entity?.[1] ?? null };
        const again = parseFilters(parseSearch(stringifySearch(toSearch(f))));
        expect(again).toEqual(f);
      }),
    );
  });

  it("sends the API the range always, and lists only when they hold something", () => {
    expect(toQuery(NO_FILTERS)).toEqual({ range: "7d" });
    expect(toQuery({ ...NO_FILTERS, severity: ["high"], rule: "r", kind: "host", value: "pc" })).toEqual({ range: "7d", severity: ["high"], rule: "r", kind: "host", value: "pc" });
  });
});

describe("halves that mean nothing", () => {
  it("a span needs both days and an entity needs both parts, in the address and to the API", () => {
    const half: Filters = { ...NO_FILTERS, range: "30d", start: "2026-10-01", end: null, kind: "ip", value: null };
    expect(toSearch(half)).toEqual({ range: "30d" });
    expect(toQuery(half)).toEqual({ range: "30d" });
    expect(toSearch({ ...NO_FILTERS, start: null, end: "2026-10-01", kind: null, value: "x" })).toEqual({});
    expect(toQuery({ ...NO_FILTERS, start: null, end: "2026-10-01", kind: null, value: "x" })).toEqual({ range: "7d" });
    expect(chips({ ...NO_FILTERS, kind: "ip", value: null }, { severity: {}, state: {}, verdict: {}, ai: {} })).toEqual([]);
    expect(chips({ ...NO_FILTERS, kind: null, value: "x" }, { severity: {}, state: {}, verdict: {}, ai: {} })).toEqual([]);
  });

  it("verdicts and assessments reach the API when there are some, and not otherwise", () => {
    expect(toQuery({ ...NO_FILTERS, verdict: ["none"], ai: ["working", "none"] })).toEqual({ range: "7d", verdict: ["none"], ai: ["working", "none"] });
    expect(toSearch({ ...NO_FILTERS, verdict: ["none"], ai: ["working"] })).toEqual({ verdict: ["none"], ai: ["working"] });
    expect(toQuery(NO_FILTERS)).toEqual({ range: "7d" });
  });

  it("a day is written YYYY-MM-DD with nothing before or after it", () => {
    expect(span("x2026-10-01", "2026-10-02")).toBeNull();
    expect(span("2026-10-01x", "2026-10-02")).toBeNull();
    expect(span("2026-10-01", "2026-10-02 ")).toBeNull();
    expect(span("2026-10-01", "2026-10-02")).toEqual(["2026-10-01", "2026-10-02"]);
  });

  it("an unknown range is the default, a known one is kept, and the span's words are the address's", () => {
    expect(parseFilters({ range: "" }).range).toBe("7d");
    expect(parseFilters({ range: "24h" }).range).toBe("24h");
    expect(parseFilters({ kind: "domain", value: "example.com" })).toMatchObject({ kind: "domain", value: "example.com" });
  });
});

describe("narrowing and chips", () => {
  it("adds a value once, replaces the rule and the entity, and never changes the span", () => {
    const f = { ...NO_FILTERS, range: "30d" as const, severity: ["high"] };
    expect(adding(f, "severity", "low").severity).toEqual(["high", "low"]);
    expect(adding(f, "severity", "high").severity).toEqual(["high"]);
    expect(adding(f, "rule", "r-9")).toMatchObject({ rule: "r-9", range: "30d" });
    expect(adding(f, "entity", "10.0.0.1", "ip")).toMatchObject({ kind: "ip", value: "10.0.0.1" });
    expect(adding(f, "state", "reviewed").state).toEqual(["reviewed"]);
  });

  it("makes one chip per active filter, each with the filters that remove it", () => {
    const f: Filters = { ...NO_FILTERS, severity: ["high", "low"], state: ["follow_up"], rule: "r", kind: "ip", value: "1.1.1.1" };
    const titles = { severity: {}, state: { follow_up: "Follow-up" }, verdict: {}, ai: {} };
    const got = chips(f, titles);
    expect(got.map((c) => `${c.name}: ${c.value}`)).toEqual(["severity: high", "severity: low", "state: Follow-up", "rule: r", "ip: 1.1.1.1"]);
    expect(got[0]?.without.severity).toEqual(["low"]);
    expect(got[2]?.without.state).toEqual([]);
    expect(got[3]?.without.rule).toBeNull();
    expect(got[4]?.without).toMatchObject({ kind: null, value: null });
    expect(chips(NO_FILTERS, titles)).toEqual([]);
    expect(chips({ ...NO_FILTERS, verdict: ["rule_false_positive"] }, titles)[0]?.value).toBe("rule false positive");
  });

  it("clears everything but the span", () => {
    const f: Filters = { ...NO_FILTERS, range: "90d", severity: ["high"], verdict: ["none"], ai: ["working"], state: ["reviewed"], rule: "r", kind: "ip", value: "x" };
    expect(cleared(f)).toEqual({ ...NO_FILTERS, range: "90d" });
  });
});
