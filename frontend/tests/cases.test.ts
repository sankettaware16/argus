// The case pages' pure parts: the list's address, the words, one planned write in a line, and what a
// "Check more" value may be.
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { entityProblem, entityShape } from "../src/lib/checkEntity";
import { APPROVAL_KIND_HINTS, APPROVAL_STATUS_TONE, APPROVAL_STATUS_WORDS, CASE_STATE_MEANING, CASE_STATE_TONE, CASE_STATE_WORDS, CASE_VIEW_HINTS, CASE_VIEW_TITLES, CASE_VIEWS, caseStateWord, casePath, casesQuery, describeWrite, parseCases, REASON_LABELS, reasonLabel } from "../src/lib/cases";
import { titleFor } from "../src/lib/titles";

describe("the address of the case list", () => {
  it("keeps a view it knows and a word, and drops the rest", () => {
    expect(parseCases({})).toEqual({ view: "active" });
    expect(parseCases({ view: "mine", q: " beacon " })).toEqual({ view: "mine", q: "beacon" });
    expect(parseCases({ view: ["closed", "mine"] })).toEqual({ view: "closed" });
    expect(parseCases({ view: "nonsense", q: "" })).toEqual({ view: "active" });
    expect(parseCases({ q: "x".repeat(121) })).toEqual({ view: "active" });
    expect(parseCases({ q: "x".repeat(120) })).toEqual({ view: "active", q: "x".repeat(120) });
    for (const view of CASE_VIEWS) expect(parseCases({ view })).toStrictEqual({ view });
    expect(parseCases({ q: "a\u0000b" })).toEqual({ view: "active" });
    expect(parseCases({ view: { __proto__: "x" } as unknown as string })).toEqual({ view: "active" });
  });

  it("asks for a number alone across every view, and for any other text as a word of the title", () => {
    expect(casesQuery({ view: "closed" })).toStrictEqual({ view: "closed" });
    expect(casesQuery({ view: "mine", q: "12" })).toStrictEqual({ view: "all", number: 12 });
    expect(casesQuery({ view: "mine", q: "#12" })).toStrictEqual({ view: "all", number: 12 });
    expect(casesQuery({ view: "mine", q: "1" })).toStrictEqual({ view: "all", number: 1 });
    expect(casesQuery({ view: "mine", q: "999999999" })).toStrictEqual({ view: "all", number: 999999999 });
    expect(casesQuery({ view: "mine", q: "0" })).toStrictEqual({ view: "mine", q: "0" });
    expect(casesQuery({ view: "mine", q: "12 beacon" })).toStrictEqual({ view: "mine", q: "12 beacon" });
    expect(casesQuery({ view: "active", q: "9999999999" })).toStrictEqual({ view: "active", q: "9999999999" });
    // text that Number() would read as a number, but is not a case number
    for (const q of ["0x10", "1e5", "1.5", "5e", "beacon12", "12beacon", "#", "##12"]) {
      expect(casesQuery({ view: "mine", q }), q).toStrictEqual({ view: "mine", q });
    }
  });

  it("never fails on any address", () => {
    fc.assert(
      fc.property(fc.dictionary(fc.string(), fc.oneof(fc.string(), fc.array(fc.string()))), (raw) => {
        const parsed = parseCases(raw);
        expect(CASE_VIEWS).toContain(parsed.view);
        if (parsed.q !== undefined) expect(parsed.q.length).toBeLessThanOrEqual(120);
      }),
    );
  });
});

describe("the words", () => {
  it("name every state and every closure reason, and say so for one they do not know", () => {
    for (const state of ["suspected", "open", "assigned", "contained", "closed"]) {
      expect(CASE_STATE_WORDS[state]).toBeTruthy();
      expect(CASE_STATE_MEANING[state]).toMatch(/\.$/);
    }
    expect(caseStateWord("open")).toBe("Open");
    expect(caseStateWord("<b>")).toBe("A state this page does not know");
    expect(Object.keys(REASON_LABELS)).toHaveLength(10);
    expect(reasonLabel("stopped_after_notice")).toBe("Stopped after the owner was told");
    expect(reasonLabel("risk_accepted")).toBe("Left as it is, by decision");
    expect(reasonLabel("whatever")).toBe("A reason this page does not know");
    expect(reasonLabel(null)).toBe("No reason");
    expect(Object.keys(APPROVAL_STATUS_WORDS)).toEqual(Object.keys(APPROVAL_STATUS_TONE));
  });

  it("keep their exact words, tones and hints", () => {
    expect(CASE_VIEW_TITLES).toEqual({ active: "Open cases", queue: "Needs a person", notified: "Notified, still active", attention: "Needs attention", mine: "Mine", suspected: "Suspected", closed: "Closed", all: "All" });
    expect(CASE_VIEW_HINTS).toEqual({
      active: "Confirmed cases that are open, assigned or contained, apart from the notified ones",
      queue: "The cases of Home's queue: suggested, changed since the owner was told, flagged, nobody's, or holding new work",
      notified: "Cases whose owner was told: tracked quietly, back in the queue only when something changes",
      attention: "Cases ARGUS wants a person to look at, or that wait for an approval",
      mine: "Cases you own",
      suspected: "Cases ARGUS suspects from its own proposals; a person's true-positive verdict confirms one",
      closed: "Cases that were closed",
      all: "Every case",
    });
    expect(CASE_STATE_TONE).toEqual({ suspected: "neutral", open: "warn", assigned: "info", contained: "ok", closed: "neutral" });
    expect(REASON_LABELS).toEqual({
      remediated_verified: "Fixed, and shown quiet",
      remediated_unverified: "Fixed, as its owner says",
      risk_accepted: "Left as it is, by decision",
      attempt_no_impact: "An attempt that did not work",
      rule_false_positive: "The rule was wrong",
      benign_expected: "Benign: expected activity",
      benign_policy: "Benign: allowed by policy",
      duplicate: "A duplicate",
      created_in_error: "Opened by mistake",
      stopped_after_notice: "Stopped after the owner was told",
    });
    expect(APPROVAL_STATUS_WORDS).toEqual({ pending: "Waiting", approved: "Approved", rejected: "Rejected", expired: "Expired", stale: "Out of date" });
    expect(APPROVAL_STATUS_TONE).toEqual({ pending: "warn", approved: "ok", rejected: "danger", expired: "neutral", stale: "neutral" });
    expect(APPROVAL_KIND_HINTS).toEqual({
      closure: "Closing the case",
      merge: "Merging the case into another",
      compensating: "Undoing a change ARGUS made in Kibana",
      resend: "Sending a Kibana change again, after its first try left no answer",
      reconfirm: "Confirming a closure again, because something changed before it was sent",
    });
  });

  it("gives a case its own address", () => {
    expect(casePath("c1c1c1c1-0000-4000-8000-000000000001")).toBe("/cases/c1c1c1c1-0000-4000-8000-000000000001");
  });

  it("titles the pages", () => {
    expect(titleFor("/cases")).toBe("Cases");
    expect(titleFor("/cases/c1c1c1c1-0000-4000-8000-000000000001")).toBe("Case");
    expect(titleFor("/approvals")).toBe("Approvals");
  });
});

describe("one planned write in a line", () => {
  it("says its class, its operation and what it sets", () => {
    expect(describeWrite({ class: "W3", op: "close", payload: { status: "closed", severity: "high", argus_tags: ["argus", "argus:closed"] } })).toBe("W3 close: status closed; severity high; ARGUS tags argus, argus:closed");
    expect(describeWrite({ class: "W3", op: "comment", payload: { template: "closed", params: { reason: "benign_expected" } } })).toBe("W3 comment: the comment “closed”");
    expect(describeWrite({ class: "W1", op: "create", payload: { title: "[ARGUS 1] t", status: "open" } })).toBe("W1 create: status open; title [ARGUS 1] t");
  });

  it("shows only the tags that are text, and nothing from a payload that is not an object", () => {
    expect(describeWrite({ class: "W2", op: "update", payload: { argus_tags: ["a", 3, null, "b"] } })).toBe("W2 update: ARGUS tags a, b");
    expect(describeWrite({ class: "W2", op: "update", payload: { argus_tags: "a" } })).toBe("W2 update");
    expect(describeWrite({ class: "W2", op: "update", payload: null })).toBe("W2 update");
    expect(describeWrite({ class: "W2", op: "update", payload: ["status"] })).toBe("W2 update");
  });

  it("reads anything without failing", () => {
    expect(describeWrite(null)).toBe("A write this page cannot read");
    expect(describeWrite("x")).toBe("A write this page cannot read");
    expect(describeWrite({})).toBe("? ?");
    expect(describeWrite({ class: 3, op: [], payload: "x" })).toBe("? ?");
    fc.assert(fc.property(fc.anything(), (w) => typeof describeWrite(w) === "string"));
  });
});

describe("what a Check more value may be", () => {
  it("is an address or a domain in printable ASCII", () => {
    expect(entityShape("203.0.113.9")).toBe("address");
    expect(entityShape(" 203.0.113.9 ")).toBe("address");
    expect(entityShape("2001:db8::1")).toBe("address");
    expect(entityShape("::1")).toBe("address");
    expect(entityShape("Example.ORG.")).toBe("domain");
    expect(entityShape("a.b-c.example")).toBe("domain");
    for (const good of ["0.0.0.0", "5.5.5.5", "55.55.55.55", "100.199.99.9", "200.249.250.255", "255.254.253.252"]) {
      expect(entityShape(good), good).toBe("address");
    }
    for (const bad of ["010.1.1.1", "1.2.3.4.5", "256.1.1.1", "300.1.1.1", "1.2.3.256", "1.2.3.2555", "1.2.3.", "a.1.1.1", "1.2", "ab", "1:2", "xx::1", "::1g", "x:y:z", "1:2:3:4:5:6:7:8:9:" + "z"]) {
      expect(entityShape(bad), bad).toBeNull();
    }
    const colons = (n: number): string => "1:".repeat(n) + "1";
    expect(entityShape(colons(22))).toBe("address"); // 45 characters
    expect(entityShape(colons(23))).toBeNull(); // 47
    expect(entityShape("1:2:3")).toBe("address");
    for (const bad of ["example.org1", "example.org/x", "example.org:80", "a.b", "ex ample.org", "a b.example", "_x.example"]) {
      expect(entityShape(bad), bad).toBeNull();
    }
    const label = (c: string, n: number): string => c.repeat(n);
    const longest = `${label("a", 63)}.${label("b", 63)}.${label("c", 63)}.${label("e", 61)}`;
    expect(longest).toHaveLength(253);
    expect(entityShape(longest)).toBe("domain");
    expect(entityShape(`${longest}e`)).toBeNull(); // 254
    expect(entityShape(`${label("a", 64)}.org`)).toBeNull();
    expect(entityShape("a.bc")).toBe("domain"); // 4 characters
    for (const bad of ["", "256.1.1.1", "1.2.3", "not an address", "fe80::1%eth0", "ex ample.org", "localhost", "a".repeat(254), "café.example", "x\u0000.org"]) {
      expect(entityShape(bad), bad).toBeNull();
    }
  });

  it("says why a template cannot take it", () => {
    expect(entityProblem("", "address")).toBe("Type an address or a domain.");
    expect(entityProblem("   ", "indicator")).toBe("Type an address or a domain.");
    expect(entityProblem(" \n", "address")).toBe("Type an address or a domain.");
    expect(entityProblem("nonsense words", "indicator")).toBe("That is neither an address nor a domain.");
    expect(entityProblem("example.org", "address")).toBe("This check takes an address, not a domain name.");
    expect(entityProblem("example.org", "internal")).toBe("This check takes an address, not a domain name.");
    expect(entityProblem("example.org", "indicator")).toBeNull();
    expect(entityProblem("10.0.0.1", "internal")).toBeNull();
  });

  it("agrees with itself on any text", () => {
    fc.assert(
      fc.property(fc.string(), (value) => {
        const shape = entityShape(value);
        expect(entityProblem(value, "indicator") === null).toBe(shape !== null);
        if (shape === "domain") expect(entityProblem(value, "address")).not.toBeNull();
      }),
    );
  });
});
