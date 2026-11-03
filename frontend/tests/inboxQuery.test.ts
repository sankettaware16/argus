// What the Inbox's address says (lib/inboxQuery.ts).
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { effectiveSort, listQuery, parseInbox, TABS } from "../src/lib/inboxQuery";
import { titleFor } from "../src/lib/titles";

const ID = "54c802b6-fb1a-5614-a6e4-f76c773213d2";

describe("parseInbox", () => {
  it("defaults to the Needs attention view and reads each valid part", () => {
    expect(parseInbox({})).toEqual({ view: "attention" });
    expect(parseInbox({ view: "open", sort: "urgent", rule: "r-1", kind: "ip", value: "1.2.3.4", id: ID, tab: "report" })).toEqual({
      view: "open", sort: "urgent", rule: "r-1", kind: "ip", value: "1.2.3.4", id: ID, tab: "report",
    });
  });

  it("leaves out whatever is not valid, and never fails", () => {
    expect(parseInbox({ view: "everything", sort: "random", id: "not-an-id", tab: "secrets", kind: "ip" })).toEqual({ view: "attention" });
    expect(parseInbox({ id: ID.toUpperCase() })).toEqual({ view: "attention" });
    expect(parseInbox({ rule: "" }).rule).toBeUndefined();
    expect(parseInbox({ rule: "r".repeat(201) }).rule).toBeUndefined();
    expect(parseInbox({ rule: "a\u0000" }).rule).toBeUndefined();
    expect(parseInbox({ kind: "host", value: "a\u0000" }).value).toBeUndefined();
    expect(parseInbox({ kind: "host", value: "x".repeat(301) }).kind).toBeUndefined();
    expect(parseInbox({ view: ["reviewed", "all"] }).view).toBe("reviewed");
    for (const tab of TABS) expect(parseInbox({ tab }).tab).toBe(tab);
    fc.assert(fc.property(fc.dictionary(fc.string({ maxLength: 6 }), fc.oneof(fc.string(), fc.array(fc.string()))), (raw) => {
      expect(["attention", "open", "reviewed", "all"]).toContain(parseInbox(raw).view);
    }));
  });
});

describe("halves and edges", () => {
  it("a kind needs a value and a value needs a known kind, within 300 characters", () => {
    expect(parseInbox({ kind: "ip" })).toEqual({ view: "attention" });
    expect(parseInbox({ value: "x" })).toEqual({ view: "attention" });
    expect(parseInbox({ kind: "phone", value: "x" })).toEqual({ view: "attention" });
    expect(parseInbox({ kind: "ip", value: "" })).toEqual({ view: "attention" });
    expect(parseInbox({ kind: "user", value: "x".repeat(300) }).value).toHaveLength(300);
    expect(parseInbox({ kind: "user", value: "x".repeat(301) })).toEqual({ view: "attention" });
    expect(parseInbox({ rule: "r".repeat(200) }).rule).toHaveLength(200);
  });

  it("a view, a sort, a tab and an id are kept only when valid", () => {
    expect(parseInbox({ view: "nope" }).view).toBe("attention");
    expect(parseInbox({ sort: "nope" })).toEqual({ view: "attention" });
    expect(parseInbox({ tab: "nope" })).toEqual({ view: "attention" });
    expect(parseInbox({ id: ID })).toEqual({ view: "attention", id: ID });
    expect(parseInbox({ id: `${ID}0` })).toEqual({ view: "attention" });
    expect(parseInbox({ id: `x${ID}` })).toEqual({ view: "attention" });
    expect(parseInbox({ id: ID.slice(1) })).toEqual({ view: "attention" });
  });

  it("the list's query carries a rule on its own and an entity only whole", () => {
    expect(listQuery({ view: "all", rule: "r" })).toEqual({ view: "all", sort: "newest", rule: "r" });
    expect(listQuery({ view: "all", value: "x" })).toEqual({ view: "all", sort: "newest" });
    expect(listQuery({ view: "all", kind: "ip", value: "x" })).toEqual({ view: "all", sort: "newest", kind: "ip", value: "x" });
  });
});

describe("the list's query", () => {
  it("sorts newest first, the reviewed view by decision (D-095), and always says so", () => {
    expect(effectiveSort({ view: "attention" })).toBe("newest");
    expect(effectiveSort({ view: "reviewed" })).toBe("reviewed");
    expect(effectiveSort({ view: "open", sort: "oldest" })).toBe("oldest");
    expect(listQuery({ view: "all" })).toEqual({ view: "all", sort: "newest" });
    expect(listQuery({ view: "reviewed" })).toEqual({ view: "reviewed", sort: "reviewed" });
  });

  it("asks for the queue's order when the address says so, the order Home walks (AR4 review)", () => {
    expect(parseInbox({ view: "attention", sort: "queue" })).toEqual({ view: "attention", sort: "queue" });
    expect(effectiveSort({ view: "attention", sort: "queue" })).toBe("queue");
    expect(listQuery({ view: "attention", sort: "queue" })).toEqual({ view: "attention", sort: "queue" });
  });

  it("keeps the decision sort to the reviewed view, and sends the rule and the thing found", () => {
    expect(listQuery({ view: "open", sort: "reviewed" }).sort).toBe("newest");
    expect(listQuery({ view: "all", rule: "r", kind: "host", value: "pc", id: ID, tab: "alerts" })).toEqual({ view: "all", sort: "newest", rule: "r", kind: "host", value: "pc" });
    expect(listQuery({ view: "all", kind: "host" })).toEqual({ view: "all", sort: "newest" });
  });
});

describe("titles", () => {
  it("names each page, an investigation too, and says when there is no such page", () => {
    expect(titleFor("/")).toBe("Home");
    expect(titleFor("/dashboard")).toBe("Dashboard");
    expect(titleFor("/dashboard/")).toBe("Dashboard");
    expect(titleFor("/inbox")).toBe("Inbox");
    expect(titleFor("/proposals")).toBe("Proposals");
    expect(titleFor("/design")).toBe("Design system");
    expect(titleFor(`/investigations/${ID}`)).toBe("Investigation");
    expect(titleFor("/investigations")).toBe("Not found");
    expect(titleFor(`/investigations/${ID}/x`)).toBe("Not found");
    expect(titleFor("/nowhere")).toBe("Not found");
    expect(titleFor("")).toBe("Home");
  });
});
