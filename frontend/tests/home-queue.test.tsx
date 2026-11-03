// AR4: Home is the case-first queue. ARGUS's cases that need a person (suggested and changed first,
// each with its verdict, devices and why), the patterns ARGUS recommends closing one at a time, the
// single investigations in Needs attention that belong to no case; the notified, still active cases
// are a count. The new and known numbers are the API's own, the same as the Inbox and the dashboard.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import type { PatternBriefOut, PatternCloseOut, PatternSummaryOut, QueueCaseOut, QueueOut, QueueSingleOut } from "../src/client/types.gen";
import { BASE, ID, ID2, ID3, investigation, mockApi, renderApp, sent, server, sessionWith, shellHandlers, stanceOf } from "./helpers";

mockApi();

const CASE1 = "c1c1c1c1-0000-4000-8000-000000000001";
const CASE2 = "c2c2c2c2-0000-4000-8000-000000000002";
const CASE3 = "c3c3c3c3-0000-4000-8000-000000000003";

function queueCase(more: Partial<QueueCaseOut>): QueueCaseOut {
  return {
    id: CASE1, number: 12, title: "Beaconing from a hostel laptop", state: "suspected", severity: "high", kind: "suggested",
    why: "Suggested by ARGUS from evidence across investigations. Nothing is open until a person confirms it.", changes: [], notified_at: null,
    stance: stanceOf({ kind: "recommends", outcome: "true_positive", confidence: 0.8, source: "the AI investigator", assessment_id: 5 }),
    devices: ["10.0.0.1", "10.0.0.2"], devices_total: 2, investigations: 3, new_members: 0, unreviewed: 2, alerts: 41, last_alert_at: "2026-10-26T08:00:00Z",
    waiting_for_approval: 0, first_investigation_id: ID, ...more,
  };
}

function single(id: string, name: string, more: Partial<QueueSingleOut> = {}): QueueSingleOut {
  return { investigation: investigation(id, { rule_name: name }), stance: stanceOf({ kind: "reading", outcome: "inconclusive", confidence: 0.4, why: "the evidence did not settle it" }), ...more };
}

function queue(more: Partial<QueueOut> = {}): QueueOut {
  const cases = more.cases_total ?? more.cases?.length ?? 0;
  const singles = more.singles_total ?? more.singles?.length ?? 0;
  return { cases: [], cases_total: 0, singles: [], singles_total: 0, notified_cases: 0, order: [], order_total: more.order?.length ?? cases + singles, ...more };
}

const BRIEF = (n: number, more: Partial<PatternBriefOut> = {}): PatternBriefOut => ({
  pattern: String(n).repeat(64).slice(0, 64), day: "2026-10-29", rule_id: `rule-${n}`, rule_name: `Rule ${n}`, investigations: 3, alerts: 20, covered: 2,
  outcome: "benign_expected", confidence: 0.9, source: "the AI investigator", examples: [ID, ID2, ID3], ...more,
});
const SUMMARY = (items: PatternBriefOut[], more: Partial<PatternSummaryOut> = {}): PatternSummaryOut => ({ total: items.length, investigations: items.reduce((n, b) => n + b.covered, 0), items, ...more });
const CLOSING = (b: PatternBriefOut, more: Partial<PatternCloseOut> = {}): PatternCloseOut => ({
  brief: b,
  members: [
    { investigation_id: ID, version: 3, latest_review: null },
    { investigation_id: ID2, version: 2, latest_review: 4 },
  ],
  ...more,
});

const reads = (q: QueueOut, patterns: PatternSummaryOut = SUMMARY([])) =>
  server.use(http.get(`${BASE}/api/v1/queue`, () => HttpResponse.json(q)), http.get(`${BASE}/api/v1/patterns/summary`, () => HttpResponse.json(patterns)));

const headings = () => screen.getAllByRole("heading", { level: 2 }).map((h) => h.textContent ?? "");

describe("Home, the queue", () => {
  it("lists what needs a person in order: the cases, the patterns to close, the single investigations", async () => {
    reads(queue({ cases: [queueCase({})], cases_total: 1, singles: [single(ID3, "A lone scan")], singles_total: 1 }), SUMMARY([BRIEF(1)]));
    renderApp("/");
    await screen.findByTestId("queue-case");
    await screen.findByTestId("queue-single");
    await screen.findByTestId("pattern-recommendation");
    expect(headings().filter((h) => /^\d\. /.test(h))).toEqual(["1. ARGUS's cases that need a person", "2. Patterns ARGUS recommends closing", "3. Single investigations that need attention"]);
  });

  it("shows each case with ARGUS's verdict in one line, its devices, its severity and why it is here", async () => {
    reads(queue({ cases: [queueCase({})], cases_total: 1 }));
    renderApp("/");
    const item = await screen.findByTestId("queue-case");
    expect(within(item).getByRole("link", { name: /Case 12: Beaconing from a hostel laptop/ }).getAttribute("href")).toBe(`/app/cases/${CASE1}`);
    expect(within(item).getByText("Suggested by ARGUS")).toBeTruthy();
    expect(within(item).getByText("high")).toBeTruthy();
    expect(within(item).getByTestId("queue-stance").textContent).toBe("ARGUS recommends: True positive (80%)");
    expect(within(item).getByText(/Suggested by ARGUS from evidence across investigations/)).toBeTruthy();
    expect(item.textContent).toContain("Devices: 10.0.0.1, 10.0.0.2");
    expect(item.textContent).toContain("3 investigations, 2 to review · 41 alerts");
    expect(within(item).getByRole("link", { name: "Review the first investigation" }).getAttribute("href")).toBe(`/app/investigations/${ID}`);
    expect(within(item).getByRole("link", { name: "Open the case" }).getAttribute("href")).toBe(`/app/cases/${CASE1}`);
  });

  it("says a reading is a reading, and nothing is nothing", async () => {
    reads(
      queue({
        cases: [
          queueCase({ stance: stanceOf({ kind: "reading", outcome: "true_positive", confidence: 0.7, why: "a safety check needs a person" }) }),
          queueCase({ id: CASE2, number: 13, stance: stanceOf() }),
        ],
        cases_total: 2,
      }),
    );
    renderApp("/");
    await screen.findAllByTestId("queue-case");
    expect(screen.getAllByTestId("queue-stance").map((e) => e.textContent)).toEqual(["ARGUS's reading: True positive (70%), not proposed because a safety check needs a person", "ARGUS has no reading of this yet"]);
  });

  it("keeps the order the API gives: suggested and changed cases first, then the others", async () => {
    reads(
      queue({
        cases: [
          queueCase({ id: CASE1, number: 3, title: "Changed one", kind: "changed", state: "open", why: "Something changed since the owner was told.", changes: ["a new flagged destination: 203.0.113.9"], notified_at: "2026-10-20T04:00:00Z" }),
          queueCase({ id: CASE2, number: 4, title: "Suggested one" }),
          queueCase({ id: CASE3, number: 5, title: "Unowned one", kind: "unowned", state: "open", why: "A person confirmed it and nobody owns it yet." }),
        ],
        cases_total: 3,
      }),
    );
    renderApp("/");
    const items = await screen.findAllByTestId("queue-case");
    expect(items.map((i) => within(i).getByRole("link", { name: /^Case/ }).textContent)).toEqual(["Case 3: Changed one", "Case 4: Suggested one", "Case 5: Unowned one"]);
    expect(within(items[0] as HTMLElement).getByText("Changed since the owner was told")).toBeTruthy();
    expect(within(items[0] as HTMLElement).getByRole("list", { name: "What changed" }).textContent).toContain("a new flagged destination: 203.0.113.9");
    expect(within(items[0] as HTMLElement).getByText(/owner told/)).toBeTruthy();
    expect(within(items[2] as HTMLElement).getByText("Nobody owns it")).toBeTruthy();
  });

  it("counts a notified case that is still active as a number with a link, never as work", async () => {
    reads(queue({ notified_cases: 4 }));
    renderApp("/");
    const totals = await screen.findByTestId("totals");
    await within(totals).findByText("3"); // /counts: known
    const known = within(totals).getByRole("link", { name: /Notified, still active/ });
    expect(known.textContent).toBe("Notified, still active: 3");
    expect(known.getAttribute("href")).toBe("/app/inbox?view=known");
    expect(within(totals).getByRole("link", { name: /Needs attention/ }).textContent).toBe("Needs attention: 6");
    expect(within(totals).getByRole("link", { name: /Needs attention/ }).getAttribute("href")).toBe("/app/inbox?view=attention");
    expect(totals.textContent).toContain("(4 cases:");
    expect(within(totals).getByRole("link", { name: "the list" }).getAttribute("href")).toBe("/app/cases?view=notified");
    expect(screen.queryByTestId("queue-case")).toBeNull();
    expect(screen.getByText("No case needs a person now.")).toBeTruthy();
  });

  it("uses the API's own counts: the numbers are /counts', not the queue's", async () => {
    server.use(http.get(`${BASE}/api/v1/counts`, () => HttpResponse.json({ attention: 1234, known: 56, open: 9, follow_up: 0, changed: 0, reviewed: 0, reviewed_today: 0, all: 99 })));
    reads(queue({ cases: [queueCase({})], cases_total: 1 }));
    renderApp("/");
    const totals = await screen.findByTestId("totals");
    await within(totals).findByText("1,234");
    expect(within(totals).getByText("56")).toBeTruthy();
    expect(sent("GET", "/api/v1/counts").length).toBeGreaterThan(0);
  });

  it("says when nothing is single, and when there are more than are shown", async () => {
    reads(queue({ singles: [single(ID3, "A lone scan"), single(ID2, "Another")], singles_total: 87 }));
    renderApp("/");
    const list = await screen.findByRole("list", { name: "Single investigations" });
    expect(within(list).getAllByTestId("queue-single")).toHaveLength(2);
    expect(screen.getByText(/The 2 first of 87 are shown\./)).toBeTruthy();
    expect(screen.getByRole("link", { name: "All 87 in the Inbox, in the same order" }).getAttribute("href")).toBe("/app/inbox?view=attention&sort=queue");
    expect(within(list).getAllByTestId("queue-stance")[0]?.textContent).toBe("ARGUS's reading: Inconclusive (40%), not proposed because the evidence did not settle it");
    expect(within(list).getByRole("link", { name: "A lone scan" }).getAttribute("href")).toBe(`/app/investigations/${ID3}`);
  });

  it("says every investigation in Needs attention is in a case when none is single", async () => {
    reads(queue());
    renderApp("/");
    expect(await screen.findByText("Every investigation in Needs attention is in a case above.")).toBeTruthy();
  });

  it("says when the queue cannot be read, with a way to try again, and the rest of Home works", async () => {
    server.use(http.get(`${BASE}/api/v1/queue`, () => HttpResponse.json({ detail: "boom", code: "internal" }, { status: 500 })));
    renderApp("/");
    expect(await screen.findByText(/The queue could not be shown/)).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Home" })).toBeTruthy();
    expect(screen.getByRole("region", { name: "Cases" })).toBeTruthy();
  });

  it("shows a hostile title and device as text", async () => {
    const hostile = '<img src=x onerror="window.__pwned=1">';
    reads(queue({ cases: [queueCase({ title: hostile, devices: [hostile], devices_total: 1, why: hostile })], cases_total: 1, singles: [single(ID3, hostile)], singles_total: 1 }));
    const { container } = renderApp("/");
    await screen.findByTestId("queue-case");
    expect(container.querySelector("img")).toBeNull();
  });
});

describe("Home, the end of the queue is told honestly", () => {
  it("says the cases beyond the first ones are in the list of the queue's cases, and counts them all", async () => {
    reads(queue({ cases: [queueCase({})], cases_total: 41, singles: [single(ID3, "A lone scan")], singles_total: 17006, order_total: 17100 }));
    renderApp("/");
    const summary = await screen.findByTestId("queue-summary");
    expect(summary.textContent).toBe("41 cases and 17,006 single investigations need a person (17,100 investigations to look at).");
    expect(screen.getByText(/The first 1 of 41 are shown\./)).toBeTruthy();
    expect(screen.getByRole("link", { name: "All 41 cases that need a person" }).getAttribute("href")).toBe("/app/cases?view=queue");
  });

  it("says every investigation in Needs attention is in a case above only when the totals say so", async () => {
    reads(queue({ cases: [queueCase({})], cases_total: 1 }));
    renderApp("/");
    expect(await screen.findByText("Every investigation in Needs attention is in a case above.")).toBeTruthy();
  });

  it("does not say it when some of the cases are not above", async () => {
    reads(queue({ cases: [queueCase({})], cases_total: 31, singles_total: 0 }));
    renderApp("/");
    await screen.findByTestId("queue-case");
    expect(screen.queryByText("Every investigation in Needs attention is in a case above.")).toBeNull();
    const note = await screen.findByText(/Every investigation in Needs attention is in one of the 31 cases; the first 1 are above/);
    expect(within(note).getByRole("link", { name: "cases list" }).getAttribute("href")).toBe("/app/cases?view=queue");
  });

  it("never says the queue is empty while the count of Needs attention says it is not", async () => {
    server.use(http.get(`${BASE}/api/v1/counts`, () => HttpResponse.json({ attention: 3, known: 0, open: 3, follow_up: 0, changed: 0, reviewed: 0, reviewed_today: 0, all: 9 })));
    reads(queue());
    renderApp("/");
    const warning = await screen.findByTestId("queue-disagrees");
    expect(warning.textContent).toContain("3 investigations are in Needs attention");
    expect(within(warning).getByRole("link", { name: "Inbox" }).getAttribute("href")).toBe("/app/inbox?view=attention&sort=queue");
  });

  it("has no warning and no summary when nothing needs a person and the counts agree", async () => {
    server.use(http.get(`${BASE}/api/v1/counts`, () => HttpResponse.json({ attention: 0, known: 0, open: 0, follow_up: 0, changed: 0, reviewed: 0, reviewed_today: 0, all: 9 })));
    reads(queue());
    renderApp("/");
    await screen.findByText("No case needs a person now.");
    await screen.findByText("Every investigation in Needs attention is in a case above.");
    expect(screen.queryByTestId("queue-disagrees")).toBeNull();
    expect(screen.queryByTestId("queue-summary")).toBeNull();
  });

  it("names the new work in a case someone owns, with how many", async () => {
    reads(queue({ cases: [queueCase({ id: CASE2, number: 9, title: "Owned", kind: "new", state: "assigned", why: "2 new investigations in a case someone owns.", new_members: 2 })], cases_total: 1 }));
    renderApp("/");
    const item = await screen.findByTestId("queue-case");
    expect(within(item).getByText("New work in a worked case")).toBeTruthy();
    expect(item.textContent).toContain("2 new investigations in a case someone owns.");
  });
});

describe("Home, the patterns to close", () => {
  it("reads a lean summary, never the Patterns page's sample", async () => {
    reads(queue(), SUMMARY([BRIEF(2)]));
    renderApp("/");
    await screen.findByRole("region", { name: "Pattern: Rule 2" });
    expect(sent("GET", "/api/v1/patterns/summary").length).toBeGreaterThan(0);
    expect(sent("GET", "/api/v1/patterns").filter((r) => !r.path.includes("/summary"))).toHaveLength(0);
  });

  it("shows the patterns ARGUS recommends closing one at a time, with real totals", async () => {
    reads(queue(), SUMMARY([BRIEF(2), BRIEF(3)], { total: 14, investigations: 4100 }));
    renderApp("/");
    const count = await screen.findByTestId("pattern-count");
    expect(count.textContent).toContain("pattern 1 of 2, the 2 largest of 14");
    expect(count.textContent).toContain("Together the 14 patterns cover 4,100 investigations.");
    const cards = screen.getAllByRole("region", { name: /^Pattern:/ });
    expect(cards).toHaveLength(1);
    expect(cards[0]?.getAttribute("aria-label")).toBe("Pattern: Rule 2");
    expect(within(cards[0] as HTMLElement).getByTestId("pattern-recommendation").textContent).toBe("ARGUS recommends: Benign: expected activity (90%) for 2 of 3 investigations (from the AI investigator). The other 1 have no proposal yet, so a close leaves them out.");
  });

  it("says nothing about the rest when every investigation of the pattern has a proposal", async () => {
    reads(queue(), SUMMARY([BRIEF(2, { investigations: 5, covered: 5 })]));
    renderApp("/");
    const text = (await screen.findByTestId("pattern-recommendation")).textContent ?? "";
    expect(text).toContain("for 5 of 5 investigations");
    expect(text).not.toContain("no proposal yet");
  });

  it("leaves a pattern for now and shows the next one", async () => {
    const user = userEvent.setup();
    reads(queue(), SUMMARY([BRIEF(2), BRIEF(3)]));
    renderApp("/");
    await screen.findByRole("region", { name: "Pattern: Rule 2" });
    await user.click(screen.getByRole("button", { name: "Leave it for now, show the next pattern" }));
    expect(await screen.findByRole("region", { name: "Pattern: Rule 3" })).toBeTruthy();
    expect(screen.queryByRole("region", { name: "Pattern: Rule 2" })).toBeNull();
    expect(screen.getByText(/pattern 2 of 2/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Leave it for now, show the next pattern" }));
    expect(await screen.findByRole("region", { name: "Pattern: Rule 2" })).toBeTruthy(); // round again
  });

  it("reads the members only when Close is pressed, and closes only those ARGUS covers, after showing the exact request", async () => {
    const user = userEvent.setup();
    const b = BRIEF(2);
    server.use(
      http.get(`${BASE}/api/v1/patterns/closing`, ({ request }) => {
        const url = new URL(request.url);
        expect(url.searchParams.get("pattern")).toBe(b.pattern);
        expect(url.searchParams.get("day")).toBe("2026-10-29");
        return HttpResponse.json(CLOSING(b));
      }),
      http.post(`${BASE}/api/v1/patterns/review`, () => HttpResponse.json({ reviewed: 2, changed: 0 })),
    );
    reads(queue(), SUMMARY([b]));
    renderApp("/");
    const card = await screen.findByRole("region", { name: "Pattern: Rule 2" });
    expect(sent("GET", "/api/v1/patterns/closing")).toHaveLength(0); // no member list until it is asked for
    await user.click(within(card).getByRole("button", { name: "Close 2 as Benign: expected activity" }));
    const dialog = await screen.findByRole("alertdialog");
    const shown = JSON.parse(within(dialog).getByTestId("payload").textContent ?? "{}") as { outcome: string; items: { investigation_id: string; version: number; latest_review: number | null }[] };
    expect(shown.outcome).toBe("benign_expected");
    expect(shown.items).toEqual([
      { investigation_id: ID, version: 3, latest_review: null },
      { investigation_id: ID2, version: 2, latest_review: 4 },
    ]); // the third member has no proposal: not named
    await user.click(within(dialog).getByRole("button", { name: "Close 2" }));
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());
    expect(await screen.findByText("2 reviewed.", { selector: "p" })).toBeTruthy();
    const [post] = sent("POST", "/api");
    expect(JSON.parse(post?.body ?? "")).toEqual(shown);
    await waitFor(() => expect(sent("GET", "/api/v1/patterns/summary").length).toBeGreaterThanOrEqual(2)); // read again
  });

  it("says plainly when ARGUS no longer recommends closing the pattern, and reads the list again", async () => {
    const user = userEvent.setup();
    server.use(http.get(`${BASE}/api/v1/patterns/closing`, () => HttpResponse.json({ detail: "ARGUS does not recommend closing this pattern now", code: "not_found" }, { status: 404 })));
    reads(queue(), SUMMARY([BRIEF(2)]));
    renderApp("/");
    const card = await screen.findByRole("region", { name: "Pattern: Rule 2" });
    await user.click(within(card).getByRole("button", { name: /^Close 2/ }));
    expect(await within(card).findByRole("alert")).toBeTruthy();
    expect(within(card).getByRole("alert").textContent).toContain("ARGUS no longer recommends closing this pattern");
    expect(screen.queryByRole("alertdialog")).toBeNull();
    await waitFor(() => expect(sent("GET", "/api/v1/patterns/summary").length).toBeGreaterThanOrEqual(2));
  });

  it("names the newest of a larger set when the close is capped", async () => {
    const user = userEvent.setup();
    const b = BRIEF(2, { investigations: 500, covered: 450 });
    server.use(http.get(`${BASE}/api/v1/patterns/closing`, () => HttpResponse.json(CLOSING(b))));
    reads(queue(), SUMMARY([b]));
    renderApp("/");
    const card = await screen.findByRole("region", { name: "Pattern: Rule 2" });
    await user.click(within(card).getByRole("button", { name: "Close 450 as Benign: expected activity" }));
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog.textContent).toContain("the newest 2 of 450; close the rest afterwards");
  });

  it("says ARGUS recommends closing no pattern, with the link to all of them", async () => {
    reads(queue(), SUMMARY([]));
    renderApp("/");
    expect(await screen.findByText(/ARGUS recommends closing no pattern now\./)).toBeTruthy();
    expect(screen.getByRole("link", { name: "All patterns" }).getAttribute("href")).toBe("/app/patterns");
  });

  it("is not offered to an account that may only view, which is told why", async () => {
    server.use(...shellHandlers(sessionWith(["view"])));
    reads(queue(), SUMMARY([BRIEF(2)]));
    renderApp("/");
    const card = await screen.findByRole("region", { name: "Pattern: Rule 2" });
    expect(within(card).queryByRole("button", { name: /^Close/ })).toBeNull();
    expect(within(card).getByText(/Your account may view only: deciding a group needs the “review” capability/)).toBeTruthy();
  });
});
