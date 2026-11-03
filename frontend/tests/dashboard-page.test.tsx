// The Dashboard in the app: the classic page's numbers, a table for every chart, the filters in
// the address, "since your last visit" and the threat-list tile, and what is said when a read fails.
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import type { DashboardOut, SinceOut, ThreatTileOut } from "../src/client/types.gen";
import { BASE, EMPTY_DASHBOARD, ID, ID2, must, renderApp, sent, server, setLeaveSpy, mockApi } from "./helpers";

mockApi();

const DASH: DashboardOut = {
  ...EMPTY_DASHBOARD,
  bucket: "day",
  kpis: { investigations: 50, open: 40, attention: 7, known: 5, follow_up: 2, incidents: 3, suspected: 4, reviewed: 8, assessed: 15, open_critical: 1, alerts: 1234, alerts_before: 1000, median_review_s: 12000 },
  series: [
    { at: "2026-10-24T00:00:00+05:30", counts: { critical: 1, high: 2, low: 4 } },
    { at: "2026-10-25T00:00:00+05:30", counts: { medium: 3 } },
  ],
  states: { unreviewed: 10, reviewed: 8, follow_up: 2 },
  severities: { high: 9, low: 11 },
  verdicts: { none: 12, true_positive: 3, benign_expected: 5 },
  ai: { none: 5, proposed_tp: 4, no_proposal: 11 },
  rules: [{ rule_id: "rule-0", rule: "Proxy: tunnel", investigations: 9, alerts: 700, open: 5, incidents: 1, suspected: 2, severity: "high" }],
  entities: { ip: [{ kind: "ip", value: "10.0.0.1", investigations: 4, alerts: 30, open: 2 }], host: [], domain: [], user: [] },
  incidents: [{ id: ID, rule: "Proxy: tunnel", severity: "high", alert_count: 2, last_event_at: "2026-10-25T10:00:00Z", state: "reviewed", verdict: "true_positive", ai: "proposed_tp", key_fields: [{ field: "source.ip", value: "10.0.0.1" }] }],
  open_investigations: [{ id: ID2, rule: "Other rule", severity: "critical", alert_count: 1, last_event_at: "2026-10-25T11:00:00Z", state: "follow_up", verdict: null, ai: "none", key_fields: [] }],
  rule_choices: [{ rule_id: "rule-0", rule: "Proxy: tunnel" }, { rule_id: "rule-1", rule: "Other rule" }],
  notified: [{ case_id: "c1c1c1c1-0000-4000-8000-000000000001", case_number: 12, title: "Beaconing laptop", notified_at: "2026-10-20T04:00:00Z", days: 6, alerts: 41, trend: "about the same each day", blocked: false, reminders: ["notify_again"] }],
};
const SINCE: SinceOut = { since: "2026-10-20T08:00:00Z", cap: 10_000, new_investigations: 14, new_severe: 3, reviewed_by_others: 2, new_proposals: 10_000 };
const TILE: ThreatTileOut = { examined: 12, on_a_list: 2, clear: 5, could_not_tell: 3, not_checked: 2, listed: [{ id: ID, rule: "Proxy: tunnel", severity: "high", alert_count: 2, last_event_at: null, state: "unreviewed", verdict: null, ai: "none", key_fields: [] }] };

function reads(dash: DashboardOut = DASH, since: SinceOut = SINCE, tile: ThreatTileOut = TILE) {
  server.use(
    http.get(`${BASE}/api/v1/dashboard`, () => HttpResponse.json(dash)),
    http.get(`${BASE}/api/v1/since`, () => HttpResponse.json(since)),
    http.get(`${BASE}/api/v1/dashboard/threat-lists`, () => HttpResponse.json(tile)),
  );
}

describe("the numbers", () => {
  it("are the API's, written as the classic page writes them", async () => {
    reads();
    renderApp("/dashboard");
    await screen.findByText("1,234");
    const kpis = within(screen.getByRole("list", { name: "Key numbers" }));
    const tile = (label: string) => must(kpis.getByText(label).closest("li")).textContent;
    expect(tile("Alerts")).toContain("+23% vs the span before (1,000)");
    expect(tile("Investigations")).toContain("50active in the span");
    expect(tile("Open investigations")).toContain("40");
    expect(tile("Needs attention")).toContain("7");
    expect(tile("Notified, still active")).toContain("5");
    expect(tile("Notified, still active")).toContain("known, counted and not raised (1 case)");
    expect(tile("Open critical")).toContain("1");
    expect(tile("Incidents")).toContain("3");
    expect(tile("Suspected incidents")).toContain("4");
    expect(tile("Reviewed")).toContain("8");
    expect(tile("Reviewed")).toContain("16.0% of the investigations");
    expect(tile("Time to first review")).toContain("3 h 20 min");
    expect(tile("Assessed by ARGUS")).toContain("30%");
    expect(tile("Assessed by ARGUS")).toContain("15 of 50 investigations");
  });

  it("make links that narrow the dashboard or open the Inbox, in the classic page's own address form", async () => {
    reads();
    renderApp("/dashboard?range=30d");
    await screen.findByText("1,234");
    const kpis = within(screen.getByRole("list", { name: "Key numbers" }));
    const href = (label: string) => kpis.getByText(label).closest("a")?.getAttribute("href");
    expect(href("Open investigations")).toBe("/app/dashboard?range=30d&state=unreviewed&state=follow_up&state=changed_since_review");
    expect(href("Open critical")).toBe("/app/dashboard?range=30d&severity=critical&state=unreviewed&state=follow_up&state=changed_since_review");
    expect(href("Incidents")).toBe("/app/dashboard?range=30d&verdict=true_positive");
    expect(href("Suspected incidents")).toBe("/app/dashboard?range=30d&state=unreviewed&state=follow_up&state=changed_since_review&ai=proposed_tp");
    expect(href("Needs attention")).toBe("/app/inbox?view=attention");
    expect(href("Notified, still active")).toBe("/app/inbox?view=known");
  });

  it("list the notified cases: when the owner was told, the days and alerts since, the trend, the block and what is due", async () => {
    reads({ ...DASH, notified: [...DASH.notified, { case_id: "c2c2c2c2-0000-4000-8000-000000000002", case_number: 13, title: "A lab machine", notified_at: "2026-10-22T04:00:00Z", days: 4, alerts: 9, trend: "falling", blocked: true, reminders: ["network_action"] }] });
    renderApp("/dashboard");
    await screen.findByText("1,234");
    const table = within(screen.getByRole("table", { name: "Notified cases" }));
    const rows = table.getAllByRole("row").slice(1).map((r) => [...r.querySelectorAll("td")].map((c) => c.textContent));
    expect(rows).toEqual([
      ["Case 12Beaconing laptop", "20 Oct 2026, 9:30 AM IST", "6", "41", "about the same each day", "none yet", "Tell the owner again: it is still active"],
      ["Case 13A lab machine", "22 Oct 2026, 9:30 AM IST", "4", "9", "falling", "recorded", "Ask for a block at the network: it is still active"],
    ]);
    expect(table.getByRole("link", { name: "Case 12" }).getAttribute("href")).toBe("/app/cases/c1c1c1c1-0000-4000-8000-000000000001");
    expect(screen.getByText(/ARGUS counts them here and raises one again only if something changes/)).toBeTruthy();
  });

  it("show no table when no owner was told, and the tile says 0 cases", async () => {
    reads({ ...DASH, notified: [], kpis: { ...DASH.kpis, known: 0 } });
    renderApp("/dashboard");
    await screen.findByText("1,234");
    expect(screen.queryByRole("table", { name: "Notified cases" })).toBeNull();
    const kpis = within(screen.getByRole("list", { name: "Key numbers" }));
    expect(must(kpis.getByText("Notified, still active").closest("li")).textContent).toContain("known, counted and not raised (0 cases)");
  });

  it("has a table for every chart, with the same numbers", async () => {
    reads();
    renderApp("/dashboard");
    await screen.findByText("1,234");
    const series = screen.getByRole("table", { name: "Alerts per day by severity", hidden: true });
    const rows = within(series).getAllByRole("row", { hidden: true }).map((r) => [...r.querySelectorAll("th,td")].map((c) => c.textContent));
    expect(rows[0]).toEqual(["Day (IST)", "critical", "high", "medium", "low", "All"]);
    expect(rows[1]?.slice(1)).toEqual(["1", "2", "0", "4", "7"]);
    expect(rows[2]?.slice(1)).toEqual(["0", "0", "3", "0", "3"]);
    for (const [name, cells] of [
      ["Investigations by state", [["Not reviewed", "10"], ["Reviewed", "8"], ["Follow-up", "2"]]],
      ["Investigations by severity", [["low", "11"], ["high", "9"]]],
      ["Person's verdict", [["No verdict yet", "12"], ["Benign: expected activity", "5"], ["True positive", "3"]]],
      ["ARGUS's assessment", [["No proposal", "11"], ["Not assessed", "5"], ["Proposes true positive", "4"]]],
    ] as const) {
      const table = screen.getByRole("table", { name });
      const body = within(table).getAllByRole("row").slice(1).map((r) => [r.querySelector("td")?.textContent, r.querySelectorAll("td")[1]?.textContent]);
      expect(body).toEqual(cells);
    }
    const rules = screen.getByRole("table", { name: "Top rules by alerts" });
    expect(within(rules).getByText("700")).toBeTruthy();
    expect(within(rules).getByRole("link", { name: "open investigations" }).getAttribute("href")).toBe("/app/inbox?view=open&rule=rule-0");
    expect(within(screen.getByRole("table", { name: "Top IP addresses" })).getByText("10.0.0.1")).toBeTruthy();
    expect(screen.getAllByText("None in this span.", { selector: "p" })).toHaveLength(3); // hosts, domains, users
    for (const chart of screen.getAllByRole("img")) expect(chart.getAttribute("aria-label")).toBeTruthy();
    expect(within(screen.getByRole("table", { name: "Incidents" })).getByText("confirmed")).toBeTruthy();
    expect(within(screen.getByRole("table", { name: "Open investigations" })).getByText("Follow-up")).toBeTruthy();
  });

  it("draws the bars and the splits as SVG with no style attribute and no script", async () => {
    reads();
    const { container } = renderApp("/dashboard");
    await screen.findByText("1,234");
    expect(container.querySelectorAll("svg[role=img]").length).toBeGreaterThanOrEqual(5);
    expect(container.querySelectorAll("[style]").length).toBe(0);
    expect(container.querySelector("svg script, svg foreignObject")).toBeNull();
    expect(container.querySelector("svg title")?.textContent).toMatch(/IST: 7 alerts, 4 low, 2 high, 1 critical/);
  });
});

describe("the filters, in the address", () => {
  it("send what the address says, and keep the span's own words", async () => {
    reads();
    renderApp("/dashboard?range=24h&severity=high&severity=low&rule=rule-0&kind=ip&value=10.0.0.1");
    await screen.findByText("1,234");
    const [first] = sent("GET", "/api/v1/dashboard?");
    expect(first?.path).toBe("/api/v1/dashboard?range=24h&severity=high&severity=low&rule=rule-0&kind=ip&value=10.0.0.1");
    expect(screen.getByText(/Last 24 hours:/)).toBeTruthy();
    const chips = within(screen.getByRole("list", { name: "Active filters" }));
    expect(chips.getAllByRole("listitem").map((c) => c.textContent)).toEqual(["severity: high×", "severity: low×", "rule: rule-0×", "ip: 10.0.0.1×", "Clear all"]);
    expect(chips.getByRole("link", { name: "Remove severity: high" }).getAttribute("href")).toBe("/app/dashboard?range=24h&severity=low&rule=rule-0&kind=ip&value=10.0.0.1");
    expect(chips.getByRole("link", { name: "Clear all" }).getAttribute("href")).toBe("/app/dashboard?range=24h");
  });

  it("apply from the form: the address changes and the numbers are read again", async () => {
    reads();
    const user = userEvent.setup();
    const { router } = renderApp("/dashboard");
    await screen.findByText("1,234");
    const form = screen.getByRole("form", { name: "Filters" });
    await user.selectOptions(within(form).getByLabelText("Time"), "30d");
    await user.click(within(form).getByLabelText("high"));
    await user.click(within(form).getByLabelText("Reviewed"));
    await user.selectOptions(within(form).getByLabelText("Rule"), "rule-1");
    await user.click(within(form).getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(router.state.location.search).toEqual({ range: "30d", severity: "high", state: "reviewed", rule: "rule-1" }));
    await waitFor(() => expect(sent("GET", "/api/v1/dashboard?")).toHaveLength(2));
    expect(sent("GET", "/api/v1/dashboard?")[1]?.path).toBe("/api/v1/dashboard?range=30d&severity=high&state=reviewed&rule=rule-1");
  });

  it("take both dates as a custom span instead of the time menu, and refuse nothing silently", async () => {
    reads();
    const user = userEvent.setup();
    const { router } = renderApp("/dashboard");
    await screen.findByText("1,234");
    const form = screen.getByRole("form", { name: "Filters" });
    await user.click(within(form).getByText(/More filters/));
    fireEvent.change(within(form).getByLabelText("From"), { target: { value: "2026-10-03" } });
    fireEvent.change(within(form).getByLabelText("To"), { target: { value: "2026-10-01" } });
    await user.type(within(form).getByLabelText("Value"), "pc-12");
    await user.selectOptions(within(form).getByLabelText("Kind"), "host");
    await user.click(within(form).getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(router.state.location.search).toEqual({ start: "2026-10-01", end: "2026-10-03", kind: "host", value: "pc-12" }));
  });
});

describe("since your last visit", () => {
  it("counts what is new, caps what the server stopped counting, and links to where it can be seen", async () => {
    reads();
    renderApp("/dashboard");
    const card = await screen.findByRole("region", { name: "Since your last visit" });
    await within(card).findByText("14");
    expect(card.textContent).toContain("14 new investigations (3 rated critical or high).");
    expect(card.textContent).toContain("2 investigations were decided by someone else.");
    expect(card.textContent).toContain("10,000 or more new proposals from ARGUS.");
    expect(within(card).getByRole("link", { name: "Open the Inbox" }).getAttribute("href")).toBe("/app/inbox?view=all&sort=newest");
    expect(within(card).getByRole("link", { name: "See the proposals" }).getAttribute("href")).toBe("/app/proposals");
  });

  it("says plainly that a first visit has nothing to compare with", async () => {
    reads(DASH, { since: null, cap: 10_000, new_investigations: 0, new_severe: 0, reviewed_by_others: 0, new_proposals: 0 });
    renderApp("/dashboard");
    expect(await screen.findByText(/This is your first visit/)).toBeTruthy();
  });
});

describe("the threat-list tile", () => {
  it("separates found, clear, could not tell and not checked, and never calls unknown clear", async () => {
    reads();
    renderApp("/dashboard");
    const card = await screen.findByRole("region", { name: "Threat lists" });
    await within(card).findByText(/The 12 most urgent open investigations \(of 40\)/);
    expect(card.textContent).toContain("2 with an address or domain on a threat list");
    expect(card.textContent).toContain("5 checked, nothing found");
    expect(card.textContent).toContain("3 could not be told (a list was out of date, or a lookup did not finish): not the same as clear");
    expect(card.textContent).toContain("2 not checked yet");
    expect(within(card).getByRole("link", { name: /Proxy: tunnel/ }).getAttribute("href")).toBe(`/app/investigations/${ID}`);
  });

  it("says when nothing is open, and reads under the same filters as the dashboard", async () => {
    reads(DASH, SINCE, { ...TILE, examined: 0, on_a_list: 0, clear: 0, could_not_tell: 0, not_checked: 0, listed: [] });
    renderApp("/dashboard?severity=critical");
    expect(await screen.findByText(/No open investigation in this span, so nothing to check against the threat lists\./)).toBeTruthy();
    expect(sent("GET", "/api/v1/dashboard/threat-lists")[0]?.path).toBe("/api/v1/dashboard/threat-lists?range=7d&severity=critical");
  });
});

describe("when a read fails", () => {
  it.each([
    [403, { detail: "your account may not do this: it needs the view capability", code: "forbidden" }, /your account may not do this/],
    [429, { detail: "x", code: "internal" }, /Too many requests just now; wait a minute and try again\./],
    [503, { detail: "ARGUS cannot reach its database; try again in a minute", code: "unavailable" }, /ARGUS cannot reach its database/],
    [500, { detail: "boom", code: "internal" }, /Something went wrong in ARGUS/],
  ])("%s is said plainly, once, and a try-again button only where it can help", async (status, body, words) => {
    server.use(
      http.get(`${BASE}/api/v1/dashboard`, () => HttpResponse.json(body, { status })),
      http.get(`${BASE}/api/v1/since`, () => HttpResponse.json(SINCE)),
      http.get(`${BASE}/api/v1/dashboard/threat-lists`, () => HttpResponse.json(TILE)),
    );
    renderApp("/dashboard");
    const alert = await screen.findByText(/The dashboard could not be shown\./);
    expect(alert.closest("[role=alert]")?.textContent).toMatch(words);
    await new Promise((resolve) => setTimeout(resolve, 150));
    expect(sent("GET", "/api/v1/dashboard?")).toHaveLength(1);
    const retry = alert.closest("[role=alert]")?.querySelector("button");
    expect(retry !== null && retry !== undefined).toBe(status === 429 || status >= 500);
  });

  it("sends the person to sign in on a 401, and reads the session again once on a refused CSRF token", async () => {
    const urls: string[] = [];
    setLeaveSpy(urls);
    server.use(
      http.get(`${BASE}/api/v1/dashboard`, () => HttpResponse.json({ detail: "sign in first", code: "unauthenticated" }, { status: 401 })),
      http.get(`${BASE}/api/v1/since`, () => HttpResponse.json({ detail: "sign in first", code: "unauthenticated" }, { status: 401 })),
      http.get(`${BASE}/api/v1/dashboard/threat-lists`, () => HttpResponse.json({ detail: "sign in first", code: "unauthenticated" }, { status: 401 })),
    );
    renderApp("/dashboard");
    await screen.findByText(/The dashboard could not be shown\./);
    expect(urls.length).toBeGreaterThanOrEqual(1);
    expect(urls.every((u) => /^\/signin\?next=.*&why=ended$/.test(u))).toBe(true);
    expect(sent("GET", "/api/v1/dashboard?")).toHaveLength(1);
  });
});

describe("hostile names", () => {
  it("in rules, hosts and filters are text only, with their hidden characters marked", async () => {
    const hostile = '<img src=x onerror="window.__pwned=1"> \u202e';
    reads({ ...DASH, rules: [{ ...must(DASH.rules[0]), rule: hostile }], rule_choices: [{ rule_id: "r", rule: hostile }], entities: { ...DASH.entities, ip: [{ kind: "ip", value: hostile, investigations: 1, alerts: 1, open: 1 }] } });
    const { container } = renderApp("/dashboard?rule=r");
    await screen.findByText("1,234");
    expect(container.querySelector("main img")).toBeNull();
    expect(container.querySelectorAll("main .ut-mark").length).toBeGreaterThanOrEqual(2);
    expect((screen.getByLabelText("Rule") as HTMLSelectElement).selectedOptions[0]?.textContent).toContain("‹RLO›");
    expect((window as unknown as { __pwned?: number }).__pwned).toBeUndefined();
  });
});
