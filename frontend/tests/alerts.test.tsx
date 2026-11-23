// Alerts (the menu's third entry): every alert group with the incident it belongs to, the two
// halves of the list one click apart, and from an alert group the way back to its incident.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import type { InvestigationOut } from "../src/client/types.gen";
import { alertsLead, alertsQuery, parseAlerts } from "../src/lib/alerts";
import { BASE, detail, ID, ID2, investigation, mockApi, renderApp, sent, server } from "./helpers";

mockApi();
const CASE = { id: "a1a1a1a1-0000-4000-8000-000000000031", number: 31, title: "Likely beaconing to 203.0.113.40", state: "suspected" as const };
const COUNTS = { all: 23117, attention: 545, open: 22340, reviewed: 800, follow_up: 7, changed: 16, known: 0 };
const RULE = { rule_id: "rule-beacon", rule_name: "Proxy: beacon", investigations: 12, open: 3, alerts: 240, last_event_at: null, type: "query", revision: 4, interval: "5m", max_signals: 100, execution_status: "succeeded", truncated: 0 };

function serveList(items: InvestigationOut[], more = false) {
  server.use(
    http.get(`${BASE}/api/v1/investigations`, ({ request }) => {
      const q = new URL(request.url).searchParams;
      const wanted = q.get("incident");
      const rule = q.get("rule");
      const shown = items.filter((i) => (wanted === null || (wanted === "in") === (i.case != null)) && (rule === null || i.rule_id === rule));
      return HttpResponse.json({ items: shown, has_more: more, limit: 50, offset: Number(q.get("offset") ?? 0), sort: "newest", view: q.get("view") ?? "all" });
    }),
    http.get(`${BASE}/api/v1/counts`, () => HttpResponse.json(COUNTS)),
    http.get(`${BASE}/api/v1/rules`, () => HttpResponse.json([RULE])),
  );
}

describe("the address", () => {
  it("keeps the three choices it knows and nothing else", () => {
    expect(parseAlerts({ in: "incident", state: "reviewed", page: "9" })).toEqual({ in: "incident", state: "reviewed" });
    expect(parseAlerts({ in: "everything", state: "known" })).toEqual({});
    expect(parseAlerts({ rule: "rule-beacon" })).toEqual({ rule: "rule-beacon" });
    expect(parseAlerts({ rule: "" })).toEqual({});
    expect(parseAlerts({ rule: "x".repeat(201) })).toEqual({});
    expect(parseAlerts({ rule: "a\u0000b" })).toEqual({});
    expect(alertsQuery({ rule: "rule-beacon", in: "incident" })).toEqual({ view: "all", incident: "in", rule: "rule-beacon" });
    expect(alertsQuery({})).toEqual({ view: "all" });
    expect(alertsQuery({ in: "incident", state: "attention" })).toEqual({ view: "attention", incident: "in" });
    expect(alertsQuery({ in: "none" })).toEqual({ view: "all", incident: "none" });
  });

  it("says in words what the list holds", () => {
    expect(alertsLead({})).toMatch(/^The alert groups, newest alert first\./);
    expect(alertsLead({ in: "incident", state: "open" })).toContain("that belong to an incident and are not reviewed yet");
    expect(alertsLead({ in: "none" })).toContain("that belong to no incident");
    expect(alertsLead({ rule: "rule-beacon", in: "incident" })).toMatch(/^The alert groups of one rule that belong to an incident, newest/);
  });
});

describe("the page", () => {
  const inside = investigation(ID, { title: "10.0.0.7 · beacon-timed", rule_name: "Proxy: beacon", alert_count: 19, severity: "high", case: CASE });
  const outside = investigation(ID2, { title: "198.51.100.9 · got HTTP 200 after", rule_name: "Web: file served", alert_count: 1, case: null });

  it("lists every alert group with its incident, and says how many there are", async () => {
    serveList([inside, outside]);
    renderApp("/alerts");
    const rows = await screen.findAllByTestId("alert-row");
    expect(rows).toHaveLength(2);
    expect(within(rows[0] as HTMLElement).getByTestId("alert-title").getAttribute("href")).toBe(`/app/alert-groups/${ID}`);
    const incident = within(rows[0] as HTMLElement).getByTestId("alert-incident");
    expect(incident.getAttribute("href")).toBe(`/app/incidents/${CASE.id}`);
    expect(incident.textContent).toContain("Possible incident #31");
    expect(incident.textContent).toContain("Likely beaconing");
    expect(within(rows[1] as HTMLElement).queryByTestId("alert-incident")).toBeNull();
    expect((await screen.findByTestId("alerts-counts")).textContent).toBe("23,117 alert groups in all · 545 need attention · 800 reviewed");
    expect(screen.getByRole("heading", { level: 1, name: "Alerts" })).toBeTruthy();
    expect(sent("GET", "/api/v1/investigations?")[0]?.path).toContain("view=all");
  });

  it("shows only the alert groups in an incident, or in none, and writes the choice to the address", async () => {
    const user = userEvent.setup();
    serveList([inside, outside]);
    const { router } = renderApp("/alerts");
    await screen.findAllByTestId("alert-row");
    await user.click(screen.getByRole("button", { name: "In an incident" }));
    await waitFor(() => expect(screen.getAllByTestId("alert-row")).toHaveLength(1));
    expect(router.state.location.search).toEqual({ in: "incident" });
    expect(sent("GET", "/api/v1/investigations?").some((r) => r.path.includes("incident=in"))).toBe(true);
    expect(screen.getByRole("button", { name: "In an incident" }).getAttribute("aria-pressed")).toBe("true");
    await user.click(screen.getByRole("button", { name: "Not in an incident" }));
    await waitFor(() => expect(sent("GET", "/api/v1/investigations?").some((r) => r.path.includes("incident=none"))).toBe(true));
    await user.click(screen.getByRole("button", { name: "Needs attention" }));
    await waitFor(() => expect(sent("GET", "/api/v1/investigations?").some((r) => r.path.includes("view=attention") && r.path.includes("incident=none"))).toBe(true));
    expect(router.state.location.search).toEqual({ in: "none", state: "attention" });
  });

  it("narrows the list to one rule, and keeps a rule the list of rules does not know", async () => {
    const user = userEvent.setup();
    serveList([{ ...inside, rule_id: "rule-beacon" }, outside]);
    const { router, unmount } = renderApp("/alerts");
    await screen.findAllByTestId("alert-row");
    const rule = screen.getByRole("combobox", { name: "Rule" });
    await within(rule).findByRole("option", { name: "Proxy: beacon" });
    await user.selectOptions(rule, "rule-beacon");
    await waitFor(() => expect(screen.getAllByTestId("alert-row")).toHaveLength(1));
    expect(router.state.location.search).toEqual({ rule: "rule-beacon" });
    expect(sent("GET", "/api/v1/investigations?").some((r) => r.path.includes("rule=rule-beacon"))).toBe(true);
    await user.selectOptions(rule, "");
    await waitFor(() => expect(screen.getAllByTestId("alert-row")).toHaveLength(2));
    expect(router.state.location.search).toEqual({});
    unmount();
    renderApp("/alerts?rule=gone-rule");
    const kept = await screen.findByRole("combobox", { name: "Rule" });
    await within(kept).findByRole("option", { name: "Proxy: beacon" });
    expect((kept as HTMLSelectElement).value).toBe("gone-rule");
    expect(within(kept).getByRole("option", { name: "gone-rule" })).toBeTruthy();
  });

  it("says so when nothing matches, and offers more rows when the server has more", async () => {
    serveList([]);
    const first = renderApp("/alerts?in=incident");
    expect((await screen.findByTestId("alerts-empty")).textContent).toContain("ARGUS has put none in an incident yet");
    first.unmount();
    serveList([inside], true);
    renderApp("/alerts");
    await screen.findAllByTestId("alert-row");
    expect(screen.getByRole("button", { name: "Show 50 more" })).toBeTruthy();
  });
});

describe("an alert group's way back", () => {
  function serveGroup(inCase: typeof CASE | null) {
    server.use(
      http.get(`${BASE}/api/v1/investigations/${ID}/reports`, () => HttpResponse.json({ items: [], logs_hidden: false })),
      http.get(`${BASE}/api/v1/investigations/${ID}`, () => HttpResponse.json(detail({ case: inCase }))),
    );
  }

  it("leads to the incident it belongs to, on its alert groups, and to the list", async () => {
    serveGroup(CASE);
    renderApp(`/alert-groups/${ID}`);
    const back = await screen.findByTestId("back-to-incident");
    expect(back.getAttribute("href")).toBe(`/app/incidents/${CASE.id}?tab=alert-groups`);
    expect(back.textContent).toContain("Back to possible incident #31: Likely beaconing to 203.0.113.40");
    const trail = within(screen.getByTestId("alert-trail"));
    expect(trail.getByRole("link", { name: "All alerts" }).getAttribute("href")).toBe("/app/alerts?in=incident");
    expect(screen.queryByText(/Open it in the alert-group list/)).toBeNull();
  });

  it("leads to the list alone when it is in no incident", async () => {
    serveGroup(null);
    renderApp(`/alert-groups/${ID}`);
    const trail = within(await screen.findByTestId("alert-trail"));
    expect(trail.getByRole("link", { name: "← All alerts" }).getAttribute("href")).toBe("/app/alerts");
    expect(screen.queryByTestId("back-to-incident")).toBeNull();
  });
});
