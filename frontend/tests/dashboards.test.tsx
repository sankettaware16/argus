// Dashboards (the menu's fourth entry): three ready-made boards under one row of controls, the
// charts read by pointer, keys or as a table, the figures one click from the list behind them.
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import type { DashboardOut, PerformanceOut } from "../src/client/types.gen";
import { keptShare, keptWords } from "../src/components/dashboards/Response";
import { boardOf, parseDashboards, rangeOf } from "../src/lib/dashboards";
import { caseRow } from "./caseFixtures";
import { BASE, EMPTY_DASHBOARD, mockApi, renderApp, sent, server, sessionWith, shellHandlers } from "./helpers";
import { engineBlock } from "./v2Fixtures";

mockApi();

const DASH: DashboardOut = {
  ...EMPTY_DASHBOARD,
  kpis: { ...EMPTY_DASHBOARD.kpis, alerts: 40364, alerts_before: 34585, investigations: 7514, open: 7291, attention: 545, incident_cases: 5, possible_incidents: 3, open_critical: 2, reviewed: 223, incidents: 12, assessed: 4100, median_review_s: 5400 },
  series: [
    { at: "2026-10-24T00:00", counts: { low: 30, medium: 10, high: 4, critical: 0 } },
    { at: "2026-10-25T00:00", counts: { low: 50, medium: 20, high: 8, critical: 2 } },
    { at: "2026-10-26T00:00", counts: { low: 9, medium: 0, high: 0, critical: 0 } },
  ],
  severities: { critical: 2, high: 40, medium: 300, low: 7172 },
  states: { unreviewed: 7200, follow_up: 7, changed_since_review: 84, reviewed: 223 },
  verdicts: { true_positive: 12, benign_expected: 150, rule_false_positive: 61, none: 7291 },
  ai: { proposed_tp: 9, proposed_other: 3000, none: 3414 },
  rules: [
    { rule_id: "r-noise", rule: "Proxy: excessive blocked requests", severity: "low", alerts: 30000, investigations: 5000, open: 4990, incidents: 0, suspected: 0 },
    { rule_id: "r-beacon", rule: "Proxy: plain-HTTP POST to a raw address", severity: "high", alerts: 900, investigations: 40, open: 20, incidents: 9, suspected: 2 },
    { rule_id: "r-scan", rule: "Web: sensitive file served", severity: "high", alerts: 4000, investigations: 2000, open: 1900, incidents: 3, suspected: 0 },
  ],
  entities: {
    ip: [
      { kind: "ip", value: "10.0.0.7", alerts: 400, investigations: 9, open: 4 },
      { kind: "ip", value: "203.0.113.40", alerts: 250, investigations: 6, open: 6 },
    ],
    host: [{ kind: "host", value: "lab-pc-02", alerts: 120, investigations: 3, open: 0 }],
    domain: [{ kind: "domain", value: "update-check.example.net", alerts: 90, investigations: 2, open: 2 }],
    user: [],
  },
};

const kept = (met: number, missed: number, pending: number) => ({ met, missed, pending, share: met + missed > 0 ? met / (met + missed) : null });
const PERFORMANCE: PerformanceOut = {
  start: "2026-10-19T00:00:00Z",
  end: "2026-10-26T00:00:00Z",
  raised: 14,
  confirmed: 3,
  dismissed: 9,
  waiting: 2,
  detect: { count: 13, median_s: 1500, mean_s: 2700, p90_s: 9000 },
  triage: { count: 12, median_s: 1800, mean_s: 5400, p90_s: 20000 },
  resolve: { count: 1, median_s: 93600, mean_s: 93600, p90_s: 93600 },
  triage_kept: kept(11, 2, 1),
  resolve_kept: kept(0, 1, 2),
  bands: [
    { band: "P1", raised: 4, triage_target_s: 3600, resolve_target_s: 86400, triage: kept(2, 2, 0), resolve: kept(0, 1, 1), triage_median_s: 2400 },
    { band: "P2", raised: 3, triage_target_s: 14400, resolve_target_s: 259200, triage: kept(3, 0, 0), resolve: kept(0, 0, 1), triage_median_s: 1800 },
    { band: "P3", raised: 2, triage_target_s: 86400, resolve_target_s: 604800, triage: kept(2, 0, 0), resolve: kept(0, 0, 0), triage_median_s: 900 },
    { band: "P4", raised: 5, triage_target_s: 259200, resolve_target_s: 1209600, triage: kept(4, 0, 1), resolve: kept(0, 0, 0), triage_median_s: 600 },
  ],
  overdue: [
    { id: "a1a1a1a1-0000-4000-8000-000000000007", number: 7, title: "Confirmed beaconing to 203.0.113.40", state: "open", band: "P1", kind: "resolve", waited_s: 1_123_200, target_s: 86400 },
    { id: "a1a1a1a1-0000-4000-8000-000000000091", number: 91, title: "Suspected beaconing from 10.0.0.9", state: "suspected", band: "P3", kind: "triage", waited_s: 100_800, target_s: 86400 },
  ],
  overdue_total: 5,
  due_soon: 1,
};

function serve(asked: string[] = [], performance: PerformanceOut = PERFORMANCE) {
  server.use(
    http.get(`${BASE}/api/v1/performance`, ({ request }) => {
      asked.push(`performance:${new URL(request.url).searchParams.get("range") ?? ""}`);
      return HttpResponse.json(performance);
    }),
    http.get(`${BASE}/api/v1/dashboard`, ({ request }) => {
      asked.push(new URL(request.url).searchParams.get("range") ?? "");
      return HttpResponse.json(DASH);
    }),
    http.get(`${BASE}/api/v1/cases`, () => HttpResponse.json({ items: [{ ...caseRow({ number: 31, title: "Likely beaconing to 203.0.113.40", state: "suspected" }), engine: engineBlock("P1", 82) }], view: "queue", offset: 0, limit: 6, has_more: false, counts: {} })),
  );
}

describe("the address", () => {
  it("names a board and a range, and leaves the usual ones out", () => {
    expect(parseDashboards({ d: "operations", range: "30d" })).toEqual({ d: "operations", range: "30d" });
    expect(parseDashboards({ d: "overview", range: "7d", x: "1" })).toEqual({});
    expect(parseDashboards({ d: "nonsense", range: "1y" })).toEqual({});
    expect([boardOf({}), rangeOf({})]).toEqual(["overview", "7d"]);
  });
});

describe("the security overview", () => {
  it("leads with the figures, each with what it means and where it goes", async () => {
    serve();
    renderApp("/dashboards");
    const alerts = await screen.findByTestId("stat-alerts");
    expect(alerts.textContent).toContain("40.4K");
    expect(within(alerts).getByTestId("stat-moved").textContent).toBe("▲ +17% vs the 7 days before");
    expect(within(alerts).getByTestId("sparkline")).toBeTruthy();
    expect(screen.getByTestId("stat-incidents").closest("a")?.getAttribute("href")).toBe("/app/incidents?view=open");
    expect(screen.getByTestId("stat-possible").closest("a")?.getAttribute("href")).toBe("/app/incidents?view=needs-you");
    expect(screen.getByTestId("stat-attention").closest("a")?.getAttribute("href")).toBe("/app/alerts?state=attention");
    expect(screen.getByTestId("stat-attention").textContent).toContain("2 rated critical");
    expect(screen.getByTestId("stat-review").textContent).toContain("1.5 h");
  });

  it("says how fast alerts became decisions: MTTD, MTTA, MTTR and the share within the targets", async () => {
    serve();
    renderApp("/dashboards");
    const response = within(await screen.findByTestId("response"));
    expect(response.getByText(/For the 14 incidents raised in this span: 3 confirmed, 9 dismissed, 2 waiting\./)).toBeTruthy();
    expect(response.getByTestId("stat-mttd").textContent).toBe("Time to detect (MTTD)45 minmedian 25 min · from the first alert to ARGUS raising the incident");
    expect(response.getByTestId("stat-mtta").textContent).toContain("1.5 h");
    expect(response.getByTestId("stat-mtta").textContent).toContain("median 30 min · 12 decided by a person");
    expect(response.getByTestId("stat-mttr").textContent).toContain("26 h");
    expect(response.getByTestId("stat-sla-triage").textContent).toBe("Decided in time (SLA)85%11 of 13 decided within their target · 1 still in time");
    expect(response.getByTestId("stat-sla-resolve").textContent).toContain("0%");
    expect(response.getByTestId("stat-overdue").textContent).toContain("5");
    expect(response.getByTestId("stat-overdue").textContent).toContain("1 more with three quarters of their time used");
  });

  it("holds each priority against its own targets, and lists what is past its time, a click from the incident", async () => {
    const user = userEvent.setup();
    serve();
    renderApp("/dashboards");
    const bands = within(await screen.findByTestId("sla-bands"));
    expect(bands.getAllByTestId("band-row")).toHaveLength(4);
    expect(bands.getByRole("img", { name: "P1 · decide within 1 h: 2 of 4 in time" })).toBeTruthy();
    expect(bands.getByRole("img", { name: "P1 · close within 24 h: 0 of 1 in time · 1 waiting" })).toBeTruthy();
    expect(bands.getByRole("img", { name: "P4 · decide within 3 days: 4 of 4 in time · 1 waiting" })).toBeTruthy();
    expect(bands.getByRole("img", { name: "P3 · close within 7 days: none yet" })).toBeTruthy();
    expect(bands.getByRole("link", { name: "Settings › Response times" }).getAttribute("href")).toBe("/app/settings");
    await user.click(bands.getByRole("button", { name: "Show as a table" }));
    expect(within(bands.getByRole("table")).getAllByRole("row")[1]?.textContent).toBe("P142201");
    const overdue = within(screen.getByTestId("overdue"));
    const rows = overdue.getAllByTestId("overdue-row");
    expect(rows.map((r) => r.getAttribute("href"))).toEqual(["/app/incidents/a1a1a1a1-0000-4000-8000-000000000007", "/app/incidents/a1a1a1a1-0000-4000-8000-000000000091"]);
    expect(rows[0]?.textContent).toContain("#7 Confirmed beaconing");
    expect(rows[0]?.textContent).toContain("Not closed for 13 days; the target is 24 h");
    expect(rows[1]?.textContent).toContain("Not decided for 28 h; the target is 24 h");
    expect(overdue.getByText("3 more are not listed.")).toBeTruthy();
  });

  it("says so when nothing was raised, and nothing is past its time", async () => {
    const none = { count: 0, median_s: null, mean_s: null, p90_s: null };
    serve([], { ...PERFORMANCE, raised: 0, confirmed: 0, dismissed: 0, waiting: 0, detect: none, triage: none, resolve: none, triage_kept: kept(0, 0, 0), resolve_kept: kept(0, 0, 0), overdue: [], overdue_total: 0, due_soon: 0 });
    renderApp("/dashboards");
    const response = within(await screen.findByTestId("response"));
    expect(response.getByTestId("stat-mttd").textContent).toContain("—");
    expect(response.getByTestId("stat-mttd").textContent).toContain("ARGUS raised no incident in this span");
    expect(response.getByTestId("stat-sla-triage").textContent).toContain("nothing was decided in this span");
    expect(response.getByText("Nothing is past its time.")).toBeTruthy();
    expect(keptShare(kept(0, 0, 3))).toBe("—");
    expect(keptWords(kept(0, 0, 3), "decided")).toBe("3 still in time");
  });

  it("draws the alerts over time: a column a day, a legend, and a readout by arrow key", async () => {
    serve();
    renderApp("/dashboards");
    const card = within(await screen.findByTestId("alerts-over-time"));
    expect(card.getAllByTestId("column")).toHaveLength(3);
    expect(within(card.getByTestId("legend")).getAllByRole("listitem").map((li) => li.textContent)).toEqual(["Low", "Medium", "High", "Critical"]);
    expect(card.queryByTestId("readout")).toBeNull();
    const chart = card.getByTestId("columns");
    fireEvent.keyDown(chart, { key: "ArrowLeft" });
    expect(card.getByTestId("readout").textContent).toContain("25 Oct");
    expect(card.getByTestId("readout").textContent).toContain("80 alerts");
    fireEvent.keyDown(chart, { key: "End" });
    expect(card.getByTestId("readout").textContent).toContain("9 alerts");
    fireEvent.keyDown(chart, { key: "Escape" });
    expect(card.queryByTestId("readout")).toBeNull();
    expect(card.getByRole("img", { name: /Alerts over time: 133 alerts in 3 days; the most, 80, on Sun 25 Oct/ })).toBeTruthy();
  });

  it("gives the same numbers as a table", async () => {
    const user = userEvent.setup();
    serve();
    renderApp("/dashboards");
    const card = within(await screen.findByTestId("alerts-over-time"));
    await user.click(card.getByRole("button", { name: "Show as a table" }));
    const table = card.getByRole("table", { name: "Alerts over time, by severity" });
    expect(within(table).getAllByRole("row")).toHaveLength(4);
    expect(within(table).getAllByRole("row")[2]?.textContent).toBe("Sun 25 Oct50208280");
    expect(card.getByRole("button", { name: "Show the chart" }).getAttribute("aria-pressed")).toBe("true");
  });

  it("shows how far the alerts are narrowed down, the devices and the outside addresses, each a way in", async () => {
    serve();
    renderApp("/dashboards");
    const funnel = within(await screen.findByTestId("funnel"));
    const steps = funnel.getAllByRole("listitem").map((li) => li.textContent);
    expect(steps[0]).toContain("Alerts from the SIEM40,364");
    expect(steps[1]).toContain("7,514 · 1 in 5");
    expect(steps[2]).toContain("545 · 1 in 14");
    expect(funnel.getByRole("link", { name: /need attention/ }).getAttribute("href")).toBe("/app/alerts?state=attention");
    const inside = within(screen.getByTestId("top-inside"));
    expect(inside.getByRole("heading", { level: 2 }).textContent).toBe("Most active campus devices");
    expect(inside.getAllByRole("link").map((a) => a.getAttribute("href"))).toEqual(["/app/entities/device/10.0.0.7", "/app/entities/device/lab-pc-02"]);
    const outside = within(screen.getByTestId("top-outside"));
    expect(outside.getAllByRole("link").map((a) => a.getAttribute("href"))).toEqual(["/app/entities/outside/203.0.113.40", "/app/entities/site/update-check.example.net"]);
    const waiting = within(await screen.findByTestId("waiting"));
    expect((await waiting.findByText(/Likely beaconing/)).closest("a")?.getAttribute("href")).toMatch(/^\/app\/incidents\//);
  });

  it("asks again for another range, keeps the board, and writes both to the address", async () => {
    const user = userEvent.setup();
    const asked: string[] = [];
    serve(asked);
    const { router } = renderApp("/dashboards");
    await screen.findByTestId("stat-alerts");
    await screen.findByTestId("response");
    expect([...asked].sort()).toEqual(["7d", "performance:7d"]);
    await user.click(screen.getByRole("button", { name: "30 days" }));
    await waitFor(() => expect([...asked].sort()).toEqual(["30d", "7d", "performance:30d", "performance:7d"]));
    expect(router.state.location.search).toEqual({ range: "30d" });
    expect(screen.getByRole("button", { name: "30 days" }).getAttribute("aria-pressed")).toBe("true");
    await user.click(screen.getByRole("button", { name: "Detections" }));
    await screen.findByTestId("rule-table");
    expect(router.state.location.search).toEqual({ d: "detections", range: "30d" });
    expect(screen.getByTestId("freshness").textContent).toContain("refreshes every minute");
  });
});

describe("detections", () => {
  it("lists every rule, sorted by the column a person picks", async () => {
    const user = userEvent.setup();
    serve();
    renderApp("/dashboards?d=detections");
    const table = within(await screen.findByTestId("rule-table"));
    const names = () => table.getAllByTestId("rule-row").map((r) => within(r).getByRole("link").textContent);
    expect(names()).toEqual(["Proxy: excessive blocked requests", "Web: sensitive file served", "Proxy: plain-HTTP POST to a raw address"]);
    await user.click(table.getByRole("button", { name: /Called real/ }));
    expect(names()).toEqual(["Proxy: plain-HTTP POST to a raw address", "Web: sensitive file served", "Proxy: excessive blocked requests"]);
    expect(table.getByRole("columnheader", { name: /Called real/ }).getAttribute("aria-sort")).toBe("descending");
    expect(table.getAllByRole("link")[0]?.getAttribute("href")).toBe("/app/search?advanced=1&view=all&rule=r-beacon");
  });

  it("names the rules that are loud and never real, and those that found something", async () => {
    serve();
    renderApp("/dashboards?d=detections");
    const loud = within(await screen.findByTestId("loud"));
    expect(loud.getAllByRole("listitem").map((li) => li.textContent)).toEqual(["Proxy: excessive blocked requests30,000 · 5,000 groups"]);
    expect(loud.getByText(/made 74% of the alerts/)).toBeTruthy();
    expect(loud.getByRole("link", { name: "Rule tuning ›" }).getAttribute("href")).toBe("/app/tuning");
    const found = within(screen.getByTestId("productive"));
    expect(found.getAllByRole("listitem").map((li) => li.textContent?.split(" · ")[0])).toEqual(["Proxy: plain-HTTP POST to a raw address11", "Web: sensitive file served3"]);
    expect(screen.getByTestId("stat-rules").textContent).toContain("3");
    expect(screen.getByTestId("stat-productive").textContent).toContain("2");
    // "no decision yet" is the grey of the rest, never a series colour of its own
    const verdicts = within(screen.getByTestId("verdicts"));
    expect(verdicts.getByText("No decision yet").previousElementSibling?.className).toContain("bg-viz-rest");
  });
});

describe("ARGUS operations", () => {
  const METRICS = { backlog: [{ assessor: "agent@1", waiting: 4, oldest_wait_s: 720 }], calls: [{ provider: "groq", attempts: 900, ok: 880, cost_usd: 0 }], fallbacks: 12, floor_hits: 3, validator_blocks: 1, outcomes: [{ assessor: "the AI investigator", label: "Real but harmless", count: 300 }], quota: [], stopped: false, month_cost_usd: 2.52 };
  const USAGE = { ai_days: [{ day: "2026-10-25", provider: "groq", calls: 40, ok: 39, tokens: 9000, cost_usd: 0 }, { day: "2026-10-26", provider: "openai", calls: 5, ok: 5, tokens: 4000, cost_usd: 0.1 }], ai_tasks: [], daily_cap_usd: 0.5, monthly_cap_usd: 10, month_usd: 9.4, today_usd: 0.1, sources: [], sources_at: null, stopped: false };

  function serveOps(admin: boolean) {
    const asked = { usage: 0 };
    server.use(
      ...shellHandlers(sessionWith(admin ? ["view", "admin"] : ["view"])),
      http.get(`${BASE}/api/v1/metrics`, () => HttpResponse.json(METRICS)),
      http.get(`${BASE}/api/v1/admin/usage`, () => {
        asked.usage += 1;
        return HttpResponse.json(USAGE);
      }),
    );
    return asked;
  }

  it("says how ARGUS is running, with no time range of its own", async () => {
    serveOps(false);
    renderApp("/dashboards?d=operations");
    expect((await screen.findByTestId("stat-siem")).textContent).toContain("Normal");
    expect(screen.queryByRole("group", { name: "Time range" })).toBeNull();
    expect((await screen.findByTestId("stat-waiting")).textContent).toContain("4");
    expect(screen.getByTestId("stat-waiting").textContent).toContain("the oldest for 12 min");
    const calls = within(screen.getByTestId("ai-calls"));
    expect(calls.getAllByRole("listitem").map((li) => li.textContent)).toEqual(["groq900 · 880 answered"]);
    expect(calls.getByText(/12 fell back to another provider · 1 stopped by the privacy check · 3 held by the safety floor/)).toBeTruthy();
    expect(sent("GET", "/api/v1/dashboard")).toEqual([]);
  });

  it("gives the SIEM's state with its reasons in plain words", async () => {
    serveOps(false);
    const health = { siem_state: "caution", siem_reasons: ["disk_caution", "never_probed"], siem_probed_at: "2026-10-26T00:00:00Z", live_cursor: null, backfill_cursor: null, open_gaps: [], last_reconciliation: null, alerts: 0, quarantined: 0, investigations: 0, jobs_waiting: 0, jobs_deferred: 0, jobs_failed: 0, dossiers: 0, checkpoint_threads: 0, checkpoint_bytes: 0, kibana_sync: { state: "none", last_cycle_at: null, last_outcome: null, last_reason: null, last_complete_at: null } };
    server.use(http.get(`${BASE}/api/v1/health`, () => HttpResponse.json(health)));
    renderApp("/dashboards?d=operations");
    const tile = await screen.findByTestId("stat-siem");
    expect(tile.textContent).toContain("disk caution, never probed");
    expect(tile.textContent).not.toContain("_");
  });

  it("shows the AI's calls and spend against its caps to an administrator only", async () => {
    const plain = serveOps(false);
    const first = renderApp("/dashboards?d=operations");
    await screen.findByTestId("stat-siem");
    expect(screen.queryByTestId("spend")).toBeNull();
    expect(plain.usage).toBe(0);
    first.unmount();
    serveOps(true);
    renderApp("/dashboards?d=operations");
    const spend = within(await screen.findByTestId("spend"));
    expect(spend.getByTestId("meter-day").textContent).toContain("$0.10 of $0.50");
    expect(spend.getByRole("img", { name: "Spent this month: $9.40 of $10.00" })).toBeTruthy();
    // the day-by-day picture is the costs board's: one click away
    expect(spend.getByRole("link", { name: "The costs board ›" }).getAttribute("href")).toBe("/app/dashboards?d=costs");
  });
});
