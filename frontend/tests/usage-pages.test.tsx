// Threat intel and Costs and usage (D-329), against a mock of the API: each source's key added
// like any key (sealed, never shown), on or off by key (Shodan's keyless fallback), its limits and
// lookups, the Test of one public address; the costs' summary first, the AI's spend a day stacked
// by provider, the tasks' table and each source's lookups against its daily limit; the menu.
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import type { JobOut, SettingOut, SettingsOut, UsageOut } from "../src/client/types.gen";
import { todayUtc } from "../src/lib/usage";
import { BASE, mockApi, renderApp, sent, server, sessionWith, shellHandlers } from "./helpers";

mockApi();
const ADMIN = sessionWith(["view", "admin"], { user: { id: 1, username: "asha", display_name: "Asha" } });

function setting(more: Partial<SettingOut> & { key: string; label: string }): SettingOut {
  return { help: "", kind: "secret", risk: "sensitive", editable: true, optional: true, choices: [], minimum: null, maximum: null, default: null, value: null, is_set: false, homes: [], in_app: false, ...more };
}
const SETTINGS: SettingsOut = {
  sections: [
    {
      key: "outside",
      label: "Outside sources",
      about: "VirusTotal, Shodan, Censys and other lookups.",
      settings: [
        setting({ key: "outside.virustotal_api_key", label: "Virustotal api key", is_set: true }),
        setting({ key: "outside.shodan_api_key", label: "Shodan api key" }),
        setting({ key: "outside.censys_api_key", label: "Censys api key" }),
        setting({ key: "outside.shodan_internetdb", label: "Shodan internetdb", kind: "bool", risk: "normal", optional: false, is_set: null, value: true }),
        setting({ key: "outside.virustotal_per_day", label: "Virustotal per day", kind: "int", risk: "normal", value: 400, is_set: null }),
      ],
    },
  ],
  applier: { running: true, last_seen: "2026-11-16T10:00:00Z" },
  problem: null,
  confirm_words: "let ARGUS write to the SIEM",
  setup_needed: false,
};
const TODAY = todayUtc();
const daysAgo = (n: number) => new Date(Date.parse(`${TODAY}T00:00:00Z`) - n * 86_400_000).toISOString().slice(0, 10);
function usage(more: Partial<UsageOut> = {}): UsageOut {
  return {
    monthly_cap_usd: 10,
    daily_cap_usd: 0.3,
    month_usd: 2.5,
    today_usd: 0.004,
    stopped: false,
    ai_days: [
      { day: daysAgo(1), provider: "paidcloud", calls: 4, ok: 4, cost_usd: 0.42, tokens: 9000 },
      { day: daysAgo(1), provider: "freecloud", calls: 9, ok: 8, cost_usd: 0, tokens: 20000 },
      { day: TODAY, provider: "paidcloud", calls: 1, ok: 1, cost_usd: 0.004, tokens: 900 },
    ],
    ai_tasks: [
      { task: "opinion", calls: 5, cost_usd: 0.424 },
      { task: "story", calls: 9, cost_usd: 0 },
    ],
    sources: [
      { source: "virustotal", key_set: true, enabled: true, today: 12, month: 140, answered_month: 139, limits: [{ window: "minute", maximum: 3 }, { window: "day", maximum: 400 }], days: [{ day: TODAY, requests: 12 }] },
      { source: "shodan", key_set: false, enabled: true, today: 0, month: 3, answered_month: 3, limits: [{ window: "minute", maximum: 30 }, { window: "day", maximum: 200 }], days: [] },
      { source: "censys", key_set: false, enabled: false, today: 0, month: 0, answered_month: 0, limits: [{ window: "day", maximum: 10 }, { window: "month", maximum: 50 }], days: [] },
    ],
    sources_at: "2026-11-16T10:00:00Z",
    ...more,
  };
}
const serve = (more: Partial<UsageOut> = {}) =>
  server.use(...shellHandlers(ADMIN), http.get(`${BASE}/api/v1/admin/settings`, () => HttpResponse.json(SETTINGS)), http.get(`${BASE}/api/v1/admin/usage`, () => HttpResponse.json(usage(more))));
const job = (more: Partial<JobOut>): JobOut => ({ id: 60, kind: "check", state: "pending", result: null, created_at: "2026-11-16T10:00:00Z", finished_at: null, ...more });

describe("Threat intel", () => {
  it("shows each source: what it gives, on or off by its key, its limits and lookups", async () => {
    serve();
    renderApp("/threat-intel");
    expect(await screen.findByRole("heading", { level: 1, name: "Threat intel" })).toBeTruthy();
    expect(document.title).toBe("Threat intel · ARGUS");
    const vt = screen.getByTestId("source-virustotal");
    expect(vt.textContent).toContain("reputation of a public address");
    expect(within(vt).getByText("On")).toBeTruthy();
    expect(vt.textContent).toContain("3 a minute, 400 a day");
    expect(vt.textContent).toContain("12 today, 140 this month (139 answered)");
    expect(within(vt).getByLabelText("Replace key: VirusTotal")).toBeTruthy();
    const shodan = screen.getByTestId("source-shodan");
    expect(within(shodan).getByText("On without a key (InternetDB)")).toBeTruthy();
    expect((within(shodan).getByLabelText("Use InternetDB when there is no key") as HTMLInputElement).checked).toBe(true);
    const censys = screen.getByTestId("source-censys");
    expect(within(censys).getByText("Off: no key")).toBeTruthy();
    expect(within(censys).queryByLabelText(/InternetDB/)).toBeNull();
    expect(screen.queryByLabelText("Virustotal per day")).toBeNull();
    expect(screen.getByRole("link", { name: "Settings, Outside sources" }).getAttribute("href")).toBe("/app/settings?section=outside");
  });

  it("adds a key: a password box, sent once through the save, never shown", async () => {
    serve();
    server.use(
      http.post(`${BASE}/api/v1/admin/changes`, () => HttpResponse.json({ batch: "b-7", changes: [{ id: 1, key: "outside.censys_api_key", state: "pending", outcome: null, created_at: "2026-11-16T10:00:00Z", finished_at: null, by: "asha" }] }, { status: 202 })),
      http.get(`${BASE}/api/v1/admin/changes`, () => HttpResponse.json({ batch: "b-7", changes: [{ id: 1, key: "outside.censys_api_key", state: "applied", outcome: null, created_at: "2026-11-16T10:00:00Z", finished_at: "2026-11-16T10:00:03Z", by: "asha" }] })),
    );
    const user = userEvent.setup();
    renderApp("/threat-intel");
    const box = (await screen.findByLabelText("Add key: Censys")) as HTMLInputElement;
    expect(box.type).toBe("password");
    await user.type(box, "Y2Vuc3lzLWV4YW1wbGU=");
    await user.click(screen.getByRole("button", { name: "Save 1 change" }));
    await waitFor(() => expect(sent("POST", "/api/v1/admin/changes").length).toBe(1));
    expect(JSON.parse(sent("POST", "/api/v1/admin/changes")[0]?.body ?? "null")).toEqual({ changes: [{ key: "outside.censys_api_key", value: "Y2Vuc3lzLWV4YW1wbGU=" }] });
    await waitFor(() => expect(screen.getByTestId("outcome").textContent).toContain("Applied."));
    expect(document.body.textContent).not.toContain("Y2Vuc3lzLWV4YW1wbGU=");
  });

  it("tests a source and shows its line", async () => {
    serve();
    server.use(
      http.post(`${BASE}/api/v1/admin/jobs/check`, () => HttpResponse.json(job({}), { status: 202 })),
      http.get(`${BASE}/api/v1/admin/jobs/60`, () => HttpResponse.json(job({ state: "done", result: { target: "outside:virustotal", ok: true, output: ["virustotal: the key works"] } }))),
    );
    const user = userEvent.setup();
    renderApp("/threat-intel");
    const vt = await screen.findByTestId("source-virustotal");
    await user.click(within(vt).getByRole("button", { name: "Test VirusTotal" }));
    expect(JSON.parse(sent("POST", "/api/v1/admin/jobs/check")[0]?.body ?? "null")).toEqual({ target: "outside:virustotal" });
    expect(await within(vt).findByText("Passed")).toBeTruthy();
    expect(within(vt).getByRole("log").textContent).toBe("virustotal: the key works");
  });

  it("is for administrators", async () => {
    renderApp("/threat-intel");
    expect((await screen.findByTestId("admin-only")).textContent).toContain("Only an ARGUS administrator");
    expect(sent("GET", "/api/v1/admin/usage")).toEqual([]);
  });
});

describe("Costs and usage", () => {
  const METRICS = { backlog: [], calls: [], fallbacks: 0, floor_hits: 0, validator_blocks: 0, outcomes: [{ assessor: "the AI investigator", label: "Real but harmless", count: 50 }], quota: [], stopped: false, month_cost_usd: 2.5 };
  const serveBoard = (more: Partial<UsageOut> = {}) => {
    serve(more);
    server.use(http.get(`${BASE}/api/v1/metrics`, () => HttpResponse.json(METRICS)));
  };

  it("is the dashboards' fourth board, and the old address leads to it", async () => {
    serveBoard();
    const { router } = renderApp("/costs");
    expect(await screen.findByTestId("stat-month")).toBeTruthy();
    expect(router.state.location.pathname).toBe("/dashboards");
    expect(router.state.location.search).toEqual({ d: "costs" });
    expect(screen.getByRole("button", { name: "Costs" }).getAttribute("aria-pressed")).toBe("true");
    expect(screen.queryByRole("group", { name: "Time range" })).toBeNull();
  });

  it("leads with what was spent against the caps and where the month is heading", async () => {
    serveBoard();
    renderApp("/dashboards?d=costs");
    const month = await screen.findByTestId("stat-month");
    expect(month.textContent).toContain("$2.50");
    expect(month.textContent).toContain("of a $10.00 cap");
    expect(screen.getByTestId("stat-today").textContent).toContain("$0.0040");
    expect(screen.getByTestId("stat-today").textContent).toContain("of a $0.30 cap");
    expect(screen.getByTestId("stat-projected").textContent).toMatch(/On course for\$\d/);
    expect(screen.getByTestId("stat-projected").textContent).toContain("by the month's end");
    expect(screen.getByTestId("stat-unit").textContent).toContain("$0.05");
    expect(screen.getByTestId("stat-unit").textContent).toContain("50 proposed outcomes this month");
    expect(screen.getByTestId("stat-lookups").textContent).toContain("12");
    const caps = within(screen.getByTestId("caps"));
    expect(caps.getByRole("img", { name: "Today: $0.0040 of $0.30" })).toBeTruthy();
    expect(caps.getByRole("img", { name: "This month: $2.50 of $10.00" })).toBeTruthy();
    expect(caps.getByRole("link", { name: "Change the caps ›" }).getAttribute("href")).toBe("/app/ai");
  });

  it("says when every AI call is stopped, with the way to resume", async () => {
    serveBoard({ stopped: true });
    renderApp("/dashboards?d=costs");
    const stopped = await screen.findByTestId("costs-stopped");
    expect(stopped.textContent).toContain("All AI calls are stopped");
    expect(within(stopped).getByRole("link").getAttribute("href")).toBe("/app/ai");
  });

  it("draws the spend a day by provider, read in dollars by the arrow keys or as a table", async () => {
    const user = userEvent.setup();
    serveBoard();
    renderApp("/dashboards?d=costs");
    const card = within(await screen.findByTestId("spend-days"));
    expect(card.getAllByTestId("column")).toHaveLength(31);
    expect(within(card.getByTestId("legend")).getAllByRole("listitem").map((li) => li.textContent)).toEqual(["freecloud", "paidcloud"]);
    const chart = card.getByTestId("columns");
    fireEvent.keyDown(chart, { key: "ArrowLeft" });
    const readout = card.getByTestId("readout").textContent ?? "";
    expect(readout).toContain("$0.42");
    expect(readout).toContain("paidcloud");
    expect(card.getByRole("img", { name: /^Spend a day: \$0\.42 in 31 days; the most, \$0\.42, on / })).toBeTruthy();
    await user.click(card.getByRole("button", { name: "Show as a table" }));
    const rows = within(card.getByRole("table", { name: "Spend a day, by provider" })).getAllByRole("row");
    expect(rows).toHaveLength(32);
    expect(rows.at(-2)?.textContent).toContain("$0.42");
  });

  it("gives two providers it does not know two different colours", async () => {
    serveBoard();
    renderApp("/dashboards?d=costs");
    const legend = within(within(await screen.findByTestId("calls-days")).getByTestId("legend"));
    const fills = legend.getAllByRole("listitem").map((li) => li.querySelector("rect")?.getAttribute("class"));
    expect(new Set(fills).size).toBe(2);
    expect(fills).not.toContain("fill-viz-rest");
  });

  it("says what the money is for and which provider answered", async () => {
    serveBoard();
    renderApp("/dashboards?d=costs");
    const tasks = within(await screen.findByTestId("tasks"));
    expect(tasks.getAllByRole("listitem").map((li) => li.textContent)).toEqual(["Second opinions on P1 incidents5 · $0.42", "Incident readings9 · $0.00"]);
    const providers = within(screen.getByTestId("providers"));
    expect(providers.getAllByRole("listitem").map((li) => li.textContent)).toEqual(["freecloud9 · 89% answered · $0.00", "paidcloud5 · 100% answered · $0.42"]);
    expect(screen.getByTestId("stat-calls").textContent).toContain("14");
    expect(screen.getByTestId("stat-calls").textContent).toContain("13 answered · 64% on free providers");
  });

  it("shows each threat-intel source against its daily limit", async () => {
    serveBoard();
    renderApp("/dashboards?d=costs");
    const sources = within(await screen.findByTestId("sources"));
    const cards = sources.getAllByTestId("source");
    expect(cards.map((c) => c.textContent?.slice(0, 12))).toEqual(["VirusTotalOn", "ShodanOn wit", "CensysOffLoo"]);
    expect(within(cards[0] as HTMLElement).getByRole("img", { name: "Lookups today: 12 of 400" })).toBeTruthy();
    expect(cards[0]?.textContent).toContain("140 this month, 139 answered · limit: 3 a minute, 400 a day");
    expect(sources.getByRole("link", { name: "Keys and limits ›" }).getAttribute("href")).toBe("/app/threat-intel");
  });

  it("says when nothing was spent and the lookups are not counted yet", async () => {
    serveBoard({ month_usd: 0, today_usd: 0, ai_days: [], ai_tasks: [], sources: [], sources_at: null });
    renderApp("/dashboards?d=costs");
    expect((await screen.findByTestId("stat-calls")).textContent).toContain("ARGUS decided without a model");
    expect(screen.getByText("No AI task ran this month.")).toBeTruthy();
    expect(screen.getByText(/has not counted the lookups yet/)).toBeTruthy();
  });

  it("is an administrator's: nobody else is shown the figures, and nothing is asked for them", async () => {
    serve();
    server.use(...shellHandlers(sessionWith(["view"])));
    renderApp("/dashboards?d=costs");
    expect((await screen.findByTestId("costs-admin-only")).textContent).toContain("an administrator's to see");
    expect(screen.queryByTestId("stat-month")).toBeNull();
    expect(sent("GET", "/api/v1/admin/usage")).toEqual([]);
  });

  it("Threat intel is in the menu under Administration; Costs and usage, opened rarely, under More", async () => {
    const user = userEvent.setup();
    serve();
    renderApp("/");
    const nav = within(await screen.findByRole("navigation", { name: "Main" }));
    const administration = within(nav.getByRole("region", { name: "Administration" }));
    expect(administration.getByRole("link", { name: "Threat intel" }).getAttribute("href")).toBe("/app/threat-intel");
    expect(administration.queryByRole("link", { name: "Costs and usage" })).toBeNull();
    await user.click(nav.getByRole("button", { name: /More/ }));
    const more = within(screen.getByTestId("more-list"));
    expect(more.getByRole("link", { name: "Costs and usage" }).getAttribute("href")).toBe("/app/costs");
  });
});
