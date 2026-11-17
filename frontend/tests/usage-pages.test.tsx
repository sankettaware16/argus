// Threat intel and Costs and usage (D-329), against a mock of the API: each source's key added
// like any key (sealed, never shown), on or off by key (Shodan's keyless fallback), its limits and
// lookups, the Test of one public address; the costs' summary first, the AI's spend a day stacked
// by provider, the tasks' table and each source's lookups against its daily limit; the menu.
import { screen, waitFor, within } from "@testing-library/react";
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
  it("says first what was spent against the limits, and that the AI is allowed", async () => {
    serve();
    renderApp("/costs");
    expect(await screen.findByRole("heading", { level: 1, name: "Costs and usage" })).toBeTruthy();
    expect(document.title).toBe("Costs and usage · ARGUS");
    expect(screen.getByTestId("costs-month").textContent).toBe("$2.50 of $10.00");
    expect(screen.getByTestId("costs-today").textContent).toBe("$0.0040 of $0.30");
    expect(within(screen.getByTestId("costs-summary")).getByRole("link", { name: /Stop them/ }).getAttribute("href")).toBe("/app/ai");
  });

  it("says when every AI call is stopped, with the way to resume", async () => {
    serve({ stopped: true });
    renderApp("/costs");
    const stopped = await screen.findByTestId("costs-stopped");
    expect(stopped.textContent).toContain("All AI calls are stopped");
    expect(within(stopped).getByRole("link").getAttribute("href")).toBe("/app/ai");
  });

  it("draws the AI's spend a day stacked by provider, the dearest first, with a legend and a table", async () => {
    serve();
    renderApp("/costs");
    const card = await screen.findByTestId("costs-ai-days");
    const chart = within(card).getByRole("img", { name: "The AI's spend a day by provider, last 31 days" });
    expect(chart.querySelectorAll("g > title").length).toBe(31);
    const legend = within(card).getByRole("list", { name: "Legend" });
    expect(within(legend).getAllByRole("listitem").map((li) => li.textContent)).toEqual(["paidcloud$0.42", "freecloud$0.00"]);
    const titles = [...chart.querySelectorAll("title")].map((t) => t.textContent);
    expect(titles).toContain(`${daysAgo(1)}: $0.42 spent, paidcloud $0.42`);
    const table = within(card).getByRole("table");
    expect(within(table).getAllByRole("row").length).toBe(3);
  });

  it("lists the tasks this month with their calls and cost", async () => {
    serve();
    renderApp("/costs");
    const rows = within(await screen.findByTestId("costs-tasks")).getAllByRole("row");
    expect(rows[1]?.textContent).toBe("Second opinions on P1 incidents5$0.42");
    expect(rows[2]?.textContent).toBe("Incident readings9$0.00");
  });

  it("draws each source's lookups a day against its daily limit", async () => {
    serve();
    renderApp("/costs");
    const vt = await screen.findByTestId("costs-source-virustotal");
    expect(vt.textContent).toContain("12 today of 400, 140 this month");
    expect(within(vt).getByRole("img", { name: "VirusTotal: lookups a day, last 31 days" }).textContent).toContain("limit 400 a day");
    expect(screen.getByTestId("costs-source-censys").textContent).toContain("Off: no key");
  });

  it("says when nothing was spent and the lookups are not counted yet", async () => {
    serve({ ai_days: [], ai_tasks: [], sources: [], sources_at: null });
    renderApp("/costs");
    expect(await screen.findByText("No AI call in the last 31 days.")).toBeTruthy();
    expect(screen.getByText("No AI call this month.")).toBeTruthy();
    expect(screen.getByText(/has not counted the lookups yet/)).toBeTruthy();
  });

  it("is in the menu under Administration with Threat intel, after AI and agents", async () => {
    const user = userEvent.setup();
    serve();
    renderApp("/");
    await user.click(within(await screen.findByRole("navigation", { name: "Main" })).getByRole("button", { name: /More/ }));
    const more = within(screen.getByTestId("more-list"));
    const links = more.getAllByRole("link").map((a) => a.textContent?.trim());
    const at = links.indexOf("Settings");
    expect(links.slice(at, at + 5)).toEqual(["Settings", "AI and agents", "Threat intel", "Costs and usage", "Users and roles"]);
    expect(more.getByRole("link", { name: "Threat intel" }).getAttribute("href")).toBe("/app/threat-intel");
    expect(more.getByRole("link", { name: "Costs and usage" }).getAttribute("href")).toBe("/app/costs");
  });
});
