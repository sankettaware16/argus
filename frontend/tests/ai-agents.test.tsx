// The "AI and agents" page (D-328), against a mock of the API: the summary first (off, stopped,
// on), the kill switch as a job, a provider's key sent once and never shown, a sensitive cap that
// asks for the password, a task's provider order (emptied: all), the readings switch through
// risk.reading, the Test button's output, the agents read-only, the case team's link, and the menu.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import type { AiOut, JobOut, SettingOut, SettingsOut } from "../src/client/types.gen";
import { BASE, mockApi, renderApp, sent, server, sessionWith, shellHandlers } from "./helpers";

mockApi();
const ADMIN = sessionWith(["view", "admin"], { user: { id: 1, username: "asha", display_name: "Asha" } });

function setting(more: Partial<SettingOut> & { key: string }): SettingOut {
  return { label: "On", help: "", kind: "bool", risk: "normal", editable: true, optional: false, choices: [], minimum: null, maximum: null, default: null, value: null, is_set: null, homes: [], in_app: false, ...more };
}
const SETTINGS: SettingOut[] = [
  setting({ key: "llm.monthly_cap_usd", label: "Monthly limit (USD)", kind: "float", risk: "sensitive", minimum: 0, value: 10 }),
  setting({ key: "llm.daily_cap_usd", label: "Daily limit (USD)", kind: "float", risk: "sensitive", optional: true, minimum: 0, value: 0.3 }),
  setting({ key: "llm.providers.freecloud.enabled", value: true }),
  setting({ key: "llm.providers.freecloud.monthly_cap_usd", label: "Its monthly limit (USD)", kind: "float", risk: "sensitive", optional: true, minimum: 0 }),
  setting({ key: "llm.providers.freecloud.daily_cap_usd", label: "Its daily limit (USD)", kind: "float", risk: "sensitive", optional: true, minimum: 0 }),
  setting({ key: "llm.keys.FREECLOUD_API_KEY", label: "freecloud: FREECLOUD_API_KEY", kind: "secret", risk: "sensitive", is_set: false }),
  setting({ key: "llm.providers.paidcloud.enabled", value: false, in_app: true, homes: ["set in the app"] }),
  setting({ key: "llm.providers.paidcloud.monthly_cap_usd", label: "Its monthly limit (USD)", kind: "float", risk: "sensitive", optional: true, minimum: 0, value: 5 }),
  setting({ key: "llm.providers.paidcloud.daily_cap_usd", label: "Its daily limit (USD)", kind: "float", risk: "sensitive", optional: true, minimum: 0 }),
  setting({ key: "llm.keys.PAIDCLOUD_API_KEY", label: "paidcloud: PAIDCLOUD_API_KEY", kind: "secret", risk: "sensitive", is_set: true }),
  setting({ key: "llm.purposes.opinion.calls_per_day", label: "Calls a day", kind: "int", optional: true, minimum: 0, value: 20 }),
  setting({ key: "llm.purposes.opinion.providers", label: "Providers, in order", kind: "list", optional: true, choices: ["freecloud", "paidcloud"], value: ["paidcloud", "freecloud"] }),
  setting({ key: "llm.purposes.opinion.tier", label: "Model size", kind: "choice", optional: true, choices: ["small", "medium", "large"], value: "large" }),
];

function aiOut(more: Partial<AiOut> = {}): AiOut {
  return {
    applier: { running: true, last_seen: "2026-11-16T10:00:00Z" },
    problem: null,
    stopped: false,
    any_key: true,
    monthly_cap_usd: 10,
    daily_cap_usd: 0.3,
    month_usd: 1.25,
    today_usd: 0.05,
    providers: [
      { name: "freecloud", enabled: true, api: "openai", trust: "cloud", paid: false, models: { large: "free-large-1", small: "free-small-1" }, keys: [{ name: "FREECLOUD_API_KEY", setting: "llm.keys.FREECLOUD_API_KEY", is_set: false }], monthly_cap_usd: null, daily_cap_usd: null, month_usd: 0, today_usd: 0, calls_month: 12, ok_month: 11, alarm: null },
      { name: "paidcloud", enabled: false, api: "openai", trust: "cloud", paid: true, models: { medium: "paid-medium-2" }, keys: [{ name: "PAIDCLOUD_API_KEY", setting: "llm.keys.PAIDCLOUD_API_KEY", is_set: true }], monthly_cap_usd: 5, daily_cap_usd: null, month_usd: 1.25, today_usd: 0.05, calls_month: 3, ok_month: 3, alarm: "quota: 429 from the provider" },
    ],
    purposes: [{ task: "opinion", label: "A second opinion on P1 incidents", calls_per_day: 20, providers: ["paidcloud", "freecloud"], tier: "large", calls_today: 4 }],
    agents: [
      { name: "investigator", kind: "coordinator", version: "3", mission: "Decides whether an incident is real, with the specialists' help.", task: "investigate", tier: "large", tools: ["search_logs", "lookup_asset"], specialists: ["network"], triggers: ["p1"], on: true, enabled_version: "3", problem: null, calls_month: 7 },
      { name: "network", kind: "specialist", version: "2", mission: "Reads the network evidence.", tier: "medium", tools: ["search_logs"], specialists: [], triggers: [], on: false, enabled_version: null, problem: "its pin does not match the file", calls_month: 0 },
    ],
    readings_on: true,
    team: [
      { user: "argus-lead", setting: "case_team.lead_api_key", is_set: true },
      { user: "argus-evidence", setting: "case_team.evidence_api_key", is_set: false },
    ],
    team_keys_expire: "2027-03-01",
    settings: SETTINGS,
    ...more,
  };
}
const SETTINGS_OUT: SettingsOut = {
  sections: [{ key: "risk", label: "Incident engine", about: "How alerts become possible incidents.", settings: [setting({ key: "risk.reading", label: "Reading", value: true })] }],
  applier: { running: true, last_seen: "2026-11-16T10:00:00Z" },
  problem: null,
  confirm_words: "let ARGUS write to the SIEM",
  setup_needed: false,
};
const serveAi = (more: Partial<AiOut> = {}) =>
  server.use(
    ...shellHandlers(ADMIN),
    http.get(`${BASE}/api/v1/admin/ai`, () => HttpResponse.json(aiOut(more))),
    http.get(`${BASE}/api/v1/admin/settings`, () => HttpResponse.json(SETTINGS_OUT)),
  );
const job = (more: Partial<JobOut>): JobOut => ({ id: 40, kind: "check", state: "pending", result: null, created_at: "2026-11-16T10:00:00Z", finished_at: null, ...more });
const change = (id: number, key: string) => ({ id, key, state: "pending" as const, outcome: null, created_at: "2026-11-16T10:00:00Z", finished_at: null, by: "asha" });
const bodyOf = (path: string, i = 0) => JSON.parse(sent("POST", path)[i]?.body ?? "null") as unknown;
const acceptSave = (key: string) =>
  server.use(
    http.post(`${BASE}/api/v1/admin/changes`, () => HttpResponse.json({ batch: "b-9", changes: [change(1, key)] }, { status: 202 })),
    http.get(`${BASE}/api/v1/admin/changes`, () => HttpResponse.json({ batch: "b-9", changes: [change(1, key)] })),
  );

describe("AI and agents", () => {
  it("says first what state the AI is in, then spending, providers, tasks, agents and the case team", async () => {
    serveAi();
    renderApp("/ai");
    expect(await screen.findByRole("heading", { level: 1, name: "AI and agents" })).toBeTruthy();
    expect(document.title).toBe("AI and agents · ARGUS");
    expect(screen.getByTestId("ai-summary").textContent).toContain("The AI is on");
    expect(screen.getByTestId("ai-status").textContent).toContain("This month $1.25 of $10.00; today $0.05 of $0.30.");
    expect(screen.getByRole("button", { name: "Stop all AI calls" })).toBeTruthy();
    const free = screen.getByTestId("provider-freecloud");
    expect(free.textContent).toContain("Free");
    expect(free.textContent).toContain("12 calls this month, 11 answered");
    expect(within(free).getAllByRole("listitem").map((li) => li.textContent)).toEqual(["small: free-small-1", "large: free-large-1"]);
    expect(within(free).queryByLabelText("Its monthly limit (USD)")).toBeNull();
    const paid = screen.getByTestId("provider-paidcloud");
    expect(paid.textContent).toContain("Paid");
    expect(paid.textContent).toContain("$1.25 of $5.00");
    expect(screen.getByTestId("alarm-paidcloud").textContent).toBe("quota: 429 from the provider");
    expect(within(paid).getByText("Changed in the app")).toBeTruthy();
    expect(screen.getByTestId("purpose-opinion").textContent).toContain("4 calls today of 20 a day");
    expect((screen.getByLabelText("ARGUS AI readings") as HTMLInputElement).checked).toBe(true);
    const agent = screen.getByTestId("agent-investigator");
    expect(agent.textContent).toContain("coordinator");
    expect(agent.textContent).toContain("search_logs, lookup_asset");
    expect(agent.textContent).toContain("7 calls this month");
    expect(within(agent).queryByRole("checkbox")).toBeNull();
    expect(screen.getByTestId("agent-problem-network").textContent).toBe("its pin does not match the file");
    expect(screen.getByTestId("agents-note").textContent).toContain("comes with an ARGUS release, not from this page");
    const team = screen.getByTestId("ai-team");
    expect(team.textContent).toContain("argus-evidence");
    expect(team.textContent).toContain("expire on 2027-03-01");
    expect(within(team).getByRole("link", { name: /Set the keys in Settings/ }).getAttribute("href")).toBe("/app/settings?section=case_team");
  });

  it("shows ARGUS's own team first: the default pack, each member in a line with its state", async () => {
    serveAi();
    renderApp("/ai");
    const pack = await screen.findByTestId("ai-pack");
    const cards = screen.getAllByRole("region").map((r) => r.getAttribute("aria-label"));
    expect(cards.indexOf("ARGUS's team")).toBeLessThan(cards.indexOf("Status"));
    expect(within(pack).getByText("Default pack · tested")).toBeTruthy();
    expect(within(pack).getAllByRole("listitem").map((li) => li.getAttribute("data-testid"))).toEqual(["pack-lead", "pack-investigator", "pack-evidence", "pack-intel", "pack-responder", "pack-hunter", "pack-reporter", "pack-visualiser"]);
    const investigator = within(pack).getByTestId("pack-investigator");
    expect(investigator.textContent).toContain("Agent: on");
    expect(investigator.textContent).toContain("Its specialists: network");
    expect(within(pack).getByTestId("pack-lead").textContent).toContain("Kibana key: set");
    expect(within(pack).getByTestId("pack-evidence").textContent).toContain("Kibana key: not set");
    expect(within(pack).getByTestId("pack-intel").textContent).toContain("Agent: not installed");
    expect(within(pack).getByTestId("pack-later").textContent).toBe("Your own agents and workflows: coming later.");
    expect(within(pack).queryByRole("button")).toBeNull();
  });

  it("says the AI is off without a key, and that ARGUS still works", async () => {
    serveAi({ any_key: false });
    renderApp("/ai");
    expect((await screen.findByTestId("ai-off")).textContent).toBe("The AI is off: add a key for at least one provider below. ARGUS still works without it.");
  });

  it("shows argus-admin down and the settings' problem", async () => {
    serveAi({ applier: { running: false, last_seen: null }, problem: "llm.local.yaml could not be read" });
    renderApp("/ai");
    expect((await screen.findByTestId("applier-down")).textContent).toContain("argus-admin is not running");
    expect(screen.getByTestId("ai-problem").textContent).toBe("llm.local.yaml could not be read");
  });

  it("stops every AI call as a job, then reads the page again", async () => {
    let stopped = false;
    serveAi();
    server.use(
      http.get(`${BASE}/api/v1/admin/ai`, () => HttpResponse.json(aiOut({ stopped }))),
      http.post(`${BASE}/api/v1/admin/jobs/llm-switch`, () => HttpResponse.json(job({ id: 41, kind: "llm_switch" }), { status: 202 })),
      http.get(`${BASE}/api/v1/admin/jobs/41`, () => {
        stopped = true;
        return HttpResponse.json(job({ id: 41, kind: "llm_switch", state: "done", result: { ok: true, stopped: true, changed: true } }));
      }),
    );
    const user = userEvent.setup();
    renderApp("/ai");
    await user.click(await screen.findByRole("button", { name: "Stop all AI calls" }));
    expect(bodyOf("/api/v1/admin/jobs/llm-switch")).toEqual({ stop: true });
    expect((await screen.findByTestId("ai-stopped")).textContent).toContain("All AI calls are stopped");
    expect(screen.getByRole("button", { name: "Resume AI calls" })).toBeTruthy();
  });

  it("resumes when stopped", async () => {
    serveAi({ stopped: true });
    server.use(http.post(`${BASE}/api/v1/admin/jobs/llm-switch`, () => HttpResponse.json(job({ id: 42, kind: "llm_switch" }), { status: 202 })), http.get(`${BASE}/api/v1/admin/jobs/42`, () => HttpResponse.json(job({ id: 42, kind: "llm_switch", state: "running" }))));
    const user = userEvent.setup();
    renderApp("/ai");
    await user.click(await screen.findByRole("button", { name: "Resume AI calls" }));
    await waitFor(() => expect(sent("POST", "/api/v1/admin/jobs/llm-switch").length).toBe(1));
    expect(bodyOf("/api/v1/admin/jobs/llm-switch")).toEqual({ stop: false });
  });

  it("adds a provider key: a password box, sent once, never shown", async () => {
    serveAi();
    acceptSave("llm.keys.FREECLOUD_API_KEY");
    const user = userEvent.setup();
    renderApp("/ai");
    const box = (await screen.findByLabelText("Add key: FREECLOUD_API_KEY")) as HTMLInputElement;
    expect(box.type).toBe("password");
    expect(within(screen.getByTestId("setting-llm.keys.FREECLOUD_API_KEY")).getByTestId("secret-state").textContent).toBe("Not set");
    expect(screen.getByLabelText("Replace key: PAIDCLOUD_API_KEY")).toBeTruthy();
    await user.type(box, "ZXhhbXBsZS1haS1rZXk=");
    expect(screen.getByText("Needs your password again")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Save 1 change" }));
    await waitFor(() => expect(sent("POST", "/api/v1/admin/changes").length).toBe(1));
    expect(bodyOf("/api/v1/admin/changes")).toEqual({ changes: [{ key: "llm.keys.FREECLOUD_API_KEY", value: "ZXhhbXBsZS1haS1rZXk=" }] });
    await waitFor(() => expect((screen.getByLabelText("Add key: FREECLOUD_API_KEY") as HTMLInputElement).value).toBe(""));
    expect(document.body.textContent).not.toContain("ZXhhbXBsZS1haS1rZXk=");
    expect(screen.getByTestId("outcome").textContent).toContain("freecloud: FREECLOUD_API_KEY");
  });

  it("asks for the password when a spending limit's save is refused for it, keeping what was typed", async () => {
    serveAi();
    server.use(http.post(`${BASE}/api/v1/admin/changes`, () => HttpResponse.json({ code: "step_up_required", detail: "Confirm your password again (within five minutes) to change this." }, { status: 403 })));
    const user = userEvent.setup();
    renderApp("/ai");
    const box = await screen.findByLabelText("Monthly limit (USD)");
    await user.clear(box);
    await user.type(box, "12.5");
    await user.click(screen.getByRole("button", { name: "Save 1 change" }));
    const error = await screen.findByTestId("save-error");
    expect(within(error).getByRole("link", { name: /Confirm your password/ }).getAttribute("href")).toBe("/stepup?next=%2Fapp%2Fconfirmed");
    expect(bodyOf("/api/v1/admin/changes")).toEqual({ changes: [{ key: "llm.monthly_cap_usd", value: 12.5 }] });
    expect((screen.getByLabelText("Monthly limit (USD)") as HTMLInputElement).value).toBe("12.5");
  });

  it("switches a provider on, the readings off and a task's model size in one save", async () => {
    serveAi();
    acceptSave("risk.reading");
    const user = userEvent.setup();
    renderApp("/ai");
    await user.click(within(await screen.findByTestId("provider-paidcloud")).getByLabelText("Use this provider"));
    await user.click(screen.getByLabelText("ARGUS AI readings"));
    await user.selectOptions(screen.getByLabelText("Model size"), "medium");
    await user.click(screen.getByRole("button", { name: "Save 3 changes" }));
    await waitFor(() => expect(sent("POST", "/api/v1/admin/changes").length).toBe(1));
    const body = bodyOf("/api/v1/admin/changes") as { changes: unknown[] };
    expect(body.changes).toEqual(
      expect.arrayContaining([
        { key: "llm.providers.paidcloud.enabled", value: true },
        { key: "llm.purposes.opinion.tier", value: "medium" },
        { key: "risk.reading", value: false },
      ]),
    );
    expect(body.changes.length).toBe(3);
  });

  it("orders a task's providers from the list, and an emptied list is sent as all (null)", async () => {
    serveAi();
    acceptSave("llm.purposes.opinion.providers");
    const user = userEvent.setup();
    renderApp("/ai");
    await user.click(await screen.findByRole("button", { name: "Move freecloud up" }));
    expect(within(screen.getByRole("group", { name: "Providers, in order" })).getAllByRole("listitem").map((li) => li.textContent?.slice(0, 11))).toEqual(["1.freecloud", "2.paidcloud"]);
    await user.click(screen.getByRole("button", { name: "Remove freecloud" }));
    await user.click(screen.getByRole("button", { name: "Remove paidcloud" }));
    expect(screen.getByText("All providers, in the files' order.")).toBeTruthy();
    await user.selectOptions(screen.getByLabelText("Add a provider to Providers, in order"), "paidcloud");
    await user.click(screen.getByRole("button", { name: "Remove paidcloud" }));
    await user.click(screen.getByRole("button", { name: "Save 1 change" }));
    await waitFor(() => expect(sent("POST", "/api/v1/admin/changes").length).toBe(1));
    expect(bodyOf("/api/v1/admin/changes")).toEqual({ changes: [{ key: "llm.purposes.opinion.providers", value: null }] });
  });

  it("sends a reset for a provider switch changed in the app", async () => {
    serveAi();
    acceptSave("llm.providers.paidcloud.enabled");
    const user = userEvent.setup();
    renderApp("/ai");
    await user.click(within(await screen.findByTestId("provider-paidcloud")).getByRole("button", { name: "Back to the file's value" }));
    await user.click(screen.getByRole("button", { name: "Save 1 change" }));
    await waitFor(() => expect(sent("POST", "/api/v1/admin/changes").length).toBe(1));
    expect(bodyOf("/api/v1/admin/changes")).toEqual({ changes: [{ key: "llm.providers.paidcloud.enabled", reset: true }] });
  });

  it("tests a provider: the job's result and what it said", async () => {
    serveAi();
    server.use(
      http.post(`${BASE}/api/v1/admin/jobs/check`, () => HttpResponse.json(job({ id: 43 }), { status: 202 })),
      http.get(`${BASE}/api/v1/admin/jobs/43`, () => HttpResponse.json(job({ id: 43, state: "done", result: { target: "llm:paidcloud", ok: false, exit: 1, output: ["paidcloud: 401 from the provider", "api_key=***"] } }))),
    );
    const user = userEvent.setup();
    renderApp("/ai");
    const paid = await screen.findByTestId("provider-paidcloud");
    await user.click(within(paid).getByRole("button", { name: "Test paidcloud" }));
    expect(bodyOf("/api/v1/admin/jobs/check")).toEqual({ target: "llm:paidcloud" });
    expect(await within(paid).findByText("Failed")).toBeTruthy();
    expect(within(paid).getByRole("log").textContent).toContain("401 from the provider");
  });

  it("is for administrators", async () => {
    renderApp("/ai");
    expect((await screen.findByTestId("admin-only")).textContent).toContain("Only an ARGUS administrator");
    expect(sent("GET", "/api/v1/admin/ai")).toEqual([]);
  });

  it("is in the menu under Administration, after Settings, for an administrator only", async () => {
    const user = userEvent.setup();
    serveAi();
    const view = renderApp("/");
    await user.click(within(await screen.findByRole("navigation", { name: "Main" })).getByRole("button", { name: /More/ }));
    const more = within(screen.getByTestId("more-list"));
    const links = more.getAllByRole("link").map((a) => a.textContent?.trim());
    expect(links.indexOf("AI and agents")).toBe(links.indexOf("Settings") + 1);
    expect(more.getByRole("link", { name: "AI and agents" }).getAttribute("href")).toBe("/app/ai");
    view.unmount();
    server.use(...shellHandlers(sessionWith(["view"])));
    renderApp("/");
    await user.click(within(await screen.findByRole("navigation", { name: "Main" })).getByRole("button", { name: /More/ }));
    // a development build shows the administration entries to everyone (the API still refuses)
    expect(within(screen.getByTestId("more-list")).queryByRole("link", { name: "AI and agents" }) !== null).toBe(import.meta.env.DEV);
  });
});
