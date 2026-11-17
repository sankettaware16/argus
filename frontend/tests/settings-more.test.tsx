// Settings' additions (D-328) and Today's notice, against a mock of the API: the history (labels
// from the loaded sections, the key when unknown), the connection checks of the SIEM and the Kibana
// keys, an asset map's upload (refused over 5 MB or not YAML, the step-up asked, the job polled),
// the link to a section, and a non-administrator told the setup is pending.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import type { JobOut, SectionOut, SettingOut, SettingsOut } from "../src/client/types.gen";
import { BASE, mockApi, renderApp, sent, server, sessionWith, shellHandlers } from "./helpers";

mockApi();
const ADMIN = sessionWith(["view", "admin"], { user: { id: 1, username: "asha", display_name: "Asha" } });

function setting(more: Partial<SettingOut> & { key: string; label: string }): SettingOut {
  return { help: "", kind: "text", risk: "normal", editable: true, optional: true, choices: [], minimum: null, maximum: null, default: null, value: null, is_set: null, homes: [], in_app: false, ...more };
}
const SECTIONS: SectionOut[] = [
  { key: "siem", label: "SIEM", about: "The Elasticsearch ARGUS reads alerts and logs from.", settings: [setting({ key: "siem.url", label: "SIEM address", value: "https://siem.example.org:9200" })] },
  { key: "kibana", label: "Kibana", about: "The Kibana ARGUS reads cases from.", settings: [setting({ key: "kibana.reader_api_key", label: "Kibana read-only key", kind: "secret", risk: "sensitive", is_set: true })] },
  { key: "case_team", label: "Kibana cases", about: "How confirmed incidents become Kibana cases.", settings: [setting({ key: "case_team.lead_api_key", label: "Lead's key", kind: "secret", risk: "sensitive", is_set: false })] },
  { key: "assets", label: "Asset map", about: "The organisation's devices, networks and owners.", settings: [setting({ key: "assets.map_path", label: "Asset map file", kind: "path", risk: "sensitive" })] },
];
const SETTINGS: SettingsOut = { sections: SECTIONS, applier: { running: true, last_seen: "2026-11-16T10:00:00Z" }, problem: null, confirm_words: "let ARGUS write to the SIEM", setup_needed: false };
const serveSettings = () => server.use(...shellHandlers(ADMIN), http.get(`${BASE}/api/v1/admin/settings`, () => HttpResponse.json(SETTINGS)));
const job = (more: Partial<JobOut>): JobOut => ({ id: 50, kind: "check", state: "pending", result: null, created_at: "2026-11-16T10:00:00Z", finished_at: null, ...more });

describe("Settings: history", () => {
  it("lists the last changes with who, when, the setting's label (or its key) and the outcome", async () => {
    serveSettings();
    server.use(
      http.get(`${BASE}/api/v1/admin/changes`, () =>
        HttpResponse.json({
          batch: null,
          changes: [
            { id: 3, key: "siem.url", state: "applied", outcome: "ARGUS restarted.", created_at: "2026-11-16T10:00:00Z", finished_at: "2026-11-16T10:00:04Z", by: "asha" },
            { id: 2, key: "llm.monthly_cap_usd", state: "refused", outcome: "at least 0", created_at: "2026-11-15T09:00:00Z", finished_at: "2026-11-15T09:00:02Z", by: "mina" },
          ],
        }),
      ),
    );
    const user = userEvent.setup();
    renderApp("/settings");
    expect(sent("GET", "/api/v1/admin/changes")).toEqual([]);
    await user.click(await screen.findByRole("button", { name: /^History/ }));
    const table = await screen.findByRole("table", { name: "The last fifty changes" });
    expect(sent("GET", "/api/v1/admin/changes")[0]?.path).toBe("/api/v1/admin/changes");
    const rows = within(table).getAllByRole("row").slice(1);
    expect(rows[0]?.textContent).toContain("asha");
    expect(rows[0]?.textContent).toContain("SIEM address");
    expect(rows[0]?.textContent).toContain("Applied. ARGUS restarted.");
    expect(rows[1]?.textContent).toContain("llm.monthly_cap_usd");
    expect(rows[1]?.textContent).toContain("refused");
    expect(screen.queryByTestId("save-bar")).toBeNull();
  });

  it("says when nothing was changed in the app yet", async () => {
    serveSettings();
    server.use(http.get(`${BASE}/api/v1/admin/changes`, () => HttpResponse.json({ batch: null, changes: [] })));
    renderApp("/settings?section=history");
    expect(await screen.findByText("No setting has been changed in the app yet.")).toBeTruthy();
  });
});

describe("Settings: connection checks", () => {
  it("checks the SIEM's connection: passed, with what it said folded", async () => {
    serveSettings();
    server.use(
      http.post(`${BASE}/api/v1/admin/jobs/check`, () => HttpResponse.json(job({}), { status: 202 })),
      http.get(`${BASE}/api/v1/admin/jobs/50`, () => HttpResponse.json(job({ state: "done", result: { target: "siem", ok: true, exit: 0, output: ["version 8.19", "the key may read logs-*"] } }))),
    );
    const user = userEvent.setup();
    renderApp("/settings");
    const checks = await screen.findByTestId("checks-siem");
    await user.click(within(checks).getByRole("button", { name: "Check the connection" }));
    expect(JSON.parse(sent("POST", "/api/v1/admin/jobs/check")[0]?.body ?? "null")).toEqual({ target: "siem" });
    expect(await within(checks).findByText("Passed")).toBeTruthy();
    expect(within(checks).getByRole("log").textContent).toContain("the key may read logs-*");
  });

  it("checks each Kibana key on its own and shows why a check could not run", async () => {
    serveSettings();
    server.use(
      http.post(`${BASE}/api/v1/admin/jobs/check`, () => HttpResponse.json(job({ id: 51 }), { status: 202 })),
      http.get(`${BASE}/api/v1/admin/jobs/51`, () => HttpResponse.json(job({ id: 51, state: "failed", result: { error: "the check of kibana:cases took longer than 3 minutes" } }))),
    );
    const user = userEvent.setup();
    renderApp("/settings?section=kibana");
    const checks = await screen.findByTestId("checks-kibana");
    expect(within(checks).getAllByRole("button").map((b) => b.textContent)).toEqual(["Check the read-only key", "Check the cases key", "Check the alerts key"]);
    await user.click(within(checks).getByRole("button", { name: "Check the cases key" }));
    expect(JSON.parse(sent("POST", "/api/v1/admin/jobs/check")[0]?.body ?? "null")).toEqual({ target: "kibana:cases" });
    const cases = within(checks).getByTestId("check-kibana:cases");
    expect(await within(cases).findByText("Failed")).toBeTruthy();
    expect(within(cases).getByRole("alert").textContent).toContain("took longer than 3 minutes");
  });
});

describe("Settings: the asset map's upload", () => {
  const yaml = (text: string, name = "assets.yaml") => new File([text], name, { type: "application/yaml" });

  it("refuses a file that is not YAML or is over 5 MB, and sends nothing", async () => {
    serveSettings();
    const user = userEvent.setup({ applyAccept: false });
    renderApp("/settings?section=assets");
    const input = await screen.findByLabelText("Upload an asset map");
    await user.upload(input, new File(["x"], "assets.csv"));
    expect((await screen.findByText("Choose a .yaml or .yml file.")).textContent).toBeTruthy();
    await user.upload(input, yaml("x".repeat(5_000_001)));
    expect(await screen.findByText(/larger than 5 MB/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Import" }).getAttribute("aria-disabled")).toBe("true");
    expect(sent("POST", "/api/v1/admin/jobs/assets")).toEqual([]);
  });

  it("asks for the password when the server wants it, keeps the file, then imports it and shows the result", async () => {
    serveSettings();
    server.use(
      http.post(`${BASE}/api/v1/admin/jobs/assets`, () => HttpResponse.json({ code: "step_up_required", detail: "Confirm your password again (within five minutes) to import an asset map." }, { status: 403 }), { once: true }),
      http.post(`${BASE}/api/v1/admin/jobs/assets`, () => HttpResponse.json(job({ id: 52, kind: "assets" }), { status: 202 })),
      http.get(`${BASE}/api/v1/admin/jobs/52`, () => HttpResponse.json(job({ id: 52, kind: "assets", state: "done", result: { ok: true, exit: 0, output: ["imported 12 networks, 40 devices"] } }))),
    );
    const user = userEvent.setup();
    renderApp("/settings?section=assets");
    await user.upload(await screen.findByLabelText("Upload an asset map"), yaml("networks:\n  - 192.0.2.0/24\n"));
    await user.click(await screen.findByRole("button", { name: "Import assets.yaml" }));
    const upload = screen.getByTestId("asset-upload");
    expect(within(upload).getByRole("link", { name: /Confirm your password/ }).getAttribute("href")).toBe("/stepup?next=%2Fapp%2Fconfirmed");
    await user.click(screen.getByRole("button", { name: "Import assets.yaml" }));
    expect(await within(upload).findByText("Imported")).toBeTruthy();
    expect(within(upload).getByRole("log").textContent).toContain("imported 12 networks");
    expect(sent("POST", "/api/v1/admin/jobs/assets").map((r) => JSON.parse(r.body) as unknown)).toEqual([{ content: "networks:\n  - 192.0.2.0/24\n" }, { content: "networks:\n  - 192.0.2.0/24\n" }]);
  });
});

describe("Settings: a list of entries", () => {
  it("shows each entry as a line of text, not as an editable box", async () => {
    server.use(
      ...shellHandlers(ADMIN),
      http.get(`${BASE}/api/v1/admin/settings`, () =>
        HttpResponse.json({ ...SETTINGS, sections: [{ key: "site", label: "Organisation and data sources", about: "Who runs ARGUS.", settings: [setting({ key: "site.families", label: "Families", kind: "list", value: [{ name: "proxy", role: "proxy" }] })] }] }),
      ),
    );
    renderApp("/settings");
    const list = await screen.findByTestId("entry-list");
    expect(list.textContent).toContain('{"name":"proxy","role":"proxy"}');
    expect(document.body.textContent).not.toContain("[object Object]");
    expect(within(screen.getByTestId("setting-site.families")).queryByRole("button", { name: "Add an item" })).toBeNull();
  });
});

describe("Settings: help and where a setting is set", () => {
  it("shows a help text's ``names`` as code and where the value comes from as written", async () => {
    server.use(
      ...shellHandlers(ADMIN),
      http.get(`${BASE}/api/v1/admin/settings`, () =>
        HttpResponse.json({ ...SETTINGS, sections: [{ key: "siem", label: "SIEM", about: "The SIEM.", settings: [setting({ key: "siem.api_key", label: "API key", kind: "secret", is_set: true, help: "The read-only ``argus_reader`` key; only in ``.env``.", homes: ["in .env"] })] }] }),
      ),
    );
    renderApp("/settings");
    const field = await screen.findByTestId("setting-siem.api_key");
    expect([...field.querySelectorAll("code")].map((c) => c.textContent)).toEqual(["argus_reader", ".env"]);
    expect(field.textContent).not.toContain("``");
    expect(field.textContent).toContain("siem.api_key · in .env");
    expect(field.textContent).not.toContain("set in in");
  });
});

describe("Settings: the organisation's domains", () => {
  it("says what a domain covers and refuses a shared suffix at the field", async () => {
    server.use(
      ...shellHandlers(ADMIN),
      http.get(`${BASE}/api/v1/admin/settings`, () =>
        HttpResponse.json({ ...SETTINGS, sections: [{ key: "site", label: "Organisation and data sources", about: "Who runs ARGUS.", settings: [setting({ key: "site.own_domains", label: "Own domains", kind: "list", value: ["example.edu"] })] }] }),
      ),
    );
    const user = userEvent.setup();
    renderApp("/settings");
    const field = await screen.findByTestId("setting-site.own_domains");
    expect(within(field).getByTestId("setting-hint").textContent).toContain("every subdomain");
    await user.click(within(field).getByRole("button", { name: "Add an item" }));
    await user.type(within(field).getByLabelText("Own domains, item 2"), "ac.in");
    await user.click(screen.getByRole("button", { name: "Save 1 change" }));
    expect(within(field).getByRole("alert").textContent).toBe("ac.in is shared by every organisation; give your own, e.g. example.ac.in.");
    expect(sent("POST", "/api/v1/admin/changes")).toEqual([]);
  });
});

describe("Settings: a link to a section", () => {
  it("opens the section the address names", async () => {
    serveSettings();
    renderApp("/settings?section=case_team");
    expect(await screen.findByRole("heading", { level: 2, name: "Kibana cases" })).toBeTruthy();
    expect(within(screen.getByRole("navigation", { name: "Settings sections" })).getByRole("button", { current: true }).textContent).toContain("Kibana cases");
  });
});

describe("Today: the setup is pending", () => {
  it("tells someone who is not an administrator, calmly, and asks no admin page", async () => {
    server.use(...shellHandlers(sessionWith(["view", "review"], { setup_pending: true })));
    renderApp("/");
    const card = await screen.findByTestId("setup-pending");
    expect(card.textContent).toContain("An administrator still has to finish the first-time setup");
    expect(within(card).queryByRole("link")).toBeNull();
    expect(screen.queryByTestId("setup-card")).toBeNull();
    expect(sent("GET", "/api/v1/admin/settings")).toEqual([]);
  });

  it("says nothing once the setup is done", async () => {
    server.use(...shellHandlers(sessionWith(["view"], { setup_pending: false })));
    renderApp("/");
    await screen.findByRole("heading", { level: 1 });
    expect(screen.queryByTestId("setup-pending")).toBeNull();
  });

  it("opens the setup by itself for an administrator, once: after Exit setup, Today asks to continue it", async () => {
    window.sessionStorage.clear();
    server.use(...shellHandlers(sessionWith(["view", "admin"], { setup_pending: true })), http.get(`${BASE}/api/v1/admin/settings`, () => HttpResponse.json({ ...SETTINGS, setup_needed: true })), http.get(`${BASE}/api/v1/admin/ai`, () => HttpResponse.json({})));
    const user = userEvent.setup();
    const { router } = renderApp("/");
    await waitFor(() => expect(router.state.location.pathname).toBe("/setup"));
    expect(router.state.location.search).toEqual({});
    expect(await screen.findByRole("heading", { level: 1, name: /first.line analyst/ })).toBeTruthy();
    await user.click(screen.getByRole("link", { name: "Exit setup" }));
    await waitFor(() => expect(router.state.location.pathname).toBe("/"));
    const card = await screen.findByTestId("setup-card");
    expect(card.textContent).toContain("The setup is not finished");
    expect(within(card).getByRole("link", { name: "Continue the setup" })).toBeTruthy();
    expect(router.state.location.pathname).toBe("/");
    expect(screen.queryByTestId("setup-pending")).toBeNull();
    window.sessionStorage.clear();
  });

  it("does not open the setup once it is done, nor for someone who is not an administrator", async () => {
    window.sessionStorage.clear();
    server.use(...shellHandlers(sessionWith(["view", "admin"], { setup_pending: false })), http.get(`${BASE}/api/v1/admin/settings`, () => HttpResponse.json(SETTINGS)));
    const first = renderApp("/");
    await screen.findByRole("heading", { level: 1 });
    expect(first.router.state.location.pathname).toBe("/");
    first.unmount();
    server.use(...shellHandlers(sessionWith(["view", "review"], { setup_pending: true })));
    const second = renderApp("/");
    expect(await screen.findByTestId("setup-pending")).toBeTruthy();
    expect(second.router.state.location.pathname).toBe("/");
  });

  it("while the setup is pending, the header says Setting up, calmly, and no red banner shows", async () => {
    window.sessionStorage.clear();
    server.use(...shellHandlers(sessionWith(["view", "review"], { setup_pending: true })), http.get(`${BASE}/api/v1/health`, () => HttpResponse.json({ siem_state: "normal", siem_reasons: [], siem_probed_at: null, live_cursor: null, backfill_cursor: null, open_gaps: [], last_reconciliation: null, alerts: 0, quarantined: 0, investigations: 0, jobs_waiting: 0, jobs_deferred: 0, jobs_failed: 0, dossiers: 0, checkpoint_threads: 0, checkpoint_bytes: 0, kibana_sync: { state: "none", last_cycle_at: null, last_outcome: null, last_reason: null, last_complete_at: null } })));
    renderApp("/");
    const dot = await screen.findByTestId("system-dot");
    await waitFor(() => expect(dot.getAttribute("data-state")).toBe("setup"));
    expect(dot.textContent).toContain("Setting up");
    expect(screen.queryByTestId("system-banner")).toBeNull();
  });
});
