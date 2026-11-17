// The administration screens (D-327), against a mock of the API: Settings (a change sends only what
// was edited, the outcome is polled, a key is never echoed, the SIEM-write words gate, step-up),
// Users and roles (the add dialog, the one-time link shown once, switching off asks first) and the
// first-time setup (the exact answers and keys sent, the output shown as it comes).
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import type { AccountOut, AccountsOut, JobOut, SectionOut, SettingChangesOut, SettingOut, SettingsOut } from "../src/client/types.gen";
import { BASE, mockApi, renderApp, sent, server, sessionWith, shellHandlers } from "./helpers";

mockApi();
const ADMIN = sessionWith(["view", "admin"], { user: { id: 1, username: "asha", display_name: "Asha" } });
const WORDS = "let ARGUS write to the SIEM";

function setting(more: Partial<SettingOut>): SettingOut {
  return { key: "history.window", label: "History window", help: "How far back ARGUS looks.", kind: "duration", risk: "normal", editable: true, optional: false, choices: [], minimum: null, maximum: null, default: 432_000, value: 432_000, is_set: null, homes: ["config/argus.yaml"], in_app: false, ...more };
}
const SECTIONS: SectionOut[] = [
  {
    key: "general",
    label: "General",
    about: "How ARGUS behaves.",
    settings: [
      setting({}),
      setting({ key: "web.port", label: "Web port", kind: "int", minimum: 1024, maximum: 65_535, value: 8765, default: 8765 }),
      setting({ key: "ui.dense", label: "Dense tables", kind: "bool", value: false, default: false, in_app: true, homes: ["config/admin.yaml"] }),
      setting({ key: "locked.value", label: "Load budget", kind: "int", editable: false, value: 3, default: 3 }),
    ],
  },
  {
    key: "siem",
    label: "SIEM and Kibana",
    about: "Where the alerts come from.",
    settings: [
      setting({ key: "siem.api_key", label: "SIEM API key", kind: "secret", risk: "sensitive", value: null, default: null, is_set: true, homes: [".env"] }),
      setting({ key: "kibana.write_classes", label: "Kibana write classes", kind: "list", risk: "siem_write", value: [], default: [], help: "Which writes ARGUS may make to Kibana." }),
    ],
  },
];
function settingsOut(more: Partial<SettingsOut> = {}): SettingsOut {
  return { sections: SECTIONS, applier: { running: true, last_seen: "2026-11-16T10:00:00Z" }, problem: null, confirm_words: WORDS, setup_needed: false, ...more };
}
const serveSettings = (more: Partial<SettingsOut> = {}) => server.use(...shellHandlers(ADMIN), http.get(`${BASE}/api/v1/admin/settings`, () => HttpResponse.json(settingsOut(more))));
const change = (id: number, key: string, state: SettingChangesOut["changes"][number]["state"], outcome: string | null = null) => ({ id, key, state, outcome, created_at: "2026-11-16T10:00:00Z", finished_at: state === "pending" ? null : "2026-11-16T10:00:03Z", by: "asha" });
const bodyOf = (path: string, i = 0) => JSON.parse(sent("POST", path)[i]?.body ?? "null") as unknown;

describe("Settings", () => {
  it("lists the sections, reads each setting from its type and marks what is not editable", async () => {
    serveSettings();
    renderApp("/settings");
    expect(await screen.findByRole("heading", { level: 1, name: "Settings" })).toBeTruthy();
    expect(document.title).toBe("Settings · ARGUS");
    const window_ = screen.getByTestId("setting-history.window");
    expect((within(window_).getByLabelText("History window") as HTMLInputElement).value).toBe("5d");
    expect(window_.textContent).toContain("5 days");
    expect(window_.textContent).toContain("config/argus.yaml");
    expect((within(screen.getByTestId("setting-web.port")).getByLabelText("Web port") as HTMLInputElement).type).toBe("number");
    expect(within(screen.getByTestId("setting-ui.dense")).getByText("Changed in the app")).toBeTruthy();
    const locked = screen.getByTestId("setting-locked.value");
    expect((within(locked).getByLabelText("Load budget") as HTMLInputElement).disabled).toBe(true);
    expect(locked.textContent).toContain("Set in the files");
    expect(screen.queryByTestId("applier-down")).toBeNull();
  });

  it("says when argus-admin is not running, and what the problem is", async () => {
    serveSettings({ applier: { running: false, last_seen: null }, problem: "local.yaml could not be read" });
    renderApp("/settings");
    expect((await screen.findByTestId("applier-down")).textContent).toContain("argus-admin is not running: changes you save wait until it runs");
    expect(screen.getByTestId("settings-problem").textContent).toBe("local.yaml could not be read");
  });

  it("sends only the edited setting, then shows the change pending and then applied", async () => {
    serveSettings();
    let polls = 0;
    server.use(
      http.post(`${BASE}/api/v1/admin/changes`, () => HttpResponse.json({ batch: "b-1", changes: [change(7, "history.window", "pending")] }, { status: 202 })),
      http.get(`${BASE}/api/v1/admin/changes`, () => HttpResponse.json({ batch: "b-1", changes: [change(7, "history.window", ++polls < 2 ? "pending" : "applied", polls < 2 ? null : "ARGUS restarted.")] })),
    );
    const user = userEvent.setup();
    renderApp("/settings");
    const box = (await screen.findByLabelText("History window")) as HTMLInputElement;
    expect(screen.getByRole("button", { name: "Save" }).getAttribute("aria-disabled")).toBe("true");
    await user.clear(box);
    await user.type(box, "36h");
    expect(screen.getByText("36 hours")).toBeTruthy();
    expect(screen.getByText("1 unsaved")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Save 1 change" }));
    await waitFor(() => expect(screen.getByTestId("outcome").textContent).toContain("Waiting for argus-admin"));
    expect(bodyOf("/api/v1/admin/changes")).toEqual({ changes: [{ key: "history.window", value: "36h" }] });
    await waitFor(() => expect(screen.getByTestId("outcome").textContent).toContain("Applied. ARGUS restarted."));
  });

  it("puts a refusal at the field it names", async () => {
    serveSettings();
    server.use(http.post(`${BASE}/api/v1/admin/changes`, () => HttpResponse.json({ code: "invalid", detail: "History window: must be at least 1h." }, { status: 422 })));
    const user = userEvent.setup();
    renderApp("/settings");
    const box = await screen.findByLabelText("History window");
    await user.clear(box);
    await user.type(box, "30m");
    await user.click(screen.getByRole("button", { name: "Save 1 change" }));
    const alert = await within(screen.getByTestId("setting-history.window")).findByRole("alert");
    expect(alert.textContent).toBe("History window: must be at least 1h.");
  });

  it("does not send a value the form can see is wrong", async () => {
    serveSettings();
    const user = userEvent.setup();
    renderApp("/settings");
    const box = await screen.findByLabelText("History window");
    await user.clear(box);
    await user.type(box, "soon");
    await user.click(screen.getByRole("button", { name: /^Save/ }));
    expect(within(screen.getByTestId("setting-history.window")).getByRole("alert").textContent).toContain("A length of time");
    expect(sent("POST", "/api/v1/admin/changes")).toEqual([]);
  });

  it("sends a reset for a setting changed in the app", async () => {
    serveSettings();
    server.use(
      http.post(`${BASE}/api/v1/admin/changes`, () => HttpResponse.json({ batch: "b-2", changes: [change(8, "ui.dense", "pending")] }, { status: 202 })),
      http.get(`${BASE}/api/v1/admin/changes`, () => HttpResponse.json({ batch: "b-2", changes: [change(8, "ui.dense", "pending")] })),
    );
    const user = userEvent.setup();
    renderApp("/settings");
    await user.click(await screen.findByRole("button", { name: "Back to the file's value" }));
    expect(screen.getByTestId("reset-note")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Save 1 change" }));
    await waitFor(() => expect(sent("POST", "/api/v1/admin/changes").length).toBe(1));
    expect(bodyOf("/api/v1/admin/changes")).toEqual({ changes: [{ key: "ui.dense", reset: true }] });
  });

  it("filters settings by label, key or help", async () => {
    serveSettings();
    const user = userEvent.setup();
    renderApp("/settings");
    await user.type(await screen.findByLabelText("Search the settings"), "write to Kibana");
    expect(screen.getByTestId("setting-kibana.write_classes")).toBeTruthy();
    expect(screen.queryByTestId("setting-history.window")).toBeNull();
    await user.clear(screen.getByLabelText("Search the settings"));
    await user.type(screen.getByLabelText("Search the settings"), "zzzz");
    expect(screen.getByText("No setting matches that search.")).toBeTruthy();
  });

  it("never echoes a key: Set, a Replace box, the typed key sent once and gone", async () => {
    serveSettings();
    server.use(
      http.post(`${BASE}/api/v1/admin/changes`, () => HttpResponse.json({ batch: "b-3", changes: [change(9, "siem.api_key", "pending")] }, { status: 202 })),
      http.get(`${BASE}/api/v1/admin/changes`, () => HttpResponse.json({ batch: "b-3", changes: [change(9, "siem.api_key", "pending")] })),
    );
    const user = userEvent.setup();
    renderApp("/settings");
    await user.click(await screen.findByRole("button", { name: /SIEM and Kibana/ }));
    const field = screen.getByTestId("setting-siem.api_key");
    expect(within(field).getByTestId("secret-state").textContent).toBe("Set");
    const input = within(field).getByLabelText("SIEM API key") as HTMLInputElement;
    expect(input.type).toBe("password");
    expect(input.value).toBe("");
    expect(within(field).queryByText("Back to the file's value")).toBeNull();
    await user.type(input, "ZXhhbXBsZS1rZXk=");
    expect(screen.getByText("Needs your password again")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Save 1 change" }));
    await waitFor(() => expect(sent("POST", "/api/v1/admin/changes").length).toBe(1));
    expect(bodyOf("/api/v1/admin/changes")).toEqual({ changes: [{ key: "siem.api_key", value: "ZXhhbXBsZS1rZXk=" }] });
    await waitFor(() => expect((screen.getByLabelText("SIEM API key") as HTMLInputElement).value).toBe(""));
    expect(document.body.textContent).not.toContain("ZXhhbXBsZS1rZXk=");
    expect(sent("GET", "/api/v1/admin/changes").every((r) => !r.path.includes("ZXhhb"))).toBe(true);
  });

  it("asks for the words before a change that lets ARGUS write to the SIEM", async () => {
    serveSettings();
    server.use(
      http.post(`${BASE}/api/v1/admin/changes`, () => HttpResponse.json({ batch: "b-4", changes: [change(10, "kibana.write_classes", "pending")] }, { status: 202 })),
      http.get(`${BASE}/api/v1/admin/changes`, () => HttpResponse.json({ batch: "b-4", changes: [change(10, "kibana.write_classes", "pending")] })),
    );
    const user = userEvent.setup();
    renderApp("/settings");
    await user.click(await screen.findByRole("button", { name: /SIEM and Kibana/ }));
    await user.click(screen.getByRole("button", { name: "Add an item" }));
    await user.type(screen.getByLabelText("Kibana write classes, item 1"), "W1");
    await user.click(screen.getByRole("button", { name: "Save 1 change" }));
    const dialog = await screen.findByRole("dialog");
    expect(dialog.textContent).toContain("Until now it only read");
    expect(sent("POST", "/api/v1/admin/changes")).toEqual([]);
    const save = within(dialog).getByRole("button", { name: "Save the change" }) as HTMLButtonElement;
    expect(save.disabled).toBe(true);
    await user.type(within(dialog).getByLabelText(/Type/), "let ARGUS write");
    expect(save.disabled).toBe(true);
    await user.type(within(dialog).getByLabelText(/Type/), " to the SIEM");
    expect(save.disabled).toBe(false);
    await user.click(save);
    await waitFor(() => expect(sent("POST", "/api/v1/admin/changes").length).toBe(1));
    expect(bodyOf("/api/v1/admin/changes")).toEqual({ changes: [{ key: "kibana.write_classes", value: ["W1"] }], confirm: WORDS });
  });

  it("sends the person to confirm their password when the server asks, keeping what they typed", async () => {
    serveSettings();
    server.use(http.post(`${BASE}/api/v1/admin/changes`, () => HttpResponse.json({ code: "step_up_required", detail: "Confirm your password again (within five minutes) to change this." }, { status: 403 })));
    const user = userEvent.setup();
    renderApp("/settings");
    const box = await screen.findByLabelText("Web port");
    await user.clear(box);
    await user.type(box, "9000");
    await user.click(screen.getByRole("button", { name: "Save 1 change" }));
    const error = await screen.findByTestId("save-error");
    const link = within(error).getByRole("link", { name: /Confirm your password/ });
    expect(link.getAttribute("href")).toBe("/stepup?next=%2Fapp%2Fsettings");
    expect((screen.getByLabelText("Web port") as HTMLInputElement).value).toBe("9000");
  });

  it("is for administrators", async () => {
    renderApp("/settings");
    expect((await screen.findByTestId("admin-only")).textContent).toContain("Only an ARGUS administrator");
    expect(sent("GET", "/api/v1/admin/settings")).toEqual([]);
  });
});

function user_(more: Partial<AccountOut>): AccountOut {
  return { id: 2, username: "mina", display_name: "Mina Rao", disabled: false, capabilities: ["view", "review"], role: "analyst", managed_in_elk: false, break_glass: false, created_at: "2026-11-01T10:00:00Z", last_seen_at: "2026-11-16T09:00:00Z", open_sessions: 1, link_open: false, ...more };
}
const ROLES: AccountsOut["roles"] = [
  { key: "viewer", label: "Viewer", about: "Reads only.", capabilities: ["view"] },
  { key: "analyst", label: "Analyst", about: "Reviews alerts.", capabilities: ["view", "review"] },
  { key: "lead", label: "Lead", about: "Runs the shift.", capabilities: ["view", "review", "approve"] },
  { key: "admin", label: "Administrator", about: "Everything.", capabilities: ["view", "admin"] },
];
const PEOPLE = [user_({ id: 1, username: "asha", display_name: "Asha", role: "admin", capabilities: ["view", "admin"] }), user_({}), user_({ id: 3, username: "ravi", display_name: "Ravi", role: "elk", managed_in_elk: true, open_sessions: 0 }), user_({ id: 4, username: "emergency", display_name: "Emergency", break_glass: true, open_sessions: 0 })];
const serveUsers = (users: AccountOut[] = PEOPLE) => server.use(...shellHandlers(ADMIN), http.get(`${BASE}/api/v1/admin/users`, () => HttpResponse.json({ users, roles: ROLES })));

describe("Users and roles", () => {
  it("lists people with their role, sessions and status; ELK and emergency accounts are read-only and say why", async () => {
    serveUsers();
    renderApp("/users");
    const table = await screen.findByRole("table", { name: "People who can sign in to ARGUS" });
    const rows = within(table).getAllByRole("row");
    const mina = rows.find((r) => r.textContent?.includes("Mina Rao"));
    expect(mina?.textContent).toContain("Analyst");
    expect(within(mina as HTMLElement).getByRole("button", { name: "Change role of Mina Rao" })).toBeTruthy();
    const ravi = rows.find((r) => r.textContent?.includes("Ravi"));
    expect(ravi?.textContent).toContain("ELK sign-in");
    expect(ravi?.textContent).toContain("changed there");
    expect(within(ravi as HTMLElement).queryByRole("button")).toBeNull();
    expect(rows.find((r) => r.textContent?.includes("Emergency"))?.textContent).toContain("command line");
    const me = rows.find((r) => r.textContent?.includes("This is you"));
    expect(within(me as HTMLElement).queryByRole("button", { name: /Switch off/ })).toBeNull();
    expect(screen.getByText("What the roles mean")).toBeTruthy();
  });

  it("checks the sign-in name before it asks the server", async () => {
    serveUsers();
    const user = userEvent.setup();
    renderApp("/users");
    await user.click(await screen.findByRole("button", { name: "Add a person" }));
    await user.type(screen.getByLabelText(/^Name/), "Sam Roy");
    await user.type(screen.getByLabelText(/^Sign-in name/), "Sam Roy");
    await user.click(screen.getByRole("button", { name: "Add the person" }));
    expect(await screen.findByText(/lower-case letter/)).toBeTruthy();
    expect(sent("POST", "/api/v1/admin/users")).toEqual([]);
  });

  it("adds a person and shows the one-time link once, with what to do with it", async () => {
    serveUsers();
    server.use(http.post(`${BASE}/api/v1/admin/users`, () => HttpResponse.json({ user: user_({ id: 9, username: "sam", display_name: "Sam Roy", link_open: true }), link: "/welcome?token=abc123", expires_at: "2026-11-19T10:00:00Z" }, { status: 201 })));
    const user = userEvent.setup();
    renderApp("/users");
    await user.click(await screen.findByRole("button", { name: "Add a person" }));
    await user.type(screen.getByLabelText(/^Name/), "Sam Roy");
    await user.type(screen.getByLabelText(/^Sign-in name/), "sam");
    await user.selectOptions(screen.getByLabelText("Role"), "lead");
    await user.click(screen.getByRole("button", { name: "Add the person" }));
    const shown = await screen.findByTestId("link-shown");
    expect(shown.textContent).toContain("It works once, for 72 hours");
    expect((within(shown).getByLabelText(/link to set a password/) as HTMLInputElement).value).toBe(`${window.location.origin}/welcome?token=abc123`);
    expect(within(shown).getByRole("button", { name: "Copy" })).toBeTruthy();
    expect(bodyOf("/api/v1/admin/users")).toEqual({ username: "sam", display_name: "Sam Roy", role: "lead" });
    await user.click(within(shown).getByRole("button", { name: "I have given it" }));
    await waitFor(() => expect(screen.queryByTestId("link-shown")).toBeNull());
    await user.click(screen.getByRole("button", { name: "Add a person" }));
    expect(screen.queryByTestId("link-shown")).toBeNull();
    expect((screen.getByLabelText(/^Sign-in name/) as HTMLInputElement).value).toBe("");
  });

  it("asks before it switches someone off, and sends exactly what it showed", async () => {
    serveUsers();
    server.use(http.put(`${BASE}/api/v1/admin/users/2/access`, () => HttpResponse.json(user_({ disabled: true }))));
    const user = userEvent.setup();
    renderApp("/users");
    await user.click(await screen.findByRole("button", { name: "Switch off Mina Rao" }));
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog.textContent).toContain("They can no longer sign in");
    expect(sent("PUT", "/api/v1/admin/users/2/access")).toEqual([]);
    await user.click(within(dialog).getByRole("button", { name: "Switch off" }));
    await waitFor(() => expect(sent("PUT", "/api/v1/admin/users/2/access").length).toBe(1));
    expect(JSON.parse(sent("PUT", "/api/v1/admin/users/2/access")[0]?.body ?? "")).toEqual({ disabled: true });
  });

  it("changes a role with a custom set that always includes view", async () => {
    serveUsers();
    server.use(http.put(`${BASE}/api/v1/admin/users/2/capabilities`, () => HttpResponse.json(user_({ role: "custom" }))));
    const user = userEvent.setup();
    renderApp("/users");
    await user.click(await screen.findByRole("button", { name: "Change role of Mina Rao" }));
    const dialog = await screen.findByRole("dialog");
    await user.selectOptions(within(dialog).getByLabelText("Role"), "custom");
    await user.click(within(dialog).getByLabelText("Approve writes to Kibana"));
    await user.click(within(dialog).getByRole("button", { name: "Save the role" }));
    await waitFor(() => expect(sent("PUT", "/api/v1/admin/users/2/capabilities").length).toBe(1));
    expect(JSON.parse(sent("PUT", "/api/v1/admin/users/2/capabilities")[0]?.body ?? "")).toEqual({ capabilities: ["view", "review", "approve"] });
  });
});

const job = (more: Partial<JobOut>): JobOut => ({ id: 31, kind: "setup", state: "running", result: null, created_at: "2026-11-16T10:00:00Z", finished_at: null, ...more });
const ANCHOR = "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89";

async function fillOrganisation(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole("button", { name: "Begin" }));
  await user.type(await screen.findByLabelText(/^Organisation name/), "Example University");
  await user.type(screen.getByLabelText(/^Security team's name/), "CSOC");
  await user.type(screen.getByLabelText(/^Your own domains/), "example.edu");
  await user.click(screen.getByRole("button", { name: "Continue" }));
}

const AI: Partial<Record<string, unknown>> = {
  providers: [{ name: "freecloud", enabled: true, api: "openai", trust: "cloud", paid: false, models: {}, keys: [{ name: "FREECLOUD_API_KEY", setting: "llm.keys.FREECLOUD_API_KEY", is_set: false }], monthly_cap_usd: null, daily_cap_usd: null, month_usd: 0, today_usd: 0, calls_month: 0, ok_month: 0, alarm: null }],
};
const serveSetup = () =>
  server.use(
    ...shellHandlers(ADMIN),
    http.get(`${BASE}/api/v1/admin/settings`, () => HttpResponse.json(settingsOut({ setup_needed: true }))),
    http.get(`${BASE}/api/v1/admin/ai`, () => HttpResponse.json({ applier: { running: true, last_seen: null }, problem: null, stopped: false, any_key: false, monthly_cap_usd: null, daily_cap_usd: null, month_usd: 0, today_usd: 0, purposes: [], agents: [], readings_on: false, team: [], team_keys_expire: null, settings: [], ...AI })),
  );

describe("First-time setup", () => {
  it("walks the chapters with the administrator's login and sends exactly the answers and keys", async () => {
    serveSetup();
    server.use(
      http.post(`${BASE}/api/v1/admin/jobs/inspect-tls`, () => HttpResponse.json(job({ id: 30, kind: "inspect_tls", state: "pending" }), { status: 202 })),
      http.get(`${BASE}/api/v1/admin/jobs/30`, () => HttpResponse.json(job({ id: 30, kind: "inspect_tls", state: "done", result: { url: "https://siem.example.org:9200", anchor: ANCHOR, chain: [{ subject: "CN=siem", issuer: "CN=Lab CA", fingerprint: "11:22", not_after: "2027-01-01T00:00:00+00:00", self_signed: false }, { subject: "CN=Lab CA", issuer: "CN=Lab CA", fingerprint: ANCHOR, not_after: "2030-01-01T00:00:00+00:00", self_signed: true }] } }))),
      http.post(`${BASE}/api/v1/admin/jobs/setup`, () => HttpResponse.json(job({ state: "pending" }), { status: 202 })),
    );
    let polls = 0;
    server.use(http.get(`${BASE}/api/v1/admin/jobs/31`, () => HttpResponse.json(++polls < 2 ? job({ state: "running", result: null }) : job({ state: "done", finished_at: "2026-11-16T10:03:00Z", result: { ok: true, exit: 0, output: ["step 1 ok", "step 2 ok"], after: ["Virustotal api key: stored", "asset map: imported"] } }))));
    const user = userEvent.setup();
    renderApp("/setup");
    expect(await screen.findByRole("heading", { level: 1, name: /first.line analyst/ })).toBeTruthy();
    await fillOrganisation(user);
    expect(await screen.findByRole("heading", { level: 1, name: "Connect your SIEM." })).toBeTruthy();
    expect(screen.getByRole("progressbar", { name: "Setup progress" }).getAttribute("aria-valuenow")).toBe("2");
    await user.type(screen.getByLabelText(/^The SIEM's address/), "https://siem.example.org:9200");
    await user.click(screen.getByRole("button", { name: "Check the certificate" }));
    expect((await screen.findByTestId("anchor")).textContent).toBe(ANCHOR);
    await user.click(screen.getByRole("radio", { name: /Trust this certificate authority/ }));
    await user.click(screen.getByRole("button", { name: "Continue" }));
    expect(await screen.findByRole("heading", { level: 1, name: "Let ARGUS set itself up." })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Continue" }));
    expect(screen.getByText("Choose how ARGUS gets its access.")).toBeTruthy();
    await user.click(screen.getByRole("radio", { name: /Let ARGUS create its own access/ }));
    await user.type(screen.getByLabelText(/^Administrator's user name/), "elastic-admin");
    await user.type(screen.getByLabelText(/^Password/), "admin-pass-1");
    await user.click(screen.getByRole("button", { name: "Continue" }));
    await user.click(await screen.findByRole("radio", { name: /Connect Kibana/ }));
    await user.type(screen.getByLabelText(/^Kibana's address/), "https://siem.example.org:5601");
    expect(screen.queryByLabelText(/^Kibana's read-only API key/)).toBeNull();
    await user.click(screen.getByRole("button", { name: "Continue" }));
    expect(await screen.findByRole("heading", { level: 1, name: "Bring your own AI. Or don't." })).toBeTruthy();
    await user.type(screen.getByLabelText(/freecloud/), "ai-key-1");
    await user.click(screen.getByRole("button", { name: "Continue" }));
    await user.type(await screen.findByLabelText(/VirusTotal/), "vt-key-1");
    await user.click(screen.getByRole("button", { name: "Continue" }));
    await user.upload(await screen.findByLabelText("Choose the asset map file"), new File(["networks: []\n"], "assets.yaml"));
    expect((await screen.findByTestId("asset-chosen")).textContent).toContain("assets.yaml");
    await user.click(screen.getByRole("button", { name: "Continue" }));
    const plan = await screen.findByTestId("elastic-plan");
    expect(plan.textContent).toContain("argus-reader");
    expect(plan.textContent).toContain("argus-kibana-reader");
    expect(plan.textContent).toContain("argus-visualiser");
    const review = screen.getByTestId("review");
    expect(review.textContent).toContain("Example University");
    expect(review.textContent).toContain("never stored");
    for (const secret of ["admin-pass-1", "ai-key-1", "vt-key-1"]) expect(document.body.textContent).not.toContain(secret);
    await user.click(screen.getByRole("button", { name: "Run the setup" }));
    await waitFor(() => expect(screen.getByTestId("running")).toBeTruthy());
    const body = bodyOf("/api/v1/admin/jobs/setup") as { answers: Record<string, unknown>; keys: Record<string, string>; asset_map: string };
    expect(body.keys).toEqual({ "elastic.admin_password": "admin-pass-1", "llm.key.freecloud_api_key": "ai-key-1", "outside.virustotal_api_key": "vt-key-1" });
    expect(body.asset_map).toBe("networks: []\n");
    expect(JSON.stringify(body.answers)).not.toContain("admin-pass-1");
    expect(body.answers).toMatchObject({ "siem.url": "https://siem.example.org:9200", "siem.trust": "chain", "siem.fingerprint": ANCHOR, "elastic.admin_user": "elastic-admin", "case_team.provision": true, "kibana.url": "https://siem.example.org:5601", "discovery.accept": true, "llm.keys_file": "none", "organisation.own_domains": ["example.edu"] });
    expect(await screen.findByRole("heading", { level: 1, name: "ARGUS is ready." })).toBeTruthy();
    expect(screen.getByTestId("setup-after").textContent).toContain("asset map: imported");
    expect(screen.getByTestId("setup-output").textContent).toContain("step 2 ok");
    expect(screen.getByRole("link", { name: "Open Today" }).getAttribute("href")).toBe("/app/");
  });

  it("does not leave a chapter that is not filled in, and says what is missing", async () => {
    serveSetup();
    const user = userEvent.setup();
    renderApp("/setup");
    await user.click(await screen.findByRole("button", { name: "Begin" }));
    await user.click(await screen.findByRole("button", { name: "Continue" }));
    expect(screen.getByText("Write the organisation's name.")).toBeTruthy();
    expect(screen.getByText("Add at least one domain.")).toBeTruthy();
    expect(screen.getByRole("heading", { level: 1, name: "Tell us who you are." })).toBeTruthy();
  });

  it("pastes keys instead, skips the optional chapters, shows what failed and asks for the password when needed", async () => {
    serveSetup();
    server.use(
      http.post(`${BASE}/api/v1/admin/jobs/setup`, () => HttpResponse.json({ code: "step_up_required", detail: "Confirm your password again (within five minutes) to run the setup." }, { status: 403 }), { once: true }),
      http.post(`${BASE}/api/v1/admin/jobs/setup`, () => HttpResponse.json(job({ state: "pending" }), { status: 202 })),
      http.get(`${BASE}/api/v1/admin/jobs/31`, () => HttpResponse.json(job({ state: "done", result: { ok: false, exit: 1, output: ["siem: 401 from the SIEM"] } }))),
    );
    const user = userEvent.setup();
    renderApp("/setup");
    await fillOrganisation(user);
    await user.type(await screen.findByLabelText(/^The SIEM's address/), "https://siem.example.org:9200");
    await user.click(screen.getByRole("radio", { name: /My system already trusts it/ }));
    await user.click(screen.getByRole("button", { name: "Continue" }));
    await user.click(await screen.findByRole("radio", { name: /Paste read-only keys/ }));
    await user.type(screen.getByLabelText(/^The read-only API key/), "k");
    await user.click(screen.getByRole("button", { name: "Continue" }));
    await user.click(await screen.findByRole("radio", { name: /Not now/ }));
    await user.click(screen.getByRole("button", { name: "Continue" }));
    await user.type(await screen.findByLabelText(/freecloud/), "typed-then-skipped");
    await user.click(screen.getByRole("button", { name: "Skip ›" }));
    await user.click(await screen.findByRole("button", { name: "Skip ›" }));
    await user.click(await screen.findByRole("button", { name: "Skip ›" }));
    const review = await screen.findByTestId("review");
    expect(review.textContent).toContain("add keys later in AI and agents");
    expect(screen.queryByTestId("elastic-plan")).toBeNull();
    await user.click(screen.getByRole("button", { name: "Run the setup" }));
    const error = await screen.findByTestId("run-error");
    expect(within(error).getByRole("link", { name: /Confirm your password/ }).getAttribute("href")).toBe("/stepup?next=%2Fapp%2Fsetup");
    await user.click(screen.getByRole("button", { name: "Run the setup" }));
    await waitFor(() => expect(screen.getByTestId("setup-output").textContent).toContain("401 from the SIEM"));
    const body = bodyOf("/api/v1/admin/jobs/setup", 1) as { answers: Record<string, unknown>; keys: Record<string, string> };
    expect(body.keys).toEqual({ "siem.api_key": "k" });
    expect(body.answers).toMatchObject({ "elastic.admin_user": "none", "kibana.url": "none", "siem.trust": "system" });
    expect(screen.getByRole("heading", { level: 1, name: "The setup did not finish." })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Back to fix" }));
    expect(await screen.findByRole("heading", { level: 1, name: "Ready when you are." })).toBeTruthy();
  });

  it("says when ARGUS is already connected and offers to run it again", async () => {
    server.use(...shellHandlers(ADMIN), http.get(`${BASE}/api/v1/admin/settings`, () => HttpResponse.json(settingsOut())), http.get(`${BASE}/api/v1/admin/ai`, () => HttpResponse.json({})));
    const user = userEvent.setup();
    renderApp("/setup");
    expect(await screen.findByRole("heading", { level: 1, name: "ARGUS is connected." })).toBeTruthy();
    await user.click(screen.getByTestId("already"));
    expect(await screen.findByRole("heading", { level: 1, name: "Tell us who you are." })).toBeTruthy();
  });
});

describe("Today and the menu", () => {
  it("asks an administrator to finish the setup, calmly, when it is needed", async () => {
    server.use(...shellHandlers(ADMIN), http.get(`${BASE}/api/v1/admin/settings`, () => HttpResponse.json(settingsOut({ setup_needed: true }))));
    renderApp("/");
    const card = await screen.findByTestId("setup-card");
    expect(card.textContent).toContain("Finish the first-time setup");
    expect(within(card).getByRole("link", { name: "Start the setup" }).getAttribute("href")).toBe("/app/setup");
  });

  it("shows no setup card once ARGUS is set up, or to someone who is not an administrator", async () => {
    server.use(...shellHandlers(ADMIN), http.get(`${BASE}/api/v1/admin/settings`, () => HttpResponse.json(settingsOut())));
    const first = renderApp("/");
    await screen.findByRole("heading", { level: 1 });
    await waitFor(() => expect(sent("GET", "/api/v1/admin/settings").length).toBe(1));
    expect(screen.queryByTestId("setup-card")).toBeNull();
    first.unmount();
    server.use(...shellHandlers(sessionWith(["view"])));
    renderApp("/");
    await screen.findByRole("heading", { level: 1 });
    expect(sent("GET", "/api/v1/admin/settings").length).toBe(1);
  });

  it("lists Settings, AI and agents and Users and roles under Administration, for an administrator only", async () => {
    const user = userEvent.setup();
    server.use(...shellHandlers(ADMIN), http.get(`${BASE}/api/v1/admin/settings`, () => HttpResponse.json(settingsOut())));
    renderApp("/");
    await user.click(within(await screen.findByRole("navigation", { name: "Main" })).getByRole("button", { name: /More/ }));
    const more = within(screen.getByTestId("more-list"));
    expect(more.getByText("Administration")).toBeTruthy();
    expect(more.getByRole("link", { name: "Settings" }).getAttribute("href")).toBe("/app/settings");
    expect(more.getByRole("link", { name: "Users and roles" }).getAttribute("href")).toBe("/app/users");
    expect(more.getByRole("link", { name: "AI and agents" }).getAttribute("href")).toBe("/app/ai");
  });
});
