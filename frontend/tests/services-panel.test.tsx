// The services panel on System health (D-329), against a mock of the API: an administrator sees
// each service and timer (running or not, the SIEM-write and deletion badges, when it was checked),
// switches an optional one with the password confirmed, types the words to switch on one that
// writes to the SIEM, restarts a service (never argus-admin); anyone else sees no panel.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import type { HealthOut, JobOut, ServiceOut, ServicesOut } from "../src/client/types.gen";
import { canRestart } from "../src/lib/admin";
import { BASE, mockApi, renderApp, sent, server, sessionWith, shellHandlers } from "./helpers";

mockApi();
const ADMIN = sessionWith(["view", "admin"], { user: { id: 1, username: "asha", display_name: "Asha" } });
const WORDS = "let ARGUS write to the SIEM";
const unit = (more: Partial<ServiceOut> & { unit: string; label: string }): ServiceOut => ({ core: false, switchable: true, on: true, running: true, writes_siem: false, deletes: false, ...more });
const UNITS: ServiceOut[] = [
  unit({ unit: "argus-web.service", label: "The web app", core: true, switchable: false }),
  unit({ unit: "argus-admin.service", label: "Applies the app's changes", core: true, switchable: false }),
  unit({ unit: "argus-retention.timer", label: "Deletes old data each night", deletes: true }),
  unit({ unit: "argus-writer.service", label: "Writes cases to Kibana", on: false, running: false, writes_siem: true }),
];
const HEALTH: HealthOut = { siem_state: "normal", siem_reasons: [], siem_probed_at: "2026-11-16T10:00:00Z", live_cursor: null, backfill_cursor: null, open_gaps: [], last_reconciliation: null, alerts: 0, quarantined: 0, investigations: 0, jobs_waiting: 0, jobs_deferred: 0, jobs_failed: 0, dossiers: 0, checkpoint_threads: 0, checkpoint_bytes: 0, kibana_sync: { state: "none", last_cycle_at: null, last_outcome: null, last_reason: null, last_complete_at: null } } as HealthOut;
const serve = (units: ServiceOut[] = UNITS) =>
  server.use(
    ...shellHandlers(ADMIN),
    http.get(`${BASE}/api/v1/health`, () => HttpResponse.json(HEALTH)),
    http.get(`${BASE}/api/v1/admin/services`, () => HttpResponse.json({ units, at: "2026-11-16T10:00:00Z", confirm_words: WORDS } satisfies ServicesOut)),
  );
const job = (more: Partial<JobOut>): JobOut => ({ id: 70, kind: "service", state: "pending", result: null, created_at: "2026-11-16T10:00:00Z", finished_at: null, ...more });
const bodies = () => sent("POST", "/api/v1/admin/jobs/service").map((r) => JSON.parse(r.body) as unknown);

describe("Services on System health", () => {
  it("lists each unit with its state and badges; a switch for the optional ones, a restart for the services but argus-admin", async () => {
    serve();
    renderApp("/health");
    const panel = await screen.findByTestId("services");
    const web = await within(panel).findByTestId("service-argus-web.service");
    expect(web.textContent).toContain("Running");
    expect(within(web).queryByRole("button", { name: /Switch/ })).toBeNull();
    expect(within(web).getByRole("button", { name: "Restart The web app" })).toBeTruthy();
    expect(within(within(panel).getByTestId("service-argus-admin.service")).queryByRole("button")).toBeNull();
    const retention = within(panel).getByTestId("service-argus-retention.timer");
    expect(retention.textContent).toContain("deletes data");
    expect(within(retention).queryByRole("button", { name: /Restart/ })).toBeNull();
    const writer = within(panel).getByTestId("service-argus-writer.service");
    expect(writer.textContent).toContain("writes to the SIEM");
    expect(writer.textContent).toContain("Off");
    expect(within(writer).getByRole("button", { name: "Switch on Writes cases to Kibana" })).toBeTruthy();
    expect(panel.textContent).toContain("Checked");
  });

  it("switches a timer off, polls the job and reads the list again", async () => {
    let off = false;
    serve();
    server.use(
      http.get(`${BASE}/api/v1/admin/services`, () => HttpResponse.json({ units: UNITS.map((u) => (u.unit === "argus-retention.timer" && off ? { ...u, on: false, running: false } : u)), at: "2026-11-16T10:00:00Z", confirm_words: WORDS })),
      http.post(`${BASE}/api/v1/admin/jobs/service`, () => HttpResponse.json(job({}), { status: 202 })),
      http.get(`${BASE}/api/v1/admin/jobs/70`, () => {
        off = true;
        return HttpResponse.json(job({ state: "done", result: { ok: true } }));
      }),
    );
    const user = userEvent.setup();
    renderApp("/health");
    await user.click(await screen.findByRole("button", { name: "Switch off Deletes old data each night" }));
    expect(bodies()).toEqual([{ unit: "argus-retention.timer", action: "off" }]);
    expect(await screen.findByTestId("service-done")).toBeTruthy();
    await waitFor(() => expect(within(screen.getByTestId("service-argus-retention.timer")).getByRole("button", { name: /Switch on/ })).toBeTruthy());
  });

  it("asks for the password when the server wants it", async () => {
    serve();
    server.use(http.post(`${BASE}/api/v1/admin/jobs/service`, () => HttpResponse.json({ code: "step_up_required", detail: "Confirm your password again (within five minutes) to switch this." }, { status: 403 })));
    const user = userEvent.setup();
    renderApp("/health");
    await user.click(await screen.findByRole("button", { name: "Switch off Deletes old data each night" }));
    const alert = await within(screen.getByTestId("services")).findByText(/Confirm your password again/);
    expect(within(alert).getByRole("link", { name: /Confirm your password/ }).getAttribute("href")).toBe("/stepup?next=%2Fapp%2Fconfirmed");
  });

  it("asks for the words before it switches on a unit that writes to the SIEM", async () => {
    serve();
    server.use(http.post(`${BASE}/api/v1/admin/jobs/service`, () => HttpResponse.json(job({ id: 71 }), { status: 202 })), http.get(`${BASE}/api/v1/admin/jobs/71`, () => HttpResponse.json(job({ id: 71, state: "running" }))));
    const user = userEvent.setup();
    renderApp("/health");
    await user.click(await screen.findByRole("button", { name: "Switch on Writes cases to Kibana" }));
    const dialog = await screen.findByRole("dialog");
    expect(dialog.textContent).toContain("Writes cases to Kibana");
    expect(bodies()).toEqual([]);
    const save = within(dialog).getByRole("button", { name: "Save the change" }) as HTMLButtonElement;
    expect(save.disabled).toBe(true);
    await user.type(within(dialog).getByLabelText(/Type/), WORDS);
    await user.click(save);
    await waitFor(() => expect(bodies()).toEqual([{ unit: "argus-writer.service", action: "on", confirm: WORDS }]));
  });

  it("restarts a service without the password dialog", async () => {
    serve();
    server.use(http.post(`${BASE}/api/v1/admin/jobs/service`, () => HttpResponse.json(job({ id: 72 }), { status: 202 })), http.get(`${BASE}/api/v1/admin/jobs/72`, () => HttpResponse.json(job({ id: 72, state: "failed", result: { error: "argus-web.service did not start" } }))));
    const user = userEvent.setup();
    renderApp("/health");
    await user.click(await screen.findByRole("button", { name: "Restart The web app" }));
    expect(bodies()).toEqual([{ unit: "argus-web.service", action: "restart" }]);
    expect((await within(screen.getByTestId("services")).findByRole("alert")).textContent).toContain("did not start");
  });

  it("is not shown to someone who is not an administrator", async () => {
    server.use(http.get(`${BASE}/api/v1/health`, () => HttpResponse.json(HEALTH)));
    renderApp("/health");
    await screen.findByRole("heading", { level: 1, name: "Health" });
    expect(screen.queryByTestId("services")).toBeNull();
    expect(sent("GET", "/api/v1/admin/services")).toEqual([]);
  });

  it("restarts only a service meant to run, never argus-admin or a timer", () => {
    expect(canRestart({ unit: "argus-web.service", on: true })).toBe(true);
    expect(canRestart({ unit: "argus-web.service", on: false })).toBe(false);
    expect(canRestart({ unit: "argus-admin.service", on: true })).toBe(false);
    expect(canRestart({ unit: "argus-backup.timer", on: true })).toBe(false);
  });
});
