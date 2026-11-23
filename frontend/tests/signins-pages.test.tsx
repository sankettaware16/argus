// "Who used this device" on the pages (AR6, D-216): the investigation's overview and the case page
// carry the card, the case timeline carries the sign-ins as context, the incident report lists the
// accounts under the affected assets, and a server without the feature shows none of it.
import { screen, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import type { SigninsOut } from "../src/client/types.gen";
import { caseDetail, CASE_ID, LEAD_ID } from "./caseFixtures";
import { BASE, detail as investigationDetail, ID, mockApi, noReportOut, REPORT, renderApp, server } from "./helpers";
import { reportOut } from "./incidentFixtures";

mockApi();
const LEAD = "Probable user, from SSO sign-ins on this address — a lead, not proof: addresses can be reassigned.";

const SIGNINS: SigninsOut = {
  enabled: true,
  hidden: false,
  lead: LEAD,
  states: [{ state: "likely", devices: 1 }],
  devices_total: 1,
  devices: [
    {
      address: "10.201.7.11",
      state: "likely",
      words: "Probable user: user-ar6-alpha.",
      accounts: [{ user: "user-ar6-alpha", first_at: "2026-10-26T03:40:00Z", last_at: "2026-10-26T12:10:00Z", events: 24, successes: 22, failures: 2, days: ["2026-10-26"], devices: ["Chrome on Windows"] }],
      account_count: 1,
      at_least: false,
      shared_days: [],
      gaps: [],
      hands: [],
      failed_only: [],
      outside_window: 0,
    },
  ],
};

function serveCase(signins: SigninsOut | null) {
  const d = caseDetail({
    signins,
    timeline: [
      { at: "2026-10-26T03:40:00Z", until: "2026-10-26T12:10:00Z", kind: "signin", text: "user-ar6-alpha signed in 24 times, 26 Oct 2026, 9:10 AM to 5:40 PM IST, Chrome on Windows (from 10.201.7.11)", by: null, investigation_id: null },
    ],
    timeline_total: 1,
  });
  server.use(
    http.get(`${BASE}/api/v1/cases/${CASE_ID}/report`, () => HttpResponse.json(noReportOut(CASE_ID))),
    http.get(`${BASE}/api/v1/cases/${CASE_ID}`, () => HttpResponse.json(d)),
    http.get(`${BASE}/api/v1/investigations/${LEAD_ID}/reports`, () => HttpResponse.json({ items: [REPORT], logs_hidden: false })),
    http.get(`${BASE}/api/v1/investigations/${LEAD_ID}`, () => HttpResponse.json(investigationDetail({}, { id: LEAD_ID }))),
  );
}

describe("the case page", () => {
  it("has the card, a way to it, and the sign-ins on the timeline as context", async () => {
    serveCase(SIGNINS);
    renderApp(`/incidents/${CASE_ID}?tab=all`);
    const card = await screen.findByRole("region", { name: "Who used this device" });
    expect(card.textContent).toContain("user-ar6-alpha");
    const timeline = screen.getByRole("region", { name: "Timeline" });
    expect(within(timeline).getByText("Sign-in (context)")).toBeTruthy();
    expect(timeline.textContent).toContain("signed in 24 times");
  });

  it("has neither without the feature", async () => {
    serveCase(null);
    renderApp(`/incidents/${CASE_ID}?tab=all`);
    await screen.findByRole("heading", { level: 1, name: /Regular beaconing/ });
    await screen.findByRole("region", { name: "Timeline" });
    expect(screen.queryByRole("region", { name: /Who used/ })).toBeNull();
  });
});

describe("the incident's tabs", () => {
  // the fixture's campus device is 10.0.0.1: its sign-ins name the probable user
  const onDevice: SigninsOut = { ...SIGNINS, devices: SIGNINS.devices.map((d) => ({ ...d, address: "10.0.0.1" })) };

  it("the overview says who used the device, as an account chip", async () => {
    serveCase(onDevice);
    renderApp(`/incidents/${CASE_ID}`);
    const who = await screen.findByRole("region", { name: "Who used the device" });
    expect(within(who).getByText("Probable user")).toBeTruthy();
    const chips = within(who).getAllByTestId("entity-chip");
    expect(chips.map((c) => c.getAttribute("data-noun"))).toEqual(["Device", "Account"]);
    expect(chips[1]?.textContent).toContain("user-ar6-alpha");
  });

  it("the entities tab puts the user on the device's card", async () => {
    serveCase(onDevice);
    renderApp(`/incidents/${CASE_ID}?tab=entities`);
    const campus = await screen.findByTestId("own-side");
    const card = await within(campus).findByTestId("device-user");
    expect(card.textContent).toContain("Probable user");
    expect(card.textContent).toContain("user-ar6-alpha");
  });

  it("the evidence tab has the sign-ins card", async () => {
    serveCase(onDevice);
    renderApp(`/incidents/${CASE_ID}?tab=evidence`);
    const card = await screen.findByRole("region", { name: "Who used this device" });
    expect(card.textContent).toContain("user-ar6-alpha");
  });

  it("the overview has no such part without sign-ins", async () => {
    serveCase(null);
    renderApp(`/incidents/${CASE_ID}`);
    await screen.findByRole("heading", { level: 1, name: /Regular beaconing/ });
    expect(screen.queryByRole("region", { name: /Who used/ })).toBeNull();
  });
});

describe("the investigation page", () => {
  it("has the card on its overview", async () => {
    server.use(
      http.get(`${BASE}/api/v1/investigations/${ID}/reports`, () => HttpResponse.json({ items: [], logs_hidden: false })),
      http.get(`${BASE}/api/v1/investigations/${ID}`, () => HttpResponse.json(investigationDetail({ signins: SIGNINS }))),
    );
    renderApp(`/investigations/${ID}`);
    const card = await screen.findByRole("region", { name: "Who used this device" });
    expect(card.textContent).toContain("Probable user");
    expect(card.textContent).toContain("Chrome on Windows");
  });
});

describe("the incident report", () => {
  it("lists the accounts that signed in from the affected devices, as text", async () => {
    const users = {
      lead: LEAD,
      devices_total: 1,
      signins: [],
      same: null,
      devices: [
        {
          device: "10.201.7.11",
          state: "likely" as const,
          sentence: { text: "10.201.7.11: Probable user: user-ar6-alpha.", cites: ["F1"], by: "code" as const },
          accounts: [{ name: "user-ar6-alpha", device: "10.201.7.11", first_seen: "2026-10-26T03:40:00Z", last_seen: "2026-10-26T12:10:00Z", signins: 24, failed: 2, days: 1, browsers: ["Chrome on Windows"] }],
          account_count: 1,
          at_least: false,
        },
      ],
    };
    const out = reportOut({ files: [...reportOut().files, { kind: "accounts_csv", name: "Affected accounts (CSV)", url: "/api/v1/cases/x/report/files/affected-accounts.csv", available: true }] }, { users });
    server.use(
      http.get(`${BASE}/api/v1/cases/${CASE_ID}/report`, () => HttpResponse.json(out)),
      http.get(`${BASE}/api/v1/cases/${CASE_ID}`, () => HttpResponse.json(caseDetail())),
      http.get(`${BASE}/api/v1/investigations/${LEAD_ID}/reports`, () => HttpResponse.json({ items: [REPORT], logs_hidden: false })),
      http.get(`${BASE}/api/v1/investigations/${LEAD_ID}`, () => HttpResponse.json(investigationDetail({}, { id: LEAD_ID }))),
    );
    renderApp(`/incidents/${CASE_ID}?tab=all`);
    const heading = await screen.findByText("Accounts that signed in from the affected devices", { selector: "h4" });
    const accounts = heading.closest("section") as HTMLElement; // inside a closed <details>: not an accessible region
    expect(accounts.textContent).toContain("user-ar6-alpha");
    expect(accounts.textContent).toContain(LEAD);
    expect(screen.getByText("Affected accounts (CSV)")).toBeTruthy();
  });
});
