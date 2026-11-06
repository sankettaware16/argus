// The entity pages and the drawer (docs/p4f-ui-spec.md §9): the coverage line on every page (E-1),
// a chip opens the drawer and Esc gives the focus back (E-2), the owner's summary holds no account
// name and no other day's host (E-4), an outside address is never a Device (E-5), and Add a note
// posts to /entity-notes (E-6).
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import { coverage, ownerSummary } from "../src/pages/Entity";
import { caseRow, casePage } from "./caseFixtures";
import { BASE, investigation, mockApi, renderApp, sent, server } from "./helpers";
import { P1_ID, p1Detail, today } from "./v2Fixtures";

mockApi();

function serveEntity() {
  server.use(
    http.get(`${BASE}/api/v1/investigations`, () => HttpResponse.json({ items: [investigation(undefined, { rule_name: "Plain-HTTP POST to a raw IP", alert_count: 1204 })], has_more: false, limit: 50, offset: 0, sort: "newest", view: "all" })),
    http.get(`${BASE}/api/v1/cases`, () => HttpResponse.json(casePage([caseRow({ id: P1_ID, number: 31, title: "Likely beaconing to 203.0.113.40", state: "suspected" })]))),
    http.get(`${BASE}/api/v1/entity-notes`, ({ request }) => HttpResponse.json({ items: [], kind: new URL(request.url).searchParams.get("kind"), value: new URL(request.url).searchParams.get("value") })),
  );
}

describe("entity pages", () => {
  it("E-1, E-5: the coverage line, and an outside address headed Outside address", async () => {
    serveEntity();
    renderApp("/entities/outside/203.0.113.40");
    expect((await screen.findByTestId("coverage")).textContent).toContain(coverage());
    const h1 = screen.getByRole("heading", { level: 1 });
    expect(h1.textContent).toBe("Outside address 203.0.113.40");
    expect(h1.textContent).not.toContain("Device");
    expect((await screen.findByTestId("entity-incidents")).textContent).toContain("#31");
    expect(screen.getByTestId("entity-groups").textContent).toContain("from alert groups");
  });

  it("E-1: a device page has the coverage line too, and a summary for the owner", async () => {
    serveEntity();
    renderApp("/entities/device/lab-pc-17");
    expect(await screen.findByTestId("coverage")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Copy a summary for the owner" })).toBeTruthy();
  });

  it("E-4: the owner's summary names no account and no other day's host", () => {
    const groups = [investigation(undefined, { key_fields: [{ field: "user.name", value: "student42" }], first_event_at: "2026-11-05T04:00:00Z", last_event_at: "2026-11-06T04:00:00Z", alert_count: 12 })];
    const text = ownerSummary("Device", "lab-pc-17", groups, [caseRow({ number: 31, state: "open" })]);
    expect(text).toContain("lab-pc-17");
    expect(text).toContain("incident #31");
    expect(text).not.toContain("student42");
    expect(text).not.toMatch(/threat list|VirusTotal/i);
  });

  it("E-6: Add a note posts the kind, the value and the words to /entity-notes", async () => {
    const user = userEvent.setup();
    serveEntity();
    server.use(http.post(`${BASE}/api/v1/entity-notes`, () => HttpResponse.json({ id: 1, author: "Asha", body: "x", created_at: "2026-11-06T10:00:00Z" }, { status: 201 })));
    renderApp("/entities/device/10.0.12.17");
    await user.click(await screen.findByRole("button", { name: "Add a note" }));
    const box = screen.getByRole("textbox", { name: "Your note" });
    expect(box.getAttribute("placeholder")).toBe("e.g. Owner called 6 Nov, says it is their backup tool");
    await user.type(box, "Lab image rebuilt");
    await user.click(screen.getByRole("button", { name: "Save the note" }));
    await waitFor(() => expect(sent("POST", "/api/v1/entity-notes")).toHaveLength(1));
    expect(JSON.parse(sent("POST", "/api/v1/entity-notes")[0]?.body ?? "")).toEqual({ kind: "ip", value: "10.0.12.17", body: "Lab image rebuilt" });
  });

  it("E-2: an entity chip opens the drawer; Esc closes it and the focus returns to the chip", async () => {
    const user = userEvent.setup();
    serveEntity();
    server.use(http.get(`${BASE}/api/v1/today`, () => HttpResponse.json(today())), http.get(`${BASE}/api/v1/cases/${P1_ID}`, () => HttpResponse.json(p1Detail())));
    renderApp("/");
    await screen.findByTestId("today-needs-you");
    const chip = screen.getAllByTestId("entity-chip").find((c) => c.textContent === "Outside address 203.0.113.40") as HTMLElement;
    await user.click(chip);
    const drawer = await screen.findByTestId("entity-drawer");
    expect(within(drawer).getByRole("heading", { level: 2 }).textContent).toContain("Outside address");
    expect(within(drawer).getByRole("link", { name: "Open full page" }).getAttribute("href")).toBe("/app/entities/outside/203.0.113.40");
    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByTestId("entity-drawer")).toBeNull());
    await waitFor(() => expect(document.activeElement).toBe(chip));
  });
});
