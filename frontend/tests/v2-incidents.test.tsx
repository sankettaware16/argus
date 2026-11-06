// The Incidents queue (docs/p4f-ui-spec.md §6): Needs you by default and never "Needs decision"
// (Q-1), its count Today's number (Q-2), priority order with an unscored case last (Q-3), filters
// and the sort in the address (Q-4), the preview pane at 1280 px with j and Esc (Q-5), one pane
// below it (Q-6), no bulk Confirm (Q-7), the bulk guard on Scan or attempt (Q-8), Review together
// (Q-9), the Kibana column (Q-10) and "Taken by", never "Owner" (Q-11).
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import type { CaseRowOut } from "../src/client/types.gen";
import { filterRows, parseIncidents, rowOf, sortRows, togetherRows } from "../src/lib/incidents";
import { casePage } from "./caseFixtures";
import { BASE, mockApi, renderApp, sent, server } from "./helpers";
import { engineBlock, engineRow, OLD_ID, P1_ID, p1Detail, p1Engine, P2X_ID, today } from "./v2Fixtures";

mockApi();

const S1 = "e1e1e1e1-0000-4000-8000-000000000001";
const S2 = "e1e1e1e1-0000-4000-8000-000000000002";

function rows(): CaseRowOut[] {
  return [
    engineRow(null, { id: OLD_ID, number: 7, title: "Old case with no score", severity: "critical" }),
    engineRow(engineBlock("P2", 60, { lane: "exposure" }), { id: P2X_ID, number: 30, title: "Likely .env scan of www.dept.example.ac.in — got HTTP 200, not verified" }),
    engineRow(p1Engine(), { id: P1_ID, number: 31, title: "Likely beaconing from 5 campus devices to 203.0.113.40" }),
    engineRow(engineBlock("P3", 30, { objects: [{ kind: "site", label: "lib.example.ac.in", role: "affected" }, { kind: "device", label: "198.51.100.2", role: "actor" }] }), { id: S1, number: 34, title: "Suspected .env scan of lib.example.ac.in — no HTTP 200 after the alerts" }),
    engineRow(engineBlock("P3", 29, { objects: [{ kind: "site", label: "hostel.example.ac.in", role: "affected" }, { kind: "device", label: "198.51.100.3", role: "actor" }, { kind: "device", label: "198.51.100.4", role: "actor" }] }), { id: S2, number: 35, title: "Suspected .env scan of hostel.example.ac.in — no HTTP 200 after the alerts" }),
  ];
}

function serveList(items: CaseRowOut[] = rows(), counts = { queue: 17 }) {
  server.use(http.get(`${BASE}/api/v1/cases`, () => HttpResponse.json(casePage(items, { counts: { active: 4, notified: 7, attention: 1, mine: 2, suspected: 5, closed: 3, queue: counts.queue, all: 30, incidents: 11 } }))));
}

function wide() {
  window.matchMedia = ((query: string) => ({ matches: query.includes("1280") || query.includes("1024"), media: query, addEventListener: () => {}, removeEventListener: () => {}, addListener: () => {}, removeListener: () => {}, dispatchEvent: () => false, onchange: null })) as unknown as typeof window.matchMedia;
}

const shownRows = () => screen.getAllByTestId("incident-row");

describe("the queue", () => {
  it("Q-1, Q-2: opens on Needs you, whose count is Today's Needs-you number; no tab says Needs decision", async () => {
    serveList();
    server.use(http.get(`${BASE}/api/v1/today`, () => HttpResponse.json(today())));
    renderApp("/incidents");
    const tabs = await screen.findByTestId("view-tabs");
    expect(within(tabs).getAllByRole("link").map((a) => a.textContent?.replace(/\d+$/, ""))).toEqual(["Needs you", "Mine", "Open", "Owner told", "Closed", "All"]);
    expect(within(tabs).getByRole("link", { name: /Needs you/ }).getAttribute("aria-current")).toBe("page");
    expect(await within(tabs).findByTestId("count-needs-you")).toHaveProperty("textContent", "17");
    expect(document.body.textContent).not.toContain("Needs decision");
    expect(sent("GET", "/api/v1/cases?view=queue").length).toBeGreaterThan(0);
  });

  it("Q-3: sorts by priority, the unscored case last with a dash", async () => {
    serveList();
    renderApp("/incidents");
    await screen.findAllByTestId("incident-row");
    const order = shownRows().map((r) => r.getAttribute("data-id"));
    expect(order[0]).toBe(P1_ID);
    expect(order.at(-1)).toBe(OLD_ID);
    expect(within(shownRows().at(-1) as HTMLElement).getByTestId("priority-badge").textContent).toContain("—");
  });

  it("Q-4: every filter and the sort round-trip through the address", async () => {
    const user = userEvent.setup();
    serveList();
    const { router } = renderApp("/incidents?view=needs-you&band=P3&sort=activity&active=1");
    await screen.findByTestId("view-tabs");
    expect(parseIncidents(router.state.location.search as Record<string, unknown>)).toMatchObject({ view: "needs-you", band: ["P3"], sort: "activity", active: "1" });
    expect(parseIncidents({ view: "open", band: ["P1", "P9"], certainty: "Likely", kibana: "waiting", together: `${S1},${S2}` })).toEqual({ view: "open", band: ["P1"], certainty: ["Likely"], kibana: "waiting", together: [S1, S2] });
    await user.click(screen.getByRole("checkbox", { name: "Still active" }));
    await waitFor(() => expect(router.state.location.search).not.toHaveProperty("active"));
  });

  it("Q-11: no column or filter says Owner; Taken by is used", async () => {
    serveList();
    renderApp("/incidents?view=open");
    await screen.findByTestId("view-tabs");
    expect(screen.getByRole("button", { name: /Taken by/ })).toBeTruthy();
    expect(document.querySelector("main")?.textContent).not.toMatch(/\bOwner\b(?! told)/);
  });

  it("Q-10: the Open view shows the Kibana state; the not-in-Kibana incident reads Not yet", async () => {
    serveList([engineRow(p1Engine(), { id: P1_ID, number: 33, state: "open", title: "Confirmed beaconing", in_kibana: false })]);
    renderApp("/incidents?view=open");
    const [row] = await screen.findAllByTestId("incident-row");
    expect(row?.textContent).toContain("Not yet");
  });

  it("G-5: the outside address is never a Device anywhere in the queue", async () => {
    serveList();
    renderApp("/incidents");
    await screen.findAllByTestId("incident-row");
    for (const chip of document.querySelectorAll("[data-testid=entity-chip][data-role=actor]")) expect(chip.getAttribute("data-noun")).not.toBe("Device");
  });

  it("says what to do when nothing needs you", async () => {
    serveList([]);
    renderApp("/incidents");
    const empty = await screen.findByTestId("incidents-empty");
    expect(empty.textContent).toContain("Nothing needs you right now.");
    expect(within(empty).getByRole("link", { name: "See open incidents" })).toBeTruthy();
  });
});

describe("the preview pane (§6.4)", () => {
  it("Q-5: a row click opens it at 1280 px; j moves it; Esc closes it", async () => {
    const user = userEvent.setup();
    wide();
    serveList();
    server.use(http.get(`${BASE}/api/v1/cases/${P1_ID}`, () => HttpResponse.json(p1Detail())), http.get(`${BASE}/api/v1/cases/${P2X_ID}`, () => HttpResponse.json(p1Detail({}, { id: P2X_ID, number: 30, title: "The exposure one" }, engineBlock("P2", 60)))));
    renderApp("/incidents");
    const [first] = await screen.findAllByTestId("incident-row");
    await user.click(first as HTMLElement);
    const pane = await screen.findByTestId("preview-pane");
    expect((await within(pane).findByTestId("preview-title")).textContent).toContain("Likely beaconing");
    for (const chip of within(pane).getAllByTestId("entity-chip").filter((c) => c.getAttribute("data-role") === "actor")) expect(chip.getAttribute("data-noun")).toBe("Outside address");
    await user.keyboard("j");
    await waitFor(() => expect(within(screen.getByTestId("preview-pane")).getByTestId("preview-title").textContent).toContain("The exposure one"));
    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByTestId("preview-pane")).toBeNull());
    expect(document.activeElement?.getAttribute("data-testid")).toBe("row-title");
    expect(document.activeElement?.closest("[data-testid=incident-row]")?.getAttribute("data-id")).toBe(P2X_ID);
  });

  it("Q-6: below 1280 px a row opens the incident's page", async () => {
    const user = userEvent.setup();
    window.matchMedia = ((query: string) => ({ matches: false, media: query, addEventListener: () => {}, removeEventListener: () => {}, addListener: () => {}, removeListener: () => {}, dispatchEvent: () => false, onchange: null })) as unknown as typeof window.matchMedia;
    serveList();
    server.use(http.get(`${BASE}/api/v1/cases/${P1_ID}`, () => HttpResponse.json(p1Detail())));
    const { router } = renderApp("/incidents");
    const [first] = await screen.findAllByTestId("incident-row");
    await user.click(first as HTMLElement);
    await waitFor(() => expect(router.state.location.pathname).toBe(`/incidents/${P1_ID}`));
    expect(screen.queryByTestId("preview-pane")).toBeNull();
  });
});

describe("bulk (§6.5)", () => {
  it("Q-7: the bulk bar has no Confirm, and says to confirm one at a time", async () => {
    const user = userEvent.setup();
    serveList();
    renderApp("/incidents");
    await screen.findAllByTestId("incident-row");
    await user.click(screen.getByRole("checkbox", { name: "Select incident #31" }));
    const bar = await screen.findByTestId("bulk-bar");
    expect(within(bar).queryByRole("button", { name: /Confirm/ })).toBeNull();
    expect(bar.textContent).toContain("Confirm incidents one at a time.");
  });

  it("Q-8: with the exposure P2 selected, Scan or attempt is disabled and the dialog names it; the rest are sent one at a time", async () => {
    const user = userEvent.setup();
    serveList();
    server.use(http.post(`${BASE}/api/v1/cases/:id/dismiss`, ({ params }) => HttpResponse.json({ case: engineRow(null, { id: String(params.id), state: "closed" }), result: "done", request_id: null })));
    renderApp("/incidents");
    await screen.findAllByTestId("incident-row");
    await user.click(screen.getByRole("checkbox", { name: "Select incident #30" }));
    await user.click(screen.getByRole("checkbox", { name: "Select incident #34" }));
    await user.click(within(screen.getByTestId("bulk-bar")).getByRole("button", { name: "Not an incident ▾" }));
    const dialog = within(await screen.findByRole("alertdialog"));
    expect(dialog.getByTestId("bulk-items").textContent).toContain("got HTTP 200, not verified");
    const scan = dialog.getByRole("radio", { name: /Scan or attempt/ }) as HTMLInputElement;
    expect(scan.disabled).toBe(true);
    expect(dialog.getByText(/1 of these got an answer: check them first \(#30\)/)).toBeTruthy();
    await user.click(dialog.getByRole("radio", { name: /Expected activity/ }));
    await user.click(dialog.getByRole("button", { name: "Close 2" }));
    await waitFor(() => expect(sent("POST", "/api/v1/cases/")).toHaveLength(2));
    expect(sent("POST", "/api/v1/cases/").map((r) => JSON.parse(r.body).reason)).toEqual(["benign_expected", "benign_expected"]);
  });

  it("Q-9: Review together lists one row per campus object, what answered before the sources, and Different on the odd one", async () => {
    serveList();
    renderApp(`/incidents?view=needs-you&together=${P2X_ID},${S1},${S2}`);
    const panel = await screen.findByTestId("review-together");
    const heads = within(panel).getAllByRole("columnheader").map((h) => h.textContent);
    expect(heads.indexOf("What answered")).toBeLessThan(heads.indexOf("Outside sources"));
    expect(heads.at(-1)).toBe("Outside sources");
    const lines = within(panel).getAllByTestId("together-row");
    expect(lines).toHaveLength(3);
    const odd = lines.find((l) => l.textContent?.includes("www.dept.example.ac.in")) as HTMLElement;
    expect(odd.textContent).toContain("Different");
    expect(lines.filter((l) => l.textContent?.includes("Different"))).toHaveLength(1);
    expect(panel.textContent).toContain("#30 is excluded from Scan or attempt: something answered");
  });
});

describe("the rules underneath", () => {
  const all = rows().map(rowOf);

  it("filters by band, certainty, side, taken and activity", () => {
    expect(filterRows(all, { view: "all", band: ["P3"] }, null).map((r) => r.row.number)).toEqual([34, 35]);
    expect(filterRows(all, { view: "all", side: ["device"] }, null).map((r) => r.row.number)).toEqual([31]);
    expect(filterRows(all, { view: "all", active: "1" }, null).map((r) => r.row.number)).toEqual([31]);
    expect(filterRows(all, { view: "all", taken: "nobody" }, null)).toHaveLength(5);
    expect(filterRows(all, { view: "all", certainty: ["Likely"] }, null).map((r) => r.row.number)).toEqual([31]);
    expect(filterRows(all, { view: "all", certainty: ["Suspected"] }, null).map((r) => r.row.number)).toEqual([30, 34, 35]);
  });

  it("sorts unscored after scored, and Different marks the minority", () => {
    expect(sortRows(all, undefined).map((r) => r.row.number)).toEqual([31, 30, 34, 35, 7]);
    const t = togetherRows(all.filter((r) => [30, 34, 35].includes(r.row.number)));
    expect(t.filter((x) => x.different).map((x) => x.number)).toEqual([30]);
    expect(t.find((x) => x.number === 30)?.blocked).toBe(true);
  });
});
