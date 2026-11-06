// The incident page's other tabs (docs/p4f-ui-spec.md §7.4–§7.9): no query twice in Evidence (I-15),
// Entities in two columns with the actor on the Other side (I-16), a "Why linked" on every alert
// group (I-17), no bulk Real on a possible incident (I-18), the Report tab's headline and its
// versions as a list (I-19), the note box and the chips on Activity (I-20), Story's picture with its
// list (I-21), and the glance from the incident report (V5).
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import type { CaseDetail, CaseReportOut } from "../src/client/types.gen";
import { dedupeEvidence, linkWords } from "../src/components/incident/IncidentTabs";
import { LEAD_ID } from "./caseFixtures";
import { query, report, reportOut } from "./incidentFixtures";
import { BASE, detail as investigationDetail, mockApi, renderApp, server, sessionWith, shellHandlers } from "./helpers";
import { P1_ID, p1Detail } from "./v2Fixtures";

mockApi();
const CASE_URL = `${BASE}/api/v1/cases/${P1_ID}`;

function serve(d: CaseDetail = p1Detail(), rep: CaseReportOut = reportOut({ case_id: P1_ID, case_state: d.case.state })) {
  server.use(
    http.get(CASE_URL, () => HttpResponse.json(d)),
    http.get(`${CASE_URL}/report`, () => HttpResponse.json(rep)),
    http.get(`${BASE}/api/v1/investigations/${LEAD_ID}`, () => HttpResponse.json(investigationDetail({}, { id: LEAD_ID }))),
  );
}

describe("Story", () => {
  it("I-21: the talked-to picture has Show as a list, and the list holds the same labels", async () => {
    const user = userEvent.setup();
    serve();
    renderApp(`/incidents/${P1_ID}?tab=story`);
    const talked = await screen.findByTestId("talked-to");
    const svg = talked.querySelector("svg") as SVGElement;
    const drawn = [...svg.querySelectorAll("text")].map((t) => t.textContent);
    await user.click(within(talked).getByRole("button", { name: "Show as a list" }));
    const list = within(talked).getByTestId("talked-list").textContent ?? "";
    for (const label of drawn) expect(list).toContain(label);
    expect(list).toContain("Outside address 203.0.113.40");
  });

  it("V5: the glance from the incident report, with entity links and the dashboard PDF", async () => {
    serve();
    renderApp(`/incidents/${P1_ID}?tab=story`);
    const glance = await screen.findByTestId("glance");
    expect(glance.textContent).toContain("At a glance");
    expect(within(glance).getByTestId("dashboard-pdf").textContent).toContain("The Visualiser's dashboard is the second part of the incident report.");
    expect(within(glance).getAllByRole("heading", { level: 3 }).length).toBeGreaterThan(0);
  });

  it("says why each alert group is linked, in words", () => {
    expect(linkWords({ link: "actor", link_value: "203.0.113.40", added_by: "ARGUS" })).toBe("same outside address 203.0.113.40");
    expect(linkWords({ link: "verdict", link_value: null, added_by: "ARGUS" })).toBe("a person called it real");
    expect(linkWords({ link: "person", link_value: null, added_by: "Asha" })).toBe("added by Asha");
    expect(linkWords({ link: "merge", link_value: null, added_by: "x" })).toBe("came with a merged incident");
  });
});

describe("Evidence", () => {
  it("I-15: lists no query twice; a repeated one says what else it was for", async () => {
    const q = query({ text: "FROM logs | WHERE source.ip == \"10.0.0.1\"" });
    const lines = [
      { id: "E1", title: "Proxy pairs", fact: "59 requests", from_logs: true, source: "proxy", at: null, status: "complete", count: 59, asked: ["timing"], query: q },
      { id: "E2", title: "Proxy pairs again", fact: "59 requests", from_logs: true, source: "proxy", at: null, status: "complete", count: 59, asked: ["destinations"], query: q },
    ];
    expect(dedupeEvidence(lines)).toHaveLength(1);
    expect(dedupeEvidence(lines)[0]?.also).toEqual(["destinations"]);
    serve(p1Detail(), reportOut({ case_id: P1_ID }, { evidence: lines }));
    renderApp(`/incidents/${P1_ID}?tab=evidence`);
    const items = await screen.findAllByTestId("evidence-item");
    expect(items).toHaveLength(1);
    expect(items[0]?.textContent).toContain("also for destinations");
    expect(items[0]?.textContent).not.toContain("E1"); // the id lives only in a tooltip
  });
});

describe("Entities", () => {
  it("I-16: two columns, Campus side and Other side; the actor IP is on the Other side", async () => {
    serve();
    renderApp(`/incidents/${P1_ID}?tab=entities`);
    const campus = await screen.findByTestId("campus-side");
    const other = screen.getByTestId("other-side");
    expect(within(campus).getByRole("heading").textContent).toBe("Campus side");
    expect(within(other).getByRole("heading").textContent).toBe("Other side");
    expect(other.textContent).toContain("Outside address 203.0.113.40");
    expect(campus.textContent).not.toContain("203.0.113.40");
    expect(document.querySelector("main")?.textContent).not.toMatch(/Malicious|Suspicious|\bClean\b/);
  });
});

describe("Alert groups", () => {
  it("I-17: every row has a non-empty Why linked", async () => {
    serve();
    renderApp(`/incidents/${P1_ID}?tab=alert-groups`);
    const cells = await screen.findAllByTestId("why-linked");
    for (const c of cells) expect((c.textContent ?? "").trim()).not.toBe("");
  });

  it("I-18: bulk Real: act on it is absent for a possible incident, offered for a confirmed one", async () => {
    const user = userEvent.setup();
    serve();
    const view = renderApp(`/incidents/${P1_ID}?tab=alert-groups`);
    await user.click((await screen.findAllByRole("checkbox", { name: /^Select / }))[0] as HTMLElement);
    const options = within(screen.getByTestId("groups-bulk")).getAllByRole("option").map((o) => o.textContent);
    expect(options).not.toContain("Real: act on it");
    view.unmount();
    serve(p1Detail({ decision: null }, { state: "open" }));
    renderApp(`/incidents/${P1_ID}?tab=alert-groups`);
    await user.click((await screen.findAllByRole("checkbox", { name: /^Select / }))[0] as HTMLElement);
    expect(within(screen.getByTestId("groups-bulk")).getAllByRole("option").map((o) => o.textContent)).toContain("Real: act on it");
  });
});

describe("Report", () => {
  it("I-19: the headline holds Possible incident · ARGUS:, never a true positive", async () => {
    serve(p1Detail(), reportOut({ case_id: P1_ID, case_state: "suspected" }, report()));
    renderApp(`/incidents/${P1_ID}?tab=report`);
    const head = await screen.findByTestId("report-v2-headline");
    expect(head.textContent).toBe("Possible incident · ARGUS: likely real");
    expect(document.querySelector("main")?.textContent).not.toMatch(/true positive/i);
    expect(document.querySelector("[data-testid=report-tab-head] select")).toBeNull();
  });
});

describe("Activity", () => {
  it("I-20: the note box at the top, then the filter chips over one list", async () => {
    const user = userEvent.setup();
    serve();
    renderApp(`/incidents/${P1_ID}?tab=activity`);
    const panel = await screen.findByRole("tabpanel");
    const box = within(panel).getByRole("textbox", { name: /Add a note/ });
    const log = within(panel).getByTestId("activity-log");
    expect(box.compareDocumentPosition(log) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    const chips = within(log).getByRole("group", { name: "Show" });
    expect(within(chips).getAllByRole("button").map((b) => b.textContent)).toEqual(["All", "People", "ARGUS", "AI", "Kibana"]);
    await user.click(within(chips).getByRole("button", { name: "People" }));
    for (const li of log.querySelectorAll("li")) expect(li.getAttribute("data-kind")).toBe("people");
  });

  it("says why a view-only person has no note box", async () => {
    server.use(...shellHandlers(sessionWith(["view"])));
    serve();
    renderApp(`/incidents/${P1_ID}?tab=activity`);
    expect(await screen.findByText(/adding a note needs the “review” capability/)).toBeTruthy();
  });
});
