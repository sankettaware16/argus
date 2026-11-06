// Reports (docs/p4f-ui-spec.md §11): incident reports before summaries (P-1), grouped by week
// (P-2), with the restricted-data line (P-3); a TA's empty states never name an admin command.
import { screen, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import { weekOf } from "../src/components/IncidentReports";
import { caseRow, casePage } from "./caseFixtures";
import { BASE, mockApi, renderApp, server } from "./helpers";

mockApi();

describe("Reports", () => {
  it("P-1, P-2, P-3: incident reports first, by week, then the summaries; the restricted line is there", async () => {
    const now = Date.now();
    server.use(
      http.get(`${BASE}/api/v1/reports`, () => HttpResponse.json([])),
      http.get(`${BASE}/api/v1/cases`, () =>
        HttpResponse.json(
          casePage([
            caseRow({ id: "f1f1f1f1-0000-4000-8000-000000000001", number: 31, title: "Confirmed beaconing from 5 campus devices", opened_at: new Date(now - 3_600_000).toISOString() }),
            caseRow({ id: "f1f1f1f1-0000-4000-8000-000000000002", number: 12, title: "Confirmed DNS tunnelling", opened_at: new Date(now - 40 * 86_400_000).toISOString() }),
            caseRow({ id: "f1f1f1f1-0000-4000-8000-000000000003", number: 40, title: "A possible one", state: "suspected" }),
          ]),
        ),
      ),
    );
    renderApp("/reports");
    const ir = await screen.findByTestId("incident-reports");
    const summaries = screen.getByRole("heading", { level: 2, name: "Summaries" });
    expect(ir.compareDocumentPosition(summaries) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    await within(ir).findAllByTestId("report-week");
    expect(within(ir).getAllByRole("heading", { level: 3 }).map((h) => h.textContent)).toEqual(["This week", "Earlier"]);
    expect(ir.textContent).not.toContain("A possible one");
    expect(within(ir).getByRole("link", { name: /#31/ }).getAttribute("href")).toContain("tab=report");
    expect(within(ir).getByTestId("restricted").textContent).toBe("Reports hold campus addresses and names: send them only to the CISO's office and ACME.");
    expect(await screen.findByText("The first daily summary appears after ARGUS's first full day.")).toBeTruthy();
    expect(document.querySelector("main")?.textContent).not.toMatch(/argus report/);
  });

  it("groups in IST weeks that start on Monday", () => {
    const now = new Date("2026-11-06T13:00:00Z"); // a Friday
    expect(weekOf(new Date("2026-11-02T00:00:00Z"), now)).toBe("This week"); // Monday 5:30 AM IST
    expect(weekOf(new Date("2026-11-01T17:00:00Z"), now)).toBe("Last week"); // Sunday 10:30 PM IST
    expect(weekOf(new Date("2026-10-20T00:00:00Z"), now)).toBe("Earlier");
  });

  it("says plainly when nothing was confirmed yet", async () => {
    server.use(http.get(`${BASE}/api/v1/reports`, () => HttpResponse.json([])));
    renderApp("/reports");
    expect(await screen.findByText("No incident has been confirmed yet, so there is no incident report.")).toBeTruthy();
  });
});
