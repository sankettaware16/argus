// Independent review of Q-B3 (new file, untracked): each test carries its finding number and fails
// on the tree as reviewed. (Placed in tests/ because vitest.config.ts includes only tests/**.)
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import { CASE_ID, caseDetail, LEAD_ID, RLO } from "./caseFixtures";
import { BASE, detail as investigationDetail, mockApi, REPORT, renderApp, server } from "./helpers";

mockApi();

describe("review of Q-B3", () => {
  it("R3-6: a person's display name in the Assign list is shown as untrusted text (markers, not the raw override character)", async () => {
    server.use(
      http.get(`${BASE}/api/v1/cases/${CASE_ID}`, () =>
        HttpResponse.json(caseDetail({ assignees: [{ id: 2, username: "ravi", display_name: `Ravi${RLO}evil` }] })),
      ),
      http.get(`${BASE}/api/v1/investigations/${LEAD_ID}/reports`, () => HttpResponse.json({ items: [REPORT], logs_hidden: false })),
      http.get(`${BASE}/api/v1/investigations/${LEAD_ID}`, () => HttpResponse.json(investigationDetail({}, { id: LEAD_ID }))),
    );
    const user = userEvent.setup();
    renderApp(`/incidents/${CASE_ID}?tab=all`);
    await user.click(await screen.findByRole("button", { name: "Assign" }));
    const select = await screen.findByLabelText("Give the case to");
    const labels = within(select).getAllByRole("option").map((o) => o.textContent ?? "");
    expect(labels.join("|")).not.toContain(RLO);
  });

  it("R3-7: a form's button that is aria-disabled says why when it is pressed or read (Assign with nobody chosen)", async () => {
    server.use(
      http.get(`${BASE}/api/v1/cases/${CASE_ID}`, () => HttpResponse.json(caseDetail())),
      http.get(`${BASE}/api/v1/investigations/${LEAD_ID}/reports`, () => HttpResponse.json({ items: [REPORT], logs_hidden: false })),
      http.get(`${BASE}/api/v1/investigations/${LEAD_ID}`, () => HttpResponse.json(investigationDetail({}, { id: LEAD_ID }))),
    );
    const user = userEvent.setup();
    renderApp(`/incidents/${CASE_ID}?tab=all`);
    await user.click(await screen.findByRole("button", { name: "Assign" }));
    const region = within(await screen.findByRole("region", { name: "Actions" }));
    const go = await region.findByRole("button", { name: "Review the request" }); // Check more has one too
    expect(go.getAttribute("aria-disabled")).toBe("true");
    await user.click(go);
    const said = region.queryByRole("alert") ?? region.queryByRole("status");
    expect(go.getAttribute("aria-describedby") !== null || said !== null).toBe(true);
  });
});
