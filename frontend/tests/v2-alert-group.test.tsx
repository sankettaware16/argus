// The alert-group page (docs/p4f-ui-spec.md §8): in no incident, the first choice reads "Real: open
// an incident…" and its Save opens a dialog that says what marking it real does, before anything is
// sent (A-2, A-3); the keys 1 to 5 still choose the five outcomes here (A-4).
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import { BASE, ID, detail, mockApi, renderApp, sent, server } from "./helpers";

mockApi();

describe("the alert-group page", () => {
  it("A-2, A-3: Real: open an incident… first, and its dialog before any request", async () => {
    const user = userEvent.setup();
    server.use(
      http.get(`${BASE}/api/v1/investigations/${ID}`, () => HttpResponse.json(detail())),
      http.get(`${BASE}/api/v1/investigations/${ID}/reports`, () => HttpResponse.json({ items: [], logs_hidden: false })),
      http.post(`${BASE}/api/v1/investigations/${ID}/reviews`, () => HttpResponse.json({ review_id: 1, version: 4, gold_saved: false }, { status: 201 })),
    );
    renderApp(`/alert-groups/${ID}`);
    const form = await screen.findByRole("form", { name: "Your decision" });
    const labels = within(form).getAllByRole("radio").map((r) => r.closest("label")?.textContent);
    expect(labels[0]).toContain("Real: open an incident…");
    await user.keyboard("1");
    await user.click(within(form).getByRole("button", { name: "Save decision" }));
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog.textContent).toContain("Marking it real opens a possible incident, or adds it to the incident that holds its activity.");
    expect(sent("POST", "/api")).toHaveLength(0);
    await user.click(within(dialog).getByRole("button", { name: "Mark it real" }));
    await waitFor(() => expect(sent("POST", `/api/v1/investigations/${ID}/reviews`)).toHaveLength(1));
    expect(JSON.parse(sent("POST", "/api")[0]?.body ?? "")).toMatchObject({ action: "reviewed", outcome: "true_positive" });
  });
});
