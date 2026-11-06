// Proposals by group, with the audit sample first; confirming a group shows the exact request.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import type { ProposalGroupOut, ProposalOut } from "../src/client/types.gen";
import { BASE, must, renderApp, sent, server, sessionWith, shellHandlers, mockApi } from "./helpers";

mockApi();

const proposal = (n: number, more: Partial<ProposalOut> = {}): ProposalOut => ({
  assessment_id: 100 + n,
  investigation_id: `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`,
  rule: `Rule ${n}`,
  alerts: n,
  bucket_start: "2026-10-09T00:00:00+05:30",
  reason: `reason ${n}`,
  ...more,
});
const items = [1, 2, 3, 4, 5].map((n) => proposal(n));
const GROUP: ProposalGroupOut = {
  group: "engine@1#fp: steps / rule-1 / 1:answered",
  source: "the decision engine",
  decided_by: "engine@1#fp: steps / rule-1 / 1:answered",
  outcome: "benign_expected",
  rule: null,
  models: [],
  size: 5,
  items,
  sample: items.slice(0, 3),
};
const AGENT: ProposalGroupOut = { ...GROUP, group: "agent@1|Rule A|true_positive", source: "the AI investigator", rule: "Rule A", models: ["m-2", "m-1"], outcome: "true_positive", size: 1, items: [proposal(9)], sample: [proposal(9)] };

describe("the groups", () => {
  it("say who proposed what for how many, with the audit sample first and the rest on demand", async () => {
    server.use(http.get(`${BASE}/api/v1/proposals`, () => HttpResponse.json([GROUP, AGENT])));
    renderApp("/proposals");
    const first = await screen.findByRole("region", { name: "Real but harmless: 5 investigations" });
    expect(first.textContent).toContain("By the decision engine");
    // what decided it is the machine's own key: behind Details (P4-F U9)
    expect(must(within(first).getByText("Details").closest("details")).textContent).toContain("Decided by engine@1#fp: steps / rule-1 / 1:answered");
    const sample = must(within(first).getByRole("heading", { name: "Audit sample" }).nextElementSibling);
    expect([...sample.querySelectorAll("li")].map((li) => li.textContent?.replace(/\s+/g, " "))).toEqual([
      "Rule 1, 1 alert, 9 Oct 2026, 12:00 AM IST — reason 1",
      "Rule 2, 2 alerts, 9 Oct 2026, 12:00 AM IST — reason 2",
      "Rule 3, 3 alerts, 9 Oct 2026, 12:00 AM IST — reason 3",
    ]);
    const rest = must(within(first).getByText("All 5").closest("details"));
    expect([...rest.querySelectorAll("li")].map((li) => li.textContent?.replace(/\s+/g, " "))).toEqual(["Rule 4, 4 alerts, 9 Oct 2026, 12:00 AM IST", "Rule 5, 5 alerts, 9 Oct 2026, 12:00 AM IST"]);
    expect(within(first).getByRole("link", { name: "Rule 1" }).getAttribute("href")).toBe("/app/alert-groups/00000000-0000-4000-8000-000000000001");
    const second = screen.getByRole("region", { name: "Real: act on it: 1 investigation" });
    expect(second.textContent).toContain("By the AI investigator on Rule A");
    expect(must(within(second).getByText("Details").closest("details")).textContent).toContain("Models: m-1, m-2");
    expect(within(second).queryByText(/^All /)).toBeNull();
  });

  it("never offers to confirm a group of real attacks together: each starts an incident (P4-F U4)", async () => {
    const big = { ...AGENT, size: 500, items: [1, 2, 3, 4, 5].map((n) => proposal(n)), sample: [proposal(1)] };
    server.use(http.get(`${BASE}/api/v1/proposals`, () => HttpResponse.json([big, GROUP])));
    renderApp("/proposals");
    const real = await screen.findByRole("region", { name: "Real: act on it: 5 investigations" });
    expect(within(real).queryByRole("button")).toBeNull();
    expect(within(real).getByTestId("one-by-one").textContent).toContain("open each one and decide it on its own page");
    expect(screen.getAllByRole("button", { name: /^Confirm all/ }).map((b) => b.textContent)).toEqual(["Confirm all 5 as Real but harmless"]);
  });

  it("say so when nothing waits", async () => {
    server.use(http.get(`${BASE}/api/v1/proposals`, () => HttpResponse.json([])));
    renderApp("/proposals");
    expect(await screen.findByText(/No proposal is waiting\./)).toBeTruthy();
  });

  it("say that the group is longer than the part listed", async () => {
    server.use(http.get(`${BASE}/api/v1/proposals`, () => HttpResponse.json([{ ...GROUP, size: 900 }])));
    renderApp("/proposals");
    expect((await screen.findByText(/900 in the group, the first 5 listed/)).textContent).toContain("900");
  });
});

describe("confirming a group", () => {
  it("shows the exact request with every listed id, sends exactly that, and says what was skipped", async () => {
    const user = userEvent.setup();
    server.use(
      http.get(`${BASE}/api/v1/proposals`, () => HttpResponse.json([GROUP])),
      http.post(`${BASE}/api/v1/proposals/confirm`, () => HttpResponse.json({ accepted: 4, skipped: 1 })),
    );
    renderApp("/proposals");
    await user.click(await screen.findByRole("button", { name: "Confirm all 5 as Real but harmless" }));
    const dialog = await screen.findByRole("alertdialog");
    const shown = within(dialog).getByTestId("payload").textContent ?? "";
    expect(JSON.parse(shown)).toEqual({ group: GROUP.group, assessment_ids: [101, 102, 103, 104, 105] });
    expect(dialog.textContent).toContain("POST/api/v1/proposals/confirm");
    await waitFor(() => expect(document.activeElement?.textContent).toBe("Cancel"));
    await user.click(within(dialog).getByRole("button", { name: "Confirm 5" }));
    await screen.findByText("Confirmed 4; 1 skipped because they changed.", { selector: "p" });
    expect(sent("POST", "/api")[0]?.body).toBe(shown);
    await waitFor(() => expect(sent("GET", "/api/v1/proposals")).toHaveLength(2)); // read again
  });

  it("sends nothing when cancelled", async () => {
    const user = userEvent.setup();
    server.use(http.get(`${BASE}/api/v1/proposals`, () => HttpResponse.json([GROUP])));
    renderApp("/proposals");
    await user.click(await screen.findByRole("button", { name: /^Confirm all 5/ }));
    await user.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());
    expect(sent("POST", "/api")).toHaveLength(0);
  });

  it("says plainly why a group could not be confirmed, in the dialog, and does not retry", async () => {
    const user = userEvent.setup();
    server.use(
      http.get(`${BASE}/api/v1/proposals`, () => HttpResponse.json([GROUP])),
      http.post(`${BASE}/api/v1/proposals/confirm`, () => HttpResponse.text("slow down", { status: 429 })),
    );
    renderApp("/proposals");
    await user.click(await screen.findByRole("button", { name: /^Confirm all 5/ }));
    const dialog = await screen.findByRole("alertdialog");
    await user.click(within(dialog).getByRole("button", { name: "Confirm 5" }));
    expect((await within(dialog).findByRole("alert")).textContent).toBe("Too many requests just now; wait a minute and try again.");
    expect(sent("POST", "/api")).toHaveLength(1);
  });

  it("is not offered to an account that may only view, which is told why", async () => {
    server.use(...shellHandlers(sessionWith(["view"])), http.get(`${BASE}/api/v1/proposals`, () => HttpResponse.json([GROUP])));
    renderApp("/proposals");
    await screen.findByRole("region", { name: /Real but harmless/ });
    expect(screen.queryByRole("button", { name: /^Confirm all/ })).toBeNull();
    expect(screen.getByText(/Your account may view only: confirming a group needs the “review” capability/)).toBeTruthy();
  });
});

describe("hostile proposals", () => {
  it("are text only, in the names, the reasons and the models", async () => {
    const hostile = '<img src=x onerror="window.__pwned=1"> \u202e';
    server.use(http.get(`${BASE}/api/v1/proposals`, () => HttpResponse.json([{ ...AGENT, rule: hostile, models: [hostile], sample: [proposal(9, { rule: hostile, reason: hostile })], items: [proposal(9, { rule: hostile, reason: hostile })] }])));
    const { container } = renderApp("/proposals");
    await screen.findByRole("heading", { name: "Audit sample" });
    expect(container.querySelector("main img")).toBeNull();
    expect(container.querySelectorAll("main .ut-mark").length).toBeGreaterThanOrEqual(3);
    expect((window as unknown as { __pwned?: number }).__pwned).toBeUndefined();
  });
});
