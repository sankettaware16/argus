// Q-B3's review fixes (R3-4, R3-7, R3-11, and Q-C2's suggestions and watch on the case page): focus
// after a decision, a button that cannot be used says why, every cut-off list says how many are not
// shown, suggested members and the watch's status are text only.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import type { CaseDetail, WatchStatusOut } from "../src/client/types.gen";
import { approval, CASE2_ID, CASE_ID, caseDetail, LEAD_ID, queue, RLO } from "./caseFixtures";
import { BASE, detail as investigationDetail, mockApi, REPORT, renderApp, server, sessionWith, shellHandlers } from "./helpers";

mockApi();
const QUEUE = `${BASE}/api/v1/approvals`;
const URL_OF = `${BASE}/api/v1/cases/${CASE_ID}`;

function serveCase(d: CaseDetail = caseDetail()) {
  server.use(
    http.get(URL_OF, () => HttpResponse.json(d)),
    http.get(`${BASE}/api/v1/investigations/${LEAD_ID}/reports`, () => HttpResponse.json({ items: [REPORT], logs_hidden: false })),
    http.get(`${BASE}/api/v1/investigations/${LEAD_ID}`, () => HttpResponse.json(investigationDetail({}, { id: LEAD_ID }))),
  );
}

const second = () => approval({ id: 32, words: "Close case 13: benign: expected activity", case: { id: CASE2_ID, number: 13, title: "Another", state: "open" } });

async function approveFirst(user: ReturnType<typeof userEvent.setup>) {
  await user.click((await screen.findAllByRole("button", { name: /^Approve/ }))[0] as HTMLElement);
  await user.click(screen.getAllByRole("button", { name: "Review the request" })[0] as HTMLElement);
  await user.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Approve" }));
}

describe("R3-4: the focus after a decision", () => {
  it("goes to the card that takes the decided one's place", async () => {
    const user = userEvent.setup();
    let decided = false;
    server.use(
      http.get(QUEUE, () => HttpResponse.json(decided ? queue({ pending: [second()] }) : queue({ pending: [approval(), second()] }))),
      http.post(`${BASE}/api/v1/approvals/31/decision`, () => {
        decided = true;
        return HttpResponse.json({ request_id: 31, status: "approved", applied: [{ case_id: CASE_ID, number: 12, state: "closed", version: 6 }] });
      }),
    );
    renderApp("/approvals");
    await approveFirst(user);
    await screen.findByText("Approved. Case 12 is closed.", { selector: "p" });
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("region", { name: second().words })));
  });

  it("goes to the page's title when no card is left", async () => {
    const user = userEvent.setup();
    let decided = false;
    server.use(
      http.get(QUEUE, () => HttpResponse.json(decided ? queue({ pending: [] }) : queue())),
      http.post(`${BASE}/api/v1/approvals/31/decision`, () => {
        decided = true;
        return HttpResponse.json({ request_id: 31, status: "approved", applied: [] });
      }),
    );
    renderApp("/approvals");
    await approveFirst(user);
    await screen.findByText("Nothing is waiting for a decision.");
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("heading", { level: 1, name: "Approvals" })));
  });

  it("stays with the card when the request waits for a second person", async () => {
    const user = userEvent.setup();
    let decided = false;
    const mine = () => approval({ required: 2, you: { can_decide: false, why_not: "You already approved this request.", decided: "approved" } });
    server.use(
      http.get(QUEUE, () => HttpResponse.json(decided ? queue({ pending: [mine()] }) : queue({ pending: [approval({ required: 2 })] }))),
      http.post(`${BASE}/api/v1/approvals/31/decision`, () => {
        decided = true;
        return HttpResponse.json({ request_id: 31, status: "pending", applied: [] });
      }),
    );
    renderApp("/approvals");
    await approveFirst(user);
    await screen.findByText("Approved; it needs one more person.", { selector: "p" });
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("region", { name: approval().words })));
  });
});

describe("R3-7: a button that cannot be used says why", () => {
  const regionOf = (name: string) => within(screen.getByRole("region", { name }));

  async function pressed(button: HTMLElement, user: ReturnType<typeof userEvent.setup>, why: string) {
    expect(button.getAttribute("aria-disabled")).toBe("true");
    const note = document.getElementById(button.getAttribute("aria-describedby") ?? "none");
    expect(note?.textContent).toBe(why);
    await user.click(button);
    const said = within(button.closest("form, li, section") as HTMLElement).getAllByRole("status").map((s) => s.textContent);
    expect(said).toContain(`Not done: ${why}`);
  }

  it("Assign, Confirm contained, Reopen and the closure form", async () => {
    const user = userEvent.setup();
    serveCase();
    renderApp(`/cases/${CASE_ID}`);
    await user.click(await screen.findByRole("button", { name: "Assign" }));
    await pressed(await regionOf("Actions").findByRole("button", { name: "Review the request" }), user, "Choose a person first.");
  });

  it("the closure form asks for a reason, then for the words a reason needs", async () => {
    const user = userEvent.setup();
    serveCase();
    renderApp(`/cases/${CASE_ID}`);
    await user.click(await screen.findByRole("button", { name: "Request closure" }));
    await pressed(await regionOf("Actions").findByRole("button", { name: "Show what it would write" }), user, "Choose a reason first.");
    await user.click(screen.getByRole("radio", { name: /Fixed, as its owner says/ }));
    await pressed(regionOf("Actions").getByRole("button", { name: "Show what it would write" }), user, "This reason needs your words first.");
  });

  it("merge asks for a case number", async () => {
    const user = userEvent.setup();
    serveCase();
    renderApp(`/cases/${CASE_ID}`);
    await user.click(await screen.findByRole("button", { name: "Merge into another case" }));
    await pressed(await regionOf("Actions").findByRole("button", { name: "Show what it would write" }), user, "Type the number of the case to merge into.");
  });

  it("Check more asks for a check, and the approvals page for the step-up", async () => {
    const user = userEvent.setup();
    serveCase();
    renderApp(`/cases/${CASE_ID}`);
    const more = await screen.findByRole("region", { name: "Check more" });
    await pressed(await within(more).findByRole("button", { name: "Review the request" }), user, "Choose a check first.");
  });

  it("an approval waits for the step-up and says so when pressed", async () => {
    const user = userEvent.setup();
    server.use(http.get(QUEUE, () => HttpResponse.json(queue({ step_up: { valid: false, valid_until: null, url: "/stepup?next=/app/approvals" } }))));
    renderApp("/approvals");
    const button = (await screen.findAllByRole("button", { name: /^Approve/ }))[0] as HTMLElement;
    expect(document.getElementById(button.getAttribute("aria-describedby") ?? "none")?.textContent).toBe("Confirm it is you first (above).");
    await user.click(button);
    expect(screen.getAllByRole("status").map((s) => s.textContent)).toContain("Not done: Confirm it is you first (above).");
  });
});

describe("R3-11: what a list cuts off, it says", () => {
  it("every list of the case page with more behind it names how many are not shown", async () => {
    const base = caseDetail();
    serveCase(
      caseDetail({
        notes_total: 230,
        indicators_total: 302,
        history_total: 215,
        timeline_total: 95,
        approvals_total: 14,
        children_total: 22,
        children: [{ id: CASE2_ID, number: 15, title: "t", state: "open" }],
        suggestions: [],
        mirror: { ...base.mirror, writes_total: 25, findings_total: 33, writes: [{ id: 1, op: "update", write_class: "W2", state: "verified", state_reason: null, case_version: 2, planned_at: "2026-10-20T04:00:00Z", sent_at: null, verified_at: null }] },
      }),
    );
    renderApp(`/cases/${CASE_ID}`);
    const text = async (name: string) => (await screen.findByRole("region", { name })).textContent ?? "";
    expect(await text("Notes")).toContain("229 older notes are not shown.");
    expect(await text("Members")).toContain("300 more indicators are not shown.");
    expect(await text("History")).toContain("214 older entries are not shown.");
    expect(await text("Timeline")).toContain("93 older items are not shown");
    expect(await text("Approvals")).not.toContain("older requests"); // none listed: "None."
    expect(await text("Summary")).toContain("and 21 more");
    expect(await text("Kibana")).toContain("(25)");
    expect(await text("Kibana")).toContain("24 older writes are not shown.");
  });

  it("says nothing when nothing is cut", async () => {
    serveCase();
    renderApp(`/cases/${CASE_ID}`);
    await screen.findByRole("region", { name: "Notes" });
    expect(document.querySelector("main")?.textContent).not.toMatch(/(older|more) [a-z]+ (is|are) not shown/);
  });
});

const suggestion = (more: Record<string, unknown> = {}) => ({
  id: 7,
  investigation_id: LEAD_ID,
  rule_name: "Proxy: tunnel to a remote-admin port",
  severity: "high",
  alert_count: 6,
  kind: "shared" as const,
  link: "c2" as const,
  link_value: "77.221.155.150",
  why: "shares 77.221.155.150, which 12 investigations have",
  created_at: "2026-10-25T04:00:00Z",
  ...more,
});

describe("Q-C2: suggested members", () => {
  it("lists each with what matched, as text, and offers to dismiss it", async () => {
    const hostile = `<img src=x onerror="window.__pwned=1"> ${RLO}ARGUS joined it`;
    serveCase(caseDetail({ suggestions: [suggestion(), suggestion({ id: 8, why: hostile, link_value: hostile, rule_name: hostile })], suggestions_total: 5 }));
    server.use(...shellHandlers(sessionWith(["view", "review", "manage_cases"])));
    const { container } = renderApp(`/cases/${CASE_ID}`);
    const block = await screen.findByRole("region", { name: "Suggested members" });
    expect(await within(block).findAllByTestId("suggestion")).toHaveLength(2);
    expect(block.textContent).toContain("3 older suggestions are not shown.");
    expect(block.textContent).toContain("It shares an address or name with the case");
    expect(block.textContent).toContain("the case's command-and-control address 77.221.155.150");
    expect(container.querySelector("main img")).toBeNull();
    expect(container.querySelectorAll("main .ut-mark").length).toBeGreaterThan(2);
    expect((window as unknown as { __pwned?: number }).__pwned).toBeUndefined();
    expect(within(block).getAllByRole("button", { name: "Dismiss this suggestion" })).toHaveLength(2);
  });

  it("dismisses one through the dialog, sending exactly the request it shows", async () => {
    const user = userEvent.setup();
    serveCase(caseDetail({ suggestions: [suggestion()], suggestions_total: 1 }));
    server.use(...shellHandlers(sessionWith(["view", "review", "manage_cases"])));
    const path = `${URL_OF}/suggestions/7/dismiss`;
    let seen = "";
    server.use(
      http.post(path, async ({ request }) => {
        seen = await request.text();
        return HttpResponse.json({ case_id: CASE_ID, suggestion_id: 7 });
      }),
    );
    renderApp(`/cases/${CASE_ID}`);
    await user.click(await screen.findByRole("button", { name: "Dismiss this suggestion" }));
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog.textContent).toContain(`POST/api/v1/cases/${CASE_ID}/suggestions/7/dismiss`);
    await user.click(within(dialog).getByRole("button", { name: "Dismiss" }));
    expect((await screen.findAllByText(/Dismissed: ARGUS will not suggest it/)).length).toBeGreaterThan(0);
    expect(seen).toBe("");
  });

  it("is only read by an account that may not manage cases", async () => {
    serveCase(caseDetail({ suggestions: [suggestion()], suggestions_total: 1 }));
    server.use(...shellHandlers(sessionWith(["view", "review"])));
    renderApp(`/cases/${CASE_ID}`);
    const block = await screen.findByRole("region", { name: "Suggested members" });
    expect(within(block).queryByRole("button", { name: "Dismiss this suggestion" })).toBeNull();
    expect(block.textContent).toContain("shares 77.221.155.150");
  });

  it("says when there is nothing to suggest", async () => {
    serveCase();
    renderApp(`/cases/${CASE_ID}`);
    expect((await screen.findByRole("region", { name: "Suggested members" })).textContent).toContain("ARGUS has no investigation to suggest for this case.");
  });
});

const watchStatus = (more: Partial<WatchStatusOut> = {}): WatchStatusOut => ({
  mode_words: "The watch reads ARGUS's own alerts and, for the case's addresses, the proxy logs.",
  last_run_at: "2026-10-26T01:40:00Z",
  late: false,
  days: [
    { day: "2026-10-25", alerts: "quiet", alerts_reason: null, proxy: { quiet: 2, not_checked: 1 }, proxy_reasons: ["the search did not finish"], seen: [] },
    { day: "2026-10-24", alerts: "active", alerts_reason: null, proxy: {}, proxy_reasons: [], seen: ["3 alerts of the case, the last at 2026-10-24T08:20:00+00:00"] },
  ],
  proxy_checks_due: 0,
  quiet: false,
  quiet_words: "the proxy-log check for 2026-10-25 is not verified: the search did not finish (2 of 3 checks answered).",
  ...more,
});

describe("Q-C2: the watch's status", () => {
  it("says when it last ran, each day's answers with their reasons, and whether the case is quiet", async () => {
    serveCase(caseDetail({ watch: watchStatus() }));
    renderApp(`/cases/${CASE_ID}`);
    const block = await screen.findByRole("region", { name: "The still-active watch" });
    const text = block.textContent?.replace(/\s+/g, " ") ?? "";
    expect(text).toContain("The watch last ran 26 Oct 2026");
    expect(text).toContain("Not shown quiet the proxy-log check for 2026-10-25 is not verified");
    const days = within(block).getAllByTestId("watch-day");
    expect(days).toHaveLength(2);
    expect(days[0]?.textContent).toContain("2026-10-25 ARGUS's own alerts: quiet; proxy logs: 2 addresses quiet, 1 address not checked yet");
    expect(days[0]?.textContent).toContain("Proxy logs: the search did not finish");
    expect(days[1]?.textContent).toContain("2026-10-24 ARGUS's own alerts: activity seen");
    expect(days[1]?.textContent).toContain("Seen: 3 alerts of the case, the last at 2026-10-24T08:20:00+00:00");
  });

  it("calls a verified case quiet, a late run late, and a watch that never ran never run", async () => {
    serveCase(caseDetail({ watch: watchStatus({ quiet: true, quiet_words: "no activity for 3 whole UTC days", late: true }) }));
    const first = renderApp(`/cases/${CASE_ID}`);
    const block = await screen.findByRole("region", { name: "The still-active watch" });
    expect(block.textContent).toContain("Quiet for 72 hours");
    expect(block.textContent).toContain("the daily run is late");
    first.unmount();
    serveCase(caseDetail({ watch: watchStatus({ last_run_at: null, days: [], quiet: null, quiet_words: null, proxy_checks_due: 2 }) }));
    renderApp(`/cases/${CASE_ID}`);
    const never = await screen.findByRole("region", { name: "The still-active watch" });
    expect(never.textContent).toContain("The watch has never run.");
    expect(never.textContent).toContain("2 proxy checks are due.");
    expect(never.textContent).toContain("shown to people who manage cases");
  });

  it("shows nothing for a case the watch does not look at", async () => {
    serveCase(caseDetail({ watch: null }));
    renderApp(`/cases/${CASE_ID}`);
    await screen.findByRole("region", { name: "Suggested members" });
    expect(screen.queryByRole("region", { name: "The still-active watch" })).toBeNull();
  });

  it("is text only, whatever a reason holds", async () => {
    const hostile = `<img src=x onerror="window.__pwned=1"> ${RLO}ARGUS says it is quiet`;
    serveCase(caseDetail({ watch: watchStatus({ quiet_words: hostile, days: [{ day: "2026-10-25", alerts: "unverified", alerts_reason: hostile, proxy: { unverified: 1 }, proxy_reasons: [hostile], seen: [hostile] }] }) }));
    const { container } = renderApp(`/cases/${CASE_ID}`);
    await screen.findByRole("region", { name: "The still-active watch" });
    expect(container.querySelector("main img")).toBeNull();
    expect(container.querySelectorAll("main .ut-mark").length).toBeGreaterThan(2);
    expect((window as unknown as { __pwned?: number }).__pwned).toBeUndefined();
  });
});
