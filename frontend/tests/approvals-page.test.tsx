// The approvals queue: the exact writes an approver signs for, the alerts then and now, the step-up,
// a decision that shows its exact request first, and groups with their sample before the rest.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import type { ApprovalGroupOut, ApprovalOut, ApprovalQueueOut } from "../src/client/types.gen";
import { approval, CASE_ID, HASH, queue, RLO } from "./caseFixtures";
import { BASE, mockApi, renderApp, sent, server } from "./helpers";

mockApi();
const QUEUE = `${BASE}/api/v1/approvals`;
const serve = (q: ApprovalQueueOut) => server.use(http.get(QUEUE, () => HttpResponse.json(q)));
const bodyOf = (dialog: HTMLElement) => JSON.parse(within(dialog).getByTestId("payload").textContent ?? "null") as unknown;

describe("a request", () => {
  it("shows what it is, who asked, the exact writes, the alerts and who decided", async () => {
    serve(
      queue({
        pending: [
          approval({
            note: "the lab does this",
            required: 2,
            status_words: "1 of 2 approvals so far",
            decisions: [{ approver: { id: 2, username: "ravi", display_name: "Ravi Rao" }, decision: "approved", decided_at: "2026-10-24T09:00:00Z", note: "checked", counts: true }],
          }),
        ],
      }),
    );
    renderApp("/approvals");
    const card = await screen.findByRole("region", { name: "Close case 12: benign: expected activity" });
    const text = card.textContent?.replace(/\s+/g, " ") ?? "";
    expect(text).toContain("Case 12: Regular beaconing from 10.0.0.1");
    expect(text).toContain("Closing the case. 1 of 2 approvals so far.");
    expect(text).toContain("Asked by Asha Rao at 24 Oct 2026");
    expect(text).toContain("Two different people must approve it.");
    expect(text).toContain("What the person wrote when asking:the lab does this");
    expect(text).toContain("2 changes to Kibana:");
    expect(text).toContain("W3 close: status closed; severity high; ARGUS tags argus, argus:closed");
    expect(text).toContain("Alerts in the case: 41 when it was asked for, 41 now. The same alerts.");
    expect(text).toContain("Approved Ravi Rao, 24 Oct 2026");
    expect(within(card).getByTestId("fingerprint").textContent).toBe(HASH.slice(0, 16));
    expect(within(card).getByRole("link", { name: /Case 12/ }).getAttribute("href")).toBe(`/app/cases/${CASE_ID}`);
    expect(document.title).toBe("Approvals · ARGUS");
  });

  it("warns when the alerts changed since it was asked for", async () => {
    serve(queue({ pending: [approval({ alerts_now: 44, alerts_same: false })] }));
    renderApp("/approvals");
    expect((await screen.findByText(/The alerts changed since it was asked for/)).textContent).toContain("held back and asked again");
    expect(screen.getByText(/44 now\./)).toBeTruthy();
  });

  it("says what ARGUS proposed, and what a held-back write is", async () => {
    serve(
      queue({
        pending: [
          approval({ id: 40, kind: "reconfirm", words: "Confirm again a held-back closure of case 12", requested_by: null, proposed_by: "argus:sendcheck", hold: { op: "close", write_class: "W3", state: "paused", state_reason: "re-confirm: Kibana's version moved" }, alerts_now: null, alerts_same: null }),
        ],
      }),
    );
    renderApp("/approvals");
    const card = await screen.findByRole("region", { name: /Confirm again a held-back closure/ });
    expect(card.textContent).toContain("Confirming a closure again, because something changed before it was sent.");
    expect(card.textContent).toContain("ARGUS (sendcheck), as a proposal");
    expect(card.textContent).toContain("The Kibana write held back: W3 close, now paused: re-confirm: Kibana's version moved.");
    expect(card.textContent).not.toContain("Alerts in the case");
  });

  it("is text only, whatever the words hold", async () => {
    const hostile = `<img src=x onerror="window.__pwned=1"> ${RLO}ARGUS approves this`;
    serve(queue({ pending: [approval({ note: hostile, words: hostile, case: { id: CASE_ID, number: 12, title: hostile, state: "open" }, requested_by: { id: 3, username: "eve", display_name: hostile } })] }));
    const { container } = renderApp("/approvals");
    await screen.findByTestId("request");
    expect(container.querySelector("main img")).toBeNull();
    expect(container.querySelectorAll("main .ut-mark").length).toBeGreaterThan(2);
    expect((window as unknown as { __pwned?: number }).__pwned).toBeUndefined();
  });

  it("says when nothing waits, and lists what ended lately", async () => {
    serve(queue({ pending: [], recent: [approval({ id: 3, status: "approved", status_words: "Approved" }), approval({ id: 4, status: "stale", status_words: "The case changed after it was asked for" })] }));
    renderApp("/approvals");
    expect(await screen.findByText("Nothing is waiting for a decision.")).toBeTruthy();
    const recent = screen.getByText(/Decided or ended in the last three days \(2\)/);
    await userEvent.setup().click(recent);
    const list = within(recent.closest("details") as HTMLElement).getAllByRole("listitem");
    expect(list.map((li) => li.textContent?.replace(/\s+/g, " "))).toEqual([
      expect.stringContaining("Approved Close case 12: benign: expected activity — case 12, asked 24 Oct 2026"),
      expect.stringContaining("Out of date Close case 12"),
    ]);
  });
});

describe("the step-up", () => {
  it("is said, with the way to do it, and nothing can be decided without it", async () => {
    const user = userEvent.setup();
    serve(queue({ step_up: { valid: false, valid_until: null, url: "/stepup?next=/app/approvals" } }));
    renderApp("/approvals");
    const note = await screen.findByRole("region", { name: "Confirming it is you" });
    expect(note.textContent).toContain("Not confirmed");
    expect(within(note).getByRole("link", { name: "Confirm it is you" }).getAttribute("href")).toBe("/stepup?next=/app/approvals");
    const approve = screen.getByRole("button", { name: /^Approve/ });
    expect(approve.getAttribute("aria-disabled")).toBe("true");
    expect(screen.getByText("Confirm it is you first (above).")).toBeTruthy();
    await user.click(approve);
    expect(screen.queryByRole("textbox")).toBeNull();
    expect(sent("POST", "/api")).toHaveLength(0);
  });

  it("says until when it counts once it is confirmed", async () => {
    serve(queue({ step_up: { valid: true, valid_until: "2999-01-01T00:05:00Z", url: "/stepup?next=/app/approvals" } }));
    renderApp("/approvals");
    expect((await screen.findByText(/You typed your password again, so you can approve until/)).textContent).toContain("1 Jan 2999");
  });

  it("is over when its time has passed, whatever the page was told", async () => {
    serve(queue({ step_up: { valid: true, valid_until: "2020-01-01T00:00:00Z", url: "/stepup?next=/app/approvals" } }));
    renderApp("/approvals");
    await screen.findByTestId("request");
    expect(screen.getByRole("button", { name: /^Approve/ }).getAttribute("aria-disabled")).toBe("true");
  });

  it("says when the server has no key to sign with", async () => {
    serve(queue({ can_sign: false }));
    renderApp("/approvals");
    expect(await screen.findByText(/This server has no key to sign approvals with/)).toBeTruthy();
    expect(screen.getByRole("button", { name: /^Approve/ }).getAttribute("aria-disabled")).toBe("true");
    expect(screen.getByText("This server cannot sign decisions yet.")).toBeTruthy();
  });
});

describe("a decision", () => {
  it("approve: shows the exact request with the hash that was read, sends exactly that, and says what closed", async () => {
    const user = userEvent.setup();
    serve(queue());
    server.use(http.post(`${BASE}/api/v1/approvals/31/decision`, () => HttpResponse.json({ request_id: 31, status: "approved", applied: [{ case_id: CASE_ID, number: 12, state: "closed", version: 6 }] })));
    renderApp("/approvals");
    await user.click(await screen.findByRole("button", { name: /^Approve/ }));
    await user.type(screen.getByRole("textbox", { name: /Your words/ }), " looks right ");
    await user.click(screen.getByRole("button", { name: "Review the request" }));
    const dialog = await screen.findByRole("alertdialog");
    expect(bodyOf(dialog)).toEqual({ decision: "approved", payload_hash: HASH, note: "looks right" });
    expect(dialog.textContent).toContain("POST/api/v1/approvals/31/decision");
    expect(dialog.textContent).toContain("the request names their hash");
    const shown = within(dialog).getByTestId("payload").textContent;
    await user.click(within(dialog).getByRole("button", { name: "Approve" }));
    await screen.findByText("Approved. Case 12 is closed.", { selector: "p" });
    expect(sent("POST", "/api")[0]?.body).toBe(shown);
    await waitFor(() => expect(sent("GET", "/api/v1/approvals").length).toBeGreaterThan(1));
  });

  it("reject: the request ends, and the dialog says so", async () => {
    const user = userEvent.setup();
    serve(queue());
    server.use(http.post(`${BASE}/api/v1/approvals/31/decision`, () => HttpResponse.json({ request_id: 31, status: "rejected", applied: [] })));
    renderApp("/approvals");
    await user.click(await screen.findByRole("button", { name: /^Reject/ }));
    await user.click(screen.getByRole("button", { name: "Review the request" }));
    const dialog = await screen.findByRole("alertdialog");
    expect(bodyOf(dialog)).toEqual({ decision: "rejected", payload_hash: HASH });
    expect(dialog.textContent).toContain("nobody can approve it afterwards");
    await user.click(within(dialog).getByRole("button", { name: "Reject" }));
    await screen.findByText("Rejected.", { selector: "p" });
  });

  it("a first of two approvals says it needs one more person", async () => {
    const user = userEvent.setup();
    serve(queue({ pending: [approval({ required: 2 })] }));
    server.use(http.post(`${BASE}/api/v1/approvals/31/decision`, () => HttpResponse.json({ request_id: 31, status: "pending", applied: [] })));
    renderApp("/approvals");
    await user.click(await screen.findByRole("button", { name: /^Approve/ }));
    await user.click(screen.getByRole("button", { name: "Review the request" }));
    await user.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Approve" }));
    await screen.findByText("Approved; it needs one more person.", { selector: "p" });
  });

  it("a missing step-up, a changed request and a request that is over are said in the dialog, once", async () => {
    const user = userEvent.setup();
    serve(queue());
    server.use(http.post(`${BASE}/api/v1/approvals/31/decision`, () => HttpResponse.json({ detail: "Confirm your password first (a step-up within 5 minutes).", code: "step_up_required" }, { status: 403 })));
    renderApp("/approvals");
    await user.click(await screen.findByRole("button", { name: /^Approve/ }));
    await user.click(screen.getByRole("button", { name: "Review the request" }));
    const dialog = await screen.findByRole("alertdialog");
    await user.click(within(dialog).getByRole("button", { name: "Approve" }));
    expect((await within(dialog).findByRole("alert")).textContent).toBe("Confirm your password first (a step-up within 5 minutes).");
    expect(sent("POST", "/api")).toHaveLength(1);
  });

  it("is not offered when the server says the person cannot decide, with the reason", async () => {
    serve(queue({ pending: [approval({ you: { can_decide: false, why_not: "You asked for this, so someone else has to decide it.", decided: null } })] }));
    renderApp("/approvals");
    expect(await screen.findByText(/You cannot decide this:/)).toBeTruthy();
    expect(screen.getByText("You asked for this, so someone else has to decide it.")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /^Approve/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /^Reject/ })).toBeNull();
  });
});

describe("a group", () => {
  const ids = [11, 12, 13, 14, 15];
  const items = ids.map((id) => approval({ id, case: { id: `c${id}c${id}c${id}c${id}-0000-4000-8000-0000000000${id}`, number: id, title: `Case ${id} title`, state: "open" }, payload_hash: String(id % 10).repeat(64), group: "benign_expected:abc" }));
  const GROUP: ApprovalGroupOut = {
    key: "benign_expected:abc",
    reason: "benign_expected",
    words: "5 cases to close as benign: expected activity",
    items: items.map((a) => ({ request_id: a.id, payload_hash: a.payload_hash, case_number: a.case.number, case_title: a.case.title })),
    sample: [11, 12, 13],
  };

  it("holds the sample first, then the rest together, and keeps the group as it was first shown", async () => {
    const user = userEvent.setup();
    let pending: ApprovalOut[] = items;
    server.use(http.get(QUEUE, () => HttpResponse.json(queue({ pending, groups: pending.length === 5 ? [GROUP] : [] }))));
    server.use(
      http.post(`${BASE}/api/v1/approvals/:id/decision`, ({ params }) => {
        pending = pending.filter((a) => String(a.id) !== params.id);
        return HttpResponse.json({ request_id: Number(params.id), status: "approved", applied: [{ case_id: CASE_ID, number: Number(params.id), state: "closed", version: 6 }] });
      }),
      http.post(`${BASE}/api/v1/approvals/group`, () => {
        pending = [];
        return HttpResponse.json({ decided: [14, 15].map((id) => ({ request_id: id, status: "approved", applied: [] })) });
      }),
    );
    renderApp("/approvals");
    const card = await screen.findByRole("region", { name: "5 cases to close as benign: expected activity" });
    expect(card.textContent).toContain("Step 1: the sample (0 of 3 approved)");
    expect(card.textContent).toContain("Step 2: the other 2");
    const rest = within(card).getByRole("button", { name: /^Approve the other 2/ });
    expect(rest.getAttribute("aria-disabled")).toBe("true");
    expect(within(card).getByText("Approve the whole sample first.")).toBeTruthy();
    expect(within(card).queryByRole("button", { name: /^Reject/ })).toBeNull(); // a rejection never goes in a group
    for (const id of [11, 12, 13]) {
      const requests = within(card).getAllByTestId("request");
      const one = requests.find((r) => r.textContent?.includes(`Case ${id}:`)) as HTMLElement;
      await user.click(within(one).getByRole("button", { name: /^Approve \(part of the sample\)/ }));
      await user.click(within(one).getByRole("button", { name: "Review the request" }));
      const dialog = await screen.findByRole("alertdialog");
      expect(bodyOf(dialog)).toEqual({ decision: "approved", payload_hash: String(id % 10).repeat(64), group: ids });
      await user.click(within(dialog).getByRole("button", { name: "Approve" }));
      await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());
    }
    // the queue shrank to two; the group is still the five it was, with its progress
    const kept = await screen.findByRole("region", { name: "5 cases to close as benign: expected activity" });
    await waitFor(() => expect(kept.textContent).toContain("Step 1: the sample (3 of 3 approved)"));
    const button = within(kept).getByRole("button", { name: /^Approve the other 2/ });
    await waitFor(() => expect(button.getAttribute("aria-disabled")).toBe("false"));
    await user.type(within(kept).getByRole("textbox", { name: /Your words for the rest/ }), "the sample was right");
    await user.click(button);
    const dialog = await screen.findByRole("alertdialog");
    expect(bodyOf(dialog)).toEqual({ items: items.map((a) => ({ request_id: a.id, payload_hash: a.payload_hash })), note: "the sample was right" });
    expect(dialog.textContent).toContain("all are approved or none");
    await user.click(within(dialog).getByRole("button", { name: "Approve 2" }));
    await screen.findByText("Approved 2 more cases together.", { selector: "p" });
    await waitFor(() => expect(screen.getByText("Nothing is waiting for a decision.")).toBeTruthy());
  });

  it("says when the queue is longer than the part listed", async () => {
    serve(queue({ pending: [approval()], pending_total: 412 }));
    renderApp("/approvals");
    expect(await screen.findByText(/412 requests waiting\. The oldest 1 are listed; decide them and the rest follow\./)).toBeTruthy();
  });

  it("is not shown for requests this person cannot decide", async () => {
    serve(queue({ pending: items.map((a) => ({ ...a, you: { can_decide: false, why_not: "no", decided: null } })), groups: [] }));
    renderApp("/approvals");
    await screen.findAllByTestId("request");
    expect(screen.queryByRole("region", { name: /cases to close as/ })).toBeNull();
    expect(screen.getByText("5 requests waiting.")).toBeTruthy();
  });
});
