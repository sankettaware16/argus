// A case in analyst order, and what a person can do with it: every action says why when it cannot be
// taken; every change shows its exact request, sends exactly that and names the version it was
// looked at; Kibana's comments and every title are text only.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import type { CaseDetail, FindingOut } from "../src/client/types.gen";
import { ACTIONS, approval, CASE_ID, CASE2_ID, caseDetail, caseRow, casePage, HASH, LEAD_ID, MIRROR, RLO } from "./caseFixtures";
import { BASE, detail as investigationDetail, mockApi, REPORT, renderApp, sent, server, sessionWith, shellHandlers } from "./helpers";

mockApi();
const URL_OF = `${BASE}/api/v1/cases/${CASE_ID}`;

function serve(d: CaseDetail = caseDetail(), more: ReturnType<typeof http.get>[] = []) {
  server.use(
    ...more, // first: the first handler that matches answers
    http.get(URL_OF, () => HttpResponse.json(d)),
    http.get(`${BASE}/api/v1/investigations/${LEAD_ID}/reports`, () => HttpResponse.json({ items: [REPORT], logs_hidden: false })),
    http.get(`${BASE}/api/v1/investigations/${LEAD_ID}`, () => HttpResponse.json(investigationDetail({}, { id: LEAD_ID }))),
  );
}

const actions = () => within(screen.getByRole("region", { name: "Actions" }));
const shownBody = (dialog: HTMLElement) => JSON.parse(within(dialog).getByTestId("payload").textContent ?? "null") as unknown;

async function openAction(user: ReturnType<typeof userEvent.setup>, name: string) {
  await user.click(await screen.findByRole("button", { name }));
}

describe("the page", () => {
  it("is in the analyst's order: the tabs, and everything on one page in the old order", async () => {
    serve();
    renderApp(`/incidents/${CASE_ID}`);
    await screen.findByRole("heading", { level: 1, name: /Regular beaconing/ });
    expect(within(screen.getByRole("tablist")).getAllByRole("tab").map((t) => t.textContent?.replace(/\d+$/, ""))).toEqual(["Overview", "Story", "Evidence", "Entities", "Alert groups", "Report", "Activity"]);
    expect(document.title).toBe("Incident · ARGUS");
    renderApp(`/incidents/${CASE_ID}?tab=all`);
    await screen.findByTestId("everything");
    const headings = within(screen.getByTestId("everything")).getAllByRole("heading", { level: 2 }).map((h) => h.textContent);
    expect(headings).toEqual(["Summary", "Report", "Kibana case preview", "What's new", "Timeline", "Evidence", "Hypotheses", "Unknowns", "What you can do", "Members", "Approvals", "Kibana", "Notes", "History"]);
  });

  it("summarises in words, numbers first", async () => {
    serve(caseDetail({ children: [{ id: CASE2_ID, number: 15, title: "t", state: "open" }], parent: { id: CASE2_ID, number: 9, title: "t", state: "closed" } }, { attention: "New activity after containment", owner: { id: 2, username: "ravi", display_name: "Ravi Rao" }, state: "assigned", waiting_for_approval: 1, in_kibana: true }));
    renderApp(`/incidents/${CASE_ID}?tab=all`);
    const summary = await screen.findByRole("region", { name: "Summary" });
    const text = summary.textContent?.replace(/\s+/g, " ") ?? "";
    expect(text).toContain("Assigned: An incident a person owns. Taken by: Ravi Rao. Opened by a person.");
    expect(text).toContain("3 alert groups, 41 alerts, from 18 Oct 2026");
    expect(text).toContain("A person has decided 1 of them; 2 have not been decided (or changed since).");
    expect(text).toContain("Rules: Proxy: tunnel to a remote-admin port (3 investigations, 41 alerts).");
    expect(text).toContain("Needs a person. New activity after containment");
    expect(text).toContain("1 request waiting for an approver");
    expect(within(summary).getByRole("link", { name: "case 9" }).getAttribute("href")).toBe("/app/cases/c2c2c2c2-0000-4000-8000-000000000002");
    expect(within(summary).getByRole("link", { name: "case 15" })).toBeTruthy();
  });

  it("says what a possible incident is, and never sends a person to the command line", async () => {
    for (const cause of ["proposal", "raised"] as const) {
      serve(caseDetail({ cause_words: "Suspected from ARGUS's own proposal." }, { state: "suspected", opened_at: null, cause }));
      const view = renderApp(`/incidents/${CASE_ID}?tab=all`);
      const summary = await screen.findByRole("region", { name: "Summary" });
      expect(summary.textContent).toContain("Possible incident: ARGUS thinks it may be an incident; nobody has confirmed it yet.");
      expect(summary.textContent).not.toContain("Kibana has nothing"); // the case team may have posted it
      expect(summary.textContent).not.toContain("argus case");
      expect(summary.textContent).not.toContain("review one of its investigations as a true positive");
      view.unmount();
    }
  });

  it("shows evidence, hypotheses and unknowns from the lead investigation's report, and says whose", async () => {
    serve();
    renderApp(`/incidents/${CASE_ID}?tab=all`);
    const evidence = await screen.findByRole("region", { name: "Evidence" });
    expect(await within(evidence).findByText("Contacts at a fixed interval.")).toBeTruthy();
    expect(evidence.textContent).toContain("From the lead investigation: Proxy: tunnel to a remote-admin port");
    expect(within(evidence).getByRole("link", { name: "its whole report" }).getAttribute("href")).toBe(`/app/alert-groups/${LEAD_ID}?tab=report`);
    expect(evidence.textContent).toContain("The other 2 investigations have their own reports.");
    expect(await within(screen.getByRole("region", { name: "Hypotheses" })).findByText("C2 beaconing")).toBeTruthy();
    expect(await within(screen.getByRole("region", { name: "Unknowns" })).findByText(/Who looks after H1/)).toBeTruthy();
  });

  it("says when logs are hidden and when a case has no investigation or no report", async () => {
    serve(caseDetail({ logs_hidden: true }), [http.get(`${BASE}/api/v1/investigations/${LEAD_ID}/reports`, () => HttpResponse.json({ items: [], logs_hidden: true }))]);
    renderApp(`/incidents/${CASE_ID}?tab=all`);
    expect(await screen.findAllByText(/No report yet: ARGUS has not built the lead investigation's dossier\./)).toHaveLength(3);
    expect(screen.getByText(/Your account cannot read the logs in ELK, so what the logs said is hidden\./)).toBeTruthy();
  });

  it("has a lead report only when there is a lead", async () => {
    serve(caseDetail({ lead_investigation_id: null, investigations: [], investigations_total: 0 }));
    renderApp(`/incidents/${CASE_ID}?tab=all`);
    expect(await screen.findAllByText("The case has no investigation yet.")).toHaveLength(3);
    expect(sent("GET", `/api/v1/investigations/${LEAD_ID}`)).toHaveLength(0);
  });

  it("says plainly when a case is not there", async () => {
    server.use(http.get(URL_OF, () => HttpResponse.json({ detail: "no such case", code: "not_found" }, { status: 404 })));
    renderApp(`/incidents/${CASE_ID}?tab=all`);
    expect(await screen.findByText(/This incident does not exist, or you cannot see it\./)).toBeTruthy();
    expect(screen.getByRole("link", { name: "Back to Incidents" })).toBeTruthy();
  });

  it("lists what is new, the timeline, the members and the history", async () => {
    serve();
    renderApp(`/incidents/${CASE_ID}?tab=all`);
    const news = await screen.findByRole("region", { name: "What's new" });
    expect(news.textContent).toContain("Ravi Rao Ravi Rao took the case");
    const timeline = screen.getByRole("region", { name: "Timeline" });
    expect(within(timeline).getAllByRole("listitem")).toHaveLength(2);
    expect(timeline.textContent).toContain("Alerts");
    const members = screen.getByRole("region", { name: "Members" });
    expect(within(members).getByRole("table", { name: "Investigations in this case" }).textContent).toContain("14");
    expect(members.textContent).toContain("2 more are not listed here");
    expect(members.textContent).toContain("A lab printer, says the lab.");
    expect(members.textContent).toContain("command & control");
    const history = screen.getByRole("region", { name: "History" });
    expect(history.textContent).toContain("v1");
    expect(history.textContent).toContain("Asha Rao opened the case");
  });
});

describe("the actions", () => {
  it("say why they cannot be taken, and do nothing then", async () => {
    const user = userEvent.setup();
    serve();
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    const release = await screen.findByRole("button", { name: "Release" });
    expect(release.getAttribute("aria-disabled")).toBe("true");
    const region = screen.getByRole("region", { name: "Actions" });
    expect(region.textContent).toContain("Not available: Only an assigned case can be released; this one is open.");
    expect(release.getAttribute("aria-describedby")).toBeTruthy();
    await user.click(release);
    await user.click(screen.getByRole("button", { name: "Reopen" }));
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(sent("POST", "/api")).toHaveLength(0);
    expect(region.textContent).toContain("has not shown the case quiet for 72 hours");
    expect(region.textContent).toContain("Every change names the version of the case you are looking at (version 4)");
  });

  it("show what a view-only account may not do, in the server's words", async () => {
    server.use(...shellHandlers(sessionWith(["view"])));
    const no = (a: (typeof ACTIONS)[number]) => ({ ...a, enabled: false, why_not: `Your account may not do this: it needs a capability (${a.label}).` });
    serve(caseDetail({ actions: ACTIONS.map(no) }));
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    await screen.findByRole("heading", { name: "What you can do" });
    const region = screen.getByRole("region", { name: "Actions" });
    for (const b of within(region).getAllByRole("button")) expect(b.getAttribute("aria-disabled")).toBe("true");
    expect(region.textContent).toContain("Your account may not do this");
    expect(screen.getByText(/Your account may view only: adding a note needs the “review” capability/)).toBeTruthy();
  });

  it("take: shows the exact request, sends exactly that, and says what happened", async () => {
    const user = userEvent.setup();
    serve(caseDetail(), [http.post(`${URL_OF}/take`, () => HttpResponse.json({ case: caseRow({ state: "assigned", version: 5 }), result: "done", request_id: null }))]);
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    await openAction(user, "Take");
    const dialog = await screen.findByRole("alertdialog");
    expect(shownBody(dialog)).toEqual({ expected_version: 4 });
    expect(dialog.textContent).toContain(`POST/api/v1/cases/${CASE_ID}/take`);
    // plain words first (P4-F U9); the version is in the request one click away
    expect(dialog.textContent).toContain("You will own case 12; others see you as its owner. If anyone changed it since you read it, nothing is saved.");
    const shown = within(dialog).getByTestId("payload").textContent;
    await user.click(within(dialog).getByRole("button", { name: "Take" }));
    await screen.findByText("You took case 12.", { selector: "p" });
    expect(sent("POST", "/api")[0]?.body).toBe(shown);
    await waitFor(() => expect(sent("GET", `/api/v1/cases/${CASE_ID}`).length).toBeGreaterThan(1)); // read again
  });

  it("sends nothing when cancelled, and nothing twice when pressed twice", async () => {
    const user = userEvent.setup();
    serve(caseDetail(), [http.post(`${URL_OF}/take`, async () => {
      await new Promise((r) => setTimeout(r, 150));
      return HttpResponse.json({ case: caseRow(), result: "done", request_id: null });
    })]);
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    await openAction(user, "Take");
    await user.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());
    expect(sent("POST", "/api")).toHaveLength(0);
    await openAction(user, "Take");
    const confirm = within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Take" });
    await user.dblClick(confirm);
    await waitFor(() => expect(sent("POST", "/api")).toHaveLength(1));
    await new Promise((r) => setTimeout(r, 300));
    expect(sent("POST", "/api")).toHaveLength(1);
  });

  it("a case that moved: said in the dialog, nothing resent, and the case read again", async () => {
    const user = userEvent.setup();
    serve(caseDetail(), [http.post(`${URL_OF}/take`, () => HttpResponse.json({ detail: "The case changed meanwhile: it is at version 5, you saw 4.", code: "conflict" }, { status: 409 }))]);
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    await openAction(user, "Take");
    const dialog = await screen.findByRole("alertdialog");
    await user.click(within(dialog).getByRole("button", { name: "Take" }));
    expect((await within(dialog).findByRole("alert")).textContent).toBe("The case changed meanwhile: it is at version 5, you saw 4.");
    expect(sent("POST", "/api")).toHaveLength(1);
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(sent("GET", `/api/v1/cases/${CASE_ID}`).length).toBeGreaterThan(1));
    expect(sent("POST", "/api")).toHaveLength(1);
  });

  it("assign: chooses an active person other than the owner, and names them by id", async () => {
    const user = userEvent.setup();
    serve(caseDetail({}, { owner: { id: 1, username: "asha", display_name: "Asha Rao" }, state: "assigned" }), [http.post(`${URL_OF}/assign`, () => HttpResponse.json({ case: caseRow({ state: "assigned", version: 5 }), result: "done", request_id: null }))]);
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    await openAction(user, "Assign");
    const choose = await screen.findByRole("combobox", { name: /Give the case to/ });
    expect(within(choose).getAllByRole("option").map((o) => o.textContent)).toEqual(["Choose a person…", "Ravi Rao (ravi)"]);
    await user.click(actions().getByRole("button", { name: "Review the request" }));
    expect(screen.queryByRole("alertdialog")).toBeNull();
    await user.selectOptions(choose, "2");
    await user.click(actions().getByRole("button", { name: "Review the request" }));
    const dialog = await screen.findByRole("alertdialog");
    expect(shownBody(dialog)).toEqual({ expected_version: 4, user_id: 2 });
    await user.click(within(dialog).getByRole("button", { name: "Assign" }));
    await screen.findByText("Assigned case 12 to Ravi Rao.", { selector: "p" });
  });

  it("contain and reopen: need the person's words, and send them with the version", async () => {
    const user = userEvent.setup();
    const contained = caseDetail({ actions: ACTIONS.map((a) => (a.action === "contain" ? { ...a, enabled: true, why_not: null } : a)) });
    serve(contained, [http.post(`${URL_OF}/contain`, () => HttpResponse.json({ detail: "ARGUS has not shown the case quiet for 72 hours, so it cannot be confirmed contained yet: the still-active watch is not running here.", code: "not_ready" }, { status: 409 }))]);
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    await openAction(user, "Confirm contained");
    await user.click(actions().getByRole("button", { name: "Review the request" }));
    expect(screen.queryByRole("alertdialog")).toBeNull(); // no words, no request
    await user.type(screen.getByRole("textbox", { name: /Why it is contained/ }), "  the host was reimaged ");
    await user.click(actions().getByRole("button", { name: "Review the request" }));
    const dialog = await screen.findByRole("alertdialog");
    expect(shownBody(dialog)).toEqual({ expected_version: 4, attestation: "the host was reimaged" });
    await user.click(within(dialog).getByRole("button", { name: "Confirm contained" }));
    expect((await within(dialog).findByRole("alert")).textContent).toContain("has not shown the case quiet for 72 hours");
  });
});

describe("asking for a closure", () => {
  const preview = (hash = HASH) => ({
    case_id: CASE_ID,
    case_version: 4,
    bound_version: 5,
    reason: "benign_expected",
    target: null,
    payload: approval().payload,
    payload_hash: hash,
    in_kibana: true,
    words: "Asking for this closure binds 2 changes to Kibana: an approver reads exactly these before they approve.",
    approvers: 1,
  });

  it("offers each reason with its meaning and why not, then shows the writes before anything is asked", async () => {
    const user = userEvent.setup();
    serve(caseDetail(), [http.get(`${URL_OF}/closure-preview`, () => HttpResponse.json(preview()))]);
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    await openAction(user, "Request closure");
    const radios = screen.getAllByRole("radio");
    expect(radios.map((r) => (r as HTMLInputElement).disabled)).toEqual([true, false, false, false, false]);
    const fieldset = screen.getByRole("group", { name: "Why should this case be closed?" });
    expect(fieldset.textContent).toContain("Not available: “Fixed, and shown quiet” needs ARGUS to have shown the case quiet for 72 hours");
    expect(fieldset.textContent).toContain("Two different people must approve it.");
    await user.click(screen.getByRole("radio", { name: /Benign: expected activity/ }));
    await user.click(screen.getByRole("button", { name: "Show what it would write" }));
    const box = await screen.findByRole("region", { name: "What asking would write" });
    expect(await within(box).findByText("2 changes to Kibana:")).toBeTruthy();
    expect(box.textContent).toContain("W3 close: status closed; severity high; ARGUS tags argus, argus:closed");
    expect(box.textContent).toContain("needs one approver");
    expect(within(box).getByTestId("fingerprint").textContent).toBe(HASH.slice(0, 16));
    expect(sent("GET", `/api/v1/cases/${CASE_ID}/closure-preview`)[0]?.path).toBe(`/api/v1/cases/${CASE_ID}/closure-preview?reason=benign_expected&expected_version=4`);
    expect(sent("POST", "/api")).toHaveLength(0);
  });

  it("sends the request with the version and the hash of the preview that was read, exactly as shown", async () => {
    const user = userEvent.setup();
    serve(caseDetail(), [
      http.get(`${URL_OF}/closure-preview`, () => HttpResponse.json(preview())),
      http.post(`${URL_OF}/closure-requests`, () => HttpResponse.json({ case: caseRow({ version: 5 }), result: "requested", request_id: 31 }, { status: 201 })),
    ]);
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    await openAction(user, "Request closure");
    await user.click(screen.getByRole("radio", { name: /Benign: expected activity/ }));
    await user.type(screen.getByRole("textbox", { name: /Your words/ }), " it is a printer ");
    await user.click(screen.getByRole("button", { name: "Show what it would write" }));
    await user.click(await screen.findByRole("button", { name: "Ask for this closure" }));
    const dialog = await screen.findByRole("alertdialog");
    expect(shownBody(dialog)).toEqual({ expected_version: 4, reason: "benign_expected", note: "it is a printer", payload_hash: HASH });
    const shown = within(dialog).getByTestId("payload").textContent;
    expect(dialog.textContent).toContain("Nothing is closed by this.");
    await user.click(within(dialog).getByRole("button", { name: "Ask for the closure" }));
    await screen.findByText(/Asked to close case 12 as benign: expected activity\. An approver decides; nothing is closed yet\./, { selector: "p" });
    expect(sent("POST", "/api")[0]?.body).toBe(shown);
    expect(sent("POST", "/api")).toHaveLength(1);
  });

  it("needs the words a reason asks for before it shows anything", async () => {
    const user = userEvent.setup();
    serve(caseDetail(), [http.get(`${URL_OF}/closure-preview`, () => HttpResponse.json({ ...preview("b".repeat(64)), reason: "risk_accepted", approvers: 2 }))]);
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    await openAction(user, "Request closure");
    await user.click(screen.getByRole("radio", { name: /Left as it is, by decision/ }));
    expect(screen.getByText("Your words (required)")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Show what it would write" }));
    expect(screen.queryByRole("region", { name: "What asking would write" })).toBeNull();
    await user.type(screen.getByRole("textbox", { name: /Your words/ }), "The lab accepts the risk, in writing.");
    await user.click(screen.getByRole("button", { name: "Show what it would write" }));
    const box = await screen.findByRole("region", { name: "What asking would write" });
    expect(await within(box).findByText(/needs two different people/)).toBeTruthy();
  });

  it("changing the reason or the words hides a preview that no longer matches", async () => {
    const user = userEvent.setup();
    serve(caseDetail(), [http.get(`${URL_OF}/closure-preview`, () => HttpResponse.json(preview()))]);
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    await openAction(user, "Request closure");
    await user.click(screen.getByRole("radio", { name: /Benign: expected activity/ }));
    await user.click(screen.getByRole("button", { name: "Show what it would write" }));
    await screen.findByRole("region", { name: "What asking would write" });
    await user.click(screen.getByRole("radio", { name: /Benign: allowed by policy/ }));
    expect(screen.queryByRole("region", { name: "What asking would write" })).toBeNull();
  });

  it("says why a preview cannot be made", async () => {
    const user = userEvent.setup();
    serve(caseDetail(), [http.get(`${URL_OF}/closure-preview`, () => HttpResponse.json({ detail: "The case changed meanwhile: it is at version 6, you saw 4.", code: "conflict" }, { status: 409 }))]);
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    await openAction(user, "Request closure");
    await user.click(screen.getByRole("radio", { name: /Benign: expected activity/ }));
    await user.click(screen.getByRole("button", { name: "Show what it would write" }));
    expect(await screen.findByText(/The preview could not be shown\./)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Ask for this closure" })).toBeNull();
  });

  it("shows the writes as text, whatever they hold", async () => {
    const user = userEvent.setup();
    const hostile = `<img src=x onerror="window.__pwned=1"> ${RLO}`;
    const payload = { writes: [{ class: "W3", op: "close", payload: { status: "closed", argus_tags: [hostile] } }] };
    serve(caseDetail(), [http.get(`${URL_OF}/closure-preview`, () => HttpResponse.json({ ...preview(), payload }))]);
    const { container } = renderApp(`/incidents/${CASE_ID}?tab=activity`);
    await openAction(user, "Request closure");
    await user.click(screen.getByRole("radio", { name: /Benign: expected activity/ }));
    await user.click(screen.getByRole("button", { name: "Show what it would write" }));
    await screen.findByTestId("writes");
    expect(container.querySelector("main img")).toBeNull();
    expect(container.querySelectorAll("[data-testid=writes] .ut-mark").length).toBeGreaterThan(0);
    expect((window as unknown as { __pwned?: number }).__pwned).toBeUndefined();
  });
});

describe("merging", () => {
  const target = (state: "open" | "suspected" | "closed" = "open", id = CASE2_ID) => casePage([caseRow({ id, number: 13, title: "Second case", state })], { view: "all" });

  it("a confirmed case asks, with the preview's hash, for the case numbered", async () => {
    const user = userEvent.setup();
    serve(caseDetail(), [
      http.get(`${BASE}/api/v1/cases`, () => HttpResponse.json(target())),
      http.get(`${URL_OF}/merge-preview`, () => HttpResponse.json({ case_id: CASE_ID, case_version: 4, bound_version: 5, reason: "duplicate", target: { id: CASE2_ID, number: 13, title: "Second case", state: "open" }, payload: { writes: [] }, payload_hash: HASH, in_kibana: false, words: "Asking for this merge writes nothing to Kibana (the case is not there).", approvers: 1 })),
      http.post(`${URL_OF}/merge`, () => HttpResponse.json({ case: caseRow({ version: 5 }), result: "requested", request_id: 40 }, { status: 201 })),
    ]);
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    await openAction(user, "Merge into another case");
    await user.type(screen.getByRole("textbox", { name: /Merge into case number/ }), "13");
    expect(await screen.findByText(/Second case/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Show what it would write" }));
    await screen.findByText(/Nothing is written to Kibana/);
    await user.click(screen.getByRole("button", { name: "Ask for this merge" }));
    const dialog = await screen.findByRole("alertdialog");
    expect(shownBody(dialog)).toEqual({ expected_version: 4, target_case_id: CASE2_ID, payload_hash: HASH });
    await user.click(within(dialog).getByRole("button", { name: "Ask for the merge" }));
    await screen.findByText(/Asked to merge case 12 into case 13\. An approver decides; nothing is merged yet\./, { selector: "p" });
  });

  it("a case that is closed, the same case or a suspected one for a confirmed case is refused with the reason", async () => {
    const user = userEvent.setup();
    serve(caseDetail(), [http.get(`${BASE}/api/v1/cases`, ({ request }) => HttpResponse.json(new URL(request.url).searchParams.get("number") === "12" ? casePage([caseRow()]) : new URL(request.url).searchParams.get("number") === "14" ? target("closed") : target("suspected")))]);
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    await openAction(user, "Merge into another case");
    const box = screen.getByRole("textbox", { name: /Merge into case number/ });
    await user.type(box, "12");
    expect(await screen.findByText(/Not possible: A case is not merged into itself\./)).toBeTruthy();
    await user.clear(box);
    await user.type(box, "14");
    expect(await screen.findByText(/Not possible: That case is closed/)).toBeTruthy();
    await user.clear(box);
    await user.type(box, "15");
    expect(await screen.findByText(/Not possible: An incident is merged into another incident, not into a possible one/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Ask for this merge" }).getAttribute("aria-disabled")).toBe("true");
  });

  it("a suspected case is merged at once, with no preview and no hash", async () => {
    const user = userEvent.setup();
    serve(caseDetail({}, { state: "suspected", opened_at: null }), [
      http.get(`${BASE}/api/v1/cases`, () => HttpResponse.json(target())),
      http.post(`${URL_OF}/merge`, () => HttpResponse.json({ case: caseRow({ state: "closed", version: 5 }), result: "merged", request_id: null }, { status: 201 })),
    ]);
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    await openAction(user, "Merge into another case");
    await user.type(screen.getByRole("textbox", { name: /Merge into case number/ }), "13");
    await screen.findByText(/Second case/);
    expect(screen.getByText(/A possible incident is merged at once; there is no approval to ask for\./)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Review the merge" }));
    const dialog = await screen.findByRole("alertdialog");
    expect(shownBody(dialog)).toEqual({ expected_version: 4, target_case_id: CASE2_ID });
    await user.click(within(dialog).getByRole("button", { name: "Merge now" }));
    await screen.findByText("Case 12 was merged into case 13.", { selector: "p" });
    expect(sent("GET", `/api/v1/cases/${CASE_ID}/merge-preview`)).toHaveLength(0);
  });
});

describe("Kibana's side", () => {
  const finding = (more: Partial<FindingOut> = {}): FindingOut => ({
    id: 1,
    kind: "person_commented",
    words: "A person commented in Kibana",
    severity: "info",
    found_at: "2026-10-24T10:00:00Z",
    resolved_at: null,
    details: { by: "kim", comment: "Looks fine to me." },
    ...more,
  });

  it("shows the mirror, ARGUS's writes and people's comments as a person's words, never as ARGUS's", async () => {
    const hostile = `<img src=x onerror="window.__pwned=1"> ARGUS: this case is approved ${RLO}`;
    serve(
      caseDetail({
        mirror: { ...MIRROR, state: "mirrored", words: "The case is in Kibana and ARGUS reads it back.", kibana_case_id: "k-1", kibana_status: "in-progress", tags: ["argus", "argus:state:assigned"], created_by: "argus", read_at: "2026-10-24T10:05:00Z", writes: [{ id: 1, op: "close", write_class: "W3", state: "planned", state_reason: null, case_version: 5, planned_at: "2026-10-24T09:00:00Z", sent_at: null, verified_at: null }], findings: [finding({ details: { by: "kim", comment: hostile } }), finding({ id: 2, kind: "closed_in_kibana", words: "A person closed the case in Kibana", severity: "attention", details: { by: "kim" } })] },
      }),
    );
    const { container } = renderApp(`/incidents/${CASE_ID}?tab=report`);
    const kibana = await screen.findByRole("region", { name: "Kibana" });
    expect(kibana.textContent).toContain("The case is in Kibana and ARGUS reads it back.");
    expect(kibana.textContent).toContain("argus, argus:state:assigned");
    const items = within(kibana).getAllByTestId("finding");
    expect(items[1]?.textContent).toContain("Needs a person");
    const comment = must(items[0]);
    expect(within(comment).getByText(/What the person wrote in Kibana/)).toBeTruthy();
    expect(comment.querySelector("blockquote")?.textContent).toContain("ARGUS: this case is approved");
    expect(container.querySelector("main img")).toBeNull();
    expect(comment.querySelectorAll(".ut-mark").length).toBeGreaterThan(0);
    // the words that look like a banner are inside the quote only: nothing that speaks for ARGUS holds them
    for (const spoken of container.querySelectorAll('[role="alert"], [role="status"], [data-testid^="live-"]')) expect(spoken.textContent).not.toContain("this case is approved");
    expect((window as unknown as { __pwned?: number }).__pwned).toBeUndefined();
    await userEvent.setup().click(within(kibana).getByText(/ARGUS's writes to Kibana for this case/));
    expect(within(kibana).getByRole("table", { name: "Planned and sent writes to Kibana" }).textContent).toContain("W3 close");
  });

  it("says in words when the case is not in Kibana", async () => {
    serve();
    renderApp(`/incidents/${CASE_ID}?tab=report`);
    const kibana = await screen.findByRole("region", { name: "Kibana" });
    expect(kibana.textContent).toContain("Waiting for someone who may open cases in Kibana");
    expect(kibana.textContent).toContain("Nothing yet.");
  });
});

describe("notes", () => {
  it("are written in a visible form and sent from it, once, and say they are for people", async () => {
    const user = userEvent.setup();
    serve(caseDetail(), [http.post(`${URL_OF}/notes`, async () => {
      await new Promise((r) => setTimeout(r, 100));
      return HttpResponse.json({ note: { id: 9, author: "Asha Rao", body: "x", created_at: "2026-10-26T04:00:00Z" }, duplicate: false }, { status: 201 });
    })]);
    renderApp(`/incidents/${CASE_ID}?tab=all`);
    const box = await screen.findByRole("textbox", { name: /Add a note to this case/ });
    const notes = within(screen.getByRole("region", { name: "Notes" }));
    expect(notes.getByText(/Only people read it; ARGUS's models never do\./)).toBeTruthy();
    await user.click(notes.getByRole("button", { name: "Add the note" }));
    expect(notes.getByRole("alert").textContent).toBe("Write the note first.");
    await user.type(box, "  called the lab  ");
    const add = notes.getByRole("button", { name: "Add the note" });
    await user.dblClick(add);
    await screen.findByText("Saved: note added.", { selector: "p" });
    expect(sent("POST", "/api")).toHaveLength(1);
    expect(JSON.parse(sent("POST", "/api")[0]?.body ?? "")).toEqual({ body: "called the lab" });
    expect((box as HTMLTextAreaElement).value).toBe("");
  });

  it("say when the same note was there a moment ago", async () => {
    const user = userEvent.setup();
    serve(caseDetail(), [http.post(`${URL_OF}/notes`, () => HttpResponse.json({ note: { id: 9, author: "Asha Rao", body: "x", created_at: "2026-10-26T04:00:00Z" }, duplicate: true }, { status: 201 }))]);
    renderApp(`/incidents/${CASE_ID}?tab=all`);
    await user.type(await screen.findByRole("textbox", { name: /Add a note to this case/ }), "again");
    await user.click(within(screen.getByRole("region", { name: "Notes" })).getByRole("button", { name: "Add the note" }));
    await screen.findByText("That note was added a moment ago; it was not added twice.", { selector: "p" });
  });

  it("keep what was typed when saving fails, and say so once next to the form", async () => {
    const user = userEvent.setup();
    serve(caseDetail(), [http.post(`${URL_OF}/notes`, () => HttpResponse.json({ detail: "boom", code: "internal" }, { status: 500 }))]);
    renderApp(`/incidents/${CASE_ID}?tab=all`);
    const box = await screen.findByRole("textbox", { name: /Add a note to this case/ });
    await user.type(box, "keep me");
    await user.click(within(screen.getByRole("region", { name: "Notes" })).getByRole("button", { name: "Add the note" }));
    expect((await within(screen.getByRole("region", { name: "Notes" })).findByRole("alert")).textContent).toBe("Something went wrong in ARGUS; it has been logged. Try again, or tell an ARGUS admin.");
    expect((box as HTMLTextAreaElement).value).toBe("keep me");
    expect(sent("POST", "/api")).toHaveLength(1);
  });

  it("show a person's words as text, in a frame that is theirs", async () => {
    const body = `<script>window.__pwned=1</script> ${RLO}hello`;
    serve(caseDetail({ notes: [{ id: 5, author: `<b>Eve</b>`, body, created_at: "2026-10-22T04:00:00Z" }] }));
    const { container } = renderApp(`/incidents/${CASE_ID}?tab=all`);
    const notes = await screen.findByRole("list", { name: "Notes" });
    expect(notes.querySelector("script")).toBeNull();
    expect(notes.querySelector("b")).toBeNull();
    expect(notes.textContent).toContain("<script>window.__pwned=1</script>");
    expect(container.querySelectorAll("[aria-label=Notes] .ut-mark").length).toBeGreaterThan(0);
    expect((window as unknown as { __pwned?: number }).__pwned).toBeUndefined();
  });

  it("about an address, sent from its own form with the kind and value", async () => {
    const user = userEvent.setup();
    serve(caseDetail(), [http.post(`${BASE}/api/v1/entity-notes`, () => HttpResponse.json({ note: { id: 2, author: "Asha Rao", body: "x", created_at: "2026-10-26T04:00:00Z" }, duplicate: false }, { status: 201 }))]);
    renderApp(`/incidents/${CASE_ID}?tab=all`);
    const [indicator] = await screen.findAllByTestId("indicator");
    await user.click(within(must(indicator)).getByText("Add a note about this ip"));
    await user.type(within(must(indicator)).getByRole("textbox"), "the lab printer");
    await user.click(within(must(indicator)).getByRole("button", { name: "Add the note" }));
    await screen.findByText("Saved: note added about it.", { selector: "p" });
    expect(JSON.parse(sent("POST", "/api")[0]?.body ?? "")).toEqual({ kind: "ip", value: "10.0.0.1", body: "the lab printer" });
  });
});

function must<T>(value: T | undefined | null): T {
  if (value === undefined || value === null) throw new Error("the value was not there");
  return value;
}

describe("Check more on a case", () => {
  it("is about the lead investigation at the version the case page read, and suggests the case's addresses", async () => {
    const user = userEvent.setup();
    serve(caseDetail());
    renderApp(`/incidents/${CASE_ID}?tab=all`);
    const members = await screen.findByRole("region", { name: "Members" });
    const check = within(await within(members).findByRole("region", { name: "Check more" }));
    expect(members.textContent).toContain("This check is about the lead investigation, Proxy: tunnel to a remote-admin port.");
    await user.selectOptions(await check.findByRole("combobox", { name: "Check" }), "ti.lookup");
    await user.type(check.getByRole("combobox", { name: "Address or domain" }), "bad.example");
    await user.click(check.getByRole("button", { name: "Review the request" }));
    const dialog = await screen.findByRole("alertdialog");
    expect(shownBody(dialog)).toEqual({ template: "ti.lookup", entity: "bad.example", seen_version: 3 });
    expect(dialog.textContent).toContain(`POST/api/v1/investigations/${LEAD_ID}/checks`);
    expect([...document.querySelectorAll("datalist option")].map((o) => o.getAttribute("value"))).toEqual(["10.0.0.1", "bad.example"]);
    expect(sent("GET", `/api/v1/investigations/${LEAD_ID}`).filter((r) => !r.path.includes("/reports") && !r.path.includes("/checks"))).toHaveLength(0);
  });
});

describe("the name of a form about an address", () => {
  it("is made of the address with its hidden characters marked, never the characters themselves", async () => {
    const hostile = `10.0.0.1${RLO}evil`;
    serve(caseDetail({ indicators: [{ kind: "host", value: hostile, role: "actor", source: "investigation", notes: [], note_count: 0 }] }));
    renderApp(`/incidents/${CASE_ID}?tab=all`);
    const [indicator] = await screen.findAllByTestId("indicator");
    const form = within(must(indicator)).getByRole("form", { hidden: true });
    expect(form.getAttribute("aria-label")).toBe("A note about host 10.0.0.1‹RLO›evil");
    expect(form.getAttribute("aria-label")).not.toContain(RLO);
  });
});

describe("approvals of the case", () => {
  it("are listed with their standing and a way to decide them", async () => {
    serve(caseDetail({ approvals: [approval({ status: "pending" }), approval({ id: 30, status: "approved", status_words: "Approved" })] }));
    renderApp(`/incidents/${CASE_ID}?tab=all`);
    const region = await screen.findByRole("region", { name: "Approvals" });
    expect(within(region).getAllByRole("listitem")).toHaveLength(2);
    expect(region.textContent).toContain("Waiting");
    expect(region.textContent).toContain("Approved");
    expect(within(region).getAllByRole("link", { name: "Decide it" })).toHaveLength(1);
  });
});
