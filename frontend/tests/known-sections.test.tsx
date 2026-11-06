// AR4b on the case page (D-169, D-176 to D-181): the owner-notified record. Recording a notice or a
// block and withdrawing one (each shows its exact request first, names the version, and says what is
// wrong before it sends), the reminders that are due, the known infection (alerts since the notice,
// new destinations, changes waiting), the managed or personal wording, the block list and its
// downloads, and the closure reason stopped after notice.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import type { BlocklistOut, CaseDetail } from "../src/client/types.gen";
import { caseDetail, CASE_ID, CHOICES, knownOut, LEAD_ID } from "./caseFixtures";
import { BASE, detail as investigationDetail, mockApi, must, REPORT, renderApp, sent, server, sessionWith, shellHandlers } from "./helpers";

mockApi();
const URL_OF = `${BASE}/api/v1/cases/${CASE_ID}`;
const MANAGER = ["view", "see_logs", "review", "manage_cases"];
const state = (action: "notify" | "block" | "withdraw_notice", label: string, enabled: boolean, why_not: string | null) => ({ action, label, enabled, why_not });

function serve(d: CaseDetail = caseDetail({ known: knownOut() }, { state: "open", notified_at: "2026-10-20T04:00:00Z" }), more: ReturnType<typeof http.get>[] = []) {
  server.use(
    ...more,
    http.get(URL_OF, () => HttpResponse.json(d)),
    http.get(`${BASE}/api/v1/investigations/${LEAD_ID}/reports`, () => HttpResponse.json({ items: [REPORT], logs_hidden: false })),
    http.get(`${BASE}/api/v1/investigations/${LEAD_ID}`, () => HttpResponse.json(investigationDetail({}, { id: LEAD_ID }))),
  );
}

const section = async () => within(await screen.findByRole("region", { name: "Owner notified" }));
const here = () => within(screen.getByRole("region", { name: "Owner notified" }));
const review = () => here().getByRole("button", { name: "Review the request" });
const shownBody = (dialog: HTMLElement) => JSON.parse(within(dialog).getByTestId("payload").textContent ?? "null") as Record<string, unknown>;
const done = (changed: Record<string, unknown> = {}) => HttpResponse.json({ case: caseDetail().case, result: "done", request_id: null, ...changed });

describe("the section", () => {
  it("is not there for a case that is not open or assigned", async () => {
    serve(caseDetail({ known: null }));
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    await screen.findByRole("heading", { level: 1, name: /Regular beaconing/ });
    await screen.findByTestId("activity-log");
    expect(screen.queryByRole("region", { name: "Owner notified" })).toBeNull();
  });

  it("is in the Activity tab under Owner and containment, and after the summary on the one-page view", async () => {
    serve();
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    await screen.findByRole("region", { name: "Owner notified" });
    const panel = screen.getByRole("tabpanel");
    expect(within(panel).getAllByRole("heading", { level: 2 }).map((h) => h.textContent).slice(0, 2)).toEqual(["Activity", "Owner notified"]);
    renderApp(`/incidents/${CASE_ID}?tab=all`);
    const all = await screen.findByTestId("everything");
    await within(all).findByRole("region", { name: "Owner notified" });
    expect(within(all).getAllByRole("heading", { level: 2 }).map((h) => h.textContent).slice(0, 5)).toEqual(["Summary", "Report", "Kibana case preview", "Owner notified", "What's new"]);
  });

  it("says who was told, how and when, by whom, and what ARGUS has counted since", async () => {
    serve();
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    const s = await section();
    expect(s.getByTestId("known-line").textContent).toContain("still active: 41 alerts in 6 days since the owner was notified on 20 Oct 2026");
    expect(s.getByText(/41 alerts in 6 days since the notice; alerts a day: about the same each day\./)).toBeTruthy();
    const [notice] = s.getAllByTestId("notice");
    expect(notice?.textContent).toContain("Owner told");
    expect(notice?.textContent).toContain("Hostel 5 warden (By phone)");
    expect(notice?.textContent).toContain("personal");
    expect(notice?.textContent).toContain("recorded by Mina Manager");
    expect(notice?.textContent).toContain("she will bring the laptop in");
    const days = s.getByRole("table", { name: "Alerts a day since the notice (IST days)" });
    expect(within(days).getAllByRole("row").slice(1).map((r) => r.textContent)).toEqual(["2026-10-2612", "2026-10-2529"]);
  });
});

describe("managed or personal", () => {
  it("says personal devices can be told and not fixed", async () => {
    serve();
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    const words = (await screen.findByTestId("managed-words")).textContent ?? "";
    expect(words).toContain("Personal devices");
    expect(words).toContain("cannot wipe or isolate it");
  });

  it("says university-managed machines are the university's to act on", async () => {
    serve(caseDetail({ known: knownOut({ managed: true }) }, { state: "open" }));
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    const words = (await screen.findByTestId("managed-words")).textContent ?? "";
    expect(words).toContain("University-managed");
    expect(words).toContain("ACME can act on them");
  });

  it("says nothing is known before the owner is told", async () => {
    serve(caseDetail({ known: knownOut({ managed: null, notified_at: null, notices: [], line: null, alerts: 0, days: 0, alerts_per_day: [] }) }, { state: "open" }));
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    const words = (await screen.findByTestId("managed-words")).textContent ?? "";
    expect(words).toContain("Not told yet");
    expect(words).toContain("Once the owner is told");
    expect(screen.getByText(/The owner has not been recorded as told, so ARGUS does not treat this case as a known infection/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Record that the owner was told" })).toBeTruthy();
  });
});

describe("the known infection", () => {
  it("lists the new destinations since the notice, and how many more are kept", async () => {
    serve(
      caseDetail(
        {
          known: knownOut({
            new_destinations: [
              { kind: "ip", value: "203.0.113.9", added_at: "2026-10-25T04:00:00Z" },
              { kind: "domain", value: "evil.example", added_at: "2026-10-26T04:00:00Z" },
            ],
            new_destinations_total: 52,
          }),
        },
        { state: "open" },
      ),
    );
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    const s = await section();
    expect(s.getByRole("region", { name: "52 new destinations since the notice" })).toBeTruthy();
    const list = s.getByRole("list", { name: "New destinations" });
    expect(within(list).getAllByRole("listitem").map((li) => li.textContent?.replace(/\s+/g, " "))).toEqual([
      "203.0.113.9 (address, first seen 25 Oct 2026, 9:30 AM IST)",
      "evil.example (domain, first seen 26 Oct 2026, 9:30 AM IST)",
    ]);
    expect(s.getByText("50 more are kept and not listed here.")).toBeTruthy();
  });

  it("lists the changes waiting for a person, each with its investigation", async () => {
    serve(caseDetail({ known: knownOut({ changes: [{ investigation_id: LEAD_ID, rule_name: "Proxy: tunnel", why: "a new flagged destination: 203.0.113.9", last_event_at: "2026-10-26T08:00:00Z" }] }) }, { state: "open" }));
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    const list = within(await screen.findByRole("list", { name: "Changes since the notice" }));
    expect(list.getByRole("link", { name: "Proxy: tunnel" }).getAttribute("href")).toBe(`/app/alert-groups/${LEAD_ID}`);
    expect(list.getByText(/a new flagged destination: 203\.0\.113\.9/)).toBeTruthy();
  });

  it("says none when nothing changed", async () => {
    serve();
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    const s = await section();
    expect(within(s.getByRole("region", { name: "Changes waiting for a person" })).getByText("None.")).toBeTruthy();
  });
});

describe("recording a notice", () => {
  async function fill(user: ReturnType<typeof userEvent.setup>) {
    await user.click(await screen.findByRole("button", { name: "Record another notice" }));
    await user.type(here().getByLabelText(/^Who was told/), "the department head");
    await user.selectOptions(here().getByLabelText("How"), "email");
  }

  it("needs who was told and how, says what is missing, and shows nothing before they are there", async () => {
    const user = userEvent.setup();
    serve();
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    await user.click(await screen.findByRole("button", { name: "Record another notice" }));
    await user.click(review());
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(await screen.findByText("Choose how the owner was told.")).toBeTruthy();
    await user.selectOptions(here().getByLabelText("How"), "phone");
    await user.click(review());
    expect(await screen.findAllByText("Who was told is needed.")).not.toHaveLength(0);
    expect(sent("POST", "/api")).toHaveLength(0);
  });

  it("refuses a time in the future and a time that is not a time", async () => {
    const user = userEvent.setup();
    serve();
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    await fill(user);
    const when = here().getByLabelText(/^When \(IST\)/);
    await user.type(when, "2099-01-01T10:00");
    await user.click(review());
    expect(await screen.findAllByText("That time is in the future. Leave it empty for now.")).not.toHaveLength(0);
    expect(sent("POST", "/api")).toHaveLength(0);
  });

  it("shows the exact request with the version looked at, sends exactly that, and says it was recorded", async () => {
    const user = userEvent.setup();
    serve(undefined, [http.post(`${URL_OF}/notices`, () => done())]);
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    await fill(user);
    await user.type(here().getByLabelText(/^A note/), "he will tell the lab");
    await user.click(review());
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog.textContent).toContain(`POST/api/v1/cases/${CASE_ID}/notices`);
    expect(shownBody(dialog)).toEqual({ expected_version: 4, told: "the department head", how: "email", note: "he will tell the lab" });
    await waitFor(() => expect(document.activeElement?.textContent).toBe("Cancel"));
    await user.click(within(dialog).getByRole("button", { name: "Record the notice" }));
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());
    expect(await screen.findByText("Recorded: the owner of case 12 was told.", { selector: "p" })).toBeTruthy();
    expect(JSON.parse(sent("POST", "/api")[0]?.body ?? "")).toEqual({ expected_version: 4, told: "the department head", how: "email", note: "he will tell the lab" });
    await waitFor(() => expect(sent("GET", `/api/v1/cases/${CASE_ID}`).filter((r) => r.path === `/api/v1/cases/${CASE_ID}`).length).toBeGreaterThanOrEqual(2));
  });

  it("sends the time as the person typed it on the campus clock, and says it in 12-hour form", async () => {
    const user = userEvent.setup();
    serve(undefined, [http.post(`${URL_OF}/notices`, () => done())]);
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    await fill(user);
    await user.type(here().getByLabelText(/^When \(IST\)/), "2026-10-26T19:20");
    await user.click(review());
    const dialog = await screen.findByRole("alertdialog");
    expect(shownBody(dialog).at).toBe("2026-10-26T19:20:00+05:30"); // not a UTC instant
    expect(dialog.textContent).toContain("It is dated 26 Oct 2026, 7:20 PM IST.");
    expect(dialog.textContent).not.toMatch(/\dZ"|T\d\d:\d\d:\d\d\.\d{3}Z/);
  });

  it("says in the dialog that the time is when it is sent when none was typed", async () => {
    const user = userEvent.setup();
    serve(undefined, [http.post(`${URL_OF}/notices`, () => done())]);
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    await fill(user);
    await user.click(review());
    const dialog = await screen.findByRole("alertdialog");
    expect(shownBody(dialog)).not.toHaveProperty("at");
    expect(dialog.textContent).toContain("It is dated when you send it.");
  });

  it("keeps a typed draft and an open dialog when the case's version moves silently, and sends the version it was shown", async () => {
    const user = userEvent.setup();
    const base = caseDetail({ known: knownOut() }, { state: "open", notified_at: "2026-10-20T04:00:00Z" });
    let answer = base;
    server.use(
      http.get(URL_OF, () => HttpResponse.json(answer)),
      http.get(`${BASE}/api/v1/investigations/${LEAD_ID}/reports`, () => HttpResponse.json({ items: [REPORT], logs_hidden: false })),
      http.get(`${BASE}/api/v1/investigations/${LEAD_ID}`, () => HttpResponse.json(investigationDetail({}, { id: LEAD_ID }))),
      http.post(`${URL_OF}/notices`, () => HttpResponse.json({ detail: "The case changed while you looked: it is at version 4, you saw 3.", code: "conflict" }, { status: 409 })),
    );
    const { queries } = renderApp(`/incidents/${CASE_ID}?tab=activity`);
    await fill(user);
    await user.click(review());
    const dialog = await screen.findByRole("alertdialog");
    const seen = shownBody(dialog).expected_version;
    expect(seen).toBe(base.case.version);
    // a background read finds the case one version on (a silent bump: nobody did anything the person saw)
    answer = { ...base, case: { ...base.case, version: base.case.version + 1 } };
    await queries.invalidateQueries({ queryKey: ["case", CASE_ID] });
    await waitFor(() => expect(sent("GET", `/api/v1/cases/${CASE_ID}`).length).toBeGreaterThanOrEqual(2));
    // the dialog is still there, still showing the version the person read, with nothing to look at again
    expect(screen.getByRole("alertdialog")).toBe(dialog);
    expect(shownBody(dialog).expected_version).toBe(seen);
    expect(within(dialog).queryByText(/This request changed while you were reading it/)).toBeNull();
    // sending it is refused plainly, and what was typed is still in the form
    await user.click(within(dialog).getByRole("button", { name: "Record the notice" }));
    expect((await within(dialog).findByRole("alert")).textContent).toContain("The case changed while you looked");
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());
    expect((here().getByLabelText(/^Who was told/) as HTMLInputElement).value).toBe("the department head");
    // the next look at the request is of the version the page has now
    await user.click(review());
    expect(shownBody(await screen.findByRole("alertdialog")).expected_version).toBe(base.case.version + 1);
  });

  it("keeps a typed draft of each form when the version moves while no dialog is open", async () => {
    const user = userEvent.setup();
    const base = caseDetail({ known: knownOut() }, { state: "open", notified_at: "2026-10-20T04:00:00Z" });
    let answer = base;
    server.use(
      http.get(URL_OF, () => HttpResponse.json(answer)),
      http.get(`${BASE}/api/v1/investigations/${LEAD_ID}/reports`, () => HttpResponse.json({ items: [REPORT], logs_hidden: false })),
      http.get(`${BASE}/api/v1/investigations/${LEAD_ID}`, () => HttpResponse.json(investigationDetail({}, { id: LEAD_ID }))),
    );
    const { queries } = renderApp(`/incidents/${CASE_ID}?tab=activity`);
    await fill(user);
    answer = { ...base, case: { ...base.case, version: base.case.version + 1 } };
    await queries.invalidateQueries({ queryKey: ["case", CASE_ID] });
    await waitFor(() => expect(sent("GET", `/api/v1/cases/${CASE_ID}`).length).toBeGreaterThanOrEqual(2));
    expect((here().getByLabelText(/^Who was told/) as HTMLInputElement).value).toBe("the department head"); // the form was not rebuilt
    await user.click(review());
    expect(shownBody(await screen.findByRole("alertdialog")).expected_version).toBe(base.case.version + 1);
  });

  it("keeps the dialog open and says why when the case moved (409), and the form stays", async () => {
    const user = userEvent.setup();
    serve(undefined, [http.post(`${URL_OF}/notices`, () => HttpResponse.json({ detail: "The case changed while you looked: nothing was saved.", code: "conflict" }, { status: 409 }))]);
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    await fill(user);
    await user.click(review());
    const dialog = await screen.findByRole("alertdialog");
    await user.click(within(dialog).getByRole("button", { name: "Record the notice" }));
    expect((await within(dialog).findByRole("alert")).textContent).toContain("The case changed while you looked");
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());
    expect((here().getByLabelText(/^Who was told/) as HTMLInputElement).value).toBe("the department head");
  });

  it("says why it is not available to someone who may not, and offers no form", async () => {
    serve(caseDetail({ known: knownOut({ notify: state("notify", "Record a notice", false, "Your account may not record notices: it needs the “manage_cases” capability.") }) }, { state: "open" }));
    server.use(...shellHandlers(sessionWith(["view"])));
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    const button = await screen.findByRole("button", { name: "Record another notice" });
    expect(button.getAttribute("aria-disabled")).toBe("true");
    expect(screen.getByText(/Your account may not record notices/)).toBeTruthy();
    await userEvent.setup().click(button);
    expect(screen.queryByLabelText(/^Who was told/)).toBeNull();
  });
});

describe("recording a block", () => {
  it("needs who and where, shows the request, and sends it", async () => {
    const user = userEvent.setup();
    serve(undefined, [http.post(`${URL_OF}/blocks`, () => done())]);
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    await user.click(await screen.findByRole("button", { name: "Record a network block" }));
    await user.click(review());
    expect(await screen.findAllByText("Who blocked it is needed.")).not.toHaveLength(0);
    await user.type(here().getByLabelText("Who blocked it"), "the network team");
    await user.click(review());
    expect(await screen.findAllByText("Where it was blocked is needed.")).not.toHaveLength(0);
    await user.type(here().getByLabelText(/^Where/), "DNS and the firewall");
    await user.click(review());
    const dialog = await screen.findByRole("alertdialog");
    expect(shownBody(dialog)).toEqual({ expected_version: 4, by: "the network team", where: "DNS and the firewall" });
    await user.click(within(dialog).getByRole("button", { name: "Record the block" }));
    expect(await screen.findByText("Recorded: the case 12 servers were blocked at the network.", { selector: "p" })).toBeTruthy();
    expect(sent("POST", "/api")[0]?.path).toBe(`/api/v1/cases/${CASE_ID}/blocks`);
  });

  it("lists a recorded block as a block", async () => {
    serve(caseDetail({ known: knownOut({ blocked_at: "2026-10-24T04:00:00Z", notices: [...knownOut().notices, { kind: "block", at: "2026-10-24T04:00:00Z", told: "the network team", how: "DNS", managed: null, note: null, by: "Mina Manager", case_version: 3, withdrawn: false }] }) }, { state: "open" }));
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    const notices = await screen.findAllByTestId("notice");
    expect(notices[1]?.textContent).toContain("Blocked at the network");
    expect(notices[1]?.textContent).toContain("the network team, at DNS");
  });
});

describe("withdrawing a notice", () => {
  it("needs a reason, shows the request, and says the notice was withdrawn", async () => {
    const user = userEvent.setup();
    serve(undefined, [http.post(`${URL_OF}/notices/withdraw`, () => done())]);
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    await user.click(await screen.findByRole("button", { name: "Withdraw a notice recorded by mistake" }));
    await user.click(review());
    expect(await screen.findAllByText("The reason is needed.")).not.toHaveLength(0);
    expect(sent("POST", "/api")).toHaveLength(0);
    await user.type(here().getByLabelText(/^Why it was a mistake/), "recorded on the wrong case");
    await user.click(review());
    const dialog = await screen.findByRole("alertdialog");
    expect(shownBody(dialog)).toEqual({ expected_version: 4, reason: "recorded on the wrong case" });
    expect(within(dialog).getByRole("button", { name: "Withdraw the notice" })).toBeTruthy();
    await user.click(within(dialog).getByRole("button", { name: "Withdraw the notice" }));
    expect(await screen.findByText("Withdrawn: case 12 is not notified any more.", { selector: "p" })).toBeTruthy();
    expect(sent("POST", "/api")[0]?.path).toBe(`/api/v1/cases/${CASE_ID}/notices/withdraw`);
  });

  it("shows a withdrawn notice as withdrawn, kept as it was said", async () => {
    serve(caseDetail({ known: knownOut({ notices: [{ ...must(knownOut().notices[0]), withdrawn: true }] }) }, { state: "open" }));
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    expect((await screen.findByTestId("notice")).textContent).toContain("(withdrawn: recorded by mistake; kept as it was said)");
  });

  it("says why there is nothing to withdraw before a notice", async () => {
    serve(caseDetail({ known: knownOut({ notified_at: null, notices: [], withdraw_notice: state("withdraw_notice", "Withdraw", false, "There is no notice to withdraw.") }) }, { state: "open" }));
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    const button = await screen.findByRole("button", { name: "Withdraw a notice recorded by mistake" });
    expect(button.getAttribute("aria-disabled")).toBe("true");
    expect(screen.getByText("There is no notice to withdraw.")).toBeTruthy();
  });
});

describe("the reminders that are due", () => {
  const REMINDERS = [
    { kind: "notify_again" as const, words: "Still active 7 days after the owner was told.", suggested_at: "2026-10-27T04:00:00Z" },
    { kind: "network_action" as const, words: "Still active 21 days after the notice and no block is recorded.", suggested_at: "2026-10-28T04:00:00Z" },
  ];

  it("lists each with its words, and says it is only a suggestion", async () => {
    serve(caseDetail({ known: knownOut({ reminders: REMINDERS }) }, { state: "open" }));
    server.use(...shellHandlers(sessionWith(MANAGER)));
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    const items = await screen.findAllByTestId("reminder");
    expect(items.map((i) => i.textContent)).toEqual([
      "Tell the owner again: the device is still active. Still active 7 days after the owner was told. Suggested 27 Oct 2026, 9:30 AM IST. It is a suggestion; nothing was sent.Dismiss this reminder",
      "Ask for a block at the network: the device is still active. Still active 21 days after the notice and no block is recorded. Suggested 28 Oct 2026, 9:30 AM IST. It is a suggestion; nothing was sent.Dismiss this reminder",
    ]);
  });

  it("says none are due", async () => {
    serve();
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    await screen.findByRole("region", { name: "Owner notified" });
    expect(within(screen.getByRole("region", { name: "Reminders that are due" })).getByText("None due.")).toBeTruthy();
  });

  it("dismisses one after showing the request", async () => {
    const user = userEvent.setup();
    serve(caseDetail({ known: knownOut({ reminders: REMINDERS }) }, { state: "open" }), [http.post(`${URL_OF}/reminders/notify_again/dismiss`, () => HttpResponse.json({ case_id: CASE_ID, kind: "notify_again" }))]);
    server.use(...shellHandlers(sessionWith(MANAGER)));
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    const [first] = await screen.findAllByRole("button", { name: "Dismiss this reminder" });
    await user.click(first as HTMLElement);
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog.textContent).toContain(`POST/api/v1/cases/${CASE_ID}/reminders/notify_again/dismiss`);
    await user.click(within(dialog).getByRole("button", { name: "Dismiss" }));
    expect(await screen.findByText("Dismissed: ARGUS will not suggest it again.", { selector: "p" })).toBeTruthy();
    expect(sent("POST", "/api")).toHaveLength(1);
  });

  it("is not offered to someone who may not manage cases", async () => {
    serve(caseDetail({ known: knownOut({ reminders: REMINDERS }) }, { state: "open" }));
    server.use(...shellHandlers(sessionWith(["view"])));
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    await screen.findAllByTestId("reminder");
    expect(screen.queryByRole("button", { name: "Dismiss this reminder" })).toBeNull();
  });
});

describe("the block list", () => {
  const LIST: BlocklistOut = {
    case_number: 12, title: "Beaconing", skipped: 2, cut: false, notified_at: "2026-10-20T04:00:00Z", blocked_at: null,
    entries: [
      { type: "family", value: "fast-dns-host.com", evidence: "7 of 94 engines flag it", engines_flagging: 7, engines_total: 94, owner: null, registered: "2026-09-01", first_seen_on_campus: "2026-10-15T04:00:00Z", campus_devices: 47, evidence_checked: "2026-10-26T04:00:00Z" },
      { type: "address", value: "203.0.113.9", evidence: "no outside record yet", engines_flagging: null, engines_total: null, owner: "Private Layer", registered: null, first_seen_on_campus: null, campus_devices: 1, evidence_checked: null },
    ],
  };

  it("says how many entries are ready and offers it as CSV and as text", async () => {
    serve();
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    const s = await section();
    expect(s.getByText("3 entries ready.")).toBeTruthy();
    const csv = s.getByRole("link", { name: "Download as CSV" });
    expect(csv.getAttribute("href")).toBe(`/api/v1/cases/${CASE_ID}/blocklist.csv`);
    expect(csv.hasAttribute("download")).toBe(true);
    const text = s.getByRole("link", { name: "Download as text (an e-mail)" });
    expect(text.getAttribute("href")).toBe(`/api/v1/cases/${CASE_ID}/blocklist.txt`);
    expect(text.getAttribute("download")).toBe("argus-case-12-blocklist.txt");
    expect(sent("GET", "/api/v1/cases/" + CASE_ID + "/blocklist")).toHaveLength(0); // not built until asked for
  });

  it("is built and shown only when the person opens it, with the evidence for each entry", async () => {
    const user = userEvent.setup();
    serve(undefined, [http.get(`${URL_OF}/blocklist`, () => HttpResponse.json(LIST))]);
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    await screen.findByRole("region", { name: "Owner notified" });
    await user.click(screen.getByText("View the list"));
    const table = await screen.findByRole("table", { name: "Block list" });
    const rows = within(table).getAllByRole("row").slice(1).map((r) => [...r.querySelectorAll("td")].map((c) => c.textContent));
    expect(rows).toEqual([
      ["domain and every name under it", "fast-dns-host.com", "7 of 94 engines flag it", "—", "2026-09-01", "15 Oct 2026, 9:30 AM IST", "47"],
      ["address", "203.0.113.9", "no outside record yet", "Private Layer", "—", "unknown time", "1"],
    ]);
    expect(screen.getByText("2 values were left out (shared infrastructure).")).toBeTruthy();
  });

  it("says when nothing qualifies, and when it cannot be read", async () => {
    const user = userEvent.setup();
    serve(undefined, [http.get(`${URL_OF}/blocklist`, () => HttpResponse.json({ ...LIST, entries: [], skipped: 0 }))]);
    const first = renderApp(`/incidents/${CASE_ID}?tab=activity`);
    await screen.findByRole("region", { name: "Owner notified" });
    await user.click(screen.getByText("View the list"));
    expect(await screen.findByText("Nothing to block yet: no outside address or domain qualifies.")).toBeTruthy();
    first.unmount();
    serve(undefined, [http.get(`${URL_OF}/blocklist`, () => HttpResponse.json({ detail: "boom", code: "internal" }, { status: 500 }))]);
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    await screen.findByRole("region", { name: "Owner notified" });
    await user.click(screen.getByText("View the list"));
    expect(await screen.findByText(/The block list could not be shown/)).toBeTruthy();
  });

  it("shows a hostile value as text", async () => {
    const user = userEvent.setup();
    const hostile = '<img src=x onerror="window.__pwned=1">';
    serve(undefined, [http.get(`${URL_OF}/blocklist`, () => HttpResponse.json({ ...LIST, entries: [{ ...must(LIST.entries[0]), value: hostile, evidence: hostile }] }))]);
    const { container } = renderApp(`/incidents/${CASE_ID}?tab=activity`);
    await screen.findByRole("region", { name: "Owner notified" });
    await user.click(screen.getByText("View the list"));
    await screen.findByRole("table", { name: "Block list" });
    expect(container.querySelector("img")).toBeNull();
  });
});

describe("the closure reason stopped after notice", () => {
  it("is among the reasons a closure is asked for, with its meaning, for a notified case", async () => {
    const user = userEvent.setup();
    const stopped = { reason: "stopped_after_notice" as const, label: "Stopped after the owner was told", meaning: "The device's owner was told and nothing matching has been seen for 14 days; it may not be fixed, but it is quiet.", enabled: true, why_not: null, note: "optional" as const, approvers: 1, note_hint: null };
    serve(caseDetail({ closure_choices: [...CHOICES, stopped], known: knownOut() }, { state: "open", notified_at: "2026-10-20T04:00:00Z" }));
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    await user.click(await within(await screen.findByRole("region", { name: "Actions" })).findByRole("button", { name: "Request closure" }));
    const radio = await screen.findByRole("radio", { name: /Stopped after the owner was told/ });
    expect((radio as HTMLInputElement).disabled).toBe(false);
    expect(screen.getByText(/nothing matching has been seen for 14 days/)).toBeTruthy();
  });

  it("says why it is not available for a case whose owner was not told", async () => {
    const user = userEvent.setup();
    const stopped = { reason: "stopped_after_notice" as const, label: "Stopped after the owner was told", meaning: "m", enabled: false, why_not: "Only a case whose owner was told can be closed as stopped after notice.", note: "optional" as const, approvers: 1, note_hint: null };
    serve(caseDetail({ closure_choices: [...CHOICES, stopped] }, { state: "open" }));
    renderApp(`/incidents/${CASE_ID}?tab=activity`);
    await user.click(await within(await screen.findByRole("region", { name: "Actions" })).findByRole("button", { name: "Request closure" }));
    const radio = await screen.findByRole("radio", { name: /Stopped after the owner was told/ });
    expect((radio as HTMLInputElement).disabled).toBe(true);
    expect(screen.getByText(/Only a case whose owner was told can be closed as stopped after notice\./)).toBeTruthy();
  });

  it("is said in words wherever a closed case is listed", async () => {
    server.use(
      http.get(`${BASE}/api/v1/cases`, () =>
        HttpResponse.json({
          items: [{ ...caseDetail().case, state: "closed", closure_reason: "stopped_after_notice", notified_at: null }],
          view: "closed", offset: 0, limit: 100, has_more: false,
          counts: { active: 0, notified: 0, attention: 0, mine: 0, suspected: 0, closed: 1, all: 1 },
        }),
      ),
    );
    renderApp("/cases?view=closed");
    expect(await screen.findByText(/Closed: Stopped after the owner was told/)).toBeTruthy();
  });
});

describe("the cases list", () => {
  it("has the notified cases as a view, each saying when the owner was told and whether it is blocked", async () => {
    server.use(
      http.get(`${BASE}/api/v1/cases`, ({ request }) =>
        HttpResponse.json({
          items: [{ ...caseDetail().case, notified_at: "2026-10-20T04:00:00Z", blocked_at: "2026-10-24T04:00:00Z" }],
          view: new URL(request.url).searchParams.get("view"), offset: 0, limit: 100, has_more: false,
          counts: { active: 3, notified: 1, attention: 1, mine: 0, suspected: 0, closed: 0, all: 4 },
        }),
      ),
    );
    renderApp("/cases?view=notified");
    await screen.findAllByTestId("incident-row");
    expect(screen.getByText((_, el) => el?.tagName === "SPAN" && el.textContent === "Owner told 20 Oct, blocked at the network")).toBeTruthy();
    const nav = screen.getByRole("navigation", { name: "Views" });
    expect(within(nav).getByRole("link", { name: /^Owner told/ }).getAttribute("aria-current")).toBe("page");
    expect(sent("GET", "/api/v1/cases")[0]?.path).toContain("view=notified");
  });
});

