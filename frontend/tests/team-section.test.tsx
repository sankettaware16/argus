// AR8 on the case page (D-195): the Kibana case preview. What ARGUS would write to the incident
// case, step by step, each by its own Kibana user, each comment in full; that posting is off (a dry
// run); what stops a post; and the approval the first cases need (the exact request is shown first).
// Text from logs and alerts is shown as text, never as markup.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse, type HttpHandler } from "msw";
import { describe, expect, it } from "vitest";
import { caseDetail, CASE_ID, LEAD_ID } from "./caseFixtures";
import { BASE, detail as investigationDetail, mockApi, noReportOut, REPORT, renderApp, sent, server } from "./helpers";
import { noTeamOut, PLAN_HASH, STEPS, step, teamOut, WAITING } from "./teamFixtures";
import type { CaseTeamOut } from "../src/client/types.gen";
import { approveBody, AUTHOR_ROLE, decisionTitle, shortAuthor } from "../src/lib/team";

mockApi();
const URL_OF = `${BASE}/api/v1/cases/${CASE_ID}`;

function serve(out: CaseTeamOut | (() => CaseTeamOut) = teamOut(CASE_ID), more: HttpHandler[] = []) {
  server.use(
    ...more,
    http.get(`${URL_OF}/team`, () => HttpResponse.json(typeof out === "function" ? out() : out)),
    http.get(`${URL_OF}/report`, () => HttpResponse.json(noReportOut(CASE_ID))),
    http.get(URL_OF, () => HttpResponse.json(caseDetail())),
    http.get(`${BASE}/api/v1/investigations/${LEAD_ID}/reports`, () => HttpResponse.json({ items: [REPORT], logs_hidden: false })),
    http.get(`${BASE}/api/v1/investigations/${LEAD_ID}`, () => HttpResponse.json(investigationDetail({}, { id: LEAD_ID }))),
  );
}

const section = async () => within(await screen.findByRole("region", { name: "Kibana case preview" }));

describe("the pure rules", () => {
  it("names the decision in a few words", () => {
    const base = teamOut(CASE_ID).decision;
    expect(decisionTitle({ ...base, dry_run: true }).words).toBe("Posting is off: a dry run");
    expect(decisionTitle({ ...base, dry_run: false, action: "open" })).toEqual({ words: "Ready to open the case", tone: "ok" });
    expect(decisionTitle({ ...base, dry_run: false, action: "update" }).words).toBe("Ready to post an update");
    expect(decisionTitle({ ...base, dry_run: false, action: "resume" }).words).toBe("A started post is being finished");
    expect(decisionTitle({ ...base, dry_run: false, action: "none" })).toEqual({ words: "Not posted yet", tone: "neutral" });
  });

  it("sends exactly the hash the person read, and names the seven users", () => {
    expect(approveBody(PLAN_HASH)).toEqual({ plan_hash: PLAN_HASH });
    expect(shortAuthor("argus-reporter")).toBe("reporter");
    expect(Object.keys(AUTHOR_ROLE)).toEqual(["argus-lead", "argus-evidence", "argus-intel", "argus-responder", "argus-hunter", "argus-reporter", "argus-visualiser"]);
  });
});

describe("the preview", () => {
  it("says that posting is off, why the case would qualify, and lists the steps in order by author", async () => {
    serve();
    renderApp(`/cases/${CASE_ID}`);
    const s = await section();
    const decision = await s.findByTestId("team-decision");
    expect(decision.textContent).toContain("Posting is off: a dry run");
    expect(decision.textContent).toContain("ACME-IR-2026-1026-01");
    expect(decision.textContent).toContain("from report version 2");
    expect(decision.textContent).toContain("Why it qualifies: ARGUS's verdict is a true positive (0.80).");
    expect(s.getByText(/Posting is switched off \(case_team\.post\)/)).toBeTruthy();
    const steps = s.getAllByTestId("team-step");
    expect(steps).toHaveLength(6);
    expect(steps.map((li) => within(li).getByText(/^argus-/).textContent)).toEqual(["argus-lead", "argus-lead", "argus-evidence", "argus-hunter", "argus-reporter", "argus-lead"]);
    expect(steps[0]?.textContent).toContain("opens the case");
    expect(steps[5]?.textContent).toContain("comments (verdict)");
    expect(s.getByText(/6 steps by lead, evidence, hunter, reporter, in this order; the lead's verdict is last\./)).toBeTruthy();
    expect(s.queryByTestId("team-approval")).toBeNull(); // no approval is asked while none is needed
  });

  it("opens a step to its comment word for word and its exact request", async () => {
    const user = userEvent.setup();
    serve();
    renderApp(`/cases/${CASE_ID}`);
    const s = await section();
    const evidence = (await s.findAllByTestId("team-step"))[2] as HTMLElement;
    await user.click(within(evidence).getByText(/comments \(evidence\)/));
    expect(within(evidence).getByTestId("team-text").textContent).toContain("## Evidence");
    expect(within(evidence).getByTestId("team-text").textContent).toContain("**E1 · The alerts of the case**");
    expect(within(evidence).getByTestId("team-request").textContent).toBe("POST /s/acme-soc/api/cases/NEWCASE/comments (application/json)");
    const file = (await s.findAllByTestId("team-step"))[4] as HTMLElement;
    await user.click(within(file).getByText(/uploads ACME/));
    expect(within(file).getByTestId("team-request").textContent).toContain("multipart/form-data");
    expect(file.textContent).toContain("sha-256 368ec2edfadbda48"); // a file is its name, size and hash, never its bytes
    expect(within(file).queryByTestId("team-text")).toBeNull();
  });

  it("shows hostile text as text: no element, no link, nothing that acts", async () => {
    const user = userEvent.setup();
    const hostile = '<img src=x onerror="document.title=1"> [x](javascript:alert(1)) <script>window.pwned=1</script> @everyone';
    serve(teamOut(CASE_ID, { steps: [step(1, "comment:evidence:1", "argus-evidence", "comment", "comments (evidence)", hostile)] }));
    renderApp(`/cases/${CASE_ID}`);
    const s = await section();
    await user.click(await s.findByText(/comments \(evidence\)/));
    const text = s.getByTestId("team-text");
    expect(text.textContent).toContain("<script>window.pwned=1</script>");
    expect(text.querySelector("img, script, a")).toBeNull();
    expect((window as unknown as { pwned?: number }).pwned).toBeUndefined();
    expect(document.title).not.toBe("1");
  });

  it("says that an account without log access sees the words hidden", async () => {
    serve(teamOut(CASE_ID, { logs_hidden: true, steps: STEPS.map((x) => ({ ...x, text: x.text === null ? null : "Hidden: needs log access in ELK.", request: null })) }));
    renderApp(`/cases/${CASE_ID}`);
    const s = await section();
    expect(await s.findByText(/may not read the logs, so the words of each comment/)).toBeTruthy();
    expect(s.getAllByTestId("team-step")).toHaveLength(6);
    expect(s.queryByTestId("team-request")).toBeNull();
    expect(s.getAllByText("The request says what the logs said: it needs log access in ELK.").length).toBeGreaterThan(0);
  });

  it("lists what stops a post, as text", async () => {
    serve(teamOut(CASE_ID, { problems: ["no key is installed for argus-intel", "the guardian refuses comment:evidence:1: a raw '<' (HTML)"] }));
    renderApp(`/cases/${CASE_ID}`);
    const s = await section();
    const list = await s.findByTestId("team-problems");
    expect(within(list).getAllByRole("listitem")).toHaveLength(2);
    expect(list.textContent).toContain("no key is installed for argus-intel");
  });

  it("says when there is nothing to write, and when there is no report yet", async () => {
    serve(noTeamOut(CASE_ID));
    renderApp(`/cases/${CASE_ID}`);
    const s = await section();
    expect((await s.findByTestId("team-nothing")).textContent).toContain("nothing to write to Kibana yet");
    expect(s.getByTestId("team-decision").textContent).toContain("ARGUS has not written this case's report yet");
    expect(s.queryByTestId("team-steps")).toBeNull();
  });

  it("shows where a post stands once it exists", async () => {
    serve(
      teamOut(CASE_ID, {
        decision: { action: "update", would: "none", why: "report version 3 is new", route: null, dry_run: false, needs_approval: false },
        post: { incident_id: "ACME-IR-2026-1026-01", kibana_case_id: "abc", state: "held", held_reason: "a Kibana case already carries ACME-IR-2026-1026-01 (made by elastic)", opened_at: "2026-10-29T08:00:00Z", last_version: 2, steps: { verified: 12, planned: 3 } },
        steps: [],
      }),
    );
    renderApp(`/cases/${CASE_ID}`);
    const s = await section();
    const post = await s.findByTestId("team-post");
    expect(post.textContent).toContain("Held");
    expect(post.textContent).toContain("12 in Kibana, 3 waiting");
    expect(post.textContent).toContain("report version 2 posted");
    expect(post.textContent).toContain("made by elastic");
    expect(s.getByTestId("team-decision").textContent).toContain("Ready to post an update");
    expect(s.getByTestId("team-nothing").textContent).toContain("Nothing new to add");
  });

  it("says why when the preview cannot be read, and reads it again on request", async () => {
    const user = userEvent.setup();
    let calls = 0;
    server.use(
      http.get(`${URL_OF}/team`, () => {
        calls += 1;
        return calls === 1 ? HttpResponse.json({ detail: "unavailable", code: "unavailable" }, { status: 503 }) : HttpResponse.json(teamOut(CASE_ID));
      }),
      http.get(`${URL_OF}/report`, () => HttpResponse.json(noReportOut(CASE_ID))),
      http.get(URL_OF, () => HttpResponse.json(caseDetail())),
      http.get(`${BASE}/api/v1/investigations/${LEAD_ID}/reports`, () => HttpResponse.json({ items: [REPORT], logs_hidden: false })),
      http.get(`${BASE}/api/v1/investigations/${LEAD_ID}`, () => HttpResponse.json(investigationDetail({}, { id: LEAD_ID }))),
    );
    renderApp(`/cases/${CASE_ID}`);
    const s = await section();
    await user.click(await s.findByRole("button", { name: /try again|retry/i }));
    expect((await s.findByTestId("team-decision")).textContent).toContain("Posting is off");
  });
});

describe("the approval of the first cases", () => {
  const canary = (more: Record<string, unknown> = {}) => teamOut(CASE_ID, { post_enabled: true, decision: { action: "none", would: "open", why: "waiting for a person's approval of this case (canary)", route: "a person confirmed the report", dry_run: false, needs_approval: true }, approval: { ...WAITING, ...more } });

  it("shows the exact request first, sends exactly the hash that was read, and reads the preview again", async () => {
    const user = userEvent.setup();
    let approved = false;
    const done = canary({ given: true, why_not: null, can_approve: false, approve_why_not: "this plan is already approved" });
    serve(() => (approved ? done : canary()), [
      http.post(`${URL_OF}/team/approve`, () => {
        approved = true;
        return HttpResponse.json({ approval_id: 5, plan_hash: PLAN_HASH, expires_at: "2026-10-30T17:30:00Z", words: "Approved. ARGUS writes this case to Kibana at its next posting run, inside the write window; the approval covers exactly the plan you read." });
      }),
    ]);
    renderApp(`/cases/${CASE_ID}`);
    const s = await section();
    const box = await s.findByTestId("team-approval");
    expect(box.textContent).toContain("The first cases need a person's approval");
    expect(box.textContent).toContain("no person has approved this plan yet");
    await user.click(within(box).getByRole("button", { name: "Approve these steps" }));
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog.textContent).toContain(`POST/api/v1/cases/${CASE_ID}/team/approve`);
    expect(JSON.parse(within(dialog).getByTestId("payload").textContent ?? "null")).toEqual({ plan_hash: PLAN_HASH });
    expect(sent("POST", "/api")).toHaveLength(0); // looking sent nothing
    await user.click(within(dialog).getByRole("button", { name: "Approve these steps" }));
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());
    expect(JSON.parse(sent("POST", "/api")[0]?.body ?? "")).toEqual({ plan_hash: PLAN_HASH });
    expect(await s.findByTestId("team-approved")).toBeTruthy();
    expect(s.queryByRole("button", { name: "Approve these steps" })).toBeNull();
  });

  it("does not offer the approval to an account that may not give it, and says why", async () => {
    const user = userEvent.setup();
    serve(canary({ can_approve: false, approve_why_not: "your account may not approve (it needs the approve capability)" }));
    renderApp(`/cases/${CASE_ID}`);
    const s = await section();
    const button = await s.findByRole("button", { name: "Approve these steps" });
    expect(button.getAttribute("aria-disabled")).toBe("true");
    expect(s.getAllByText(/needs the approve capability/).length).toBeGreaterThan(0);
    await user.click(button);
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(sent("POST", "/api")).toHaveLength(0);
  });

  it("sends a person who has not typed their password again to do so, and back to the case", async () => {
    serve(canary({ can_approve: false, approve_why_not: "confirm your password again first (a step-up within five minutes)", needs_step_up: true, step_up_url: `/stepup?next=/app/cases/${CASE_ID}` }));
    renderApp(`/cases/${CASE_ID}`);
    const s = await section();
    const link = await s.findByRole("link", { name: "Confirm it is you" });
    expect(link.getAttribute("href")).toBe(`/stepup?next=/app/cases/${CASE_ID}`);
    expect(s.getByRole("button", { name: "Approve these steps" }).getAttribute("aria-disabled")).toBe("true");
    expect(s.getAllByText(/confirm your password again first/).length).toBeGreaterThan(0);
  });

  it("keeps the dialog open and says so when the plan changed (409), sending nothing more", async () => {
    const user = userEvent.setup();
    serve(canary(), [http.post(`${URL_OF}/team/approve`, () => HttpResponse.json({ detail: "The plan changed while you read it. Read it again before you approve.", code: "conflict" }, { status: 409 }))]);
    renderApp(`/cases/${CASE_ID}`);
    const s = await section();
    await user.click(await s.findByRole("button", { name: "Approve these steps" }));
    const dialog = await screen.findByRole("alertdialog");
    await user.click(within(dialog).getByRole("button", { name: "Approve these steps" }));
    expect(await within(dialog).findByText(/plan changed while you read it/i)).toBeTruthy();
    expect(screen.getByRole("alertdialog")).toBeTruthy();
    expect(sent("POST", "/api")).toHaveLength(1);
  });

  it("asks for nothing when no approval is needed", async () => {
    serve(teamOut(CASE_ID, { post_enabled: true, decision: { action: "open", would: "none", why: "ready to open", route: "a person confirmed the report", dry_run: false, needs_approval: false } }));
    renderApp(`/cases/${CASE_ID}`);
    const s = await section();
    expect((await s.findByTestId("team-decision")).textContent).toContain("Ready to open the case");
    expect(s.queryByTestId("team-approval")).toBeNull();
  });
});
