// AR7 on the case page (D-190): the incident report as ARGUS wrote it. The summary and the verdict
// first, then your decision (Confirm, or Reject with a reason: both are labels and neither closes
// anything), then each part; every evidence line has its exact query and a read-only Discover link;
// an account without log access sees what the logs said hidden; hostile text and links are inert.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import { caseDetail, CASE_ID, LEAD_ID } from "./caseFixtures";
import { BASE, detail as investigationDetail, mockApi, must, noReportOut, REPORT, renderApp, sent, server } from "./helpers";
import { query, reportOut } from "./incidentFixtures";
import { confirmBody, dayLabel, reasonProblem, rejectBody, rejectProblem, safeLink } from "../src/lib/incident";

// built in two pieces: the lint rule that keeps script links out of the app's own code is right to see them
const SCRIPT_URL = ["java", "script:alert(1)"].join("");
mockApi();
const URL_OF = `${BASE}/api/v1/cases/${CASE_ID}`;

function serve(out = reportOut(), more: ReturnType<typeof http.get>[] = []) {
  server.use(
    ...more,
    http.get(`${URL_OF}/report`, () => HttpResponse.json(out)),
    http.get(URL_OF, () => HttpResponse.json(caseDetail())),
    http.get(`${BASE}/api/v1/investigations/${LEAD_ID}/reports`, () => HttpResponse.json({ items: [REPORT], logs_hidden: false })),
    http.get(`${BASE}/api/v1/investigations/${LEAD_ID}`, () => HttpResponse.json(investigationDetail({}, { id: LEAD_ID }))),
  );
}

const section = async () => within(await screen.findByRole("region", { name: "Report" }));
const decided = (more: Record<string, unknown> = {}) =>
  HttpResponse.json({ decision: { id: 1, decision: "confirmed", outcome: "true_positive", reason: null, by: "Asha", decided_at: "2026-10-29T08:00:00Z", labelled: 5 }, labelled: 5, already: 0, kept: 0, conflicts: 0, gold_saved: 0, left: 0, words: 'Confirmed: 5 investigation(s) labelled "Real: act on it". Nothing was closed.', ...more });
const shownBody = (dialog: HTMLElement) => JSON.parse(within(dialog).getByTestId("payload").textContent ?? "null") as Record<string, unknown>;

describe("the pure rules", () => {
  it("asks for a reason of a few words and an outcome", () => {
    expect(reasonProblem("")).toMatch(/Say why/);
    expect(reasonProblem("  ab ")).toMatch(/few more words/);
    expect(reasonProblem("It is the backup tool.")).toBeNull();
    expect(reasonProblem("x".repeat(4001))).toMatch(/at most 4000/);
    expect(rejectProblem("", "It is the backup tool.")).toMatch(/Choose the outcome/);
    expect(rejectProblem("benign_expected", "It is the backup tool.")).toBeNull();
    expect(rejectBody(2, "benign_expected", "  because it is  ")).toEqual({ expected_version: 2, outcome: "benign_expected", reason: "because it is" });
    expect(confirmBody(7)).toEqual({ expected_version: 7 });
  });

  it("follows only http and https links", () => {
    expect(safeLink("https://kibana.example/s/x/app/discover#/?_g=(a:1)")).toContain("https://kibana.example");
    expect(safeLink(SCRIPT_URL)).toBeNull();
    expect(safeLink("data:text/html,<script>1</script>")).toBeNull();
    expect(safeLink("not a url")).toBeNull();
  });

  it("writes an IST day", () => {
    expect(dayLabel("2026-10-15")).toBe("Thu 15 Oct");
    expect(dayLabel("nonsense")).toBe("nonsense");
  });
});

describe("reading the report", () => {
  it("says there is none yet, in plain words", async () => {
    serve(noReportOut(CASE_ID));
    renderApp(`/incidents/${CASE_ID}?tab=report`);
    const s = await section();
    expect((await s.findByTestId("no-report")).textContent).toContain("next assessment pass");
    expect(s.queryByRole("group", { name: "Your decision" })).toBeNull();
  });

  it("puts the summary and the verdict first, then the decision, then every part", async () => {
    serve();
    renderApp(`/incidents/${CASE_ID}?tab=report`);
    const s = await section();
    expect((await s.findByTestId("incident-id")).textContent).toBe("ACME-IR-2026-1026-01");
    // the state and ARGUS's call apart (P4-F U3); the case's title is the page's own heading
    expect(s.getByTestId("report-headline").textContent).toBe("Open · ARGUS's call: Real: act on it (80% (medium-high))");
    expect(within(s.getByRole("group", { name: "Report summary" })).getByText(/1 campus device contacted 4 servers/)).toBeTruthy();
    expect(s.getByTestId("verdict-line").textContent).toContain("Real: act on it");
    expect(s.getByTestId("verdict-line").textContent).toContain("confidence 80% (medium-high)");
    const order = Array.from(document.querySelectorAll('#report [role="group"], #report details summary')).map((e) => (e.getAttribute("aria-label") ?? e.textContent ?? "").trim());
    expect(order).toEqual(["Report summary", "ARGUS's call", "Your decision", "Timeline", "Actors and roles", "Affected assets", "Evidence", "Hypotheses", "Indicators", "Recommended actions", "Queries to verify", "Scope and limits"]);
  });

  it("is the Report tab, and after the summary on the one-page view", async () => {
    serve();
    renderApp(`/incidents/${CASE_ID}?tab=report`);
    await section();
    expect(screen.getByRole("tab", { name: "Report" }).getAttribute("aria-selected")).toBe("true");
    renderApp(`/incidents/${CASE_ID}?tab=all`);
    const all = await screen.findByTestId("everything");
    await waitFor(() => expect(within(all).getAllByRole("heading", { level: 2 }).map((h) => h.textContent).slice(0, 2)).toEqual(["Summary", "Report"]));
  });

  it("gives each evidence line its exact query and a read-only Discover link that opens in a new tab", async () => {
    serve();
    renderApp(`/incidents/${CASE_ID}?tab=report`);
    const s = await section();
    const lines = await s.findAllByTestId("evidence-line");
    expect(lines).toHaveLength(2);
    for (const line of lines) {
      const link = within(line).getByRole("link", { name: /Open this query in Kibana Discover/ });
      expect(link.getAttribute("href")).toMatch(/^https:\/\/kibana\.example\/s\/acme-soc\/app\/discover#\//);
      expect(link.getAttribute("target")).toBe("_blank");
      expect(link.getAttribute("rel")).toBe("noopener noreferrer");
    }
    expect(within(lines[1] as HTMLElement).getByText(/FROM acme-logs-squid-\* \| WHERE source\.ip == "10\.201\.7\.11"/)).toBeTruthy();
    expect(within(lines[1] as HTMLElement).getByText(/10\.201\.7\.11 made 42 requests to 77\.221\.155\.150/)).toBeTruthy();
    expect((lines[1] as HTMLElement).textContent).toContain("ES|QL on acme-logs-squid-*");
  });

  it("shows the hypotheses with their results, the actions with their owners, and the indicators", async () => {
    serve();
    renderApp(`/incidents/${CASE_ID}?tab=report`);
    const s = await section();
    const hypotheses = await s.findAllByTestId("hypothesis");
    expect(hypotheses.map((h) => within(h).getAllByText(/Kept|Ruled out/)[0]?.textContent)).toEqual(["Kept", "Ruled out"]);
    const actions = within(s.getByRole("table", { name: "Recommended actions" }));
    expect(actions.getByText("Take the computers off the network.")).toBeTruthy();
    expect(actions.getByText("Network team")).toBeTruthy();
    expect(within(s.getByRole("table", { name: "Indicators" })).getByText("77.221.155.150")).toBeTruthy();
    expect(within(s.getByRole("table", { name: "Alerts a day by rule (IST)" })).getByText("Fri 23 Oct")).toBeTruthy();
    expect(s.getByText("Limit: 2 more checks of the case are not listed.")).toBeTruthy();
  });

  it("lists the files, the PDF only for an account that may read the logs", async () => {
    serve(reportOut({ logs_hidden: true, files: reportOut().files.map((f) => (f.kind === "pdf" ? { ...f, available: false } : f)) }));
    renderApp(`/incidents/${CASE_ID}?tab=report`);
    const files = within(await screen.findByRole("list", { name: "Files" }));
    expect(files.getByRole("link", { name: "Indicators (CSV)" }).getAttribute("href")).toBe(`/api/v1/cases/${CASE_ID}/report/files/indicators.csv`);
    expect(files.queryByRole("link", { name: /Incident report/ })).toBeNull();
    expect(files.getByText("Incident report (PDF) (needs log access)")).toBeTruthy();
    expect((await section()).getByText(/what the logs said is hidden here and in the PDF/)).toBeTruthy();
  });

  it("says the owner was notified and that a newer version is coming when the case changed", async () => {
    serve(reportOut({ stale: true }, { summary: { ...must(reportOut().report).summary, notice: { notified_at: "2026-10-27T07:30:00Z", told: ["Hostel 5 warden"], blocked_at: null, alerts_since: 6, last_alert_at: "2026-10-28T00:30:00Z", still_active: true, changes: 0, line: "The owner was told on 27 Oct 2026 (Hostel 5 warden). Since then 6 more alerts arrived: the device is still active." } } }));
    renderApp(`/incidents/${CASE_ID}?tab=report`);
    const s = await section();
    expect((await s.findByTestId("report-notice")).textContent).toContain("Hostel 5 warden");
    expect(s.getByText(/The case changed: ARGUS writes a new version/)).toBeTruthy();
  });

  it("shows the model's wording only as marked, and why it was not used when it was not", async () => {
    const base = must(reportOut().report);
    serve(reportOut({ prose_by: "fake/model-1" }, { summary: { ...base.summary, prose: [{ text: "One campus device has been in touch with four flagged servers.", cites: ["F1", "F3"], by: "model" }] } }));
    renderApp(`/incidents/${CASE_ID}?tab=report`);
    const s = await section();
    expect(await s.findByText("One campus device has been in touch with four flagged servers.")).toBeTruthy();
    expect(s.getByText("Summary worded by a model, checked by ARGUS")).toBeTruthy();
  });

  it("shows hostile text inert: markup is text, hidden characters are visible, a script link is no link", async () => {
    const base = must(reportOut().report);
    const evil = query({ url: SCRIPT_URL, text: 'FROM x | WHERE a == "<img src=x onerror=alert(1)>"' });
    serve(
      reportOut(
        {},
        {
          actors: [{ ...must(base.actors[0]), value: "10.1.1.1‮gnp.exe", user_agents: ["<script>alert(1)</script>\u0000x"] }],
          evidence: [{ ...must(base.evidence[1]), query: evil }],
        },
      ),
    );
    renderApp(`/incidents/${CASE_ID}?tab=report`);
    const s = await section();
    expect(document.querySelector("#report script, #report img")).toBeNull();
    expect(await s.findByText(/No link is available for this query/)).toBeTruthy();
    const line = within(s.getAllByTestId("evidence-line")[0] as HTMLElement);
    expect(line.getByText(/<img src=x onerror=alert\(1\)>/)).toBeTruthy();
    expect(line.queryByRole("link")).toBeNull();
    const untrusted = Array.from(document.querySelectorAll('#report [data-untrusted]')).map((n) => n.textContent ?? "");
    expect(untrusted.some((t) => t.includes("<script>alert(1)</script>"))).toBe(true);
    expect(untrusted.join("").includes("‮")).toBe(false); // the override character is shown as a marker
  });

  it("shows another version when it is chosen, and says it is an older one", async () => {
    const user = userEvent.setup();
    const old = reportOut({ version: 1, decision: { id: 1, decision: "rejected", outcome: "benign_expected", reason: "It was the backup tool.", by: "Rita", decided_at: "2026-10-28T09:00:00Z", labelled: 5 }, confirm: { enabled: false, why_not: "This is version 1; decide the newest (version 2)." }, reject: { enabled: false, why_not: "This is version 1; decide the newest (version 2)." } });
    serve(reportOut(), [http.get(`${URL_OF}/report`, ({ request }) => HttpResponse.json(new URL(request.url).searchParams.get("version") === "1" ? old : reportOut()))]);
    renderApp(`/incidents/${CASE_ID}?tab=report`);
    const s = await section();
    const versions = await s.findByTestId("report-versions");
    expect(versions.tagName).toBe("UL"); // I-19: a list, not a select
    await user.click(within(versions).getByRole("button", { name: /^v1/ }));
    expect(await s.findByText("An older version")).toBeTruthy();
    expect((await s.findByTestId("decision-line")).textContent).toContain("Rejected by Rita");
    expect(s.getByTestId("decision-line").textContent).toContain("Reason: It was the backup tool.");
    expect(s.getByText("This is version 1; decide the newest (version 2).", { selector: "p" })).toBeTruthy();
  });
});

describe("deciding", () => {
  it("says why Confirm is not possible, in the server's words, and does nothing", async () => {
    const user = userEvent.setup();
    serve(reportOut({ confirm: { enabled: false, why_not: "ARGUS has no verdict on this case to confirm (only a reading, or nothing): reject the report with the outcome you hold instead." } }));
    renderApp(`/incidents/${CASE_ID}?tab=report`);
    const s = await section();
    await user.click(await s.findByRole("button", { name: "Confirm the verdict" }));
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(s.getAllByText(/only a reading, or nothing/).length).toBeGreaterThan(0);
    expect(sent("POST", "/api")).toHaveLength(0);
  });

  it("shows the exact request, names the version, sends exactly that and says what was labelled", async () => {
    const user = userEvent.setup();
    serve(reportOut(), [http.post(`${URL_OF}/report/confirm`, () => decided())]);
    renderApp(`/incidents/${CASE_ID}?tab=report`);
    const s = await section();
    await user.click(await s.findByRole("button", { name: "Confirm the verdict" }));
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog.textContent).toContain(`POST/api/v1/cases/${CASE_ID}/report/confirm`);
    expect(shownBody(dialog)).toEqual({ expected_version: 2 });
    expect(dialog.textContent).toContain("Nothing is closed");
    await user.click(within(dialog).getByRole("button", { name: "Confirm the verdict" }));
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());
    expect(await screen.findByText(/Confirmed: 5 investigation\(s\) labelled "Real: act on it"\. Nothing was closed\./, { selector: "p" })).toBeTruthy();
    expect(JSON.parse(sent("POST", "/api")[0]?.body ?? "")).toEqual({ expected_version: 2 });
    await waitFor(() => expect(sent("GET", `${"/api/v1/cases/" + CASE_ID}/report`).length).toBeGreaterThanOrEqual(2));
  });

  it("needs an outcome and a reason before the request can be reviewed, and says what is missing", async () => {
    const user = userEvent.setup();
    serve();
    renderApp(`/incidents/${CASE_ID}?tab=report`);
    const s = await section();
    await user.click(await s.findByRole("button", { name: "Reject with a reason…" }));
    expect(s.getByRole("option", { name: "Real but harmless" })).toBeTruthy();
    await user.click(s.getByRole("button", { name: "Review the request" }));
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(await s.findByText("Choose the outcome you hold instead.")).toBeTruthy();
    await user.selectOptions(s.getByLabelText("What it is instead"), "benign_expected");
    await user.click(s.getByRole("button", { name: "Review the request" }));
    expect(await s.findAllByText(/Say why the report is wrong/)).not.toHaveLength(0);
    expect(sent("POST", "/api")).toHaveLength(0);
  });

  it("rejects with an outcome and a reason: shows them in the request, sends exactly that, records it", async () => {
    const user = userEvent.setup();
    serve(reportOut(), [http.post(`${URL_OF}/report/reject`, () => decided({ decision: { id: 2, decision: "rejected", outcome: "benign_expected", reason: "It is the department's backup tool.", by: "Asha", decided_at: "2026-10-29T08:00:00Z", labelled: 5 }, words: 'Rejected: 5 investigation(s) labelled "Real but harmless". Nothing was closed.' }))]);
    renderApp(`/incidents/${CASE_ID}?tab=report`);
    const s = await section();
    await user.click(await s.findByRole("button", { name: "Reject with a reason…" }));
    expect(within(s.getByLabelText("What it is instead")).queryByRole("option", { name: "Real: act on it" })).toBeNull(); // the report's own verdict is no alternative
    await user.selectOptions(s.getByLabelText("What it is instead"), "benign_expected");
    await user.type(s.getByLabelText(/^Why the report is wrong/), "It is the department's backup tool.");
    await user.click(s.getByRole("button", { name: "Review the request" }));
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog.textContent).toContain(`POST/api/v1/cases/${CASE_ID}/report/reject`);
    expect(shownBody(dialog)).toEqual({ expected_version: 2, outcome: "benign_expected", reason: "It is the department's backup tool." });
    await user.click(within(dialog).getByRole("button", { name: "Reject with this reason" }));
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());
    expect(await screen.findByText(/Rejected: 5 investigation\(s\) labelled "Real but harmless"/, { selector: "p" })).toBeTruthy();
    expect(JSON.parse(sent("POST", "/api")[0]?.body ?? "")).toEqual({ expected_version: 2, outcome: "benign_expected", reason: "It is the department's backup tool." });
  });

  it("keeps what was typed and says nothing was saved when the report moved on (409)", async () => {
    const user = userEvent.setup();
    serve(reportOut(), [http.post(`${URL_OF}/report/reject`, () => HttpResponse.json({ detail: "The report changed while you read it (it is now version 3): nothing was saved. Read it again.", code: "conflict" }, { status: 409 }))]);
    renderApp(`/incidents/${CASE_ID}?tab=report`);
    const s = await section();
    await user.click(await s.findByRole("button", { name: "Reject with a reason…" }));
    await user.selectOptions(s.getByLabelText("What it is instead"), "inconclusive");
    await user.type(s.getByLabelText(/^Why the report is wrong/), "Not enough to say.");
    await user.click(s.getByRole("button", { name: "Review the request" }));
    const dialog = await screen.findByRole("alertdialog");
    await user.click(within(dialog).getByRole("button", { name: "Reject with this reason" }));
    expect(await within(dialog).findByText(/nothing was saved/i)).toBeTruthy();
    expect(screen.getByRole("alertdialog")).toBeTruthy(); // still open: nothing was lost
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect((s.getByLabelText(/^Why the report is wrong/) as HTMLTextAreaElement).value).toBe("Not enough to say.");
  });

  it("does not offer a decision to an account that may only view (the server's reason is shown)", async () => {
    serve(reportOut({ confirm: { enabled: false, why_not: "Your account may view reports, not decide them (it needs the review capability)." }, reject: { enabled: false, why_not: "Your account may view reports, not decide them (it needs the review capability)." } }));
    renderApp(`/incidents/${CASE_ID}?tab=report`);
    const s = await section();
    expect((await s.findAllByText(/needs the review capability/)).length).toBeGreaterThan(0);
    expect(s.getByRole("button", { name: "Reject with a reason…" }).getAttribute("aria-disabled")).toBe("true");
  });

  it("shows a decision already made, with who, when and why", async () => {
    serve(reportOut({ decision: { id: 3, decision: "rejected", outcome: "benign_policy", reason: "Allowed by the lab policy.", by: "Rita Reviewer", decided_at: "2026-10-29T09:00:00Z", labelled: 4 } }));
    renderApp(`/incidents/${CASE_ID}?tab=report`);
    const s = await section();
    const line = (await s.findByTestId("decision-line")).textContent ?? "";
    expect(line).toContain("Rejected by Rita Reviewer");
    expect(line).toContain("as “Allowed by policy”");
    expect(line).toContain("4 investigations labelled");
    expect(line).toContain("Reason: Allowed by the lab policy.");
    expect(line).not.toContain("Made on version");
  });

  it("keeps a confirm made on an earlier version that differs only in the case's name (naming v2)", async () => {
    serve(reportOut({ decision: { id: 4, decision: "confirmed", outcome: "true_positive", reason: null, by: "Asha", decided_at: "2026-10-29T09:00:00Z", labelled: 4, held_from: 1 } }));
    renderApp(`/incidents/${CASE_ID}?tab=report`);
    const s = await section();
    const line = (await s.findByTestId("decision-line")).textContent ?? "";
    expect(line).toContain("Confirmed by Asha");
    expect(line).toContain("Made on version 1; it still holds: since then only the case's name or the sign-in accounts changed.");
  });
});
