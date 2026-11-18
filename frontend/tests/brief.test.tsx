// The analyst brief (D-332) on the Report tab: a model's words over the report's facts, labelled
// as such, with the steps asked for and the facts they rest on; no brief, no block.
import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { IncidentReport, ReportBrief } from "../src/client/types.gen";
import { BriefBlock, briefOf, statementOf } from "../src/components/incident/Brief";
import { reportOut } from "./incidentFixtures";

const line = (text: string) => ({ text, cites: ["F1"] });
const BRIEF: ReportBrief = {
  statement: [line("A laptop keeps sending its browser's cookies to 203.0.113.40."), line("It is still going on.")],
  points: [line("It started on 31 Oct."), line("One account is behind most addresses.")],
  why: [line("The paths name cookies and history.")],
  impact: [],
  actions: [
    { ...line("Block 203.0.113.40 at the proxy."), who: "network", when: "now" },
    { ...line("Change the password from a clean device."), who: "accounts", when: "after" },
  ],
  facts: { F1: "The proxy logged 40 requests.", F2: "VirusTotal flags it." },
  facts_sha: "0".repeat(64),
  by: "anthropic/claude-opus-5-5",
  at: "2026-10-29T07:30:00Z",
  basis: "true_positive|ongoing|open",
  dropped: 0,
};
const report = (more: Partial<IncidentReport>): IncidentReport => reportOut({}, more).report as IncidentReport;

describe("the analyst brief", () => {
  it("shows what is happening, each part that has lines, the steps with who and when, and who wrote it", () => {
    render(<BriefBlock report={report({ brief: BRIEF })} />);
    const block = screen.getByTestId("brief");
    expect(screen.getByTestId("brief-statement").textContent).toBe("A laptop keeps sending its browser's cookies to 203.0.113.40. It is still going on.");
    expect(within(block).getAllByRole("heading").map((h) => h.textContent)).toEqual(["Summary", "Why it is judged real", "Actions asked for"]);
    const steps = within(screen.getByTestId("brief-actions")).getAllByRole("listitem");
    expect(steps.map((s) => s.textContent)).toEqual(["Block 203.0.113.40 at the proxy. (Network team · Immediately)", "Change the password from a clean device. (Account holders · After the device is clean)"]);
    expect(screen.getByTestId("brief-by").textContent).toContain("Written by ARGUS's AI (anthropic/claude-opus-5-5)");
    expect(screen.getByTestId("brief-by").textContent).toContain("It may still be wrong");
    expect(within(block).getByText("The 2 facts it rests on")).toBeTruthy();
    expect(within(block).getByText("VirusTotal flags it.")).toBeTruthy();
  });

  it("without a brief shows why not, or nothing", () => {
    const { container, rerender } = render(<BriefBlock report={report({ brief: null, brief_note: "no model answered (Refused)" })} />);
    expect(screen.queryByTestId("brief")).toBeNull();
    expect(screen.getByTestId("brief-note").textContent).toBe("No analyst brief: no model answered (Refused)");
    rerender(<BriefBlock report={report({ brief: null, brief_note: null })} />);
    expect(container.textContent).toBe("");
  });

  it("reads the brief of a report, and of none", () => {
    expect(briefOf(null)).toBeNull();
    expect(briefOf(report({ brief: null }))).toBeNull();
    expect(statementOf(briefOf(report({ brief: BRIEF })) as ReportBrief)).toBe("A laptop keeps sending its browser's cookies to 203.0.113.40. It is still going on.");
  });
});
