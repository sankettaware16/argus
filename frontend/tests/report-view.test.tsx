// report@2 in the app: the verdict and evidence strength, the box of what the extra SIEM queries
// found, and every part of the report, shown as text.
import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { Report } from "../src/client/types.gen";
import { FoundBox } from "../src/components/investigation/FoundBox";
import { ReportView } from "../src/components/investigation/ReportView";
import { must, REPORT } from "./helpers";

describe("What ARGUS found with extra SIEM queries", () => {
  it("says each finding once, leaves out those shown above as key facts, and says when it reused an earlier check (P4-F U18)", () => {
    const found = { ...REPORT.found, checks: 0, server_ms: 0, items: [...REPORT.found.items, REPORT.found.items[0] as (typeof REPORT.found.items)[number]] };
    render(<FoundBox report={{ ...REPORT, found }} shown={["Two more campus hosts reached the same C2 today."]} />);
    const box = screen.getByRole("region", { name: "What ARGUS found with extra SIEM queries" });
    expect(within(box).getByTestId("found-heading").textContent).toBe("Reused from an earlier check: this version made no new SIEM query. Compared with what the alerts alone say.");
    expect(within(box).getByTestId("found-above").textContent).toBe("One finding is under Key facts above.");
    const texts = [...(box.querySelector("ul")?.children ?? [])].map((li) => li.textContent ?? "");
    expect(texts.filter((t) => t.includes("Host H1 reached the C2 every 300 s"))).toHaveLength(1);
    expect(texts.some((t) => t.includes("Two more campus hosts"))).toBe(false);
  });

  it("never says reused when no earlier answer was reused: checks skipped for load or deferred are not checked", () => {
    const skipped = { kind: "not_checked" as const, sentence: "Whether H1 reached other C2s: skipped, the SIEM is under load.", eids: ["E3"], from_logs: false };
    render(<FoundBox report={{ ...REPORT, found: { ...REPORT.found, checks: 0, server_ms: 0, items: [skipped] }, cost: { ...REPORT.cost, siem_requests: 0, siem_server_ms: 0, reused: 0 } }} />);
    const heading = screen.getByTestId("found-heading").textContent ?? "";
    expect(heading).not.toContain("Reused");
    expect(heading).toBe("0 checks, 0 ms of SIEM server time. Compared with what the alerts alone say.");
  });

  it("heads the box with its checks and server time, and starts every line with its words and E-numbers", () => {
    render(<FoundBox report={REPORT} />);
    const box = screen.getByRole("region", { name: "What ARGUS found with extra SIEM queries" });
    expect(within(box).getByText("3 checks, 2.1 s of SIEM server time. Compared with what the alerts alone say.")).toBeTruthy();
    const lines = [...(box.querySelector("ul")?.children ?? [])];
    expect(lines.map((li) => li.textContent?.replace(/\s+/g, " ").trim())).toEqual([
      "FoundHost H1 reached the C2 every 300 s, 59 times. E3destination: 203.0.113.9 (59)E3 · proxy.pair@1 · complete",
      "FoundTwo more campus hosts reached the same C2 today. E4",
      "Nothing foundNo other destination of H1 is on a threat list. E5",
      "Could not tellWhether H1 looked the C2 up by name; DNS logs were 40 minutes behind. E6",
      "Still openWho looks after H1.",
    ]);
  });

  it("says when no SIEM query was made", () => {
    render(<FoundBox report={{ ...REPORT, found: { ...REPORT.found, checks: 0, server_ms: 0, items: [] } }} />);
    expect(screen.getByText("No SIEM query was made for this investigation version.")).toBeTruthy();
  });

  it("shows hidden results as hidden, in words", () => {
    render(<FoundBox report={{ ...REPORT, found: { ...REPORT.found, items: [{ kind: "hidden", sentence: "Hidden: needs log access in ELK.", eids: ["E3"], from_logs: true }] } }} />);
    expect(screen.getByText("Hidden", { selector: "span" })).toBeTruthy();
    expect(screen.getByText("Hidden: needs log access in ELK.")).toBeTruthy();
  });
});

describe("the report", () => {
  it("has the verdict with its confidence and the evidence strength apart from it", () => {
    render(<ReportView reports={[REPORT]} />);
    const verdict = screen.getByRole("region", { name: "Verdict" });
    expect(verdict.textContent).toContain("The AI investigator proposes Real: act on it (the model's confidence 75%)");
    expect(verdict.textContent).toContain("It beacons.");
    expect(verdict.textContent).toContain("Evidence strength: Moderate.");
    expect(verdict.textContent).toContain("separate from any confidence");
    expect(within(verdict).getByRole("list", { name: "What the strength counts" }).textContent).toContain("Facts that decide a benign proposal: 2 of 3");
  });

  it("has the timeline, the evidence table, hypotheses, unknowns, actions, cost and sources", () => {
    render(<ReportView reports={[REPORT]} />);
    expect(within(screen.getByRole("region", { name: "Timeline" })).getByText("H1 reached the C2.")).toBeTruthy();
    const evidence = screen.getByRole("table", { name: /Evidence: each known fact/ });
    expect(within(evidence).getAllByRole("row").slice(1).map((r) => [...r.querySelectorAll("td")].map((c) => c.textContent))).toEqual([
      ["Supports", "Contacts at a fixed interval.", "E3"],
      ["Neutral", "2 alerts.", "the alerts"],
    ]);
    expect(within(screen.getByRole("table", { name: /Hypotheses/ })).getByText("C2 beaconing")).toBeTruthy();
    const unknowns = screen.getByRole("region", { name: "Checked and unknown" });
    expect(unknowns.textContent).toContain("Blocks a benign proposal");
    expect(unknowns.textContent).toContain("Who can resolve it: the asset owner.");
    expect(screen.getByRole("region", { name: "Actions" }).textContent).toContain("Who: a reviewer. Why: it is still active.");
    expect(screen.getByRole("region", { name: "Cost" }).textContent).toContain("3 SIEM requests, 2,100 ms of server time, 1 answer reused from an earlier version; 2 model calls, $0.0123.");
    expect(screen.getByRole("region", { name: "Where each fact came from" }).textContent).toContain("E3 · proxy.pair@1 · squid, 03:30-08:30 UTC · 59 rows · complete");
  });

  it("shows the model's summary with its quotes and whether they were all found", () => {
    render(<ReportView reports={[REPORT]} />);
    const summary = screen.getByRole("region", { name: "Summary, in the AI investigator's words" });
    expect(summary.textContent).toContain("It beacons every 300 s.");
    expect(summary.textContent).toContain("Every quote below was found in what the model read.");
    expect(within(summary).getByText("every 300 s", { selector: "q *" })).toBeTruthy();
    render(<ReportView reports={[{ ...REPORT, summary: { ...must(REPORT.summary), checked: false } }]} />);
    expect(screen.getByText(/Some quotes could not be matched to what the model read\./)).toBeTruthy();
    render(<ReportView reports={[{ ...REPORT, summary: null }]} />);
    expect(screen.getAllByRole("region", { name: /Summary, in the AI investigator's words/ })).toHaveLength(2);
  });

  it("offers each assessor's report when there are several, the first shown", () => {
    const engine: Report = { ...REPORT, assessment_id: 8, verdict: { ...REPORT.verdict, source: "the decision engine", status: "no_decision", outcome: null, model_confidence: null, why: [] }, summary: null };
    render(<ReportView reports={[REPORT, engine]} />);
    const group = screen.getByRole("group", { name: "Reports of this investigation" });
    const [ai, decision] = within(group).getAllByRole("button");
    expect(ai?.getAttribute("aria-pressed")).toBe("true");
    expect(screen.getByRole("region", { name: "Verdict" }).textContent).toContain("The AI investigator proposes Real: act on it");
    fireEvent.click(must(decision));
    expect(decision?.getAttribute("aria-pressed")).toBe("true");
    expect(screen.getByRole("region", { name: "Verdict" }).textContent).toContain("The decision engine made no proposal");
    expect(screen.queryByRole("region", { name: /Summary/ })).toBeNull();
  });

  it("says there is no report before the dossier exists, and when results are hidden", () => {
    const { rerender } = render(<ReportView reports={[]} />);
    expect(screen.getByText(/No report yet: ARGUS has not built this investigation's dossier/)).toBeTruthy();
    rerender(<ReportView reports={[{ ...REPORT, hidden: 2 }]} />);
    expect(screen.getByText("The results of 2 log checks are hidden: they need log access in ELK.")).toBeTruthy();
    rerender(<ReportView reports={[{ ...REPORT, hidden: 1 }]} />);
    expect(screen.getByText("The results of 1 log check are hidden: they need log access in ELK.")).toBeTruthy();
  });

  it("shows every text from logs or models as text: no markup, no link, hidden characters marked", () => {
    const evil = '<img src=x onerror="window.__pwned=1"> \u202e<a href="https://evil.example">x</a>';
    const hostile: Report = {
      ...REPORT,
      note: evil,
      summary: { text: evil, cites: [{ quote: evil, eids: ["E3"] }], checked: true, note: evil },
      found: { ...REPORT.found, items: [{ kind: "new", sentence: evil, values: [{ label: evil, text: evil, count: 1 }], note: evil }] },
      timeline: [{ at: "2026-10-09T09:02:00Z", sentence: evil, values: [{ label: "a", text: evil }] }],
      evidence: [{ stance: "supports", fact: { key: "k", kind: "signal", name: "n", sentence: evil, status: "known", source: evil } }],
      hypotheses: [{ name: evil, by: "model", support: [{ key: "k", text: evil }], against: [{ key: "k2", text: evil }] }],
      unknowns: [{ key: "u", what: evil, why: evil, who: evil }],
      actions: [{ text: evil, who: evil, why: evil }],
      provenance: [{ ...must(REPORT.provenance[0]), line: evil }],
      verdict: { ...REPORT.verdict, why: [evil] },
      strength: { ...REPORT.strength, reasons: [evil] },
    };
    const { container } = render(<ReportView reports={[hostile]} />);
    expect(container.querySelector("img, a, script, iframe, svg")).toBeNull();
    expect(container.querySelectorAll(".ut-mark").length).toBeGreaterThanOrEqual(15);
    expect(container.textContent).toContain('<img src=x onerror="window.__pwned=1">');
    expect((window as unknown as { __pwned?: number }).__pwned).toBeUndefined();
  });
});
