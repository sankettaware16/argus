// report@2 as people read it (lib/report.ts).
import { describe, expect, it } from "vitest";
import { confidenceText, costSentence, eidText, factSource, foundHeading, GRADE_LABEL, LINE_LABEL, LINE_TONE, reportTab, strengthCounts, verdictSentence } from "../src/lib/report";
import { REPORT } from "./helpers";

describe("the lines of what ARGUS found", () => {
  it("name every kind in words, and give each a tone, so a colour is never the only sign", () => {
    expect(LINE_LABEL).toEqual({ new: "New", nothing_found: "Nothing found", could_not_tell: "Could not tell", failed: "Failed", not_checked: "Not checked", still_open: "Still open", hidden: "Hidden" });
    expect(LINE_TONE.nothing_found).toBe("ok");
    expect(LINE_TONE.could_not_tell).toBe("warn");
    expect(Object.keys(LINE_TONE).sort()).toEqual(Object.keys(LINE_LABEL).sort());
  });

  it("heads the box with the checks and the SIEM's server time", () => {
    expect(foundHeading(3, 2100)).toBe("3 checks, 2.1 s of SIEM server time");
    expect(foundHeading(1, 850)).toBe("1 check, 850 ms of SIEM server time");
    expect(foundHeading(0, 0)).toBe("0 checks, 0 ms of SIEM server time");
    expect(eidText(["E3", "E4"])).toBe("E3, E4");
    expect(eidText(undefined)).toBe("");
    expect(eidText([])).toBe("");
  });
});

describe("the verdict", () => {
  it("says who proposes what, or why there is no proposal", () => {
    expect(verdictSentence(REPORT.verdict)).toBe("The AI investigator proposes True positive");
    const v = { ...REPORT.verdict, status: "no_decision", outcome: null, source: "the decision engine" };
    expect(verdictSentence(v)).toBe("The decision engine made no proposal");
    expect(verdictSentence({ ...v, status: "queued" })).toBe("The decision engine has not assessed it yet");
    expect(verdictSentence({ ...v, status: "running" })).toBe("The decision engine is assessing it now");
    expect(verdictSentence({ ...v, status: "failed" })).toBe("The decision engine could not finish");
    expect(verdictSentence({ ...v, status: "none", source: "nobody yet" })).toBe("Nobody has assessed this investigation yet");
    expect(verdictSentence({ ...v, status: "odd_state" })).toBe("The decision engine odd state");
  });

  it("gives the model's confidence only when there is one, and grades the evidence apart from it", () => {
    expect(confidenceText(REPORT.verdict)).toBe("the model's confidence 75%");
    expect(confidenceText({ ...REPORT.verdict, model_confidence: null })).toBeNull();
    expect(confidenceText({ ...REPORT.verdict, model_confidence: undefined })).toBeNull();
    expect(confidenceText({ ...REPORT.verdict, model_confidence: 0 })).toBe("the model's confidence 0%");
    expect(GRADE_LABEL).toEqual({ strong: "Strong", moderate: "Moderate", weak: "Weak" });
    expect(strengthCounts(REPORT.strength).map((c) => `${c.label}: ${c.known}/${c.of}`)).toEqual([
      "Facts that decide a benign proposal: 2/3",
      "SIEM checks that completed: 3/4",
      "Investigation steps answered: 1/2",
      "Alerts read: 2/2",
    ]);
  });
});

describe("where a fact came from, and what it cost", () => {
  it("lists its E-numbers and the store it comes from, else the alerts", () => {
    expect(factSource({ eids: ["E3"], source: "acme-threat-intel" })).toBe("E3, acme-threat-intel");
    expect(factSource({ eids: ["E3"] })).toBe("E3");
    expect(factSource({ source: "abuse-ioc" })).toBe("abuse-ioc");
    expect(factSource({})).toBe("the alerts");
    expect(factSource({ eids: [], source: null })).toBe("the alerts");
  });

  it("counts SIEM requests and, when a model ran, its calls and cost", () => {
    expect(costSentence(REPORT.cost)).toBe("3 SIEM requests, 2,100 ms of server time, 1 answer reused from an earlier version; 2 model calls, $0.0123");
    expect(costSentence({ siem_requests: 1, siem_server_ms: 5, reused: 0 })).toBe("1 SIEM request, 5 ms of server time, 0 answers reused from an earlier version");
    expect(costSentence({ siem_requests: 0, siem_server_ms: 0, reused: 2, model_calls: 1, model_cost_usd: 0 })).toBe("0 SIEM requests, 0 ms of server time, 2 answers reused from an earlier version; 1 model call, $0.0000");
    expect(reportTab("the AI investigator")).toBe("The AI investigator");
    expect(reportTab("")).toBe("");
  });
});
