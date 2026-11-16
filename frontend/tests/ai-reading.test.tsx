// ARGUS AI's reading on the incident page (D-324): read from the engine block (a malformed or
// empty reading is left out), shown under the summary as "ARGUS AI's reading" with the model in
// small text and the "may be wrong" note, the second opinion under it, an earlier version said,
// the cited facts on demand, and a disagreement as the line above the summary.
import { screen, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import type { CaseDetail } from "../src/client/types.gen";
import { citedFacts, modelName } from "../src/components/incident/AiReading";
import { aiReadingOf, engineOf } from "../src/lib/engine";
import { report, reportOut } from "./incidentFixtures";
import { BASE, mockApi, renderApp, server } from "./helpers";
import { P1_ID, p1Detail, p1Engine } from "./v2Fixtures";

mockApi();
const CASE_URL = `${BASE}/api/v1/cases/${P1_ID}`;

const story = (more: Record<string, unknown> = {}) => ({
  kind: "story",
  model: "openai/gpt-5.4-mini",
  written_at: "2026-11-16T06:00:00Z",
  current: true,
  agrees: true,
  incidents: "one",
  sections: [
    { key: "happened", title: "What happened", claims: [{ text: "Five lab PCs reached one flagged address.", based_on: ["The engine's priority is P1, 82 of 100."] }] },
    { key: "against", title: "The strongest case against it", claims: [{ text: "A shared lab tool could do this.", based_on: ["A harmless explanation still fits."] }] },
    { key: "split", title: "One incident or two", claims: [{ text: "All five share one destination.", based_on: ["The engine's priority is P1, 82 of 100."] }] },
    {
      key: "next_steps",
      title: "What to check next",
      claims: [
        { text: "Ask the lab what it installed.", based_on: [] },
        { text: "Check the proxy logs.", based_on: [] },
      ],
    },
  ],
  ...more,
});
const opinion = {
  kind: "second_opinion",
  model: "openai/gpt-5.5",
  written_at: "2026-11-16T06:00:00Z",
  current: true,
  agrees: true,
  incidents: null,
  sections: [
    { key: "reading", title: "Its reading", claims: [{ text: "It looks like a real beacon.", based_on: [] }] },
    { key: "doubts", title: "The weakest point", claims: [{ text: "One lab only.", based_on: [] }] },
    { key: "decide", title: "The check that would settle it", claims: [{ text: "Look at one PC's processes.", based_on: [] }] },
  ],
};

function serve(engine: Record<string, unknown>) {
  const d: CaseDetail = p1Detail({}, {}, engine);
  server.use(
    http.get(CASE_URL, () => HttpResponse.json(d)),
    http.get(`${CASE_URL}/report`, () => HttpResponse.json(reportOut({ case_id: P1_ID, case_number: 31 }, { summary: report().summary }))),
  );
}

describe("reading the AI's reading", () => {
  it("takes a well-formed reading and leaves out what is not", () => {
    const got = aiReadingOf(story());
    expect(got?.kind).toBe("story");
    expect(got?.sections.map((s) => s.key)).toEqual(["happened", "against", "split", "next_steps"]);
    expect(aiReadingOf(null)).toBeNull();
    expect(aiReadingOf({ ...story(), kind: "verdict" })).toBeNull();
    expect(aiReadingOf({ ...story(), sections: [] })).toBeNull();
    expect(aiReadingOf({ ...story(), sections: [{ key: "happened", title: "What happened", claims: [{ text: "  " }] }] })).toBeNull();
    const e = engineOf(p1Engine({ ai_story: story(), ai_second_opinion: { bad: true } }));
    expect(e?.ai_story?.model).toBe("openai/gpt-5.4-mini");
    expect(e?.ai_second_opinion).toBeNull();
    expect(engineOf(p1Engine())?.ai_story).toBeNull();
  });

  it("names the model without its provider and lists each cited fact once", () => {
    expect(modelName("openai/gpt-5.4-mini")).toBe("gpt-5.4-mini");
    expect(modelName("plain")).toBe("plain");
    expect(citedFacts([aiReadingOf(story()), null])).toEqual(["The engine's priority is P1, 82 of 100.", "A harmless explanation still fits."]);
  });
});

describe("the incident page", () => {
  it("shows the reading under the summary, the model small, the note, the second opinion", async () => {
    serve(p1Engine({ ai_story: story(), ai_second_opinion: opinion }));
    renderApp(`/incidents/${P1_ID}`);
    const region = await screen.findByRole("region", { name: "ARGUS AI's reading" });
    const order = [...document.querySelectorAll("[data-testid=overview] [data-region]")].map((r) => r.getAttribute("data-region"));
    expect(order.indexOf("ai-reading")).toBe(order.indexOf("why") - 1);
    expect(order.indexOf("ai-reading")).toBeGreaterThan(order.indexOf("what-happened"));
    const r = within(region);
    expect(r.getByTestId("ai-note").textContent).toBe("gpt-5.4-mini · may be wrong; the evidence on this page decides");
    expect(r.getByTestId("ai-happened").textContent).toContain("Five lab PCs reached one flagged address.");
    expect(r.getByTestId("ai-against").textContent).toContain("A shared lab tool could do this.");
    expect(r.getByTestId("ai-split").textContent).toContain("One incident.");
    expect(within(r.getByTestId("ai-next_steps")).getAllByRole("listitem")).toHaveLength(2);
    const second = within(r.getByTestId("ai-second_opinion"));
    expect(second.getByRole("heading", { level: 3 }).textContent).toBe("Second opinion gpt-5.5");
    expect(second.getByTestId("ai-decide").textContent).toContain("Look at one PC's processes.");
    expect(r.getByText("The facts it cited (2)")).toBeTruthy();
    expect(r.queryByTestId("ai-earlier")).toBeNull();
  });

  it("says when it read an earlier version, and shows a disagreement as the line above", async () => {
    const line = "ARGUS AI reads this differently from the engine (P1, Likely): one lab only.";
    serve(p1Engine({ ai_story: story({ current: false, agrees: false }), disagreement: line }));
    renderApp(`/incidents/${P1_ID}`);
    const region = await screen.findByRole("region", { name: "ARGUS AI's reading" });
    expect(within(region).getByTestId("ai-earlier").textContent).toContain("earlier version");
    const top = document.querySelector("[data-region=disagreement]");
    expect(top?.textContent).toContain(line);
  });

  it("shows nothing before a reading is written", async () => {
    serve(p1Engine());
    renderApp(`/incidents/${P1_ID}`);
    await screen.findByTestId("summary");
    expect(screen.queryByRole("region", { name: "ARGUS AI's reading" })).toBeNull();
  });
});
