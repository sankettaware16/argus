// AR1: when the AI investigator proposed nothing but left a reading, the investigation page says
// what ARGUS made of it, why that is not a proposal, and which cited facts were found in the evidence.
import { screen, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import type { AssessmentOut, ReadingOut } from "../src/client/types.gen";
import { BASE, detail, ID, mockApi, renderApp, server, stanceOf } from "./helpers";

mockApi();

const API = `${BASE}/api/v1/investigations/${ID}`;
const NOREPORTS = () => HttpResponse.json({ items: [], logs_hidden: false });
const READING: ReadingOut = {
  kind: "floor",
  outcome: "benign_expected",
  confidence: 0.8,
  headline: "ARGUS's reading: benign, expected activity (80%) — not proposed because a safety check needs a person: the severity is high",
  why: "a safety check needs a person: the severity is high",
  reason: "A lab scanner.",
  facts: [
    { text: "severity high", checked: true },
    { text: "made up", checked: false },
  ],
};
const NO_DECISION: AssessmentOut = {
  id: 7,
  assessor: "agent@1",
  source: "the AI investigator",
  status: "no_decision",
  outcome: null,
  confidence: null,
  decided_by: "agent@1#m",
  reasons: ["A lab scanner.", "floor: severity high"],
  run: null,
  reading: READING,
  created_at: "2026-10-09T13:00:00Z",
  finished_at: "2026-10-09T13:05:00Z",
};

async function open(assessments: AssessmentOut[], tab = "ai") {
  server.use(http.get(API, () => HttpResponse.json(detail({ assessments }))), http.get(`${API}/reports`, NOREPORTS));
  renderApp(`/investigations/${ID}?tab=${tab}`);
  await screen.findByText("Your decision");
}

describe("ARGUS's reading", () => {
  it("is shown on the AI assessment tab: the sentence, the reason and each fact marked", async () => {
    await open([NO_DECISION]);
    const card = screen.getByRole("article", { name: /no proposal/ });
    expect(within(card).getByTestId("reading-headline").textContent).toBe(READING.headline);
    expect(within(card).getByText("A lab scanner.")).toBeTruthy();
    const facts = within(card).getAllByRole("listitem");
    expect(facts).toHaveLength(2);
    expect(within(facts[0] as HTMLElement).getByText("checked, found in the evidence")).toBeTruthy();
    expect(within(facts[1] as HTMLElement).getByText("not found in the evidence")).toBeTruthy();
    expect(within(card).getByText(/This is ARGUS.s reading, not a proposal/)).toBeTruthy();
    expect(within(card).queryByRole("button", { name: /Accept/ })).toBeNull(); // never something to accept
    expect(within(card).queryByText(/Why no proposal/)).toBeNull(); // the plain words replace the raw refusal
    expect(within(card).queryByText(/Facts it cited/)).toBeNull();
  });

  it("is the verdict card's headline, with why it is not a proposal, and nothing to confirm", async () => {
    const stance = stanceOf({ kind: "reading", outcome: "benign_expected", confidence: 0.8, source: "the AI investigator", why: READING.why, assessment_id: 7 });
    server.use(http.get(API, () => HttpResponse.json(detail({ assessments: [NO_DECISION], stance }))), http.get(`${API}/reports`, NOREPORTS));
    renderApp(`/investigations/${ID}`);
    await screen.findByText("Your decision");
    expect(screen.getByTestId("verdict-headline").textContent).toBe("ARGUS leans to: Real but harmless (80%), but did not propose it");
    expect(screen.getByTestId("stance-why").textContent).toContain("Not proposed because a safety check needs a person: the severity is high.");
    expect(screen.queryByRole("button", { name: /^Accept ARGUS/ })).toBeNull(); // a reading is never a proposal
    expect(screen.getByText(/ARGUS did not propose its call, so there is nothing to accept/)).toBeTruthy();
  });

  it("shows nothing new for a no-decision run that left none, and the old words stay", async () => {
    await open([{ ...NO_DECISION, reading: null, reasons: ["no usable answer from the model", "2 rounds"] }]);
    expect(screen.queryByTestId("reading-headline")).toBeNull();
    expect(screen.queryByTestId("reading-brief")).toBeNull();
    expect(screen.getAllByText(/no usable answer from the model/).length).toBeGreaterThan(0);
  });

  it("is not shown for a proposal, which is displayed as before", async () => {
    const proposal: AssessmentOut = { ...NO_DECISION, status: "proposed", outcome: "true_positive", confidence: 0.75, reading: null, reasons: ["It beacons."] };
    await open([proposal]);
    expect(screen.queryByTestId("reading-headline")).toBeNull();
    expect(screen.getAllByText(/proposes Real: act on it/).length).toBeGreaterThan(0);
    expect(screen.getAllByText("It beacons.").length).toBeGreaterThan(0);
  });

  it("is not shown unless the run was a no-decision, whatever the server sent", async () => {
    await open([{ ...NO_DECISION, status: "failed" }]);
    expect(screen.queryByTestId("reading-headline")).toBeNull();
    expect(screen.queryByTestId("reading-brief")).toBeNull();
  });

  it("shows hidden characters in the model's words as markers, never as they are", async () => {
    await open([{ ...NO_DECISION, reading: { ...READING, reason: "evil‮txt" } }]);
    const card = screen.getByRole("article", { name: /no proposal/ });
    expect(card.querySelector(".ut-mark")).not.toBeNull();
    expect(card.textContent).not.toContain("‮");
  });
});
