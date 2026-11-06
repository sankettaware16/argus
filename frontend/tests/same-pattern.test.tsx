// AR2: an investigation without a run of the AI investigator of its own shows the investigator's run on
// another one of its pattern as a link and one sentence: never a proposal for this investigation, nothing
// to accept. A real member of a pattern always has the decision engine's own "no proposal" (that is how the
// pattern's picker finds it), so the line shows beside that card, not only when there is no assessment.
import { screen, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import type { AssessmentOut } from "../src/client/types.gen";
import { BASE, detail, ID, mockApi, renderApp, server } from "./helpers";

mockApi();

const API = `${BASE}/api/v1/investigations/${ID}`;
const NOREPORTS = () => HttpResponse.json({ items: [], logs_hidden: false });
const OTHER = "11111111-2222-4333-8444-555555555555";
const PROPOSAL: AssessmentOut = {
  id: 9,
  assessor: "agent@1",
  source: "the AI investigator",
  status: "proposed",
  outcome: "true_positive",
  confidence: 0.75,
  decided_by: "agent@1#m",
  reasons: ["It beacons."],
  run: null,
  reading: null,
  created_at: "2026-10-09T13:00:00Z",
  finished_at: "2026-10-09T13:05:00Z",
};
// what every real member of a pattern has: the decision engine looked and found nothing it can propose
const ENGINE: AssessmentOut = {
  id: 4,
  assessor: "engine@1",
  source: "the decision engine",
  status: "no_decision",
  outcome: null,
  confidence: null,
  decided_by: "engine@1#fp: steps / rule / no past verdicts",
  reasons: ["No past verdicts support a proposal for this kind of alert."],
  run: null,
  reading: null,
  created_at: "2026-10-09T12:00:00Z",
  finished_at: "2026-10-09T12:00:05Z",
};

async function open(more: Parameters<typeof detail>[0]) {
  server.use(http.get(API, () => HttpResponse.json(detail(more))), http.get(`${API}/reports`, NOREPORTS));
  renderApp(`/investigations/${ID}?tab=ai`);
  await screen.findByText("Your decision");
}

describe("same pattern as another investigation", () => {
  it("links to the investigation the run was made on and says it is not a proposal here", async () => {
    await open({ assessments: [ENGINE], same_pattern: { investigation_id: OTHER, earlier: false, assessment: PROPOSAL } });
    const line = screen.getByTestId("same-pattern");
    expect(within(line).getByRole("link", { name: OTHER }).getAttribute("href")).toContain(OTHER);
    expect(line.textContent).toContain("Same pattern as");
    expect(line.textContent).toContain("proposes Real: act on it (75%)");
    expect(line.textContent).toContain("not a proposal for this investigation");
    expect(screen.getByRole("article", { name: "The decision engine: no proposal" })).toBeTruthy(); // its own card stays
    expect(screen.queryByRole("button", { name: /Accept/ })).toBeNull();
    expect(screen.queryByText(/Not assessed yet/)).toBeNull();
  });

  it("shows the same line when the investigation has no assessment at all", async () => {
    await open({ same_pattern: { investigation_id: OTHER, earlier: false, assessment: PROPOSAL } });
    expect(screen.getByTestId("same-pattern").textContent).toContain("Same pattern as");
    expect(screen.queryByText(/Not assessed yet/)).toBeNull();
  });

  it("says so when the run is this investigation's own, before it changed", async () => {
    await open({ assessments: [ENGINE], same_pattern: { investigation_id: ID, earlier: true, assessment: PROPOSAL } });
    const line = screen.getByTestId("same-pattern");
    expect(line.textContent).toContain("before it changed");
    expect(within(line).queryByRole("link")).toBeNull();
  });

  it("shows nothing about a pattern when the investigation has a run of its own", async () => {
    await open({ assessments: [PROPOSAL, ENGINE] });
    expect(screen.queryByTestId("same-pattern")).toBeNull();
  });

  it("shows the investigator's own run and not the shared line when both would be there", async () => {
    await open({ assessments: [PROPOSAL, ENGINE], same_pattern: { investigation_id: OTHER, earlier: false, assessment: PROPOSAL } });
    expect(screen.queryByTestId("same-pattern")).toBeNull();
    expect(screen.getByRole("article", { name: /The AI investigator: proposes Real: act on it/ })).toBeTruthy();
  });
});
