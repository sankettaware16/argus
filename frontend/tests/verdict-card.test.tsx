// AR4: the verdict-first card on an investigation's page. What ARGUS recommends or read and why it
// is not a proposal, the facts behind it, Confirm and Change in one place, Next through the queue,
// and the keys C, 1 to 5 and N (never while typing).
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import type { AssessmentOut, GoldItemOut, InvestigationDetail, KnownRefOut, QueueOut } from "../src/client/types.gen";
import { BASE, detail, ID, ID2, ID3, mockApi, REPORT, renderApp, sent, server, sessionWith, shellHandlers, stanceOf } from "./helpers";

mockApi();

const API = `${BASE}/api/v1/investigations/${ID}`;
const PROPOSAL: AssessmentOut = {
  id: 7, assessor: "agent@1", source: "the AI investigator", status: "proposed", outcome: "true_positive", confidence: 0.75,
  decided_by: "agent@1#m", reasons: ["It beacons."], run: null, reading: null, created_at: "2026-10-09T13:00:00Z", finished_at: "2026-10-09T13:05:00Z",
};
const OWN = stanceOf({ kind: "recommends", outcome: "true_positive", confidence: 0.75, source: "the AI investigator", assessment_id: 7, acceptable: true, pattern_investigations: 14, pattern_alerts: 230 });
const SHARED = stanceOf({ kind: "recommends", outcome: "benign_expected", confidence: 0.9, source: "the AI investigator", assessment_id: 8, from_investigation_id: ID3, acceptable: false, pattern_investigations: 3, pattern_alerts: 9 });
const READING = stanceOf({ kind: "reading", outcome: "true_positive", confidence: 0.7, source: "the AI investigator", why: "it quoted something that is not in the evidence", assessment_id: 9 });
const GOLD: GoldItemOut = { split: "dev", why: ["a kind"], suggestion: { outcome: "benign_expected", source: "signals", reasons: ["no hit"] }, outcome: null, note: null, answered_by: null, answered_at: null };
const NOTHING = () => HttpResponse.json({ items: [], logs_hidden: false });
const WITH_REPORT = () => HttpResponse.json({ items: [REPORT], logs_hidden: false });

const queueOf = (order: string[], total: number = order.length): QueueOut => ({ cases: [], cases_total: 0, singles: [], singles_total: 0, notified_cases: 0, order, order_total: total });

function reads(d: InvestigationDetail, order: string[] = [ID, ID2], report: () => Response = NOTHING) {
  server.use(
    http.get(API, () => HttpResponse.json(d)),
    http.get(`${API}/reports`, report),
    http.get(`${BASE}/api/v1/queue`, () => HttpResponse.json(queueOf(order))),
  );
}

async function open(d: InvestigationDetail, order?: string[], report?: () => Response) {
  reads(d, order, report);
  const view = renderApp(`/investigations/${ID}`);
  await screen.findByText("Your review");
  return view;
}

const headline = () => screen.getByTestId("verdict-headline").textContent;
const outcome = () => screen.getByLabelText(/^Outcome/) as HTMLSelectElement;

describe("the top card says what ARGUS thinks", () => {
  it("recommends: the outcome and the confidence, where it comes from, the pattern's size and Confirm", async () => {
    await open(detail({ assessments: [PROPOSAL], acceptable_assessment_id: 7, stance: OWN }));
    expect(headline()).toBe("ARGUS recommends: True positive (75%)");
    expect(screen.getByText("From the AI investigator. A proposal, not a decision.")).toBeTruthy();
    expect(screen.getByText("This pattern: 14 investigations, 230 alerts.")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Confirm: True positive" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Change" })).toBeTruthy();
  });

  it("recommends from the pattern's run on another investigation, which it links, and says Confirm records the person's own review", async () => {
    await open(detail({ stance: SHARED }));
    expect(headline()).toBe("ARGUS recommends: Benign: expected activity (90%)");
    const same = screen.getByTestId("same-pattern-source");
    expect(within(same).getByRole("link").getAttribute("href")).toBe(`/app/investigations/${ID3}`);
    expect(screen.getByText(/Confirming records your own review of this investigation/)).toBeTruthy();
  });

  it("reads: the outcome, not proposed because, and nothing to confirm; the person chooses", async () => {
    await open(detail({ stance: READING }));
    expect(headline()).toBe("ARGUS's reading: True positive (70%), not proposed because it quoted something that is not in the evidence");
    expect(screen.getByText("From the AI investigator. A reading is not a proposal: nothing is closed from it.")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /^Confirm/ })).toBeNull();
    expect(screen.getByText(/ARGUS did not propose an outcome, so there is nothing to confirm/)).toBeTruthy();
  });

  it("has nothing: it says so, and offers the form", async () => {
    await open(detail());
    expect(headline()).toBe("ARGUS has no reading of this yet");
    expect(screen.queryByRole("button", { name: /^Confirm/ })).toBeNull();
    expect(screen.getByText(/ARGUS has no recommendation for this one/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Mark reviewed" })).toBeTruthy();
  });

  it("lists three to five key facts, each linking to its rows: the report's sources for an E-number, the alerts otherwise", async () => {
    await open(detail({ stance: OWN, dossier: { ...DOSSIER, facts: ["Two alerts from 10.0.0.1."] } }), undefined, WITH_REPORT);
    const facts = within(await screen.findByRole("region", { name: "The facts behind this" }));
    await facts.findByText("Host H1 reached the C2 every 300 s, 59 times.");
    const items = facts.getAllByRole("listitem");
    expect(items.map((li) => li.textContent)).toEqual([
      "Host H1 reached the C2 every 300 s, 59 times.See the rows (E3)",
      "Two more campus hosts reached the same C2 today.See the rows (E4)",
      "Contacts at a fixed interval.See the rows (E3)",
      "Two alerts from 10.0.0.1.See the alerts",
    ]);
    expect(within(items[0] as HTMLElement).getByRole("link").getAttribute("href")).toBe(`/app/investigations/${ID}?tab=report#eid-E3`);
    expect(within(items[3] as HTMLElement).getByRole("link").getAttribute("href")).toBe(`/app/investigations/${ID}?tab=alerts`);
  });

  it("says known or changed since the notice, with the case", async () => {
    const known: KnownRefOut = { case_id: "c1c1c1c1-0000-4000-8000-000000000001", case_number: 12, outcome: "changed", why: "a new flagged destination: 203.0.113.9", notified_at: "2026-10-20T04:00:00Z" };
    await open(detail({ stance: OWN }, { known }));
    const note = screen.getByTestId("known-note");
    expect(note.textContent).toContain("Changed since notice. Changed since the owner was told: a new flagged destination: 203.0.113.9");
    expect(within(note).getByRole("link", { name: "Open case 12" }).getAttribute("href")).toBe("/app/cases/c1c1c1c1-0000-4000-8000-000000000001");
  });

  it("says a known investigation is counted and not raised", async () => {
    const known: KnownRefOut = { case_id: "c1c1c1c1-0000-4000-8000-000000000001", case_number: 12, outcome: "known", why: null, notified_at: "2026-10-20T04:00:00Z" };
    await open(detail({}, { known }));
    expect(screen.getByTestId("known-note").textContent).toContain("Known. Known: the owner of this device was told");
  });

  it("shows a hostile fact as text", async () => {
    const hostile = '<img src=x onerror="window.__pwned=1">';
    const { container } = await open(detail({ stance: OWN, dossier: { ...DOSSIER, facts: [hostile] } }));
    await screen.findAllByText(hostile);
    expect(container.querySelector("img")).toBeNull();
  });
});

const DOSSIER: NonNullable<InvestigationDetail["dossier"]> = {
  version: 3, pack: "generic@12", status: "evidence_ready", partial_reason: null, created_at: "2026-10-09T12:00:00Z", facts: [], decoded_paths: [], addresses: [], related: [], steps: [], has_note: true, complete: true, alerts_read: 2,
};

describe("Confirm", () => {
  it("accepts ARGUS's own proposal, says so, and reads the investigation again", async () => {
    const user = userEvent.setup();
    server.use(http.post(`${API}/accept`, () => HttpResponse.json({ assessment_id: 7, investigation_id: ID })));
    await open(detail({ assessments: [PROPOSAL], acceptable_assessment_id: 7, stance: OWN }));
    await user.click(screen.getByRole("button", { name: "Confirm: True positive" }));
    expect(await screen.findByText("Saved: you confirmed ARGUS's recommendation, True positive.", { selector: "p" })).toBeTruthy();
    const [post] = sent("POST", "/api");
    expect(post?.path).toBe(`/api/v1/investigations/${ID}/accept`);
    expect(JSON.parse(post?.body ?? "")).toEqual({ assessment_id: 7 });
    await waitFor(() => expect(sent("GET", `/api/v1/investigations/${ID}`).filter((r) => r.path === `/api/v1/investigations/${ID}`).length).toBeGreaterThanOrEqual(2));
  });

  it("records the person's own review for the pattern's proposal, naming what they saw, and does not accept it", async () => {
    const user = userEvent.setup();
    server.use(http.post(`${API}/reviews`, () => HttpResponse.json({ review_id: 11, version: 3, gold_saved: false }, { status: 201 })));
    await open(detail({ stance: SHARED }, { latest_review: 5 }));
    await user.click(screen.getByRole("button", { name: "Confirm: Benign: expected activity" }));
    expect(await screen.findByText("Saved: you confirmed Benign: expected activity as your review.", { selector: "p" })).toBeTruthy();
    const posts = sent("POST", "/api");
    expect(posts).toHaveLength(1);
    expect(posts[0]?.path).toBe(`/api/v1/investigations/${ID}/reviews`);
    expect(JSON.parse(posts[0]?.body ?? "")).toEqual({ action: "reviewed", outcome: "benign_expected", note: null, seen_review: 5, seen_version: 3, also_gold: false });
  });

  it("says it did not save when the proposal moved (409), keeps the card, and reads the investigation again", async () => {
    const user = userEvent.setup();
    server.use(http.post(`${API}/accept`, () => HttpResponse.json({ detail: "the proposal changed (new alerts, a newer assessment, or someone reviewed it): nothing was saved", code: "conflict" }, { status: 409 })));
    await open(detail({ assessments: [PROPOSAL], acceptable_assessment_id: 7, stance: OWN }));
    await user.click(screen.getByRole("button", { name: "Confirm: True positive" }));
    const alert = await screen.findByText(/Someone else reviewed this, or new alerts arrived, while you were reading\. Nothing was saved\./);
    expect(alert.getAttribute("role")).toBe("alert");
    expect(sent("POST", "/api")).toHaveLength(1);
    await waitFor(() => expect(sent("GET", `/api/v1/investigations/${ID}`).filter((r) => r.path === `/api/v1/investigations/${ID}`).length).toBeGreaterThanOrEqual(2));
    expect(screen.getByRole("button", { name: "Confirm: True positive" })).toBeTruthy();
  });

  it("says why a failure was not saved, in the server's words, and can be tried again", async () => {
    const user = userEvent.setup();
    let calls = 0;
    server.use(
      http.post(`${API}/accept`, () => {
        calls += 1;
        return calls === 1 ? HttpResponse.json({ detail: "ARGUS cannot answer just now; try again in a minute.", code: "unavailable" }, { status: 503 }) : HttpResponse.json({ assessment_id: 7, investigation_id: ID });
      }),
    );
    await open(detail({ assessments: [PROPOSAL], acceptable_assessment_id: 7, stance: OWN }));
    await user.click(screen.getByRole("button", { name: "Confirm: True positive" }));
    expect((await screen.findByText(/cannot answer just now/)).getAttribute("role")).toBe("alert");
    await user.click(screen.getByRole("button", { name: "Confirm: True positive" }));
    await screen.findByText("Saved: you confirmed ARGUS's recommendation, True positive.", { selector: "p" });
    expect(calls).toBe(2);
  });

  it("sends nothing while the investigation moved under the person, and takes them to what they must do first", async () => {
    const user = userEvent.setup();
    const { queries } = await open(detail({ assessments: [PROPOSAL], acceptable_assessment_id: 7, stance: OWN }));
    queries.setQueryData(["investigation", ID], detail({ assessments: [PROPOSAL], acceptable_assessment_id: 7, stance: OWN }, { version: 4, alert_count: 9 }));
    const looked = await screen.findByRole("button", { name: "I have looked at what changed" });
    await user.click(screen.getByRole("button", { name: "Confirm: True positive" }));
    expect(sent("POST", "/api")).toHaveLength(0);
    expect(document.activeElement).toBe(looked);
  });

  it("is one send at a time, whatever the clicks", async () => {
    const user = userEvent.setup();
    let posts = 0;
    server.use(
      http.post(`${API}/accept`, async () => {
        posts += 1;
        await new Promise((resolve) => setTimeout(resolve, 150));
        return HttpResponse.json({ assessment_id: 7, investigation_id: ID });
      }),
    );
    await open(detail({ assessments: [PROPOSAL], acceptable_assessment_id: 7, stance: OWN }));
    const button = screen.getByRole("button", { name: "Confirm: True positive" });
    await user.click(button);
    await user.click(button);
    fireEvent.click(button);
    await screen.findByText("Saved: you confirmed ARGUS's recommendation, True positive.", { selector: "p" });
    expect(posts).toBe(1);
  });

  it("is not offered to an account that may only view, which is told why", async () => {
    server.use(...shellHandlers(sessionWith(["view"])));
    await open(detail({ assessments: [PROPOSAL], acceptable_assessment_id: 7, stance: OWN }));
    expect(screen.queryByRole("button", { name: /^Confirm/ })).toBeNull();
    expect(screen.queryByRole("button", { name: "Change" })).toBeNull();
    expect(screen.getByText(/Your account may view only: reviewing needs the “review” capability/)).toBeTruthy();
  });

  it("is not offered for an investigation that is reviewed already", async () => {
    await open(detail({ stance: OWN }, { human_state: "reviewed", latest_review: 5, last_outcome: "true_positive", last_reviewer: "Ravi" }));
    expect(screen.queryByRole("button", { name: /^Confirm/ })).toBeNull();
    expect(screen.getByText((_, el) => el?.tagName === "P" && /^Already reviewed by Ravi: True positive\. A new review below replaces it\.$/.test(el.textContent ?? ""))).toBeTruthy();
  });

  it("starts with the gold-set box unticked, so ARGUS's suggestion is not the person's answer by default (AR4 review)", async () => {
    await open(detail({ assessments: [PROPOSAL], acceptable_assessment_id: 7, stance: OWN, gold: GOLD }));
    expect((screen.getByRole("checkbox", { name: "Also save the outcome as my gold-set answer" }) as HTMLInputElement).checked).toBe(false);
  });

  it("also saves the gold-set answer for a gold item when the box is ticked, through a review rather than an accept", async () => {
    const user = userEvent.setup();
    server.use(http.post(`${API}/reviews`, () => HttpResponse.json({ review_id: 11, version: 3, gold_saved: true }, { status: 201 })));
    await open(detail({ assessments: [PROPOSAL], acceptable_assessment_id: 7, stance: OWN, gold: GOLD }));
    await user.click(screen.getByRole("checkbox", { name: "Also save the outcome as my gold-set answer" }));
    await user.click(screen.getByRole("button", { name: "Confirm: True positive" }));
    await screen.findByText("Saved: you confirmed True positive as your review. Also saved as your gold-set answer.", { selector: "p" });
    const [post] = sent("POST", "/api");
    expect(post?.path).toBe(`/api/v1/investigations/${ID}/reviews`);
    expect(JSON.parse(post?.body ?? "")).toMatchObject({ action: "reviewed", outcome: "true_positive", also_gold: true });
  });

  it("leaves the gold-set answer out when the box is left unticked, and accepts", async () => {
    const user = userEvent.setup();
    server.use(http.post(`${API}/accept`, () => HttpResponse.json({ assessment_id: 7, investigation_id: ID })));
    await open(detail({ assessments: [PROPOSAL], acceptable_assessment_id: 7, stance: OWN, gold: GOLD }));
    await user.click(screen.getByRole("button", { name: "Confirm: True positive" }));
    await screen.findByText("Saved: you confirmed ARGUS's recommendation, True positive.", { selector: "p" });
    expect(sent("POST", "/api")[0]?.path).toBe(`/api/v1/investigations/${ID}/accept`);
  });

  it("saves a reviewed gold item's answer alone, as the gold box does, with a button that says so and is not Confirm's", async () => {
    const user = userEvent.setup();
    server.use(http.post(`${API}/gold`, () => HttpResponse.json({ next_investigation_id: null })));
    await open(detail({ stance: OWN, gold: GOLD }, { human_state: "reviewed", latest_review: 5 }));
    expect(screen.queryByRole("button", { name: /^Confirm/ })).toBeNull();
    const button = screen.getByRole("button", { name: "Save as my gold-set answer: True positive" });
    expect(button.getAttribute("aria-keyshortcuts")).toBeNull(); // not bound to C
    expect(button.querySelector("kbd")).toBeNull();
    await user.click(button);
    await screen.findByText("Saved: your gold-set answer is True positive, as ARGUS recommends.", { selector: "p" });
    const [post] = sent("POST", "/api");
    expect(post?.path).toBe(`/api/v1/investigations/${ID}/gold`);
    expect(JSON.parse(post?.body ?? "")).toEqual({ outcome: "true_positive", note: null });
  });
});

describe("Confirm does not discard what the form holds (AR4 review)", () => {
  const confirmButton = () => screen.getByRole("button", { name: "Confirm: True positive" });

  it("waits, with a hint, when the form holds another outcome than ARGUS's, and sends nothing", async () => {
    const user = userEvent.setup();
    server.use(http.post(`${API}/accept`, () => HttpResponse.json({ assessment_id: 7, investigation_id: ID })));
    await open(detail({ assessments: [PROPOSAL], acceptable_assessment_id: 7, stance: OWN }));
    await user.selectOptions(outcome(), "benign_policy");
    expect(confirmButton().getAttribute("aria-disabled")).toBe("true");
    const hint = screen.getByTestId("confirm-hold");
    expect(hint.textContent).toContain("You chose Benign: allowed by policy: use Mark reviewed to save your choice.");
    expect(confirmButton().getAttribute("aria-describedby")).toBe(hint.id);
    await user.click(confirmButton());
    expect(sent("POST", "/api")).toHaveLength(0);
  });

  it("waits, with a hint, when a note was written, and says so in a message too", async () => {
    const user = userEvent.setup();
    await open(detail({ assessments: [PROPOSAL], acceptable_assessment_id: 7, stance: OWN }));
    await user.type(screen.getByLabelText("Note"), "I called the owner; it is a real infection");
    expect(screen.getByTestId("confirm-hold").textContent).toContain("You wrote a note");
    await user.click(confirmButton());
    expect(sent("POST", "/api")).toHaveLength(0);
    expect((await screen.findAllByText(/You wrote a note: choose the outcome and use Mark reviewed to keep it/)).length).toBeGreaterThan(1);
  });

  it("the C key waits the same way, and says why, instead of discarding the form", async () => {
    const user = userEvent.setup();
    await open(detail({ assessments: [PROPOSAL], acceptable_assessment_id: 7, stance: OWN }));
    await user.selectOptions(outcome(), "inconclusive");
    outcome().blur();
    await user.keyboard("c");
    expect(sent("POST", "/api")).toHaveLength(0);
    expect((await screen.findAllByText(/You chose Inconclusive: use Mark reviewed/)).length).toBeGreaterThan(1);
  });

  it("is the person's own choice that Mark reviewed saves, with the note", async () => {
    const user = userEvent.setup();
    server.use(http.post(`${API}/reviews`, () => HttpResponse.json({ review_id: 12, version: 3, gold_saved: false }, { status: 201 })));
    await open(detail({ assessments: [PROPOSAL], acceptable_assessment_id: 7, stance: OWN }));
    await user.selectOptions(outcome(), "true_positive");
    await user.type(screen.getByLabelText("Note"), "I called the owner");
    await user.click(screen.getByRole("button", { name: "Mark reviewed" }));
    await screen.findByText("Saved: marked reviewed.", { selector: "p" });
    expect(JSON.parse(sent("POST", "/api")[0]?.body ?? "")).toMatchObject({ outcome: "true_positive", note: "I called the owner" });
  });

  it("confirms at once when the form holds the same outcome as ARGUS's and no note, and again after the form is cleared", async () => {
    const user = userEvent.setup();
    server.use(http.post(`${API}/accept`, () => HttpResponse.json({ assessment_id: 7, investigation_id: ID })));
    await open(detail({ assessments: [PROPOSAL], acceptable_assessment_id: 7, stance: OWN }));
    await user.selectOptions(outcome(), "benign_policy");
    expect(screen.queryByTestId("confirm-hold")).not.toBeNull();
    await user.selectOptions(outcome(), "true_positive"); // the same as ARGUS's: nothing is dropped
    expect(screen.queryByTestId("confirm-hold")).toBeNull();
    expect(confirmButton().getAttribute("aria-disabled")).toBeNull();
    await user.click(confirmButton());
    await screen.findByText("Saved: you confirmed ARGUS's recommendation, True positive.", { selector: "p" });
  });
});

describe("after Confirm the focus goes on (AR4 review)", () => {
  const confirmed = (queue: string[], after: string[]) => {
    let reviewed = false;
    const d = () => detail({ assessments: [PROPOSAL], acceptable_assessment_id: reviewed ? null : 7, stance: OWN }, reviewed ? { human_state: "reviewed", latest_review: 9, last_outcome: "true_positive", last_reviewer: "Mina" } : {});
    server.use(
      http.post(`${API}/accept`, () => {
        reviewed = true;
        return HttpResponse.json({ assessment_id: 7, investigation_id: ID });
      }),
      http.get(API, () => HttpResponse.json(d())),
      http.get(`${API}/reports`, NOTHING),
      http.get(`${BASE}/api/v1/queue`, () => HttpResponse.json(queueOf(reviewed ? after : queue))),
    );
  };

  it("moves to Next when there is a next item", async () => {
    const user = userEvent.setup();
    confirmed([ID, ID2], [ID2]);
    renderApp(`/investigations/${ID}`);
    await screen.findByText("Your review");
    await screen.findByText("1 more in the queue after this one.");
    const button = screen.getByRole("button", { name: /^Confirm/ });
    button.focus();
    await user.keyboard("{Enter}");
    await screen.findByText("Saved: you confirmed ARGUS's recommendation, True positive.", { selector: "p" });
    await waitFor(() => expect(screen.queryByRole("button", { name: /^Confirm/ })).toBeNull());
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("button", { name: "Next" })));
  });

  it("moves to the headline when there is no next item, never to the page body", async () => {
    const user = userEvent.setup();
    confirmed([ID], []);
    renderApp(`/investigations/${ID}`);
    await screen.findByText("Your review");
    await user.click(await screen.findByRole("button", { name: /^Confirm/ }));
    await screen.findByText("Saved: you confirmed ARGUS's recommendation, True positive.", { selector: "p" });
    await waitFor(() => expect(document.activeElement).toBe(screen.getByTestId("verdict-headline")));
    expect(document.activeElement).not.toBe(document.body);
  });

  it("moves to the headline in the Inbox's pane, which has no Next", async () => {
    const user = userEvent.setup();
    confirmed([ID, ID2], [ID2]);
    renderApp(`/inbox?view=attention&id=${ID}`);
    await user.click(await screen.findByRole("button", { name: /^Confirm/ }));
    await screen.findByText("Saved: you confirmed ARGUS's recommendation, True positive.", { selector: "p" });
    await waitFor(() => expect(document.activeElement).toBe(screen.getByTestId("verdict-headline")));
  });
});

describe("an account that cannot review", () => {
  it("has C and 1 to 5 do nothing and announce nothing, but N and ? work", async () => {
    const user = userEvent.setup();
    server.use(...shellHandlers(sessionWith(["view"])));
    const { router } = await open(detail({ assessments: [PROPOSAL], acceptable_assessment_id: 7, stance: OWN }), [ID, ID2]);
    await user.keyboard("1");
    await user.keyboard("c");
    expect(document.body.textContent).not.toMatch(/Chosen:/);
    expect(document.body.textContent).not.toMatch(/There is no recommendation to confirm here/);
    expect(sent("POST", "/api")).toHaveLength(0);
    expect(screen.queryByRole("button", { name: /^Confirm/ })).toBeNull();
    await user.keyboard("?");
    const dialog = await screen.findByRole("dialog");
    expect(dialog.textContent).toContain("go to the next item of the queue");
    expect(dialog.textContent).not.toContain("confirm what ARGUS recommends");
    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    await user.keyboard("n");
    await waitFor(() => expect(router.state.location.pathname).toBe(`/investigations/${ID2}`));
  });

  it("is not told about keys it has no use for", async () => {
    server.use(...shellHandlers(sessionWith(["view"])));
    await open(detail({ stance: OWN }));
    expect(screen.getByText("Single-key shortcuts (N)")).toBeTruthy();
  });
});

describe("only the plain letter is a shortcut (AR4 review)", () => {
  it("Shift+C and Shift+N do nothing, and neither does a capital from Caps Lock", async () => {
    const user = userEvent.setup();
    server.use(http.post(`${API}/accept`, () => HttpResponse.json({ assessment_id: 7, investigation_id: ID })));
    const { router } = await open(detail({ assessments: [PROPOSAL], acceptable_assessment_id: 7, stance: OWN }), [ID, ID2]);
    await user.keyboard("{Shift>}C{/Shift}");
    await user.keyboard("{Shift>}N{/Shift}");
    fireEvent.keyDown(window, { key: "C" }); // Caps Lock: the capital arrives without Shift
    fireEvent.keyDown(window, { key: "N" });
    expect(sent("POST", "/api")).toHaveLength(0);
    expect(router.state.location.pathname).toBe(`/investigations/${ID}`);
    await user.keyboard("c");
    await screen.findByText("Saved: you confirmed ARGUS's recommendation, True positive.", { selector: "p" });
  });
});

describe("? lists the keys on the investigation page (D-184)", () => {
  it("opens the list, which names C, 1 to 5, N and ?, and closes with Escape", async () => {
    const user = userEvent.setup();
    await open(detail({ stance: OWN }));
    await user.keyboard("?");
    const dialog = await screen.findByRole("dialog", { name: "Keyboard shortcuts on an investigation" });
    for (const word of ["confirm what ARGUS recommends", "choose the outcome", "go to the next item of the queue", "show this list"]) expect(dialog.textContent).toContain(word);
    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });

  it("does not open while a person types", async () => {
    const user = userEvent.setup();
    await open(detail({ stance: OWN }));
    await user.click(screen.getByLabelText("Note"));
    await user.keyboard("?");
    expect(screen.queryByRole("dialog")).toBeNull();
    expect((screen.getByLabelText("Note") as HTMLTextAreaElement).value).toBe("?");
  });
});

describe("Change", () => {
  it("takes an outcome and an optional note, and sends them with what was seen", async () => {
    const user = userEvent.setup();
    server.use(http.post(`${API}/reviews`, () => HttpResponse.json({ review_id: 12, version: 3, gold_saved: false }, { status: 201 })));
    await open(detail({ stance: OWN }));
    await user.click(screen.getByRole("button", { name: "Change" }));
    expect(document.activeElement).toBe(outcome());
    await user.selectOptions(outcome(), "benign_policy");
    await user.type(screen.getByLabelText("Note"), "A lab printer, says the lab");
    await user.click(screen.getByRole("button", { name: "Mark reviewed" }));
    await screen.findByText("Saved: marked reviewed.", { selector: "p" });
    expect(JSON.parse(sent("POST", "/api")[0]?.body ?? "")).toEqual({ action: "reviewed", outcome: "benign_policy", note: "A lab printer, says the lab", seen_review: null, seen_version: 3, also_gold: false });
  });

  it("works without a note", async () => {
    const user = userEvent.setup();
    server.use(http.post(`${API}/reviews`, () => HttpResponse.json({ review_id: 12, version: 3, gold_saved: false }, { status: 201 })));
    await open(detail());
    await user.selectOptions(outcome(), "inconclusive");
    await user.click(screen.getByRole("button", { name: "Mark reviewed" }));
    await screen.findByText("Saved: marked reviewed.", { selector: "p" });
    expect(JSON.parse(sent("POST", "/api")[0]?.body ?? "")).toMatchObject({ outcome: "inconclusive", note: null });
  });

  it("says nothing was saved and what to do when it moved (409), and keeps what was typed", async () => {
    const user = userEvent.setup();
    server.use(http.post(`${API}/reviews`, () => HttpResponse.json({ detail: "someone else reviewed it", code: "conflict" }, { status: 409 })));
    await open(detail({ stance: OWN }));
    await user.selectOptions(outcome(), "true_positive");
    await user.type(screen.getByLabelText("Note"), "keep me");
    await user.click(screen.getByRole("button", { name: "Mark reviewed" }));
    expect((await screen.findByText(/Nothing was saved\. What you typed is still here/)).getAttribute("role")).toBe("alert");
    expect((screen.getByLabelText("Note") as HTMLTextAreaElement).value).toBe("keep me");
    expect(outcome().value).toBe("true_positive");
  });

  it("is told what is missing when no outcome is chosen", async () => {
    const user = userEvent.setup();
    await open(detail());
    await user.click(screen.getByRole("button", { name: "Mark reviewed" }));
    expect(await screen.findByText("Choose an outcome to mark it reviewed.")).toBeTruthy();
    expect(sent("POST", "/api")).toHaveLength(0);
  });
});

describe("the keys", () => {
  it("C confirms what ARGUS recommends", async () => {
    const user = userEvent.setup();
    server.use(http.post(`${API}/accept`, () => HttpResponse.json({ assessment_id: 7, investigation_id: ID })));
    await open(detail({ assessments: [PROPOSAL], acceptable_assessment_id: 7, stance: OWN }));
    await user.keyboard("c");
    await screen.findByText("Saved: you confirmed ARGUS's recommendation, True positive.", { selector: "p" });
    expect(sent("POST", "/api")).toHaveLength(1);
  });

  it("C with nothing to confirm says so and sends nothing", async () => {
    const user = userEvent.setup();
    await open(detail({ stance: READING }));
    await user.keyboard("c");
    expect(await screen.findByText("There is no recommendation to confirm here: choose an outcome with the keys 1 to 5.", { selector: "p" })).toBeTruthy();
    expect(sent("POST", "/api")).toHaveLength(0);
  });

  it("1 to 5 choose the outcome and take the focus to Mark reviewed", async () => {
    const user = userEvent.setup();
    await open(detail({ stance: OWN }));
    const wanted = ["benign_expected", "benign_policy", "rule_false_positive", "true_positive", "inconclusive"];
    for (const [i, value] of wanted.entries()) {
      await user.keyboard(String(i + 1));
      expect(outcome().value).toBe(value);
    }
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Mark reviewed" }));
    expect(await screen.findByText("Chosen: Inconclusive. Press Mark reviewed to save it.", { selector: "p" })).toBeTruthy();
    expect(sent("POST", "/api")).toHaveLength(0); // choosing is not sending
  });

  it("do nothing while the person types in the note", async () => {
    const user = userEvent.setup();
    await open(detail({ assessments: [PROPOSAL], acceptable_assessment_id: 7, stance: OWN }));
    await user.click(screen.getByLabelText("Note"));
    await user.keyboard("c3n 4");
    expect((screen.getByLabelText("Note") as HTMLTextAreaElement).value).toBe("c3n 4");
    expect(outcome().value).toBe("");
    expect(sent("POST", "/api")).toHaveLength(0);
    expect(screen.queryByText(/Chosen:/)).toBeNull();
  });

  it("do nothing while the outcome select has the focus (the keys type-ahead there)", async () => {
    const user = userEvent.setup();
    await open(detail({ assessments: [PROPOSAL], acceptable_assessment_id: 7, stance: OWN }));
    outcome().focus();
    await user.keyboard("c");
    expect(sent("POST", "/api")).toHaveLength(0);
  });

  it("do nothing with a modifier held", async () => {
    const user = userEvent.setup();
    await open(detail({ assessments: [PROPOSAL], acceptable_assessment_id: 7, stance: OWN }));
    await user.keyboard("{Control>}c{/Control}{Alt>}n{/Alt}");
    expect(sent("POST", "/api")).toHaveLength(0);
  });

  it("can be switched off, the buttons still work, and the choice is kept", async () => {
    const user = userEvent.setup();
    server.use(http.post(`${API}/accept`, () => HttpResponse.json({ assessment_id: 7, investigation_id: ID })));
    const view = await open(detail({ assessments: [PROPOSAL], acceptable_assessment_id: 7, stance: OWN }));
    await user.click(screen.getByRole("checkbox", { name: "Single-key shortcuts (C, 1–5, N)" }));
    expect(window.localStorage.getItem("argus-shortcuts")).toBe("off");
    await user.keyboard("c");
    expect(sent("POST", "/api")).toHaveLength(0);
    expect(screen.getByRole("button", { name: "Confirm: True positive" }).getAttribute("aria-keyshortcuts")).toBeNull();
    await user.click(screen.getByRole("button", { name: "Confirm: True positive" }));
    await screen.findByText("Saved: you confirmed ARGUS's recommendation, True positive.", { selector: "p" });
    view.unmount();
  });

  it("do nothing while a dialog is open", async () => {
    const user = userEvent.setup();
    await open(detail({ assessments: [PROPOSAL], acceptable_assessment_id: 7, stance: OWN }));
    await user.click(screen.getByRole("button", { name: "Show keyboard shortcuts" }));
    const dialog = await screen.findByRole("dialog", { name: "Keyboard shortcuts on an investigation" });
    expect(within(dialog).getByText(/confirm what ARGUS recommends/)).toBeTruthy();
    await user.keyboard("c");
    expect(sent("POST", "/api")).toHaveLength(0);
    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });

  it("are named on the buttons for a screen reader (aria-keyshortcuts) and drawn on them", async () => {
    await open(detail({ assessments: [PROPOSAL], acceptable_assessment_id: 7, stance: OWN }));
    expect(screen.getByRole("button", { name: "Confirm: True positive" }).getAttribute("aria-keyshortcuts")).toBe("c");
    expect(screen.getByRole("button", { name: "Change" }).getAttribute("aria-keyshortcuts")).toBe("1 2 3 4 5");
    expect(screen.getByRole("button", { name: "Next" }).getAttribute("aria-keyshortcuts")).toBe("n");
  });
});

describe("Next", () => {
  it("goes to the next item of the queue, by the button and by N", async () => {
    const user = userEvent.setup();
    server.use(
      http.get(`${BASE}/api/v1/investigations/${ID2}`, () => HttpResponse.json(detail({ stance: OWN }, { id: ID2, rule_name: "The next one" }))),
      http.get(`${BASE}/api/v1/investigations/${ID2}/reports`, NOTHING),
    );
    const { router } = await open(detail({ stance: OWN }), [ID, ID2, ID3]);
    expect(await screen.findByText("2 more in the queue after this one.")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Next" }));
    await waitFor(() => expect(router.state.location.pathname).toBe(`/investigations/${ID2}`));
    await screen.findByText("The next one");
    await user.keyboard("n");
    await waitFor(() => expect(router.state.location.pathname).toBe(`/investigations/${ID3}`));
  });

  it("lands on the next one after C: the confirmed one leaves the queue and the next stands in its place", async () => {
    const user = userEvent.setup();
    let confirmed = false;
    server.use(
      http.post(`${API}/accept`, () => {
        confirmed = true;
        return HttpResponse.json({ assessment_id: 7, investigation_id: ID });
      }),
      http.get(`${BASE}/api/v1/queue`, () => HttpResponse.json(queueOf(confirmed ? [ID2, ID3] : [ID, ID2, ID3]))),
      http.get(`${BASE}/api/v1/investigations/${ID2}`, () => HttpResponse.json(detail({ stance: OWN }, { id: ID2, rule_name: "The next one" }))),
      http.get(`${BASE}/api/v1/investigations/${ID2}/reports`, NOTHING),
    );
    const { router } = await open(detail({ assessments: [PROPOSAL], acceptable_assessment_id: 7, stance: OWN }), [ID, ID2, ID3]);
    await screen.findByText("2 more in the queue after this one.");
    await user.keyboard("c");
    await screen.findByText("Saved: you confirmed ARGUS's recommendation, True positive.", { selector: "p" });
    await waitFor(() => expect(sent("GET", "/api/v1/queue").length).toBeGreaterThanOrEqual(2)); // the queue is read again
    await user.keyboard("n");
    await waitFor(() => expect(router.state.location.pathname).toBe(`/investigations/${ID2}`));
  });

  it("says it was the last one at the end of the queue, and stays", async () => {
    const user = userEvent.setup();
    const { router } = await open(detail({ stance: OWN }), [ID]);
    expect(await screen.findByText(/This is the last item in the queue\./)).toBeTruthy();
    await user.keyboard("n");
    expect((await screen.findAllByText("That was the last item in the queue: nothing else needs a person.")).length).toBeGreaterThan(0);
    expect(screen.queryByText(/more need a person in the Inbox/)).toBeNull();
    expect(screen.queryByRole("link", { name: "Open them in the Inbox" })).toBeNull();
    expect(router.state.location.pathname).toBe(`/investigations/${ID}`);
    expect(screen.getByRole("link", { name: "Back to the queue" }).getAttribute("href")).toBe("/app/");
  });

  it("never says nothing else needs a person while the queue holds more than the walk does (the walk is capped)", async () => {
    const user = userEvent.setup();
    reads(detail({ stance: OWN }), [ID]);
    server.use(http.get(`${BASE}/api/v1/queue`, () => HttpResponse.json({ ...queueOf([ID], 17047), singles_total: 17006, cases_total: 41 })));
    renderApp(`/investigations/${ID}`);
    await screen.findByText("Your review");
    expect(await screen.findByText(/This is the last of the 1 most urgent; 17,046 more need a person in the Inbox\./)).toBeTruthy();
    expect(screen.queryByText(/nothing else needs a person/)).toBeNull();
    await user.keyboard("n");
    expect((await screen.findAllByText("That was the last of the 1 most urgent; 17,046 more need a person in the Inbox.")).length).toBeGreaterThan(0);
    expect(screen.queryByText(/nothing else needs a person/)).toBeNull();
    expect(screen.getByRole("link", { name: "Open them in the Inbox" }).getAttribute("href")).toBe("/app/inbox?view=attention&sort=queue");
  });

  it("goes to the queue's first item from an investigation that is not in it", async () => {
    const user = userEvent.setup();
    server.use(
      http.get(`${BASE}/api/v1/investigations/${ID3}`, () => HttpResponse.json(detail({}, { id: ID3, rule_name: "The first of the queue" }))),
      http.get(`${BASE}/api/v1/investigations/${ID3}/reports`, NOTHING),
    );
    const { router } = await open(detail(), [ID3, ID2]);
    await screen.findByText("2 more in the queue after this one.");
    await user.click(screen.getByRole("button", { name: "Next" }));
    await waitFor(() => expect(router.state.location.pathname).toBe(`/investigations/${ID3}`));
  });

  it("says the queue could not be read, and N then says nothing is there", async () => {
    server.use(http.get(`${BASE}/api/v1/queue`, () => HttpResponse.json({ detail: "boom", code: "internal" }, { status: 500 })));
    reads(detail({ stance: OWN }));
    server.use(http.get(`${BASE}/api/v1/queue`, () => HttpResponse.json({ detail: "boom", code: "internal" }, { status: 500 })));
    renderApp(`/investigations/${ID}`);
    await screen.findByText("Your review");
    expect(await screen.findByText(/The queue could not be read, so Next has nowhere to go\./)).toBeTruthy();
  });
});

describe("in the Inbox's pane", () => {
  it("has the card, Confirm and Change, but no Next and no keys: the list is the way on", async () => {
    const user = userEvent.setup();
    window.matchMedia = ((query: string) => ({ matches: query.includes("1024"), media: query, addEventListener: () => {}, removeEventListener: () => {}, addListener: () => {}, removeListener: () => {}, dispatchEvent: () => false, onchange: null })) as unknown as typeof window.matchMedia;
    server.use(
      http.get(`${BASE}/api/v1/investigations`, () => HttpResponse.json({ items: [detail().investigation], view: "attention", sort: "newest", offset: 0, limit: 100, has_more: false })),
      http.get(API, () => HttpResponse.json(detail({ assessments: [PROPOSAL], acceptable_assessment_id: 7, stance: OWN }))),
      http.get(`${API}/reports`, NOTHING),
    );
    renderApp(`/inbox?view=attention&id=${ID}`);
    await screen.findByTestId("verdict-headline");
    expect(screen.getByRole("button", { name: "Confirm: True positive" }).getAttribute("aria-keyshortcuts")).toBeNull();
    expect(screen.queryByRole("button", { name: "Next" })).toBeNull();
    expect(screen.queryByRole("checkbox", { name: "Single-key shortcuts (C, 1–5, N)" })).toBeNull();
    await user.keyboard("c");
    expect(sent("POST", "/api")).toHaveLength(0);
    expect(sent("GET", "/api/v1/queue")).toHaveLength(0); // nothing asks for the queue there
  });
});
