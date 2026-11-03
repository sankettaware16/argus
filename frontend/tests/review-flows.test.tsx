// Reviewing an investigation in the app (Q-B2): the review form with its 409 kept, Accept, Ask
// the AI investigator, and the gold box; each change through the form or the confirm dialog, and
// what a person reads when it fails.
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import type { AssessmentOut, GoldItemOut } from "../src/client/types.gen";
import { BASE, detail, ID, ID3, must, renderApp, requests, SESSION, sent, server, sessionWith, setLeaveSpy, shellHandlers, mockApi } from "./helpers";

mockApi();

const API = `${BASE}/api/v1/investigations/${ID}`;
const PROPOSAL: AssessmentOut = {
  id: 7, assessor: "agent@1", source: "the AI investigator", status: "proposed", outcome: "true_positive", confidence: 0.75,
  decided_by: "agent@1#m", reasons: ["It beacons."], run: null, reading: null, created_at: "2026-10-09T13:00:00Z", finished_at: "2026-10-09T13:05:00Z",
};
const GOLD: GoldItemOut = { split: "dev", why: ["a kind"], suggestion: { outcome: "benign_expected", source: "signals", reasons: ["no hit"] }, outcome: null, note: null, answered_by: null, answered_at: null };

function reads(d = detail()) {
  server.use(
    http.get(API, () => HttpResponse.json(d)),
    http.get(`${API}/reports`, () => HttpResponse.json({ items: [], logs_hidden: false })),
  );
}

async function open(d = detail(), search = "") {
  reads(d);
  const view = renderApp(`/investigations/${ID}${search}`);
  await screen.findByText("Your review");
  return view;
}

const outcome = () => screen.getByLabelText(/^Outcome/);
const note = () => screen.getByLabelText("Note");

describe("the review form", () => {
  it("is not there for an account that may only view, which is told why", async () => {
    server.use(...shellHandlers(sessionWith(["view"])));
    await open(detail({ acceptable_assessment_id: 7, assessments: [PROPOSAL], ask_available: true, gold: GOLD }));
    expect(screen.queryByRole("button", { name: "Mark reviewed" })).toBeNull();
    expect(screen.getAllByText(/Your account may view only/)).toHaveLength(2); // the review form and the gold box
    expect(screen.queryByRole("button", { name: /^Accept/ })).toBeNull();
  });

  it("will not mark reviewed without an outcome, and says so without sending anything", async () => {
    const user = userEvent.setup();
    await open();
    await user.click(screen.getByRole("button", { name: "Mark reviewed" }));
    expect((await screen.findByText("Choose an outcome to mark it reviewed.")).getAttribute("role")).toBe("alert");
    expect(sent("POST", "/api")).toHaveLength(0);
    await user.click(screen.getByRole("button", { name: "Add note only" }));
    expect(await screen.findByText("Write a note first.")).toBeTruthy();
    expect(sent("POST", "/api")).toHaveLength(0);
  });

  it("sends the outcome and note with what it saw, the CSRF token, then says it was saved and reads again", async () => {
    const user = userEvent.setup();
    let version = 3;
    server.use(http.post(`${API}/reviews`, () => HttpResponse.json({ review_id: 11, version, gold_saved: false }, { status: 201 })));
    await open(detail({}, { latest_review: 5 }));
    await user.selectOptions(outcome(), "benign_policy");
    await user.type(note(), "Scanner of the lab.");
    await user.click(screen.getByRole("button", { name: "Mark reviewed" }));
    await screen.findByText("Saved: marked reviewed.", { selector: "p" });
    const [post] = sent("POST", "/api/v1/investigations");
    expect(post?.path).toBe(`/api/v1/investigations/${ID}/reviews`);
    expect(JSON.parse(post?.body ?? "")).toEqual({ action: "reviewed", outcome: "benign_policy", note: "Scanner of the lab.", seen_review: 5, seen_version: 3, also_gold: false });
    await waitFor(() => expect(sent("GET", `/api/v1/investigations/${ID}`).filter((r) => r.path === `/api/v1/investigations/${ID}`).length).toBe(2));
    expect((note() as HTMLTextAreaElement).value).toBe("");
    expect((outcome() as HTMLSelectElement).value).toBe("");
    version = 4;
  });

  it("asks for a follow-up with or without an outcome, and adds a note alone", async () => {
    const user = userEvent.setup();
    server.use(http.post(`${API}/reviews`, () => HttpResponse.json({ review_id: 12, version: 3, gold_saved: false }, { status: 201 })));
    await open();
    await user.click(screen.getByRole("button", { name: "Needs follow-up" }));
    await screen.findByText("Saved: follow-up requested.", { selector: "p" });
    expect(JSON.parse(sent("POST", "/api")[0]?.body ?? "")).toEqual({ action: "follow_up", outcome: null, note: null, seen_review: null, seen_version: 3, also_gold: false });
    await user.type(note(), "Look at the host.");
    await user.click(screen.getByRole("button", { name: "Add note only" }));
    await screen.findByText("Saved: note added.", { selector: "p" });
    expect(JSON.parse(sent("POST", "/api")[1]?.body ?? "")).toEqual({ action: "note", note: "Look at the host.", seen_review: null, seen_version: 3 });
  });

  it("keeps what was typed when someone else got there first (409), reads again, and sends the new versions next", async () => {
    const user = userEvent.setup();
    let reading = 0;
    server.use(
      http.get(API, () => {
        reading += 1;
        return HttpResponse.json(reading === 1 ? detail() : detail({}, { version: 4, latest_review: 9, human_state: "reviewed" }));
      }),
      http.get(`${API}/reports`, () => HttpResponse.json({ items: [], logs_hidden: false })),
    );
    let answers = 0;
    server.use(
      http.post(`${API}/reviews`, () => {
        answers += 1;
        return answers === 1 ? HttpResponse.json({ detail: "someone else reviewed it", code: "conflict" }, { status: 409 }) : HttpResponse.json({ review_id: 13, version: 4, gold_saved: false }, { status: 201 });
      }),
    );
    renderApp(`/investigations/${ID}`);
    await screen.findByText("Your review");
    await user.selectOptions(outcome(), "true_positive");
    await user.type(note(), "My reason, typed with care.");
    await user.click(screen.getByRole("button", { name: "Mark reviewed" }));
    const alert = await screen.findByText(/Someone else reviewed this, or new alerts arrived, while you were reading\. Nothing was saved\./);
    expect(alert.textContent).toContain("What you typed is still here");
    await waitFor(() => expect(reading).toBe(2));
    expect((note() as HTMLTextAreaElement).value).toBe("My reason, typed with care.");
    expect((outcome() as HTMLSelectElement).value).toBe("true_positive");
    expect(await screen.findAllByText("Reviewed", { selector: "span" })).not.toHaveLength(0);
    // the read-again investigation is not the one she saw: she says she looked before anything is sent (review B2-R1)
    await screen.findByText(/This investigation changed while you were typing/);
    await user.click(screen.getByRole("button", { name: "Mark reviewed" }));
    expect(sent("POST", "/api/v1/investigations")).toHaveLength(1);
    await user.click(screen.getByRole("button", { name: "I have looked at what changed" }));
    expect(screen.queryByText(/Someone else reviewed this, or new alerts arrived/)).toBeNull(); // the refusal's words are answered
    await user.click(screen.getByRole("button", { name: "Mark reviewed" }));
    await screen.findByText("Saved: marked reviewed.", { selector: "p" });
    const posts = sent("POST", "/api/v1/investigations");
    expect(posts).toHaveLength(2);
    expect(JSON.parse(posts[0]?.body ?? "")).toMatchObject({ seen_review: null, seen_version: 3 });
    expect(JSON.parse(posts[1]?.body ?? "")).toMatchObject({ seen_review: 9, seen_version: 4, note: "My reason, typed with care." });
  });

  it("also saves the gold-set answer only when the box is ticked, which it is not until the person ticks it (AR4 review)", async () => {
    const user = userEvent.setup();
    server.use(http.post(`${API}/reviews`, () => HttpResponse.json({ review_id: 14, version: 3, gold_saved: true }, { status: 201 })));
    await open(detail({ gold: GOLD }));
    const box = screen.getByLabelText("Also save the outcome as my gold-set answer") as HTMLInputElement;
    expect(box.checked).toBe(false);
    await user.selectOptions(outcome(), "benign_expected");
    await user.click(screen.getByRole("button", { name: "Mark reviewed" }));
    await waitFor(() => expect(sent("POST", "/api")).toHaveLength(1));
    expect(JSON.parse(sent("POST", "/api")[0]?.body ?? "")).toMatchObject({ also_gold: false });
    await user.click(box);
    await user.selectOptions(outcome(), "benign_expected");
    await user.click(screen.getByRole("button", { name: "Mark reviewed" }));
    expect((await screen.findAllByText(/Also saved as your gold-set answer/, { selector: "p" })).length).toBeGreaterThan(0);
    expect(JSON.parse(sent("POST", "/api")[1]?.body ?? "")).toMatchObject({ also_gold: true });
  });
});

describe("the gold box", () => {
  it("shows the suggestion as ARGUS's, saves a correct outcome, and offers the next item", async () => {
    const user = userEvent.setup();
    server.use(http.post(`${API}/gold`, () => HttpResponse.json({ next_investigation_id: ID3 })));
    await open(detail({ gold: GOLD }));
    const box = screen.getByRole("region", { name: "Gold set: your answer" });
    expect(within(box).getByText(/the suggestion is ARGUS's, not an answer/)).toBeTruthy();
    expect(within(box).getByText("not given yet")).toBeTruthy();
    await user.click(within(box).getByRole("button", { name: "Save answer" }));
    expect(await within(box).findByText("Choose the correct outcome first.")).toBeTruthy();
    expect(sent("POST", "/api")).toHaveLength(0);
    await user.selectOptions(within(box).getByLabelText("Correct outcome"), "true_positive");
    await user.type(within(box).getByLabelText(/^Why/), "It beacons.");
    await user.click(within(box).getByRole("button", { name: "Save answer" }));
    const link = await within(box).findByRole("link", { name: "Go to the next unanswered item" });
    expect(link.getAttribute("href")).toBe(`/app/investigations/${ID3}`);
    expect(JSON.parse(sent("POST", "/api")[0]?.body ?? "")).toEqual({ outcome: "true_positive", note: "It beacons." });
  });

  it("says when no item is left, and says why a view-only account cannot answer", async () => {
    const user = userEvent.setup();
    server.use(http.post(`${API}/gold`, () => HttpResponse.json({ next_investigation_id: null })));
    await open(detail({ gold: { ...GOLD, outcome: "inconclusive", note: "Unsure.", answered_by: "Ravi", answered_at: "2026-10-10T00:00:00Z" } }));
    const box = screen.getByRole("region", { name: "Gold set: your answer" });
    expect(box.textContent).toContain("Inconclusive — Unsure.");
    await user.selectOptions(within(box).getByLabelText("Correct outcome"), "true_positive");
    await user.click(within(box).getByRole("button", { name: "Save answer" }));
    expect(await within(box).findByText("No unanswered gold-set item is left.")).toBeTruthy();
  });
});

describe("accepting a proposal", () => {
  it("shows the exact request first, sends exactly that, and says it is done", async () => {
    const user = userEvent.setup();
    server.use(http.post(`${API}/accept`, () => HttpResponse.json({ assessment_id: 7, investigation_id: ID })));
    await open(detail({ acceptable_assessment_id: 7, assessments: [PROPOSAL] }), "?tab=ai");
    await user.click(must(screen.getAllByRole("button", { name: "Accept: True positive" })[0]));
    const dialog = await screen.findByRole("alertdialog");
    expect(within(dialog).getByTestId("payload").textContent).toBe('{\n  "assessment_id": 7\n}');
    expect(dialog.textContent).toContain(`/api/v1/investigations/${ID}/accept`);
    await waitFor(() => expect(document.activeElement?.textContent).toBe("Cancel"));
    await user.click(within(dialog).getByRole("button", { name: "Accept" }));
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());
    expect(screen.getByText("Accepted: True positive.", { selector: "p" })).toBeTruthy();
    const [post] = sent("POST", "/api");
    expect(post?.body).toBe('{\n  "assessment_id": 7\n}');
  });

  it("keeps the dialog open and says why when the proposal moved on (409)", async () => {
    const user = userEvent.setup();
    server.use(http.post(`${API}/accept`, () => HttpResponse.json({ detail: "the proposal changed (new alerts, a newer assessment, or someone reviewed it): nothing was saved", code: "conflict" }, { status: 409 })));
    await open(detail({ acceptable_assessment_id: 7, assessments: [PROPOSAL] }), "?tab=ai");
    await user.click(must(screen.getAllByRole("button", { name: "Accept: True positive" })[0]));
    const dialog = await screen.findByRole("alertdialog");
    await user.click(within(dialog).getByRole("button", { name: "Accept" }));
    expect((await within(dialog).findByRole("alert")).textContent).toMatch(/the proposal changed .* nothing was saved/);
    expect(sent("POST", "/api")).toHaveLength(1);
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());
    await waitFor(() => expect(sent("GET", `/api/v1/investigations/${ID}`).filter((r) => r.path === `/api/v1/investigations/${ID}`).length).toBeGreaterThanOrEqual(2));
  });

  it("is offered only for the current proposal of an investigation not reviewed", async () => {
    await open(detail({ acceptable_assessment_id: null, assessments: [PROPOSAL] }));
    expect(screen.queryByRole("button", { name: /^Accept/ })).toBeNull();
  });
});

describe("asking the AI investigator", () => {
  it("sends one request with no body, after showing it, and says it was asked", async () => {
    const user = userEvent.setup();
    server.use(http.post(`${API}/assess`, () => HttpResponse.json({ result: "queued" }, { status: 202 })));
    await open(detail({ ask_available: true }));
    await user.click(screen.getByRole("tab", { name: /AI assessment/ }));
    await user.click(await screen.findByRole("button", { name: "Ask the AI investigator now" }));
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog.textContent).toContain("No body: the request sends nothing else.");
    await user.click(within(dialog).getByRole("button", { name: "Ask now" }));
    await screen.findByText(/Asked\. The AI investigator looks within a few minutes/, { selector: "p" });
    expect(sent("POST", "/api")).toEqual([{ method: "POST", path: `/api/v1/investigations/${ID}/assess`, body: "" }]);
  });

  it("says when it had already assessed what the investigation shows, and when it is not on this server", async () => {
    const user = userEvent.setup();
    let answer: () => Response = () => HttpResponse.json({ result: "exists" }, { status: 202 });
    server.use(http.post(`${API}/assess`, () => answer()));
    await open(detail({ ask_available: true }));
    await user.click(screen.getByRole("tab", { name: /AI assessment/ }));
    await user.click(await screen.findByRole("button", { name: "Ask the AI investigator now" }));
    await user.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Ask now" }));
    await screen.findByText("The AI investigator has already assessed what this shows now.", { selector: "p" });
    answer = () => HttpResponse.json({ detail: "the AI investigator is not available on this server", code: "unavailable" }, { status: 503 });
    await user.click(await screen.findByRole("button", { name: "Ask the AI investigator now" }));
    const dialog = await screen.findByRole("alertdialog");
    await user.click(within(dialog).getByRole("button", { name: "Ask now" }));
    expect((await within(dialog).findByRole("alert")).textContent).toBe("the AI investigator is not available on this server");
  });
});

describe("what a person reads when a change fails", () => {
  const cases: [string, () => Response, RegExp][] = [
    ["a forbidden account", () => HttpResponse.json({ detail: "your account may not do this: it needs the review capability", code: "forbidden" }, { status: 403 }), /your account may not do this: it needs the review capability/],
    ["a refused body", () => HttpResponse.json({ detail: "body.outcome: must be one of 'a', 'b'", code: "invalid" }, { status: 422 }), /ARGUS did not accept that: body\.outcome/],
    ["a vanished investigation", () => HttpResponse.json({ detail: "no such investigation", code: "not_found" }, { status: 404 }), /no such investigation/],
    ["too many requests", () => HttpResponse.json({ detail: "x", code: "internal" }, { status: 429 }), /Too many requests just now; wait a minute and try again\./],
    ["an unreachable database", () => HttpResponse.json({ detail: "ARGUS cannot reach its database; try again in a minute", code: "unavailable" }, { status: 503 }), /ARGUS cannot reach its database; try again in a minute/],
    ["a server error", () => HttpResponse.json({ detail: "boom", code: "internal" }, { status: 500 }), /Something went wrong in ARGUS; it has been logged/],
    ["no answer at all", () => HttpResponse.error(), /ARGUS could not be reached/],
  ];

  it.each(cases)("%s: said plainly, sent once, never retried, what was typed kept", async (_name, answer, words) => {
    const user = userEvent.setup();
    server.use(http.post(`${API}/reviews`, () => answer()));
    await open();
    await user.selectOptions(outcome(), "inconclusive");
    await user.type(note(), "keep me");
    await user.click(screen.getByRole("button", { name: "Mark reviewed" }));
    const alert = await screen.findByText(words, { selector: "p" });
    expect(alert.getAttribute("role")).toBe("alert");
    await new Promise((resolve) => setTimeout(resolve, 150));
    expect(sent("POST", "/api")).toHaveLength(1);
    expect((note() as HTMLTextAreaElement).value).toBe("keep me");
  });

  it("reads the session again once on a refused CSRF token, tells the person to try again, and resends nothing", async () => {
    const user = userEvent.setup();
    let sessions = 0;
    server.use(
      http.get(`${BASE}/api/v1/session`, () => {
        sessions += 1;
        return HttpResponse.json({ ...SESSION, csrf_token: `token-${sessions}` });
      }),
      http.post(`${API}/reviews`, () => HttpResponse.json({ detail: "missing or wrong X-CSRF-Token", code: "csrf" }, { status: 403 })),
    );
    await open();
    expect(sessions).toBe(1);
    await user.selectOptions(outcome(), "inconclusive");
    await user.click(screen.getByRole("button", { name: "Mark reviewed" }));
    await screen.findByText(/This page was out of date with the server, so it has been refreshed\. Nothing was changed: try again\./, { selector: "p" });
    expect(sessions).toBe(2);
    expect(sent("POST", "/api")).toHaveLength(1);
    expect(requests.filter((r) => r.path === "/api/v1/session")).toHaveLength(2);
  });

  it("sends the person to sign in when the session ended, and the page does not crash", async () => {
    const user = userEvent.setup();
    server.use(http.post(`${API}/reviews`, () => HttpResponse.json({ detail: "sign in first", code: "unauthenticated" }, { status: 401 })));
    const urls: string[] = [];
    setLeaveSpy(urls);
    await open();
    await user.selectOptions(outcome(), "inconclusive");
    await user.click(screen.getByRole("button", { name: "Mark reviewed" }));
    await screen.findByText("Your session ended. Sign in again to continue.", { selector: "p" });
    expect(urls).toHaveLength(1);
    expect(urls[0]).toMatch(/^\/signin\?next=%2Fapp&why=ended$/);
    expect(sent("POST", "/api")).toHaveLength(1);
  });
});

describe("hostile text", () => {
  it("in an investigation's name, notes and history is shown as text only", async () => {
    const hostile = '<img src=x onerror="window.__pwned=1"> \u202e';
    await open(detail({ reviews: [{ id: 1, action: "note", alert_count: 2, created_at: "2026-10-10T00:00:00Z", note: hostile, outcome: null, reviewer: hostile, version: 3 }] }, { rule_name: hostile }));
    expect(document.querySelector("main img")).toBeNull();
    expect(screen.getByRole("heading", { level: 1 }).textContent).toContain("<img src=x");
    await userEvent.setup().click(screen.getByRole("tab", { name: /History/ }));
    expect((await screen.findAllByText(/<img src=x/)).length).toBeGreaterThanOrEqual(2);
    expect(document.querySelector("main img")).toBeNull();
    expect((window as unknown as { __pwned?: number }).__pwned).toBeUndefined();
  });
});

describe("one send at a time", () => {
  it("sends a review once however fast the button is pressed, and the gold answer too", async () => {
    const user = userEvent.setup();
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    server.use(
      http.post(`${API}/reviews`, async () => {
        await gate;
        return HttpResponse.json({ review_id: 15, version: 3, gold_saved: false }, { status: 201 });
      }),
      http.post(`${API}/gold`, async () => {
        await gate;
        return HttpResponse.json({ next_investigation_id: null });
      }),
    );
    await open(detail({ gold: GOLD }));
    await user.selectOptions(outcome(), "inconclusive");
    const mark = screen.getByRole("button", { name: "Mark reviewed" });
    await user.dblClick(mark);
    fireEvent.click(mark);
    const box = screen.getByRole("region", { name: "Gold set: your answer" });
    await user.selectOptions(within(box).getByLabelText("Correct outcome"), "true_positive");
    const save = within(box).getByRole("button", { name: "Save answer" });
    await user.dblClick(save);
    fireEvent.submit(must(save.closest("form")));
    await new Promise((resolve) => setTimeout(resolve, 100));
    release();
    await screen.findByText("Saved: marked reviewed.", { selector: "p" });
    await screen.findByText("Saved your gold-set answer.", { selector: "p" });
    expect(sent("POST", `/api/v1/investigations/${ID}/reviews`)).toHaveLength(1);
    expect(sent("POST", `/api/v1/investigations/${ID}/gold`)).toHaveLength(1);
  });
});
