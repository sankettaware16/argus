// The independent review of Q-B2 (docs/gates/q-b2.md, "Review"): each finding as a test that failed
// before its fix. R1 a review is sent only against versions the person saw; R3 what is typed for one
// investigation is never carried to another; R4 the assessment poll stops when it is refused; R5 the
// focus stays where the person is while a change is sent and goes to the investigation's title when
// the button they used goes away; R7 the Find box follows the address.
import { act, fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { delay, http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AssessmentOut, GoldItemOut } from "../src/client/types.gen";
import { investigationOptions } from "../src/lib/queries";
import { BASE, detail, ID, ID2, investigation, layout, mockApi, must, renderApp, REPORT, requests, sent, server, sessionWith, shellHandlers, viewport } from "./helpers";

mockApi();

const API = `${BASE}/api/v1/investigations/${ID}`;
const API2 = `${BASE}/api/v1/investigations/${ID2}`;
const NOREPORTS = () => HttpResponse.json({ items: [], logs_hidden: false });
const GOLD: GoldItemOut = { split: "dev", why: ["a kind"], suggestion: { outcome: "benign_expected", source: "signals", reasons: ["no hit"] }, outcome: null, note: null, answered_by: null, answered_at: null };
const QUEUED: AssessmentOut = { id: 7, assessor: "agent@1", source: "the AI investigator", status: "queued", outcome: null, confidence: null, decided_by: "agent@1", reasons: [], run: null, reading: null, created_at: "2026-10-09T13:00:00Z", finished_at: null };
const PROPOSAL: AssessmentOut = { ...QUEUED, status: "proposed", outcome: "true_positive", confidence: 0.75, reasons: ["It beacons."], finished_at: "2026-10-09T13:05:00Z" };

const radio = (value: string) => document.querySelector(`form[aria-label="Your decision"] input[type="radio"][value="${value}"]`) as HTMLInputElement;
const pick = (user: { click: (el: Element) => Promise<void> }, value: string) => user.click(radio(value));
const chosen = () => document.querySelector<HTMLInputElement>('form[aria-label="Your decision"] input[type="radio"]:checked')?.value ?? "";
const notice = () => screen.queryByText(/This alert group changed while you were deciding/);
const looked = () => screen.getByRole("button", { name: "I have looked at what changed" });

afterEach(() => vi.useRealTimers());

describe("B2-R1: a review is sent against the versions the person saw", () => {
  async function typing(moved = true) {
    const user = userEvent.setup();
    server.use(
      http.get(API, () => HttpResponse.json(detail({}, { version: 3, latest_review: null }))),
      http.get(`${API}/reports`, NOREPORTS),
      http.post(`${API}/reviews`, () => HttpResponse.json({ review_id: 11, version: 4, gold_saved: false }, { status: 201 })),
    );
    const view = renderApp(`/investigations/${ID}`);
    await screen.findByText("Your decision");
    await pick(user, "benign_policy");
    await user.type(screen.getByLabelText("Note"), "Scanner of the lab.");
    // what the 15 s poll does while an assessment waits (components/investigation/actions.tsx)
    if (moved) act(() => view.queries.setQueryData(["investigation", ID], detail({}, { version: 4, latest_review: 9, human_state: "reviewed" })));
    return { user, ...view };
  }

  it("says it changed while she typed, and sends nothing (any of the three buttons, or Enter) until she says she looked", async () => {
    const { user } = await typing();
    expect(await screen.findByText(/This alert group changed while you were deciding/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Save decision" }));
    await user.click(screen.getByRole("checkbox", { name: /Come back to it/ })); // a follow-up waits the same way
    for (const name of ["Save, and come back to it", "Add note only"]) await user.click(screen.getByRole("button", { name }));
    fireEvent.submit(screen.getByRole("form", { name: "Your decision" }));
    expect(sent("POST", "/api")).toHaveLength(0);
    expect(chosen()).toBe("benign_policy"); // what she typed is still there
    expect((screen.getByLabelText("Note") as HTMLTextAreaElement).value).toBe("Scanner of the lab.");
    expect(document.activeElement).toBe(looked()); // a press that did nothing leads her to the one thing that continues
  });

  it("sends the versions she has now looked at, once she says so, with what she typed", async () => {
    const { user } = await typing();
    await user.click(await screen.findByRole("button", { name: "I have looked at what changed" }));
    expect(notice()).toBeNull();
    await user.click(screen.getByRole("button", { name: "Save decision" }));
    await screen.findByText("Saved: your decision.", { selector: "p" });
    expect(sent("POST", "/api")).toHaveLength(1);
    expect(JSON.parse(must(sent("POST", "/api")[0]).body)).toMatchObject({ action: "reviewed", outcome: "benign_policy", note: "Scanner of the lab.", seen_review: 9, seen_version: 4 });
  });

  it("does not say it changed when nothing moved, and not after her own save either", async () => {
    const user = userEvent.setup();
    let reading = 0;
    server.use(
      http.get(API, () => {
        reading += 1;
        return HttpResponse.json(reading === 1 ? detail() : detail({}, { version: 4, latest_review: 11, human_state: "reviewed" }));
      }),
      http.get(`${API}/reports`, NOREPORTS),
      http.post(`${API}/reviews`, () => HttpResponse.json({ review_id: 11, version: 4, gold_saved: false }, { status: 201 })),
    );
    renderApp(`/investigations/${ID}`);
    await screen.findByText("Your decision");
    expect(notice()).toBeNull();
    await pick(user, "benign_policy");
    await user.click(screen.getByRole("button", { name: "Save decision" }));
    await screen.findByText("Saved: your decision.", { selector: "p" });
    await waitFor(() => expect(reading).toBe(2));
    await screen.findAllByText("Reviewed", { selector: "span" });
    expect(notice()).toBeNull();
    await pick(user, "true_positive");
    await user.click(screen.getByRole("button", { name: "Save decision" }));
    expect((await screen.findByRole("alertdialog")).textContent).toContain("Marking it real opens a possible incident");
    expect(sent("POST", "/api")).toHaveLength(1); // nothing before the dialog's own button (A-3)
    await user.click(screen.getByRole("button", { name: "Mark it real" }));
    await waitFor(() => expect(sent("POST", "/api")).toHaveLength(2));
    expect(JSON.parse(must(sent("POST", "/api")[1]).body)).toMatchObject({ seen_review: 11, seen_version: 4 });
  });
});

describe("B2-R2: the investigation's AI tabs for an account without log access", () => {
  const HIDDEN = "Hidden: needs log access in ELK.";
  const RUN = {
    answer: { outcome: "true_positive" as const, confidence: 0.8, explanation: HIDDEN, hypotheses: [{ name: HIDDEN, evidence_for: [], evidence_against: [] }], cites: [HIDDEN] },
    checks: [{ tool: "proxy.host", value: "10.0.0.1", result: HIDDEN }],
    specialists: [{ domain: "proxy", notes: HIDDEN }],
    rounds: 2, calls: 3, models: ["m"], cost_usd: 0.01, seconds: 1,
  };
  const WITH_RUN: AssessmentOut = { ...PROPOSAL, reasons: [HIDDEN], run: RUN };

  it("shows the hidden marker where the explanation, cites, checks and notes were, and says why", async () => {
    server.use(...shellHandlers(sessionWith(["view", "review"])), http.get(API, () => HttpResponse.json(detail({ assessments: [WITH_RUN] }))), http.get(`${API}/reports`, NOREPORTS));
    renderApp(`/investigations/${ID}?tab=ai`);
    const note = await screen.findByTestId("logs-hidden");
    expect(note.textContent).toMatch(/cannot read the logs in ELK/);
    const card = screen.getByRole("article", { name: /proposes Real: act on it/ });
    expect(within(card).getAllByText(HIDDEN).length).toBeGreaterThanOrEqual(5); // explanation, hypothesis, cite, check, specialist
    expect(within(card).getByText("proxy.host")).toBeTruthy(); // what was asked stays
  });

  it("says nothing about it to an account that may read the logs", async () => {
    server.use(http.get(API, () => HttpResponse.json(detail({ assessments: [{ ...WITH_RUN, run: { ...RUN, checks: [{ tool: "proxy.host", value: "10.0.0.1", result: "59 rows" }] } }] }))), http.get(`${API}/reports`, NOREPORTS));
    renderApp(`/investigations/${ID}?tab=ai`);
    await screen.findByText("59 rows");
    expect(screen.queryByTestId("logs-hidden")).toBeNull();
  });
});

describe("B2-R3: what is typed for one investigation is not carried to another", () => {
  it("the gold box starts empty for the next investigation and posts nothing from the last one", async () => {
    const user = userEvent.setup();
    const second = { ...detail({ gold: GOLD }), investigation: investigation(ID2, { rule_name: "Second one" }) };
    server.use(
      http.get(API, () => HttpResponse.json(detail({ gold: GOLD }))),
      http.get(API2, () => HttpResponse.json(second)),
      http.get(`${API}/reports`, NOREPORTS),
      http.get(`${API2}/reports`, NOREPORTS),
    );
    const { router, queries } = renderApp(`/investigations/${ID}`);
    await screen.findByText("Gold set: your answer");
    await queries.prefetchQuery(investigationOptions(ID2)); // looked at a moment ago: cached, so shown at once
    await user.selectOptions(screen.getByLabelText("Correct outcome"), "true_positive");
    await user.type(screen.getByLabelText(/^Why/), "typed for the FIRST investigation");
    await act(async () => {
      await router.navigate({ to: "/investigations/$id", params: { id: ID2 } });
    });
    await screen.findByText("Second one");
    expect((screen.getByLabelText("Correct outcome") as HTMLSelectElement).value).toBe("");
    expect((screen.getByLabelText(/^Why/) as HTMLTextAreaElement).value).toBe("");
    await user.click(screen.getByRole("button", { name: "Save answer" }));
    expect(await screen.findByText("Choose the correct outcome first.")).toBeTruthy();
    expect(sent("POST", "/api")).toHaveLength(0);
  });

  it("the alerts tab's column choice and open raw alert are the investigation's own", async () => {
    const user = userEvent.setup();
    const fields = [{ field: "source.ip", count: 2 }];
    const second = { ...detail({ alert_fields: fields }), investigation: investigation(ID2, { rule_name: "Second one" }) };
    server.use(
      http.get(API, () => HttpResponse.json(detail({ alert_fields: fields }))),
      http.get(API2, () => HttpResponse.json(second)),
      http.get(`${API}/reports`, NOREPORTS),
      http.get(`${API2}/reports`, NOREPORTS),
      http.get(`${API}/alerts`, () => HttpResponse.json({ total: 0, columns: [], items: [] })),
      http.get(`${API2}/alerts`, () => HttpResponse.json({ total: 0, columns: [], items: [] })),
    );
    const { router, queries } = renderApp(`/investigations/${ID}?tab=alerts`);
    await screen.findByText("Choose columns (0 of 1 fields shown)");
    await queries.prefetchQuery(investigationOptions(ID2));
    await user.click(screen.getByText(/^Choose columns/));
    await user.click(screen.getByLabelText(/source\.ip/));
    await user.click(screen.getByRole("button", { name: "Show these columns" }));
    await waitFor(() => expect(sent("GET", `/api/v1/investigations/${ID}/alerts?columns=source.ip`)).toHaveLength(1));
    await act(async () => {
      await router.navigate({ to: "/investigations/$id", params: { id: ID2 }, search: { tab: "alerts" } });
    });
    await screen.findByText("Second one");
    await waitFor(() => expect(sent("GET", `/api/v1/investigations/${ID2}/alerts`)).toHaveLength(1));
    expect(must(sent("GET", `/api/v1/investigations/${ID2}/alerts`)[0]).path).toBe(`/api/v1/investigations/${ID2}/alerts`); // no columns of the other one
    expect((screen.getByLabelText(/source\.ip/) as HTMLInputElement).checked).toBe(false);
  });
});

describe("B2-R4: the assessment poll stops when it is refused", () => {
  for (const status of [404, 429, 503]) {
    it(`after a ${status} it does not ask again`, async () => {
      let reads = 0;
      server.use(
        http.get(API, () => {
          reads += 1;
          return reads === 1 ? HttpResponse.json(detail({ assessments: [QUEUED] })) : HttpResponse.json({ detail: "refused", code: "x" }, { status });
        }),
        http.get(`${API}/reports`, NOREPORTS),
      );
      vi.useFakeTimers({ shouldAdvanceTime: true, toFake: ["setInterval", "setTimeout", "clearInterval", "clearTimeout"] });
      renderApp(`/investigations/${ID}`);
      await screen.findByText("Your decision");
      for (let i = 0; i < 6; i++)
        await act(async () => {
          await vi.advanceTimersByTimeAsync(15_000);
        });
      const gets = requests.filter((r) => r.method === "GET" && r.path === `/api/v1/investigations/${ID}`).length;
      expect(gets).toBe(2); // the first read, one poll that was refused, and no more
    });
  }

  it("still asks every 15 s while the answers are good", async () => {
    let reads = 0;
    server.use(
      http.get(API, () => {
        reads += 1;
        return HttpResponse.json(detail({ assessments: [QUEUED] }));
      }),
      http.get(`${API}/reports`, NOREPORTS),
    );
    vi.useFakeTimers({ shouldAdvanceTime: true, toFake: ["setInterval", "setTimeout", "clearInterval", "clearTimeout"] });
    renderApp(`/investigations/${ID}`);
    await screen.findByText("Your decision");
    for (let i = 0; i < 3; i++)
      await act(async () => {
        await vi.advanceTimersByTimeAsync(15_000);
      });
    expect(reads).toBeGreaterThanOrEqual(4);
  });
});

describe("B2-R5: the focus stays with the person", () => {
  it("a keyboard review keeps the focus on the button that was pressed while it is sent, and after", async () => {
    const user = userEvent.setup();
    server.use(
      http.get(API, () => HttpResponse.json(detail())),
      http.get(`${API}/reports`, NOREPORTS),
      http.post(`${API}/reviews`, async () => {
        await delay(150);
        return HttpResponse.json({ review_id: 11, version: 3, gold_saved: false }, { status: 201 });
      }),
    );
    renderApp(`/investigations/${ID}`);
    await screen.findByText("Your decision");
    await pick(user, "benign_policy");
    const button = screen.getByRole("button", { name: "Save decision" });
    button.focus();
    await user.keyboard("{Enter}");
    expect(button.getAttribute("aria-disabled")).toBe("true"); // busy, but still a button the focus may stay on
    expect(button.hasAttribute("disabled")).toBe(false);
    expect(document.activeElement).toBe(button);
    await screen.findByText("Saved: your decision.", { selector: "p" });
    await waitFor(() => expect(button.getAttribute("aria-disabled")).not.toBe("true"));
    expect(document.activeElement).toBe(button);
    expect(sent("POST", "/api")).toHaveLength(1);
  });

  it("a button that is busy sends nothing when it is pressed again", async () => {
    const user = userEvent.setup();
    server.use(
      http.get(API, () => HttpResponse.json(detail())),
      http.get(`${API}/reports`, NOREPORTS),
      http.post(`${API}/reviews`, async () => {
        await delay(200);
        return HttpResponse.json({ review_id: 11, version: 3, gold_saved: false }, { status: 201 });
      }),
    );
    renderApp(`/investigations/${ID}`);
    await screen.findByText("Your decision");
    await pick(user, "benign_policy");
    await user.click(screen.getByRole("button", { name: "Save decision" }));
    await user.click(screen.getByRole("button", { name: "Add note only" }));
    await user.click(screen.getByRole("button", { name: "Save decision" }));
    await screen.findByText("Saved: your decision.", { selector: "p" });
    expect(sent("POST", "/api")).toHaveLength(1);
  });

  it("after Ask the AI investigator the focus goes to the title too (its button is replaced by the queued request)", async () => {
    const user = userEvent.setup();
    let asked = false;
    server.use(
      http.get(API, () => HttpResponse.json(asked ? detail({ ask_available: false, assessments: [QUEUED] }) : detail({ ask_available: true }))),
      http.get(`${API}/reports`, NOREPORTS),
      http.post(`${API}/assess`, () => {
        asked = true;
        return HttpResponse.json({ result: "queued" }, { status: 202 });
      }),
    );
    renderApp(`/investigations/${ID}?tab=ai`);
    await user.click(await screen.findByRole("button", { name: "Ask the AI investigator now" }));
    await user.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Ask now" }));
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());
    await waitFor(() => expect(screen.queryByRole("button", { name: "Ask the AI investigator now" })).toBeNull());
    await waitFor(() => expect(document.activeElement?.id).toBe("investigation-title"));
  });
});

describe("B2-R7: the Find box follows the address", () => {
  beforeEach(() => {
    layout();
    viewport(true);
  });

  it("empties when the address loses its search (Clear), and shows a new address's search", async () => {
    server.use(
      http.get(`${BASE}/api/v1/investigations`, () => HttpResponse.json({ items: [investigation(ID)], view: "all", sort: "newest", offset: 0, limit: 100, has_more: false })),
      http.get(`${BASE}/api/v1/investigations/:id`, () => HttpResponse.json(detail())),
      http.get(`${BASE}/api/v1/investigations/:id/reports`, () => HttpResponse.json({ items: [REPORT], logs_hidden: false })),
      http.get(`${BASE}/api/v1/rules`, () => HttpResponse.json([])),
    );
    const user = userEvent.setup();
    const { router } = renderApp("/inbox?view=all&kind=host&value=lab-pc-7");
    await screen.findByRole("grid", { name: "Investigations" });
    const value = () => screen.getByLabelText("Value") as HTMLInputElement;
    const kind = () => screen.getByLabelText("Find") as HTMLSelectElement;
    expect([kind().value, value().value]).toEqual(["host", "lab-pc-7"]);
    await user.click(screen.getByRole("link", { name: "Clear" }));
    await waitFor(() => expect(router.state.location.search).not.toHaveProperty("value"));
    await waitFor(() => expect(value().value).toBe(""));
    expect(kind().value).toBe("ip");
    // typing that is not sent stays while the address does not change
    await user.type(value(), "10.8.0.1");
    expect(value().value).toBe("10.8.0.1");
    await act(async () => {
      await router.navigate({ to: "/inbox", search: { view: "all", kind: "user", value: "asha" } });
    });
    await waitFor(() => expect([kind().value, value().value]).toEqual(["user", "asha"]));
  });
});
