// "Check more" on an investigation: one approved check on one address or domain; its cost said before,
// the exact request shown, the person's own allowance, and the record of every request with its
// E-numbers, cost and whether an assessment has read it.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it, vi } from "vitest";
import type { InvestigationCheckOut } from "../src/client/types.gen";
import { CHECK_POLL_MS } from "../src/components/investigation/CheckMore";
import { RLO } from "./caseFixtures";
import { BASE, checksOf, detail, ID, mockApi, renderApp, sent, server, sessionWith, shellHandlers } from "./helpers";

mockApi();
const API = `${BASE}/api/v1/investigations/${ID}`;

const check = (more: Partial<InvestigationCheckOut> = {}): InvestigationCheckOut => ({
  id: 7,
  version: 3,
  template: "proxy.pair",
  words: "How regularly a host reached a destination",
  entity: "10.0.0.1",
  requested_by: "asha",
  requested_at: "2026-10-26T04:00:00Z",
  status: "queued",
  status_words: "Waiting for ARGUS's service to run it",
  started_at: null,
  finished_at: null,
  requests: null,
  heavy_requests: null,
  server_ms: null,
  lines: [],
  dossier: null,
  assessed: false,
  why_not: null,
  ...more,
});

function open(checks = checksOf(), d = detail()) {
  server.use(
    http.get(API, () => HttpResponse.json(d)),
    http.get(`${API}/reports`, () => HttpResponse.json({ items: [], logs_hidden: false })),
    http.get(`${API}/checks`, () => HttpResponse.json(checks)),
  );
  return renderApp(`/investigations/${ID}`);
}

const panel = async () => within(await screen.findByRole("region", { name: "Check more" }));

describe("the form", () => {
  it("lists the approved checks with what each takes and what it costs, and the person's allowance", async () => {
    const user = userEvent.setup();
    open(checksOf(ID, { limits: { open_per_person: 5, open_now: 2, per_day: 30, today: 9 } }));
    const p = await panel();
    const choose = await p.findByRole("combobox", { name: "Check" });
    expect(within(choose).getAllByRole("option").map((o) => o.textContent)).toEqual([
      "Choose a check…",
      "A campus host's proxy traffic (heavy; takes a campus address)",
      "How regularly a host reached a destination (heavy; takes any address)",
      "Whether an address or domain is on the threat lists (light; takes an address or a domain)",
    ]);
    expect(p.getByText("You have 2 of 5 checks waiting, and have asked for 9 of 30 today.")).toBeTruthy();
    expect(p.queryByTestId("check-cost")).toBeNull();
    await user.selectOptions(choose, "proxy.pair");
    expect(p.getByTestId("check-cost").textContent).toContain("A heavy check: a search of the logs.");
    expect(p.getByTestId("check-cost").textContent).toContain("300 heavy requests and 6 minutes");
    await user.selectOptions(choose, "ti.lookup");
    expect(p.getByTestId("check-cost").textContent).toContain("A light check: one small lookup.");
  });

  it("will not ask for a value that could never be asked about, and says why", async () => {
    const user = userEvent.setup();
    open();
    const p = await panel();
    await user.selectOptions(await p.findByRole("combobox", { name: "Check" }), "proxy.pair");
    const entity = p.getByRole("textbox", { name: "Address or domain" });
    await user.type(entity, "example.org");
    expect(p.getByText("This check takes an address, not a domain name.")).toBeTruthy();
    await user.click(p.getByRole("button", { name: "Review the request" }));
    expect(screen.queryByRole("alertdialog")).toBeNull();
    await user.clear(entity);
    await user.type(entity, "not an address");
    expect(p.getByText("That is neither an address nor a domain.")).toBeTruthy();
    expect(sent("POST", "/api")).toHaveLength(0);
  });

  it("shows the exact request, with the version looked at, and sends exactly that under the person's own name", async () => {
    const user = userEvent.setup();
    open();
    server.use(http.post(`${API}/checks`, () => HttpResponse.json({ result: "queued", id: 9 }, { status: 202 })));
    const p = await panel();
    await user.selectOptions(await p.findByRole("combobox", { name: "Check" }), "proxy.pair");
    await user.type(p.getByRole("textbox", { name: "Address or domain" }), " 203.0.113.9 ");
    await user.click(p.getByRole("button", { name: "Review the request" }));
    const dialog = await screen.findByRole("alertdialog");
    const shown = within(dialog).getByTestId("payload").textContent ?? "";
    expect(JSON.parse(shown)).toEqual({ template: "proxy.pair", entity: "203.0.113.9", seen_version: 3 });
    expect(dialog.textContent).toContain(`POST/api/v1/investigations/${ID}/checks`);
    expect(dialog.textContent).toContain("about version 3 of the investigation, under your name");
    expect(dialog.textContent).toContain("A heavy check");
    await user.click(within(dialog).getByRole("button", { name: "Ask for this check" }));
    await screen.findByText(/Queued\. ARGUS runs it when the SIEM allows/, { selector: "p" });
    expect(sent("POST", "/api")[0]?.body).toBe(shown); // no requested_by: the session says whose it is
    await waitFor(() => expect(sent("GET", `/api/v1/investigations/${ID}/checks`).length).toBeGreaterThan(1));
  });

  it("says when the same check was waiting already, and when the server refuses it", async () => {
    const user = userEvent.setup();
    open();
    server.use(http.post(`${API}/checks`, () => HttpResponse.json({ result: "open", id: 7 }, { status: 202 })));
    const p = await panel();
    await user.selectOptions(await p.findByRole("combobox", { name: "Check" }), "ti.lookup");
    await user.type(p.getByRole("textbox", { name: "Address or domain" }), "example.org");
    await user.click(p.getByRole("button", { name: "Review the request" }));
    await user.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Ask for this check" }));
    await screen.findByText("The same check is waiting already.", { selector: "p" });
    server.use(http.post(`${API}/checks`, () => HttpResponse.json({ detail: "You have 5 checks waiting already: wait for them to finish.", code: "invalid" }, { status: 422 })));
    await user.type(p.getByRole("textbox", { name: "Address or domain" }), "example.net");
    await user.click(p.getByRole("button", { name: "Review the request" }));
    const dialog = await screen.findByRole("alertdialog");
    await user.click(within(dialog).getByRole("button", { name: "Ask for this check" }));
    expect((await within(dialog).findByRole("alert")).textContent).toContain("You have 5 checks waiting already");
  });

  it("is not offered once the person has the most checks waiting", async () => {
    open(checksOf(ID, { limits: { open_per_person: 5, open_now: 5, per_day: 30, today: 5 } }));
    const p = await panel();
    expect(await p.findByText("You have 5 checks waiting already: wait for one to finish.")).toBeTruthy();
    expect(p.getByRole("button", { name: "Review the request" }).getAttribute("aria-disabled")).toBe("true");
  });

  it("is not there for an account that may only view, which is told why", async () => {
    server.use(...shellHandlers(sessionWith(["view"])));
    open();
    const p = await panel();
    expect(await p.findByText(/Your account may view only: asking for a check needs the “review” capability/)).toBeTruthy();
    expect(p.queryByRole("combobox", { name: "Check" })).toBeNull();
  });

  it("suggests the investigation's own addresses", async () => {
    open(checksOf(), detail({ dossier: { version: 3, pack: "generic@12", status: "ok", partial_reason: null, created_at: "2026-10-09T13:00:00Z", facts: [], decoded_paths: [], addresses: [{ address: "203.0.113.9", kind: "public", asset: null }, { address: "bogus", kind: "invalid", asset: null }, { address: "<script>x</script>", kind: "public", asset: null }, { address: "203.0.113.9", kind: "public", asset: null }], related: [], steps: [], has_note: null, complete: true, alerts_read: 2 } }));
    await panel();
    await waitFor(() => expect([...document.querySelectorAll("datalist option")].map((o) => o.getAttribute("value"))).toEqual(["203.0.113.9"]));
  });
});

describe("the record", () => {
  it("shows a finished check's E-number, its cost, a link to the report and that nothing has read it yet", async () => {
    open(
      checksOf(ID, {
        items: [
          check({ status: "done", status_words: "Done", finished_at: "2026-10-26T04:03:00Z", requests: 1, heavy_requests: 1, server_ms: 640, dossier: "generic+wave.1@12", lines: [{ template: "proxy.pair", eid: "E4", status: "ok", server_ms: 640, heavy: true, sent: true, why_not: null }] }),
          check({ id: 6, status: "refused", status_words: "Not asked", why_not: "the rule does not read the log this check needs", template: "proxy.host", words: "A campus host's proxy traffic" }),
        ],
      }),
    );
    const p = await panel();
    const records = await p.findAllByTestId("check-record");
    const done = records[0]?.textContent?.replace(/\s+/g, " ") ?? "";
    expect(done).toContain("How regularly a host reached a destination for 10.0.0.1 Done");
    expect(done).toContain("Asked by asha at 26 Oct 2026");
    expect(done).toContain("It sent 1 request to the SIEM (1 heavy), 640 ms of SIEM time. Its answer is E4 in the report.");
    expect(done).toContain("Not yet assessed: ARGUS reads this answer in its next assessment.");
    expect(done).toContain("E4 · proxy.pair · ok · 640 ms");
    expect(within(records[0] as HTMLElement).getByRole("link", { name: "the report" }).getAttribute("href")).toBe(`/app/alert-groups/${ID}?tab=report`);
    const refused = records[1]?.textContent?.replace(/\s+/g, " ") ?? "";
    expect(refused).toContain("Not asked");
    expect(refused).toContain("Why: the rule does not read the log this check needs");
  });

  it("says an assessment has read it, and an answer ARGUS already held", async () => {
    open(checksOf(ID, { items: [check({ status: "done", status_words: "Done: ARGUS already held the answer, so nothing new was asked of the SIEM", requests: 0, heavy_requests: 0, server_ms: 0, assessed: true, lines: [{ template: "proxy.pair", eid: "E4", status: "ok", server_ms: 0, heavy: true, sent: false, why_not: null }] })] }));
    const p = await panel();
    const text = (await p.findByTestId("check-record")).textContent?.replace(/\s+/g, " ") ?? "";
    expect(text).toContain("An assessment has read it.");
    expect(text).toContain("answered from what ARGUS already held");
    expect(text).toContain("It sent 0 requests to the SIEM");
  });

  it("is read again every 15 seconds while a check waits, as a background request, and no longer once none does", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    try {
      const background: (string | null)[] = [];
      let waiting = true;
      open(checksOf(ID, { items: [check()] }));
      server.use(
        http.get(`${API}/checks`, ({ request }) => {
          background.push(request.headers.get("X-Argus-Background"));
          return HttpResponse.json(checksOf(ID, { items: [waiting ? check() : check({ status: "done", status_words: "Done", finished_at: "2026-10-26T04:03:00Z" })] }));
        }),
      );
      const p = await panel();
      await p.findByTestId("check-record");
      expect(background).toEqual([null]);
      await vi.advanceTimersByTimeAsync(CHECK_POLL_MS);
      await waitFor(() => expect(background).toEqual([null, "1"]));
      waiting = false;
      await vi.advanceTimersByTimeAsync(CHECK_POLL_MS);
      await waitFor(() => expect(background).toEqual([null, "1", "1"]));
      await p.findByText("Done");
      await vi.advanceTimersByTimeAsync(CHECK_POLL_MS * 4);
      expect(background).toHaveLength(3); // nothing waits any more: nobody asks
    } finally {
      vi.useRealTimers();
    }
  });

  it("stops asking after a refusal", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    try {
      let asked = 0;
      open(checksOf(ID, { items: [check()] }));
      server.use(
        http.get(`${API}/checks`, () => {
          asked += 1;
          return asked === 1 ? HttpResponse.json(checksOf(ID, { items: [check()] })) : HttpResponse.json({ detail: "slow down", code: "unavailable" }, { status: 503 });
        }),
      );
      const p = await panel();
      await p.findByTestId("check-record");
      await vi.advanceTimersByTimeAsync(CHECK_POLL_MS);
      await waitFor(() => expect(asked).toBe(2));
      await vi.advanceTimersByTimeAsync(CHECK_POLL_MS * 4);
      expect(asked).toBe(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it("shows a person's words as text only", async () => {
    const hostile = `<img src=x onerror="window.__pwned=1"> ${RLO}`;
    open(checksOf(ID, { items: [check({ entity: hostile, requested_by: hostile, status: "failed", status_words: "Failed", why_not: hostile })] }));
    const { container } = { container: document.body };
    const p = await panel();
    await p.findByTestId("check-record");
    expect(container.querySelector("main img")).toBeNull();
    expect(container.querySelectorAll("[data-testid=check-record] .ut-mark").length).toBeGreaterThan(2);
    expect((window as unknown as { __pwned?: number }).__pwned).toBeUndefined();
  });
});

describe("a list that cannot be read", () => {
  it("is said once with one try again, and the rest of the page still works", async () => {
    server.use(
      http.get(API, () => HttpResponse.json(detail())),
      http.get(`${API}/reports`, () => HttpResponse.json({ items: [], logs_hidden: false })),
      http.get(`${API}/checks`, () => HttpResponse.json({ detail: "boom", code: "internal" }, { status: 500 })),
    );
    renderApp(`/investigations/${ID}`);
    expect(await screen.findByText(/The checks could not be shown\./)).toBeTruthy();
    expect(screen.getByText("Your decision")).toBeTruthy();
    await new Promise((r) => setTimeout(r, 200));
    expect(sent("GET", `/api/v1/investigations/${ID}/checks`)).toHaveLength(1);
  });
});
