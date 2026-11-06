// The Reports page: the list, one report with its figures and how they are counted, the two
// downloads, and a hostile name shown as text only.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ReportOut, ReportRowOut } from "../src/client/types.gen";
import { BASE, must, renderApp, server, mockApi } from "./helpers";

mockApi();

const ROW = (id: number, more: Partial<ReportRowOut> = {}): ReportRowOut => ({
  id,
  kind: "daily",
  period_start: "2026-10-20T00:00:00Z",
  period_end: "2026-10-21T00:00:00Z",
  generated_at: "2026-10-21T02:15:00Z",
  has_prose: false,
  ...more,
});
const WEEK = ROW(2, { kind: "weekly", period_start: "2026-10-14T00:00:00Z" });
const REPORT: ReportOut = {
  ...ROW(1),
  as_at: "2026-10-21T02:15:00Z",
  text: "ARGUS daily report for the UTC day 20 Oct 2026\n- Cases suspected: 2\n",
  prose: null,
  sections: [
    {
      id: "cases",
      title: "Cases by state and age",
      notes: [],
      metrics: [
        { key: "cases.suspected", label: "Cases suspected, waiting for a first look", value: 2, unit: "count", definition: "Rows of cases in state 'suspected'." },
        { key: "cases.oldest_unclosed_age", label: "Age of the oldest unclosed case", value: null, unit: "hours", definition: "Whole hours from created_at." },
      ],
    },
    {
      id: "siem_load",
      title: "the SIEM load, by lane and in total",
      notes: ["Server time is the SIEM's own."],
      metrics: [
        { key: "siem.server_time", label: "Server time those requests took", value: 3_903_250, unit: "ms", definition: "Sum of took_ms." },
        { key: "kibana.success_rate", label: "Share of cycles that read everything", value: 66.7, unit: "percent", definition: "complete / all." },
      ],
    },
    {
      id: "active_hosts",
      title: "Still-active hosts",
      notes: [],
      metrics: [{ key: "active_hosts.host.x", label: "<img src=x onerror=alert(1)> ws-017‮", value: 3, unit: "count", definition: "Days active." }],
    },
    { id: "gaps", title: "Gaps and outages", notes: ["This section could not be read: boom"], metrics: [] },
  ],
};

describe("the list", () => {
  it("names each report by the days it covers, with when it was made, and asks the server for one kind", async () => {
    const asked: (string | null)[] = [];
    server.use(
      http.get(`${BASE}/api/v1/reports`, ({ request }) => {
        const kind = new URL(request.url).searchParams.get("kind");
        asked.push(kind);
        return HttpResponse.json([WEEK, ROW(1)].filter((r) => kind === null || r.kind === kind));
      }),
    );
    const user = userEvent.setup();
    renderApp("/reports");
    const table = await screen.findByRole("table", { name: "Reports" });
    const links = within(table).getAllByRole("link").map((a) => [a.textContent, a.getAttribute("href")]);
    expect(links).toEqual([
      ["Weekly report, 14 Oct 2026 to 20 Oct 2026", "/app/reports/2"],
      ["Daily report for 20 Oct 2026", "/app/reports/1"],
    ]);
    expect(within(table).getAllByText(/21 Oct 2026, 7:45 AM IST/).length).toBe(2);
    await user.click(screen.getByRole("button", { name: "Weekly" }));
    await waitFor(() => expect(within(screen.getByRole("table", { name: "Reports" })).getAllByRole("link").length).toBe(1));
    await user.click(screen.getByRole("button", { name: "Daily" }));
    await waitFor(() =>
      expect(within(screen.getByRole("table", { name: "Reports" })).getAllByRole("link").map((a) => a.textContent)).toEqual(["Daily report for 20 Oct 2026"]),
    );
    expect(asked).toEqual([null, "weekly", "daily"]); // the filter is the server's: older weeklies are never pushed out by dailies
  });

  it("says so when none has been made", async () => {
    server.use(http.get(`${BASE}/api/v1/reports`, () => HttpResponse.json([])));
    renderApp("/reports");
    expect(await screen.findByText("The first daily summary appears after ARGUS's first full day.")).toBeTruthy();
  });

  it("is in the menu", async () => {
    server.use(http.get(`${BASE}/api/v1/reports`, () => HttpResponse.json([])));
    renderApp("/reports");
    expect(await screen.findByRole("heading", { name: "Reports" })).toBeTruthy();
    expect(document.title).toBe("Reports · ARGUS");
    expect(screen.getAllByRole("link", { name: "Reports" }).length).toBeGreaterThan(0);
  });
});

describe("one report", () => {
  beforeEach(() => {
    server.use(http.get(`${BASE}/api/v1/reports/1`, () => HttpResponse.json(REPORT)));
  });
  afterEach(() => vi.restoreAllMocks());

  it("shows every figure as the text says it, and none as 0 when there is nothing", async () => {
    renderApp("/reports/1");
    expect(await screen.findByRole("heading", { name: "Daily report for 20 Oct 2026" })).toBeTruthy();
    const cases = within(await screen.findByRole("region", { name: "Cases by state and age" }));
    const rows = cases.getAllByRole("row").slice(1).map((r) => r.textContent);
    expect(rows).toEqual(["Cases suspected, waiting for a first look2", "Age of the oldest unclosed casen/a"]);
    const load = within(screen.getByRole("region", { name: "the SIEM load, by lane and in total" }));
    expect(load.getByText("1 h 5 min 3 s 250 ms")).toBeTruthy();
    expect(load.getByText("66.7%")).toBeTruthy();
    expect(load.getByText("Server time is the SIEM's own.")).toBeTruthy();
    expect(screen.getByText("This section could not be read: boom")).toBeTruthy();
    expect(document.title).toBe("Report · ARGUS");
  });

  it("says how each figure is counted, on demand", async () => {
    const user = userEvent.setup();
    renderApp("/reports/1");
    const cases = within(await screen.findByRole("region", { name: "Cases by state and age" }));
    const details = must(cases.getByText("How these figures are counted").closest("details"));
    expect(details.open).toBe(false);
    await user.click(cases.getByText("How these figures are counted"));
    expect(within(details).getByText("Rows of cases in state 'suspected'.")).toBeTruthy();
  });

  it("shows a name from the SIEM as text, never as markup", async () => {
    renderApp("/reports/1");
    const hosts = within(await screen.findByRole("region", { name: "Still-active hosts" }));
    expect(hosts.getAllByText(/ws-017/).length).toBeGreaterThan(0);
    expect(document.querySelector("img")).toBeNull();
    expect(document.body.textContent).toContain("<img src=x onerror=alert(1)>");
  });

  it("downloads the text and the JSON under names of the last day", async () => {
    const user = userEvent.setup();
    const made: Blob[] = [];
    const urls = vi.fn((blob: Blob) => (made.push(blob), `blob:${made.length}`));
    Object.assign(URL, { createObjectURL: urls, revokeObjectURL: vi.fn() });
    const names: string[] = [];
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
      names.push(this.download);
    });
    renderApp("/reports/1");
    await user.click(await screen.findByRole("button", { name: "Download as text" }));
    await user.click(screen.getByRole("button", { name: "Download as JSON" }));
    expect(names).toEqual(["argus-daily-report-2026-10-20.txt", "argus-daily-report-2026-10-20.json"]);
    expect(await made[0]?.text()).toBe(REPORT.text);
    expect(JSON.parse((await made[1]?.text()) ?? "{}").sections.length).toBe(4);
    expect(click).toHaveBeenCalledTimes(2);
  });

  it("shows the AI's summary above the figures only when there is one", async () => {
    server.use(http.get(`${BASE}/api/v1/reports/1`, () => HttpResponse.json({ ...REPORT, prose: "Two cases wait." })));
    renderApp("/reports/1");
    const summary = within(await screen.findByRole("region", { name: "Summary" }));
    expect(summary.getByText("Two cases wait.")).toBeTruthy();
    expect(summary.getByText(/every number in it was checked/)).toBeTruthy();
  });

  it("says when the waiting figures are as at, in IST", async () => {
    renderApp("/reports/1");
    await screen.findByRole("heading", { name: "Daily report for 20 Oct 2026" });
    expect(document.body.textContent).toMatch(/is as at 21 Oct 2026, 7:45 AM IST, what happened is for the period/);
  });

  it("has no summary section when there is none", async () => {
    renderApp("/reports/1");
    await screen.findByRole("heading", { name: "Daily report for 20 Oct 2026" });
    expect(screen.queryByRole("region", { name: "Summary" })).toBeNull();
  });
});

describe("a report that cannot be shown", () => {
  it("says so for an id that is no report", async () => {
    renderApp("/reports/abc");
    expect(await screen.findByText(/This report could not be shown/)).toBeTruthy();
  });

  it("asks for an id of more than 16 digits as written, not rounded to a number", async () => {
    const id = "4611686018427387904";
    const seen: string[] = [];
    server.use(
      http.get(`${BASE}/api/v1/reports/:id`, ({ params }) => {
        seen.push(String(params.id));
        return HttpResponse.json({ ...REPORT, id: 1 });
      }),
    );
    renderApp(`/reports/${id}`);
    expect(await screen.findByRole("heading", { name: "Daily report for 20 Oct 2026" })).toBeTruthy();
    expect(seen).toEqual([id]);
  });

  it("says so for an id above 2^62, which the API refuses", async () => {
    renderApp("/reports/4611686018427387905");
    expect(await screen.findByText(/This report could not be shown/)).toBeTruthy();
  });

  it("says so when the server has none", async () => {
    server.use(http.get(`${BASE}/api/v1/reports/9`, () => HttpResponse.json({ detail: "no such report", code: "not_found" }, { status: 404 })));
    renderApp("/reports/9");
    await waitFor(() => expect(screen.getAllByRole("alert").map((a) => a.textContent).join(" ")).toContain("This report could not be shown. no such report"));
  });
});
