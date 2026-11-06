// Q-B4 review 2: the app says what the classic pages said on every page: an emergency (break-glass)
// session, and ELK sign-in that ARGUS cannot confirm right now. Neither may be silent: in both,
// nothing the person reviews reaches Kibana.
import { act, screen, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { afterEach, describe, expect, it, vi } from "vitest";
import { BASE, SESSION, must, mockApi, renderApp, server } from "./helpers";

mockApi();
afterEach(() => {
  vi.useRealTimers();
});

const serve = (more: Partial<typeof SESSION>) => server.use(http.get(`${BASE}/api/v1/session`, () => HttpResponse.json({ ...SESSION, ...more })));
const banners = () => screen.queryAllByText(/Emergency \(break-glass\) session|cannot confirm your access/);

describe("the access banner", () => {
  it("shows nothing for an ordinary session", async () => {
    renderApp("/");
    await screen.findByTestId("account-menu");
    expect(banners()).toEqual([]);
  });

  it("tells an emergency session that nothing it does is sent to Kibana, with a way to the details", async () => {
    serve({ break_glass: true });
    renderApp("/");
    const alert = must((await screen.findByText("Emergency (break-glass) session.")).closest("p"));
    expect(alert.getAttribute("role")).toBe("alert");
    expect(alert.textContent).toContain("Emergency (break-glass) session.");
    expect(alert.textContent).toContain("you can view and review only");
    expect(alert.textContent).toContain("Nothing you do is sent to Kibana, and every action is recorded.");
    expect(alert.querySelector("a")?.getAttribute("href")).toBe("/access");
  });

  it("tells a person ARGUS cannot confirm that reviews are saved here and not sent to Kibana (an outage)", async () => {
    serve({ unverified: { since: "2026-10-26T10:00:00Z", why: "outage" } });
    renderApp("/");
    const note = await screen.findByText(/cannot confirm your access in ELK right now/);
    const box = note.closest("p");
    expect(box?.getAttribute("role")).toBe("status");
    expect(box?.textContent).toContain("You can read and review (reviews are saved here, not sent to Kibana); changes that need ELK wait.");
    expect(box?.querySelector("a")?.getAttribute("href")).toBe("/access");
  });

  it("promises no reviewing after ARGUS's own refusal: reading only", async () => {
    serve({ unverified: { since: "2026-10-26T10:00:00Z", why: "refused" } });
    renderApp("/");
    const box = (await screen.findByText(/cannot confirm your access in ELK right now/)).closest("p");
    expect(box?.textContent).toContain("You can read; changes that need ELK wait.");
    expect(box?.textContent).not.toContain("review");
  });

  it("follows the server without a reload: the session is read again each minute, as a background read", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    let reads = 0;
    const seen: (string | null)[] = [];
    server.use(
      http.get(`${BASE}/api/v1/session`, ({ request }) => {
        reads += 1;
        seen.push(request.headers.get("X-Argus-Background"));
        return HttpResponse.json(reads === 1 ? SESSION : { ...SESSION, unverified: { since: "2026-10-26T10:00:00Z", why: "outage" } });
      }),
    );
    renderApp("/");
    await screen.findByRole("heading", { level: 1 });
    expect(banners()).toEqual([]);
    expect(reads).toBe(1); // no second read at once
    await act(async () => {
      await vi.advanceTimersByTimeAsync(61_000);
    });
    await waitFor(() => expect(banners().length).toBe(1));
    expect(seen).toEqual([null, "1"]); // the page's own read, then a background one
  });
});
