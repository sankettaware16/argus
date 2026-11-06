// Search (docs/p4f-ui-spec.md §10): the type guess (R-1), grouped results with at most five and
// Show all (R-3), and the no-result words that say what ARGUS keeps (R-4).
import { screen, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import { guessOf, kindsFor } from "../src/lib/searchPage";
import { caseRow, casePage } from "./caseFixtures";
import { BASE, investigation, mockApi, renderApp, server } from "./helpers";

mockApi();

describe("the type guess (R-1)", () => {
  it("knows an incident number, an IR number, a device and an outside address, a domain, a name and words", () => {
    expect(guessOf("#31")).toBe("number");
    expect(guessOf("31")).toBe("number");
    expect(guessOf("ACME-IR-2026-1106-02")).toBe("ir");
    expect(guessOf("203.0.113.40")).toBe("outside");
    expect(guessOf("10.0.12.17")).toBe("device");
    expect(guessOf("www.dept.example.ac.in")).toBe("domain");
    expect(guessOf("lab-pc-17")).toBe("name");
    expect(guessOf("beacon to a raw ip")).toBe("words");
    expect(kindsFor("name")).toEqual(["host", "user"]);
  });

  it("shows its guess for the address typed", async () => {
    server.use(http.get(`${BASE}/api/v1/investigations`, () => HttpResponse.json({ items: [], has_more: false, limit: 25, offset: 0, sort: "newest", view: "all" })));
    renderApp("/search?q=203.0.113.40");
    const guess = await screen.findByTestId("search-guess");
    expect((within(guess).getByRole("combobox") as HTMLSelectElement).value).toBe("outside");
    expect(screen.getByTestId("search-entity").textContent).toContain("Outside address 203.0.113.40");
  });
});

describe("results", () => {
  it("R-3: grouped, at most five a group, with Show all", async () => {
    const many = Array.from({ length: 7 }, (_, i) => caseRow({ id: `c0c0c0c0-0000-4000-8000-00000000000${i}`, number: 40 + i, title: `Beaconing to 203.0.113.40, case ${i}` }));
    server.use(
      http.get(`${BASE}/api/v1/cases`, () => HttpResponse.json(casePage(many))),
      http.get(`${BASE}/api/v1/investigations`, () => HttpResponse.json({ items: [investigation()], has_more: false, limit: 25, offset: 0, sort: "newest", view: "all" })),
    );
    renderApp("/search?q=203.0.113.40");
    const incidents = await screen.findByTestId("search-incidents");
    expect(within(incidents).getAllByRole("listitem")).toHaveLength(5);
    expect(within(incidents).getByRole("link", { name: "Show all 7" })).toBeTruthy();
    expect(await screen.findByTestId("search-groups")).toBeTruthy();
  });

  it("R-4: the no-result words name what ARGUS keeps", async () => {
    server.use(http.get(`${BASE}/api/v1/investigations`, () => HttpResponse.json({ items: [], has_more: false, limit: 25, offset: 0, sort: "newest", view: "all" })));
    renderApp("/search?q=nothing-here.example");
    expect((await screen.findByTestId("search-nothing")).textContent).toBe("Nothing in ARGUS matches “nothing-here.example”. ARGUS keeps alert detail for the last 5 days, and every incident.");
  });

  it("before typing, says what can be searched", async () => {
    renderApp("/search");
    expect(await screen.findByText("Search for an address, a host, an account, a domain, a rule, an incident number or an IR number.")).toBeTruthy();
  });
});
