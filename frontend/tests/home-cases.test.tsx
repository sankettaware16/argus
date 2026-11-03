// Home shows the cases and the approvals at a glance, each number a link to its list.
import { screen, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import { approval, casePage, queue } from "./caseFixtures";
import { BASE, mockApi, renderApp, server } from "./helpers";

mockApi();

describe("the cases on Home", () => {
  it("are tiles with their numbers, and the approvals waiting", async () => {
    server.use(
      http.get(`${BASE}/api/v1/cases`, () => HttpResponse.json(casePage([], { counts: { active: 7, notified: 1, attention: 2, mine: 3, suspected: 11, closed: 4, queue: 3, all: 25 } }))),
      http.get(`${BASE}/api/v1/approvals`, () => HttpResponse.json(queue({ pending: [approval(), approval({ id: 32 })] }))),
    );
    renderApp("/");
    const region = await screen.findByRole("region", { name: "Cases" });
    await within(region).findByText("11");
    const text = within(region)
      .getAllByRole("link")
      .map((a) => [a.textContent, a.getAttribute("href")]);
    expect(text).toEqual([
      ["7Open cases", "/app/cases?view=active"],
      ["2Cases needing attention", "/app/cases?view=attention"],
      ["3Your cases", "/app/cases?view=mine"],
      ["11Suspected", "/app/cases?view=suspected"],
      ["2Waiting for an approval", "/app/approvals"],
    ]);
  });

  it("show a question mark when the numbers cannot be read, and the rest of Home still works", async () => {
    server.use(http.get(`${BASE}/api/v1/cases`, () => HttpResponse.json({ detail: "boom", code: "internal" }, { status: 500 })));
    renderApp("/");
    const region = await screen.findByRole("region", { name: "Cases" });
    await within(region).findByText("Open cases");
    expect(within(region).getAllByText("?").length).toBeGreaterThan(0);
    expect(screen.getByRole("heading", { name: "Home" })).toBeTruthy();
  });
});
