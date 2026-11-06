// Home is the queue, not a dashboard (P4-F U20): no tiles of numbers, no leftover card; the numbers
// are the Dashboard's.
import { screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { BASE, mockApi, renderApp, sent } from "./helpers";

mockApi();
void BASE;

describe("Home", () => {
  it("has no tiles and no leftover card, and does not read the case counts for them", async () => {
    renderApp("/");
    await screen.findByRole("heading", { name: "Home" });
    await screen.findByRole("heading", { name: /Possible incidents and incidents that need you/ });
    expect(screen.queryByRole("region", { name: "Cases" })).toBeNull();
    expect(screen.queryByRole("region", { name: "Investigations" })).toBeNull();
    expect(screen.queryByText("At a glance")).toBeNull();
    expect(screen.queryByText("The ARGUS app")).toBeNull();
    expect(sent("GET", "/api/v1/cases").filter((r) => r.path.includes("limit=1"))).toHaveLength(0);
  });
});
