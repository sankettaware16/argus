// The account look-up (D-337): its page and menu entry exist only where the site has a directory
// and the person may ask it; an account's page shows the directory's answer; an expired session
// says who saves a new one, and the account's name alone still says something.
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import type { DirectoryOut } from "../src/client/types.gen";
import { directoryWords } from "../src/components/DirectoryCard";
import { MORE } from "../src/shell/nav";
import { BASE, mockApi, renderApp, server, SESSION, shellHandlers } from "./helpers";

mockApi();

const FOUND: DirectoryOut = {
  account: "25m0001",
  directory: "The directory",
  outcome: "found",
  why: null,
  person: { name: "A Person", kind: "Masters student", department: "Design", details: [{ label: "Joined", value: "2025" }] },
  described: { name: null, kind: "Masters student", department: null, details: [{ label: "Joined", value: "2025" }] },
};

function serve(answer: DirectoryOut, asked: string[] = []) {
  server.use(
    ...shellHandlers({ ...SESSION, directory: "The directory" }),
    http.get(`${BASE}/api/v1/directory/:account`, ({ params }) => {
      asked.push(String(params.account));
      return HttpResponse.json({ ...answer, account: String(params.account) });
    }),
    http.get(`${BASE}/api/v1/investigations`, () => HttpResponse.json({ items: [], has_more: false, limit: 50, offset: 0, sort: "newest", view: "all" })),
    http.get(`${BASE}/api/v1/cases`, () => HttpResponse.json({ items: [], has_more: false, limit: 50, offset: 0 })),
    http.get(`${BASE}/api/v1/entity-notes`, () => HttpResponse.json({ items: [], kind: "user", value: "25m0001" })),
  );
}

describe("account look-up", () => {
  it("the menu entry is the directory's own", () => {
    const item = MORE.find((m) => m.to === "/account-lookup");
    expect(item?.directory).toBe(true);
    expect(item?.admin).toBeUndefined();
  });

  it("without a directory the page says so and asks nothing", async () => {
    const asked: string[] = [];
    server.use(http.get(`${BASE}/api/v1/directory/:account`, ({ params }) => (asked.push(String(params.account)), HttpResponse.json(FOUND))));
    renderApp("/account-lookup?account=25m0001");
    expect((await screen.findByText(/This is not available/)).textContent).toContain("no account directory");
    expect(asked).toEqual([]);
  });

  it("a typed account is looked up and its name, kind and department shown", async () => {
    const user = userEvent.setup();
    const asked: string[] = [];
    serve(FOUND, asked);
    renderApp("/account-lookup");
    await user.type(await screen.findByTestId("directory-box"), "25m0001");
    await user.click(screen.getByRole("button", { name: "Look up" }));
    const lines = await screen.findByTestId("directory-lines");
    expect(lines.textContent).toContain("A Person");
    expect(lines.textContent).toContain("Masters student");
    expect(lines.textContent).toContain("Design");
    expect(asked).toEqual(["25m0001"]);
    expect(screen.getByTestId("directory-card").textContent).toContain("not stored");
  });

  it("a value that is no account name is not asked", async () => {
    const user = userEvent.setup();
    const asked: string[] = [];
    serve(FOUND, asked);
    renderApp("/account-lookup");
    await user.type(await screen.findByTestId("directory-box"), "a b/c");
    expect(screen.getByRole("button", { name: "Look up" })).toHaveProperty("disabled", true);
    expect(asked).toEqual([]);
  });

  it("an account's page shows who it is", async () => {
    serve(FOUND);
    renderApp("/entities/account/25m0001");
    expect((await screen.findByTestId("entity-directory")).textContent).toContain("from The directory");
    expect((await screen.findByTestId("directory-lines")).textContent).toContain("A Person");
  });

  it("an expired session says so, and the name alone still says the kind", async () => {
    serve({ ...FOUND, outcome: "expired", why: "it no longer accepts the saved session", person: null });
    renderApp("/account-lookup?account=25m0001");
    expect((await screen.findByTestId("directory-words")).textContent).toContain("no longer accepts");
    expect(screen.getByTestId("directory-lines").textContent).toContain("Masters student");
    expect(screen.getByTestId("directory-lines").textContent).not.toContain("A Person");
  });

  it("the words: an administrator is sent to Settings, anyone else to an administrator", () => {
    const d = { outcome: "expired" as const, directory: "The directory", why: null, account: "x" };
    expect(directoryWords(d, true)).toContain("Settings › Account directory");
    expect(directoryWords(d, false)).toContain("Ask an administrator");
    expect(directoryWords({ ...d, outcome: "not_found" }, false)).toContain("has no account x");
    expect(directoryWords({ ...d, outcome: "found" }, false)).toBe("");
  });
});
