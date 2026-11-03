// The confirm dialog on the wire (review F1): what goes out is the method, the path and the body
// text the dialog showed, byte for byte, through the foundation's own sender (sendExact).
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import fc from "fast-check";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { ConfirmDialog } from "../src/components/ConfirmDialog";
import { client, configure, isExactPath, sendExact, setCsrf, setLeave } from "../src/lib/api";
import type { Sent } from "../src/lib/payload";

const BASE = "http://localhost:3000";
const ID = "11111111-1111-1111-1111-111111111111";
const PATH = `/api/v1/investigations/${ID}/reviews`;
interface Wire {
  method: string;
  path: string;
  body: string;
  type: string | null;
  csrf: string | null;
}
const wire: Wire[] = [];
let answer: () => Response = () => HttpResponse.json({ id: 7 }, { status: 201 });
const server = setupServer(
  http.all(`${BASE}/api/v1/*`, async ({ request }) => {
    const url = new URL(request.url);
    wire.push({
      method: request.method,
      path: url.pathname + url.search,
      body: await request.text(),
      type: request.headers.get("Content-Type"),
      csrf: request.headers.get("X-CSRF-Token"),
    });
    return answer();
  }),
);

beforeAll(() => {
  configure();
  client.setConfig({ baseUrl: BASE });
  server.listen({ onUnhandledRequest: "error" });
});
beforeEach(() => {
  wire.length = 0;
  answer = () => HttpResponse.json({ id: 7 }, { status: 201 });
  setCsrf("token-1");
});
afterEach(() => setCsrf(null));
afterAll(() => server.close());

function shownText(): string {
  return screen.getByTestId("payload").textContent ?? "";
}

describe("the confirm dialog sends what it shows", () => {
  it("puts the shown method, path and body on the wire, byte for byte, for any JSON value", async () => {
    await fc.assert(
      fc.asyncProperty(fc.jsonValue({ maxDepth: 2 }), fc.constantFrom("POST", "PUT", "PATCH"), async (body, method) => {
        wire.length = 0;
        const onSent = vi.fn<(sent: Sent) => void>();
        const view = render(
          <ConfirmDialog open onOpenChange={() => {}} title="Send it?" confirmLabel="Send" onSent={onSent}
            request={{ method, path: PATH, body }} />,
        );
        const text = JSON.stringify(body, null, 2);
        fireEvent.click(screen.getByRole("button", { name: "Send" }));
        await waitFor(() => expect(onSent).toHaveBeenCalledTimes(1));
        expect(wire).toEqual([{ method, path: PATH, body: text, type: "application/json", csrf: "token-1" }]);
        expect(onSent).toHaveBeenCalledWith({ status: 201, data: { id: 7 } });
        view.unmount();
      }),
      { numRuns: 20 },
    );
  });

  it("shows the text that is sent (markers aside, the same characters)", async () => {
    const onSent = vi.fn<(sent: Sent) => void>();
    render(
      <ConfirmDialog open onOpenChange={() => {}} title="Send it?" confirmLabel="Send" onSent={onSent}
        request={{ method: "POST", path: PATH, body: { outcome: "benign" } }} />,
    );
    const shown = shownText();
    fireEvent.click(screen.getByRole("button", { name: "Send" }));
    await waitFor(() => expect(onSent).toHaveBeenCalledTimes(1));
    expect(wire[0]?.body).toBe(shown);
    expect(wire[0]?.body).toBe('{\n  "outcome": "benign"\n}');
  });
});

describe("sendExact", () => {
  it("sends no body and no content type for an empty text", async () => {
    answer = () => new HttpResponse(null, { status: 204 });
    expect(await sendExact({ method: "DELETE", path: "/api/v1/session", text: "" })).toMatchObject({ status: 204 });
    expect(wire).toEqual([{ method: "DELETE", path: "/api/v1/session", body: "", type: null, csrf: "token-1" }]);
  });

  it("says why when the answer is a refusal, and when no answer came", async () => {
    answer = () => HttpResponse.json({ detail: "The investigation changed; read it again.", code: "conflict" }, { status: 409 });
    await expect(sendExact({ method: "POST", path: PATH, text: "{}" })).rejects.toThrow("The investigation changed; read it again.");
    answer = () => HttpResponse.error();
    await expect(sendExact({ method: "POST", path: PATH, text: "{}" })).rejects.toThrow(
      "No answer came from ARGUS, so it is not known whether this was done. Look before you try again.",
    );
    const leave = vi.fn();
    setLeave(leave);
    answer = () => HttpResponse.json({ detail: "sign in", code: "unauthenticated" }, { status: 401 });
    await expect(sendExact({ method: "POST", path: PATH, text: "{}" })).rejects.toThrow("sign in");
    expect(leave).toHaveBeenCalledTimes(1);
  });

  it("sends nothing to an address the browser would not request as written", async () => {
    const refused = [
      "https://evil.example/api/v1/x",
      "//evil.example/api/v1/x",
      "/api/v1",
      "/api/v1/",
      "/api/v2/x",
      "/api/v1/x/",
      "/api/v1//x",
      "/api/v1/../session",
      "/api/v1/x/..",
      "/api/v1/./x",
      "/api/v1/%2e%2E/x",
      "/api/v1/.%2e/x",
      "/api/v1/%2E/x",
      "/api/v1/x?y=1",
      "/api/v1/x#y",
      "/api/v1/x y",
      "/api/v1/x\\y",
      "/api/v1/\u00e9",
      "/api/v1/%zz",
      "/api/v1/%4",
      "/api/v1/{id}",
      " /api/v1/x",
      "/api/v1/x\n",
      "/app/x",
    ];
    for (const path of refused) {
      expect(isExactPath(path), path).toBe(false);
      await expect(sendExact({ method: "POST", path, text: "{}" })).rejects.toThrow(
        "This request's address is not one ARGUS can send exactly as shown, so nothing was sent.",
      );
    }
    expect(wire).toEqual([]);
    for (const path of [PATH, "/api/v1/session", "/api/v1/a.b/c~d_e-f", "/api/v1/x%2Fy", "/api/v1/...", "/api/v1/.a", "/api/v1/a."]) {
      expect(isExactPath(path), path).toBe(true);
    }
  });
});
