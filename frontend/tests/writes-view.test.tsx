// The writes an approval binds, as an approver reads them; and the clock a page reads the time of.
import { act, render, renderHook, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { WritesView } from "../src/components/cases/WritesView";
import { useNow } from "../src/lib/now";
import { HASH, RLO } from "./caseFixtures";

describe("the writes", () => {
  const payload = { writes: [{ class: "W3", op: "close", payload: { status: "closed", argus_tags: ["argus"] } }, { class: "W3", op: "comment", payload: { template: "closed" } }] };

  it("are a line each, the raw payload on demand, and the fingerprint", () => {
    render(<WritesView payload={payload} hash={HASH} />);
    const view = within(screen.getByTestId("writes"));
    expect(view.getByText("2 changes to Kibana:")).toBeTruthy();
    expect(view.getAllByRole("listitem").map((li) => li.textContent)).toEqual(["W3 close: status closed; ARGUS tags argus", "W3 comment: the comment “closed”"]);
    expect(JSON.parse(view.getByLabelText("The exact payload").textContent ?? "")).toEqual(payload);
    expect(view.getByTestId("fingerprint").textContent).toBe("a".repeat(16));
  });

  it("say so when there is nothing to write, and for one write say 'change'", () => {
    const { rerender } = render(<WritesView payload={{ writes: [] }} hash={HASH} />);
    expect(screen.getByText(/Nothing is written to Kibana \(the case is not there\)/)).toBeTruthy();
    rerender(<WritesView payload={{ writes: [payload.writes[0]] }} hash={HASH} />);
    expect(screen.getByText("1 change to Kibana:")).toBeTruthy();
    rerender(<WritesView payload={{ writes: "nonsense" }} hash={HASH} />);
    expect(screen.getByText(/Nothing is written to Kibana/)).toBeTruthy();
  });

  it("are text only", () => {
    const hostile = `<img src=x onerror="window.__pwned=1">${RLO}`;
    const { container } = render(<WritesView payload={{ writes: [{ class: "W2", op: "update", payload: { title: hostile } }] }} hash={HASH} />);
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelectorAll(".ut-mark").length).toBeGreaterThan(0);
    expect((window as unknown as { __pwned?: number }).__pwned).toBeUndefined();
  });
});

describe("the clock", () => {
  it("is read again every interval, and no longer once the page is gone", () => {
    vi.useFakeTimers({ now: new Date("2026-10-26T04:00:00Z") });
    try {
      const { result, unmount } = renderHook(() => useNow(1000));
      const first = result.current;
      expect(first).toBe(new Date("2026-10-26T04:00:00Z").getTime());
      act(() => {
        vi.advanceTimersByTime(3000);
      });
      expect(result.current).toBe(first + 3000);
      unmount();
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });
});
