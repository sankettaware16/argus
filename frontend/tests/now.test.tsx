// useNow: the time now, read again every interval, and again when the interval changes.
import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useNow } from "../src/lib/now";

describe("the time now", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-10-26T10:00:00Z"));
  });
  afterEach(() => vi.useRealTimers());

  it("is read again every interval, and a new interval replaces the old one", () => {
    const start = Date.now();
    const { result, rerender, unmount } = renderHook(({ every }) => useNow(every), { initialProps: { every: 1000 } });
    expect(result.current).toBe(start);
    act(() => void vi.advanceTimersByTime(1000));
    expect(result.current).toBe(start + 1000);
    rerender({ every: 5000 });
    act(() => void vi.advanceTimersByTime(1000)); // the old timer is gone
    expect(result.current).toBe(start + 1000);
    act(() => void vi.advanceTimersByTime(4000));
    expect(result.current).toBe(start + 6000);
    unmount();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("reads every 30 seconds unless told otherwise", () => {
    const start = Date.now();
    const { result } = renderHook(() => useNow());
    act(() => void vi.advanceTimersByTime(29_000));
    expect(result.current).toBe(start);
    act(() => void vi.advanceTimersByTime(1000));
    expect(result.current).toBe(start + 30_000);
  });
});
