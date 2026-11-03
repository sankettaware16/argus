import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { BUILD, isStale, mustAskForReload, noteServerBuild, onPreloadError, reloadOnce, resetBuildState, serverBuild } from "../src/lib/build";

function nav() {
  return { assign: vi.fn(), reload: vi.fn() };
}

beforeEach(() => {
  resetBuildState();
  sessionStorage.clear();
});
afterEach(() => vi.unstubAllGlobals());

describe("the stale-build check", () => {
  it("knows its own build and takes only well-formed server ids", () => {
    expect(BUILD).toBe("test-build");
    noteServerBuild(null);
    noteServerBuild("");
    noteServerBuild("not-an-id");
    noteServerBuild("0123456789ABCDEF");
    noteServerBuild("0123456789abcdef0");
    expect(serverBuild()).toBeNull();
    expect(isStale()).toBe(false);
    noteServerBuild("0123456789abcdef");
    expect(serverBuild()).toBe("0123456789abcdef");
    expect(isStale()).toBe(true);
  });

  it("reloads once for a build, never in a loop", () => {
    noteServerBuild("aaaaaaaaaaaaaaaa");
    const n = nav();
    expect(reloadOnce("/app/design", n)).toBe(true);
    expect(n.assign).toHaveBeenCalledWith("/app/design");
    expect(mustAskForReload()).toBe(false);
    // the page loaded again and is still stale: no second reload, the notice instead
    expect(reloadOnce("/app/design", n)).toBe(false);
    expect(reloadOnce(undefined, n)).toBe(false);
    expect(n.assign).toHaveBeenCalledTimes(1);
    expect(n.reload).not.toHaveBeenCalled();
    expect(mustAskForReload()).toBe(true);
  });

  it("reloads again for a newer build", () => {
    const n = nav();
    noteServerBuild("aaaaaaaaaaaaaaaa");
    reloadOnce(undefined, n);
    noteServerBuild("bbbbbbbbbbbbbbbb");
    expect(reloadOnce(undefined, n)).toBe(true);
    expect(n.reload).toHaveBeenCalledTimes(2);
  });

  it("never reloads by itself without sessionStorage", () => {
    vi.stubGlobal("sessionStorage", undefined);
    Object.defineProperty(window, "sessionStorage", {
      configurable: true,
      get() {
        throw new DOMException("blocked", "SecurityError");
      },
    });
    const n = nav();
    noteServerBuild("aaaaaaaaaaaaaaaa");
    expect(reloadOnce(undefined, n)).toBe(false);
    expect(n.reload).not.toHaveBeenCalled();
    expect(mustAskForReload()).toBe(true);
    // @ts-expect-error: put jsdom's storage back
    delete window.sessionStorage;
  });

  it("does not reload when the storage refuses the write", () => {
    const n = nav();
    const set = vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new DOMException("full", "QuotaExceededError");
    });
    expect(reloadOnce(undefined, n)).toBe(false);
    expect(n.reload).not.toHaveBeenCalled();
    expect(mustAskForReload()).toBe(true);
    set.mockRestore();
  });

  it("reloads once on a failed lazy part, then lets the error through", () => {
    const n = nav();
    const first = new Event("vite:preloadError", { cancelable: true });
    onPreloadError(first, n);
    expect(first.defaultPrevented).toBe(true);
    expect(n.reload).toHaveBeenCalledTimes(1);
    const second = new Event("vite:preloadError", { cancelable: true });
    onPreloadError(second, n);
    expect(second.defaultPrevented).toBe(false);
    expect(n.reload).toHaveBeenCalledTimes(1);
  });

  it("forgets on reset", () => {
    noteServerBuild("aaaaaaaaaaaaaaaa");
    noteServerBuild("aaaaaaaaaaaaaaaa");
    resetBuildState();
    expect(serverBuild()).toBeNull();
    expect(mustAskForReload()).toBe(false);
  });
});
