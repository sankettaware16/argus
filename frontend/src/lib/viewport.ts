/** Whether the window is wide enough for two panes (the plan's ~1024 px); below that, one pane at a time. */
import { useSyncExternalStore } from "react";

export const WIDE = "(min-width: 1024px)";

function query(): MediaQueryList | null {
  return typeof window !== "undefined" && typeof window.matchMedia === "function" ? window.matchMedia(WIDE) : null;
}

function subscribe(onChange: () => void): () => void {
  const q = query();
  q?.addEventListener("change", onChange);
  return () => q?.removeEventListener("change", onChange);
}

export function useWide(): boolean {
  return useSyncExternalStore(subscribe, () => query()?.matches ?? true, () => true);
}
