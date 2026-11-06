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

const PHONE = "(max-width: 639px)";
const PANE = "(min-width: 1280px)";

function watch(media: string) {
  const q = () => (typeof window !== "undefined" && typeof window.matchMedia === "function" ? window.matchMedia(media) : null);
  return {
    subscribe(onChange: () => void): () => void {
      const m = q();
      m?.addEventListener("change", onChange);
      return () => m?.removeEventListener("change", onChange);
    },
    read: () => q()?.matches ?? false,
  };
}
const phone = watch(PHONE);
const pane = watch(PANE);

/** Under 640 px (the UI v2's phone layout, docs/p4f-ui-spec.md §15). */
export function usePhone(): boolean {
  return useSyncExternalStore(phone.subscribe, phone.read, () => false);
}

/** 1280 px and wider: the Incidents queue has its preview pane (§6.4). */
export function usePaneWide(): boolean {
  return useSyncExternalStore(pane.subscribe, pane.read, () => false);
}
