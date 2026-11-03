/**
 * The stale-build check (Q-B1, plan §7.5). The code knows the build it came from
 * (__ARGUS_BUILD__); every answer of the server says the build it serves (X-Argus-Build). When
 * they differ, the next navigation loads the page afresh, once: if the page is still stale
 * after that one reload (or a lazy part failed to load twice), it says so and offers a reload
 * button instead, so it never reloads in a loop. Without sessionStorage it never reloads by
 * itself.
 */
import { useSyncExternalStore } from "react";

export const BUILD: string = __ARGUS_BUILD__;
const KEY = "argus-reloaded-for";
const ID = /^[0-9a-f]{16}$/;

let server: string | null = null;
let stuck = false;
const listeners = new Set<() => void>();

function changed(): void {
  for (const listener of listeners) listener();
}

/** Record the build the server says it serves (from an X-Argus-Build header). */
export function noteServerBuild(id: string | null | undefined): void {
  if (!id || !ID.test(id) || id === server) return;
  server = id;
  changed();
}

export function serverBuild(): string | null {
  return server;
}

export function isStale(): boolean {
  return server !== null && server !== BUILD;
}

function storage(): Storage | null {
  try {
    const s = window.sessionStorage;
    s.getItem(KEY);
    return s;
  } catch {
    return null;
  }
}

export interface Navigator {
  assign: (url: string) => void;
  reload: () => void;
}

const browser: Navigator = {
  assign: (url) => window.location.assign(url),
  reload: () => window.location.reload(),
};

/**
 * Load the page afresh (at `url`, or the current one), once for each build the server serves.
 * Returns whether it did; when it may not, the page shows the "updated" notice instead.
 */
export function reloadOnce(url?: string, nav: Navigator = browser): boolean {
  const store = storage();
  const key = server ?? "unknown";
  if (store === null || store.getItem(KEY) === key) {
    stuck = true;
    changed();
    return false;
  }
  try {
    store.setItem(KEY, key);
  } catch {
    stuck = true;
    changed();
    return false;
  }
  if (url === undefined) nav.reload();
  else nav.assign(url);
  return true;
}

/** Whether the page must tell the person to reload (it could not do it by itself). */
export function mustAskForReload(): boolean {
  return stuck;
}

/**
 * A lazy part of the app failed to load (vite:preloadError): usually a deploy removed it. The
 * page reloads once; if it may not, the error goes on to the page's error message.
 */
export function onPreloadError(event: Event, nav: Navigator = browser): void {
  if (reloadOnce(undefined, nav)) event.preventDefault();
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/** For the shell's notice: { stale, ask } re-rendered when either changes. */
export function useBuildState(): { stale: boolean; ask: boolean } {
  const stale = useSyncExternalStore(subscribe, isStale, isStale);
  const ask = useSyncExternalStore(subscribe, mustAskForReload, mustAskForReload);
  return { stale, ask };
}

/** Tests only: forget what was seen. */
export function resetBuildState(): void {
  server = null;
  stuck = false;
  changed();
}
