/** What the administration pages read (settings, changes, people, jobs). Nothing typed into a
 * secret's box is ever part of a query key. */
import { queryOptions } from "@tanstack/react-query";
import { getAdminJob, getServices, getSettingChanges, getSettings, listUsers } from "../client/sdk.gen";
import type { JobOut, ServiceOut, SettingChangesOut } from "../client/types.gen";
import { BACKGROUND } from "./api";
import { unwrap } from "./call";
import { settled } from "./settings";

export const settingsOptions = queryOptions({
  queryKey: ["admin", "settings"],
  queryFn: () => unwrap(getSettings()),
  staleTime: 15_000,
});

export const usersOptions = queryOptions({
  queryKey: ["admin", "users"],
  queryFn: () => unwrap(listUsers()),
  staleTime: 15_000,
});

export const POLL_MS = 1_500;

/** A save's changes, read every 1.5 s (in the background) until each is applied, refused or rolled back. */
export function changesOptions(batch: string | null) {
  return queryOptions({
    queryKey: ["admin", "changes", batch],
    queryFn: () => unwrap(getSettingChanges({ query: { batch: batch ?? undefined }, headers: BACKGROUND })),
    enabled: batch !== null,
    refetchInterval: (q) => (allSettled(q.state.data) ? false : POLL_MS),
  });
}

export function allSettled(data: SettingChangesOut | undefined): boolean {
  return data !== undefined && data.changes.length > 0 && data.changes.every((c) => settled(c.state));
}

/** A job (the certificate check, the setup), read every 1.5 s until it is done or failed. */
export function jobOptions(id: number | null) {
  return queryOptions({
    queryKey: ["admin", "job", id],
    queryFn: () => unwrap(getAdminJob({ path: { job_id: id ?? 0 }, headers: BACKGROUND })),
    enabled: id !== null,
    refetchInterval: (q) => (jobSettled(q.state.data) ? false : POLL_MS),
  });
}

export function jobSettled(job: JobOut | undefined): boolean {
  return job !== undefined && (job.state === "done" || job.state === "failed");
}

/** The last fifty changes of any save (Settings' history). */
export const historyOptions = queryOptions({
  queryKey: ["admin", "changes", "history"],
  queryFn: () => unwrap(getSettingChanges()),
  staleTime: 15_000,
});

export type JobOutcome = { state: "none" | "waiting" | "passed" | "failed"; lines: string[]; error: string | null };

/** What a check or an import came to: passed or failed, what it said, and why it could not run. */
export function jobOutcome(job: JobOut | undefined): JobOutcome {
  if (job === undefined) return { state: "none", lines: [], error: null };
  if (!jobSettled(job)) return { state: "waiting", lines: [], error: null };
  const r = job.result ?? {};
  const lines = Array.isArray(r.output) ? r.output.map(String) : [];
  const error = typeof r.error === "string" ? r.error : null;
  return { state: job.state === "done" && r.ok === true ? "passed" : "failed", lines, error };
}

/** The largest asset map the app sends (the server takes at most 5,000,000 characters). */
export const ASSET_MAP_MAX = 5_000_000;

/** Why a chosen file cannot be sent as the asset map, or null. */
export function assetFileProblem(name: string, size: number): string | null {
  if (!/\.ya?ml$/i.test(name)) return "Choose a .yaml or .yml file.";
  if (size === 0) return "The file is empty.";
  if (size > ASSET_MAP_MAX) return "The file is larger than 5 MB; ARGUS takes an asset map of at most 5 MB.";
  return null;
}

/** ARGUS's services and timers as argus-admin last saw them. */
export const servicesOptions = queryOptions({
  queryKey: ["admin", "services"],
  queryFn: () => unwrap(getServices()),
  staleTime: 30_000,
});

/** Whether a unit may be restarted from the app: a service other than argus-admin, meant to run. */
export function canRestart(u: Pick<ServiceOut, "unit" | "on">): boolean {
  return u.on && u.unit.endsWith(".service") && u.unit !== "argus-admin.service";
}
