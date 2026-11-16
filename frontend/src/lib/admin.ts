/** What the administration pages read (settings, changes, people, jobs). Nothing typed into a
 * secret's box is ever part of a query key. */
import { queryOptions } from "@tanstack/react-query";
import { getAdminJob, getSettingChanges, getSettings, listUsers } from "../client/sdk.gen";
import type { JobOut, SettingChangesOut } from "../client/types.gen";
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
