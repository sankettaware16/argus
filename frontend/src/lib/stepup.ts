/**
 * Waiting for a password confirmed in another tab (the server's /stepup page: a password never
 * goes through the API). The page that needs it reads the session every 2 s, in the background,
 * while it waits (10 minutes at most), and goes on by itself once the confirmation is there.
 */
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useRef, useState } from "react";
import { getSession } from "../client/sdk.gen";
import { BACKGROUND } from "./api";
import { sessionQuery } from "./session";
import { parse } from "./time";

export const POLL_MS = 2_000;
export const WAIT_MS = 10 * 60_000;
/** Where the step-up tab lands: a page that says to go back (the waiting tab goes on by itself). */
export const CONFIRMED_PATH = "/app/confirmed";

/** Whether a new confirmation arrived: valid now, and not the one there was when the wait began. */
export function stepUpConfirmed(before: string | null | undefined, until: string | null | undefined, now: number): boolean {
  const at = parse(until);
  return at !== null && at.getTime() > now && until !== before;
}

export type StepUpWait = "idle" | "waiting" | "confirmed" | "gave_up";

/** Starts waiting with `start()`; calls `onConfirmed` once when the password is confirmed. */
export function useStepUpWait(onConfirmed?: () => void): { state: StepUpWait; start: () => void } {
  const queries = useQueryClient();
  const [since, setSince] = useState<{ at: number; before: string | null } | null>(null);
  const [state, setState] = useState<StepUpWait>("idle");
  const done = useRef(onConfirmed);
  useEffect(() => {
    done.current = onConfirmed;
  });
  const waiting = useRef(since);
  useEffect(() => {
    waiting.current = since;
  });
  useQuery({
    queryKey: ["session", "step-up-wait", since?.at ?? 0],
    // each read checks for itself: the page goes on from the read's own callback
    queryFn: async () => {
      const { data } = await getSession({ headers: BACKGROUND });
      const asked = waiting.current;
      if (data && asked !== null && stepUpConfirmed(asked.before, data.step_up_valid_until, Date.now())) {
        setSince(null);
        setState("confirmed");
        queries.setQueryData(sessionQuery.queryKey, data);
        done.current?.();
      }
      return data ?? null;
    },
    enabled: since !== null,
    refetchInterval: POLL_MS,
    refetchIntervalInBackground: true,
  });
  useEffect(() => {
    if (since === null) return;
    const timer = setTimeout(() => {
      setSince(null);
      setState("gave_up");
    }, WAIT_MS);
    return () => clearTimeout(timer);
  }, [since]);
  const start = useCallback(() => {
    const now = queries.getQueryData(sessionQuery.queryKey);
    setSince({ at: Date.now(), before: now?.step_up_valid_until ?? null });
    setState("waiting");
  }, [queries]);
  return { state, start };
}
