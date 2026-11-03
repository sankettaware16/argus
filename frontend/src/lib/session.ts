/**
 * The session (Q-B1, plan §7.5): who is signed in and what they may do, from GET
 * /api/v1/session; the CSRF token goes to memory (lib/api.ts) and nowhere else. Signing out is
 * DELETE /api/v1/session, then the sign-in page.
 */
import { QueryClient, queryOptions, useQuery, useQueryClient } from "@tanstack/react-query";
import { endSession, getSession } from "../client/sdk.gen";
import type { SessionOut } from "../client/types.gen";
import { BACKGROUND, onCsrfRefused, setCsrf } from "./api";
import { setSite } from "./site";

export type Session = SessionOut;

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly code: string | null = null,
  ) {
    super(message);
  }
}

async function readSession(): Promise<Session> {
  const { data, response } = await getSession();
  if (!data) throw new ApiError(response?.status ?? 0, "Your session could not be read.");
  setCsrf(data.csrf_token);
  setSite(data.site);
  return data;
}

export const sessionQuery = queryOptions({
  queryKey: ["session"],
  queryFn: readSession,
  staleTime: 60_000,
  retry: false,
});

export function makeQueryClient(): QueryClient {
  const queries = new QueryClient({
    defaultOptions: {
      // no 4xx is retried, nothing refetches on focus or reconnect by itself (that would keep a
      // session alive without the person): polls say they are background requests
      queries: { retry: false, refetchOnWindowFocus: false, refetchOnReconnect: false },
      mutations: { retry: false },
    },
  });
  onCsrfRefused(async () => {
    await queries.fetchQuery({ ...sessionQuery, staleTime: 0 });
  });
  return queries;
}

export function useSession() {
  return useQuery(sessionQuery);
}

/**
 * Reads the session again every minute, in the background (such a read never keeps the session
 * alive), so what the server now knows about the person's access reaches the page without a
 * reload: the banner for an emergency session or for ELK that cannot be asked (Q-B4 review 2).
 * The first read is the page's own; this one starts a minute after it.
 */
export function useSessionWatch(): void {
  const queries = useQueryClient();
  useQuery({
    queryKey: ["session-watch"],
    queryFn: async () => {
      const { data } = await getSession({ headers: BACKGROUND, throwOnError: true });
      setSite(data.site);
      queries.setQueryData(sessionQuery.queryKey, data);
      return true;
    },
    initialData: true,
    staleTime: 60_000,
    refetchInterval: 60_000,
  });
}

export function can(session: Session | undefined, capability: string): boolean {
  return session?.capabilities.some((c) => c.name === capability) ?? false;
}

/** Sign out: the session ends on the server, the token leaves memory, then /signin. */
export async function signOut(leave: (url: string) => void = (url) => window.location.assign(url)): Promise<void> {
  const { response } = await endSession();
  const status = response?.status ?? 0;
  if (status !== 204 && status !== 401) {
    throw new ApiError(status, "Signing out did not work; try again.");
  }
  setCsrf(null);
  leave("/signin?why=out");
}
