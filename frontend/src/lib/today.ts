/**
 * Today's one call (`GET /api/v1/today`, docs/p4f-ui-spec.md §2.2, §5): not in the generated client
 * until the engine's presenter is merged, so it is read through the same client by its address.
 * A 404 or a 501 means the server does not serve Today yet: the route `/` shows Home then (§2.4).
 */
import { queryOptions, useQuery } from "@tanstack/react-query";
import { BACKGROUND, client } from "./api";
import { failureText } from "./failure";
import { ApiError } from "./session";
import { needsYouCount, toToday, type Today } from "./engine";

export type TodayRead = { served: false } | { served: true; today: Today };

export type SinceChoice = "round" | "24h" | "3d" | "7d";

export async function readToday(since: SinceChoice = "round"): Promise<TodayRead> {
  let result: { data?: unknown; error?: unknown; response?: Response };
  try {
    // a background read (it is polled and read again on focus): it never keeps the session alive
    result = (await client.request({ method: "GET", url: "/api/v1/today", headers: BACKGROUND, query: since === "round" ? {} : { since } })) as typeof result;
  } catch {
    throw new ApiError(0, failureText(0, null, null));
  }
  const status = result.response?.status ?? 0;
  if (status === 404 || status === 501) return { served: false };
  if (result.response?.ok === true && result.data !== undefined) return { served: true, today: toToday(result.data) };
  const error = result.error as { code?: unknown; detail?: unknown } | undefined;
  const code = typeof error?.code === "string" ? error.code : null;
  throw new ApiError(status, failureText(status, code, typeof error?.detail === "string" ? error.detail : null), code);
}

export function todayOptions(since: SinceChoice = "round") {
  return queryOptions({
    queryKey: ["today", since],
    queryFn: () => readToday(since),
    staleTime: 15_000,
    refetchInterval: 5 * 60_000,
    refetchOnWindowFocus: true,
  });
}

/** The Today badge in the nav (§4.1): the Needs-you number, or null when Today is not served. */
export function useNeedsYouCount(): number | null {
  const today = useQuery(todayOptions());
  return today.data?.served && today.data.today.mode === "present" ? needsYouCount(today.data.today) : null;
}
