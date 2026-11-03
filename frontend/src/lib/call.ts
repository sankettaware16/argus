/**
 * Turns the generated client's result into a value or an ApiError (status, code, plain words).
 * Nothing is retried here or by the query client: a failed request is said, and the person
 * decides (plan §7.5: no 4xx retried).
 */
import { failureText } from "./failure";
import { ApiError } from "./session";

interface Result<T> {
  data?: T;
  error?: unknown;
  response?: Response;
}

function field(error: unknown, name: "detail" | "code"): string | null {
  if (error && typeof error === "object" && name in error) {
    const value = (error as Record<string, unknown>)[name];
    return typeof value === "string" ? value : null;
  }
  return null;
}

export async function unwrap<T>(pending: Promise<Result<T>>): Promise<T> {
  let result: Result<T>;
  try {
    result = await pending;
  } catch {
    throw new ApiError(0, failureText(0, null, null));
  }
  const status = result.response?.status ?? 0;
  if (result.response?.ok === true && result.data !== undefined) return result.data;
  const code = field(result.error, "code");
  throw new ApiError(status, failureText(status, code, field(result.error, "detail")), code);
}
