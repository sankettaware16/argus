import { ApiError } from "../lib/session";
import { failureText, retryable } from "../lib/failure";
import { Button } from "./ui/button";

/** A failed read, said in plain words, with "Try again" only where trying again can help. */
export function Problem({ error, what, onRetry }: { error: unknown; what: string; onRetry?: () => void }) {
  const status = error instanceof ApiError ? error.status : 0;
  const words = error instanceof ApiError ? error.message : failureText(0, null, null);
  return (
    <div role="alert" className="flex flex-col items-start gap-2 rounded-control border border-danger/40 bg-danger-soft px-3 py-2 text-sm text-danger">
      <p className="m-0">
        <strong>{what} could not be shown.</strong> {words}
      </p>
      {onRetry && retryable(status) && (
        <Button size="sm" onClick={onRetry}>
          Try again
        </Button>
      )}
    </div>
  );
}

export function Loading({ what }: { what: string }) {
  return (
    <p className="m-0 text-sm text-muted" aria-busy="true">
      Loading {what}…
    </p>
  );
}
