import { HARD_MAX } from "../lib/untrusted";
import type { Method, Payload } from "../lib/payload";
import { UntrustedText } from "./UntrustedText";

const WHOLE = { maxChars: HARD_MAX, maxLines: HARD_MAX };

/** The exact request a change sends: method, path and body, every character visible. */
export function PayloadView({ method, path, payload }: { method: Method; path: string; payload: Payload }) {
  return (
    <figure className="m-0 overflow-hidden rounded-control border border-border bg-surface-2">
      <figcaption className="flex flex-wrap items-baseline gap-x-2 border-b border-border px-3 py-2 text-sm">
        <span className="font-semibold">{method}</span>
        <code className="break-all">
          <UntrustedText value={path} limits={WHOLE} />
        </code>
      </figcaption>
      {payload.ok ? (
        payload.empty ? (
          <p className="m-0 px-3 py-2 text-sm text-muted">No body: the request sends nothing else.</p>
        ) : (
          <pre
            className="m-0 max-h-80 overflow-auto px-3 py-2 text-sm leading-relaxed"
            data-testid="payload"
            tabIndex={0}
            aria-label="The exact body that will be sent"
          >
            <UntrustedText value={payload.text} limits={WHOLE} block />
          </pre>
        )
      ) : (
        <p className="m-0 px-3 py-2 text-sm text-danger" role="alert">
          {payload.why}
        </p>
      )}
    </figure>
  );
}
