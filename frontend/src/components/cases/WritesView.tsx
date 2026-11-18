import { HARD_MAX } from "../../lib/untrusted";
import { describeWrite } from "../../lib/cases";
import { UntrustedText } from "../UntrustedText";

const WHOLE = { maxChars: HARD_MAX, maxLines: HARD_MAX };

/**
 * The exact writes a closure or merge binds, as an approver reads them: a line for each, then
 * every character of the payload on demand, and the fingerprint (the hash the request carries).
 * Nothing here is sent anywhere; it is what the approval is about.
 */
export function WritesView({ payload, hash }: { payload: Record<string, unknown>; hash: string }) {
  const writes = Array.isArray(payload.writes) ? (payload.writes as unknown[]) : [];
  return (
    <div className="flex flex-col gap-1.5" data-testid="writes">
      {writes.length === 0 ? (
        <p className="m-0 text-sm">Nothing is written to Kibana (the case is not there); the change is recorded in ARGUS only.</p>
      ) : (
        <>
          <p className="m-0 text-sm font-medium">
            {writes.length} {writes.length === 1 ? "change" : "changes"} to Kibana:
          </p>
          <ol className="m-0 pl-5 text-sm">
            {writes.map((w, i) => (
              <li key={i}>
                <UntrustedText value={describeWrite(w)} limits={{ maxChars: 600, maxLines: 6 }} />
              </li>
            ))}
          </ol>
        </>
      )}
      <details>
        <summary className="cursor-pointer text-sm font-medium">The exact writes (raw)</summary>
        <pre className="m-0 mt-1 max-h-80 overflow-auto rounded-control bg-surface-2 p-2 text-xs" tabIndex={0} aria-label="The exact payload">
          <UntrustedText value={JSON.stringify(payload, null, 2)} block limits={WHOLE} />
        </pre>
      </details>
      <p className="m-0 text-xs text-muted">
        Fingerprint of these writes: <code data-testid="fingerprint">{hash.slice(0, 16)}</code>… (the request carries the whole hash).
      </p>
    </div>
  );
}
