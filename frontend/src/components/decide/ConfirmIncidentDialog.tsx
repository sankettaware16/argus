import { AlertDialog } from "@base-ui/react/alert-dialog";
import { useId, useRef, useState } from "react";
import type { CaseRowOut } from "../../client/types.gen";
import { SendError } from "../../lib/api";
import { stillOpen } from "../../lib/engine";
import { payloadText } from "../../lib/payload";
import { PayloadView } from "../PayloadView";
import { UntrustedText } from "../UntrustedText";
import { Button } from "../ui/button";
import { confirmSentence, sendShown, type Shown, type Target } from "./target";

const NOTE_MAX = 4000;

export interface ConfirmIncidentProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  target: Target;
  /** the person may take cases (manage_cases): "Take it myself" is offered */
  canTake: boolean;
  /** the signed-in person's username (a hold by someone else is warned of) */
  me: string | null;
  onConfirmed: (row: CaseRowOut, takeFailed: string | null) => void;
  /** a 409: the case moved; nothing was sent after it */
  onConflict: () => void;
  finalFocus?: () => HTMLElement | null;
}

/**
 * Confirm incident (docs/p4f-ui-spec.md §5.4, F1, F15): what happens, in the server's words (never
 * a promise of a Kibana post); what still argues against it, when anything does ("Confirm anyway"
 * then); an optional note and "Take it myself"; the exact request one click away, built from what
 * is on screen and sent as shown.
 */
export function ConfirmIncidentDialog({ open, onOpenChange, target, canTake, me, onConfirmed, onConflict, finalFocus }: ConfirmIncidentProps) {
  const id = useId();
  const [note, setNote] = useState("");
  const [take, setTake] = useState(false);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const busy = useRef(false);
  const cancel = useRef<HTMLButtonElement>(null);
  const open_ = stillOpen(target.engine ?? (target.alternatives?.length ? { alternatives: [...target.alternatives], checks: [] } : null));
  const said = note.trim();
  const tooLong = said.length > NOTE_MAX;
  const request: Shown = { method: "POST", path: `/api/v1/cases/${target.id}/confirm`, body: { expected_version: target.version, ...(said !== "" ? { note: said } : {}) } };
  const payload = payloadText(request.body);
  const heldByOther = target.hold !== null && target.hold.by.username !== me;

  async function confirm() {
    if (busy.current || tooLong) return;
    busy.current = true;
    setSending(true);
    setError(null);
    try {
      const changed = await sendShown(request);
      let takeFailed: string | null = null;
      if (take) {
        try {
          const took = await sendShown({ method: "POST", path: `/api/v1/cases/${target.id}/take`, body: { expected_version: changed.case.version } });
          onConfirmed(took.case, null);
        } catch (e) {
          takeFailed = e instanceof Error ? e.message : "it was refused";
          onConfirmed(changed.case, takeFailed);
        }
      } else onConfirmed(changed.case, null);
      setNote("");
      setTake(false);
      onOpenChange(false);
    } catch (e) {
      if (e instanceof SendError && e.status === 409) {
        onOpenChange(false);
        onConflict();
      } else setError(e instanceof Error && e.message ? e.message : "It could not be sent. Nothing was changed by this attempt; try again.");
    } finally {
      busy.current = false;
      setSending(false);
    }
  }

  return (
    <AlertDialog.Root
      open={open}
      onOpenChange={(next) => {
        if (!next && busy.current) return;
        setError(null);
        onOpenChange(next);
      }}
    >
      <AlertDialog.Portal>
        <AlertDialog.Backdrop className="fixed inset-0 z-40 bg-black/40" />
        <AlertDialog.Popup
          initialFocus={cancel}
          finalFocus={finalFocus ? () => finalFocus() ?? true : undefined}
          data-testid="confirm-incident"
          className="fixed top-1/2 left-1/2 z-50 flex max-h-[90vh] w-[min(42rem,calc(100vw-2rem))] -translate-x-1/2 -translate-y-1/2 flex-col gap-3 overflow-auto rounded-card border border-border bg-raised p-5 text-text shadow-card"
        >
          <AlertDialog.Title className="m-0 text-lg font-semibold">Confirm incident #{target.number}?</AlertDialog.Title>
          <p className="m-0 text-sm font-medium">
            <UntrustedText value={target.title} limits={{ maxChars: 240, maxLines: 3 }} />
          </p>
          <AlertDialog.Description className="m-0 text-sm" data-testid="what-happens">
            <span className="font-semibold">What happens: </span>
            <UntrustedText value={confirmSentence(target)} limits={{ maxChars: 600, maxLines: 6 }} />
          </AlertDialog.Description>
          {heldByOther && target.hold !== null && (
            <p className="m-0 rounded-control border border-warn/40 bg-warn-soft px-3 py-2 text-sm text-warn" role="note">
              <UntrustedText value={target.hold.by.name} limits={{ maxChars: 60, maxLines: 1 }} /> is checking this. Decide anyway?
            </p>
          )}
          {open_.lines.length > 0 && (
            <section aria-labelledby={`${id}-open`} className="flex flex-col gap-1 rounded-control bg-surface-2 px-3 py-2 text-sm" data-testid="still-open">
              <h3 id={`${id}-open`} className="m-0 text-sm font-semibold">
                Still open — read before you confirm:
              </h3>
              <ul className="m-0 flex flex-col gap-1 pl-5">
                {open_.lines.map((line, i) => (
                  <li key={i}>
                    <UntrustedText value={line} limits={{ maxChars: 400, maxLines: 4 }} />
                  </li>
                ))}
              </ul>
              {open_.more > 0 && <p className="m-0 text-muted">+{open_.more} more on the incident's page</p>}
            </section>
          )}
          {canTake && (
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" className="size-4 accent-accent" checked={take} onChange={(e) => setTake(e.target.checked)} />
              Take it myself
            </label>
          )}
          <label className="flex flex-col gap-1 text-sm" htmlFor={`${id}-note`}>
            <span className="font-medium">Note (optional)</span>
            <textarea
              id={`${id}-note`}
              rows={2}
              maxLength={NOTE_MAX + 1}
              value={note}
              onChange={(e) => setNote(e.target.value)}
              className="rounded-control border border-border-strong bg-bg px-2 py-1 text-sm text-text"
            />
          </label>
          {tooLong && <p className="m-0 text-sm text-danger">The note is longer than {NOTE_MAX} characters.</p>}
          <details className="text-sm">
            <summary className="cursor-pointer font-medium">Show the exact request</summary>
            <div className="mt-1">
              <PayloadView method={request.method} path={request.path} payload={payload} />
            </div>
          </details>
          {error && (
            <p className="m-0 rounded-control border border-danger/40 bg-danger-soft px-3 py-2 text-sm text-danger" role="alert">
              {error}
            </p>
          )}
          <div className="flex flex-wrap justify-end gap-2">
            <AlertDialog.Close render={<Button ref={cancel} disabled={sending} />}>Cancel</AlertDialog.Close>
            <Button variant="primary" aria-disabled={sending || tooLong} onClick={() => void confirm()}>
              {sending ? "Sending…" : open_.lines.length > 0 ? "Confirm anyway" : "Confirm incident"}
            </Button>
          </div>
        </AlertDialog.Popup>
      </AlertDialog.Portal>
    </AlertDialog.Root>
  );
}
