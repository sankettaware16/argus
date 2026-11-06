import { AlertDialog } from "@base-ui/react/alert-dialog";
import { useMemo, useRef, useState, type ReactNode } from "react";
import { sendExact } from "../lib/api";
import { payloadText, type ExactRequest, type Method, type Payload, type PendingRequest, type Sent } from "../lib/payload";
import { PayloadView } from "./PayloadView";
import { Button } from "./ui/button";

export interface ConfirmDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  /** what happens, in plain words */
  description?: ReactNode;
  /** the exact request: shown whole, and sent as shown */
  request: PendingRequest;
  /** the confirm button's words, e.g. "Send the review" */
  confirmLabel: string;
  /** called with the server's answer once the request was accepted (then the dialog closes) */
  onSent?: (sent: Sent) => void;
  /** how the shown request goes out: sendExact (the default) puts its method, path and text on
   * the wire as they are. Tests and /app/design only; it throws an Error to say why not. */
  send?: (exact: ExactRequest) => Promise<Sent>;
  danger?: boolean;
  /** where the focus goes when the dialog closes: the element to focus, or null for the button that opened it
   * (Q-B2 review B2-R5: the opener may be gone once the change is made) */
  finalFocus?: () => HTMLElement | null;
}

interface Shown {
  method: Method;
  path: string;
  payload: Payload;
}

function same(a: Shown, b: Shown): boolean {
  const text = (p: Payload) => (p.ok ? `+${p.text}` : `-${p.why}`);
  return a.method === b.method && a.path === b.path && text(a.payload) === text(b.payload);
}

/**
 * The confirm dialog (Q-B1, plan §7.5): before a change is sent, the person reads what it does in
 * plain words, with the exact request (method, path, body) one click away under "Show the exact
 * request" (P4-F U9: plain words first), and confirms that. The request is copied when the dialog opens,
 * its body serialized once; that copy is shown and that copy is sent, method, path and text
 * together (review F1). If the page's request changes while the dialog is open, the copy stays,
 * the dialog says so and confirms nothing until the person looks at the new one (review F2).
 * One send at a time (no double submit); Cancel has the focus first; the dialog stays open and
 * says why when sending fails.
 */
export function ConfirmDialog(props: ConfirmDialogProps) {
  const { open, onOpenChange, title, description, request, confirmLabel, onSent, send = sendExact, danger, finalFocus } = props;
  const { method, path, body } = request;
  const current = useMemo<Shown>(() => ({ method, path, payload: payloadText(body) }), [method, path, body]);
  const [shown, setShown] = useState(current);
  const [wasOpen, setWasOpen] = useState(open);
  if (open !== wasOpen) {
    // a fresh copy each time it opens (and when it closes: nothing shows it then)
    setWasOpen(open);
    setShown(current);
  }
  const changed = !same(shown, current);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const cancel = useRef<HTMLButtonElement>(null);
  const busy = useRef(false);

  async function confirm() {
    if (busy.current || changed || !shown.payload.ok) return;
    busy.current = true;
    setSending(true);
    setError(null);
    try {
      const sent = await send({ method: shown.method, path: shown.path, text: shown.payload.text });
      onSent?.(sent);
      onOpenChange(false);
    } catch (e) {
      setError(e instanceof Error && e.message ? e.message : "It could not be sent. Nothing was changed by this attempt; try again.");
    } finally {
      busy.current = false;
      setSending(false);
    }
  }

  return (
    <AlertDialog.Root
      open={open}
      onOpenChange={(next) => {
        if (!next && busy.current) return; // never closed while sending
        setError(null); // a closed dialog forgets its failure
        onOpenChange(next);
      }}
    >
      <AlertDialog.Portal>
        <AlertDialog.Backdrop className="fixed inset-0 z-40 bg-black/40" />
        <AlertDialog.Popup
          initialFocus={cancel}
          finalFocus={finalFocus ? () => finalFocus() ?? true : undefined}
          className="fixed top-1/2 left-1/2 z-50 flex max-h-[90vh] w-[min(42rem,calc(100vw-2rem))] -translate-x-1/2 -translate-y-1/2 flex-col gap-3 overflow-auto rounded-card border border-border bg-surface p-5 text-text shadow-card"
        >
          <AlertDialog.Title className="m-0 text-lg font-semibold">{title}</AlertDialog.Title>
          {description && <AlertDialog.Description className="m-0 text-sm text-muted">{description}</AlertDialog.Description>}
          <details className="text-sm" open={changed || !shown.payload.ok}>
            <summary className="cursor-pointer font-medium">Show the exact request</summary>
            <div className="mt-1">
              <PayloadView method={shown.method} path={shown.path} payload={shown.payload} />
            </div>
          </details>
          {changed && (
            <div
              className="flex flex-wrap items-center gap-2 rounded-control border border-warn/40 bg-warn-soft px-3 py-2 text-sm text-warn"
              role="status"
            >
              <p className="m-0 flex-1">
                This request changed while you were reading it. What is shown is what you read; it cannot be sent until you
                look at the new one.
              </p>
              <Button size="sm" disabled={sending} onClick={() => setShown(current)}>
                Show the new request
              </Button>
            </div>
          )}
          {error && (
            <p className="m-0 rounded-control border border-danger/40 bg-danger-soft px-3 py-2 text-sm text-danger" role="alert">
              {error}
            </p>
          )}
          <div className="flex flex-wrap justify-end gap-2">
            <AlertDialog.Close render={<Button ref={cancel} disabled={sending} />}>Cancel</AlertDialog.Close>
            <Button
              variant={danger ? "danger" : "primary"}
              disabled={sending || changed || !shown.payload.ok}
              onClick={() => void confirm()}
            >
              {sending ? "Sending…" : confirmLabel}
            </Button>
          </div>
        </AlertDialog.Popup>
      </AlertDialog.Portal>
    </AlertDialog.Root>
  );
}
