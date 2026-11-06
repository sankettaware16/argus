import { useEffect, useRef, useState } from "react";
import { useDecided } from "../../lib/decided";
import { Button } from "../ui/button";

const SHOWN_MS = 10_000;

/**
 * The toast after a dismissal (§5.5): "Incident #29 closed: … [Undo]", for 10 s, kept open while
 * the pointer is on it or the focus is in it. The result itself was already announced; Undo stays
 * on Today's "Just decided" row for the rest of the session.
 */
export function UndoToast() {
  const { toast, close } = useDecided();
  const [held, setHeld] = useState({ hover: false, focus: false });
  const [busy, setBusy] = useState(false);
  const timer = useRef<number | null>(null);
  const paused = held.hover || held.focus;

  useEffect(() => {
    if (toast === null || paused) return;
    timer.current = window.setTimeout(close, SHOWN_MS);
    return () => {
      if (timer.current !== null) window.clearTimeout(timer.current);
    };
  }, [toast, paused, close]);

  if (toast === null) return null;
  return (
    <div
      data-testid="undo-toast"
      onMouseEnter={() => setHeld((h) => ({ ...h, hover: true }))}
      onMouseLeave={() => setHeld((h) => ({ ...h, hover: false }))}
      onFocus={() => setHeld((h) => ({ ...h, focus: true }))}
      onBlur={() => setHeld((h) => ({ ...h, focus: false }))}
      className="fixed right-4 bottom-20 left-4 z-40 mx-auto flex max-w-xl flex-wrap items-center justify-between gap-2 rounded-card border border-border-strong bg-surface px-4 py-3 text-sm text-text shadow-card sm:bottom-4"
    >
      <p className="m-0 min-w-0 flex-1">{toast.text}</p>
      <div className="flex gap-2">
        {toast.undo !== null && (
          <Button
            variant="primary"
            aria-disabled={busy}
            onClick={() => {
              if (busy || toast.undo === null) return;
              setBusy(true);
              void toast.undo().finally(() => setBusy(false));
            }}
          >
            Undo
          </Button>
        )}
        <Button variant="ghost" onClick={close} aria-label="Close this message">
          Close
        </Button>
      </div>
    </div>
  );
}
