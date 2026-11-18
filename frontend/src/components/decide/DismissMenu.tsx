import { useEffect, useId, useRef, useState, type KeyboardEvent, type MutableRefObject, type ReactNode } from "react";
import type { CaseRowOut, DismissChoiceOut } from "../../client/types.gen";
import { SendError } from "../../lib/api";
import { scanReasonBlocked } from "../../lib/engine";
import { payloadText } from "../../lib/payload";
import { cn } from "../../lib/cn";
import { PayloadView } from "../PayloadView";
import { UntrustedText } from "../UntrustedText";
import { Button } from "../ui/button";
import { dismissSentence, sendShown, type Shown, type Target } from "./target";

/** The mnemonic letter of each reason (§5.5, F16): never a digit. */
export const REASON_KEYS: Readonly<Record<string, string>> = {
  benign_expected: "e",
  attempt_no_impact: "s",
  benign_policy: "p",
  rule_false_positive: "w",
  duplicate: "u",
};

/** The reasons a TA is offered, in the server's order ("Created in error" is the lead's, §18). */
export function offered(reasons: readonly DismissChoiceOut[]): DismissChoiceOut[] {
  return reasons.filter((r) => r.reason !== "created_in_error" && REASON_KEYS[r.reason] !== undefined);
}

const NOTE_MAX = 4000;

export interface DismissProps {
  target: Target;
  onDismissed: (row: CaseRowOut, label: string) => void;
  onConflict: () => void;
  /** "Duplicate of…": the merge picker, where the control has one */
  onDuplicate?: () => void;
  /** the link "Ask ARGUS to check" under a blocked "Scan or attempt" */
  checkLink?: ReactNode;
  /** the `d` key: opens the menu */
  openRef?: MutableRefObject<(() => void) | null>;
  disabled?: { why: string; id: string } | null;
  size?: "md" | "touch";
  /** the button's words (the phone card's "More") */
  label?: string;
  extraItems?: ReactNode;
}

/**
 * "Not an incident ▾" (§5.5): a menu of the server's reasons, each with its letter and one-line
 * help; "Scan or attempt" is disabled when something answered (it says so, with the way to check).
 * A reason opens a one-line sheet under the button that says the consequence before anything is
 * sent; Enter sends, so `d` `s` `Enter` is the whole keyboard path. Duplicate opens the merge picker.
 */
export function DismissMenu({ target, onDismissed, onConflict, onDuplicate, checkLink, openRef, disabled = null, size = "md", label = "Not an incident ▾", extraItems }: DismissProps) {
  const id = useId();
  const [stage, setStage] = useState<"closed" | "menu" | DismissChoiceOut>("closed");
  const button = useRef<HTMLButtonElement>(null);
  const items = useRef<(HTMLElement | null)[]>([]);
  const box = useRef<HTMLDivElement>(null);
  const reasons = offered(target.reasons);
  const blocked = scanReasonBlocked(target.engine, target.title);
  const usable = (r: DismissChoiceOut) => !(r.reason === "attempt_no_impact" && blocked) && (r.reason !== "duplicate" || onDuplicate !== undefined);

  const off = disabled !== null;
  const openMenu = () => {
    if (!off) setStage("menu");
  };
  useEffect(() => {
    if (!openRef) return;
    openRef.current = () => !off && setStage("menu");
    return () => {
      openRef.current = null;
    };
  }, [openRef, off]);

  useEffect(() => {
    if (stage === "menu") {
      const first = items.current.find((el) => el !== null && el.getAttribute("aria-disabled") !== "true");
      first?.focus();
    }
  }, [stage]);

  useEffect(() => {
    if (stage === "closed") return;
    const away = (e: MouseEvent) => {
      if (box.current && !box.current.contains(e.target as Node)) setStage("closed");
    };
    document.addEventListener("mousedown", away);
    return () => document.removeEventListener("mousedown", away);
  }, [stage]);

  const close = () => {
    setStage("closed");
    button.current?.focus();
  };

  const pick = (r: DismissChoiceOut) => {
    if (!usable(r)) return;
    if (r.reason === "duplicate") {
      setStage("closed");
      onDuplicate?.();
      return;
    }
    setStage(r);
  };

  const onMenuKey = (e: KeyboardEvent<HTMLDivElement>) => {
    const els = items.current.filter((el): el is HTMLElement => el !== null);
    const at = els.indexOf(document.activeElement as HTMLElement);
    if (e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      close();
    } else if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      const step = e.key === "ArrowDown" ? 1 : -1;
      els[(at + step + els.length) % els.length]?.focus();
    } else if (e.key === "Home" || e.key === "End") {
      e.preventDefault();
      (e.key === "Home" ? els[0] : els.at(-1))?.focus();
    } else if (e.key.length === 1 && !e.ctrlKey && !e.metaKey && !e.altKey) {
      const r = reasons.find((x) => REASON_KEYS[x.reason] === e.key.toLowerCase());
      if (r !== undefined) {
        e.preventDefault();
        e.stopPropagation();
        pick(r);
      } else if (/^\d$/.test(e.key)) {
        e.preventDefault(); // no digits here (F16): the alert group's 1–5 do nothing in this menu
        e.stopPropagation();
      }
    }
  };

  return (
    <div ref={box} className="relative inline-block">
      <Button
        ref={button}
        className={cn(size === "touch" && "min-h-11")}
        aria-haspopup="menu"
        aria-expanded={stage === "menu"}
        aria-controls={stage === "menu" ? `${id}-menu` : undefined}
        aria-disabled={disabled !== null}
        aria-describedby={disabled?.id}
        onClick={() => (stage === "closed" ? openMenu() : setStage("closed"))}
        data-testid="dismiss-button"
      >
        {label}
      </Button>
      {stage === "menu" && (
        <div
          id={`${id}-menu`}
          role="menu"
          aria-label="Why is it not an incident?"
          onKeyDown={onMenuKey}
          className="absolute left-0 z-30 mt-1 flex w-[min(26rem,calc(100vw-2rem))] flex-col rounded-card border border-border bg-raised p-1 text-text shadow-card"
          data-testid="dismiss-menu"
        >
          {reasons.map((r, i) => {
            const off = !usable(r);
            const scan = r.reason === "attempt_no_impact" && blocked;
            return (
              <div key={r.reason} className="flex flex-col">
                <div
                  ref={(el) => {
                    items.current[i] = el;
                  }}
                  role="menuitem"
                  tabIndex={-1}
                  aria-disabled={off || undefined}
                  data-reason={r.reason}
                  onClick={() => pick(r)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      e.stopPropagation();
                      pick(r);
                    }
                  }}
                  className={cn("flex cursor-pointer flex-col gap-0.5 rounded-control px-3 py-2 text-sm outline-none hover:bg-surface-2 focus:bg-accent-soft", off && "cursor-not-allowed opacity-70")}
                >
                  <span className="flex items-baseline justify-between gap-3">
                    <span className="font-medium">
                      <UntrustedText value={r.label} limits={{ maxChars: 80, maxLines: 1 }} />
                    </span>
                    <kbd className="rounded border border-border px-1 text-xs text-muted" aria-hidden="true">
                      {REASON_KEYS[r.reason]}
                    </kbd>
                  </span>
                  <span className="text-muted">{scan ? "Something answered: check first" : <UntrustedText value={r.meaning} limits={{ maxChars: 240, maxLines: 3 }} />}</span>
                </div>
                {scan && checkLink !== undefined && <div className="px-3 pb-2 text-sm">{checkLink}</div>}
              </div>
            );
          })}
          {extraItems}
        </div>
      )}
      {typeof stage === "object" && <DismissSheet target={target} reason={stage} onCancel={close} onDismissed={(row) => { setStage("closed"); onDismissed(row, stage.label); }} onConflict={() => { setStage("closed"); onConflict(); }} />}
    </div>
  );
}

/** The one-line sheet (§5.5): the consequence first, an optional note, the exact request, Close it. */
export function DismissSheet({ target, reason, onCancel, onDismissed, onConflict }: { target: Target; reason: DismissChoiceOut; onCancel: () => void; onDismissed: (row: CaseRowOut) => void; onConflict: () => void }) {
  const id = useId();
  const [note, setNote] = useState("");
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const busy = useRef(false);
  const field = useRef<HTMLInputElement>(null);
  const said = note.trim();
  const request: Shown = { method: "POST", path: `/api/v1/cases/${target.id}/dismiss`, body: { expected_version: target.version, reason: reason.reason, ...(said !== "" ? { note: said } : {}) } };
  useEffect(() => field.current?.focus(), []);

  async function send() {
    if (busy.current || said.length > NOTE_MAX) return;
    busy.current = true;
    setSending(true);
    setError(null);
    try {
      const changed = await sendShown(request);
      onDismissed(changed.case);
    } catch (e) {
      if (e instanceof SendError && e.status === 409) onConflict();
      else setError(e instanceof Error && e.message ? e.message : "It could not be sent. Nothing was changed; try again.");
    } finally {
      busy.current = false;
      setSending(false);
    }
  }

  return (
    <form
      role="group"
      aria-labelledby={`${id}-say`}
      data-testid="dismiss-sheet"
      onSubmit={(e) => {
        e.preventDefault();
        void send();
      }}
      onKeyDown={(e) => {
        if (e.key === "Escape") {
          e.preventDefault();
          e.stopPropagation();
          onCancel();
        }
      }}
      className="absolute left-0 z-30 mt-1 flex w-[min(34rem,calc(100vw-2rem))] flex-col gap-2 rounded-card border border-border bg-raised p-3 text-sm text-text shadow-card"
    >
      <p id={`${id}-say`} className="m-0" data-testid="dismiss-consequence">
        Close #{target.number} as “<UntrustedText value={reason.label} limits={{ maxChars: 80, maxLines: 1 }} />”. <UntrustedText value={dismissSentence(target)} limits={{ maxChars: 400, maxLines: 4 }} />
      </p>
      <label className="flex flex-col gap-1" htmlFor={`${id}-note`}>
        <span className="font-medium">Note (optional)</span>
        <input ref={field} id={`${id}-note`} value={note} maxLength={NOTE_MAX + 1} onChange={(e) => setNote(e.target.value)} className="min-h-8 rounded-control border border-border-strong bg-bg px-2 text-sm text-text" />
      </label>
      <details>
        <summary className="cursor-pointer font-medium">Show the exact request</summary>
        <div className="mt-1">
          <PayloadView method={request.method} path={request.path} payload={payloadText(request.body)} />
        </div>
      </details>
      {error && (
        <p className="m-0 rounded-control border border-danger/40 bg-danger-soft px-3 py-2 text-danger" role="alert">
          {error}
        </p>
      )}
      <div className="flex flex-wrap justify-end gap-2">
        <Button onClick={onCancel} aria-disabled={sending}>
          Cancel
        </Button>
        <Button type="submit" variant="primary" aria-disabled={sending}>
          {sending ? "Sending…" : "Close it"}
        </Button>
      </div>
    </form>
  );
}
