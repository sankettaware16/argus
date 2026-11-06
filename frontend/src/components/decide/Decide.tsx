import { useEffect, useRef, useState, type MutableRefObject, type ReactNode } from "react";
import type { CaseRowOut } from "../../client/types.gen";
import { cn } from "../../lib/cn";
import { can, useSession } from "../../lib/session";
import { Button } from "../ui/button";
import { ConfirmIncidentDialog } from "./ConfirmIncidentDialog";
import { DismissMenu } from "./DismissMenu";
import type { Target } from "./target";
import { useOutcome } from "./useOutcome";

export interface DecideKeys {
  confirm: MutableRefObject<(() => void) | null>;
  dismiss: MutableRefObject<(() => void) | null>;
}

export function useDecideKeys(): DecideKeys {
  return { confirm: useRef<(() => void) | null>(null), dismiss: useRef<(() => void) | null>(null) };
}

/**
 * The two answers on a possible incident, wherever it is shown (§5.3, §6.4, §7.1): Confirm
 * incident… (primary) and Not an incident ▾. "I'm checking" needs the hold route (A1), which the
 * server does not serve yet, so it is not offered. `onDone` follows a decision (a card collapses);
 * `onConflict` a 409 (the case moved: nothing was sent).
 */
export function PossibleButtons({
  target,
  size = "md",
  confirmRef,
  dismissRef,
  onDone,
  onConflict,
  onDuplicate,
  checkLink,
  confirmDisabled = null,
  dismissDisabled = null,
  children,
}: {
  target: Target;
  size?: "md" | "touch";
  /** the `c` and `d` keys of the page that holds these buttons */
  confirmRef?: MutableRefObject<(() => void) | null>;
  dismissRef?: MutableRefObject<(() => void) | null>;
  onDone?: (row: CaseRowOut, kind: "confirmed" | "closed") => void;
  onConflict?: () => void;
  onDuplicate?: () => void;
  checkLink?: ReactNode;
  confirmDisabled?: { why: string; id: string } | null;
  dismissDisabled?: { why: string; id: string } | null;
  children?: ReactNode;
}) {
  const [asking, setAsking] = useState(false);
  const session = useSession();
  const outcome = useOutcome();
  const confirmButton = useRef<HTMLButtonElement>(null);
  const open = () => {
    if (confirmDisabled === null) setAsking(true);
  };
  const off = confirmDisabled !== null;
  useEffect(() => {
    if (!confirmRef) return;
    confirmRef.current = () => !off && setAsking(true);
    return () => {
      confirmRef.current = null;
    };
  }, [confirmRef, off]);
  const conflict = () => {
    outcome.conflict(target.id);
    onConflict?.();
  };
  return (
    <div className="flex flex-wrap items-center gap-2" data-testid="decide-buttons">
      <Button ref={confirmButton} variant="primary" className={cn(size === "touch" && "min-h-11")} aria-disabled={confirmDisabled !== null} aria-describedby={confirmDisabled?.id} onClick={open}>
        Confirm incident…
      </Button>
      <DismissMenu
        target={target}
        size={size}
        openRef={dismissRef}
        disabled={dismissDisabled}
        checkLink={checkLink}
        onDuplicate={onDuplicate}
        onConflict={conflict}
        onDismissed={(row, label) => {
          outcome.dismissed(target, row, label);
          onDone?.(row, "closed");
        }}
      />
      {children}
      <ConfirmIncidentDialog
        open={asking}
        onOpenChange={setAsking}
        target={target}
        canTake={can(session.data, "manage_cases")}
        me={session.data?.user.username ?? null}
        onConflict={conflict}
        onConfirmed={(row, takeFailed) => {
          outcome.confirmed(target, row, takeFailed);
          onDone?.(row, "confirmed");
        }}
      />
    </div>
  );
}
