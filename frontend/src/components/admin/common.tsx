import { Dialog } from "@base-ui/react/dialog";
import { useQueryClient } from "@tanstack/react-query";
import { useRouterState } from "@tanstack/react-router";
import { useEffect, type ReactNode } from "react";
import { cn } from "../../lib/cn";
import { useNow } from "../../lib/now";
import { can, sessionQuery, useSession } from "../../lib/session";
import { parse } from "../../lib/time";
import { Time } from "../Time";
import { Button } from "../ui/button";

/** The administration pages are for administrators: anyone else is told so (the API refuses them too). */
export function AdminOnly({ what, children }: { what: string; children: ReactNode }) {
  const session = useSession();
  if (session.isPending) return <p className="m-0 text-sm text-muted">Loading…</p>;
  if (!can(session.data, "admin")) {
    return (
      <>
        <h1 className="m-0 text-2xl font-semibold">{what}</h1>
        <p className="m-0 text-sm text-muted" data-testid="admin-only">
          Only an ARGUS administrator can open this page. Ask one to change what you need.
        </p>
      </>
    );
  }
  return children;
}

/** The step-up page, in a new tab so nothing typed here is lost; back at this page afterwards. */
export function StepUpLink({ label = "Confirm your password" }: { label?: string }) {
  const here = useRouterState({ select: (s) => s.location.pathname });
  return (
    <a href={`/stepup?${new URLSearchParams({ next: `/app${here === "/" ? "" : here}` }).toString()}`} target="_blank" rel="noopener noreferrer" className="text-sm">
      {label} (opens a new tab)
    </a>
  );
}

/** Says whether the person's password was confirmed in the last five minutes, and where to do it. */
export function StepUpNote() {
  const session = useSession();
  const queries = useQueryClient();
  // back from the step-up tab: read the session again
  useEffect(() => {
    const again = () => void queries.invalidateQueries({ queryKey: sessionQuery.queryKey });
    window.addEventListener("focus", again);
    return () => window.removeEventListener("focus", again);
  }, [queries]);
  const now = useNow(30_000);
  const until = parse(session.data?.step_up_valid_until);
  const fresh = until !== null && until.getTime() > now;
  return (
    <p className="m-0 text-sm text-muted" data-testid="step-up-note">
      {fresh ? (
        <>
          Your password was confirmed; changes that need it are allowed until <Time value={until} />.
        </>
      ) : (
        <>
          Some changes need your password again (confirmed within the last five minutes). <StepUpLink />
        </>
      )}
    </p>
  );
}

export function Notice({ tone, children, testId, role = "status" }: { tone: "warn" | "danger" | "info" | "ok"; children: ReactNode; testId?: string; role?: "status" | "alert" }) {
  const tones = {
    warn: "border-warn/40 bg-warn-soft text-warn",
    danger: "border-danger/40 bg-danger-soft text-danger",
    info: "border-info/40 bg-info-soft text-info",
    ok: "border-ok/40 bg-ok-soft text-ok",
  };
  return (
    <div role={role} data-testid={testId} className={cn("rounded-control border px-3 py-2 text-sm", tones[tone])}>
      {children}
    </div>
  );
}

/** A dialog with a title, a body and its own buttons. */
export function Modal({ open, onOpenChange, title, description, children, wide = false }: { open: boolean; onOpenChange: (open: boolean) => void; title: string; description?: ReactNode; children: ReactNode; wide?: boolean }) {
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Backdrop className="fixed inset-0 z-40 bg-black/40" />
        <Dialog.Popup className={cn("fixed top-1/2 left-1/2 z-50 flex max-h-[90vh] -translate-x-1/2 -translate-y-1/2 flex-col gap-3 overflow-auto rounded-card border border-border bg-surface p-5 text-text shadow-card", wide ? "w-[min(40rem,calc(100vw-2rem))]" : "w-[min(30rem,calc(100vw-2rem))]")}>
          <Dialog.Title className="m-0 text-lg font-semibold">{title}</Dialog.Title>
          {description && <Dialog.Description className="m-0 text-sm text-muted">{description}</Dialog.Description>}
          {children}
        </Dialog.Popup>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  return (
    <Button
      size="sm"
      onClick={() => {
        void navigator.clipboard?.writeText(text).catch(() => undefined);
      }}
    >
      {label}
    </Button>
  );
}
