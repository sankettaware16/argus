import { AlertDialog } from "@base-ui/react/alert-dialog";
import { useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useId, useRef, useState } from "react";
import { previewMerge } from "../../client/sdk.gen";
import { useAnnounce } from "../../lib/announce";
import { unwrap } from "../../lib/call";
import { blockedRows, outcomeWords, type Row } from "../../lib/incidents";
import { changedCase } from "../../lib/queries";
import { inSentence } from "../decide/useOutcome";
import { DEFAULT_REASONS, DISMISS_WAVE1, sendShown } from "../decide/target";
import { UntrustedText } from "../UntrustedText";
import { Button } from "../ui/button";

export const BULK_MAX = 25;
export const MERGE_MAX = 5;

function Shell({ open, onOpenChange, title, children, busy }: { open: boolean; onOpenChange: (o: boolean) => void; title: string; children: React.ReactNode; busy: boolean }) {
  return (
    <AlertDialog.Root open={open} onOpenChange={(next) => (busy && !next ? undefined : onOpenChange(next))}>
      <AlertDialog.Portal>
        <AlertDialog.Backdrop className="fixed inset-0 z-40 bg-black/40" />
        <AlertDialog.Popup className="fixed top-1/2 left-1/2 z-50 flex max-h-[90vh] w-[min(44rem,calc(100vw-2rem))] -translate-x-1/2 -translate-y-1/2 flex-col gap-3 overflow-auto rounded-card border border-border bg-surface p-5 text-text shadow-card">
          <AlertDialog.Title className="m-0 text-lg font-semibold">{title}</AlertDialog.Title>
          {children}
        </AlertDialog.Popup>
      </AlertDialog.Portal>
    </AlertDialog.Root>
  );
}

/**
 * Bulk "Not an incident" (§6.5): one reason for at most 25 possible incidents, each listed with its
 * title and what answered; "Scan or attempt" is not offered when any of them got an answer (the
 * dialog names them); sent one at a time (no bulk route yet: A9), stopping at the first refusal.
 */
export function BulkDismiss({ rows, open, onOpenChange, onDone }: { rows: Row[]; open: boolean; onOpenChange: (o: boolean) => void; onDone: () => void }) {
  const id = useId();
  const queries = useQueryClient();
  const { announce } = useAnnounce();
  const [reason, setReason] = useState("");
  const [note, setNote] = useState("");
  const [progress, setProgress] = useState<string | null>(null);
  const [stopped, setStopped] = useState<string | null>(null);
  const busy = useRef(false);
  const [sending, setSending] = useState(false);
  const items = rows.filter((r) => r.row.state === "suspected").slice(0, BULK_MAX);
  const blocked = blockedRows(items);
  const reasons = DEFAULT_REASONS.filter((r) => r.reason !== "duplicate");
  const chosen = reasons.find((r) => r.reason === reason);

  async function send() {
    if (busy.current || chosen === undefined || items.length === 0) return;
    busy.current = true;
    setSending(true);
    setStopped(null);
    let done = 0;
    for (const r of items) {
      setProgress(`Closing ${done + 1} of ${items.length}…`);
      try {
        await sendShown({ method: "POST", path: `/api/v1/cases/${r.row.id}/dismiss`, body: { expected_version: r.row.version, reason: chosen.reason, ...(note.trim() ? { note: note.trim() } : {}) } });
        done++;
      } catch (e) {
        setStopped(`Stopped at #${r.row.number}: ${e instanceof Error ? e.message : "it was refused"}. ${done === 0 ? "Nothing was closed." : `The ${done} before it ${done === 1 ? "is" : "are"} closed.`}`);
        break;
      }
    }
    setProgress(null);
    busy.current = false;
    setSending(false);
    await changedCase(queries);
    await queries.invalidateQueries({ queryKey: ["today"] });
    if (done === items.length) {
      announce(`${done} possible ${done === 1 ? "incident" : "incidents"} closed: ${inSentence(chosen.label)}.`, "ok");
      onOpenChange(false);
      onDone();
    }
  }

  return (
    <Shell open={open} onOpenChange={onOpenChange} title={`Not an incident: ${items.length} possible ${items.length === 1 ? "incident" : "incidents"}`} busy={sending}>
      <ul className="m-0 flex max-h-56 flex-col gap-1 overflow-auto pl-5 text-sm" data-testid="bulk-items">
        {items.map((r) => (
          <li key={r.row.id}>
            #{r.row.number} <UntrustedText value={r.row.title} limits={{ maxChars: 160, maxLines: 2 }} />
            <span className="text-muted"> — {outcomeWords(r) ?? "what answered is not known"}</span>
          </li>
        ))}
      </ul>
      {rows.length > items.length && <p className="m-0 text-sm text-muted">Only possible incidents are closed here, at most {BULK_MAX} at a time.</p>}
      <fieldset className="m-0 flex flex-col gap-1 border-0 p-0 text-sm">
        <legend className="mb-1 font-medium">Why are they not incidents?</legend>
        {reasons.map((r) => {
          const off = r.reason === "attempt_no_impact" && blocked.length > 0;
          return (
            <label key={r.reason} className="flex items-start gap-2">
              <input type="radio" name={`${id}-r`} className="mt-1 size-4 accent-accent" value={r.reason} checked={reason === r.reason} disabled={off} onChange={() => setReason(r.reason)} />
              <span>
                <strong>{r.label}.</strong> {off ? `${blocked.length} of these got an answer: check them first (${blocked.map((b) => `#${b.row.number}`).join(", ")}).` : r.meaning}
              </span>
            </label>
          );
        })}
      </fieldset>
      <p className="m-0 text-sm" data-testid="bulk-consequence">
        {DISMISS_WAVE1}
      </p>
      <label className="flex flex-col gap-1 text-sm" htmlFor={`${id}-note`}>
        <span className="font-medium">Note (optional, for each)</span>
        <input id={`${id}-note`} value={note} onChange={(e) => setNote(e.target.value)} maxLength={4000} className="min-h-8 rounded-control border border-border-strong bg-surface px-2 text-sm text-text" />
      </label>
      {progress && (
        <p className="m-0 text-sm" role="status">
          {progress}
        </p>
      )}
      {stopped && (
        <p className="m-0 rounded-control border border-danger/40 bg-danger-soft px-3 py-2 text-sm text-danger" role="alert">
          {stopped}
        </p>
      )}
      <div className="flex flex-wrap justify-end gap-2">
        <AlertDialog.Close render={<Button disabled={sending} />}>Cancel</AlertDialog.Close>
        <Button variant="danger" aria-disabled={sending || chosen === undefined} onClick={() => void send()}>
          {sending ? "Closing…" : `Close ${items.length}`}
        </Button>
      </div>
    </Shell>
  );
}

/** Merge into one (§6.5): the highest-priority selected item is the target (changeable); at most 5. */
export function BulkMerge({ rows, open, onOpenChange, onDone }: { rows: Row[]; open: boolean; onOpenChange: (o: boolean) => void; onDone: () => void }) {
  const id = useId();
  const queries = useQueryClient();
  const { announce } = useAnnounce();
  const items = rows.slice(0, MERGE_MAX);
  const [target, setTarget] = useState(items[0]?.row.id ?? "");
  const [error, setError] = useState<string | null>(null);
  const [sending, setSending] = useState(false);
  const into = items.find((r) => r.row.id === target);

  async function send() {
    if (sending || into === undefined) return;
    setSending(true);
    setError(null);
    let done = 0;
    for (const r of items) {
      if (r.row.id === into.row.id) continue;
      try {
        const confirmed = r.row.state !== "suspected";
        const hash = confirmed ? (await unwrap(previewMerge({ path: { case_id: r.row.id }, query: { target: into.row.id, expected_version: r.row.version } }))).payload_hash : null;
        await sendShown({ method: "POST", path: `/api/v1/cases/${r.row.id}/merge`, body: { expected_version: r.row.version, target_case_id: into.row.id, ...(hash ? { payload_hash: hash } : {}) } });
        done++;
      } catch (e) {
        setError(`Stopped at #${r.row.number}: ${e instanceof Error ? e.message : "it was refused"}. ${done} merged before it.`);
        break;
      }
    }
    setSending(false);
    await changedCase(queries);
    if (error === null && done === items.length - 1) {
      announce(`Merged ${done} into incident #${into.row.number} (a confirmed incident's merge waits for an approver).`, "ok");
      onOpenChange(false);
      onDone();
    }
  }

  return (
    <Shell open={open} onOpenChange={onOpenChange} title={`Merge ${items.length} into one`} busy={sending}>
      <fieldset className="m-0 flex flex-col gap-1 border-0 p-0 text-sm">
        <legend className="mb-1 font-medium">Into which?</legend>
        {items.map((r) => (
          <label key={r.row.id} className="flex items-start gap-2">
            <input type="radio" name={`${id}-t`} className="mt-1 size-4 accent-accent" checked={target === r.row.id} onChange={() => setTarget(r.row.id)} />
            <span>
              #{r.row.number} <UntrustedText value={r.row.title} limits={{ maxChars: 160, maxLines: 2 }} />
            </span>
          </label>
        ))}
      </fieldset>
      {rows.length > MERGE_MAX && <p className="m-0 text-sm text-muted">At most {MERGE_MAX} at a time: the first {MERGE_MAX} are here.</p>}
      <p className="m-0 text-sm text-muted">The others move into it with their alert groups. A confirmed incident's merge is asked for: an approver decides.</p>
      {error && (
        <p className="m-0 rounded-control border border-danger/40 bg-danger-soft px-3 py-2 text-sm text-danger" role="alert">
          {error}
        </p>
      )}
      <div className="flex flex-wrap justify-end gap-2">
        <AlertDialog.Close render={<Button disabled={sending} />}>Cancel</AlertDialog.Close>
        <Button variant="primary" aria-disabled={sending || into === undefined} onClick={() => void send()}>
          {sending ? "Merging…" : "Merge"}
        </Button>
      </div>
    </Shell>
  );
}

/** The bar above the list while rows are selected (§6.5): there is no bulk Confirm. */
export function BulkBar({ rows, onClear, togetherIds }: { rows: Row[]; onClear: () => void; togetherIds: string[] }) {
  const [dialog, setDialog] = useState<"dismiss" | "merge" | null>(null);
  return (
    <div data-testid="bulk-bar" className="fixed inset-x-0 bottom-14 z-20 flex flex-wrap items-center gap-2 border-t border-border-strong bg-surface-2 px-4 py-2 text-sm sm:sticky sm:top-0 sm:bottom-auto sm:rounded-card sm:border">
      <span className="font-semibold">{rows.length} selected</span>
      <Button onClick={() => setDialog("dismiss")} aria-disabled={!rows.some((r) => r.row.state === "suspected")}>
        Not an incident ▾
      </Button>
      <Button onClick={() => setDialog("merge")} aria-disabled={rows.length < 2}>
        Merge into one…
      </Button>
      <Link to="/incidents" search={(prev: Record<string, unknown>) => ({ ...prev, view: (prev.view as never) ?? "needs-you", together: togetherIds })} className="inline-flex min-h-8 items-center rounded-control border border-border-strong bg-surface px-3 font-medium text-text no-underline hover:bg-surface-3">
        Review together
      </Link>
      <Button variant="ghost" onClick={onClear}>
        Clear
      </Button>
      <span className="text-muted">Confirm incidents one at a time.</span>
      {dialog === "dismiss" && <BulkDismiss rows={rows} open onOpenChange={(o) => !o && setDialog(null)} onDone={onClear} />}
      {dialog === "merge" && <BulkMerge rows={rows} open onOpenChange={(o) => !o && setDialog(null)} onDone={onClear} />}
    </div>
  );
}
