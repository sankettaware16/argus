import { Dialog } from "@base-ui/react/dialog";
import { Button } from "./ui/button";

const KEYS: [string, string][] = [
  ["j or Down arrow", "next investigation"],
  ["k or Up arrow", "previous investigation"],
  ["Home, End", "first, last loaded investigation"],
  ["Page Down, Page Up", "a screenful further"],
  ["Enter", "open the investigation and move to it"],
  ["Escape", "from the investigation, back to the list"],
  ["?", "show this list"],
];

const PAGE_KEYS: [string, string][] = [
  ["C", "accept ARGUS's call (only when it makes one)"],
  ["1, 2, 3, 4, 5", "choose your decision: real, act on it; real but harmless; allowed by policy; wrong alert; can't tell yet. Then press Save decision"],
  ["N", "go to the next item of the queue"],
  ["?", "show this list"],
];

/**
 * The keys, in a dialog (Escape closes it and the focus returns to where it was). `page`: the
 * investigation's own page (C, 1 to 5, N); without it, the Inbox's.
 */
export function KeysHelp({ open, onOpenChange, page = false, canReview = true }: { open: boolean; onOpenChange: (open: boolean) => void; page?: boolean; canReview?: boolean }) {
  // an account that cannot review has no use for C and 1 to 5, and they do nothing for it
  const keys = page ? (canReview ? PAGE_KEYS : PAGE_KEYS.filter(([key]) => key === "N" || key === "?")) : KEYS;
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Backdrop className="fixed inset-0 z-40 bg-black/40" />
        <Dialog.Popup className="fixed top-1/2 left-1/2 z-50 flex w-[min(30rem,calc(100vw-2rem))] -translate-x-1/2 -translate-y-1/2 flex-col gap-3 rounded-card border border-border bg-surface p-5 text-text shadow-card">
          <Dialog.Title className="m-0 text-lg font-semibold">{page ? "Keyboard shortcuts on an investigation" : "Keyboard shortcuts in the Inbox"}</Dialog.Title>
          <Dialog.Description className="m-0 text-sm text-muted">
            {page
              ? "These work while you are not typing in a field and no dialog is open. They can be switched off with the “Single-key shortcuts” box on this page; the buttons always work."
              : "These work while the list has the focus. The letter keys can be switched off with the “Single-key shortcuts” box above the list; the arrow keys and Enter always work there."}
          </Dialog.Description>
          <dl className="m-0 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-sm">
            {keys.map(([key, what]) => (
              <div key={key} className="contents">
                <dt>
                  <kbd className="rounded-control border border-border-strong bg-surface-2 px-1.5 py-0.5">{key}</kbd>
                </dt>
                <dd className="m-0">{what}</dd>
              </div>
            ))}
          </dl>
          <div className="flex justify-end">
            <Dialog.Close render={<Button variant="primary" />}>Close</Dialog.Close>
          </div>
        </Dialog.Popup>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
