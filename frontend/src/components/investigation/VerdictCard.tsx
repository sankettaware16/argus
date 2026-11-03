import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { useEffect, useId, useRef, useState } from "react";
import type { InvestigationDetail } from "../../client/types.gen";
import { useAnnounce } from "../../lib/announce";
import { count } from "../../lib/format";
import { outcomeLabel } from "../../lib/labels";
import { endWords, useNext } from "../../lib/queueNext";
import { reportsOptions } from "../../lib/queries";
import { useShortcuts } from "../../lib/useShortcuts";
import { keyFacts, knownSentence, needsReview, patternSize, stanceHeadline, stanceSource } from "../../lib/verdict";
import { dialogOpen, verdictAct } from "../../lib/verdictKeys";
import { KeysHelp } from "../KeysHelp";
import { Time } from "../Time";
import { UntrustedText } from "../UntrustedText";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Check } from "../ui/field";
import { ReviewPanel } from "./ReviewPanel";
import { useReview } from "./useReview";

/** The key a button answers to, drawn on it; the button's name stays its own words (aria-keyshortcuts says the key). */
function Key({ children }: { children: string }) {
  return (
    <kbd aria-hidden="true" className="rounded-control border border-border-strong bg-surface px-1 text-xs">
      {children}
    </kbd>
  );
}

/**
 * The verdict-first top card (AR4, D-182): what ARGUS recommends, or its reading and why it is not
 * a proposal; the few facts behind it, each linking to its raw rows; the size of its pattern; and
 * Confirm, Change and Next in one place. Under it the review form (outcome, note) is the same
 * control Confirm uses. `queue` is the investigation's own page: Next and the keys (C confirms, 1 to
 * 5 choose an outcome, N goes on) belong to it; in the Inbox's pane the list is the way on.
 */
export function VerdictCard({ detail, queue = false }: { detail: InvestigationDetail; queue?: boolean }) {
  const inv = detail.investigation;
  const stance = detail.stance;
  const review = useReview(detail);
  const reports = useQuery(reportsOptions(inv.id));
  const next = useNext(inv.id, queue);
  const navigate = useNavigate();
  const { announce } = useAnnounce();
  const [shortcuts, setShortcuts] = useShortcuts();
  const [help, setHelp] = useState(false);
  const headline = useId();
  const holdId = useId();
  const [reached, setReached] = useState(false); // Next was asked at the end of the queue
  const nextButton = useRef<HTMLButtonElement>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const settle = useRef(false); // a confirmation was saved: the focus goes on once the page has been read again
  const [, setSettled] = useState(0);
  const facts = keyFacts(reports.data?.items[0], detail.dossier?.facts);
  const size = patternSize(stance);
  const source = stanceSource(stance);
  const open = needsReview(inv);

  const end = endWords(next.walked, next.total);
  const goNext = () => {
    if (next.next === null || next.next.id === null) {
      setReached(true);
      announce(next.loading ? "The queue is still loading." : next.failed ? "The queue could not be read, so Next has nowhere to go." : end.text, "info");
      return;
    }
    void navigate({ to: "/investigations/$id", params: { id: next.next.id } });
  };
  const choose = (outcome: string) => {
    review.setOutcome(outcome);
    announce(`Chosen: ${outcomeLabel(outcome)}. Press Mark reviewed to save it.`, "info");
    document.querySelector<HTMLElement>('form[aria-label="Review this investigation"] button[type="submit"]')?.focus();
  };
  const change = () => document.querySelector<HTMLElement>('form[aria-label="Review this investigation"] select')?.focus();
  // Confirm saved: the button is gone with the recommendation, so the focus goes to Next (the way
  // on), or to the headline when there is no Next (AR4 review, D-186)
  const confirm = async () => {
    if (await review.confirm()) {
      settle.current = true;
      setSettled((n) => n + 1); // a render to land the focus in, whatever else was pending
    }
  };
  useEffect(() => {
    if (!settle.current) return;
    settle.current = false;
    const target = queue && next.next !== null && next.next.id !== null ? nextButton.current : null;
    (target ?? headingRef.current)?.focus();
  });

  // the keys: one listener, whose handlers are always the latest render's
  const latest = useRef({ confirm, goNext, choose, confirmable: review.confirmable, goldOnly: review.goldOnly, canReview: review.canReview });
  useEffect(() => {
    latest.current = { confirm, goNext, choose, confirmable: review.confirmable, goldOnly: review.goldOnly, canReview: review.canReview };
  });
  useEffect(() => {
    if (!queue) return;
    const onKey = (e: KeyboardEvent) => {
      const act = verdictAct(e, shortcuts, dialogOpen(), latest.current.canReview);
      if (act === null) return;
      e.preventDefault();
      if (act.kind === "help") setHelp(true);
      else if (act.kind === "next") latest.current.goNext();
      else if (act.kind === "outcome") latest.current.choose(act.outcome);
      else if (latest.current.goldOnly) announce("C confirms a review. A gold-set answer is saved with its own button, so that it is never saved by a slip.", "info");
      else if (latest.current.confirmable) void latest.current.confirm();
      else announce("There is no recommendation to confirm here: choose an outcome with the keys 1 to 5.", "info");
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [queue, shortcuts, announce]);

  return (
    <section aria-labelledby={headline} className="flex flex-col gap-3 rounded-card border border-border-strong bg-surface-2 p-4 shadow-card">
      <div className="flex flex-col gap-1">
        <h2 id={headline} ref={headingRef} tabIndex={-1} data-testid="verdict-headline" className="m-0 text-lg font-semibold focus:outline-none">
          {stanceHeadline(stance)}
        </h2>
        {source && <p className="m-0 text-sm text-muted">{source}</p>}
        {stance.from_investigation_id && (
          <p className="m-0 text-sm" data-testid="same-pattern-source">
            Same pattern as{" "}
            <Link to="/investigations/$id" params={{ id: stance.from_investigation_id }} className="font-mono">
              {stance.from_investigation_id}
            </Link>
            .
          </p>
        )}
        {size && <p className="m-0 text-sm">{size}.</p>}
      </div>

      {inv.known && (
        <div role="note" data-testid="known-note" className={inv.known.outcome === "changed" ? "rounded-control border border-warn/40 bg-warn-soft px-3 py-2 text-sm text-warn" : "rounded-control border border-info/40 bg-info-soft px-3 py-2 text-sm text-info"}>
          <strong>{inv.known.outcome === "changed" ? "Changed since notice." : "Known."}</strong>{" "}
          <UntrustedText value={knownSentence(inv.known)} limits={{ maxChars: 600, maxLines: 4 }} />
          {inv.known.notified_at && (
            <>
              {" "}
              (told <Time value={inv.known.notified_at} />)
            </>
          )}{" "}
          <Link to="/cases/$id" params={{ id: inv.known.case_id }}>
            Open case {inv.known.case_number}
          </Link>
        </div>
      )}

      <section aria-label="The facts behind this" className="flex flex-col gap-1">
        <h3 className="m-0 text-sm font-semibold">Key facts</h3>
        {facts.length === 0 ? (
          <p className="m-0 text-sm text-muted">{reports.isPending ? "Reading what ARGUS found…" : "ARGUS has no key fact for this yet."}</p>
        ) : (
          <ul className="m-0 flex list-none flex-col gap-1 p-0 text-sm">
            {facts.map((f, i) => (
              <li key={`${i}:${f.text}`} className="flex flex-wrap items-baseline gap-x-2">
                <span>
                  <UntrustedText value={f.text} limits={{ maxChars: 400, maxLines: 4 }} />
                </span>
                {f.eid === null ? (
                  <Link to="/investigations/$id" params={{ id: inv.id }} search={{ tab: "alerts" }} className="text-xs">
                    See the alerts
                  </Link>
                ) : (
                  <Link to="/investigations/$id" params={{ id: inv.id }} search={{ tab: "report" }} hash={`eid-${f.eid}`} className="text-xs">
                    See the rows ({f.eid})
                  </Link>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>

      <div className="flex flex-col gap-2">
        <div className="flex flex-wrap items-center gap-2">
          {review.confirmable && stance.outcome != null && (
            <Button
              variant="primary"
              aria-keyshortcuts={queue && shortcuts && !review.goldOnly ? "c" : undefined}
              aria-disabled={review.busy || review.moved || review.hold !== null || undefined}
              aria-describedby={review.hold !== null ? holdId : undefined}
              onClick={() => void confirm()}
            >
              {review.goldOnly ? `Save as my gold-set answer: ${outcomeLabel(stance.outcome)}` : `Confirm: ${outcomeLabel(stance.outcome)}`}
              {queue && shortcuts && !review.goldOnly && <Key>C</Key>}
            </Button>
          )}
          {review.canReview && (
            <Button aria-keyshortcuts={queue && shortcuts ? "1 2 3 4 5" : undefined} onClick={change}>
              Change{queue && shortcuts && <Key>1–5</Key>}
            </Button>
          )}
          {queue && (
            <Button ref={nextButton} aria-keyshortcuts={shortcuts ? "n" : undefined} onClick={goNext} aria-disabled={next.loading || undefined}>
              Next{shortcuts && <Key>N</Key>}
            </Button>
          )}
          {queue && (
            <span className="inline-flex items-center gap-2 text-sm">
              <Check checked={shortcuts} onChange={(e) => setShortcuts(e.target.checked)}>
                Single-key shortcuts ({review.canReview ? "C, 1–5, N" : "N"})
              </Check>
              <Button size="sm" variant="ghost" onClick={() => setHelp(true)} aria-label="Show keyboard shortcuts">
                ?
              </Button>
            </span>
          )}
        </div>
        {review.hold !== null && (
          <p id={holdId} className="m-0 text-sm text-warn" data-testid="confirm-hold">
            {review.hold}
          </p>
        )}
        {!open && inv.last_outcome && (
          <p className="m-0 text-sm text-muted">
            Already reviewed{inv.last_reviewer ? <> by <UntrustedText value={inv.last_reviewer} limits={{ maxChars: 60, maxLines: 1 }} /></> : null}: {outcomeLabel(inv.last_outcome)}. A new review below replaces it.
          </p>
        )}
        {open && stance.kind !== "recommends" && review.canReview && (
          <p className="m-0 text-sm text-muted">
            {stance.kind === "reading" ? "ARGUS did not propose an outcome, so there is nothing to confirm." : "ARGUS has no recommendation for this one."} Choose an outcome with the keys 1 to 5 or in the form below.
          </p>
        )}
        {queue && (
          <p className="m-0 text-sm text-muted" aria-live="polite">
            {next.loading
              ? "Reading the queue…"
              : next.failed
                ? "The queue could not be read, so Next has nowhere to go."
                : next.next === null || next.next.id === null
                  ? reached
                    ? end.text
                    : end.all
                      ? "This is the last item in the queue."
                      : `This is the last of the ${count(next.walked)} most urgent; ${count(next.total - next.walked)} more need a person in the Inbox.`
                  : `${next.next.left} more in the queue after this one.`}{" "}
            {!end.all && (next.next === null || next.next.id === null) && (
              <>
                <Link to="/inbox" search={{ view: "attention", sort: "queue" }}>
                  Open them in the Inbox
                </Link>
                {" · "}
              </>
            )}
            <Link to="/">Back to the queue</Link>
          </p>
        )}
        {stance.kind === "recommends" && stance.from_investigation_id && review.confirmable && (
          <p className="m-0 text-xs text-muted">Confirming records your own review of this investigation; the pattern&apos;s proposal is not accepted for it.</p>
        )}
      </div>

      <ReviewPanel detail={detail} review={review} inCard />
      {review.busy && <Badge tone="info">Saving…</Badge>}
      {queue && <KeysHelp open={help} onOpenChange={setHelp} page canReview={review.canReview} />}
    </section>
  );
}
