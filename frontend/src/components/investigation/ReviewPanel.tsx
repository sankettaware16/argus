import { AlertDialog } from "@base-ui/react/alert-dialog";
import { REAL_SENTENCE } from "../decide/AlertGroupDecide";
import { useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useId, useRef, useState, type FormEvent } from "react";
import { answerGold } from "../../client/sdk.gen";
import type { InvestigationDetail, ReviewedIn } from "../../client/types.gen";
import { useAnnounce } from "../../lib/announce";
import { unwrap } from "../../lib/call";
import { OUTCOME_HINTS, OUTCOME_KEYS, OUTCOMES, outcomeLabel } from "../../lib/labels";
import { changed } from "../../lib/queries";
import { ApiError } from "../../lib/session";
import { Time } from "../Time";
import { UntrustedText } from "../UntrustedText";
import { Button } from "../ui/button";
import { Card, CardTitle } from "../ui/card";
import { Check, Field, Select, TextArea } from "../ui/field";
import { NeedsCapability, useCan } from "./actions";
import type { Review } from "./useReview";

/** The key a choice answers to, drawn beside it (the choice's name stays its own words). */
function KeyCap({ children }: { children: string }) {
  return (
    <kbd aria-hidden="true" className="rounded-control border border-border-strong bg-bg px-1 text-xs text-muted">
      {children}
    </kbd>
  );
}

/**
 * Your decision on an alert group (P4-F U6/U7, over D-052's review): one choice of five (the keys
 * 1 to 5 choose it too), "Come back to it" to keep it for a follow-up (ticked by "Can't tell
 * yet"), a note, then Save decision or Add note only. The state and the sending are `useReview`'s:
 * the card above owns them, so accepting ARGUS's call and this form are one control with one set
 * of rules. The review model is unchanged: a decision is a review with its outcome, "Come back to
 * it" a follow-up (with the decision, or without one).
 */
export function ReviewPanel({ detail, review, inCard = false }: { detail: InvestigationDetail; review: Review; inCard?: boolean }) {
  const id = useId();
  const { canReview, canGold, outcome, setOutcome, followUp, setFollowUp, decide, note, setNote, alsoGold, setAlsoGold, busy, problem, moved, looked, look, send } = review;
  const [askReal, setAskReal] = useState(false);
  const realDialog = (
    <AlertDialog.Root open={askReal} onOpenChange={setAskReal}>
      <AlertDialog.Portal>
        <AlertDialog.Backdrop className="fixed inset-0 z-40 bg-black/40" />
        <AlertDialog.Popup className="fixed top-1/2 left-1/2 z-50 flex w-[min(36rem,calc(100vw-2rem))] -translate-x-1/2 -translate-y-1/2 flex-col gap-3 rounded-card border border-border bg-raised p-5 text-text shadow-card">
          <AlertDialog.Title className="m-0 text-lg font-semibold">Real: open an incident?</AlertDialog.Title>
          <AlertDialog.Description className="m-0 text-sm">{REAL_SENTENCE}</AlertDialog.Description>
          <div className="flex flex-wrap justify-end gap-2">
            <AlertDialog.Close render={<Button />}>Cancel</AlertDialog.Close>
            <Button
              variant="primary"
              onClick={() => {
                setAskReal(false);
                void decide();
              }}
            >
              Mark it real
            </Button>
          </div>
        </AlertDialog.Popup>
      </AlertDialog.Portal>
    </AlertDialog.Root>
  );
  const Body = (
    <>
      {!canReview ? (
        <NeedsCapability what="reviewing" capability="review" />
      ) : (
        <form
          className="flex flex-col gap-3"
          onSubmit={(e) => {
            e.preventDefault();
            // Real opens or joins an incident: said in a dialog first (docs/p4f-ui-spec.md §8, F6)
            if (outcome === "true_positive" && !followUp && !moved && !busy) setAskReal(true);
            else void decide();
          }}
          aria-label="Your decision"
        >
          <fieldset className="m-0 flex flex-col gap-1.5 border-0 p-0">
            <legend className="mb-1 text-sm font-medium">
              What is it? <span className="font-normal text-muted">(keys 1 to 5)</span>
            </legend>
            <div className="flex flex-wrap gap-2">
              {OUTCOME_KEYS.map((key, i) => (
                <label
                  key={key}
                  title={OUTCOME_HINTS[key]}
                  className="inline-flex min-h-9 cursor-pointer items-center gap-1.5 rounded-full border border-border-strong bg-bg px-3.5 text-sm has-[:checked]:border-accent has-[:checked]:bg-accent-soft has-[:checked]:font-semibold has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-accent"
                >
                  <input type="radio" name={`${id}-outcome`} value={key} checked={outcome === key} onChange={() => setOutcome(key)} className="sr-only" />
                  <KeyCap>{String(i + 1)}</KeyCap>
                  {key === "true_positive" ? "Real: open an incident…" : OUTCOMES[key]}
                </label>
              ))}
            </div>
            {outcome !== "" && (
              <p className="m-0 text-sm text-muted" data-testid="outcome-hint">
                {OUTCOME_HINTS[outcome]}
              </p>
            )}
          </fieldset>
          <Check checked={followUp} onChange={(e) => setFollowUp(e.target.checked)}>
            Come back to it: keep it in Needs attention for a follow-up
          </Check>
          <Field label="Note" htmlFor={`${id}-note`}>
            <TextArea id={`${id}-note`} rows={2} maxLength={4000} value={note} onChange={(e) => setNote(e.target.value)} />
          </Field>
          {detail.gold !== null && canGold && (
            <Check checked={alsoGold} onChange={(e) => setAlsoGold(e.target.checked)}>
              Also save the outcome as my gold-set answer
            </Check>
          )}
          {problem && (
            <p role="alert" className="m-0 rounded-control border border-danger/40 bg-danger-soft px-3 py-2 text-sm text-danger">
              {problem.text}
            </p>
          )}
          {moved && (
            <div role="alert" className="flex flex-wrap items-center gap-2 rounded-control border border-warn/40 bg-warn-soft px-3 py-2 text-sm text-warn">
              <p className="m-0 flex-1">
                <strong>This alert group changed while you were deciding</strong> (new alerts, a newer assessment, or a review by someone else). Look at what changed above and in the tabs. Nothing is sent until you say you have; what you chose stays.
              </p>
              <Button ref={looked} size="sm" onClick={look}>
                I have looked at what changed
              </Button>
            </div>
          )}
          <div className="flex flex-wrap gap-2">
            <Button type="submit" variant="primary" aria-disabled={busy || moved || undefined}>
              {followUp ? "Save, and come back to it" : "Save decision"}
            </Button>
            <Button aria-disabled={busy || moved || undefined} onClick={() => void send("note")}>
              Add note only
            </Button>
          </div>
          {realDialog}
        </form>
      )}
    </>
  );
  if (inCard) {
    return (
      <section aria-labelledby={`${id}-title`} className="flex flex-col gap-2 border-t border-border pt-3">
        <h3 id={`${id}-title`} className="m-0 text-sm font-semibold">
          Your decision
        </h3>
        {Body}
      </section>
    );
  }
  return (
    <Card aria-labelledby={`${id}-title`}>
      <CardTitle id={`${id}-title`}>Your decision</CardTitle>
      {Body}
    </Card>
  );
}

/** The gold set (D-080): this investigation is in the answer key; judge it from the evidence, then save your answer. */
export function GoldBox({ detail }: { detail: InvestigationDetail }) {
  const gold = detail.gold;
  const canGold = useCan("answer_gold");
  const queries = useQueryClient();
  const { announce } = useAnnounce();
  const id = useId();
  const [outcome, setOutcome] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const sending = useRef(false);
  const [problem, setProblem] = useState<string | null>(null);
  const [next, setNext] = useState<string | null | undefined>(undefined);
  if (gold === null) return null;

  async function save(e: FormEvent) {
    e.preventDefault();
    if (sending.current) return;
    if (outcome === "") {
      setProblem("Choose the correct outcome first.");
      return;
    }
    sending.current = true;
    setBusy(true);
    setProblem(null);
    try {
      const saved = await unwrap(answerGold({ path: { investigation_id: detail.investigation.id }, body: { outcome: outcome as ReviewedIn["outcome"], note: note.trim() === "" ? null : note } }));
      announce("Saved your gold-set answer.", "ok");
      setNext(saved.next_investigation_id);
      setOutcome("");
      setNote("");
      await changed(queries, detail.investigation.id);
    } catch (error) {
      const text = error instanceof ApiError ? error.message : "Your answer could not be saved. Try again.";
      setProblem(text);
    } finally {
      sending.current = false;
      setBusy(false);
    }
  }

  return (
    <Card aria-labelledby={`${id}-title`}>
      <CardTitle id={`${id}-title`}>Gold set: your answer</CardTitle>
      <p className="m-0 mb-2 text-sm">
        This investigation is in the answer key ({gold.split} part). Judge it from the evidence; the suggestion is ARGUS&apos;s, not an answer.
      </p>
      <p className="m-0 mb-1 text-sm">
        <strong>Your answer:</strong>{" "}
        {gold.outcome ? (
          <>
            {outcomeLabel(gold.outcome)}
            {gold.note && (
              <>
                {" "}
                — <UntrustedText value={gold.note} limits={{ maxChars: 600, maxLines: 6 }} />
              </>
            )}{" "}
            <span className="text-muted">
              (<UntrustedText value={gold.answered_by} limits={{ maxChars: 60, maxLines: 1 }} />, <Time value={gold.answered_at} />; answer again to correct it)
            </span>
          </>
        ) : (
          <em>not given yet</em>
        )}
      </p>
      <p className="m-0 mb-1 text-sm">
        <strong>Suggested:</strong> {gold.suggestion.outcome ? outcomeLabel(gold.suggestion.outcome) : "nothing"}{" "}
        {gold.suggestion.source && (
          <span className="text-muted">
            (from <UntrustedText value={gold.suggestion.source} limits={{ maxChars: 40, maxLines: 1 }} />)
          </span>
        )}
      </p>
      {gold.suggestion.reasons.length > 0 && (
        <ul className="m-0 mb-1 pl-5 text-sm">
          {gold.suggestion.reasons.map((r, i) => (
            <li key={i}>
              <UntrustedText value={r} limits={{ maxChars: 400, maxLines: 4 }} />
            </li>
          ))}
        </ul>
      )}
      <p className="m-0 mb-2 text-xs text-muted">
        Chosen because: <UntrustedText value={gold.why.join("; ")} limits={{ maxChars: 300, maxLines: 3 }} />
      </p>
      {!canGold ? (
        <NeedsCapability what="the gold set" capability="answer_gold" />
      ) : (
        <form className="flex flex-col gap-2" onSubmit={(e) => void save(e)} aria-label="Gold-set answer">
          <Field label="Correct outcome" htmlFor={`${id}-outcome`}>
            <Select id={`${id}-outcome`} value={outcome} onChange={(e) => setOutcome(e.target.value)}>
              <option value="">— choose —</option>
              {OUTCOME_KEYS.map((key) => (
                <option key={key} value={key}>
                  {OUTCOMES[key]}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Why" hint="(optional, one line)" htmlFor={`${id}-note`}>
            <TextArea id={`${id}-note`} rows={2} maxLength={4000} value={note} onChange={(e) => setNote(e.target.value)} />
          </Field>
          {problem && (
            <p role="alert" className="m-0 text-sm text-danger">
              {problem}
            </p>
          )}
          <div className="flex flex-wrap items-center gap-2">
            <Button type="submit" variant="primary" aria-disabled={busy || undefined}>
              Save answer
            </Button>
            {next !== undefined &&
              (next === null ? (
                <span className="text-sm text-muted">No unanswered gold-set item is left.</span>
              ) : (
                <Link to="/alert-groups/$id" params={{ id: next }} className="text-sm">
                  Go to the next unanswered item
                </Link>
              ))}
          </div>
        </form>
      )}
    </Card>
  );
}
