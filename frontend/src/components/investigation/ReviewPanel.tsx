import { useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useId, useRef, useState, type FormEvent } from "react";
import { answerGold } from "../../client/sdk.gen";
import type { InvestigationDetail, ReviewedIn } from "../../client/types.gen";
import { useAnnounce } from "../../lib/announce";
import { unwrap } from "../../lib/call";
import { OUTCOME_KEYS, OUTCOMES, outcomeLabel } from "../../lib/labels";
import { changed } from "../../lib/queries";
import { ApiError } from "../../lib/session";
import { Time } from "../Time";
import { UntrustedText } from "../UntrustedText";
import { Button } from "../ui/button";
import { Card, CardTitle } from "../ui/card";
import { Check, Field, Select, TextArea } from "../ui/field";
import { NeedsCapability, useCan } from "./actions";
import type { Review } from "./useReview";

/**
 * Your review (D-052): an outcome (the keys 1 to 5 choose it too) and a note, then Mark reviewed,
 * Needs follow-up or Add note only. The state and the sending are `useReview`'s: the verdict card
 * above owns them, so Confirm and this form are one control with one set of rules.
 */
export function ReviewPanel({ detail, review, inCard = false }: { detail: InvestigationDetail; review: Review; inCard?: boolean }) {
  const id = useId();
  const { canReview, canGold, outcome, setOutcome, note, setNote, alsoGold, setAlsoGold, busy, problem, moved, looked, look, send } = review;
  const Body = (
    <>
      {!canReview ? (
        <NeedsCapability what="reviewing" capability="review" />
      ) : (
        <form
          className="grid gap-3 sm:grid-cols-[minmax(0,15rem)_1fr]"
          onSubmit={(e) => {
            e.preventDefault();
            void send("reviewed");
          }}
          aria-label="Review this investigation"
        >
          <Field label="Outcome" hint="(needed to mark it reviewed; keys 1 to 5)" htmlFor={`${id}-outcome`}>
            <Select id={`${id}-outcome`} value={outcome} onChange={(e) => setOutcome(e.target.value)}>
              <option value="">— not decided —</option>
              {OUTCOME_KEYS.map((key, i) => (
                <option key={key} value={key}>
                  {i + 1} · {OUTCOMES[key]}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Note" htmlFor={`${id}-note`}>
            <TextArea id={`${id}-note`} rows={2} maxLength={4000} value={note} onChange={(e) => setNote(e.target.value)} />
          </Field>
          {detail.gold !== null && canGold && (
            <Check className="sm:col-span-2" checked={alsoGold} onChange={(e) => setAlsoGold(e.target.checked)}>
              Also save the outcome as my gold-set answer
            </Check>
          )}
          {problem && (
            <p role="alert" className="m-0 rounded-control border border-danger/40 bg-danger-soft px-3 py-2 text-sm text-danger sm:col-span-2">
              {problem.text}
            </p>
          )}
          {moved && (
            <div role="alert" className="flex flex-wrap items-center gap-2 rounded-control border border-warn/40 bg-warn-soft px-3 py-2 text-sm text-warn sm:col-span-2">
              <p className="m-0 flex-1">
                <strong>This investigation changed while you were typing</strong> (new alerts, a newer assessment, or a review by someone else). Look at what changed above and in the tabs. Nothing is sent until you say you have; what you typed stays.
              </p>
              <Button ref={looked} size="sm" onClick={look}>
                I have looked at what changed
              </Button>
            </div>
          )}
          <div className="flex flex-wrap gap-2 sm:col-span-2">
            <Button type="submit" variant="primary" aria-disabled={busy || moved || undefined}>
              Mark reviewed
            </Button>
            <Button aria-disabled={busy || moved || undefined} onClick={() => void send("follow_up")}>
              Needs follow-up
            </Button>
            <Button aria-disabled={busy || moved || undefined} onClick={() => void send("note")}>
              Add note only
            </Button>
          </div>
        </form>
      )}
    </>
  );
  if (inCard) {
    return (
      <section aria-labelledby={`${id}-title`} className="flex flex-col gap-2 border-t border-border pt-3">
        <h3 id={`${id}-title`} className="m-0 text-sm font-semibold">
          Your review
        </h3>
        {Body}
      </section>
    );
  }
  return (
    <Card aria-labelledby={`${id}-title`}>
      <CardTitle id={`${id}-title`}>Your review</CardTitle>
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
                <Link to="/investigations/$id" params={{ id: next }} className="text-sm">
                  Go to the next unanswered item
                </Link>
              ))}
          </div>
        </form>
      )}
    </Card>
  );
}
