import { useQueryClient } from "@tanstack/react-query";
import { useRef, useState, type RefObject } from "react";
import { acceptProposal, answerGold, createReview } from "../../client/sdk.gen";
import type { FollowUpIn, InvestigationDetail, NoteIn, ReviewedIn } from "../../client/types.gen";
import { useAnnounce } from "../../lib/announce";
import { unwrap } from "../../lib/call";
import { outcomeLabel } from "../../lib/labels";
import { changed } from "../../lib/queries";
import { ApiError } from "../../lib/session";
import { useCan } from "./actions";

export type Action = "reviewed" | "follow_up" | "note";
const DONE: Record<Action, string> = { reviewed: "Saved: marked reviewed.", follow_up: "Saved: follow-up requested.", note: "Saved: note added." };

/** What a review needs before it is sent (the server says the same in 422). */
export function reviewProblem(action: Action, outcome: string, note: string): string | null {
  if (action === "reviewed" && outcome === "") return "Choose an outcome to mark it reviewed.";
  if (action === "note" && note.trim() === "") return "Write a note first.";
  return null;
}

const CONFLICT =
  "Someone else reviewed this, or new alerts arrived, while you were reading. Nothing was saved. What you typed is still here. The investigation has been read again: look at what changed, say so below, then send again.";

export interface Review {
  canReview: boolean;
  canGold: boolean;
  outcome: string;
  setOutcome: (outcome: string) => void;
  note: string;
  setNote: (note: string) => void;
  alsoGold: boolean;
  setAlsoGold: (on: boolean) => void;
  busy: boolean;
  problem: { text: string; conflict: boolean } | null;
  setProblem: (problem: { text: string; conflict: boolean } | null) => void;
  /** it moved while the person was reading: nothing is sent until they say they looked */
  moved: boolean;
  looked: RefObject<HTMLButtonElement | null>;
  /** "I have looked at what changed" */
  look: () => void;
  send: (action: Action) => Promise<void>;
  /** ARGUS's recommendation can be confirmed as it stands: it recommends an outcome and nobody has reviewed this version */
  confirmable: boolean;
  /**
   * Why Confirm waits: the form holds another outcome than ARGUS's or a note, and Confirm would
   * send neither. Confirm says so and does nothing until the form is cleared or Mark reviewed is
   * used (AR4 review, D-186); null when nothing in the form stands in its way.
   */
  hold: string | null;
  /** The reviewed gold-set item: the one button saves the gold-set answer alone, and is not the C key's */
  goldOnly: boolean;
  /** Confirm ARGUS's recommendation (its own proposal is accepted; the pattern's becomes the person's review); true when it was saved */
  confirm: () => Promise<boolean>;
}

/**
 * Your review (D-052) and, on top of it, Confirm (AR4, D-182): the one place an outcome is chosen
 * and sent. It names the latest review and version you saw. What you saw is fixed when the form
 * opens (review B2-R1): if the investigation moves while you type (a background read, someone
 * else's review, new alerts) it says so and sends nothing until you confirm that you have looked
 * at the change; then it names what you are looking at now. If it moved before you got to send,
 * the answer is 409, nothing is saved, what you typed stays, and the investigation is read again.
 * Confirm sends at once (the review path's own rule: a person's single decision, named in the
 * message that says it was saved); it is refused in the same two ways.
 */
export function useReview(detail: InvestigationDetail): Review {
  const inv = detail.investigation;
  const canReview = useCan("review");
  const canGold = useCan("answer_gold");
  const queries = useQueryClient();
  const { announce } = useAnnounce();
  const [outcome, setOutcome] = useState("");
  const [note, setNote] = useState("");
  // unticked (AR4 review, D-186): a gold-set answer is the person's own judgement; a box that
  // starts ticked makes ARGUS's suggestion the default answer, which anchors it
  const [alsoGold, setAlsoGold] = useState(false);
  const [busy, setBusy] = useState(false);
  const sending = useRef(false); // one send at a time, whatever the clicks
  const [problem, setProblem] = useState<{ text: string; conflict: boolean } | null>(null);
  // the review and version the person is looking at: taken when the form opens and again only when
  // they say they looked at a change (or their own save was read back), never by a background read
  const live = { review: inv.latest_review, version: inv.version };
  const [seen, setSeen] = useState(live);
  const moved = !busy && (seen.review !== live.review || seen.version !== live.version);
  const looked = useRef<HTMLButtonElement>(null);
  const stance = detail.stance;
  const reviewed = inv.human_state === "reviewed";
  const gold = detail.gold !== null && canGold;
  // a reviewed item of the gold set is confirmed as the person's gold-set answer alone
  const confirmable = canReview && stance.kind === "recommends" && stance.outcome != null && (!reviewed || gold);
  const goldOnly = confirmable && reviewed;
  // what the form holds that Confirm would drop (a reviewed gold item saves the gold answer alone: the form is not its)
  const hold =
    !confirmable || goldOnly
      ? null
      : outcome !== "" && outcome !== stance.outcome
        ? `You chose ${outcomeLabel(outcome)}: use Mark reviewed to save your choice. Confirm sends ARGUS's recommendation only.`
        : note.trim() !== ""
          ? "You wrote a note: choose the outcome and use Mark reviewed to keep it. Confirm would not keep the note."
          : null;

  /** One send at a time; on success `done` says what was saved and the investigation is read again. Returns whether it was saved. */
  async function guarded(act: () => Promise<string>, failed: string, afterwards?: () => void): Promise<boolean> {
    sending.current = true;
    setBusy(true);
    setProblem(null);
    try {
      announce(await act(), "ok");
      afterwards?.();
      await changed(queries, inv.id);
      const fresh = queries.getQueryData<InvestigationDetail>(["investigation", inv.id])?.investigation;
      if (fresh) setSeen({ review: fresh.latest_review, version: fresh.version }); // her own save, read back: not "a change"
      return true;
    } catch (e) {
      const error = e instanceof ApiError ? e : null;
      const conflict = error?.status === 409;
      const text = conflict ? CONFLICT : (error?.message ?? failed);
      setProblem({ text, conflict }); // a role=alert next to the form says it to screen readers too
      if (conflict) await changed(queries, inv.id);
      return false;
    } finally {
      sending.current = false;
      setBusy(false);
    }
  }

  async function send(action: Action) {
    if (sending.current) return;
    if (moved) {
      looked.current?.focus(); // the one thing that continues
      return;
    }
    const wrong = reviewProblem(action, outcome, note);
    if (wrong) {
      setProblem({ text: wrong, conflict: false });
      return;
    }
    const named = { seen_review: seen.review, seen_version: seen.version };
    const text = note.trim() === "" ? null : note;
    const alsoSaved = detail.gold !== null && canGold && alsoGold;
    const body: ReviewedIn | FollowUpIn | NoteIn =
      action === "reviewed"
        ? { action, outcome: outcome as ReviewedIn["outcome"], note: text, ...named, also_gold: alsoSaved }
        : action === "follow_up"
          ? { action, outcome: outcome === "" ? null : (outcome as ReviewedIn["outcome"]), note: text, ...named, also_gold: alsoSaved && outcome !== "" }
          : { action, note: note, ...named };
    await guarded(
      async () => {
        const done = await unwrap(createReview({ path: { investigation_id: inv.id }, body }));
        return DONE[action] + (done.gold_saved ? " Also saved as your gold-set answer." : "");
      },
      "The review could not be saved. Try again.",
      () => {
        setNote("");
        setOutcome("");
      },
    );
  }

  async function confirm(): Promise<boolean> {
    if (sending.current || !confirmable || stance.outcome == null) return false;
    if (hold) {
      announce(hold, "warn");
      return false;
    }
    if (moved) {
      looked.current?.focus();
      return false;
    }
    const agreed = stance.outcome;
    const words = outcomeLabel(agreed);
    const named = { seen_review: seen.review, seen_version: seen.version };
    const alsoSaved = detail.gold !== null && canGold && alsoGold;
    return guarded(async () => {
      if (reviewed) {
        // already reviewed: the gold-set answer alone, as the gold box saves it
        await unwrap(answerGold({ path: { investigation_id: inv.id }, body: { outcome: agreed, note: null } }));
        return `Saved: your gold-set answer is ${words}, as ARGUS recommends.`;
      }
      if (stance.acceptable && stance.assessment_id != null && !alsoSaved) {
        await unwrap(acceptProposal({ path: { investigation_id: inv.id }, body: { assessment_id: stance.assessment_id } }));
        return `Saved: you confirmed ARGUS's recommendation, ${words}.`;
      }
      const done = await unwrap(createReview({ path: { investigation_id: inv.id }, body: { action: "reviewed", outcome: agreed, note: null, ...named, also_gold: alsoSaved } }));
      return `Saved: you confirmed ${words} as your review.${done.gold_saved ? " Also saved as your gold-set answer." : ""}`;
    }, "It could not be confirmed. Try again.");
  }

  return {
    canReview,
    canGold,
    outcome,
    setOutcome,
    note,
    setNote,
    alsoGold,
    setAlsoGold,
    busy,
    problem,
    setProblem,
    moved,
    looked,
    look: () => {
      setSeen(live);
      if (problem?.conflict) setProblem(null);
    },
    send,
    confirmable,
    hold,
    goldOnly,
    confirm,
  };
}
