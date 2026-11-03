/**
 * "Next" on an investigation (AR4, D-182): the next item of the queue after this one. The queue
 * (ARGUS's cases' investigations, case by case, then the single investigations) is read once and
 * kept fresh; when the person reviews this investigation it leaves the queue, and the item that
 * followed it takes its place, so "next" is whatever stands where this one stood. An investigation
 * that was never in the queue (opened from a search, say) is followed by the queue's first item.
 * Pure (tests/queueNext.test.ts); the hook below only remembers where the investigation stood.
 */
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { queueOptions } from "./queries";

export interface NextItem {
  /** the next investigation, or null at the end of the queue */
  id: string | null;
  /** how many of the queue's items are still ahead of this one, the next included */
  left: number;
}

/**
 * `order` is the queue now, `id` the investigation, `stood` where it last stood in the queue
 * (-1: it never did).
 */
export function nextOf(order: readonly string[], id: string, stood: number): NextItem {
  const here = order.indexOf(id);
  // reviewed, so gone from the queue: whatever followed it now stands where it stood
  const from = here >= 0 ? here + 1 : stood >= 0 ? Math.min(stood, order.length) : 0;
  const ahead = order.slice(from).filter((other) => other !== id);
  return { id: ahead[0] ?? null, left: ahead.length };
}

/** How many of the queue's items the walk cannot reach: the queue holds `total`, the walk `walked` (it is capped). */
export function beyondWalk(walked: number, total: number): number {
  return Math.max(0, total - walked);
}

/**
 * What to say at the end of the walk. The queue's order is capped, so "that was the last" is only
 * true when the walk held everything the queue holds (`order_total`); otherwise it says how many
 * more need a person, and where to find them (AR4 review, D-186).
 */
export function endWords(walked: number, total: number): { all: boolean; text: string } {
  const more = beyondWalk(walked, total);
  if (more === 0) return { all: true, text: "That was the last item in the queue: nothing else needs a person." };
  return { all: false, text: `That was the last of the ${walked.toLocaleString("en-IN")} most urgent; ${more.toLocaleString("en-IN")} more need a person in the Inbox.` };
}

export function useNext(
  id: string,
  enabled = true,
): { next: NextItem | null; loading: boolean; failed: boolean; walked: number; total: number } {
  const queue = useQuery({ ...queueOptions, enabled });
  const [stood, setStood] = useState(-1);
  const order = queue.data?.order;
  const here = order === undefined ? -1 : order.indexOf(id);
  if (here >= 0 && here !== stood) setStood(here);
  if (order === undefined) return { next: null, loading: enabled && queue.isPending, failed: queue.isError, walked: 0, total: 0 };
  return { next: nextOf(order, id, here >= 0 ? here : stood), loading: false, failed: false, walked: order.length, total: queue.data?.order_total ?? order.length };
}
