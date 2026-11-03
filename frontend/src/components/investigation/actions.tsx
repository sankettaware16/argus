import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useRef, useState } from "react";
import type { AssessmentOut, InvestigationDetail } from "../../client/types.gen";
import { useAnnounce } from "../../lib/announce";
import { outcomeLabel } from "../../lib/labels";
import { changed, pollInvestigation } from "../../lib/queries";
import { can, useSession } from "../../lib/session";
import { ConfirmDialog } from "../ConfirmDialog";
import { Button } from "../ui/button";

/** "Your account may view only" notice, with the reason a button is missing. */
export function NeedsCapability({ what, capability }: { what: string; capability: string }) {
  return (
    <p className="m-0 text-sm text-muted">
      Your account may view only: {what} needs the “{capability}” capability. Ask an ARGUS admin.
    </p>
  );
}

/**
 * Where the focus goes when a confirm dialog closes (review B2-R5): back to the button that opened
 * it, unless the request was sent: that button is replaced once the investigation is read again, so
 * the focus goes to the investigation's title, which stays.
 */
function useAfterSend() {
  const done = useRef(false);
  return {
    sent: () => {
      done.current = true;
    },
    focus: () => {
      if (!done.current) return null;
      done.current = false;
      return document.getElementById("investigation-title");
    },
  };
}

/** Accept the current proposal: the exact request is shown first (the confirm dialog), then sent. */
export function AcceptAction({ investigationId, assessment }: { investigationId: string; assessment: AssessmentOut }) {
  const [open, setOpen] = useState(false);
  const afterSend = useAfterSend();
  const queries = useQueryClient();
  const { announce } = useAnnounce();
  const request = useMemo(
    () => ({ method: "POST" as const, path: `/api/v1/investigations/${investigationId}/accept`, body: { assessment_id: assessment.id } }),
    [investigationId, assessment.id],
  );
  return (
    <>
      <Button variant="primary" onClick={() => setOpen(true)}>
        Accept: {outcomeLabel(assessment.outcome)}
      </Button>
      <ConfirmDialog
        open={open}
        onOpenChange={(next) => {
          setOpen(next);
          if (!next) void changed(queries, investigationId); // a refused accept means it moved on: read it again
        }}
        title="Accept this proposal"
        description={`This records ${outcomeLabel(assessment.outcome)} as your review, marked as a confirmed proposal. To disagree, close this and choose another outcome in the review form.`}
        request={request}
        confirmLabel="Accept"
        finalFocus={afterSend.focus}
        onSent={() => {
          afterSend.sent();
          announce(`Accepted: ${outcomeLabel(assessment.outcome)}.`, "ok");
        }}
      />
    </>
  );
}

/** Ask the AI investigator now (D-095): no body, one request, shown before it is sent. */
export function AskAction({ investigationId }: { investigationId: string }) {
  const [open, setOpen] = useState(false);
  const afterSend = useAfterSend();
  const queries = useQueryClient();
  const { announce } = useAnnounce();
  const request = useMemo(() => ({ method: "POST" as const, path: `/api/v1/investigations/${investigationId}/assess` }), [investigationId]);
  return (
    <>
      <Button onClick={() => setOpen(true)}>Ask the AI investigator now</Button>
      <p className="m-0 text-xs text-muted">It looks at this investigation within a few minutes, reviewed or not. The free AI providers are asked first; only if none can answer does the paid one, for about a US cent.</p>
      <ConfirmDialog
        open={open}
        onOpenChange={(next) => {
          setOpen(next);
          if (!next) void changed(queries, investigationId);
        }}
        title="Ask the AI investigator"
        description="The investigation is looked at within a few minutes. This sends one request and no other data."
        request={request}
        confirmLabel="Ask now"
        finalFocus={afterSend.focus}
        onSent={(sent) => {
          afterSend.sent();
          const result = (sent.data as { result?: string } | undefined)?.result;
          announce(
            result === "exists"
              ? "The AI investigator has already assessed what this shows now."
              : "Asked. The AI investigator looks within a few minutes; this page checks for its answer by itself.",
            "ok",
          );
        }}
      />
    </>
  );
}

/** While an assessment waits or runs, read the investigation again every 15 s (a background request: it never keeps the session alive). */
export function useAssessmentPoll(detail: InvestigationDetail | undefined): void {
  const queries = useQueryClient();
  const id = detail?.investigation.id;
  const waiting = detail?.assessments.some((a) => a.status === "queued" || a.status === "running") ?? false;
  useQuery({
    queryKey: ["poll", id],
    queryFn: async () => {
      if (id === undefined) throw new Error("no investigation to read");
      const fresh = await pollInvestigation(id);
      queries.setQueryData(["investigation", id], fresh);
      return fresh.investigation.version;
    },
    enabled: waiting && id !== undefined,
    // a refusal (gone, too many requests, unavailable) stops the asking: the page's own read and the
    // person's "Try again" go on from there (review B2-R4)
    refetchInterval: (query) => (query.state.status === "error" ? false : 15_000),
    gcTime: 0,
  });
}

export function useCan(capability: string): boolean {
  return can(useSession().data, capability);
}
