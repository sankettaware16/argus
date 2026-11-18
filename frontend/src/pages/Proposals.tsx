import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import type { ProposalGroupOut, ProposalOut } from "../client/types.gen";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { NeedsCapability, useCan } from "../components/investigation/actions";
import { Loading, Problem } from "../components/Problem";
import { Time } from "../components/Time";
import { UntrustedText } from "../components/UntrustedText";
import { Card, CardTitle } from "../components/ui/card";
import { Button } from "../components/ui/button";
import { useAnnounce } from "../lib/announce";
import { count, plural } from "../lib/format";
import { outcomeLabel } from "../lib/labels";
import { changed, proposalsOptions } from "../lib/queries";

function ProposalLine({ p, withReason }: { p: ProposalOut; withReason: boolean }) {
  return (
    <li>
      <Link to="/alert-groups/$id" params={{ id: p.investigation_id }}>
        <UntrustedText value={p.rule} limits={{ maxChars: 100, maxLines: 1 }} />
      </Link>
      , {count(p.alerts)} {plural(p.alerts, "alert")}, <Time value={p.bucket_start} />
      {withReason && p.reason !== "" && (
        <>
          {" "}
          — <UntrustedText value={p.reason} limits={{ maxChars: 300, maxLines: 3 }} />
        </>
      )}
    </li>
  );
}

function Group({ g }: { g: ProposalGroupOut }) {
  const canReview = useCan("review");
  const queries = useQueryClient();
  const { announce } = useAnnounce();
  const [open, setOpen] = useState(false);
  const request = useMemo(
    () => ({ method: "POST" as const, path: "/api/v1/proposals/confirm", body: { group: g.group, assessment_ids: g.items.map((p) => p.assessment_id) } }),
    [g.group, g.items],
  );
  const rest = g.items.slice(g.sample.length);
  const heading = `${outcomeLabel(g.outcome)}: ${count(g.items.length)} ${plural(g.items.length, "investigation")}`;
  return (
    <Card aria-label={heading}>
      <CardTitle>{heading}</CardTitle>
      <p className="m-0 mb-2 text-sm text-muted">
        {g.rule !== null && g.rule !== undefined ? (
          <>
            By {g.source} on <strong><UntrustedText value={g.rule} limits={{ maxChars: 200, maxLines: 1 }} /></strong>
          </>
        ) : (
          <>By {g.source}</>
        )}
        {g.size > g.items.length && <> · {count(g.size)} in the group, the first {count(g.items.length)} listed</>}
      </p>
      <details className="mb-2 text-xs text-muted">
        <summary className="cursor-pointer">Details</summary>
        {g.rule !== null && g.rule !== undefined ? (
          <>
            Models: <UntrustedText value={[...g.models].sort().join(", ")} limits={{ maxChars: 200, maxLines: 1 }} />
          </>
        ) : (
          <>
            Decided by <UntrustedText value={g.decided_by} limits={{ maxChars: 200, maxLines: 2 }} />
          </>
        )}
      </details>
      <h3 className="m-0 mb-1 text-sm font-semibold">Audit sample</h3>
      <ul className="m-0 mb-2 pl-5 text-sm">
        {g.sample.map((p) => (
          <ProposalLine key={p.assessment_id} p={p} withReason />
        ))}
      </ul>
      {rest.length > 0 && (
        <details className="mb-2">
          <summary className="cursor-pointer text-sm font-medium">All {count(g.items.length)}</summary>
          <ul className="m-0 mt-1 pl-5 text-sm">
            {rest.map((p) => (
              <ProposalLine key={p.assessment_id} p={p} withReason={false} />
            ))}
          </ul>
        </details>
      )}
      {g.outcome === "true_positive" ? (
        <p className="m-0 max-w-prose text-sm" data-testid="one-by-one">
          A real attack starts an incident, so these are never confirmed together: open each one and decide it on its own page, where it can open an incident or join one.
        </p>
      ) : canReview ? (
        <>
          <Button onClick={() => setOpen(true)}>
            Confirm all {count(g.items.length)} as {outcomeLabel(g.outcome)}
          </Button>
          <ConfirmDialog
            open={open}
            onOpenChange={(next) => {
              setOpen(next);
              if (!next) void changed(queries);
            }}
            title={`Confirm ${count(g.items.length)} as ${outcomeLabel(g.outcome)}`}
            description="Only the proposals listed here are accepted, and only while each is still current and still of this group; the others are skipped and counted. Nothing is closed in Kibana: a confirmed proposal counts as reviewed here."
            request={request}
            confirmLabel={`Confirm ${count(g.items.length)}`}
            onSent={(sent) => {
              const done = sent.data as { accepted?: number; skipped?: number } | undefined;
              const skipped = done?.skipped ?? 0;
              announce(`Confirmed ${count(done?.accepted ?? 0)}${skipped > 0 ? `; ${count(skipped)} skipped because they changed` : ""}.`, "ok");
            }}
          />
        </>
      ) : (
        <NeedsCapability what="confirming a group" capability="review" />
      )}
    </Card>
  );
}

/** Proposals by group, each with its audit sample; confirm a group only after looking at the sample. */
export function Proposals() {
  const proposals = useQuery(proposalsOptions);
  return (
    <>
      <h1 className="page-h">Proposals</h1>
      <p className="page-sub">
        Outcomes ARGUS proposes, waiting for you. They are grouped by what decided them; open the audit sample of a group (chosen at random each day), and if those are right, confirm the group. Nothing is closed in Kibana; a confirmed proposal counts as reviewed here.
      </p>
      {proposals.isPending && <Loading what="the proposals" />}
      {proposals.isError && <Problem error={proposals.error} what="The proposals" onRetry={() => void proposals.refetch()} />}
      {proposals.data && proposals.data.length === 0 && (
        <p className="m-0 text-sm">No proposal is waiting. ARGUS proposes only what people&apos;s verdicts or its investigator&apos;s evidence support.</p>
      )}
      <div className="flex flex-col gap-4" aria-busy={proposals.isFetching}>
        {proposals.data?.map((g) => <Group key={g.group} g={g} />)}
      </div>
    </>
  );
}
