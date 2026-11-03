// A pattern ARGUS recommends closing, as Home shows it (AR4 review, D-186): the lean summary the
// server counted (real totals, no dossier read), not the Patterns page's sampled group. Pressing
// Close reads the members now, with the version and latest review each has, and shows the exact
// request before anything is sent; only the investigations ARGUS has a proposal for are named.
import { useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState, type ReactNode } from "react";
import { getPatternClosing } from "../../client/sdk.gen";
import type { PatternBriefOut, PatternCloseOut, PatternReviewIn } from "../../client/types.gen";
import { useAnnounce } from "../../lib/announce";
import { unwrap } from "../../lib/call";
import { count, plural } from "../../lib/format";
import { outcomeLabel } from "../../lib/labels";
import { changed } from "../../lib/queries";
import { ApiError } from "../../lib/session";
import { surePart } from "../../lib/verdict";
import { ConfirmDialog } from "../ConfirmDialog";
import { NeedsCapability, useCan } from "../investigation/actions";
import { UntrustedText } from "../UntrustedText";
import { Button } from "../ui/button";
import { Card, CardTitle } from "../ui/card";

function requestOf(c: PatternCloseOut) {
  const body: PatternReviewIn = {
    outcome: c.brief.outcome,
    items: c.members.map((m) => ({ investigation_id: m.investigation_id, version: m.version, latest_review: m.latest_review ?? null })),
  };
  return { method: "POST" as const, path: "/api/v1/patterns/review", body };
}

export function PatternSummaryCard({ b, extra }: { b: PatternBriefOut; extra?: ReactNode }) {
  const canReview = useCan("review");
  const queries = useQueryClient();
  const { announce } = useAnnounce();
  const [reading, setReading] = useState(false);
  const [closing, setClosing] = useState<PatternCloseOut | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const rest = b.investigations - b.covered;

  async function close() {
    if (reading) return;
    setReading(true);
    setProblem(null);
    try {
      setClosing(await unwrap(getPatternClosing({ query: { pattern: b.pattern, day: b.day } })));
    } catch (e) {
      const gone = e instanceof ApiError && e.status === 404;
      setProblem(gone ? "ARGUS no longer recommends closing this pattern: it changed since this page was read. The list has been read again." : e instanceof ApiError ? e.message : "The members could not be read. Try again.");
      if (gone) await changed(queries);
    } finally {
      setReading(false);
    }
  }

  const sent = (back: { data?: unknown }) => {
    const done = back.data as { reviewed?: number; changed?: number } | undefined;
    const left = done?.changed ?? 0;
    announce(`${count(done?.reviewed ?? 0)} reviewed.${left > 0 ? ` ${count(left)} changed since you looked and were left as they are.` : ""}`, "ok");
  };
  const shown = closing?.members.length ?? 0;
  return (
    <Card aria-label={`Pattern: ${b.rule_name ?? b.rule_id}`}>
      <CardTitle>
        <UntrustedText value={`${b.rule_name ?? b.rule_id}: ${count(b.investigations)} ${plural(b.investigations, "investigation")}, ${count(b.alerts)} ${plural(b.alerts, "alert")}`} limits={{ maxChars: 200, maxLines: 1 }} />
      </CardTitle>
      <p className="m-0 mb-1 text-sm" data-testid="pattern-recommendation">
        <strong>
          ARGUS recommends: {outcomeLabel(b.outcome)}
          {surePart(b.confidence)}
        </strong>{" "}
        for {count(b.covered)} of {count(b.investigations)} {plural(b.investigations, "investigation")} (from {b.source}).{" "}
        {rest > 0 && `The other ${count(rest)} have no proposal yet, so a close leaves them out.`}
      </p>
      {b.examples.length > 0 && (
        <p className="m-0 mb-2 text-sm">
          For example:{" "}
          {b.examples.map((id, i) => (
            <span key={id}>
              {i > 0 && ", "}
              <Link to="/investigations/$id" params={{ id }}>
                investigation {i + 1}
              </Link>
            </span>
          ))}
          {" · "}
          <Link to="/patterns">The Patterns page</Link>
        </p>
      )}
      {canReview ? (
        <div className="flex flex-col gap-2">
          <div className="flex flex-wrap items-center gap-2">
            <Button variant="primary" aria-disabled={reading || undefined} onClick={() => void close()}>
              {reading ? "Reading the members…" : `Close ${count(b.covered)} as ${outcomeLabel(b.outcome)}`}
            </Button>
            {extra}
          </div>
          {problem && (
            <p role="alert" className="m-0 rounded-control border border-danger/40 bg-danger-soft px-3 py-2 text-sm text-danger">
              {problem}
            </p>
          )}
          {closing && (
            <ConfirmDialog
              open
              onOpenChange={(next) => {
                if (!next) {
                  setClosing(null);
                  void changed(queries);
                }
              }}
              title={`Close ${count(shown)} ${plural(shown, "investigation")} as ${outcomeLabel(closing.brief.outcome)}`}
              description={`Only the investigations ARGUS has a proposal for are named${closing.brief.covered > shown ? ` (the newest ${count(shown)} of ${count(closing.brief.covered)}; close the rest afterwards)` : ""}. Each is marked reviewed only if it is still exactly as it was just read (its version and latest review); the others are left as they are and counted. Nothing is closed in Kibana.`}
              request={requestOf(closing)}
              confirmLabel={`Close ${count(shown)}`}
              onSent={sent}
            />
          )}
        </div>
      ) : (
        <NeedsCapability what="deciding a group" capability="review" />
      )}
    </Card>
  );
}
