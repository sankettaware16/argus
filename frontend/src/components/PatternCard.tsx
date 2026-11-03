// One pattern (the Patterns page's group): unreviewed investigations the same rule found the same
// things in, to decide together. A group is marked reviewed only after the person chose its outcome
// and saw the exact request; each member only if it is still as it was shown. When ARGUS recommends
// closing it (AR4), the recommended outcome is one button for the members ARGUS covers.
import { useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useId, useMemo, useState, type ReactNode } from "react";
import type { PatternOut, PatternReviewIn } from "../client/types.gen";
import { useAnnounce } from "../lib/announce";
import { count, plural } from "../lib/format";
import { OUTCOME_KEYS, OUTCOMES, outcomeLabel } from "../lib/labels";
import { optionText } from "../lib/optionText";
import { changed } from "../lib/queries";
import { surePart } from "../lib/verdict";
import { ConfirmDialog } from "./ConfirmDialog";
import { NeedsCapability, useCan } from "./investigation/actions";
import { UntrustedText } from "./UntrustedText";
import { Badge, type Tone } from "./ui/badge";
import { Button } from "./ui/button";
import { Card, CardTitle } from "./ui/card";
import { Field, Select } from "./ui/field";

const STEP: Record<string, [Tone, string]> = {
  answered: ["ok", "Answered"],
  deferred: ["neutral", "Not checked yet"],
  manual: ["info", "For you"],
  unknown: ["neutral", "No data"],
};
/** The most one request names (the API's limit). */
export const GROUP_MAX = 200;

type Which = "chosen" | "recommended";

/** The request body for marking some members reviewed as `chosen`: each with the version and review it was shown at. */
function body(chosen: string, list: PatternOut["members"]): PatternReviewIn {
  return {
    outcome: chosen as PatternReviewIn["outcome"],
    items: list.map((m) => ({ investigation_id: m.investigation_id, version: m.version, latest_review: m.latest_review ?? null })),
  };
}

export function PatternCard({ g, extra }: { g: PatternOut; extra?: ReactNode }) {
  const canReview = useCan("review");
  const queries = useQueryClient();
  const { announce } = useAnnounce();
  const id = useId();
  const [outcome, setOutcome] = useState("");
  const [open, setOpen] = useState<Which | null>(null);
  const rec = g.recommendation ?? null;
  const members = useMemo(() => g.members.slice(0, GROUP_MAX), [g.members]);
  // ARGUS's recommendation covers the members it has a proposal for, and no others
  const covered = useMemo(() => {
    const named = new Set(rec?.members ?? []);
    return g.members.filter((m) => named.has(m.investigation_id)).slice(0, GROUP_MAX);
  }, [g.members, rec]);
  const request = useMemo(() => ({ method: "POST" as const, path: "/api/v1/patterns/review", body: body(outcome, members) }), [members, outcome]);
  const recommended = useMemo(() => ({ method: "POST" as const, path: "/api/v1/patterns/review", body: body(rec?.outcome ?? "", covered) }), [covered, rec]);
  const heading = `${g.rule_name ?? g.rule_id}: ${count(g.members.length)} ${plural(g.members.length, "investigation")}, ${count(g.alerts)} ${plural(g.alerts, "alert")}`;
  const label = g.members.length > GROUP_MAX ? `the first ${GROUP_MAX} of these ${count(g.members.length)}` : `these ${count(g.members.length)}`;
  const sent = (sentBack: { data?: unknown }) => {
    const done = sentBack.data as { reviewed?: number; changed?: number } | undefined;
    const left = done?.changed ?? 0;
    announce(`${count(done?.reviewed ?? 0)} reviewed.${left > 0 ? ` ${count(left)} changed since you looked and were left as they are.` : ""}`, "ok");
  };
  return (
    <Card aria-label={`Pattern: ${optionText(g.rule_name ?? g.rule_id, 60)}`}>
      <CardTitle>
        <UntrustedText value={heading} limits={{ maxChars: 200, maxLines: 1 }} />
      </CardTitle>
      {rec && (
        <p className="m-0 mb-1 text-sm" data-testid="pattern-recommendation">
          <strong>
            ARGUS recommends: {outcomeLabel(rec.outcome)}
            {surePart(rec.confidence)}
          </strong>{" "}
          for {count(rec.covered)} of {count(rec.total)} {plural(rec.total, "investigation")} (from {rec.source}).{" "}
          {rec.covered < rec.total && `The other ${count(rec.total - rec.covered)} of this group have no proposal yet, so a close leaves them out.`}
        </p>
      )}
      <p className="m-0 mb-1 flex flex-wrap items-center gap-1 text-sm">
        Steps:
        {g.steps.map((s, i) => (
          <Badge key={`${s}-${i}`} tone={STEP[s]?.[0] ?? "neutral"}>
            {STEP[s]?.[1] ?? "Other"}
          </Badge>
        ))}
        {g.listed && <Badge tone="danger">Threat-list hit</Badge>}
      </p>
      {g.common.length > 0 && (
        <p className="m-0 mb-1 text-sm">
          In common:{" "}
          {g.common.map((c, i) => (
            <span key={`${c.field}-${i}`}>
              {i > 0 && " · "}
              <UntrustedText value={c.field} limits={{ maxChars: 60, maxLines: 1 }} className="font-mono" />{" "}
              <UntrustedText value={c.values.join(", ")} limits={{ maxChars: 200, maxLines: 2 }} className="font-mono" />
            </span>
          ))}
        </p>
      )}
      <p className="m-0 mb-2 text-sm">
        For example:{" "}
        {g.members.slice(0, 3).map((m, i) => (
          <span key={m.investigation_id}>
            {i > 0 && ", "}
            <Link to="/investigations/$id" params={{ id: m.investigation_id }}>
              investigation {i + 1}
            </Link>
          </span>
        ))}
      </p>
      {canReview ? (
        <div className="flex flex-col gap-3">
          {rec && covered.length > 0 && (
            <div className="flex flex-wrap items-center gap-2">
              <Button variant="primary" onClick={() => setOpen("recommended")}>
                Close {count(covered.length)} as {outcomeLabel(rec.outcome)}
              </Button>
              {extra}
            </div>
          )}
          <div className="flex flex-wrap items-end gap-2">
            <Field label={rec ? "Or choose another outcome" : "Outcome"} htmlFor={`${id}-outcome`}>
              <Select id={`${id}-outcome`} value={outcome} onChange={(e) => setOutcome(e.target.value)}>
                <option value="">— choose an outcome —</option>
                {OUTCOME_KEYS.map((k) => (
                  <option key={k} value={k}>
                    {OUTCOMES[k]}
                  </option>
                ))}
              </Select>
            </Field>
            <Button disabled={outcome === ""} onClick={() => setOpen("chosen")}>
              Mark {label} reviewed
            </Button>
            {!(rec && covered.length > 0) && extra}
          </div>
          <ConfirmDialog
            open={open === "chosen"}
            onOpenChange={(next) => {
              setOpen(next ? "chosen" : null);
              if (!next) void changed(queries);
            }}
            title={`Mark ${label} reviewed as ${outcomeLabel(outcome)}`}
            description="Each investigation is marked only if it is still exactly as this page showed it (its version and latest review); the others are left as they are and counted. Nothing is closed in Kibana."
            request={request}
            confirmLabel={`Mark ${count(members.length)} reviewed`}
            onSent={sent}
          />
          {rec && (
            <ConfirmDialog
              open={open === "recommended"}
              onOpenChange={(next) => {
                setOpen(next ? "recommended" : null);
                if (!next) void changed(queries);
              }}
              title={`Close ${count(covered.length)} ${plural(covered.length, "investigation")} as ${outcomeLabel(rec.outcome)}`}
              description="Only the investigations ARGUS has a proposal for are named. Each is marked reviewed only if it is still exactly as this page showed it; the others are left as they are and counted. Nothing is closed in Kibana."
              request={recommended}
              confirmLabel={`Close ${count(covered.length)}`}
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
