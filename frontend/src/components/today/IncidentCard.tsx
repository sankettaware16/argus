import { Link } from "@tanstack/react-router";
import { Fragment, useState, type Ref } from "react";
import type { CaseRowOut } from "../../client/types.gen";
import { cn } from "../../lib/cn";
import { shownCertainty, side, startsWithCertainty, stateWords, topWhy, type Card } from "../../lib/engine";
import { parse } from "../../lib/time";
import { clock, sinceWords, waited, weekdayDay } from "../../lib/when";
import { AlertGroupDecide } from "../decide/AlertGroupDecide";
import { PossibleButtons, type DecideKeys } from "../decide/Decide";
import { targetOfCard } from "../decide/target";
import { CheckList } from "../incident/CheckList";
import { ActivityLine, CertaintyWord, ChangedStrip, ChipRow, PriorityBadge } from "../incident/Parts";
import { UntrustedText } from "../UntrustedText";
import { ConfirmDialog } from "../ConfirmDialog";
import { Button } from "../ui/button";
import { useAnnounce } from "../../lib/announce";
import { useQueryClient } from "@tanstack/react-query";
import { changedCase } from "../../lib/queries";

export type CardForm = "full" | "compact" | "phone";

function Title({ card, titleRef }: { card: Card; titleRef?: Ref<HTMLAnchorElement> }) {
  const certainty = card.kind === "incident" ? shownCertainty(card.state, null, card.engine) : card.engine.certainty;
  const words = (
    <>
      {certainty !== null && !startsWithCertainty(card.title) && (
        <>
          <CertaintyWord value={certainty} /> ·{" "}
        </>
      )}
      <UntrustedText value={card.title} limits={{ maxChars: 240, maxLines: 2 }} />
    </>
  );
  if (card.id === null) return <span>{words}</span>;
  return card.kind === "incident" ? (
    <Link ref={titleRef} to="/incidents/$id" params={{ id: card.id }} className="text-text no-underline hover:underline" data-testid="card-title">
      {words}
    </Link>
  ) : (
    <Link ref={titleRef} to="/alert-groups/$id" params={{ id: card.id }} className="text-text no-underline hover:underline" data-testid="card-title">
      {words}
    </Link>
  );
}

/** "waiting for a person since Mon (3 days)", or the hold's words. */
function waitingWords(card: Card, now: Date, short = false): string | null {
  if (card.hold) {
    const until = parse(card.hold.until);
    return `${card.hold.by.name} is checking${card.hold.reason ? ` · ${card.hold.reason}` : ""}${until ? ` · back ${weekdayDay(until)}` : ""}`;
  }
  const since = parse(card.waiting_since);
  if (since === null) return null;
  return short ? `waiting ${waited(since, now)}` : `waiting for a person since ${sinceWords(since, now)} (${waited(since, now)})`;
}

function Meta({ card, now }: { card: Card; now: Date }) {
  const waiting = waitingWords(card, now);
  const mailed = parse(card.engine.team_notified_at);
  const parts = [
    <span key="state">{card.kind === "incident" ? stateWords({ state: card.state, number: card.number, taken_by: card.taken_by }) : "Alert group"}</span>,
    <ActivityLine key="activity" engine={card.engine} />,
    waiting ? (
      <span key="waiting" className={cn(card.hold && "font-semibold text-text")}>
        {waiting}
      </span>
    ) : null,
    card.engine.raised_by_ai ? <span key="ai">Raised by ARGUS&apos;s AI</span> : null,
    card.engine.band === "P1" && mailed ? <span key="mailed">team e-mailed {clock(mailed)}</span> : null,
  ].filter((p) => p !== null);
  return (
    <p className="m-0 text-[0.8125rem] text-muted" data-testid="card-meta">
      {parts.map((p, i) => (
        <Fragment key={i}>
          {i > 0 && " · "}
          {p}
        </Fragment>
      ))}
    </p>
  );
}

function Why({ card }: { card: Card }) {
  const top = topWhy(card.engine);
  if (top.shown.length === 0) return null;
  return (
    <p className="m-0 truncate text-sm" data-testid="card-why">
      <span className="mr-1 text-xs font-semibold text-muted">Why</span>
      <UntrustedText value={top.shown.join(" · ")} limits={{ maxChars: 300, maxLines: 1 }} />
      {top.more > 0 && <span className="text-muted"> +{top.more} more</span>}
    </p>
  );
}

function Sides({ card }: { card: Card }) {
  const campus = side(card.engine, "affected");
  const other = side(card.engine, "actor");
  if (campus.length === 0 && other.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-x-4 gap-y-1" data-testid="card-sides">
      <ChipRow objects={campus} label="Campus side" />
      <ChipRow objects={other} label="Other side" />
    </div>
  );
}

/** "Take it" on an open incident nobody took: the exact request first. */
function TakeIt({ card }: { card: Card }) {
  const [open, setOpen] = useState(false);
  const { announce } = useAnnounce();
  const queries = useQueryClient();
  if (card.id === null || card.version === null) return null;
  const id = card.id;
  return (
    <>
      <Button variant="primary" onClick={() => setOpen(true)}>
        Take it
      </Button>
      <ConfirmDialog
        open={open}
        onOpenChange={setOpen}
        title={`Take incident #${card.number ?? ""}`}
        description="You will be the person working it; others see it as taken by you. If anyone changed it since you read it, nothing is saved."
        request={{ method: "POST", path: `/api/v1/cases/${id}/take`, body: { expected_version: card.version } }}
        confirmLabel="Take it"
        onSent={() => {
          announce(`You took incident #${card.number ?? ""}.`, "ok");
          void changedCase(queries, id);
          void queries.invalidateQueries({ queryKey: ["today"] });
        }}
      />
    </>
  );
}

function Buttons({ card, keys, size, onDone, onConflict }: { card: Card; keys?: DecideKeys; size: "md" | "touch"; onDone?: (row: CaseRowOut | null) => void; onConflict?: () => void }) {
  if (card.kind === "alert_group") return card.id ? <AlertGroupDecide id={card.id} title={card.title} size={size} onDone={() => onDone?.(null)} /> : null;
  const target = targetOfCard(card);
  if (target === null) return null;
  if (card.state === "suspected") {
    return (
      <PossibleButtons
        target={target}
        confirmRef={keys?.confirm}
        dismissRef={keys?.dismiss}
        size={size}
        onDone={(row) => onDone?.(row)}
        onConflict={onConflict}
        checkLink={
          <Link to="/incidents/$id" params={{ id: target.id }} search={{ tab: "evidence" }} className="text-accent">
            Ask ARGUS to check
          </Link>
        }
      />
    );
  }
  if (card.state === "open" && card.taken_by === null) return <TakeIt card={card} />;
  return null;
}

/**
 * One possible incident (or a gray-band alert group) on Today (docs/p4f-ui-spec.md §5.3): how
 * urgent, how sure, why, what was checked, the two sides and the answers, in that order. The
 * compact form (the gray band) says why ARGUS is unsure and the check that would decide; the
 * phone form is four lines and expands in place.
 */
export function IncidentCard({
  card,
  form = "full",
  now,
  keys,
  titleRef,
  conflict = false,
  onDone,
  onConflict,
}: {
  card: Card;
  form?: CardForm;
  now: Date;
  keys?: DecideKeys;
  titleRef?: Ref<HTMLAnchorElement>;
  conflict?: boolean;
  onDone?: (row: CaseRowOut | null) => void;
  onConflict?: () => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const changed = conflict ? <ChangedStrip changed={card.engine.changed.length ? card.engine.changed : ["someone else changed it first"]} lead="It changed while you were deciding" /> : <ChangedStrip changed={card.engine.changed} />;
  const open =
    card.id === null ? null : card.kind === "incident" ? (
      <Link to="/incidents/$id" params={{ id: card.id }} className="ml-auto text-sm">
        Open <span aria-hidden="true">→</span>
        <span className="sr-only"> incident #{card.number}</span>
      </Link>
    ) : (
      <Link to="/alert-groups/$id" params={{ id: card.id }} className="ml-auto text-sm">
        Open <span aria-hidden="true">→</span>
        <span className="sr-only"> the alert group</span>
      </Link>
    );
  const common = {
    "data-testid": "incident-card",
    "data-band": card.engine.band,
    "data-kind": card.kind,
    "data-id": card.id ?? undefined,
  };

  if (form === "phone") {
    const certainty = card.kind === "incident" ? shownCertainty(card.state, null, card.engine) : card.engine.certainty;
    const waiting = waitingWords(card, now, true);
    const top = topWhy(card.engine, 1).shown[0];
    return (
      <article {...common} className="flex flex-col gap-1 rounded-card border border-border bg-surface px-3 py-2" onClick={(e) => (e.target as HTMLElement).closest("a,button,[role=menu],form") === null && setExpanded(!expanded)}>
        <p className="m-0 flex flex-wrap items-center gap-x-2 text-sm">
          <PriorityBadge engine={card.engine} />
          <CertaintyWord value={certainty} />
          {waiting && <span className="text-muted">· {waiting}</span>}
        </p>
        <h3 className="m-0 line-clamp-2 text-base leading-snug font-semibold">
          <Title card={card} titleRef={titleRef} />
        </h3>
        {top && (
          <p className="m-0 truncate text-sm">
            <UntrustedText value={top} limits={{ maxChars: 200, maxLines: 1 }} />
          </p>
        )}
        {expanded && (
          <div className="flex flex-col gap-1.5">
            {changed}
            <CheckList checks={card.engine.checks} inline />
            <Sides card={card} />
          </div>
        )}
        <div className="flex flex-wrap items-center gap-2">
          <Buttons card={card} keys={keys} size="touch" onDone={onDone} onConflict={onConflict} />
          {open}
        </div>
      </article>
    );
  }

  if (form === "compact") {
    const unsure = card.engine.checks.find((c) => c.state === "unknown")?.text ?? topWhy(card.engine, 1).shown[0] ?? null;
    const decider = card.engine.alternatives.find((a) => a.state === "fits") ?? card.engine.alternatives.find((a) => a.state === "unknown");
    return (
      <article {...common} className="flex flex-col gap-1.5 rounded-card border border-border bg-surface p-3">
        <h3 className="m-0 flex items-start gap-2 text-base leading-snug font-semibold">
          <PriorityBadge engine={card.engine} className="mt-0.5" />
          <span className="min-w-0">
            <Title card={card} titleRef={titleRef} />
          </span>
        </h3>
        <Meta card={card} now={now} />
        {unsure && (
          <p className="m-0 text-sm">
            <span className="font-medium">Why it&apos;s unsure:</span> <UntrustedText value={unsure} limits={{ maxChars: 240, maxLines: 2 }} />
          </p>
        )}
        {decider?.test && (
          <p className="m-0 text-sm">
            <span className="font-medium">The check that would decide:</span> <UntrustedText value={decider.test} limits={{ maxChars: 240, maxLines: 2 }} />
          </p>
        )}
        <div className="flex flex-wrap items-center gap-2">
          <Buttons card={card} keys={keys} size="md" onDone={onDone} onConflict={onConflict} />
          {open}
        </div>
      </article>
    );
  }

  return (
    <article {...common} className="flex flex-col gap-1.5 rounded-card border border-border bg-surface p-4">
      <h3 className="m-0 flex items-start gap-2 text-base leading-snug font-semibold">
        <PriorityBadge engine={card.engine} className="mt-0.5" />
        <span className="min-w-0 text-balance">
          <Title card={card} titleRef={titleRef} />
        </span>
      </h3>
      <Meta card={card} now={now} />
      {changed}
      <Why card={card} />
      <CheckList checks={card.engine.checks} inline />
      <Sides card={card} />
      <div className="flex flex-wrap items-center gap-2 pt-1">
        <Buttons card={card} keys={keys} size="md" onDone={onDone} onConflict={onConflict} />
        {open}
      </div>
    </article>
  );
}
