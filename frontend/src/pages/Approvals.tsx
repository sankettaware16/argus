import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { createContext, useContext, useEffect, useId, useMemo, useRef, useState } from "react";
import type { ApprovalGroupOut, ApprovalOut, ApprovalQueueOut, DecisionDone } from "../client/types.gen";
import { WritesView } from "../components/cases/WritesView";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { Loading, Problem } from "../components/Problem";
import { Time } from "../components/Time";
import { UntrustedText } from "../components/UntrustedText";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Card, CardTitle } from "../components/ui/card";
import { Field, TextArea } from "../components/ui/field";
import { useAnnounce } from "../lib/announce";
import { APPROVAL_KIND_HINTS, APPROVAL_STATUS_TONE, APPROVAL_STATUS_WORDS } from "../lib/cases";
import { count, plural } from "../lib/format";
import { useGuard } from "../lib/guard";
import { useNow } from "../lib/now";
import { approvalsOptions, changedCase } from "../lib/queries";

const NOTE_MAX = 4000;

function Text({ value, max = 400, lines = 4 }: { value: string; max?: number; lines?: number }) {
  return <UntrustedText value={value} limits={{ maxChars: max, maxLines: lines }} />;
}

const TITLE = "approvals-title";
const CARD = "[data-queue-card]";

interface Settle {
  /** a decision came from this card: the focus goes to the card that takes its place */
  place: (from: Element | null) => void;
  /** for a dialog's finalFocus: where the focus goes when it closes (null: the default) */
  restore: () => HTMLElement | null;
}

const SettleFocus = createContext<Settle>({ place: () => undefined, restore: () => null });

/**
 * After a decision the card the person worked in may be gone (decided, so no longer waiting) and
 * the focus with it: it goes to the card that takes its place, else to the page's title, instead
 * of falling to the top of the page (WCAG 2.4.3; Q-B3 review R3-4). It acts once the queue has
 * been read again, and only when the focus is really lost; a dialog still open on that moment
 * hands it over when it closes.
 */
function useSettleFocus(readAt: number): Settle {
  const at = useRef<number | null>(null);
  const fresh = useRef(false);
  const target = (): HTMLElement | null => {
    const cards = [...document.querySelectorAll<HTMLElement>(CARD)];
    return cards[Math.min(at.current ?? 0, cards.length - 1)] ?? document.getElementById(TITLE);
  };
  const done = () => {
    at.current = null;
    fresh.current = false;
  };
  useEffect(() => {
    if (at.current === null) return;
    fresh.current = true;
    const active = document.activeElement;
    if (active === null || active === document.body || !document.body.contains(active)) {
      target()?.focus();
      done();
    }
  }, [readAt]);
  return {
    place: (from) => {
      const index = from === null ? -1 : [...document.querySelectorAll(CARD)].indexOf(from);
      at.current = Math.max(index, 0);
      fresh.current = false;
    },
    restore: () => {
      if (at.current === null || !fresh.current) return null;
      const found = target();
      done();
      return found;
    },
  };
}

/** The step-up line: deciding needs the person's password typed again within five minutes. */
function StepUp({ queue }: { queue: ApprovalQueueOut }) {
  const s = queue.step_up;
  return (
    <section aria-label="Confirming it is you" className="rounded-control bg-surface-2 px-3 py-2 text-sm">
      {s.valid ? (
        <p className="m-0">
          <Badge tone="ok">Confirmed</Badge> You typed your password again, so you can approve until <Time value={s.valid_until} />.
        </p>
      ) : (
        <p className="m-0">
          <Badge tone="warn">Not confirmed</Badge> To approve or reject you type your password again first (it counts for five minutes).{" "}
          <a href={s.url}>Confirm it is you</a>
        </p>
      )}
      {!queue.can_sign && (
        <p className="m-0 mt-1 text-warn">
          This server has no key to sign approvals with, so decisions cannot be recorded here yet. An ARGUS admin sets one up; you can still read every request.
        </p>
      )}
    </section>
  );
}

function Decisions({ a }: { a: ApprovalOut }) {
  if (a.decisions.length === 0) return null;
  return (
    <ul className="m-0 list-none p-0 text-sm" aria-label="Decisions so far">
      {a.decisions.map((d, i) => (
        <li key={i}>
          <Badge tone={d.decision === "approved" ? (d.counts ? "ok" : "warn") : "danger"}>{d.decision === "approved" ? "Approved" : "Rejected"}</Badge>{" "}
          <Text value={d.approver?.display_name ?? "someone"} max={60} lines={1} />, <Time value={d.decided_at} />
          {d.decision === "approved" && !d.counts && " (no longer counts: that person's access was revoked since)"}
          {d.note && (
            <span className="block border-l-4 border-dashed border-border-strong pl-2 text-muted">
              <Text value={d.note} max={600} lines={6} />
            </span>
          )}
        </li>
      ))}
    </ul>
  );
}

/** What approving or rejecting one request sends, composed from what is on the card. */
function Decide({ a, stepped, canSign, group, onSent }: { a: ApprovalOut; stepped: boolean; canSign: boolean; group?: readonly number[]; onSent: (done: DecisionDone, group: readonly number[] | undefined) => void }) {
  const id = useId();
  const [mode, setMode] = useState<"approved" | "rejected" | null>(null);
  const [note, setNote] = useState("");
  const [open, setOpen] = useState(false);
  const said = note.trim();
  const queries = useQueryClient();
  const settle = useContext(SettleFocus);
  const root = useRef<HTMLDivElement>(null);
  const blocked = !canSign ? "This server cannot sign decisions yet." : !stepped ? "Confirm it is you first (above)." : null;
  const guard = useGuard(blocked);
  const request = useMemo(
    () => ({
      method: "POST" as const,
      path: `/api/v1/approvals/${a.id}/decision`,
      body: {
        decision: mode ?? "approved",
        payload_hash: a.payload_hash,
        ...(said !== "" ? { note: said } : {}),
        ...(group !== undefined && mode === "approved" ? { group: [...group] } : {}),
      },
    }),
    [a.id, a.payload_hash, mode, said, group],
  );
  if (!a.you.can_decide) {
    return (
      <p className="m-0 text-sm text-muted">
        <span className="font-medium">You cannot decide this: </span>
        <Text value={a.you.why_not ?? "not available"} max={300} lines={3} />
      </p>
    );
  }
  return (
    <div className="flex flex-col gap-2" ref={root}>
      <div className="flex flex-wrap items-center gap-2">
        <Button variant="primary" {...guard.props} aria-expanded={mode === "approved"} onClick={guard.press(() => setMode(mode === "approved" ? null : "approved"))}>
          Approve{group !== undefined ? " (part of the sample)" : ""}…
        </Button>
        {group === undefined && (
          <Button variant="danger" {...guard.props} aria-expanded={mode === "rejected"} onClick={guard.press(() => setMode(mode === "rejected" ? null : "rejected"))}>
            Reject…
          </Button>
        )}
        {guard.hint}
      </div>
      {mode !== null && (
        <div className="flex flex-col gap-2 rounded-card bg-surface-2 p-3">
          <Field label={mode === "approved" ? "Your words (optional)" : "Why you reject it (optional)"} htmlFor={id}>
            <TextArea id={id} rows={2} maxLength={NOTE_MAX} value={note} onChange={(e) => setNote(e.target.value)} />
          </Field>
          <div>
            <Button variant={mode === "approved" ? "primary" : "danger"} onClick={() => setOpen(true)}>
              Review the request
            </Button>
          </div>
        </div>
      )}
      <ConfirmDialog
        open={open}
        onOpenChange={(next) => {
          setOpen(next);
          if (!next) void changedCase(queries);
        }}
        title={`${mode === "rejected" ? "Reject" : "Approve"}: ${a.words}`}
        description={
          mode === "rejected"
            ? "The request ends; nobody can approve it afterwards. Your reason is kept with the decision."
            : "You approve exactly the writes shown on the card (the request names their hash). If the case, its alerts or the writes changed since you read them, nothing is recorded."
        }
        request={request}
        confirmLabel={mode === "rejected" ? "Reject" : "Approve"}
        finalFocus={settle.restore}
        onSent={(sent) => {
          settle.place(root.current?.closest(CARD) ?? null);
          onSent(sent.data as DecisionDone, group);
        }}
      />
    </div>
  );
}

/** What a decision came to, in words. */
function sayDecision(d: DecisionDone): string {
  const closed = d.applied.map((a) => `case ${a.number} is ${a.state}`).join(", ");
  if (d.status === "rejected") return "Rejected.";
  if (d.status === "pending") return "Approved; it needs one more person.";
  return closed === "" ? "Approved." : `Approved. ${closed[0]?.toUpperCase()}${closed.slice(1)}.`;
}

function Alerts({ a }: { a: ApprovalOut }) {
  if (a.kind !== "closure" && a.kind !== "merge") return null;
  return (
    <p className="m-0 text-sm">
      Alerts in the case: {count(a.alerts_then)} when it was asked for
      {a.alerts_now !== null && a.alerts_now !== undefined && (
        <>
          , {count(a.alerts_now)} now.{" "}
          {a.alerts_same ? "The same alerts." : <strong className="text-warn">The alerts changed since it was asked for: the closure will be held back and asked again if you approve it.</strong>}
        </>
      )}
      .
    </p>
  );
}

function Request({ a, stepped, canSign, group, onSent }: { a: ApprovalOut; stepped: boolean; canSign: boolean; group?: readonly number[]; onSent: (done: DecisionDone, group: readonly number[] | undefined) => void }) {
  return (
    <Card aria-label={a.words} className="flex flex-col gap-2" data-testid="request" data-queue-card="" tabIndex={-1}>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <CardTitle className="mb-0">
          <Text value={a.words} max={200} lines={1} />
        </CardTitle>
        <Badge tone={APPROVAL_STATUS_TONE[a.status] ?? "neutral"}>{APPROVAL_STATUS_WORDS[a.status] ?? a.status}</Badge>
      </div>
      <p className="m-0 text-sm">
        <Link to="/cases/$id" params={{ id: a.case.id }}>
          Case {a.case.number}: <Text value={a.case.title} max={160} lines={1} />
        </Link>
        {a.target && (
          <>
            {" "}
            into{" "}
            <Link to="/cases/$id" params={{ id: a.target.id }}>
              case {a.target.number}
            </Link>
          </>
        )}
        . {APPROVAL_KIND_HINTS[a.kind] ?? "A request"}. {a.status_words}.
      </p>
      <p className="m-0 text-xs text-muted">
        Asked by{" "}
        {a.requested_by ? <Text value={a.requested_by.display_name} max={60} lines={1} /> : <>ARGUS{a.proposed_by ? ` (${a.proposed_by.replace(/^argus:/, "")})` : ""}, as a proposal</>} at <Time value={a.requested_at} />; open until <Time value={a.expires_at} />.
        {a.required === 2 && " Two different people must approve it."}
      </p>
      {a.note && (
        <blockquote className="m-0 border-l-4 border-dashed border-border-strong pl-3 text-sm">
          <span className="block text-xs text-muted">What the person wrote when asking:</span>
          <Text value={a.note} max={1500} lines={15} />
        </blockquote>
      )}
      {a.hold && (
        <p className="m-0 text-sm">
          The Kibana write held back: {a.hold.write_class} {a.hold.op}, now {a.hold.state}
          {a.hold.state_reason ? <>: <Text value={a.hold.state_reason} max={300} lines={3} /></> : ""}.
        </p>
      )}
      <Alerts a={a} />
      <WritesView payload={a.payload} hash={a.payload_hash} />
      <Decisions a={a} />
      <Decide a={a} stepped={stepped} canSign={canSign} group={group} onSent={onSent} />
    </Card>
  );
}

// ------------------------------------------------------------------ groups

type Snapshot = ApprovalGroupOut;

function GroupCard({ group, byId, pendingIds, stepped, canSign, onSample, onDone }: {
  group: Snapshot;
  byId: ReadonlyMap<number, ApprovalOut>;
  pendingIds: ReadonlySet<number>;
  stepped: boolean;
  canSign: boolean;
  onSample: (g: Snapshot) => void;
  onDone: (g: Snapshot) => void;
}) {
  const ids = group.items.map((i) => i.request_id);
  const sample = group.sample;
  const rest = ids.filter((i) => !sample.includes(i));
  const sampleLeft = sample.filter((i) => pendingIds.has(i));
  const restLeft = rest.filter((i) => pendingIds.has(i));
  const [open, setOpen] = useState(false);
  const [note, setNote] = useState("");
  const { announce } = useAnnounce();
  const queries = useQueryClient();
  const settle = useContext(SettleFocus);
  const card = useRef<HTMLElement>(null);
  const said = note.trim();
  const stopped = sampleLeft.length > 0 ? "Approve the whole sample first." : !stepped ? "Confirm it is you first (above)." : !canSign ? "This server cannot sign decisions yet." : null;
  const guard = useGuard(stopped);
  const request = useMemo(
    () => ({
      method: "POST" as const,
      path: "/api/v1/approvals/group",
      body: { items: group.items.map((i) => ({ request_id: i.request_id, payload_hash: i.payload_hash })), ...(said !== "" ? { note: said } : {}) },
    }),
    [group.items, said],
  );
  const finished = restLeft.length === 0 && sampleLeft.length === 0;
  return (
    <Card aria-label={group.words} className="flex flex-col gap-3" data-testid="group" data-queue-card="" tabIndex={-1} ref={card}>
      <CardTitle className="mb-0">
        <Text value={group.words} max={200} lines={1} />
      </CardTitle>
      <p className="m-0 max-w-prose text-sm text-muted">
        These closures are alike. Look at the sample below and approve each of its cases one by one; then the other {count(rest.length)} {plural(rest.length, "case")} can be approved together. A group is never more than twenty cases.
      </p>
      {finished ? (
        <p className="m-0 text-sm" role="status">
          <Badge tone="ok">Done</Badge> Every case of this group was decided.{" "}
          <Button size="sm" onClick={() => onDone(group)}>
            Close this group
          </Button>
        </p>
      ) : (
        <>
          <h3 className="m-0 text-sm font-semibold">
            Step 1: the sample ({count(sample.length - sampleLeft.length)} of {count(sample.length)} approved)
          </h3>
          <ul className="m-0 flex list-none flex-col gap-3 p-0">
            {sample.map((rid) => {
              const a = byId.get(rid);
              return (
                <li key={rid}>
                  {a ? (
                    <Request
                      a={a}
                      stepped={stepped}
                      canSign={canSign}
                      group={ids}
                      onSent={(d) => {
                        announce(sayDecision(d), "ok");
                        onSample(group);
                      }}
                    />
                  ) : (
                    <p className="m-0 text-sm text-muted">
                      Request {rid}: <Badge tone="ok">decided</Badge>
                    </p>
                  )}
                </li>
              );
            })}
          </ul>
          <h3 className="m-0 text-sm font-semibold">Step 2: the other {count(rest.length)}</h3>
          <ul className="m-0 pl-5 text-sm">
            {rest.map((rid) => {
              const item = group.items.find((i) => i.request_id === rid);
              return (
                <li key={rid}>
                  Case {item?.case_number}: <Text value={item?.case_title ?? ""} max={160} lines={1} /> {pendingIds.has(rid) ? "" : <Badge tone="ok">decided</Badge>}
                </li>
              );
            })}
          </ul>
          {restLeft.length > 0 && (
            <div className="flex flex-col gap-2">
              <Field label="Your words for the rest (optional)" htmlFor={`${group.key}-note`}>
                <TextArea id={`${group.key}-note`} rows={2} maxLength={NOTE_MAX} value={note} onChange={(e) => setNote(e.target.value)} />
              </Field>
              <div className="flex flex-wrap items-center gap-2">
                <Button variant="primary" {...guard.props} onClick={guard.press(() => setOpen(true))}>
                  Approve the other {count(restLeft.length)}…
                </Button>
                {guard.hint}
              </div>
            </div>
          )}
          <ConfirmDialog
            open={open}
            onOpenChange={(next) => {
              setOpen(next);
              if (!next) void changedCase(queries);
            }}
            title={`Approve the other ${count(rest.length)} cases together`}
            description="Each request is named with the hash of the writes you read; all are approved or none. If any of them changed since the queue was read, nothing is recorded."
            request={request}
            confirmLabel={`Approve ${count(rest.length)}`}
            finalFocus={settle.restore}
            onSent={(sent) => {
              settle.place(card.current);
              const done = sent.data as { decided?: DecisionDone[] } | undefined;
              announce(`Approved ${count(done?.decided?.length ?? 0)} more cases together.`, "ok");
              onDone(group);
            }}
          />
        </>
      )}
    </Card>
  );
}

/**
 * The approvals queue (plan §5 Q-B3, §7.1): every request waiting for a decision with the exact
 * writes it binds, the alerts when it was asked for and now, and who decided what; groups of
 * alike benign closures with their sample first; the person's step-up. A decision shows its
 * exact request and sends it only after the person confirms.
 */
export function Approvals() {
  const queue = useQuery(approvalsOptions);
  const { announce } = useAnnounce();
  const queries = useQueryClient();
  const settle = useSettleFocus(queue.dataUpdatedAt);
  // a group being worked through is kept as it was first shown: after each approval of its sample
  // the queue shrinks, and a smaller group would have a smaller sample
  const [active, setActive] = useState<Record<string, Snapshot>>({});
  const now = useNow();
  if (queue.isPending) return <Loading what="the approvals" />;
  if (queue.isError) return <Problem error={queue.error} what="The approvals" onRetry={() => void queue.refetch()} />;
  const q = queue.data;
  const byId = new Map(q.pending.map((a) => [a.id, a]));
  const pendingIds = new Set(byId.keys());
  const kept = Object.values(active);
  const taken = new Set(kept.flatMap((g) => g.items.map((i) => i.request_id)));
  const live = q.groups.filter((g) => !g.items.some((i) => taken.has(i.request_id)));
  const stepped = q.step_up.valid && (q.step_up.valid_until === null || q.step_up.valid_until === undefined || new Date(q.step_up.valid_until).getTime() > now);
  const done = (d: DecisionDone) => {
    announce(sayDecision(d), "ok");
    void changedCase(queries);
  };
  const grouped = new Set([...kept, ...live].flatMap((g) => g.items.map((i) => i.request_id)));
  const loose = q.pending.filter((a) => !grouped.has(a.id));
  return (
    <SettleFocus.Provider value={settle}>
      <h1 id={TITLE} tabIndex={-1} className="page-h focus:outline-none">
        Approvals
      </h1>
      <p className="m-0 max-w-prose text-sm text-muted">
        Closures, merges and the Kibana writes that need a person&apos;s decision. Read exactly what each one writes; approving signs for those writes and nothing else. A request ARGUS proposed
        is only ever a proposal: ARGUS never approves.
      </p>
      <StepUp queue={q} />
      {q.pending.length === 0 && kept.length === 0 ? (
        <p className="m-0 text-sm">Nothing is waiting for a decision.</p>
      ) : (
        <p className="m-0 text-sm" aria-live="polite">
          {count(q.pending_total)} {plural(q.pending_total, "request")} waiting.
          {q.pending_total > q.pending.length && ` The oldest ${count(q.pending.length)} are listed; decide them and the rest follow.`}
        </p>
      )}
      {(kept.length > 0 || live.length > 0) && (
        <section aria-label="Groups" className="flex flex-col gap-4">
          <h2 className="m-0 text-lg font-semibold">Alike requests, together</h2>
          {[...kept, ...live].map((g) => (
            <GroupCard
              key={g.key}
              group={g}
              byId={byId}
              pendingIds={pendingIds}
              stepped={stepped}
              canSign={q.can_sign}
              onSample={(snap) => setActive((now) => ({ ...now, [snap.key]: now[snap.key] ?? snap }))}
              onDone={(snap) =>
                setActive((held) => Object.fromEntries(Object.entries(held).filter(([key]) => key !== snap.key)))
              }
            />
          ))}
        </section>
      )}
      {loose.length > 0 && (
        <section aria-label="Waiting" className="flex flex-col gap-4">
          <h2 className="m-0 text-lg font-semibold">Waiting for a decision</h2>
          {loose.map((a) => (
            <Request key={a.id} a={a} stepped={stepped} canSign={q.can_sign} onSent={done} />
          ))}
        </section>
      )}
      {q.recent.length > 0 && (
        <details>
          <summary className="cursor-pointer text-sm font-medium">Decided or ended in the last three days ({q.recent.length})</summary>
          <ul className="m-0 mt-2 flex list-none flex-col gap-1 p-0 text-sm">
            {q.recent.map((a) => (
              <li key={a.id}>
                <Badge tone={APPROVAL_STATUS_TONE[a.status] ?? "neutral"}>{APPROVAL_STATUS_WORDS[a.status] ?? a.status}</Badge> <Text value={a.words} max={200} lines={1} /> —{" "}
                <Link to="/cases/$id" params={{ id: a.case.id }}>
                  case {a.case.number}
                </Link>
                , asked <Time value={a.requested_at} />. {a.status_words}.
              </li>
            ))}
          </ul>
        </details>
      )}
    </SettleFocus.Provider>
  );
}
