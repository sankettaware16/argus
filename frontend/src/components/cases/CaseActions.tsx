import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useId, useMemo, useRef, useState, type ReactNode } from "react";
import { listCases } from "../../client/sdk.gen";
import type { CaseActionStateOut, CaseChanged, CaseDetail, ClosureChoiceOut } from "../../client/types.gen";
import { useAnnounce } from "../../lib/announce";
import { unwrap } from "../../lib/call";
import { caseStateWord, reasonLabel } from "../../lib/cases";
import { useGuard } from "../../lib/guard";
import { optionText } from "../../lib/optionText";
import { closurePreviewOptions, changedCase, mergePreviewOptions } from "../../lib/queries";
import { ConfirmDialog } from "../ConfirmDialog";
import { Loading, Problem } from "../Problem";
import { UntrustedText } from "../UntrustedText";
import { Button } from "../ui/button";
import { Field, Select, TextArea, TextInput } from "../ui/field";
import { WritesView } from "./WritesView";

const NOTE_MAX = 4000;
const CASE_TITLE = "case-title";

/** After a change the opener may be gone, so the focus goes to the case's title, which stays. */
export function useAfterSend() {
  const done = useRef(false);
  return {
    sent: () => {
      done.current = true;
    },
    focus: () => {
      if (!done.current) return null;
      done.current = false;
      return document.getElementById(CASE_TITLE);
    },
  };
}

export interface Shared {
  detail: CaseDetail;
  onDone: () => void;
}

export function useAfterChange(detail: CaseDetail, onDone: () => void) {
  const queries = useQueryClient();
  const { announce } = useAnnounce();
  return {
    queries,
    finish: async (say: string, tone: "ok" | "info" = "ok") => {
      announce(say, tone);
      onDone();
      await changedCase(queries, detail.case.id);
    },
  };
}

function Sentence({ text }: { text: string }) {
  return <UntrustedText value={text} limits={{ maxChars: 400, maxLines: 4 }} />;
}

// ------------------------------------------------------------------ one-click and small forms

/** Take or Release: no fields, so the exact request is shown at once. */
function Plain({ detail, onDone, action, title, say, label }: Shared & { action: "take" | "release"; title: string; say: string; label: string }) {
  const [open, setOpen] = useState(true);
  const after = useAfterChange(detail, onDone);
  const afterSend = useAfterSend();
  const request = useMemo(
    () => ({ method: "POST" as const, path: `/api/v1/cases/${detail.case.id}/${action}`, body: { expected_version: detail.case.version } }),
    [detail.case.id, detail.case.version, action],
  );
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (!next) {
          onDone();
          void changedCase(after.queries, detail.case.id);
        }
      }}
      title={title}
      description={`${action === "take" ? `You will own case ${detail.case.number}; others see you as its owner.` : `Case ${detail.case.number} is open again, owned by nobody.`} If anyone changed it since you read it, nothing is saved.`}
      request={request}
      confirmLabel={label}
      finalFocus={afterSend.focus}
      onSent={() => {
        afterSend.sent();
        void after.finish(say);
      }}
    />
  );
}

function Assign({ detail, onDone }: Shared) {
  const id = useId();
  const [who, setWho] = useState("");
  const [open, setOpen] = useState(false);
  const after = useAfterChange(detail, onDone);
  const afterSend = useAfterSend();
  const people = detail.assignees.filter((p) => p.id !== detail.case.owner?.id);
  const chosen = people.find((p) => String(p.id) === who);
  const guard = useGuard(chosen === undefined ? "Choose a person first." : null);
  const request = useMemo(
    () => ({ method: "POST" as const, path: `/api/v1/cases/${detail.case.id}/assign`, body: { expected_version: detail.case.version, user_id: Number(who) } }),
    [detail.case.id, detail.case.version, who],
  );
  return (
    <div className="flex flex-col gap-2">
      <Field label="Give the case to" htmlFor={id}>
        <Select id={id} value={who} onChange={(e) => setWho(e.target.value)}>
          <option value="">Choose a person…</option>
          {people.map((p) => (
            <option key={p.id} value={p.id}>
              {optionText(p.display_name, 60)} ({optionText(p.username, 40)})
            </option>
          ))}
        </Select>
      </Field>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <Button variant="primary" {...guard.props} onClick={guard.press(() => setOpen(true))}>
          Review the request
        </Button>
        {guard.hint}
      </div>
      {chosen !== undefined && (
        <ConfirmDialog
          open={open}
          onOpenChange={(next) => {
            setOpen(next);
            if (!next) void changedCase(after.queries, detail.case.id);
          }}
          title={`Assign case ${detail.case.number}`}
          description="The person becomes the case's owner. They are not told by e-mail; the case shows under Mine for them."
          request={request}
          confirmLabel="Assign"
          finalFocus={afterSend.focus}
          onSent={() => {
            afterSend.sent();
            void after.finish(`Assigned case ${detail.case.number} to ${chosen.display_name}.`);
          }}
        />
      )}
    </div>
  );
}

/** Contain and Reopen: one text the person writes, then the exact request. */
function Words({ detail, onDone, action, label, hint, title, say, confirmLabel, field }: Shared & { action: "contain" | "reopen"; label: string; hint: string; title: string; say: string; confirmLabel: string; field: "attestation" | "reason" }) {
  const id = useId();
  const [text, setText] = useState("");
  const [open, setOpen] = useState(false);
  const after = useAfterChange(detail, onDone);
  const afterSend = useAfterSend();
  const said = text.trim();
  const problem = said === "" ? "Write your words first." : said.length > NOTE_MAX ? `Your words are longer than ${NOTE_MAX} characters.` : said.includes("\u0000") ? "Your words hold a character ARGUS cannot keep." : null;
  const guard = useGuard(problem);
  const request = useMemo(
    () => ({ method: "POST" as const, path: `/api/v1/cases/${detail.case.id}/${action}`, body: { expected_version: detail.case.version, [field]: said } }),
    [detail.case.id, detail.case.version, action, field, said],
  );
  return (
    <div className="flex flex-col gap-2">
      <Field label={label} hint={hint} htmlFor={id}>
        <TextArea id={id} value={text} maxLength={NOTE_MAX} onChange={(e) => setText(e.target.value)} />
      </Field>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <Button variant="primary" {...guard.props} onClick={guard.press(() => setOpen(true))}>
          Review the request
        </Button>
        {guard.hint}
      </div>
      <ConfirmDialog
        open={open}
        onOpenChange={(next) => {
          setOpen(next);
          if (!next) void changedCase(after.queries, detail.case.id);
        }}
        title={title}
        description="Your words are kept with the case and shown to everyone who reads it."
        request={request}
        confirmLabel={confirmLabel}
        finalFocus={afterSend.focus}
        onSent={() => {
          afterSend.sent();
          void after.finish(say);
        }}
      />
    </div>
  );
}

// ------------------------------------------------------------------ closure

function ClosureForm({ detail, onDone }: Shared) {
  const noteId = useId();
  const [reason, setReason] = useState<string>("");
  const [note, setNote] = useState("");
  const [shown, setShown] = useState(false);
  const [open, setOpen] = useState(false);
  const after = useAfterChange(detail, onDone);
  const afterSend = useAfterSend();
  const choice: ClosureChoiceOut | undefined = detail.closure_choices.find((c) => c.reason === reason);
  const said = note.trim();
  const noteOk = choice === undefined ? false : choice.note === "required" ? said !== "" : true;
  const ready = choice !== undefined && choice.enabled && noteOk && said.length <= NOTE_MAX && !said.includes("\u0000");
  const problem = choice === undefined ? "Choose a reason first." : !noteOk ? "This reason needs your words first." : said.length > NOTE_MAX ? `Your words are longer than ${NOTE_MAX} characters.` : said.includes("\u0000") ? "Your words hold a character ARGUS cannot keep." : null;
  const guard = useGuard(ready ? null : (problem ?? "This reason cannot be asked for now."));
  const preview = useQuery({ ...closurePreviewOptions(detail.case.id, reason, detail.case.version), enabled: shown && ready });
  const request = useMemo(
    () => ({
      method: "POST" as const,
      path: `/api/v1/cases/${detail.case.id}/closure-requests`,
      body: {
        expected_version: detail.case.version,
        reason,
        ...(said !== "" ? { note: said } : {}),
        payload_hash: preview.data?.payload_hash ?? "",
      },
    }),
    [detail.case.id, detail.case.version, reason, said, preview.data?.payload_hash],
  );
  return (
    <div className="flex flex-col gap-3">
      <fieldset className="m-0 flex flex-col gap-1.5 border-0 p-0">
        <legend className="mb-1 text-sm font-medium">Why should this case be closed?</legend>
        {detail.closure_choices.map((c) => (
          <label key={c.reason} className="flex items-start gap-2 text-sm">
            <input
              type="radio"
              name="closure-reason"
              className="mt-1 size-4 accent-accent"
              value={c.reason}
              checked={reason === c.reason}
              disabled={!c.enabled}
              onChange={() => {
                setReason(c.reason);
                setShown(false);
              }}
            />
            <span>
              <strong>{c.label}.</strong> {c.meaning}
              {c.approvers === 2 && <span className="text-muted"> Two different people must approve it.</span>}
              {!c.enabled && c.why_not && (
                <span className="block text-muted">
                  Not available: <Sentence text={c.why_not} />
                </span>
              )}
            </span>
          </label>
        ))}
      </fieldset>
      {choice !== undefined && (
        <Field
          label={choice.note === "required" ? "Your words (required)" : "Your words (optional)"}
          hint={choice.note_hint ?? "A reason an approver will read."}
          htmlFor={noteId}
        >
          <TextArea id={noteId} value={note} maxLength={NOTE_MAX} onChange={(e) => { setNote(e.target.value); setShown(false); }} />
        </Field>
      )}
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <Button {...guard.props} onClick={guard.press(() => setShown(true))}>
          Show what it would write
        </Button>
        {guard.hint}
      </div>
      {shown && ready && (
        <section aria-label="What asking would write" className="flex flex-col gap-2 rounded-card border border-border bg-surface-2 p-3">
          <h4 className="m-0 text-sm font-semibold">What asking for this closure binds</h4>
          {preview.isPending && <Loading what="the preview" />}
          {preview.isError && <Problem error={preview.error} what="The preview" onRetry={() => void preview.refetch()} />}
          {preview.data && (
            <>
              <p className="m-0 text-sm">
                <Sentence text={preview.data.words} /> It binds version {preview.data.bound_version} of the case and
                needs {preview.data.approvers === 2 ? "two different people" : "one approver"}.
              </p>
              <WritesView payload={preview.data.payload} hash={preview.data.payload_hash} />
              <div>
                <Button variant="primary" onClick={() => setOpen(true)}>
                  Ask for this closure
                </Button>
              </div>
            </>
          )}
        </section>
      )}
      {preview.data && (
        <ConfirmDialog
          open={open}
          onOpenChange={(next) => {
            setOpen(next);
            if (!next) void changedCase(after.queries, detail.case.id);
          }}
          title={`Ask to close case ${detail.case.number}: ${reasonLabel(reason).toLowerCase()}`}
          description="Nothing is closed by this. An approver reads the same writes and decides; if the case or what these writes would be changed since you read them, nothing is saved."
          request={request}
          confirmLabel="Ask for the closure"
          finalFocus={afterSend.focus}
          onSent={() => {
            afterSend.sent();
            void after.finish(`Asked to close case ${detail.case.number} as ${reasonLabel(reason).toLowerCase()}. An approver decides; nothing is closed yet.`);
          }}
        />
      )}
    </div>
  );
}

// ------------------------------------------------------------------ merge

export function MergeForm({ detail, onDone, label = "Merge into case number", hint = "The other case takes this case's alert groups and indicators." }: Shared & { label?: string; hint?: string }) {
  const numberId = useId();
  const [text, setText] = useState("");
  const [shown, setShown] = useState(false);
  const [open, setOpen] = useState(false);
  const [note, setNote] = useState("");
  const after = useAfterChange(detail, onDone);
  const afterSend = useAfterSend();
  const digits = text.trim().replace(/^#/, "");
  const wanted = /^\d{1,9}$/.test(digits) ? Number(digits) : null;
  const found = useQuery({
    queryKey: ["case-by-number", wanted],
    queryFn: () => unwrap(listCases({ query: { view: "all", number: wanted ?? 1, limit: 1 } })),
    enabled: wanted !== null,
    staleTime: 0,
  });
  const target = found.data?.items[0];
  const own = target?.id === detail.case.id;
  const confirmed = detail.case.state !== "suspected";
  const refusal =
    target === undefined ? null : own ? "A case is not merged into itself." : target.state === "closed" ? "That case is closed; a case is merged into one that is not." : confirmed && target.state === "suspected" ? "An incident is merged into another incident, not into a possible one." : null;
  const ready = target !== undefined && refusal === null;
  const said = note.trim();
  const preview = useQuery({ ...mergePreviewOptions(detail.case.id, target?.id ?? "", detail.case.version), enabled: shown && ready && confirmed });
  const request = useMemo(
    () => ({
      method: "POST" as const,
      path: `/api/v1/cases/${detail.case.id}/merge`,
      body: {
        expected_version: detail.case.version,
        target_case_id: target?.id ?? "",
        ...(said !== "" ? { note: said } : {}),
        ...(confirmed ? { payload_hash: preview.data?.payload_hash ?? "" } : {}),
      },
    }),
    [detail.case.id, detail.case.version, target?.id, said, confirmed, preview.data?.payload_hash],
  );
  const sendable = ready && (!confirmed || preview.data !== undefined);
  const notReady = wanted === null ? "Type the number of the case to merge into." : target === undefined ? "There is no case with that number yet." : (refusal ?? "This merge cannot be asked for now.");
  const showGuard = useGuard(ready ? null : notReady);
  const askGuard = useGuard(sendable ? null : ready ? "Show what it would write first." : notReady);
  return (
    <div className="flex flex-col gap-3">
      <Field label={label} hint={hint} htmlFor={numberId}>
        <TextInput
          id={numberId}
          inputMode="numeric"
          value={text}
          onChange={(e) => {
            setText(e.target.value);
            setShown(false);
          }}
          className="max-w-40"
        />
      </Field>
      {wanted !== null && found.isPending && <Loading what="the case" />}
      {wanted !== null && found.isSuccess && target === undefined && <p className="m-0 text-sm text-muted">There is no case with that number.</p>}
      {target !== undefined && (
        <p className="m-0 text-sm">
          Case {target.number}: <UntrustedText value={target.title} limits={{ maxChars: 160, maxLines: 2 }} /> ({caseStateWord(target.state).toLowerCase()}).
          {refusal !== null && <span className="block text-muted">Not possible: {refusal}</span>}
        </p>
      )}
      <Field label="Your words (optional)" htmlFor={`${numberId}-note`}>
        <TextArea id={`${numberId}-note`} value={note} maxLength={NOTE_MAX} onChange={(e) => { setNote(e.target.value); setShown(false); }} />
      </Field>
      {confirmed ? (
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <Button {...showGuard.props} onClick={showGuard.press(() => setShown(true))}>
            Show what it would write
          </Button>
          {showGuard.hint}
        </div>
      ) : (
        <p className="m-0 text-sm text-muted">A possible incident is merged at once; there is no approval to ask for.</p>
      )}
      {shown && ready && confirmed && (
        <section aria-label="What asking would write" className="flex flex-col gap-2 rounded-card border border-border bg-surface-2 p-3">
          <h4 className="m-0 text-sm font-semibold">What asking for this merge binds</h4>
          {preview.isPending && <Loading what="the preview" />}
          {preview.isError && <Problem error={preview.error} what="The preview" onRetry={() => void preview.refetch()} />}
          {preview.data && (
            <>
              <p className="m-0 text-sm">
                <Sentence text={preview.data.words} />
              </p>
              <WritesView payload={preview.data.payload} hash={preview.data.payload_hash} />
            </>
          )}
        </section>
      )}
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <Button variant="primary" {...askGuard.props} onClick={askGuard.press(() => setOpen(true))}>
          {confirmed ? "Ask for this merge" : "Review the merge"}
        </Button>
        {askGuard.hint}
      </div>
      {sendable && target !== undefined && (
        <ConfirmDialog
          open={open}
          onOpenChange={(next) => {
            setOpen(next);
            if (!next) void changedCase(after.queries, detail.case.id);
          }}
          title={`${confirmed ? "Ask to merge" : "Merge"} case ${detail.case.number} into case ${target.number}`}
          description={confirmed ? "Nothing is merged by this. An approver reads the same writes and decides." : "This possible incident is closed as a duplicate now, and its alert groups move to the other case."}
          request={request}
          confirmLabel={confirmed ? "Ask for the merge" : "Merge now"}
          finalFocus={afterSend.focus}
          onSent={(sent) => {
            afterSend.sent();
            const result = (sent.data as CaseChanged | undefined)?.result;
            void after.finish(
              result === "merged" ? `Case ${detail.case.number} was merged into case ${target.number}.` : `Asked to merge case ${detail.case.number} into case ${target.number}. An approver decides; nothing is merged yet.`,
            );
          }}
        />
      )}
    </div>
  );
}

// ------------------------------------------------------------------ the list of actions

function Row({ a, active, onOpen, children }: { a: CaseActionStateOut; active: boolean; onOpen: () => void; children?: ReactNode }) {
  const why = useId();
  return (
    <li className="flex flex-col gap-2 border-b border-border py-2 last:border-b-0">
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <Button variant={a.enabled ? "secondary" : "ghost"} aria-disabled={!a.enabled} aria-expanded={a.enabled ? active : undefined} aria-describedby={a.enabled ? undefined : why} onClick={() => a.enabled && onOpen()}>
          {a.label}
        </Button>
        {!a.enabled && a.why_not && (
          <p id={why} className="m-0 max-w-prose text-sm text-muted">
            <span className="font-medium">Not available: </span>
            <Sentence text={a.why_not} />
          </p>
        )}
      </div>
      {active && a.enabled && <div className="rounded-card border border-border bg-surface-2 p-3">{children}</div>}
    </li>
  );
}

/** The form of one action (the decision bar's More menu opens one at a time), or null. */
export function ActionForm({ detail, action, onDone }: { detail: CaseDetail; action: string; onDone: () => void }) {
  const done = onDone;
  // a fresh form after the case changes: nothing typed for one version is sent for the next
  const key = `${detail.case.id}:${detail.case.version}`;
  const forms: Record<string, ReactNode> = {
    take: <Plain key={key} detail={detail} onDone={done} action="take" title={`Take case ${detail.case.number}`} say={`You took case ${detail.case.number}.`} label="Take" />,
    assign: <Assign key={key} detail={detail} onDone={done} />,
    release: <Plain key={key} detail={detail} onDone={done} action="release" title={`Release case ${detail.case.number}`} say={`Released case ${detail.case.number}; it is open again.`} label="Release" />,
    contain: (
      <Words
        key={key}
        detail={detail}
        onDone={done}
        action="contain"
        field="attestation"
        label="Why it is contained"
        hint="Your statement; it is kept as yours."
        title={`Confirm case ${detail.case.number} is contained`}
        say={`Case ${detail.case.number} is contained.`}
        confirmLabel="Confirm contained"
      />
    ),
    request_closure: <ClosureForm key={key} detail={detail} onDone={done} />,
    merge: <MergeForm key={key} detail={detail} onDone={done} />,
    reopen: (
      <Words
        key={key}
        detail={detail}
        onDone={done}
        action="reopen"
        field="reason"
        label="Why it is reopened"
        hint="A reason the next person will read."
        title={`Reopen case ${detail.case.number}`}
        say={`Reopened case ${detail.case.number}.`}
        confirmLabel="Reopen"
      />
    ),
  };
  return forms[action] ?? null;
}

/**
 * What a person can do with the case: Take, Assign, Release, Confirm contained, Request closure,
 * Merge, Reopen. Each says why when it is unavailable (the server's own answer, the refusal the
 * command would give). Each change shows its exact request in the confirm dialog first, and
 * names the version of the case the person looked at.
 */
export function CaseActions({ detail }: { detail: CaseDetail }) {
  const [active, setActive] = useState<string | null>(null);
  const toggle = (action: string) => setActive((now) => (now === action ? null : action));
  const done = () => setActive(null);
  if (detail.decision) {
    // a possible incident: its decision is the bar at the top; nothing below applies before it
    return (
      <section aria-label="Actions" id="actions" className="flex flex-col gap-2">
        <h2 className="m-0 text-lg font-semibold">What you can do</h2>
        <p className="m-0 max-w-prose text-sm text-muted" data-testid="after-confirm">
          <Sentence text={detail.decision.after} /> Decide it with <a href="#decision">the decision at the top of the page</a>.
        </p>
      </section>
    );
  }
  return (
    <section aria-label="Actions" id="actions" className="flex flex-col gap-2">
      <h2 className="m-0 text-lg font-semibold">What you can do</h2>
      <p className="m-0 max-w-prose text-sm text-muted">
        Every change names the version of the case you are looking at (version {detail.case.version}): if anyone changed it first, nothing is saved. A closure
        or a merge is only asked for here; an approver decides it in{" "}
        <Link to="/approvals">Approvals</Link>.
      </p>
      <ul className="m-0 list-none p-0">
        {detail.actions.map((a) => (
          <Row key={a.action} a={a} active={active === a.action} onOpen={() => toggle(a.action)}>
            <ActionForm detail={detail} action={a.action} onDone={done} />
          </Row>
        ))}
      </ul>
    </section>
  );
}
