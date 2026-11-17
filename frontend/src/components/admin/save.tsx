// A save of settings (D-327), shared by Settings and "AI and agents": the drafts and resets the
// person made, the change set sent to /admin/changes, the step-up and SIEM-write gates, and the
// outcome argus-admin reports, read until every change is settled.
import { useMutation, useQuery, useQueryClient, type QueryKey } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { saveSettings } from "../../client/sdk.gen";
import type { SettingChangeIn, SettingChangesOut, SettingOut } from "../../client/types.gen";
import { allSettled, changesOptions } from "../../lib/admin";
import { unwrap } from "../../lib/call";
import { ApiError } from "../../lib/session";
import { confirmOk, fieldFor, outcomeWords, RISK_NOTE, type ChangeSet, type Draft } from "../../lib/settings";
import { Time } from "../Time";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Card, CardTitle } from "../ui/card";
import { TextInput } from "../ui/field";
import { Modal, Notice, StepUpLink } from "./common";

const PREFIX = "ARGUS did not accept that: ";

export function stateTone(state: SettingChangesOut["changes"][number]["state"]) {
  return state === "applied" ? "ok" : state === "refused" || state === "rolled_back" ? "danger" : "neutral";
}

export function Outcome({ data, labels }: { data: SettingChangesOut; labels: ReadonlyMap<string, string> }) {
  const done = allSettled(data);
  return (
    <Card aria-label="What happened to your changes" data-testid="outcome">
      <CardTitle>{done ? "Your changes" : "Applying your changes…"}</CardTitle>
      <ul className="m-0 flex list-none flex-col gap-1.5 p-0 text-sm">
        {data.changes.map((c) => (
          <li key={c.id} className="flex flex-wrap items-baseline gap-x-2">
            <Badge tone={stateTone(c.state)}>{c.state.replace("_", " ")}</Badge>
            <strong>{labels.get(c.key) ?? c.key}</strong>
            <span className="text-muted">{outcomeWords(c)}</span>
            {c.finished_at && (
              <span className="text-xs text-muted">
                <Time value={c.finished_at} />
              </span>
            )}
          </li>
        ))}
      </ul>
    </Card>
  );
}

const SIEM_WRITE_WORDS = "This change lets ARGUS write to your SIEM (for example cases in Kibana, or changes to an alert). Until now it only read. It needs your password again, and you must type the words below.";

export function ConfirmSiemWrite({ open, onOpenChange, words, labels, busy, onSend, description = SIEM_WRITE_WORDS }: { open: boolean; onOpenChange: (o: boolean) => void; words: string; labels: string[]; busy: boolean; onSend: (typed: string) => void; description?: string }) {
  return (
    <Modal open={open} onOpenChange={onOpenChange} title="Let ARGUS write to the SIEM?" description={description}>
      <SiemWriteForm words={words} labels={labels} busy={busy} onCancel={() => onOpenChange(false)} onSend={onSend} />
    </Modal>
  );
}

/** Mounted only while the dialog is open, so what was typed is forgotten when it closes. */
function SiemWriteForm({ words, labels, busy, onCancel, onSend }: { words: string; labels: string[]; busy: boolean; onCancel: () => void; onSend: (typed: string) => void }) {
  const [typed, setTyped] = useState("");
  const ok = confirmOk(typed, words);
  return (
    <>
      <ul className="m-0 pl-5 text-sm">
        {labels.map((l) => (
          <li key={l}>{l}</li>
        ))}
      </ul>
      <form
        className="flex flex-col gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          if (ok && !busy) onSend(typed);
        }}
      >
        <label htmlFor="confirm-words" className="text-sm font-medium">
          Type <q data-testid="confirm-words">{words}</q> to go on
        </label>
        <TextInput id="confirm-words" value={typed} autoComplete="off" onChange={(e) => setTyped(e.target.value)} />
        <div className="flex justify-end gap-2">
          <Button onClick={onCancel}>Cancel</Button>
          <Button type="submit" variant="danger" aria-disabled={!ok || busy} disabled={!ok || busy}>
            {busy ? "Saving…" : "Save the change"}
          </Button>
        </div>
      </form>
    </>
  );
}

type Sent = { sent: SettingChangeIn[]; among: SettingOut[]; confirm?: string };

/**
 * The state of one page's save: what was edited, what was refused at which field, the batch sent
 * and its changes as argus-admin reports them. When the batch is settled, `refresh` is read again.
 */
export function useSettingsSave(refresh: readonly QueryKey[]) {
  const queries = useQueryClient();
  const [drafts, setDrafts] = useState<Record<string, Draft>>({});
  const [resets, setResets] = useState<ReadonlySet<string>>(new Set());
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [barError, setBarError] = useState<{ text: string; stepUp: boolean } | null>(null);
  const [batch, setBatch] = useState<string | null>(null);
  const [asking, setAsking] = useState<{ sent: SettingChangeIn[]; among: SettingOut[] } | null>(null);
  const changes = useQuery(changesOptions(batch));
  const refreshed = useRef<string | null>(null);
  const keys = useRef(refresh);
  useEffect(() => {
    keys.current = refresh;
  });

  useEffect(() => {
    if (batch !== null && allSettled(changes.data) && refreshed.current !== batch) {
      refreshed.current = batch;
      for (const key of keys.current) void queries.invalidateQueries({ queryKey: key });
    }
  }, [batch, changes.data, queries]);

  const last = useRef<Sent | null>(null);
  const save = useMutation({
    mutationFn: (v: Sent) => {
      last.current = v;
      return unwrap(saveSettings({ body: { changes: v.sent, confirm: v.confirm } }));
    },
    onSuccess: (out, v) => {
      setBatch(out.batch);
      const sent = new Set(v.sent.map((c) => c.key));
      setDrafts((d) => Object.fromEntries(Object.entries(d).filter(([k]) => !sent.has(k))));
      setResets((r) => new Set([...r].filter((k) => !sent.has(k))));
      setErrors({});
      setBarError(null);
      setAsking(null);
    },
    onError: (e: unknown, v) => {
      setAsking(null);
      const text = e instanceof ApiError ? e.message : "The change could not be saved.";
      if (e instanceof ApiError && e.code === "step_up_required") return setBarError({ text, stepUp: true });
      const field = e instanceof ApiError && e.status === 422 ? fieldFor(text.replace(PREFIX, ""), v.among) : null;
      if (field !== null) setErrors({ [field]: text.replace(PREFIX, "") });
      else setBarError({ text, stepUp: false });
    },
  });

  return {
    drafts,
    resets,
    errors,
    barError,
    batch,
    changes,
    save,
    asking,
    edit(key: string, draft: Draft) {
      setDrafts((old) => ({ ...old, [key]: draft }));
      setErrors((old) => Object.fromEntries(Object.entries(old).filter(([k]) => k !== key)));
    },
    reset(key: string, on: boolean) {
      setResets((old) => new Set(on ? [...old, key] : [...old].filter((k) => k !== key)));
    },
    /** Send `built` (made from `scope`), or show what is wrong with it; a SIEM write asks first. */
    press(scope: readonly SettingOut[], built: ChangeSet) {
      setErrors(built.errors);
      setBarError(null);
      if (Object.keys(built.errors).length > 0 || built.changes.length === 0) return;
      const among = scope.filter((s) => built.changes.some((c) => c.key === s.key));
      if (built.risk === "siem_write") setAsking({ sent: built.changes, among });
      else save.mutate({ sent: built.changes, among });
    },
    cancelAsking() {
      setAsking(null);
    },
    /** The save that was refused for the password, sent again once it is confirmed. */
    retry() {
      if (last.current !== null && !save.isPending) save.mutate(last.current);
    },
  };
}

export type SettingsSave = ReturnType<typeof useSettingsSave>;

/** What happened to the last save, and a note while ARGUS cannot be reached (it may be restarting). */
export function SaveOutcome({ state, labels }: { state: SettingsSave; labels: ReadonlyMap<string, string> }) {
  if (state.batch === null) return null;
  return (
    <>
      {state.changes.data && <Outcome data={state.changes.data} labels={labels} />}
      {state.changes.isError && <Notice tone="warn">ARGUS could not be reached just now; looking again. A change may be restarting ARGUS.</Notice>}
    </>
  );
}

/** The sticky bar with the save button, what a save needs, and why the last one was refused. */
export function SaveBar({ state, built, onSave }: { state: SettingsSave; built: ChangeSet; onSave: () => void }) {
  const n = built.changes.length + Object.keys(built.errors).length;
  const busy = state.save.isPending;
  const note = RISK_NOTE[built.risk];
  return (
    <div className="sticky bottom-2 flex flex-wrap items-center gap-3 rounded-card border border-border bg-surface px-3 py-2 shadow-card" data-testid="save-bar">
      <Button variant="primary" aria-disabled={n === 0 || busy} onClick={() => n > 0 && !busy && onSave()}>
        {busy ? "Saving…" : n === 0 ? "Save" : `Save ${n} ${n === 1 ? "change" : "changes"}`}
      </Button>
      <span className="text-sm text-muted">{n === 0 ? "Nothing changed here yet." : (note ?? "Only what you changed is sent.")}</span>
      {state.barError && (
        <span role="alert" className="text-sm text-danger" data-testid="save-error">
          {state.barError.text} {state.barError.stepUp && <StepUpLink onConfirmed={state.retry} />}
        </span>
      )}
    </div>
  );
}

/** The typed-words dialog of a change that lets ARGUS write to the SIEM. */
export function SiemWriteGate({ state, words }: { state: SettingsSave; words: string }) {
  const asking = state.asking;
  return (
    <ConfirmSiemWrite
      open={asking !== null}
      onOpenChange={(o) => !o && state.cancelAsking()}
      words={words}
      labels={(asking?.among ?? []).map((s) => s.label)}
      busy={state.save.isPending}
      onSend={(typed) => asking && state.save.mutate({ ...asking, confirm: typed })}
    />
  );
}
