// Settings (D-327): every setting ARGUS lets an administrator change, as a form made from the
// setting's own type. A save is rows for argus-admin, which checks them again, writes the files,
// restarts what reads them and says what happened; this page shows that outcome as it arrives.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState } from "react";
import { saveSettings } from "../client/sdk.gen";
import type { SectionOut, SettingChangesOut, SettingOut } from "../client/types.gen";
import { AdminOnly, Modal, Notice, StepUpLink, StepUpNote } from "../components/admin/common";
import { SettingField } from "../components/admin/SettingField";
import { Loading, Problem } from "../components/Problem";
import { Time } from "../components/Time";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Card, CardTitle } from "../components/ui/card";
import { TextInput } from "../components/ui/field";
import { allSettled, changesOptions, settingsOptions } from "../lib/admin";
import { unwrap } from "../lib/call";
import { cn } from "../lib/cn";
import { ApiError } from "../lib/session";
import { buildChanges, confirmOk, fieldFor, outcomeWords, RISK_NOTE, searchSettings, toDraft, type Draft } from "../lib/settings";

const PREFIX = "ARGUS did not accept that: ";

function Outcome({ data, sections }: { data: SettingChangesOut; sections: readonly SectionOut[] }) {
  const labels = new Map(sections.flatMap((s) => s.settings.map((x) => [x.key, x.label] as const)));
  const done = allSettled(data);
  return (
    <Card aria-label="What happened to your changes" data-testid="outcome">
      <CardTitle>{done ? "Your changes" : "Applying your changes…"}</CardTitle>
      <ul className="m-0 flex list-none flex-col gap-1.5 p-0 text-sm">
        {data.changes.map((c) => (
          <li key={c.id} className="flex flex-wrap items-baseline gap-x-2">
            <Badge tone={c.state === "applied" ? "ok" : c.state === "refused" || c.state === "rolled_back" ? "danger" : "neutral"}>{c.state.replace("_", " ")}</Badge>
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

function ConfirmSiemWrite({ open, onOpenChange, words, labels, busy, onSend }: { open: boolean; onOpenChange: (o: boolean) => void; words: string; labels: string[]; busy: boolean; onSend: (typed: string) => void }) {
  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title="Let ARGUS write to the SIEM?"
      description="This change lets ARGUS write to your SIEM (for example cases in Kibana, or changes to an alert). Until now it only read. It needs your password again, and you must type the words below."
    >
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

function SettingsView() {
  const queries = useQueryClient();
  const data = useQuery(settingsOptions);
  const [picked, setPicked] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [drafts, setDrafts] = useState<Record<string, Draft>>({});
  const [resets, setResets] = useState<ReadonlySet<string>>(new Set());
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [barError, setBarError] = useState<{ text: string; stepUp: boolean } | null>(null);
  const [batch, setBatch] = useState<string | null>(null);
  const [asking, setAsking] = useState(false);
  const changes = useQuery(changesOptions(batch));
  const refreshed = useRef<string | null>(null);

  useEffect(() => {
    if (batch !== null && allSettled(changes.data) && refreshed.current !== batch) {
      refreshed.current = batch;
      void queries.invalidateQueries({ queryKey: settingsOptions.queryKey });
    }
  }, [batch, changes.data, queries]);

  const sections = data.data?.sections;
  const section = sections?.find((s) => s.key === picked) ?? sections?.[0];
  const searching = query.trim() !== "";
  const groups = useMemo(() => (sections === undefined ? [] : searching ? searchSettings(sections, query) : section ? [{ section, settings: section.settings }] : []), [sections, section, query, searching]);
  const shown = useMemo(() => groups.flatMap((g) => g.settings), [groups]);
  const built = useMemo(() => buildChanges(shown, drafts, resets), [shown, drafts, resets]);
  const dirtyBySection = useMemo(() => new Map((sections ?? []).map((s) => [s.key, buildChanges(s.settings, drafts, resets).changes.length])), [sections, drafts, resets]);
  const [lastSent, setLastSent] = useState<SettingOut[]>([]);

  const save = useMutation({
    mutationFn: (v: { sent: ReturnType<typeof buildChanges>["changes"]; confirm?: string }) => unwrap(saveSettings({ body: { changes: v.sent, confirm: v.confirm } })),
    onSuccess: (out, v) => {
      setBatch(out.batch);
      const keys = new Set(v.sent.map((c) => c.key));
      setDrafts((d) => Object.fromEntries(Object.entries(d).filter(([k]) => !keys.has(k))));
      setResets((r) => new Set([...r].filter((k) => !keys.has(k))));
      setErrors({});
      setBarError(null);
      setAsking(false);
    },
    onError: (e: unknown) => {
      setAsking(false);
      const text = e instanceof ApiError ? e.message : "The change could not be saved.";
      if (e instanceof ApiError && e.code === "step_up_required") return setBarError({ text, stepUp: true });
      const field = e instanceof ApiError && e.status === 422 ? fieldFor(text.replace(PREFIX, ""), lastSent) : null;
      if (field !== null) setErrors({ [field]: text.replace(PREFIX, "") });
      else setBarError({ text, stepUp: false });
    },
  });

  if (data.isPending) return <Loading what="the settings" />;
  if (data.isError) return <Problem error={data.error} what="The settings" onRetry={() => void data.refetch()} />;
  const out = data.data;

  function press() {
    setErrors(built.errors);
    setBarError(null);
    if (Object.keys(built.errors).length > 0 || built.changes.length === 0) return;
    setLastSent(shown.filter((s) => built.changes.some((c) => c.key === s.key)));
    if (built.risk === "siem_write") setAsking(true);
    else save.mutate({ sent: built.changes });
  }

  const note = RISK_NOTE[built.risk];
  const nChanges = built.changes.length + Object.keys(built.errors).length;
  const savedLabels = lastSent.map((s) => s.label);
  return (
    <>
      <div className="flex flex-col gap-1">
        <h1 className="m-0 text-2xl font-semibold">Settings</h1>
        <p className="m-0 max-w-prose text-sm text-muted">Change how ARGUS works. A change is checked again, written to the right file and applied by argus-admin; the result shows here within a few seconds.</p>
      </div>
      {!out.applier.running && (
        <Notice tone="warn" testId="applier-down">
          argus-admin is not running: changes you save wait until it runs.
          {out.applier.last_seen && (
            <>
              {" "}
              Last seen <Time value={out.applier.last_seen} relative />.
            </>
          )}
        </Notice>
      )}
      {out.problem && (
        <Notice tone="danger" testId="settings-problem" role="alert">
          {out.problem}
        </Notice>
      )}
      <StepUpNote />
      {batch !== null && changes.data && <Outcome data={changes.data} sections={out.sections} />}
      {batch !== null && changes.isError && <Notice tone="warn">ARGUS could not be reached just now; looking again. A change may be restarting ARGUS.</Notice>}
      <div className="flex flex-wrap items-center gap-2">
        <label htmlFor="settings-search" className="sr-only">
          Search the settings
        </label>
        <TextInput id="settings-search" type="search" value={query} placeholder="Search the settings by name or help" onChange={(e) => setQuery(e.target.value)} className="max-w-md" data-search-box="page" />
      </div>
      <div className="grid gap-4 md:grid-cols-[16rem_1fr]">
        <nav aria-label="Settings sections">
          <ul className="m-0 flex list-none flex-col gap-0.5 p-0">
            {out.sections.map((s) => {
              const current = !searching && section?.key === s.key;
              const dirty = dirtyBySection.get(s.key) ?? 0;
              return (
                <li key={s.key}>
                  <button
                    type="button"
                    aria-current={current ? "true" : undefined}
                    onClick={() => {
                      setPicked(s.key);
                      setQuery("");
                    }}
                    className={cn("flex w-full cursor-pointer flex-col items-start rounded-control border-0 bg-transparent px-2 py-1.5 text-left text-sm text-text hover:bg-surface-3", current && "bg-accent-soft")}
                  >
                    <span className={cn("flex w-full items-center justify-between gap-2", current && "font-semibold")}>
                      {s.label}
                      {dirty > 0 && <Badge tone="warn">{dirty} unsaved</Badge>}
                    </span>
                    <span className="text-xs text-muted">{s.about}</span>
                  </button>
                </li>
              );
            })}
          </ul>
        </nav>
        <div className="flex min-w-0 flex-col gap-3">
          {groups.length === 0 && <p className="m-0 text-sm text-muted">No setting matches that search.</p>}
          {groups.map((g) => (
            <Card key={g.section.key} aria-label={g.section.label}>
              <CardTitle>{g.section.label}</CardTitle>
              <p className="m-0 mb-1 max-w-prose text-sm text-muted">{g.section.about}</p>
              {g.settings.map((s) => (
                <SettingField
                  key={s.key}
                  setting={s}
                  draft={drafts[s.key] ?? toDraft(s)}
                  onChange={(d) => {
                    setDrafts((old) => ({ ...old, [s.key]: d }));
                    setErrors((old) => Object.fromEntries(Object.entries(old).filter(([k]) => k !== s.key)));
                  }}
                  error={errors[s.key]}
                  reset={resets.has(s.key)}
                  onReset={(on) => setResets((old) => new Set(on ? [...old, s.key] : [...old].filter((k) => k !== s.key)))}
                />
              ))}
            </Card>
          ))}
          <div className="sticky bottom-2 flex flex-wrap items-center gap-3 rounded-card border border-border bg-surface px-3 py-2 shadow-card" data-testid="save-bar">
            <Button variant="primary" aria-disabled={nChanges === 0 || save.isPending} onClick={() => nChanges > 0 && !save.isPending && press()}>
              {save.isPending ? "Saving…" : nChanges === 0 ? "Save" : `Save ${nChanges} ${nChanges === 1 ? "change" : "changes"}`}
            </Button>
            <span className="text-sm text-muted">{nChanges === 0 ? "Nothing changed here yet." : (note ?? "Only what you changed is sent.")}</span>
            {barError && (
              <span role="alert" className="text-sm text-danger" data-testid="save-error">
                {barError.text} {barError.stepUp && <StepUpLink />}
              </span>
            )}
          </div>
        </div>
      </div>
      <ConfirmSiemWrite
        open={asking}
        onOpenChange={setAsking}
        words={out.confirm_words}
        labels={savedLabels}
        busy={save.isPending}
        onSend={(typed) => save.mutate({ sent: built.changes, confirm: typed })}
      />
    </>
  );
}

export function Settings() {
  return (
    <AdminOnly what="Settings">
      <SettingsView />
    </AdminOnly>
  );
}

