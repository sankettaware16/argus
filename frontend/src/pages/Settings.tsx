// Settings (D-327): every setting ARGUS lets an administrator change, as a form made from the
// setting's own type. A save is rows for argus-admin, which checks them again, writes the files,
// restarts what reads them and says what happened; this page shows that outcome as it arrives.
// D-328: the connection checks of the SIEM and Kibana keys, an asset map's upload and the history.
import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import type { SectionOut, SettingChangeOut } from "../client/types.gen";
import { AdminOnly, Notice, StepUpNote } from "../components/admin/common";
import { AssetUpload, CheckButton } from "../components/admin/jobs";
import { SaveBar, SaveOutcome, SiemWriteGate, stateTone, useSettingsSave } from "../components/admin/save";
import { SettingField } from "../components/admin/SettingField";
import { Loading, Problem } from "../components/Problem";
import { Time } from "../components/Time";
import { Badge } from "../components/ui/badge";
import { Card, CardTitle } from "../components/ui/card";
import { TextInput } from "../components/ui/field";
import { aiOptions } from "../lib/ai";
import { historyOptions, settingsOptions } from "../lib/admin";
import { cn } from "../lib/cn";
import { buildChanges, outcomeWords, searchSettings, toDraft } from "../lib/settings";

const HISTORY = "history";
const REFRESH = [settingsOptions.queryKey, historyOptions.queryKey, aiOptions.queryKey];
const ASSET_REFRESH = [settingsOptions.queryKey];

/** The connection checks a section offers (argus-admin runs them; nothing is changed). */
export const SECTION_CHECKS: Record<string, { target: string; label: string }[]> = {
  siem: [{ target: "siem", label: "Check the connection" }],
  kibana: [
    { target: "kibana:reader", label: "Check the read-only key" },
    { target: "kibana:cases", label: "Check the cases key" },
    { target: "kibana:alerts", label: "Check the alerts key" },
  ],
  outside: [
    { target: "outside:virustotal", label: "Test VirusTotal" },
    { target: "outside:shodan", label: "Test Shodan" },
    { target: "outside:censys", label: "Test Censys" },
  ],
};

/** The setting's label for a key, from every loaded section (the key itself when it is unknown). */
export function labelsOf(sections: readonly SectionOut[]): Map<string, string> {
  return new Map(sections.flatMap((s) => s.settings.map((x) => [x.key, x.label] as const)));
}

function History({ labels }: { labels: ReadonlyMap<string, string> }) {
  const history = useQuery(historyOptions);
  return (
    <Card aria-label="History" data-testid="history">
      <CardTitle>History</CardTitle>
      <p className="m-0 mb-2 max-w-prose text-sm text-muted">The last fifty changes saved in the app, newest first: when, who, which setting and what became of it.</p>
      {history.isPending && <Loading what="the history" />}
      {history.isError && <Problem error={history.error} what="The history" onRetry={() => void history.refetch()} />}
      {history.data && history.data.changes.length === 0 && <p className="m-0 text-sm text-muted">No setting has been changed in the app yet.</p>}
      {history.data && history.data.changes.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-sm" aria-label="The last fifty changes">
            <thead>
              <tr className="border-b border-border text-left text-xs text-muted">
                <th className="py-1.5 pr-3 font-medium">When</th>
                <th className="py-1.5 pr-3 font-medium">Who</th>
                <th className="py-1.5 pr-3 font-medium">Setting</th>
                <th className="py-1.5 pr-3 font-medium">State</th>
                <th className="py-1.5 font-medium">Outcome</th>
              </tr>
            </thead>
            <tbody>
              {history.data.changes.map((c: SettingChangeOut) => (
                <tr key={c.id} className="border-b border-border align-top last:border-b-0">
                  <td className="py-1.5 pr-3 whitespace-nowrap">
                    <Time value={c.created_at} />
                  </td>
                  <td className="py-1.5 pr-3">{c.by}</td>
                  <td className="py-1.5 pr-3">{labels.get(c.key) ?? c.key}</td>
                  <td className="py-1.5 pr-3">
                    <Badge tone={stateTone(c.state)}>{c.state.replace("_", " ")}</Badge>
                  </td>
                  <td className="py-1.5 text-muted">{outcomeWords(c)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

function SettingsView({ section: asked }: { section?: string }) {
  const data = useQuery(settingsOptions);
  const [picked, setPicked] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const state = useSettingsSave(REFRESH);

  const sections = data.data?.sections;
  const want = picked ?? asked ?? null;
  const showHistory = want === HISTORY;
  const section = sections?.find((s) => s.key === want) ?? sections?.[0];
  const searching = query.trim() !== "";
  const groups = useMemo(() => (sections === undefined || (showHistory && !searching) ? [] : searching ? searchSettings(sections, query) : section ? [{ section, settings: section.settings }] : []), [sections, section, query, searching, showHistory]);
  const shown = useMemo(() => groups.flatMap((g) => g.settings), [groups]);
  const built = useMemo(() => buildChanges(shown, state.drafts, state.resets), [shown, state.drafts, state.resets]);
  const dirtyBySection = useMemo(() => new Map((sections ?? []).map((s) => [s.key, buildChanges(s.settings, state.drafts, state.resets).changes.length])), [sections, state.drafts, state.resets]);
  const labels = useMemo(() => labelsOf(sections ?? []), [sections]);

  if (data.isPending) return <Loading what="the settings" />;
  if (data.isError) return <Problem error={data.error} what="The settings" onRetry={() => void data.refetch()} />;
  const out = data.data;
  const navButton = (key: string, label: string, about: string, current: boolean, dirty: number) => (
    <li key={key}>
      <button
        type="button"
        aria-current={current ? "true" : undefined}
        onClick={() => {
          setPicked(key);
          setQuery("");
        }}
        className={cn("flex w-full cursor-pointer flex-col items-start rounded-control border-0 bg-transparent px-3 py-2 text-left text-sm text-text hover:bg-surface", current && "bg-surface")}
      >
        <span className={cn("flex w-full items-center justify-between gap-2", current && "font-semibold")}>
          {label}
          {dirty > 0 && <Badge tone="warn">{dirty} unsaved</Badge>}
        </span>
        <span className="text-xs text-muted">{about}</span>
      </button>
    </li>
  );

  return (
    <>
      <div className="flex flex-col gap-1">
        <h1 className="page-h">Settings</h1>
        <p className="page-sub">Change how ARGUS works. A change is checked again, written to the right file and applied by argus-admin; the result shows here within a few seconds.</p>
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
      <SaveOutcome state={state} labels={labels} />
      <div className="flex flex-wrap items-center gap-2">
        <label htmlFor="settings-search" className="sr-only">
          Search the settings
        </label>
        <TextInput id="settings-search" type="search" value={query} placeholder="Search the settings by name or help" onChange={(e) => setQuery(e.target.value)} className="max-w-md" data-search-box="page" />
      </div>
      <div className="grid gap-4 md:grid-cols-[16rem_1fr]">
        <nav aria-label="Settings sections">
          <ul className="m-0 flex list-none flex-col gap-0.5 p-0">
            {out.sections.map((s) => navButton(s.key, s.label, s.about, !searching && !showHistory && section?.key === s.key, dirtyBySection.get(s.key) ?? 0))}
            {navButton(HISTORY, "History", "The last fifty changes and what became of them", !searching && showHistory, 0)}
          </ul>
        </nav>
        <div className="flex min-w-0 flex-col gap-3">
          {showHistory && !searching ? (
            <History labels={labels} />
          ) : (
            <>
              {groups.length === 0 && <p className="m-0 text-sm text-muted">No setting matches that search.</p>}
              {groups.map((g) => (
                <Card key={g.section.key} aria-label={g.section.label}>
                  <CardTitle>{g.section.label}</CardTitle>
                  <p className="m-0 mb-1 max-w-prose text-sm text-muted">{g.section.about}</p>
                  {g.settings.map((s) => (
                    <SettingField key={s.key} setting={s} draft={state.drafts[s.key] ?? toDraft(s)} onChange={(d) => state.edit(s.key, d)} error={state.errors[s.key]} reset={state.resets.has(s.key)} onReset={(on) => state.reset(s.key, on)} />
                  ))}
                  {!searching && (SECTION_CHECKS[g.section.key] ?? []).length > 0 && (
                    <div className="flex flex-col gap-2 border-t border-border pt-3" data-testid={`checks-${g.section.key}`}>
                      <p className="m-0 text-sm text-muted">Check that ARGUS can reach it with the keys saved here. argus-admin runs the check; nothing is changed.</p>
                      {(SECTION_CHECKS[g.section.key] ?? []).map((c) => (
                        <CheckButton key={c.target} target={c.target} label={c.label} />
                      ))}
                    </div>
                  )}
                  {!searching && g.section.key === "assets" && <AssetUpload refresh={ASSET_REFRESH} />}
                </Card>
              ))}
              <SaveBar state={state} built={built} onSave={() => state.press(shown, built)} />
            </>
          )}
        </div>
      </div>
      <SiemWriteGate state={state} words={out.confirm_words} />
    </>
  );
}

export function Settings({ section }: { section?: string }) {
  return (
    <AdminOnly what="Settings">
      <SettingsView section={section} />
    </AdminOnly>
  );
}
