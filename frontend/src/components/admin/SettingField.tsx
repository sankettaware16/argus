import { useId, type ReactNode } from "react";
import type { SettingOut } from "../../client/types.gen";
import { DURATION_HELP, durationWords, entryList, parseDuration, RISK_NOTE, SETTING_HINTS, splitHelp, valueWords, type Draft } from "../../lib/settings";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Check, Select, TextInput } from "../ui/field";

/** The control a setting's kind calls for. */
export function Control({ setting, id, draft, onChange, disabled, describedBy }: { setting: SettingOut; id: string; draft: Draft; onChange: (draft: Draft) => void; disabled: boolean; describedBy?: string }) {
  const s = setting;
  const common = { id, disabled, "aria-describedby": describedBy };
  switch (s.kind) {
    case "bool":
      return (
        <Check {...common} checked={draft === true} onChange={(e) => onChange(e.target.checked)}>
          {draft === true ? "On" : "Off"}
        </Check>
      );
    case "int":
    case "float":
      return <TextInput {...common} type="number" inputMode={s.kind === "int" ? "numeric" : "decimal"} step={s.kind === "int" ? 1 : "any"} min={s.minimum ?? undefined} max={s.maximum ?? undefined} value={String(draft)} onChange={(e) => onChange(e.target.value)} className="max-w-48" />;
    case "choice":
      return (
        <Select {...common} value={String(draft)} onChange={(e) => onChange(e.target.value)} className="max-w-72">
          {s.optional && <option value="">Not set</option>}
          {s.choices.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </Select>
      );
    case "date":
      return <TextInput {...common} type="date" value={String(draft)} onChange={(e) => onChange(e.target.value)} className="max-w-48" />;
    case "duration": {
      const seconds = typeof draft === "string" ? parseDuration(draft) : null;
      return (
        <span className="flex flex-wrap items-center gap-2">
          <TextInput {...common} value={String(draft)} placeholder="5d" onChange={(e) => onChange(e.target.value)} className="max-w-32" />
          <span className="text-sm text-muted">{seconds !== null ? durationWords(seconds) : DURATION_HELP}</span>
        </span>
      );
    }
    case "list":
      if (entryList(s)) return <EntryList setting={s} id={id} />;
      return <ListEditor id={id} label={s.label} items={Array.isArray(draft) ? draft : []} onChange={onChange} disabled={disabled} />;
    case "secret":
      return (
        <span className="flex flex-wrap items-center gap-2">
          <Badge tone={s.is_set ? "ok" : "neutral"} data-testid="secret-state">
            {s.is_set ? "Set" : "Not set"}
          </Badge>
          <TextInput {...common} type="password" autoComplete="new-password" spellCheck={false} placeholder={s.is_set ? "Type a new key to replace it" : "Type the key"} value={String(draft)} onChange={(e) => onChange(e.target.value)} className="max-w-md" />
        </span>
      );
    default:
      return <TextInput {...common} value={String(draft)} onChange={(e) => onChange(e.target.value)} className={s.kind === "path" ? "max-w-xl font-mono" : "max-w-xl"} />;
  }
}

/** A list of entries, each in one line; it is changed in the files, not here. */
function EntryList({ setting, id }: { setting: SettingOut; id: string }) {
  const items = Array.isArray(setting.value) ? setting.value : [];
  return (
    <div className="flex max-w-3xl flex-col gap-1" id={id} data-testid="entry-list">
      <ul className="m-0 flex list-none flex-col gap-1 p-0">
        {items.map((item, i) => (
          <li key={i} className="rounded-control border border-border bg-surface-2 px-2 py-1 font-mono text-xs break-all">
            {typeof item === "object" && item !== null ? JSON.stringify(item) : String(item)}
          </li>
        ))}
      </ul>
      <p className="m-0 text-sm text-muted">A list of entries: change it in the files (site.yaml or local.yaml).</p>
    </div>
  );
}

export function ListEditor({ id, label, items, onChange, disabled }: { id: string; label: string; items: string[]; onChange: (draft: Draft) => void; disabled: boolean }) {
  const rows = items.length === 0 ? [] : items;
  return (
    <div className="flex max-w-xl flex-col gap-1.5" role="group" aria-label={label}>
      {rows.length === 0 && <p className="m-0 text-sm text-muted">Empty.</p>}
      {rows.map((item, i) => (
        <div key={i} className="flex gap-1.5">
          <TextInput id={i === 0 ? id : undefined} aria-label={`${label}, item ${i + 1}`} value={item} disabled={disabled} onChange={(e) => onChange(rows.map((x, j) => (j === i ? e.target.value : x)))} />
          <Button size="sm" disabled={disabled} aria-label={`Remove item ${i + 1} of ${label}`} onClick={() => onChange(rows.filter((_, j) => j !== i))}>
            Remove
          </Button>
        </div>
      ))}
      <div>
        <Button size="sm" disabled={disabled} onClick={() => onChange([...rows, ""])}>
          Add an item
        </Button>
      </div>
    </div>
  );
}

/** Help text with its ``names`` (as the settings' docs write them) shown as code. */
export function withCode(text: string): ReactNode[] {
  return text.split(/``([^`]+)``/).map((part, i) => (i % 2 === 1 ? <code key={i} className="font-mono text-[0.92em]">{part}</code> : part));
}

/** One setting: what it is, its help, its control, where it is set, and the risk of changing it. */
export function SettingField({ setting, draft, onChange, error, reset, onReset }: { setting: SettingOut; draft: Draft; onChange: (draft: Draft) => void; error?: string; reset: boolean; onReset: (on: boolean) => void }) {
  const s = setting;
  const id = useId();
  const { short, more } = splitHelp(s.help);
  const note = RISK_NOTE[s.risk];
  const canReset = s.in_app && s.kind !== "secret" && s.editable && !entryList(s);
  return (
    <div className="flex flex-col gap-1.5 border-b border-border py-3 last:border-b-0" data-testid={`setting-${s.key}`}>
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <label htmlFor={id} className="text-sm font-semibold">
          {s.label}
        </label>
        {s.in_app && <Badge tone="info">Changed in the app</Badge>}
        {note && <Badge tone={s.risk === "siem_write" ? "warn" : "neutral"}>{s.risk === "siem_write" ? "Writes to the SIEM" : "Needs your password"}</Badge>}
      </div>
      {short !== "" && <p className="m-0 max-w-prose text-sm text-muted">{withCode(short)}</p>}
      {SETTING_HINTS[s.key] && (
        <p className="m-0 max-w-prose rounded-control bg-info-soft px-2 py-1 text-sm text-info" data-testid="setting-hint">
          {SETTING_HINTS[s.key]}
        </p>
      )}
      {more && (
        <details className="text-sm text-muted">
          <summary className="cursor-pointer">More</summary>
          <p className="m-0 mt-1 max-w-prose">{withCode(more)}</p>
        </details>
      )}
      {reset ? (
        <p className="m-0 text-sm" data-testid="reset-note">
          Will go back to the file&apos;s value when you save.{" "}
          <Button size="sm" variant="ghost" onClick={() => onReset(false)}>
            Keep it
          </Button>
        </p>
      ) : (
        <>
          <Control setting={s} id={id} draft={draft} onChange={onChange} disabled={!s.editable} describedBy={error ? `${id}-err` : undefined} />
          {!s.editable && (
            <p className="m-0 text-sm text-muted">
              Set in the files (argus.yaml / local.yaml). Now: {valueWords(s)}. It is not changed here.
            </p>
          )}
        </>
      )}
      {error && (
        <p id={`${id}-err`} role="alert" className="m-0 text-sm text-danger">
          {error}
        </p>
      )}
      <div className="flex flex-wrap items-center gap-x-3 text-xs text-muted">
        <span>
          {s.key}
          {s.homes.length > 0 && <> · {s.homes.join(", ")}</>}
        </span>
        {canReset && !reset && (
          <Button size="sm" variant="ghost" onClick={() => onReset(true)}>
            Back to the file&apos;s value
          </Button>
        )}
      </div>
    </div>
  );
}
