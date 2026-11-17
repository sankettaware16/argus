// A setting as a compact row (the AI and threat-intel pages): its label, control, refusal and the
// way back to the file's value. A list chosen from fixed choices (a task's providers) is ordered.
import { useId } from "react";
import type { SettingOut } from "../../client/types.gen";
import { toDraft, type Draft } from "../../lib/settings";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Select } from "../ui/field";
import type { SettingsSave } from "./save";
import { Control } from "./SettingField";

/** A task's providers in order, chosen from the providers ARGUS has; none means all of them. */
export function ProviderOrder({ id, label, items, choices, onChange, disabled }: { id: string; label: string; items: string[]; choices: readonly string[]; onChange: (d: Draft) => void; disabled: boolean }) {
  const left = choices.filter((c) => !items.includes(c));
  const move = (i: number, by: number) => {
    const next = [...items];
    const [x] = next.splice(i, 1);
    if (x !== undefined) next.splice(i + by, 0, x);
    onChange(next);
  };
  return (
    <div className="flex flex-col gap-1.5" role="group" aria-label={label}>
      {items.length === 0 ? (
        <p className="m-0 text-sm text-muted">All providers, in the files&apos; order.</p>
      ) : (
        <ol className="m-0 flex list-none flex-col gap-1 p-0">
          {items.map((p, i) => (
            <li key={p} className="flex flex-wrap items-center gap-1.5 text-sm">
              <span className="min-w-6 text-muted">{i + 1}.</span>
              <span className="min-w-24 font-medium">{p}</span>
              <Button size="sm" variant="ghost" disabled={disabled || i === 0} aria-label={`Move ${p} up`} onClick={() => move(i, -1)}>
                Up
              </Button>
              <Button size="sm" variant="ghost" disabled={disabled || i === items.length - 1} aria-label={`Move ${p} down`} onClick={() => move(i, 1)}>
                Down
              </Button>
              <Button size="sm" variant="ghost" disabled={disabled} aria-label={`Remove ${p}`} onClick={() => onChange(items.filter((x) => x !== p))}>
                Remove
              </Button>
            </li>
          ))}
        </ol>
      )}
      {left.length > 0 && (
        <Select
          id={id}
          aria-label={`Add a provider to ${label}`}
          value=""
          disabled={disabled}
          onChange={(e) => {
            if (e.target.value !== "") onChange([...items, e.target.value]);
          }}
          className="max-w-56"
        >
          <option value="">Add a provider…</option>
          {left.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </Select>
      )}
    </div>
  );
}

/** One setting, compact: its label, control, refusal and the way back to the file's value. */
export function CompactField({ setting, label, hint, state }: { setting: SettingOut | undefined; label: string; hint?: string; state: SettingsSave }) {
  const id = useId();
  if (setting === undefined) return null;
  const s = setting;
  const reset = state.resets.has(s.key);
  const error = state.errors[s.key];
  const draft = state.drafts[s.key] ?? toDraft(s);
  return (
    <div className="flex flex-col gap-1" data-testid={`setting-${s.key}`}>
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <label htmlFor={id} className="text-sm font-medium">
          {label}
        </label>
        {s.in_app && <Badge tone="info">Changed in the app</Badge>}
        {s.risk === "sensitive" && <Badge>Needs your password</Badge>}
      </div>
      {hint && <p className="m-0 text-xs text-muted">{hint}</p>}
      {reset ? (
        <p className="m-0 text-sm" data-testid="reset-note">
          Will go back to the file&apos;s value when you save.{" "}
          <Button size="sm" variant="ghost" onClick={() => state.reset(s.key, false)}>
            Keep it
          </Button>
        </p>
      ) : s.kind === "list" && s.choices.length > 0 ? (
        <ProviderOrder id={id} label={label} items={Array.isArray(draft) ? draft : []} choices={s.choices} onChange={(d) => state.edit(s.key, d)} disabled={!s.editable} />
      ) : (
        <Control setting={s} id={id} draft={draft} onChange={(d) => state.edit(s.key, d)} disabled={!s.editable} describedBy={error ? `${id}-err` : undefined} />
      )}
      {error && (
        <p id={`${id}-err`} role="alert" className="m-0 text-sm text-danger">
          {error}
        </p>
      )}
      {s.in_app && s.kind !== "secret" && s.editable && !reset && (
        <div>
          <Button size="sm" variant="ghost" onClick={() => state.reset(s.key, true)}>
            Back to the file&apos;s value
          </Button>
        </div>
      )}
    </div>
  );
}

