/**
 * The small parts every card, row, pane and Overview shares (docs/p4f-ui-spec.md §12): the priority
 * badge (the band differs in style as well as colour: solid, bordered, soft, text only), the
 * certainty word (plain bold text, no colour), the activity line ("Still active" is plain text,
 * not a badge), the changed strip and the entity chip (its noun from `nounFor`: an outside
 * address is never a "Device").
 */
import { createContext, useContext, type ReactNode } from "react";
import { cn } from "../../lib/cn";
import { nounFor, priorityTip, type Band, type Engine, type EngineObject, type Shown } from "../../lib/engine";
import { parse } from "../../lib/time";
import { UntrustedText } from "../UntrustedText";
import { dayAndTime, shortDay } from "../../lib/when";

const BAND_STYLE: Record<Band, string> = {
  P1: "bg-critical text-accent-fg border-critical font-bold",
  P2: "bg-high-soft text-high border-[1.5px] border-high font-semibold",
  P3: "bg-medium-soft text-medium border-transparent font-medium",
  P4: "bg-transparent text-muted border-transparent font-medium",
};

/** P1–P4 as a badge, the score and the band's time words in its tooltip; "—" when not scored yet. */
export function PriorityBadge({ engine, className }: { engine: Pick<Engine, "priority" | "band"> | null; className?: string }) {
  const tip = priorityTip(engine);
  return (
    <span
      data-testid="priority-badge"
      data-band={engine?.band ?? "none"}
      title={tip}
      className={cn("inline-flex min-w-9 shrink-0 items-center justify-center rounded-control border px-1.5 py-px text-xs tabular-nums", engine ? BAND_STYLE[engine.band] : "border-border text-muted", className)}
    >
      <span aria-hidden="true">{engine?.band ?? "—"}</span>
      <span className="sr-only">{engine ? `Priority ${engine.band}` : "Not scored yet"}</span>
    </span>
  );
}

/** How sure ARGUS is (or "Confirmed"), in plain bold words: never a colour, never a number. */
export function CertaintyWord({ value, className }: { value: Shown | null; className?: string }) {
  if (value === null) return null;
  return (
    <strong data-testid="certainty" className={cn("font-semibold text-text", className)}>
      {value}
    </strong>
  );
}

/** "Still active since 4 Nov" or "quiet since 5 Nov 2:00 PM", from the engine's times. */
export function activityText(engine: Pick<Engine, "active" | "first_seen" | "last_seen">): string | null {
  if (engine.active) {
    const first = parse(engine.first_seen);
    return first ? `still active since ${shortDay(first)}` : "still active";
  }
  const last = parse(engine.last_seen);
  return last ? `quiet since ${dayAndTime(last)}` : null;
}

export function ActivityLine({ engine, capital = false }: { engine: Pick<Engine, "active" | "first_seen" | "last_seen">; capital?: boolean }) {
  const text = activityText(engine);
  if (text === null) return null;
  const shown = capital ? text.charAt(0).toUpperCase() + text.slice(1) : text;
  return (
    <span data-testid="activity" className="text-text">
      {engine.active && (
        <span aria-hidden="true" className="mr-1 text-xs text-muted motion-safe:animate-pulse">
          ●
        </span>
      )}
      {shown}
    </span>
  );
}

/** What changed since this viewer last looked (no version numbers); hidden when nothing did. */
export function ChangedStrip({ changed, lead = "New since you last looked", testId = "changed-strip", children }: { changed: readonly string[]; lead?: string; testId?: string; children?: ReactNode }) {
  if (changed.length === 0) return null;
  return (
    <p data-testid={testId} className="m-0 flex flex-wrap items-center gap-x-2 gap-y-1 rounded-control bg-accent-soft px-3 py-1.5 text-sm text-text">
      <span aria-hidden="true" className="inline-block size-2 shrink-0 rounded-full bg-accent" />
      <span className="min-w-0 flex-1">
        {lead}: <UntrustedText value={changed.join(" · ")} limits={{ maxChars: 400, maxLines: 3 }} />
      </span>
      {children}
    </p>
  );
}

/** The 8 px changed dot of a row, with its word for screen readers. */
export function ChangedDot({ on }: { on: boolean }) {
  if (!on) return <span aria-hidden="true" className="inline-block size-2" />;
  return (
    <span data-testid="changed-dot" className="inline-flex items-center">
      <span aria-hidden="true" className="inline-block size-2 rounded-full bg-accent" />
      <span className="sr-only">changed</span>
    </span>
  );
}

/** Opens an entity: the drawer when the page has one (§9.5). */
export const EntityOpener = createContext<((o: EngineObject, from: HTMLElement) => void) | null>(null);

/** One campus-side or other-side object, with its noun. */
export function EntityChip({ object }: { object: EngineObject }) {
  const open = useContext(EntityOpener);
  const noun = nounFor(object);
  const body = (
    <>
      <span className="text-muted">{noun}</span>{" "}
      <span className="font-medium">
        <UntrustedText value={object.label} limits={{ maxChars: 80, maxLines: 1 }} />
      </span>
    </>
  );
  const common = { "data-testid": "entity-chip", "data-role": object.role, "data-noun": noun };
  const style = "inline-flex max-w-full min-h-6 items-center gap-1 truncate rounded-control bg-surface-2 px-2 py-px text-xs text-text";
  if (open === null) {
    return (
      <span {...common} className={style}>
        {body}
      </span>
    );
  }
  return (
    <button type="button" {...common} className={cn(style, "cursor-pointer hover:bg-surface-3")} onClick={(e) => open(object, e.currentTarget)} aria-haspopup="dialog">
      {body}
    </button>
  );
}

/** The first `max` chips of a side, then "+N". */
export function ChipRow({ objects, max = 2, label }: { objects: readonly EngineObject[]; max?: number; label: string }) {
  if (objects.length === 0) return null;
  const more = objects.length - max;
  return (
    <span className="inline-flex min-w-0 flex-wrap items-center gap-1">
      <span className="text-xs font-semibold text-muted">{label}</span>
      {objects.slice(0, max).map((o) => (
        <EntityChip key={`${o.role}:${o.kind}:${o.label}`} object={o} />
      ))}
      {more > 0 && <span className="text-xs text-muted">+{more}</span>}
    </span>
  );
}
