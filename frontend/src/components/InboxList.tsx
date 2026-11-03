import { useVirtualizer } from "@tanstack/react-virtual";
import { useEffect, useId, useRef, type KeyboardEvent } from "react";
import type { InvestigationOut } from "../client/types.gen";
import { count } from "../lib/format";
import { actionFor, moveCursor } from "../lib/shortcuts";
import { AiChip, StateChip } from "./chips";
import { Sized } from "./Sized";
import { Time } from "./Time";
import { UntrustedText } from "./UntrustedText";
import { Badge, SeverityBadge } from "./ui/badge";

export const ROW_HEIGHT = 84;
const OVERSCAN = 6;

export interface InboxListProps {
  rows: readonly InvestigationOut[];
  /** the server has more rows after these */
  hasMore: boolean;
  /** a further page is being read */
  loadingMore: boolean;
  onLoadMore: () => void;
  cursor: number;
  onCursor: (index: number) => void;
  /** a row was chosen (Enter, a click): open it; `focus` moves the focus into the opened pane */
  onOpen: (row: InvestigationOut, focus: boolean) => void;
  shortcuts: boolean;
  onHelp: () => void;
  /** investigations first grouped after this time are marked "new" (the previous visit) */
  since: string | null | undefined;
  /** tests: the window's size in a browser-less run */
  viewport?: { width: number; height: number };
  label?: string;
}

/**
 * The Inbox's list: an ARIA grid (one tab stop; arrows, Home, End, Page keys, Enter, and j, k, ?
 * unless switched off) whose rows are virtualised: only the rows near the window exist, so
 * thousands of investigations stay light. The grid keeps the focus and names the cursor row with
 * aria-activedescendant (rows come and go as the window moves); more rows are read as the
 * window nears the end.
 */
export function InboxList(props: InboxListProps) {
  const { rows, hasMore, loadingMore, onLoadMore, cursor, onCursor, onOpen, shortcuts, onHelp, since, viewport, label = "Investigations" } = props;
  const base = useId();
  const scroller = useRef<HTMLDivElement>(null); // the grid itself scrolls: the one focusable, keyboard-operable element
  const total = rows.length + (hasMore ? 1 : 0);
  // eslint-disable-next-line react-hooks/incompatible-library -- the list reads the virtualizer only while rendering
  const virtual = useVirtualizer({
    count: total,
    getScrollElement: () => scroller.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: OVERSCAN,
    initialRect: viewport ?? { width: 400, height: 600 },
  });
  const items = virtual.getVirtualItems();
  const lastShown = items.at(-1)?.index ?? -1;
  useEffect(() => {
    if (hasMore && !loadingMore && lastShown >= rows.length - 8) onLoadMore();
  }, [hasMore, loadingMore, lastShown, rows.length, onLoadMore]);

  const rowId = (i: number) => `${base}-row-${i}`;
  const perPage = Math.max(1, Math.floor((scroller.current?.clientHeight ?? viewport?.height ?? 600) / ROW_HEIGHT) - 1);

  function onKeyDown(e: KeyboardEvent<HTMLDivElement>) {
    if (e.target !== e.currentTarget) return;
    const act = actionFor(e, shortcuts);
    if (act === null) return;
    e.preventDefault();
    if (act === "help") return onHelp();
    if (act === "open") {
      const row = rows[cursor];
      if (row) onOpen(row, true);
      return;
    }
    const next = moveCursor(cursor, act.move, rows.length, perPage);
    if (next < 0) return;
    onCursor(next);
    virtual.scrollToIndex(next, { align: "auto" });
  }

  return (
    <div
      ref={scroller}
      role="grid"
      aria-label={label}
      aria-rowcount={hasMore ? -1 : rows.length + 1}
      aria-colcount={3}
      aria-activedescendant={cursor >= 0 && cursor < rows.length && items.some((v) => v.index === cursor) ? rowId(cursor) : undefined}
      tabIndex={0}
      onKeyDown={onKeyDown}
      className="min-h-0 flex-1 overflow-y-auto rounded-card border border-border bg-surface focus-visible:outline-2"
    >
      <div role="rowgroup">
        <div role="row" aria-rowindex={1} className="sr-only">
          <span role="columnheader" aria-colindex={1}>
            Investigation
          </span>
          <span role="columnheader" aria-colindex={2}>
            Status
          </span>
          <span role="columnheader" aria-colindex={3}>
            Alerts and last alert
          </span>
        </div>
      </div>
      <div role="rowgroup">
        <Sized height={virtual.getTotalSize()} className="relative w-full">
          {items.map((v) => {
            const row = rows[v.index];
            if (!row) {
              return (
                <Sized key={`more-${v.index}`} top={v.start} height={ROW_HEIGHT} role="row" aria-rowindex={v.index + 2} className="flex items-center px-3 text-sm text-muted">
                  <span role="gridcell" aria-colindex={1}>
                    Loading more…
                  </span>
                </Sized>
              );
            }
            const selected = v.index === cursor;
            const keyLine = row.key_fields.map((k) => `${k.field} ${String(k.value ?? "")}`).join(" · ");
            const fresh = since !== null && since !== undefined && Date.parse(row.created_at) > Date.parse(since);
            return (
              <Sized
                key={row.id}
                top={v.start}
                height={ROW_HEIGHT}
                id={rowId(v.index)}
                role="row"
                aria-rowindex={v.index + 2}
                aria-selected={selected}
                onClick={() => {
                  onCursor(v.index);
                  onOpen(row, false);
                }}
                className={`grid cursor-pointer grid-cols-[1fr_auto] content-center gap-x-2 gap-y-1 border-b border-border px-3 py-2 text-sm ${selected ? "bg-accent-soft" : "hover:bg-surface-2"}`}
              >
                <div role="gridcell" aria-colindex={1} className="col-start-1 row-start-1 min-w-0">
                  <div className="truncate font-medium">
                    <UntrustedText value={row.rule_name ?? row.rule_id} limits={{ maxChars: 120, maxLines: 1 }} />
                    {fresh && <Badge tone="info" className="ml-1.5">new</Badge>}
                  </div>
                  <div className="truncate font-mono text-xs text-muted">
                    {keyLine === "" ? "single alert" : <UntrustedText value={keyLine} limits={{ maxChars: 160, maxLines: 1 }} />}
                  </div>
                </div>
                <div role="gridcell" aria-colindex={2} className="col-span-2 row-start-2 flex flex-wrap items-center gap-1.5">
                  <SeverityBadge severity={row.severity} />
                  <StateChip state={row.human_state} />
                  <AiChip ai={row.ai} />
                </div>
                <div role="gridcell" aria-colindex={3} className="col-start-2 row-start-1 text-right text-xs text-muted">
                  <div>
                    {count(row.alert_count)} {row.alert_count === 1 ? "alert" : "alerts"}
                  </div>
                  <Time value={row.last_event_at} relative />
                </div>
              </Sized>
            );
          })}
        </Sized>
      </div>
    </div>
  );
}
