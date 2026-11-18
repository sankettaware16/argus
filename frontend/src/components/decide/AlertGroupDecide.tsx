import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useId, useRef, useState } from "react";
import { useAnnounce } from "../../lib/announce";
import { cn } from "../../lib/cn";
import { OUTCOME_HINTS, OUTCOMES } from "../../lib/labels";
import { changed, investigationOptions } from "../../lib/queries";
import { ConfirmDialog } from "../ConfirmDialog";
import { Button } from "../ui/button";
import { KIBANA_WAVE1 } from "./target";

/** "Real: open an incident…" (§8, F6): what marking an alert group real does, before it is sent. */
export const REAL_SENTENCE = `Marking it real opens a possible incident, or adds it to the incident that holds its activity. ${KIBANA_WAVE1}`;

type Outcome = "true_positive" | "benign_expected" | "benign_policy" | "rule_false_positive" | "inconclusive";
const OTHERS: Outcome[] = ["benign_expected", "benign_policy", "rule_false_positive", "inconclusive"];
const FOLLOW_UP = "You are checking: it stays in the queue until someone decides.";

/**
 * An alert group in no incident, decided from a card (§5.3's gray band): "Real: open an
 * incident…" opens a dialog first (no request before the dialog's own button, T-13), and "Other
 * outcome ▾" holds the four others. Each review names the version and the latest review the
 * person's page read; "Can't tell yet" keeps it for a follow-up, as on the alert group's page.
 */
export function AlertGroupDecide({ id, title, onDone, size = "md" }: { id: string; title: string; onDone?: () => void; size?: "md" | "touch" }) {
  const [asking, setAsking] = useState<Outcome | null>(null);
  const [menu, setMenu] = useState(false);
  const menuId = useId();
  const box = useRef<HTMLDivElement>(null);
  const detail = useQuery({ ...investigationOptions(id), enabled: asking !== null });
  const queries = useQueryClient();
  const { announce } = useAnnounce();
  const inv = detail.data?.investigation;
  useEffect(() => {
    if (!menu) return;
    const away = (e: MouseEvent) => {
      if (box.current && !box.current.contains(e.target as Node)) setMenu(false);
    };
    document.addEventListener("mousedown", away);
    return () => document.removeEventListener("mousedown", away);
  }, [menu]);
  const outcome = asking ?? "true_positive";
  const action = outcome === "inconclusive" ? "follow_up" : "reviewed";
  const body = { action, outcome, seen_review: inv?.latest_review ?? null, seen_version: inv?.version ?? 0 };
  const touch = size === "touch" ? "min-h-11" : undefined;
  return (
    <div className="flex flex-wrap items-center gap-2">
      <Button variant="primary" className={touch} onClick={() => setAsking("true_positive")}>
        Real: open an incident…
      </Button>
      <div ref={box} className="relative inline-block">
        <Button className={touch} aria-haspopup="menu" aria-expanded={menu} aria-controls={menu ? menuId : undefined} onClick={() => setMenu(!menu)}>
          Other outcome ▾
        </Button>
        {menu && (
          <div id={menuId} role="menu" aria-label="Other outcome" className="absolute left-0 z-30 mt-1 flex w-[min(22rem,calc(100vw-2rem))] flex-col rounded-card border border-border bg-raised p-1 shadow-card" onKeyDown={(e) => e.key === "Escape" && setMenu(false)}>
            {OTHERS.map((o) => (
              <button
                key={o}
                type="button"
                role="menuitem"
                className={cn("flex flex-col items-start rounded-control px-3 py-2 text-left text-sm hover:bg-surface-2")}
                onClick={() => {
                  setMenu(false);
                  setAsking(o);
                }}
              >
                <span className="font-medium">{OUTCOMES[o]}</span>
                <span className="text-muted">{o === "inconclusive" ? FOLLOW_UP : OUTCOME_HINTS[o]}</span>
              </button>
            ))}
          </div>
        )}
      </div>
      {asking !== null && inv === undefined && (
        <span className="text-sm text-muted" role="status">
          {detail.isError ? "The alert group could not be read; nothing was sent." : "Reading the alert group…"}
        </span>
      )}
      {asking !== null && inv !== undefined && (
        <ConfirmDialog
          open
          onOpenChange={(next) => !next && setAsking(null)}
          title={asking === "true_positive" ? "Real: open an incident?" : `${OUTCOMES[asking]}?`}
          description={
            <>
              <span className="block font-medium text-text">{title}</span>
              {asking === "true_positive" ? REAL_SENTENCE : asking === "inconclusive" ? FOLLOW_UP : OUTCOME_HINTS[asking]}
            </>
          }
          request={{ method: "POST", path: `/api/v1/investigations/${id}/reviews`, body }}
          confirmLabel={asking === "true_positive" ? "Mark it real" : "Save decision"}
          onSent={() => {
            announce(asking === "true_positive" ? "Marked real: ARGUS opens a possible incident for it, or adds it to the incident that holds its activity." : `Saved: ${OUTCOMES[asking]}.`, "ok");
            setAsking(null);
            onDone?.();
            void changed(queries, id);
            void queries.invalidateQueries({ queryKey: ["today"] });
          }}
        />
      )}
    </div>
  );
}
