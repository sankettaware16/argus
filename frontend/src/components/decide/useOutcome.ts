import { useQueryClient } from "@tanstack/react-query";
import type { CaseRowOut } from "../../client/types.gen";
import { useAnnounce } from "../../lib/announce";
import { useDecided } from "../../lib/decided";
import { changedCase } from "../../lib/queries";
import { can, useSession } from "../../lib/session";
import { sendShown, type Target } from "./target";

/** "Scan or attempt, no sign it worked": a label read inside a sentence. */
export function inSentence(label: string): string {
  return label.replace(/:\s*/g, ", ");
}

/**
 * What follows a decision on a possible incident, wherever it was made (§5.3–§5.5): the words said
 * (and announced), the "Just decided" row, the Undo toast after a dismissal (Undo only for a person
 * with `reopen`), and the reads made again.
 */
export function useOutcome() {
  const queries = useQueryClient();
  const { announce } = useAnnounce();
  const decided = useDecided();
  const session = useSession();
  const canReopen = can(session.data, "reopen");
  const name = session.data?.user.display_name ?? "the person who closed it";

  async function refresh(id: string) {
    await Promise.all([changedCase(queries, id), queries.invalidateQueries({ queryKey: ["today"] })]);
  }

  async function undo(id: string, number: number, row: CaseRowOut) {
    try {
      const changed = await sendShown({ method: "POST", path: `/api/v1/cases/${id}/reopen`, body: { expected_version: row.version, reason: `Undone by ${name} right after closing it` } });
      decided.update(id, changed.case, { undone: true });
      announce(`Incident #${number} is open again: a possible incident.`, "ok");
    } catch (e) {
      announce(e instanceof Error ? `Undo did not work: ${e.message}` : "Undo did not work; try again.", "danger");
    }
    decided.close();
    await refresh(id);
  }

  return {
    canReopen,
    undo,
    confirmed(t: Pick<Target, "id" | "number" | "title">, row: CaseRowOut, takeFailed: string | null) {
      decided.add({ id: t.id, number: t.number, title: t.title, kind: "confirmed", label: null, row });
      announce(takeFailed === null ? `Incident #${t.number} is confirmed.` : `Incident #${t.number} is confirmed. Taking it failed: ${takeFailed}`, takeFailed === null ? "ok" : "warn");
      void refresh(t.id);
    },
    dismissed(t: Pick<Target, "id" | "number" | "title">, row: CaseRowOut, label: string) {
      decided.add({ id: t.id, number: t.number, title: t.title, kind: "closed", label, row });
      const said = `Incident #${t.number} closed: ${inSentence(label)}.`;
      announce(said, "ok");
      decided.offer({
        id: t.id,
        text: canReopen ? said : `Incident #${t.number} closed. If this was a mistake, a person with reopen access can reopen it.`,
        undo: canReopen ? () => undo(t.id, t.number, row) : null,
      });
      void refresh(t.id);
    },
    conflict(id: string) {
      announce("It changed while you were deciding: nothing was sent. Read it again.", "warn");
      void refresh(id);
    },
  };
}
