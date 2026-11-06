/**
 * What this person decided in this session (docs/p4f-ui-spec.md §5.2 region 4, §5.5): the "Just
 * decided" rows on Today, each with its Kibana state or its Undo, and the Undo toast after a
 * dismissal (10 s, kept open while hovered or focused). Kept in memory only: a reload starts a new
 * session. Outside a provider (a component test), nothing is kept and nothing is offered.
 */
import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";
import type { CaseRowOut } from "../client/types.gen";

export interface Decided {
  id: string;
  number: number;
  title: string;
  kind: "confirmed" | "closed";
  /** the reason's label, for a closure */
  label: string | null;
  /** the case as the decision left it (its version for Undo, its Kibana state) */
  row: CaseRowOut;
  undone: boolean;
}

export interface UndoOffer {
  id: string;
  text: string;
  /** null: this person may not reopen, and the toast says who can */
  undo: (() => Promise<void>) | null;
}

interface Store {
  items: readonly Decided[];
  add: (d: Omit<Decided, "undone">) => void;
  update: (id: string, row: CaseRowOut, more?: Partial<Decided>) => void;
  toast: UndoOffer | null;
  offer: (o: UndoOffer) => void;
  close: () => void;
}

const NONE: Store = { items: [], add: () => {}, update: () => {}, toast: null, offer: () => {}, close: () => {} };
const Context = createContext<Store>(NONE);

export function DecidedProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<Decided[]>([]);
  const [toast, setToast] = useState<UndoOffer | null>(null);
  const add = useCallback((d: Omit<Decided, "undone">) => setItems((old) => [{ ...d, undone: false }, ...old.filter((o) => o.id !== d.id)]), []);
  const update = useCallback((id: string, row: CaseRowOut, more: Partial<Decided> = {}) => setItems((old) => old.map((o) => (o.id === id ? { ...o, ...more, row } : o))), []);
  const offer = useCallback((o: UndoOffer) => setToast(o), []);
  const close = useCallback(() => setToast(null), []);
  const value = useMemo(() => ({ items, add, update, toast, offer, close }), [items, add, update, toast, offer, close]);
  return <Context.Provider value={value}>{children}</Context.Provider>;
}

export function useDecided(): Store {
  return useContext(Context);
}
