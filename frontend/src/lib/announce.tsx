/**
 * Messages (Q-B1, plan §7.5): every result of a person's action is said in words, on screen and
 * to screen readers. Two live regions (polite for results, assertive for failures that need
 * attention now) and a visible list of the latest messages, each kept until it is dismissed (no
 * message disappears on a timer: WCAG 2.2.1).
 */
import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from "react";
import { Button } from "../components/ui/button";
import { cn } from "./cn";

export type MessageTone = "info" | "ok" | "warn" | "danger";

export interface Message {
  id: number;
  text: string;
  tone: MessageTone;
}

interface Announcer {
  /** say `text`: polite unless the tone is danger */
  announce: (text: string, tone?: MessageTone) => void;
  messages: readonly Message[];
  dismiss: (id: number) => void;
}

const MAX_SHOWN = 4;
const MAX_TEXT = 300;
const Context = createContext<Announcer | null>(null);

export function AnnounceProvider({ children }: { children: ReactNode }) {
  const [messages, setMessages] = useState<Message[]>([]);
  const [polite, setPolite] = useState("");
  const [assertive, setAssertive] = useState("");
  const next = useRef(1);

  const announce = useCallback((raw: string, tone: MessageTone = "info") => {
    const text = raw.length > MAX_TEXT ? `${raw.slice(0, MAX_TEXT)}…` : raw;
    const id = next.current++;
    setMessages((old) => [...old, { id, text, tone }].slice(-MAX_SHOWN));
    // a live region speaks a change: the same words twice in a row are made different by an
    // invisible counter, so a repeated result is still announced
    const spoken = `${text}${id % 2 ? "" : "\u00a0"}`;
    if (tone === "danger") setAssertive(spoken);
    else setPolite(spoken);
  }, []);

  const dismiss = useCallback((id: number) => setMessages((old) => old.filter((m) => m.id !== id)), []);
  const value = useMemo(() => ({ announce, messages, dismiss }), [announce, messages, dismiss]);
  return (
    <Context.Provider value={value}>
      {children}
      <div className="sr-only" role="status" aria-live="polite" aria-atomic="true" data-testid="live-polite">
        {polite}
      </div>
      <div className="sr-only" role="alert" aria-live="assertive" aria-atomic="true" data-testid="live-assertive">
        {assertive}
      </div>
    </Context.Provider>
  );
}

export function useAnnounce(): Announcer {
  const value = useContext(Context);
  if (value === null) throw new Error("useAnnounce needs an AnnounceProvider");
  return value;
}

const TONE: Record<MessageTone, string> = {
  info: "border-info/40 bg-info-soft text-info",
  ok: "border-ok/40 bg-ok-soft text-ok",
  warn: "border-warn/40 bg-warn-soft text-warn",
  danger: "border-danger/40 bg-danger-soft text-danger",
};
const WORD: Record<MessageTone, string> = { info: "Note", ok: "Done", warn: "Check", danger: "Problem" };

/** The visible messages (already spoken by the live regions, so this list is not live). */
export function Messages() {
  const { messages, dismiss } = useAnnounce();
  if (messages.length === 0) return null;
  return (
    <section aria-label="Messages" className="flex flex-col gap-2">
      {messages.map((m) => (
        <div
          key={m.id}
          className={cn("flex items-start justify-between gap-3 rounded-control border px-3 py-2 text-sm", TONE[m.tone])}
        >
          <p className="m-0">
            <strong className="font-semibold">{WORD[m.tone]}: </strong>
            {m.text}
          </p>
          <Button size="sm" variant="ghost" onClick={() => dismiss(m.id)} aria-label={`Dismiss: ${m.text}`}>
            Dismiss
          </Button>
        </div>
      ))}
    </section>
  );
}
