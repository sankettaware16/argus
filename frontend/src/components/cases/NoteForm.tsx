import { useId, useRef, useState, type FormEvent } from "react";
import { useAnnounce } from "../../lib/announce";
import { ApiError } from "../../lib/session";
import { Button } from "../ui/button";
import { Field, TextArea } from "../ui/field";

const NOTE_MAX = 4000;

/**
 * A note, for people only (plan §3 rule 14): never sent to a model, never to Kibana. Typed in a
 * visible form and sent from it (Q-B2's rule for a change the person composes); one send at a
 * time; a failure is said once, next to the form, and what was typed stays.
 */
export function NoteForm({
  label,
  submit,
  say,
  compact = false,
}: {
  label: string;
  /** sends the words; returns whether the same note was there already */
  submit: (body: string) => Promise<{ duplicate: boolean }>;
  say: string;
  compact?: boolean;
}) {
  const id = useId();
  const { announce } = useAnnounce();
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const sending = useRef(false);
  const said = text.trim();

  async function send(e: FormEvent) {
    e.preventDefault();
    if (sending.current) return;
    if (said === "") {
      setProblem("Write the note first.");
      return;
    }
    if (said.length > NOTE_MAX || said.includes("\u0000")) {
      setProblem(`A note has at most ${NOTE_MAX} characters, and no NUL character.`);
      return;
    }
    sending.current = true;
    setBusy(true);
    setProblem(null);
    try {
      const done = await submit(said);
      announce(done.duplicate ? "That note was added a moment ago; it was not added twice." : say, done.duplicate ? "info" : "ok");
      setText("");
    } catch (error) {
      setProblem(error instanceof ApiError ? error.message : "The note could not be saved. Try again.");
    } finally {
      sending.current = false;
      setBusy(false);
    }
  }

  return (
    <form className="flex flex-col gap-2" onSubmit={(e) => void send(e)} aria-label={label}>
      <Field label={label} hint="Only people read it; ARGUS's models never do." htmlFor={id}>
        <TextArea id={id} rows={compact ? 2 : 3} maxLength={NOTE_MAX} value={text} onChange={(e) => setText(e.target.value)} />
      </Field>
      {problem && (
        <p role="alert" className="m-0 rounded-control border border-danger/40 bg-danger-soft px-3 py-2 text-sm text-danger">
          {problem}
        </p>
      )}
      <div>
        <Button type="submit" variant="primary" aria-disabled={busy} onClick={(e) => busy && e.preventDefault()}>
          {busy ? "Saving…" : "Add the note"}
        </Button>
      </div>
    </form>
  );
}
