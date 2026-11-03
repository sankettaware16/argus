import { useId, useState, type ReactNode } from "react";

/**
 * A button that cannot be used yet says why (WCAG 3.3.1; Q-B3 review R3-7). The button stays
 * focusable (`aria-disabled`, never `disabled`) and is described by the reason, which is shown
 * beside it; pressing it anyway has the reason read out and shown plainly instead of doing nothing.
 *
 * `why` is the reason the action is not possible now, or null when it is.
 */
export function useGuard(why: string | null) {
  const id = useId();
  const [pressed, setPressed] = useState(false);
  const blocked = why !== null;
  return {
    blocked,
    /** spread on the Button */
    props: { "aria-disabled": blocked, "aria-describedby": blocked ? id : undefined },
    /** wrap the button's action: it runs only when nothing blocks it */
    press: (act: () => void) => () => {
      if (blocked) setPressed(true);
      else act();
    },
    /** the reason, to put beside the button (nothing when the action is possible) */
    hint: blocked ? (
      <>
        <span id={id} className={pressed ? "text-sm text-text" : "text-sm text-muted"}>
          {why}
        </span>
        <span role="status" className="sr-only">
          {pressed ? `Not done: ${why}` : ""}
        </span>
      </>
    ) : (null as ReactNode),
  };
}
