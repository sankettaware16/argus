import { useState } from "react";
import { browserStorage, loadShortcuts, saveShortcuts } from "./shortcuts";

/** The single-key shortcuts' switch (WCAG 2.1.4): one box for the Inbox and the investigation page, kept in this browser. */
export function useShortcuts(): [boolean, (on: boolean) => void] {
  const [on, setOn] = useState(() => loadShortcuts(browserStorage()));
  return [
    on,
    (next) => {
      setOn(next);
      saveShortcuts(browserStorage(), next);
    },
  ];
}
