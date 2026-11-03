import { useEffect, useState } from "react";

/** The time now in milliseconds, read again every `everyMs` (a page that shows how long something stays valid). */
export function useNow(everyMs = 30_000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), everyMs);
    return () => clearInterval(timer);
  }, [everyMs]);
  return now;
}
