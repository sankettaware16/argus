import { useLayoutEffect, useRef, useState, type RefObject } from "react";

/**
 * The width a chart has to draw in, in pixels: charts are drawn at their real size (text and
 * marks never scale with the card). Where the browser cannot say (a test without layout), `fallback`.
 */
export function useWidth<T extends Element>(fallback = 720): [RefObject<T | null>, number] {
  const ref = useRef<T | null>(null);
  const [width, setWidth] = useState(fallback);
  useLayoutEffect(() => {
    const el = ref.current;
    if (el === null || typeof ResizeObserver === "undefined") return;
    const seen = new ResizeObserver((entries) => {
      const next = Math.round(entries[0]?.contentRect.width ?? 0);
      if (next > 0) setWidth(next);
    });
    seen.observe(el);
    return () => seen.disconnect();
  }, []);
  return [ref, width];
}
