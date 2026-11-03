import { useLayoutEffect, useRef, type ComponentProps } from "react";

/**
 * An element whose size or place is a number the code works out (a virtual list's rows). The CSP
 * refuses a `style` attribute written in markup, and our lint refuses the JSX prop; the CSSOM
 * (`element.style.height = ...`) is not a style attribute in markup and is allowed by the policy
 * (the browser suite's tripwire counts 0 violations). This is the one place that does it.
 */
export function Sized({ height, top, ...props }: ComponentProps<"div"> & { height?: number; top?: number }) {
  const ref = useRef<HTMLDivElement>(null);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (height !== undefined) el.style.height = `${height}px`;
    if (top !== undefined) {
      el.style.position = "absolute";
      el.style.top = "0";
      el.style.left = "0";
      el.style.width = "100%";
      el.style.transform = `translateY(${top}px)`;
    }
  }, [height, top]);
  return <div ref={ref} {...props} />;
}
