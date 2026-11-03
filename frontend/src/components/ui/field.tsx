import type { ComponentProps, ReactNode } from "react";
import { cn } from "../../lib/cn";

const CONTROL =
  "min-h-8 w-full rounded-control border border-border-strong bg-surface px-2 py-1 text-sm text-text placeholder:text-muted disabled:opacity-55";

/** A labelled form control: the label is always visible and tied to the control. */
export function Field({ label, hint, htmlFor, children, className }: { label: ReactNode; hint?: ReactNode; htmlFor: string; children: ReactNode; className?: string }) {
  return (
    <div className={cn("flex flex-col gap-1", className)}>
      <label htmlFor={htmlFor} className="text-sm font-medium">
        {label}
        {hint && <span className="ml-1 font-normal text-muted">{hint}</span>}
      </label>
      {children}
    </div>
  );
}

export function TextInput({ className, ...props }: ComponentProps<"input">) {
  return <input className={cn(CONTROL, className)} {...props} />;
}

export function TextArea({ className, ...props }: ComponentProps<"textarea">) {
  return <textarea className={cn(CONTROL, "min-h-16", className)} {...props} />;
}

/** The browser's own select: keyboard and screen readers work as people expect. */
export function Select({ className, ...props }: ComponentProps<"select">) {
  return <select className={cn(CONTROL, "pr-6", className)} {...props} />;
}

export function Check({ className, children, ...props }: ComponentProps<"input"> & { children: ReactNode }) {
  return (
    <label className={cn("inline-flex min-h-6 items-center gap-1.5 text-sm", className)}>
      <input type="checkbox" className="size-4 accent-accent" {...props} />
      {children}
    </label>
  );
}
