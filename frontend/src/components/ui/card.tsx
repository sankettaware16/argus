import type { ComponentProps, HTMLAttributes } from "react";
import { cn } from "../../lib/cn";

export function Card({ className, ...props }: ComponentProps<"section">) {
  return <section className={cn("rounded-card border border-border bg-surface p-4 shadow-card", className)} {...props} />;
}

export function CardTitle({ className, ...props }: HTMLAttributes<HTMLHeadingElement>) {
  return <h2 className={cn("m-0 mb-2 text-base font-semibold", className)} {...props} />;
}
