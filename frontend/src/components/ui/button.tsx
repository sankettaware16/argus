import { cva, type VariantProps } from "class-variance-authority";
import type { ComponentProps } from "react";
import { cn } from "../../lib/cn";

export const buttonVariants = cva(
  "inline-flex min-h-8 cursor-pointer items-center justify-center gap-1.5 rounded-control border px-3 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-55 aria-disabled:cursor-not-allowed aria-disabled:opacity-55",
  {
    variants: {
      variant: {
        primary: "rounded-full border-accent bg-accent px-4 text-accent-fg hover:bg-accent-hover",
        secondary: "border-border-strong bg-surface text-text hover:bg-surface-2",
        ghost: "border-transparent bg-transparent text-text hover:bg-surface-2",
        danger: "border-danger bg-danger text-surface hover:opacity-90",
      },
      size: { sm: "min-h-7 px-2 text-[0.8125rem]", md: "", lg: "min-h-10 px-4 text-base" },
    },
    defaultVariants: { variant: "secondary", size: "md" },
  },
);

export type ButtonProps = ComponentProps<"button"> & VariantProps<typeof buttonVariants>;

/**
 * A button. `type` defaults to "button": nothing submits a form by accident. A button that is busy
 * is `aria-disabled`, not `disabled`: a disabled button that has the focus drops it to the page
 * (review B2-R5), and the handler of an aria-disabled one does nothing while it is busy.
 */
export function Button({ className, variant, size, type = "button", ...props }: ButtonProps) {
  return <button type={type} className={cn(buttonVariants({ variant, size }), className)} {...props} />;
}
