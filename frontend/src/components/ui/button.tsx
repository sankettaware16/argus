import { cva, type VariantProps } from "class-variance-authority";
import type { ComponentProps } from "react";
import { cn } from "../../lib/cn";

export const buttonVariants = cva(
  "inline-flex min-h-8 cursor-pointer items-center justify-center gap-1.5 rounded-full border px-3.5 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-55 aria-disabled:cursor-not-allowed aria-disabled:opacity-55",
  {
    variants: {
      variant: {
        primary: "border-accent bg-accent px-4 text-accent-fg hover:border-accent-hover hover:bg-accent-hover",
        secondary: "border-transparent bg-surface-2 text-text hover:bg-surface-3",
        ghost: "border-transparent bg-transparent text-link hover:bg-surface-2",
        danger: "border-danger bg-danger text-bg hover:opacity-90",
      },
      size: { sm: "min-h-7 px-3 text-[0.8125rem]", md: "", lg: "min-h-11 px-5 text-base" },
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
