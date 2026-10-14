/**
 * The one set of button classes every surface draws from. The auth pages,
 * the account console and the admin console each keep their own facade
 * (`components/ui.tsx`, `components/console/ui.tsx`) and compose these.
 *
 * Variants follow design/README.md: `primary` is a solid → solid-hover
 * gradient with an inner highlight, `secondary` a bordered paper button,
 * `quiet` borderless, `danger` paper with danger text, `link` text only.
 */
export type ButtonVariant = "primary" | "secondary" | "quiet" | "danger" | "link";
/** 26 px (row actions), 32 px (toolbars), 44 px (auth forms). */
export type ButtonSize = "sm" | "md" | "lg";

const BASE =
  "inline-flex items-center justify-center whitespace-nowrap rounded-[var(--radius)] font-medium transition-[filter,background-color,border-color] disabled:cursor-not-allowed disabled:opacity-60 [&>svg]:shrink-0";

const VARIANT: Record<ButtonVariant, string> = {
  // The tenant's primary itself (a non-hex colour sets nothing else), with a
  // translucent top-to-bottom sheen for the reference's gradient.
  primary:
    "border border-accent-solid-hover bg-accent bg-[linear-gradient(180deg,rgba(255,255,255,0.1),rgba(0,0,0,0.12))] text-accent-ink shadow-[0_1px_2px_rgba(15,18,24,0.2),inset_0_0_0_1px_rgba(255,255,255,0.12)] hover:brightness-[1.06] active:brightness-95",
  secondary: "border border-line-strong bg-paper text-ink shadow-[0_1px_1px_rgba(15,18,24,0.04)] hover:bg-ground",
  quiet: "border border-transparent bg-transparent text-ink-2 hover:bg-ground hover:text-ink",
  danger: "border border-line-strong bg-paper text-danger shadow-[0_1px_1px_rgba(15,18,24,0.04)] hover:bg-danger-soft",
  link: "border border-transparent bg-transparent text-link hover:underline underline-offset-4",
};

const SIZE: Record<ButtonSize, string> = {
  sm: "min-h-7 gap-1.5 px-2.5 text-caption [&>svg]:size-3.5",
  md: "min-h-8 gap-1.5 px-3 text-small [&>svg]:size-4",
  lg: "min-h-11 gap-2 px-4 text-lead [&>svg]:size-4",
};

export function buttonClass(variant: ButtonVariant = "secondary", size: ButtonSize = "md", extra = ""): string {
  return `${BASE} ${VARIANT[variant]} ${SIZE[size]} ${extra}`.trim();
}

/** A square button holding one icon; the caller supplies the accessible name. */
export function iconButtonClass(size: ButtonSize = "md", extra = ""): string {
  const box = size === "sm" ? "size-7 [&>svg]:size-3.5" : size === "lg" ? "size-11 [&>svg]:size-5" : "size-8 [&>svg]:size-4";
  return `inline-flex shrink-0 items-center justify-center rounded-[var(--radius)] text-muted transition-colors hover:bg-ground hover:text-ink disabled:cursor-not-allowed disabled:opacity-60 ${box} ${extra}`.trim();
}
