"use client";

import { forwardRef, useId, useState, type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode } from "react";
import { Eye, EyeOff, Loader2 } from "lucide-react";
import { useI18n } from "@/i18n/provider";

type Variant = "primary" | "secondary" | "quiet" | "danger";

const variantClass: Record<Variant, string> = {
  primary: "bg-accent text-accent-ink hover:brightness-110 active:brightness-95",
  secondary: "bg-paper text-ink border border-line hover:bg-ground",
  quiet: "bg-transparent text-accent hover:underline underline-offset-4",
  danger: "bg-paper text-danger border border-line hover:bg-danger-soft",
};

export function Button({
  variant = "primary",
  busy = false,
  className = "",
  children,
  disabled,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; busy?: boolean }) {
  return (
    <button
      {...rest}
      disabled={disabled || busy}
      aria-busy={busy || undefined}
      className={`relative inline-flex min-h-11 w-full items-center justify-center gap-2 rounded-[var(--radius)] px-4 text-[0.9375rem] font-medium transition-[filter,background-color] disabled:cursor-not-allowed disabled:opacity-60 ${variantClass[variant]} ${className}`}
    >
      {busy && <Loader2 className="size-4 animate-spin" aria-hidden />}
      {children}
    </button>
  );
}

interface FieldProps extends InputHTMLAttributes<HTMLInputElement> {
  label: string;
  error?: string | null;
  hint?: string | null;
  /** Rendered after the input, inside the field (e.g. a reveal button). */
  trailing?: ReactNode;
}

/** Text input with a stacked label, hint and inline error. */
export const TextField = forwardRef<HTMLInputElement, FieldProps>(function TextField(
  { label, error, hint, trailing, id, className = "", ...rest },
  ref,
) {
  const auto = useId();
  const inputId = id ?? auto;
  const describedBy = [error ? `${inputId}-err` : null, hint ? `${inputId}-hint` : null]
    .filter(Boolean)
    .join(" ");
  return (
    <div className={`flex flex-col gap-1.5 ${className}`}>
      <label htmlFor={inputId} className="text-[0.8125rem] font-medium text-ink">
        {label}
      </label>
      <div className="relative">
        <input
          ref={ref}
          id={inputId}
          aria-invalid={error ? true : undefined}
          aria-describedby={describedBy || undefined}
          className={`min-h-11 w-full rounded-[var(--radius)] border bg-paper px-3.5 text-ink placeholder:text-muted/70 ${
            trailing ? "pe-11" : ""
          } ${error ? "border-danger" : "border-line hover:border-muted/60"}`}
          {...rest}
        />
        {trailing && <div className="absolute inset-y-0 end-1 flex items-center">{trailing}</div>}
      </div>
      {error ? (
        <p id={`${inputId}-err`} className="text-[0.8125rem] text-danger" role="alert">
          {error}
        </p>
      ) : hint ? (
        <p id={`${inputId}-hint`} className="text-[0.8125rem] text-muted">
          {hint}
        </p>
      ) : null}
    </div>
  );
});

export function PasswordField(props: Omit<FieldProps, "type" | "trailing">) {
  const [shown, setShown] = useState(false);
  const { t } = useI18n();
  return (
    <TextField
      {...props}
      type={shown ? "text" : "password"}
      trailing={
        <button
          type="button"
          onClick={() => setShown((s) => !s)}
          aria-label={shown ? t("common.hide_password") : t("common.show_password")}
          aria-pressed={shown}
          className="flex size-9 items-center justify-center rounded-md text-muted hover:text-ink"
        >
          {shown ? <EyeOff className="size-4" aria-hidden /> : <Eye className="size-4" aria-hidden />}
        </button>
      }
    />
  );
}

export function Checkbox({
  label,
  className = "",
  ...rest
}: InputHTMLAttributes<HTMLInputElement> & { label: ReactNode }) {
  const id = useId();
  return (
    <label htmlFor={id} className={`flex cursor-pointer items-start gap-2.5 text-[0.9375rem] ${className}`}>
      <input id={id} type="checkbox" className="mt-1 size-4 shrink-0 accent-[var(--accent)]" {...rest} />
      <span>{label}</span>
    </label>
  );
}

export function Alert({ tone, children }: { tone: "error" | "ok" | "info"; children: ReactNode }) {
  const cls =
    tone === "error"
      ? "bg-danger-soft text-danger"
      : tone === "ok"
        ? "bg-ok-soft text-ok"
        : "bg-ground text-ink";
  return (
    <div role={tone === "error" ? "alert" : "status"} className={`rounded-[var(--radius)] px-3.5 py-3 text-[0.9rem] ${cls}`}>
      {children}
    </div>
  );
}

export function Divider({ label }: { label: string }) {
  return (
    <div className="flex items-center gap-3 text-[0.8125rem] text-muted" aria-hidden>
      <span className="h-px flex-1 bg-line" />
      {label}
      <span className="h-px flex-1 bg-line" />
    </div>
  );
}

export function Spinner({ label }: { label: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-8 text-muted" role="status">
      <Loader2 className="size-5 animate-spin" aria-hidden />
      <span>{label}</span>
    </div>
  );
}

export function Title({ children, sub }: { children: ReactNode; sub?: ReactNode }) {
  return (
    <header className="mb-6">
      <h1 className="text-[1.75rem] font-semibold leading-tight tracking-[-0.01em] text-ink">{children}</h1>
      {sub && <p className="mt-1.5 text-[0.9375rem] text-muted">{sub}</p>}
    </header>
  );
}
