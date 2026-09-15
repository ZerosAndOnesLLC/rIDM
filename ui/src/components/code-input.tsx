"use client";

import { useId } from "react";

/** One wide input for a numeric one-time code; autofills from SMS on mobile. */
export function CodeInput({
  label,
  value,
  onChange,
  length = 6,
  error,
  autoFocus,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  length?: number;
  error?: string | null;
  autoFocus?: boolean;
}) {
  const id = useId();
  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor={id} className="text-[0.8125rem] font-medium text-ink">
        {label}
      </label>
      <input
        id={id}
        value={value}
        onChange={(e) => onChange(e.target.value.replace(/\D/g, "").slice(0, length))}
        inputMode="numeric"
        autoComplete="one-time-code"
        pattern="[0-9]*"
        maxLength={length}
        autoFocus={autoFocus}
        aria-invalid={error ? true : undefined}
        className={`min-h-12 w-full rounded-[var(--radius)] border bg-paper px-3.5 text-center font-mono text-[1.375rem] tracking-[0.4em] text-ink ${
          error ? "border-danger" : "border-line"
        }`}
      />
      {error && (
        <p className="text-[0.8125rem] text-danger" role="alert">
          {error}
        </p>
      )}
    </div>
  );
}
