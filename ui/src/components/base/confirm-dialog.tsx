"use client";

import * as Dialog from "@radix-ui/react-dialog";
import { useId, useState, type FormEvent, type ReactNode } from "react";
import { buttonClass } from "./button";

/**
 * "Are you sure?" for destructive actions, on the same dialog primitive as
 * the console's modals. `confirmName` asks the person to type a name before
 * the button enables (deleting a tenant, revoking a key). `onConfirm` may be
 * async: the dialog shows the request as pending, closes on success and
 * shows the error otherwise. The e2e helper `confirmDialog()` drives it.
 */
export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel = "Confirm",
  tone = "danger",
  confirmName,
  onConfirm,
  children,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description?: ReactNode;
  confirmLabel?: string;
  tone?: "danger" | "primary";
  /** The exact text the person must type before confirming. */
  confirmName?: string;
  onConfirm: () => Promise<unknown> | unknown;
  /** Extra content between the description and the buttons. */
  children?: ReactNode;
}) {
  const [typed, setTyped] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const id = useId();
  const ready = !pending && (!confirmName || typed.trim() === confirmName);

  const change = (next: boolean) => {
    if (pending) return;
    if (!next) {
      setTyped("");
      setError(null);
    }
    onOpenChange(next);
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!ready) return;
    setPending(true);
    setError(null);
    try {
      await onConfirm();
      setPending(false);
      setTyped("");
      onOpenChange(false);
    } catch (err) {
      setPending(false);
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  return (
    <Dialog.Root open={open} onOpenChange={change}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 bg-black/40 backdrop-blur-[2px]" />
        <Dialog.Content className="fixed inset-x-4 top-[18vh] z-50 mx-auto flex max-h-[70vh] w-auto max-w-md flex-col overflow-hidden rounded-[var(--radius-lg)] border border-line bg-paper shadow-pop">
          <form onSubmit={submit} className="flex flex-col gap-4 px-5 pt-5 pb-4">
            <div className="flex flex-col gap-1.5">
              <Dialog.Title className="text-md font-semibold text-ink">{title}</Dialog.Title>
              <Dialog.Description className={description ? "text-body text-muted" : "sr-only"}>{description ?? title}</Dialog.Description>
            </div>
            {children}
            {confirmName && (
              <div className="flex flex-col gap-1.5">
                <label htmlFor={`${id}-name`} className="text-small text-ink">
                  Type <code className="rounded bg-ground px-1 font-mono text-caption">{confirmName}</code> to confirm
                </label>
                <input
                  id={`${id}-name`}
                  value={typed}
                  onChange={(e) => setTyped(e.target.value)}
                  autoComplete="off"
                  spellCheck={false}
                  autoFocus
                  className="min-h-10 w-full rounded-[var(--radius)] border border-line-strong bg-paper px-3 font-mono text-small text-ink max-sm:text-md!"
                />
              </div>
            )}
            {error && (
              <p role="alert" className="text-small text-danger">
                {error}
              </p>
            )}
            <div className="flex justify-end gap-2">
              <Dialog.Close asChild>
                <button type="button" className={buttonClass("secondary", "md")} disabled={pending}>
                  Cancel
                </button>
              </Dialog.Close>
              <button type="submit" aria-busy={pending || undefined} disabled={!ready} className={buttonClass(tone, "md")}>
                {pending ? "Working…" : confirmLabel}
              </button>
            </div>
          </form>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
