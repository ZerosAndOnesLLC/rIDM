"use client";

import { useState, type FormEvent, type ReactNode } from "react";
import { Button, Modal } from "@/components/console/ui";

/** Small create dialog frame: fields, error line, cancel/submit. */
export function CreateDialog({ open, onOpenChange, title, description, submitLabel, pending, error, onSubmit, children }: { open: boolean; onOpenChange: (o: boolean) => void; title: string; description?: string; submitLabel: string; pending: boolean; error: string | null; onSubmit: () => void; children: ReactNode }) {
  const submit = (e: FormEvent) => {
    e.preventDefault();
    onSubmit();
  };
  return (
    <Modal open={open} onOpenChange={onOpenChange} title={title} description={description}>
      <form onSubmit={submit} className="flex flex-col gap-4 overflow-y-auto px-5 pb-5 pt-3" noValidate>
        {children}
        {error && (
          <p role="alert" className="text-[0.875rem] text-danger">
            {error}
          </p>
        )}
        <div className="flex justify-end gap-2">
          <Button onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={pending}>
            {pending ? "Working…" : submitLabel}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

/** Confirm-then-run for deletions. */
export function DeleteButton({ what, onConfirm, pending, error, description }: { what: string; onConfirm: () => void; pending: boolean; error: string | null; description?: string }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button variant="danger" onClick={() => setOpen(true)}>
        Delete {what}
      </Button>
      <Modal open={open} onOpenChange={setOpen} title={`Delete this ${what}?`} description={description ?? "There is no undo."}>
        <div className="flex flex-col gap-3 px-5 pb-5 pt-3">
          {error && (
            <p role="alert" className="text-[0.875rem] text-danger">
              {error}
            </p>
          )}
          <div className="flex justify-end gap-2">
            <Button onClick={() => setOpen(false)}>Cancel</Button>
            <Button variant="danger" disabled={pending} onClick={onConfirm}>
              {pending ? "Deleting…" : `Delete ${what}`}
            </Button>
          </div>
        </div>
      </Modal>
    </>
  );
}

export function ErrorLine({ error }: { error: Error | null | undefined }) {
  if (!error) return null;
  return (
    <p role="alert" className="text-[0.875rem] text-danger">
      {error.message}
    </p>
  );
}

/** Two-column list/detail layout; the list keeps its place while a detail is open. */
export function Split({ list, detail }: { list: ReactNode; detail: ReactNode }) {
  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(16rem,22rem)_minmax(0,1fr)]">
      <div className="min-w-0">{list}</div>
      <div className="min-w-0">{detail}</div>
    </div>
  );
}
