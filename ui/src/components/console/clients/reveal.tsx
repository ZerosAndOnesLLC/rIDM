"use client";

import { Check, Copy } from "lucide-react";
import { useState } from "react";
import { Button, Modal } from "@/components/console/ui";

/** Copies `value` and confirms for a moment. */
export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <Button
      variant="secondary"
      className="min-h-8 px-2.5 text-[0.8125rem]"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setDone(true);
          window.setTimeout(() => setDone(false), 1500);
        } catch {
          // Clipboard blocked: the value is selectable on screen.
        }
      }}
    >
      {done ? <Check className="size-3.5" aria-hidden /> : <Copy className="size-3.5" aria-hidden />}
      {done ? "Copied" : label}
    </Button>
  );
}

/** A value shown exactly once (secret, registration token): monospace, selectable, copyable. */
export function Secret({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-col gap-1.5">
      <span className="text-[0.8125rem] font-medium text-ink">{label}</span>
      <div className="flex items-start gap-2">
        <code className="min-w-0 flex-1 break-all rounded-[var(--radius)] border border-line bg-ground px-3 py-2 font-mono text-[0.8125rem] text-ink select-all" data-testid="secret-value">
          {value}
        </code>
        <CopyButton value={value} />
      </div>
    </div>
  );
}

export interface Revealed {
  title: string;
  description: string;
  values: { label: string; value: string }[];
}

/** Modal for reveal-once values; closing it is the only way on. */
export function RevealModal({ revealed, onClose }: { revealed: Revealed | null; onClose: () => void }) {
  return (
    <Modal open={revealed !== null} onOpenChange={(o) => !o && onClose()} title={revealed?.title ?? ""} description={revealed?.description}>
      <div className="flex flex-col gap-4 px-5 pb-5 pt-3">
        {revealed?.values.map((v) => (
          <Secret key={v.label} label={v.label} value={v.value} />
        ))}
        <p className="text-[0.8125rem] text-muted">This is the only time it is shown. Store it now; rotate it later if it is lost.</p>
        <div className="flex justify-end">
          <Button variant="primary" onClick={onClose}>
            I have stored it
          </Button>
        </div>
      </div>
    </Modal>
  );
}
