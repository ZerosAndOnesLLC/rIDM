"use client";

import { CheckCircle2, Info, X, XCircle } from "lucide-react";
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { iconButtonClass } from "./button";

export type ToastTone = "ok" | "error" | "info";

export interface ToastOptions {
  title: string;
  description?: ReactNode;
  tone?: ToastTone;
  /** Milliseconds on screen; 0 keeps it until dismissed. Errors stay longer. */
  duration?: number;
}

interface ToastItem extends ToastOptions {
  id: number;
  tone: ToastTone;
}

interface ToastApi {
  toast: (options: ToastOptions) => void;
  dismiss: (id: number) => void;
}

const ToastContext = createContext<ToastApi | null>(null);

/**
 * Brief confirmations after an action ("Key revoked"). Each toast is its own
 * `role="status"`, announced when it appears, so the region is silent while
 * empty. Titles never say "Loading": the console's tests take a status that
 * does as a page still fetching. Mounted once per console layout.
 */
export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const timers = useRef(new Map<number, number>());
  const next = useRef(1);

  const dismiss = useCallback((id: number) => {
    const t = timers.current.get(id);
    if (t !== undefined) {
      window.clearTimeout(t);
      timers.current.delete(id);
    }
    setItems((list) => list.filter((x) => x.id !== id));
  }, []);

  const toast = useCallback(
    (options: ToastOptions) => {
      const id = next.current++;
      const tone = options.tone ?? "ok";
      // At most four on screen: the oldest makes room.
      setItems((list) => [...list.slice(-3), { ...options, id, tone }]);
      const duration = options.duration ?? (tone === "error" ? 8000 : 5000);
      if (duration > 0) timers.current.set(id, window.setTimeout(() => dismiss(id), duration));
    },
    [dismiss],
  );

  useEffect(() => {
    const pending = timers.current;
    return () => pending.forEach((t) => window.clearTimeout(t));
  }, []);

  const api = useMemo(() => ({ toast, dismiss }), [toast, dismiss]);
  return (
    <ToastContext.Provider value={api}>
      {children}
      <Toasts items={items} onDismiss={dismiss} />
    </ToastContext.Provider>
  );
}

export function useToast(): ToastApi {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast must be used inside <ToastProvider>");
  return ctx;
}

const ICON: Record<ToastTone, { icon: typeof Info; className: string }> = {
  ok: { icon: CheckCircle2, className: "text-ok" },
  error: { icon: XCircle, className: "text-danger" },
  info: { icon: Info, className: "text-link" },
};

function Toasts({ items, onDismiss }: { items: ToastItem[]; onDismiss: (id: number) => void }) {
  if (items.length === 0) return null;
  return (
    <section aria-label="Notifications" className="pointer-events-none fixed inset-x-0 bottom-4 z-[60] flex flex-col items-center gap-2 px-4">
      {items.map((t) => {
        const { icon: Icon, className } = ICON[t.tone];
        return (
          <div
            key={t.id}
            role="status"
            className="pointer-events-auto flex w-full max-w-md items-start gap-2.5 rounded-[var(--radius-lg)] border border-line bg-raised py-2.5 ps-3.5 pe-2 text-small text-ink shadow-pop"
          >
            <Icon className={`mt-0.5 size-4 shrink-0 ${className}`} aria-hidden />
            <div className="min-w-0 flex-1 py-0.5">
              <p className="font-medium">{t.title}</p>
              {t.description && <p className="mt-0.5 text-muted">{t.description}</p>}
            </div>
            <button type="button" aria-label="Dismiss" onClick={() => onDismiss(t.id)} className={iconButtonClass("sm")}>
              <X aria-hidden />
            </button>
          </div>
        );
      })}
    </section>
  );
}
