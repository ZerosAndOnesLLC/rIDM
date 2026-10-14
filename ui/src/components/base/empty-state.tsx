import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";

/** A list or tab with nothing in it yet: what it is for, and the way to start. */
export function EmptyState({
  icon: Icon,
  title,
  description,
  action,
  compact = false,
}: {
  icon?: LucideIcon;
  title: string;
  description?: ReactNode;
  action?: ReactNode;
  /** Less vertical room, for a tab or a card body. */
  compact?: boolean;
}) {
  return (
    <div className={`flex flex-col items-center gap-2 px-6 text-center ${compact ? "py-6" : "py-12"}`}>
      {Icon && (
        <span aria-hidden className="mb-1 flex size-10 items-center justify-center rounded-full bg-accent-soft text-accent-text">
          <Icon className="size-5" />
        </span>
      )}
      <p className="text-md font-semibold text-ink">{title}</p>
      {description && <p className="max-w-sm text-small text-muted">{description}</p>}
      {action && <div className="mt-2 flex flex-wrap justify-center gap-2">{action}</div>}
    </div>
  );
}
