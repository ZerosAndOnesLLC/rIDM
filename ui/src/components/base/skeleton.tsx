/**
 * Placeholder for content still loading. It is a `role="status"` that says
 * "Loading…" to assistive tech, which is also what the accessibility sweep
 * waits on before it audits a page, so a page is never checked mid-fetch.
 */
export function Skeleton({
  shape = "lines",
  count = 3,
  label = "Loading…",
  className = "",
}: {
  /** `lines` of text, table `rows`, or one `block`. */
  shape?: "lines" | "rows" | "block";
  count?: number;
  label?: string;
  className?: string;
}) {
  const bars = Array.from({ length: shape === "block" ? 1 : count }, (_, i) => i);
  return (
    <div role="status" aria-busy className={`animate-pulse ${className}`}>
      <span className="sr-only">{label}</span>
      {shape === "block" ? (
        <div aria-hidden className="h-24 rounded-[var(--radius)] bg-line" />
      ) : shape === "rows" ? (
        <div aria-hidden className="divide-y divide-line rounded-[var(--radius)] border border-line">
          {bars.map((i) => (
            <div key={i} className="flex min-h-[var(--row-h)] items-center gap-3 px-4">
              <span className="size-7 shrink-0 rounded-full bg-line" />
              <span className="h-3 flex-1 rounded bg-line" style={{ maxWidth: `${55 - (i % 3) * 10}%` }} />
              <span className="ms-auto h-3 w-16 rounded bg-line" />
            </div>
          ))}
        </div>
      ) : (
        <div aria-hidden className="flex flex-col gap-2.5 py-1">
          {bars.map((i) => (
            <span key={i} className="block h-3 rounded bg-line" style={{ width: `${90 - (i % 3) * 20}%` }} />
          ))}
        </div>
      )}
    </div>
  );
}
