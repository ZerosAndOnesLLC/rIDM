"use client";

import { ArrowDown, ArrowUp, ArrowUpDown } from "lucide-react";
import Link from "next/link";
import { useEffect, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { useRowWindow } from "@/lib/console/virtual";
import { buttonClass } from "./button";
import { Skeleton } from "./skeleton";

export interface Column<T> {
  key: string;
  header: ReactNode;
  cell: (row: T) => ReactNode;
  /** Grid track; `minmax(8rem, 1fr)` when omitted. */
  width?: string;
  align?: "start" | "end";
  /** Clicking the header sorts by this column (the table needs `sort`). */
  sortable?: boolean;
  /** The header text is for assistive tech only (an actions column). */
  hideHeader?: boolean;
  className?: string;
}

export interface SortState {
  key: string;
  dir: "asc" | "desc";
}

export interface DataTableProps<T> {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  /** The table's accessible name ("Users"). */
  label: string;
  /** The first column links to the row's own page. */
  rowHref?: (row: T) => string;
  /** Shown instead of the table when there are no rows and nothing loading. */
  empty: ReactNode;
  /** Rows are on their way (skeleton rows while there are none yet). */
  loading?: boolean;
  /** The end of the loaded rows came into view: fetch the next page. */
  onEndReached?: () => void;
  sort?: { state: SortState | null; onChange: (next: SortState) => void };
  /** Checkbox column; `name` gives each checkbox its label. */
  selection?: { selected: ReadonlySet<string>; onChange: (next: Set<string>) => void; name: (row: T) => string };
  /** A `ListFooter`, below the rows. */
  footer?: ReactNode;
  /** Window the rows (thousands of them). Rows are then all `--row-h` tall. */
  virtualize?: boolean;
  /** Width below which the table scrolls sideways. */
  minWidth?: string;
  rowClass?: (row: T) => string;
  /** How many rows exist, when more than are loaded (`aria-rowcount`). */
  total?: number;
}

const CELL = "flex min-w-0 items-center";

/**
 * Every list in the consoles: a CSS grid with table semantics (`role=table`,
 * rows, cells), so a row is found by its text, columns keep their widths at
 * any row count, and long lists can be windowed. Loading and empty states
 * render in the table's place rather than inside it, which keeps the table's
 * required children valid.
 */
export function DataTable<T>({
  columns,
  rows,
  rowKey,
  label,
  rowHref,
  empty,
  loading = false,
  onEndReached,
  sort,
  selection,
  footer,
  virtualize = false,
  minWidth = "38rem",
  rowClass,
  total,
}: DataTableProps<T>) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const rowHeight = useRowHeight(scrollRef);
  const windowed = useRowWindow(virtualize ? rows.length : 0, rowHeight, scrollRef);
  const endRef = useRef<HTMLDivElement>(null);
  const onEnd = useRef(onEndReached);
  useEffect(() => {
    onEnd.current = onEndReached;
  });

  // Windowed: ask for more when the window nears the end of what is loaded.
  const lastVisible = windowed.items[windowed.items.length - 1]?.index ?? -1;
  useEffect(() => {
    if (virtualize && lastVisible >= rows.length - 20 && rows.length > 0) onEnd.current?.();
  }, [virtualize, lastVisible, rows.length]);

  // Page-scrolled: a sentinel after the last row.
  useEffect(() => {
    const el = endRef.current;
    if (virtualize || !el || !onEndReached) return;
    const io = new IntersectionObserver((entries) => {
      if (entries.some((e) => e.isIntersecting)) onEnd.current?.();
    });
    io.observe(el);
    return () => io.disconnect();
  }, [virtualize, onEndReached, rows.length]);

  if (loading && rows.length === 0) return <Skeleton shape="rows" count={6} />;
  if (!loading && rows.length === 0) return <>{empty}</>;

  const template = [selection ? "2.25rem" : null, ...columns.map((c) => c.width ?? "minmax(8rem, 1fr)")].filter(Boolean).join(" ");
  const allSelected = selection ? rows.length > 0 && rows.every((r) => selection.selected.has(rowKey(r))) : false;
  const someSelected = selection ? rows.some((r) => selection.selected.has(rowKey(r))) : false;

  const toggleAll = () => {
    if (!selection) return;
    const next = new Set(selection.selected);
    if (allSelected) rows.forEach((r) => next.delete(rowKey(r)));
    else rows.forEach((r) => next.add(rowKey(r)));
    selection.onChange(next);
  };

  const renderRow = (row: T, index: number, style?: React.CSSProperties) => {
    const key = rowKey(row);
    const selected = selection?.selected.has(key) ?? false;
    return (
      <div
        key={key}
        role="row"
        aria-rowindex={index + 2}
        aria-selected={selection ? selected : undefined}
        style={{ gridTemplateColumns: template, ...style }}
        className={`grid min-h-[var(--row-h)] items-center gap-3 border-b border-line px-4 text-body hover:bg-accent-soft aria-selected:bg-contrast-soft ${rowClass?.(row) ?? ""}`}
      >
        {selection && (
          <span role="cell" className={CELL}>
            <input
              type="checkbox"
              checked={selected}
              aria-label={`Select ${selection.name(row)}`}
              onChange={() => {
                const next = new Set(selection.selected);
                if (selected) next.delete(key);
                else next.add(key);
                selection.onChange(next);
              }}
              className="size-4 accent-[var(--contrast-solid)]"
            />
          </span>
        )}
        {columns.map((c, ci) => {
          const content = c.cell(row);
          return (
            <span key={c.key} role="cell" className={`${CELL} ${c.align === "end" ? "justify-end text-end" : ""} ${c.className ?? ""}`}>
              {ci === 0 && rowHref ? (
                <Link href={rowHref(row)} className="flex min-w-0 items-center gap-2.5 no-underline hover:underline underline-offset-4">
                  {content}
                </Link>
              ) : (
                content
              )}
            </span>
          );
        })}
      </div>
    );
  };

  const header = (
    <div role="row" aria-rowindex={1} style={{ gridTemplateColumns: template }} className="grid items-center gap-3 border-b border-line bg-ground px-4 py-2 text-caption font-semibold text-muted">
      {selection && (
        <span role="columnheader" className={CELL}>
          <input
            type="checkbox"
            checked={allSelected}
            ref={(el) => {
              if (el) el.indeterminate = !allSelected && someSelected;
            }}
            aria-label="Select all"
            onChange={toggleAll}
            className="size-4 accent-[var(--contrast-solid)]"
          />
        </span>
      )}
      {columns.map((c) => {
        const sorted = sort?.state?.key === c.key ? sort.state.dir : null;
        const Icon = sorted === "asc" ? ArrowUp : sorted === "desc" ? ArrowDown : ArrowUpDown;
        return (
          <span
            key={c.key}
            role="columnheader"
            aria-sort={sorted ? (sorted === "asc" ? "ascending" : "descending") : undefined}
            className={`${CELL} ${c.align === "end" ? "justify-end" : ""}`}
          >
            {sort && c.sortable ? (
              <button
                type="button"
                onClick={() => sort.onChange({ key: c.key, dir: sorted === "asc" ? "desc" : "asc" })}
                className={`inline-flex items-center gap-1 rounded hover:text-ink ${sorted ? "text-ink" : ""}`}
              >
                {c.header}
                <Icon className={`size-3 ${sorted ? "" : "opacity-60"}`} aria-hidden />
              </button>
            ) : c.hideHeader ? (
              <span className="sr-only">{c.header}</span>
            ) : (
              c.header
            )}
          </span>
        );
      })}
    </div>
  );

  return (
    <div className="flex flex-col gap-2">
      <div className="overflow-x-auto rounded-[var(--radius)] border border-line bg-paper">
        <div role="table" aria-label={label} aria-rowcount={total !== undefined ? total + 1 : rows.length + 1} style={{ minWidth }} className="text-body">
          {header}
          {virtualize ? (
            <div ref={scrollRef} className="max-h-[calc(100dvh-18rem)] overflow-y-auto">
              <div role="rowgroup" style={{ height: windowed.totalSize, position: "relative" }}>
                {windowed.items.map((v) =>
                  renderRow(rows[v.index]!, v.index, { position: "absolute", top: 0, left: 0, width: "100%", height: v.size, transform: `translateY(${v.start}px)` }),
                )}
              </div>
            </div>
          ) : (
            <div role="rowgroup" className="[&>[role=row]:last-child]:border-b-0">
              {rows.map((row, i) => renderRow(row, i))}
              <div ref={endRef} aria-hidden className="h-px" />
            </div>
          )}
        </div>
      </div>
      {footer}
    </div>
  );
}

/** The skin's row height (`--row-h` on the table), for windowing. */
function useRowHeight(ref: React.RefObject<HTMLElement | null>): number {
  const [h, setH] = useState(50);
  useLayoutEffect(() => {
    const el = ref.current ?? document.documentElement;
    const v = parseFloat(getComputedStyle(el).getPropertyValue("--row-h"));
    if (v > 0) setH(v);
  }, [ref]);
  return h;
}

export type ListFooterProps =
  | {
      /** Rows load as the person scrolls; the footer only reports. */
      mode: "auto";
      count: number;
      total?: number;
      hasMore: boolean;
      loading?: boolean;
      note?: ReactNode;
    }
  | {
      /** A "Load more" button. */
      mode: "more";
      count: number;
      total?: number;
      hasMore: boolean;
      loading?: boolean;
      onMore: () => void;
      note?: ReactNode;
    }
  | {
      /** Page by cursor, newest first. */
      mode: "cursor";
      count: number;
      canNewer: boolean;
      canOlder: boolean;
      loading?: boolean;
      onNewer: () => void;
      onOlder: () => void;
      note?: ReactNode;
    };

/**
 * Below a list: how much is loaded and how to get more. The button labels
 * ("Load more", "Newer", "Older") are what the tests click.
 */
export function ListFooter(props: ListFooterProps) {
  const { count, loading = false, note } = props;
  const sum =
    props.mode === "cursor"
      ? `${count} shown`
      : props.total !== undefined
        ? `${count} of ${props.total} loaded`
        : `${count}${props.hasMore ? "+" : ""} loaded`;
  return (
    <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 px-0.5 font-mono text-caption text-muted">
      <p aria-live="polite">
        {sum}
        {props.mode === "auto" && props.hasMore && !loading ? " · scroll for more" : ""}
        {loading && (
          <span role="status" className="ms-2">
            Loading more…
          </span>
        )}
      </p>
      {note && <span>{note}</span>}
      {props.mode === "more" && props.hasMore && (
        <button type="button" onClick={props.onMore} disabled={loading} className={buttonClass("secondary", "sm", "font-sans")}>
          {loading ? "Loading…" : "Load more"}
        </button>
      )}
      {props.mode === "cursor" && (
        <span className="flex gap-1.5">
          <button type="button" onClick={props.onNewer} disabled={!props.canNewer || loading} className={buttonClass("secondary", "sm", "font-sans")}>
            Newer
          </button>
          <button type="button" onClick={props.onOlder} disabled={!props.canOlder || loading} className={buttonClass("secondary", "sm", "font-sans")}>
            Older
          </button>
        </span>
      )}
    </div>
  );
}
