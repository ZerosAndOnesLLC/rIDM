"use client";

import { useEffect, useState, type RefObject } from "react";

export interface RowWindow {
  /** Rows to render, with their offset from the top of the list. */
  items: { index: number; start: number; size: number }[];
  totalSize: number;
}

/**
 * Windowing for a long list of fixed-height rows: only the rows inside the
 * scroll element's viewport (plus `overscan` either side) are rendered.
 */
export function useRowWindow(count: number, rowHeight: number, scrollRef: RefObject<HTMLElement | null>, overscan = 10): RowWindow {
  const [view, setView] = useState({ top: 0, height: 800 });

  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    const measure = () => setView({ top: el.scrollTop, height: el.clientHeight });
    const onScroll = () => setView((v) => (v.top === el.scrollTop ? v : { ...v, top: el.scrollTop }));
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    el.addEventListener("scroll", onScroll, { passive: true });
    return () => {
      ro.disconnect();
      el.removeEventListener("scroll", onScroll);
    };
  }, [scrollRef]);

  const first = Math.max(0, Math.floor(view.top / rowHeight) - overscan);
  const last = Math.min(count - 1, Math.ceil((view.top + view.height) / rowHeight) + overscan);
  const items = [];
  for (let index = first; index <= last; index += 1) items.push({ index, start: index * rowHeight, size: rowHeight });
  return { items, totalSize: count * rowHeight };
}
