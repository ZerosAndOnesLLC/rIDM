"use client";

import { Loader2, Search } from "lucide-react";
import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { Modal } from "./ui";

export interface PickerItem {
  id: string;
  /** Group heading the item is listed under. */
  group: string;
  icon?: ReactNode;
  label: string;
  hint?: string;
  /** Trailing detail, e.g. a keyboard shortcut. */
  trailing?: ReactNode;
  onSelect: () => void;
}

/**
 * A searchable list in a modal (command palette, tenant switcher): one text
 * field driving a listbox, arrow keys to move, Enter to pick.
 */
export function Picker({
  open,
  onOpenChange,
  title,
  placeholder,
  query,
  onQueryChange,
  items,
  loading = false,
  empty,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  placeholder: string;
  query: string;
  onQueryChange: (q: string) => void;
  items: PickerItem[];
  loading?: boolean;
  empty: string;
}) {
  const [active, setActive] = useState(0);
  const listId = useId();
  const listRef = useRef<HTMLUListElement>(null);

  // Results may shrink under the cursor between renders.
  const cursor = Math.min(active, Math.max(0, items.length - 1));
  useEffect(() => {
    listRef.current?.querySelector<HTMLElement>(`[data-index="${cursor}"]`)?.scrollIntoView({ block: "nearest" });
  }, [cursor]);
  const pick = (i: number) => {
    const it = items[i];
    if (!it) return;
    onOpenChange(false);
    it.onSelect();
  };

  const groups: { name: string; items: { item: PickerItem; index: number }[] }[] = [];
  items.forEach((item, index) => {
    let g = groups.find((x) => x.name === item.group);
    if (!g) {
      g = { name: item.group, items: [] };
      groups.push(g);
    }
    g.items.push({ item, index });
  });
  const activeId = items[cursor] ? `${listId}-${items[cursor].id}` : undefined;

  return (
    <Modal open={open} onOpenChange={onOpenChange} title={title} hideTitle size="lg">
      <div className="flex items-center gap-3 border-b border-line px-4">
        <Search className="size-4 shrink-0 text-muted" aria-hidden />
        <input
          autoFocus
          role="combobox"
          aria-expanded
          aria-controls={listId}
          aria-activedescendant={activeId}
          aria-label={title}
          aria-autocomplete="list"
          value={query}
          onChange={(e) => {
            setActive(0);
            onQueryChange(e.target.value);
          }}
          onKeyDown={(e) => {
            if (e.key === "ArrowDown") {
              e.preventDefault();
              setActive((a) => Math.min(items.length - 1, a + 1));
            } else if (e.key === "ArrowUp") {
              e.preventDefault();
              setActive((a) => Math.max(0, a - 1));
            } else if (e.key === "Enter") {
              e.preventDefault();
              pick(cursor);
            }
          }}
          placeholder={placeholder}
          className="min-h-12 w-full bg-transparent text-[0.9375rem] text-ink outline-none placeholder:text-muted/70"
        />
        {loading && <Loader2 className="size-4 animate-spin text-muted" aria-hidden />}
      </div>
      <ul ref={listRef} id={listId} role="listbox" aria-label={title} className="overflow-y-auto p-2">
        {items.length === 0 && !loading && <li className="px-3 py-6 text-center text-[0.875rem] text-muted">{empty}</li>}
        {groups.map((g) => (
          <li key={g.name} role="presentation">
            <div className="px-3 pb-1 pt-2 text-[0.6875rem] font-semibold uppercase tracking-wide text-muted" aria-hidden>
              {g.name}
            </div>
            <ul role="group" aria-label={g.name}>
              {g.items.map(({ item, index }) => (
                <li
                  key={item.id}
                  id={`${listId}-${item.id}`}
                  role="option"
                  aria-selected={index === cursor}
                  data-index={index}
                  onMouseEnter={() => setActive(index)}
                  onMouseDown={(e) => e.preventDefault()}
                  onClick={() => pick(index)}
                  className={`flex cursor-pointer items-center gap-3 rounded-[var(--radius)] px-3 py-2 text-[0.9rem] ${
                    index === cursor ? "bg-[color-mix(in_oklab,var(--accent)_12%,transparent)] text-ink" : "text-ink"
                  }`}
                >
                  {item.icon && <span className="flex size-5 shrink-0 items-center justify-center text-muted">{item.icon}</span>}
                  <span className="min-w-0 flex-1 truncate">
                    {item.label}
                    {item.hint && <span className="ms-2 text-[0.8125rem] text-muted">{item.hint}</span>}
                  </span>
                  {item.trailing && <span className="shrink-0 text-muted">{item.trailing}</span>}
                </li>
              ))}
            </ul>
          </li>
        ))}
      </ul>
    </Modal>
  );
}
