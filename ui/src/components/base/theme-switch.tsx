"use client";

import { Monitor, Moon, Sun } from "lucide-react";
import { useTheme, type Theme } from "@/lib/theme/provider";

export interface ThemeLabels {
  group: string;
  system: string;
  light: string;
  dark: string;
}

/** The console's English labels; the localized surfaces pass their own. */
const DEFAULT_LABELS: ThemeLabels = { group: "Theme", system: "Follow system theme", light: "Light theme", dark: "Dark theme" };

const THEMES: { value: Theme; icon: typeof Sun }[] = [
  { value: "system", icon: Monitor },
  { value: "light", icon: Sun },
  { value: "dark", icon: Moon },
];

/**
 * Light / dark / follow-the-device, as a pressed-button group. Renders
 * nothing when the tenant does not let people override its mode. `bar`
 * draws it for the dark command bar, `paper` for a light surface.
 */
export function ThemeSwitch({ surface = "paper", className = "", labels = DEFAULT_LABELS }: { surface?: "paper" | "bar"; className?: string; labels?: ThemeLabels }) {
  const { theme, setTheme, policy } = useTheme();
  if (!policy.allowSwitch) return null;
  const bar = surface === "bar";
  return (
    <div
      role="group"
      aria-label={labels.group}
      className={`flex items-center gap-0.5 rounded-full p-0.5 ${bar ? "border border-[var(--bar-line)] bg-[var(--bar-field)]" : "border border-line bg-ground"} ${className}`}
    >
      {THEMES.map((t) => {
        const on = theme === t.value;
        const label = labels[t.value];
        return (
          <button
            key={t.value}
            type="button"
            aria-label={label}
            title={label}
            aria-pressed={on}
            onClick={() => setTheme(t.value)}
            className={`flex size-7 items-center justify-center rounded-full transition-colors ${
              bar ? (on ? "bg-bar-ink text-bar" : "text-bar-muted hover:text-bar-ink") : on ? "bg-paper text-ink shadow-sm" : "text-muted hover:text-ink"
            }`}
          >
            <t.icon className="size-3.5" aria-hidden />
          </button>
        );
      })}
    </div>
  );
}
