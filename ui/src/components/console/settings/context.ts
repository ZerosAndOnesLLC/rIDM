"use client";

import { createContext, useContext } from "react";
import type { SettingsPatch, Tenant } from "@/lib/console/settings";

export interface SettingsEditor {
  draft: Tenant;
  /** The administrator may change settings (otherwise the form is read-only). */
  editable: boolean;
  global: boolean;
  /** Patch `settings` in the draft and queue it for saving. */
  update: (patch: SettingsPatch) => void;
  /** Patch top-level tenant fields. */
  updateTenant: (patch: { display_name?: string; status?: "active" | "disabled" }) => void;
}

export const SettingsContext = createContext<SettingsEditor | null>(null);

export function useSettingsEditor(): SettingsEditor {
  const ctx = useContext(SettingsContext);
  if (!ctx) throw new Error("useSettingsEditor must be used inside the settings page");
  return ctx;
}
