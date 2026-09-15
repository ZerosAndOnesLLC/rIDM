"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  useSyncExternalStore,
  type ReactNode,
} from "react";
import { DEFAULT_LOCALE, dir, negotiate, translate, type MessageKey, type Params } from "./index";

interface I18n {
  locale: string;
  dir: "ltr" | "rtl";
  t: (key: MessageKey | string, params?: Params) => string;
  /** Switch language, e.g. to the server's negotiated `locale` or a picker's choice. */
  setLocale: (locale: string | null | undefined) => void;
}

const I18nContext = createContext<I18n | null>(null);

function subscribeToLanguage(onChange: () => void): () => void {
  window.addEventListener("languagechange", onChange);
  return () => window.removeEventListener("languagechange", onChange);
}
const browserLocale = () => negotiate(navigator.languages);
const serverLocale = () => DEFAULT_LOCALE;

/**
 * Provides translations and keeps `<html lang dir>` in sync. Until a page
 * calls `setLocale` with the flow's negotiated locale, the browser's own
 * languages decide (the static export knows nothing at build time; the
 * prerendered HTML is English and hydrates without mismatch).
 */
export function I18nProvider({ children, initial }: { children: ReactNode; initial?: string }) {
  const fromBrowser = useSyncExternalStore(subscribeToLanguage, browserLocale, serverLocale);
  const [chosen, setChosen] = useState<string | null>(initial ?? null);
  const locale = chosen ?? fromBrowser;

  useEffect(() => {
    const html = document.documentElement;
    html.lang = locale;
    html.dir = dir(locale);
  }, [locale]);

  const setLocale = useCallback((next: string | null | undefined) => {
    setChosen(next ? negotiate([next]) : null);
  }, []);

  const value = useMemo<I18n>(
    () => ({
      locale,
      dir: dir(locale),
      t: (key, params) => translate(locale, key, params),
      setLocale,
    }),
    [locale, setLocale],
  );

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n(): I18n {
  const ctx = useContext(I18nContext);
  if (!ctx) throw new Error("useI18n must be used inside <I18nProvider>");
  return ctx;
}
