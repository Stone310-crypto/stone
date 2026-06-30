import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";

/** Hook: Theme-Engine — lädt und injiziert Theme-CSS. */
export function useTheme() {
  const [activeTheme, setActiveTheme] = useState<string | null>(
    () => localStorage.getItem("stone-theme") || null
  );

  // Theme-CSS laden und als <style>-Tag injizieren
  const applyTheme = useCallback(async (extensionId: string | null) => {
    let styleEl = document.getElementById("stone-theme-css") as HTMLStyleElement | null;
    if (!styleEl) {
      styleEl = document.createElement("style");
      styleEl.id = "stone-theme-css";
      document.head.appendChild(styleEl);
    }

    if (extensionId) {
      try {
        const css = await invoke<string | null>("get_theme_css", { extensionId });
        styleEl.textContent = css || "";
        setActiveTheme(extensionId);
        localStorage.setItem("stone-theme", extensionId);
      } catch {
        styleEl.textContent = "";
        setActiveTheme(null);
        localStorage.removeItem("stone-theme");
      }
    } else {
      styleEl.textContent = "";
      setActiveTheme(null);
      localStorage.removeItem("stone-theme");
    }
  }, []);

  // Beim Mount: gespeichertes Theme laden
  useEffect(() => {
    if (activeTheme) {
      applyTheme(activeTheme);
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  /** Installierte Themes abrufen */
  const loadInstalledThemes = useCallback(async () => {
    try {
      return await invoke<{ id: string; name: string; icon: string }[]>("list_themes");
    } catch {
      return [];
    }
  }, []);

  return { activeTheme, applyTheme, loadInstalledThemes };
}
