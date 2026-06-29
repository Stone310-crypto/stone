import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";

export interface ModuleInfo {
  name: string;
  display_name: string;
  description: string;
  available: boolean;
  built_in: boolean;
  file_path: string | null;
  download_url: string;
  size_mb: number;
  icon: string;
}

/** Hook: Lädt die Modul-Liste vom Rust-Backend. */
export function useModules() {
  const [modules, setModules] = useState<ModuleInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setLoading(true);
      const mods = await invoke<ModuleInfo[]>("get_modules");
      setModules(mods);
      setError(null);
    } catch (e: any) {
      setError(e?.message ?? String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  /** Core-Module (immer verfügbar) */
  const coreModules = modules.filter((m) =>
    ["messenger", "wallet", "explorer", "node-manager"].includes(m.name)
  );

  /** Optionale Module (Gaming, Node) */
  const optionalModules = modules.filter(
    (m) => !["messenger", "wallet", "explorer", "node-manager"].includes(m.name)
  );

  return {
    modules,
    coreModules,
    optionalModules,
    loading,
    error,
    refresh,
    /** Prüft ob ein bestimmtes Modul verfügbar ist */
    isAvailable: (name: string) => modules.find((m) => m.name === name)?.available ?? false,
  };
}

/** Lädt ein optionales Modul herunter (via externen Download-Link). */
export async function downloadModule(moduleInfo: ModuleInfo): Promise<void> {
  // Öffne den Download-Link im Browser
  const { openUrl } = await import("@tauri-apps/plugin-opener");
  await openUrl(moduleInfo.download_url);
}
