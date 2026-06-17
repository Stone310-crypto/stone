import { useState, useEffect } from "react";

export interface SystemStats {
  system_cpu_pct: number;
  system_memory_used_mb: number;
  system_memory_total_mb: number;
  app_cpu_pct: number;
  app_memory_mb: number;
}

let cached: SystemStats | null = null;
let lastFetch = 0;

async function fetchStats(): Promise<SystemStats | null> {
  const now = Date.now();
  if (cached && now - lastFetch < 2000) return cached;

  try {
    const { invoke } = await import("@tauri-apps/api/core");
    const stats: SystemStats = await invoke("get_system_stats");
    cached = stats;
    lastFetch = now;
    return stats;
  } catch {
    return null;
  }
}

export function useSystemStats(refreshMs = 3000) {
  const [stats, setStats] = useState<SystemStats | null>(null);

  useEffect(() => {
    let active = true;

    const poll = async () => {
      const s = await fetchStats();
      if (active) setStats(s);
    };

    poll();
    const id = setInterval(poll, refreshMs);
    return () => {
      active = false;
      clearInterval(id);
    };
  }, [refreshMs]);

  return stats;
}