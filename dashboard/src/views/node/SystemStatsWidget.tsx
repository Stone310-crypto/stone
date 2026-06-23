import { useState, useEffect } from "react";
import { Cpu, Thermometer, Activity } from "lucide-react";

interface NodeStats {
  cpu_usage: number;
  cpu_temp: number;
  memory_used: number;
  memory_total: number;
}

export default function SystemStatsWidget() {
  const [stats, setStats] = useState<NodeStats | null>(null);

  useEffect(() => {
    let active = true;
    const fetchStats = async () => {
      try {
        const resp = await fetch("http://127.0.0.1:3080/api/v1/system-stats", {
          headers: { "x-api-key": "stone-local-dev" },
        });
        if (!resp.ok) return;
        const data = await resp.json();
        if (active) setStats(data);
      } catch {}
    };
    fetchStats();
    const id = setInterval(fetchStats, 5000);
    return () => { active = false; clearInterval(id); };
  }, []);

  if (!stats) return null;

  return (
    <div className="flex items-center gap-4 px-3 py-1 text-xs"
         style={{ color: "var(--text-muted)", fontFamily: "monospace" }}>
      <span className="flex items-center gap-1">
        <Cpu size={12} /> {stats.cpu_usage.toFixed(0)}%
      </span>
      {stats.cpu_temp > 0 && (
        <span className="flex items-center gap-1">
          <Thermometer size={12} /> {stats.cpu_temp.toFixed(0)}°C
        </span>
      )}
      <span className="flex items-center gap-1">
        <Activity size={12} /> {(stats.memory_used / 1024).toFixed(0)}/{(stats.memory_total / 1024).toFixed(0)} GB
      </span>
    </div>
  );
}