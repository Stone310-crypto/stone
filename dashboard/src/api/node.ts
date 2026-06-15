import { invoke } from "@tauri-apps/api/core";

export interface NodeConfig {
  enabled: boolean;
  port: number;
  cpu_pct: number;
  binary_path: string;
  seed_peers: string;
}

export type NodeStatus =
  | { status: "stopped" }
  | { status: "starting" }
  | { status: "running"; port: number; pid: number }
  | { status: "error"; message: string }
  | { status: "binary_not_found" };

// Parse the tagged enum Rust returns
export function parseNodeStatus(raw: unknown): NodeStatus {
  if (typeof raw === "string") {
    if (raw === "stopped") return { status: "stopped" };
    if (raw === "starting") return { status: "starting" };
    if (raw === "binary_not_found") return { status: "binary_not_found" };
  }
  if (typeof raw === "object" && raw !== null) {
    const obj = raw as Record<string, unknown>;
    if ("running" in obj) {
      const r = obj["running"] as { port: number; pid: number };
      return { status: "running", port: r.port, pid: r.pid };
    }
    if ("error" in obj) {
      return { status: "error", message: String((obj["error"] as { message: string }).message) };
    }
  }
  return { status: "stopped" };
}

async function tauriInvoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(cmd, args);
  } catch (e) {
    throw new Error(String(e));
  }
}

export const nodeManager = {
  getStatus: async (): Promise<NodeStatus> => {
    const raw = await tauriInvoke<unknown>("node_get_status");
    return parseNodeStatus(raw);
  },

  getConfig: (): Promise<NodeConfig> => tauriInvoke("node_get_config"),

  setConfig: (config: NodeConfig): Promise<void> =>
    tauriInvoke("node_set_config", { config }),

  start: (): Promise<string> => tauriInvoke("node_start"),

  stop: (): Promise<void> => tauriInvoke("node_stop"),
};
