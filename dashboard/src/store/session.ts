import type { Session, NodeSettings } from "../types/api";

const SESSION_KEY = "stone_session";
const SETTINGS_KEY = "stone_settings";
const NETWORK_MODE_KEY = "stone-network-mode";

export function loadSession(): Session | null {
  try {
    const raw = localStorage.getItem(SESSION_KEY);
    return raw ? (JSON.parse(raw) as Session) : null;
  } catch {
    return null;
  }
}

export function saveSession(s: Session): void {
  localStorage.setItem(SESSION_KEY, JSON.stringify(s));
}

export function clearSession(): void {
  localStorage.removeItem(SESSION_KEY);
}

const defaultSettings: NodeSettings = {
  nodeUrl: "http://127.0.0.1:3180",
  label: "Stonechain Desktop Node",
  network: "mainnet",
};

/** Load settings, syncing network from stone-network-mode if present. */
export function loadSettings(): NodeSettings {
  try {
    const raw = localStorage.getItem(SETTINGS_KEY);
    const stored = raw ? { ...defaultSettings, ...JSON.parse(raw) } : { ...defaultSettings };

    // Sync network from the dedicated stone-network-mode key (set by extension/testnet banner)
    const networkMode = localStorage.getItem(NETWORK_MODE_KEY);
    if (networkMode === "testnet" || networkMode === "mainnet") {
      stored.network = networkMode;
      if (networkMode === "testnet" && stored.nodeUrl === defaultSettings.nodeUrl) {
        stored.nodeUrl = "http://127.0.0.1:3080";
      } else if (networkMode === "mainnet" && stored.nodeUrl === "http://127.0.0.1:3080") {
        stored.nodeUrl = "http://127.0.0.1:3180";
      }
    }

    return stored;
  } catch {
    return { ...defaultSettings };
  }
}

/** Save settings and also sync network to stone-network-mode. */
export function saveSettings(s: NodeSettings): void {
  localStorage.setItem(SETTINGS_KEY, JSON.stringify(s));
  // Keep stone-network-mode in sync so extension & banner agree
  if (s.network === "testnet" || s.network === "mainnet") {
    try { localStorage.setItem(NETWORK_MODE_KEY, s.network); } catch { /* ignore */ }
  }
}
