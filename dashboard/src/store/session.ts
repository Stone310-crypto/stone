import type { Session, NodeSettings } from "../types/api";

const SESSION_KEY = "stone_session";
const SETTINGS_KEY = "stone_settings";

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
  nodeUrl: "http://127.0.0.1:13080",
  label: "Stonechain Desktop Node",
};

export function loadSettings(): NodeSettings {
  try {
    const raw = localStorage.getItem(SETTINGS_KEY);
    return raw ? { ...defaultSettings, ...JSON.parse(raw) } : { ...defaultSettings };
  } catch {
    return { ...defaultSettings };
  }
}

export function saveSettings(s: NodeSettings): void {
  localStorage.setItem(SETTINGS_KEY, JSON.stringify(s));
}
