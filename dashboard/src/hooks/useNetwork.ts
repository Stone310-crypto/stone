/// Network-aware API hook for switching between mainnet and testnet endpoints.

/** Returns the current network mode and API endpoints. */
export type NetworkMode = "mainnet" | "testnet" | "unknown";

export interface NetworkConfig {
  mode: NetworkMode;
  mainnetUrl: string;
  testnetUrl: string;
  activeUrl: string;
  chainId: string;
  blockHeight: number;
  peerCount: number;
}

const STORAGE_KEY = "stone-network-mode";

/** Get the persisted network preference. */
export function getStoredNetwork(): NetworkMode {
  try {
    return (localStorage.getItem(STORAGE_KEY) as NetworkMode) || "mainnet";
  } catch {
    return "mainnet";
  }
}

/** Persist the network preference. */
export function setStoredNetwork(mode: NetworkMode): void {
  try {
    localStorage.setItem(STORAGE_KEY, mode);
  } catch {
    // ignore
  }
}

/** Build network-aware API URL for a given path. */
export function apiUrl(path: string, _mode?: NetworkMode): string {
  // The extension manages switching via localStorage
  const base = window.location.origin;
  return `${base}${path}`;
}

/** Feature flags gated by network mode. */
export function isFeatureEnabled(feature: string, mode?: NetworkMode): boolean {
  const network = mode || getStoredNetwork();

  // Features that work on BOTH networks
  const alwaysEnabled = ["chat", "messenger", "servers", "files", "storage", "profile", "settings"];
  if (alwaysEnabled.includes(feature)) return true;

  // Features that are MAINNET only (disable in testnet with warning)
  const mainnetOnly = ["coins", "tokens", "send", "wallet-send", "companies", "nft", "items", "market", "staking", "rewards", "game-register"];
  if (mainnetOnly.includes(feature)) {
    return network !== "testnet";
  }

  // Features that are TESTNET only (experimental)
  const testnetOnly = ["experimental", "testnet-dashboard"];
  if (testnetOnly.includes(feature)) {
    return network === "testnet";
  }

  return true;
}

/** Returns true if the feature should show a testnet warning overlay. */
export function needsTestnetWarning(feature: string, mode?: NetworkMode): boolean {
  const network = mode || getStoredNetwork();
  if (network !== "testnet") return false;
  const mainnetOnly = ["coins", "tokens", "send", "wallet-send", "companies", "nft", "items", "market", "staking", "rewards", "game-register"];
  return mainnetOnly.includes(feature);
}
