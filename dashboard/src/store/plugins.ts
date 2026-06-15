import type { PluginInstance, PluginManifest } from "../types/plugin";

const PLUGINS_KEY = "stone_plugins";

export function loadPlugins(): PluginInstance[] {
  try {
    const raw = localStorage.getItem(PLUGINS_KEY);
    return raw ? (JSON.parse(raw) as PluginInstance[]) : [];
  } catch {
    return [];
  }
}

export function savePlugins(plugins: PluginInstance[]): void {
  localStorage.setItem(PLUGINS_KEY, JSON.stringify(plugins));
}

export function addPlugin(instance: PluginInstance): PluginInstance[] {
  const plugins = loadPlugins();
  plugins.push(instance);
  savePlugins(plugins);
  return plugins;
}

export function removePlugin(instanceId: string): PluginInstance[] {
  const plugins = loadPlugins().filter((p) => p.instance_id !== instanceId);
  savePlugins(plugins);
  return plugins;
}

export function updatePlugin(
  instanceId: string,
  partial: Partial<PluginInstance>
): PluginInstance[] {
  const plugins = loadPlugins().map((p) =>
    p.instance_id === instanceId ? { ...p, ...partial } : p
  );
  savePlugins(plugins);
  return plugins;
}

export function getPluginByChannel(
  channelId: string
): PluginInstance | undefined {
  return loadPlugins().find(
    (p) => p.enabled && p.config.channel_id === channelId
  );
}

// ── Built-in Plugin Registry ────────────────────────────────────────────────

const BUILTIN_REGISTRY: PluginManifest[] = [
  {
    plugin_id: "iframe-web-embed",
    name: "Website Embed",
    version: "1.0.0",
    type: "iframe",
    description:
      "Integriere eine beliebige Website als iFrame in einen Channel.",
    config_schema: {
      url: {
        type: "string",
        label: "Website URL",
        placeholder: "https://example.com",
      },
      width: {
        type: "number",
        label: "Breite (px)",
        default: 800,
      },
      height: {
        type: "number",
        label: "Höhe (px)",
        default: 600,
      },
      channel_id: {
        type: "string",
        label: "Channel-ID",
        placeholder: "channel-uuid-hier-einfügen",
      },
    },
    manifest: {
      permissions: ["web.request"],
      content_security_policy: "frame-src *;",
    },
  },
];

/** Look up a plugin manifest by plugin_id in the built-in registry. */
export function getPluginManifest(
  pluginId: string
): PluginManifest | undefined {
  return BUILTIN_REGISTRY.find((m) => m.plugin_id === pluginId);
}

/** Return all available plugin manifests (built-in registry). */
export function listAvailablePlugins(): PluginManifest[] {
  return BUILTIN_REGISTRY;
}

/** Generate a unique instance id */
export function newInstanceId(pluginId: string): string {
  const rand = Math.random().toString(36).substring(2, 8);
  return `${pluginId}-${rand}`;
}