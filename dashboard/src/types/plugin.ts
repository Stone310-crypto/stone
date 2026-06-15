// ── Plugin System Types ────────────────────────────────────────────────────

export type PluginType = "iframe" | "widget";

export interface PluginConfigField {
  type: "string" | "number";
  label: string;
  placeholder?: string;
  default?: string | number;
}

export interface PluginManifest {
  plugin_id: string;
  name: string;
  version: string;
  type: PluginType;
  description?: string;
  icon?: string;
  config_schema: Record<string, PluginConfigField>;
  manifest: {
    permissions?: string[];
    content_security_policy?: string;
  };
}

/** A plugin that has been installed with user-provided configuration */
export interface PluginInstance {
  /** Unique instance id (plugin_id + random suffix) */
  instance_id: string;
  plugin_id: string;
  name: string;
  version: string;
  type: PluginType;
  /** User-provided config values */
  config: Record<string, string | number>;
  /** When the plugin was installed (Unix ms) */
  installed_at: number;
  /** Whether the plugin is active */
  enabled: boolean;
}