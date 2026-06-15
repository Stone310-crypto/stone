import type { PluginInstance } from "../../types/plugin";
import IframePlugin from "./IframePlugin";

interface PluginRendererProps {
  plugin: PluginInstance;
}

export default function PluginRenderer({ plugin }: PluginRendererProps) {
  switch (plugin.type) {
    case "iframe":
      return <IframePlugin plugin={plugin} />;
    default:
      return (
        <div
          style={{
            background: "var(--bg-surface)",
            borderRadius: 12,
            padding: 24,
            textAlign: "center",
            color: "var(--text-muted)",
            fontSize: 13,
            border: "1px solid var(--border-subtle)",
          }}
        >
          Unbekannter Plugin-Typ: {plugin.type}
        </div>
      );
  }
}