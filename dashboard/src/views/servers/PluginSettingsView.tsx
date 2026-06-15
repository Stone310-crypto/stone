import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plug, Trash2, Power, PowerOff, X, Plus } from "lucide-react";
import type { PluginInstance, PluginConfigField } from "../../types/plugin";
import {
  loadPlugins,
  addPlugin,
  removePlugin,
  updatePlugin,
  getPluginManifest,
  listAvailablePlugins,
  newInstanceId,
} from "../../store/plugins";
import { orgs } from "../../api/stone";
import PluginRenderer from "../../components/plugins/PluginRenderer";

interface PluginSettingsViewProps {
  orgId: string;
}

export default function PluginSettingsView({ orgId }: PluginSettingsViewProps) {
  const [plugins, setPlugins] = useState<PluginInstance[]>(loadPlugins);
  const [importId, setImportId] = useState("");
  const [importError, setImportError] = useState("");
  const [selectedPlugin, setSelectedPlugin] = useState<string | null>(null);
  const [showImport, setShowImport] = useState(false);
  const [showCreateCh, setShowCreateCh] = useState(false);
  const [newChName, setNewChName] = useState("");
  const qc = useQueryClient();

  const detailQ = useQuery({
    queryKey: ["org", orgId],
    queryFn: () => orgs.detail(orgId),
    enabled: !!orgId,
    refetchInterval: 15_000,
  });
  const raw = detailQ.data as any;
  const channels: { id: string; name: string; category_id?: string }[] =
    (raw?.channels ?? [])
      .map((c: any) => ({ id: c.id ?? "", name: c.name ?? "", category_id: c.category_id ?? "" }))
      .filter((c: any) => c.id);

  const createChMt = useMutation({
    mutationFn: (name: string) => orgs.createChannel(orgId, name, "", "text"),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["org", orgId] });
      setShowCreateCh(false);
      setNewChName("");
    },
  });

  useEffect(() => {
    setPlugins(loadPlugins());
  }, []);

  function handleImport() {
    const clean = importId.trim();
    if (!clean) return;
    const manifest = getPluginManifest(clean);
    if (!manifest) {
      setImportError(
        `Plugin-ID "${clean}" nicht gefunden. Verfügbar: ${listAvailablePlugins()
          .map((m) => m.plugin_id)
          .join(", ")}`
      );
      return;
    }
    if (plugins.some((p) => p.plugin_id === manifest.plugin_id)) {
      setImportError(`Plugin "${manifest.name}" ist bereits installiert.`);
      return;
    }
    const defaultConfig: Record<string, string | number> = {};
    for (const [key, field] of Object.entries(manifest.config_schema)) {
      defaultConfig[key] = field.default ?? (field.type === "number" ? 0 : "");
    }
    const instance: PluginInstance = {
      instance_id: newInstanceId(manifest.plugin_id),
      plugin_id: manifest.plugin_id,
      name: manifest.name,
      version: manifest.version,
      type: manifest.type,
      config: defaultConfig,
      installed_at: Date.now(),
      enabled: true,
    };
    const updated = addPlugin(instance);
    setPlugins(updated);
    setImportId("");
    setImportError("");
    setShowImport(false);
    setSelectedPlugin(instance.instance_id);
  }

  function handleToggle(instanceId: string) {
    const updated = updatePlugin(instanceId, {
      enabled: !plugins.find((p) => p.instance_id === instanceId)?.enabled,
    });
    setPlugins(updated);
  }

  function handleRemove(instanceId: string) {
    const updated = removePlugin(instanceId);
    setPlugins(updated);
    if (selectedPlugin === instanceId) setSelectedPlugin(null);
  }

  function handleConfigChange(instanceId: string, key: string, value: string | number) {
    const p = plugins.find((p2) => p2.instance_id === instanceId);
    if (!p) return;
    const updated = updatePlugin(instanceId, { config: { ...p.config, [key]: value } });
    setPlugins(updated);
  }

  const selected = plugins.find((p) => p.instance_id === selectedPlugin);
  const manifest = selected ? getPluginManifest(selected.plugin_id) : null;

  // Render config field — channel_id gets a dropdown, others get <input>
  function renderConfigField(
    key: string,
    field: PluginConfigField,
    val: string | number,
    instanceId: string
  ) {
    if (key === "channel_id") {
      return (
        <div key={key}>
          <label style={{ fontSize: 11, fontWeight: 500, color: "var(--text-secondary)", marginBottom: 4, display: "block" }}>
            {field.label}
          </label>
          <div style={{ display: "flex", gap: 6 }}>
            <select
              value={String(val)}
              onChange={(e) => handleConfigChange(instanceId, key, e.target.value)}
              style={{
                flex: 1,
                background: "var(--bg-input)",
                border: "1px solid var(--border-default)",
                borderRadius: 6,
                padding: "6px 8px",
                fontSize: 12,
                color: "var(--text-primary)",
                outline: "none",
                fontFamily: "monospace",
              }}
            >
              <option value="">— Channel wählen —</option>
              {channels.map((ch) => (
                <option key={ch.id} value={ch.id}>
                  # {ch.name}
                </option>
              ))}
            </select>
            <button
              onClick={() => setShowCreateCh(true)}
              title="Neuen Channel erstellen"
              style={{
                padding: "6px 10px",
                borderRadius: 6,
                background: "var(--accent-bg)",
                border: "1px solid rgba(212,168,83,0.3)",
                color: "var(--accent)",
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                gap: 4,
                fontSize: 11,
                fontWeight: 500,
                whiteSpace: "nowrap",
              }}
            >
              <Plus size={12} /> Neu
            </button>
          </div>
        </div>
      );
    }

    return (
      <div key={key}>
        <label style={{ fontSize: 11, fontWeight: 500, color: "var(--text-secondary)", marginBottom: 4, display: "block" }}>
          {field.label}
        </label>
        <input
          type={field.type === "number" ? "number" : "text"}
          value={val}
          onChange={(e) =>
            handleConfigChange(instanceId, key, field.type === "number" ? Number(e.target.value) : e.target.value)
          }
          placeholder={field.placeholder}
          style={{
            width: "100%",
            background: "var(--bg-input)",
            border: "1px solid var(--border-default)",
            borderRadius: 6,
            padding: "6px 10px",
            fontSize: 12,
            color: "var(--text-primary)",
            outline: "none",
            fontFamily: key === "url" ? "monospace" : "inherit",
          }}
        />
      </div>
    );
  }

  // Create channel modal
  if (showCreateCh) {
    return (
      <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.6)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 200 }}>
        <div style={{ background: "var(--bg-panel)", borderRadius: 16, padding: 24, width: 400, border: "1px solid var(--border-strong)" }}>
          <h2 style={{ fontSize: 18, fontWeight: 700, marginBottom: 16 }}>Channel erstellen</h2>
          <div style={{ marginBottom: 16 }}>
            <label style={{ fontSize: 12, fontWeight: 500, color: "var(--text-secondary)", marginBottom: 6, display: "block" }}>Channel-Name</label>
            <input
              type="text" value={newChName} onChange={(e) => setNewChName(e.target.value)}
              placeholder="plugin-channel" autoFocus
              style={{ width: "100%", background: "var(--bg-input)", border: "1px solid var(--border-default)", borderRadius: 8, padding: "8px 12px", fontSize: 13, color: "var(--text-primary)", outline: "none" }}
            />
          </div>
          <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
            <button onClick={() => setShowCreateCh(false)} style={{ padding: "10px 20px", borderRadius: 8, border: "1px solid var(--border-default)", color: "var(--text-secondary)", cursor: "pointer", fontSize: 13, background: "transparent" }}>Abbrechen</button>
            <button
              onClick={() => { if (newChName.trim()) createChMt.mutate(newChName.trim()); }}
              disabled={!newChName.trim() || createChMt.isPending}
              style={{ padding: "10px 20px", borderRadius: 8, background: (!newChName.trim() || createChMt.isPending) ? "rgba(212,168,83,0.3)" : "var(--accent)", color: "var(--text-inverse)", cursor: (!newChName.trim() || createChMt.isPending) ? "not-allowed" : "pointer", border: "none", fontSize: 13, fontWeight: 600 }}
            >{createChMt.isPending ? <span style={{ display: "inline-block", width: 14, height: 14, border: "2px solid rgba(255,255,255,0.3)", borderTopColor: "#fff", borderRadius: "50%", animation: "spin 0.7s linear infinite" }} /> : "Erstellen"}</button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
        <div>
          <h3 style={{ fontSize: 14, fontWeight: 600, color: "var(--accent)" }}>Plugins</h3>
          <p style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 4 }}>Erweitere deine Server um iFrames und Widgets.</p>
        </div>
        <button onClick={() => setShowImport(!showImport)}
          style={{
            padding: "8px 14px", borderRadius: 8,
            background: showImport ? "var(--bg-surface)" : "var(--accent-bg)",
            border: showImport ? "1px solid var(--border-default)" : "1px solid rgba(212,168,83,0.3)",
            color: showImport ? "var(--text)" : "var(--accent)",
            cursor: "pointer", fontSize: 12, fontWeight: 600, display: "flex", alignItems: "center", gap: 6,
          }}
        >
          {showImport ? <><X size={14} /> Abbrechen</> : <><Plus size={14} /> Plugin importieren</>}
        </button>
      </div>

      {showImport && (
        <div style={{ background: "var(--bg-surface)", borderRadius: 10, border: "1px solid var(--border-default)", padding: 16, marginBottom: 20 }}>
          <label style={{ fontSize: 12, fontWeight: 500, color: "var(--text-secondary)", marginBottom: 8, display: "block" }}>Plugin-ID eingeben</label>
          <div style={{ display: "flex", gap: 8 }}>
            <input type="text" value={importId} onChange={(e) => { setImportId(e.target.value); setImportError(""); }} placeholder="iframe-web-embed" autoFocus onKeyDown={(e) => { if (e.key === "Enter") handleImport(); }}
              style={{ flex: 1, background: "var(--bg-input)", border: "1px solid var(--border-default)", borderRadius: 8, padding: "8px 12px", fontSize: 13, color: "var(--text-primary)", outline: "none", fontFamily: "monospace" }}
            />
            <button onClick={handleImport} disabled={!importId.trim()}
              style={{ padding: "8px 16px", borderRadius: 8, background: importId.trim() ? "var(--accent)" : "var(--bg-hover)", color: importId.trim() ? "#fff" : "var(--text-muted)", border: "none", cursor: importId.trim() ? "pointer" : "not-allowed", fontSize: 12, fontWeight: 600 }}
            >Installieren</button>
          </div>
          {importError && <div style={{ marginTop: 8, padding: "8px 12px", borderRadius: 6, background: "rgba(237,66,69,0.1)", border: "1px solid rgba(237,66,69,0.3)", color: "var(--red)", fontSize: 12 }}>{importError}</div>}
          <div style={{ marginTop: 10, fontSize: 11, color: "var(--text-muted)" }}>
            Verfügbare Plugins:{" "}
            {listAvailablePlugins().map((m) => (
              <code key={m.plugin_id} onClick={() => { setImportId(m.plugin_id); setImportError(""); }}
                style={{ background: "var(--bg-hover)", borderRadius: 4, padding: "1px 6px", cursor: "pointer", marginRight: 4, fontFamily: "monospace", fontSize: 11 }}
                title={`${m.name} v${m.version} — ${m.description}`}
              >{m.plugin_id}</code>
            ))}
          </div>
        </div>
      )}

      {plugins.length === 0 ? (
        <div style={{ textAlign: "center", padding: "40px 24px", color: "var(--text-muted)" }}>
          <Plug size={32} style={{ marginBottom: 8, opacity: 0.2 }} />
          <p style={{ fontSize: 13, fontWeight: 600 }}>Keine Plugins installiert</p>
          <p style={{ fontSize: 11, marginTop: 4 }}>Importiere dein erstes Plugin über die Plugin-ID.</p>
        </div>
      ) : (
        <div style={{ display: "flex", gap: 16 }}>
          <div style={{ width: 220, flexShrink: 0, display: "flex", flexDirection: "column", gap: 4 }}>
            {plugins.map((p) => (
              <button key={p.instance_id} onClick={() => setSelectedPlugin(p.instance_id)}
                style={{
                  width: "100%", padding: "10px 12px", borderRadius: 8, textAlign: "left",
                  background: selectedPlugin === p.instance_id ? "var(--bg-hover)" : "transparent",
                  border: selectedPlugin === p.instance_id ? "1px solid var(--border-strong)" : "1px solid transparent",
                  color: "var(--text)", cursor: "pointer", fontSize: 12, display: "flex", alignItems: "center", gap: 8,
                }}
              >
                <div style={{ width: 8, height: 8, borderRadius: "50%", background: p.enabled ? "var(--green)" : "var(--text-muted)", flexShrink: 0 }} />
                <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{p.name}</span>
                <button onClick={(e) => { e.stopPropagation(); handleRemove(p.instance_id); }}
                  style={{ background: "none", border: "none", color: "var(--text-muted)", cursor: "pointer", padding: 2 }} title="Entfernen"
                ><Trash2 size={12} /></button>
              </button>
            ))}
          </div>

          <div style={{ flex: 1, background: "var(--bg-surface)", borderRadius: 10, border: "1px solid var(--border-default)", padding: 16, minHeight: 300 }}>
            {selected && manifest ? (
              <div>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16 }}>
                  <div>
                    <h4 style={{ fontSize: 14, fontWeight: 700 }}>{selected.name} <span style={{ fontSize: 11, fontWeight: 400, color: "var(--text-muted)" }}>v{selected.version}</span></h4>
                    <p style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2, fontFamily: "monospace" }}>{selected.plugin_id}</p>
                  </div>
                  <button onClick={() => handleToggle(selected.instance_id)}
                    style={{
                      padding: "6px 14px", borderRadius: 8,
                      background: selected.enabled ? "rgba(237,66,69,0.1)" : "rgba(59,165,92,0.1)",
                      border: selected.enabled ? "1px solid rgba(237,66,69,0.3)" : "1px solid rgba(59,165,92,0.3)",
                      color: selected.enabled ? "var(--red)" : "var(--green)",
                      cursor: "pointer", display: "flex", alignItems: "center", gap: 6, fontSize: 12, fontWeight: 500,
                    }}
                  >
                    {selected.enabled ? <><PowerOff size={12} /> Deaktiviert</> : <><Power size={12} /> Aktiviert</>}
                  </button>
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 12, marginBottom: 20 }}>
                  <h5 style={{ fontSize: 11, fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.05em" }}>Konfiguration</h5>
                  {Object.entries(manifest.config_schema).map(([key, field]) =>
                    renderConfigField(key, field as PluginConfigField, selected.config[key] ?? "", selected.instance_id)
                  )}
                </div>
                {selected.enabled && (
                  <div>
                    <h5 style={{ fontSize: 11, fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 10 }}>Vorschau</h5>
                    <div style={{ position: "relative" }}>
                      <PluginRenderer plugin={selected} />
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", color: "var(--text-muted)", fontSize: 13 }}>
                {plugins.length === 0 ? "Keine Plugins installiert." : "Wähle ein Plugin aus der Liste."}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}