import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Download, Star, Trash2, Check, Loader2, Package, Shield, User } from "lucide-react";

interface ExtensionManifest {
  id: string;
  name: string;
  description: string;
  version: string;
  icon: string;
  rating: number;
  reviews: number;
  downloads: number;
  size_mb: number;
  repository: string;
  permissions: string[];
  author: string;
}

export default function ExtensionsView() {
  const [available, setAvailable] = useState<ExtensionManifest[]>([]);
  const [installed, setInstalled] = useState<ExtensionManifest[]>([]);
  const [loading, setLoading] = useState(true);
  const [installing, setInstalling] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setLoading(true);
      const [avail, inst] = await Promise.all([
        invoke<ExtensionManifest[]>("get_available_extensions"),
        invoke<ExtensionManifest[]>("get_installed_extensions"),
      ]);
      setAvailable(avail);
      setInstalled(inst);
      setError(null);
    } catch (e: any) {
      setError(e?.message ?? String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const handleInstall = async (id: string) => {
    try {
      setInstalling(id);
      await invoke<ExtensionManifest>("cmd_install_extension", { id });
      await load(); // Refresh lists
    } catch (e: any) {
      setError(e?.message ?? String(e));
    } finally {
      setInstalling(null);
    }
  };

  const handleUninstall = async (id: string, name: string) => {
    if (!confirm(`Möchtest du "${name}" wirklich deinstallieren?`)) return;
    try {
      await invoke("cmd_uninstall_extension", { id });
      await load();
    } catch (e: any) {
      setError(e?.message ?? String(e));
    }
  };

  const installedIds = new Set(installed.map((e) => e.id));

  if (loading) {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", color: "var(--text-muted)" }}>
        <Loader2 size={24} style={{ animation: "spin 1s linear infinite" }} />
      </div>
    );
  }

  return (
    <div style={{ padding: 24, height: "100%", overflow: "auto", color: "var(--text-primary)" }}>
      {/* ── Header ─────────────────────────────────────────────────── */}
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, margin: 0, marginBottom: 4 }}>🧩 Erweiterungen</h1>
        <p style={{ color: "var(--text-secondary)", fontSize: 13, margin: 0 }}>
          Optimiere dein Dashboard mit zusätzlichen Modulen aus dem Stone Extension-Store.
        </p>
      </div>

      {error && (
        <div style={{
          background: "rgba(239,68,68,0.12)", border: "1px solid rgba(239,68,68,0.3)",
          borderRadius: 10, padding: "10px 14px", marginBottom: 16,
          color: "var(--red)", fontSize: 12,
        }}>
          {error}
        </div>
      )}

      {/* ── Verfügbare Erweiterungen ────────────────────────────────── */}
      <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 12, display: "flex", alignItems: "center", gap: 8 }}>
        <Package size={18} /> Verfügbare Erweiterungen
        <span style={{ fontSize: 12, fontWeight: 400, color: "var(--text-muted)" }}>
          ({available.length})
        </span>
      </h2>

      <div style={{ display: "flex", flexDirection: "column", gap: 8, marginBottom: 28 }}>
        {available.map((ext) => {
          const isInstalled = installedIds.has(ext.id);
          return (
            <div
              key={ext.id}
              style={{
                display: "flex", alignItems: "center", gap: 14,
                background: isInstalled ? "rgba(34,197,94,0.06)" : "var(--bg-panel)",
                border: `1px solid ${isInstalled ? "rgba(34,197,94,0.2)" : "var(--border)"}`,
                borderRadius: 12, padding: "14px 16px",
                transition: "all 0.15s",
              }}
            >
              {/* Icon */}
              <div style={{
                width: 44, height: 44, borderRadius: 10,
                background: "rgba(255,255,255,0.06)", display: "flex",
                alignItems: "center", justifyContent: "center",
                fontSize: 22, flexShrink: 0,
              }}>
                {ext.icon}
              </div>

              {/* Info */}
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 2 }}>
                  <h3 style={{ fontSize: 14, fontWeight: 600, margin: 0 }}>{ext.name}</h3>
                  <span style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "monospace" }}>
                    v{ext.version}
                  </span>
                </div>
                <p style={{ fontSize: 12, color: "var(--text-secondary)", margin: 0, marginBottom: 4 }}>
                  {ext.description}
                </p>
                <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
                  {/* Rating */}
                  <span style={{ display: "flex", alignItems: "center", gap: 3, fontSize: 11, color: "var(--text-muted)" }}>
                    <Star size={12} style={{ color: "var(--accent)" }} />
                    {ext.rating} ({ext.reviews})
                  </span>
                  {/* Downloads */}
                  <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
                    👤 {ext.downloads.toLocaleString()} Downloads
                  </span>
                  {/* Size */}
                  <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
                    📦 {ext.size_mb} MB
                  </span>
                  {/* Author */}
                  {ext.author && (
                    <span style={{ display: "flex", alignItems: "center", gap: 3, fontSize: 11, color: "var(--text-muted)" }}>
                      <User size={11} /> {ext.author}
                    </span>
                  )}
                  {/* Permissions */}
                  {ext.permissions.length > 0 && (
                    <span style={{ display: "flex", alignItems: "center", gap: 3, fontSize: 11, color: "var(--text-muted)" }}>
                      <Shield size={11} /> {ext.permissions.join(", ")}
                    </span>
                  )}
                </div>
              </div>

              {/* Actions */}
              <div style={{ display: "flex", gap: 6, flexShrink: 0 }}>
                {isInstalled ? (
                  <>
                    <button
                      disabled
                      style={{
                        display: "flex", alignItems: "center", gap: 4,
                        padding: "8px 14px", borderRadius: 8,
                        background: "rgba(34,197,94,0.15)", border: "none",
                        color: "var(--green)", fontSize: 12, fontWeight: 600,
                        cursor: "default",
                      }}
                    >
                      <Check size={14} /> Installiert
                    </button>
                    <button
                      onClick={() => handleUninstall(ext.id, ext.name)}
                      style={{
                        display: "flex", alignItems: "center", gap: 4,
                        padding: "8px 14px", borderRadius: 8,
                        background: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.2)",
                        color: "var(--red)", fontSize: 12, fontWeight: 500,
                        cursor: "pointer",
                      }}
                    >
                      <Trash2 size={14} /> Deinstallieren
                    </button>
                  </>
                ) : (
                  <button
                    onClick={() => handleInstall(ext.id)}
                    disabled={installing === ext.id}
                    style={{
                      display: "flex", alignItems: "center", gap: 4,
                      padding: "8px 16px", borderRadius: 8,
                      background: installing === ext.id ? "rgba(212,168,83,0.3)" : "var(--accent)",
                      border: "none", color: "var(--text-inverse)",
                      fontSize: 12, fontWeight: 600, cursor: installing === ext.id ? "wait" : "pointer",
                    }}
                  >
                    {installing === ext.id ? (
                      <><Loader2 size={14} style={{ animation: "spin 1s linear infinite" }} /> Installiere…</>
                    ) : (
                      <><Download size={14} /> Installieren</>
                    )}
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* ── Installierte Erweiterungen ──────────────────────────────── */}
      {installed.length > 0 && (
        <>
          <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 12, display: "flex", alignItems: "center", gap: 8 }}>
            📋 Installierte Erweiterungen
            <span style={{ fontSize: 12, fontWeight: 400, color: "var(--text-muted)" }}>
              ({installed.length})
            </span>
          </h2>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
            {installed.map((ext) => (
              <div
                key={ext.id}
                style={{
                  display: "flex", alignItems: "center", gap: 8,
                  background: "var(--bg-panel)", border: "1px solid var(--border)",
                  borderRadius: 8, padding: "8px 12px",
                }}
              >
                <span style={{ fontSize: 16 }}>{ext.icon}</span>
                <span style={{ fontSize: 12, fontWeight: 500 }}>{ext.name}</span>
                <span style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "monospace" }}>
                  v{ext.version}
                </span>
                <button
                  onClick={() => handleUninstall(ext.id, ext.name)}
                  title="Deinstallieren"
                  style={{
                    width: 24, height: 24, borderRadius: 6,
                    background: "rgba(239,68,68,0.08)", border: "none",
                    color: "var(--red)", cursor: "pointer",
                    display: "flex", alignItems: "center", justifyContent: "center",
                  }}
                >
                  <Trash2 size={12} />
                </button>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
