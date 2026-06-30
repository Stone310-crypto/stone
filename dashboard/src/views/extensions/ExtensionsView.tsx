import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { ask } from "@tauri-apps/plugin-dialog";
import { triggerModuleRefresh } from "../../hooks/useModules";
import { Download, Trash2, Check, Loader2, Package, Shield, User, RefreshCw, Paintbrush, Eye } from "lucide-react";

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
  category?: string;
}

interface SavedThemeInfo {
  name: string;
  path: string;
  size: number;
}

export default function ExtensionsView() {
  const [available, setAvailable] = useState<ExtensionManifest[]>([]);
  const [installed, setInstalled] = useState<ExtensionManifest[]>([]);
  const [loadingInstalled, setLoadingInstalled] = useState(true);
  const [loadingStore, setLoadingStore] = useState(true);
  const [installing, setInstalling] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [myRatings, setMyRatings] = useState<Record<string, number>>({});
  const [updates, setUpdates] = useState<Record<string, string>>({});
  const [activeTab, setActiveTab] = useState<"extensions" | "designs">("extensions");
  const [savedThemes, setSavedThemes] = useState<SavedThemeInfo[]>([]);
  const [loadingSavedThemes, setLoadingSavedThemes] = useState(false);

  // Filtere nach Kategorie
  const filteredAvailable = available.filter((ext) => {
    if (activeTab === "designs") return ext.category === "theme";
    return ext.category !== "theme"; // extensions = alles außer themes
  });

  // Installierte Extensions laden (lokal, schnell)
  const loadInstalled = useCallback(async () => {
    try {
      const inst = await invoke<ExtensionManifest[]>("get_installed_extensions");
      setInstalled(inst);

      // Check for updates
      try {
        const updatesList = await invoke<[string, string, string][]>("check_for_updates");
        const updateMap: Record<string, string> = {};
        for (const [id, , newVer] of updatesList) {
          updateMap[id] = newVer;
        }
        setUpdates(updateMap);
      } catch {
        // Update check ist optional
      }
      setError(null);
    } catch (e: any) {
      setError(e?.message ?? String(e));
    } finally {
      setLoadingInstalled(false);
    }
  }, []);

  // Store laden (Netzwerk, langsam — im Hintergrund)
  const loadStore = useCallback(async () => {
    try {
      const avail = await invoke<ExtensionManifest[]>("get_available_extensions");
      setAvailable(avail);
    } catch (e: any) {
      // Store-Fehler sind nicht kritisch — Fallback wird im Backend geliefert
      console.warn("[extensions] Store nicht erreichbar:", e);
    } finally {
      setLoadingStore(false);
    }
  }, []);

  // Beim Mount: installierte sofort, Store parallel
  useEffect(() => {
    loadInstalled();
    loadStore();
  }, [loadInstalled, loadStore]);

  // Lokale Themes laden wenn Designs-Tab aktiv
  useEffect(() => {
    if (activeTab === "designs") {
      loadSavedThemes();
    }
  }, [activeTab]);

  const loadSavedThemes = async () => {
    setLoadingSavedThemes(true);
    try {
      const themes = await invoke<SavedThemeInfo[]>("list_saved_themes");
      setSavedThemes(themes);
    } catch {
      // Nicht kritisch
    } finally {
      setLoadingSavedThemes(false);
    }
  };

  const handleInstall = async (id: string) => {
    try {
      setInstalling(id);
      setError(null);
      await invoke<ExtensionManifest>("cmd_install_extension", { id });
      await loadInstalled(); // Nur installierte neu laden (schnell)
      triggerModuleRefresh();
    } catch (e: any) {
      setError(e?.message ?? String(e));
    } finally {
      setInstalling(null);
    }
  };

  const handleUninstall = async (id: string, name: string) => {
    const ok = await ask(`Möchtest du "${name}" wirklich deinstallieren?`, {
      title: "Extension deinstallieren",
      kind: "warning",
    });
    if (!ok) return;
    try {
      setError(null);
      await invoke("cmd_uninstall_extension", { id });
      await loadInstalled(); // Nur installierte neu laden (schnell)
      triggerModuleRefresh();
    } catch (e: any) {
      setError(e?.message ?? String(e));
    }
  };
  const handleDeleteSavedTheme = async (name: string) => {
    const ok = await ask(`Möchtest du das Design "${name}" wirklich löschen?`, {
      title: "Design löschen",
      kind: "warning",
    });
    if (!ok) return;
    try {
      await invoke("delete_saved_theme", { name });
      await loadSavedThemes();
    } catch (e: any) {
      setError(e?.message ?? String(e));
    }
  };

  const handleApplyLocalTheme = async (name: string) => {
    try {
      const css = await invoke<string>("load_saved_theme", { name });
      await invoke("write_theme_css", { extensionId: "theme-editor", css });
      localStorage.setItem("stone-theme", "theme-editor");
      const styleEl = document.getElementById("stone-theme-css") as HTMLStyleElement | null;
      if (styleEl) styleEl.textContent = css;
      else {
        const el = document.createElement("style");
        el.id = "stone-theme-css";
        el.textContent = css;
        document.head.appendChild(el);
      }
      triggerModuleRefresh();
    } catch (e: any) {
      setError(e?.message ?? String(e));
    }
  };

  const handleRate = async (extId: string, stars: number) => {
    try {
      const [newRating, newReviews] = await invoke<[number, number]>("rate_extension", {
        extensionId: extId,
        rating: stars,
      });
      // Update available list with new rating
      setAvailable((prev) =>
        prev.map((e) =>
          e.id === extId ? { ...e, rating: newRating, reviews: newReviews } : e
        )
      );
      setMyRatings((prev) => ({ ...prev, [extId]: stars }));
    } catch (e: any) {
      console.warn("[extensions] Bewertung fehlgeschlagen:", e);
    }
  };
  const installedIds = new Set(installed.map((e) => e.id));

  // Lade-Indikator nur wenn BEIDE noch laden
  if (loadingInstalled && loadingStore) {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", color: "var(--text-muted)", flexDirection: "column", gap: 12 }}>
        <Loader2 size={24} style={{ animation: "spin 1s linear infinite" }} />
        <span style={{ fontSize: 13 }}>Extensions werden geladen…</span>
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

        {/* Tabs */}
        <div style={{ display: "flex", gap: 4, marginTop: 14, marginBottom: 16 }}>
          {[
            ["extensions", "🧩 Extensions"],
            ["designs", "🎨 Designs"],
          ].map(([id, label]) => (
            <button
              key={id}
              onClick={() => setActiveTab(id as "extensions" | "designs")}
              style={{
                padding: "6px 16px", borderRadius: 8,
                background: activeTab === id ? "var(--accent)" : "transparent",
                color: activeTab === id ? "#000" : "var(--text-secondary)",
                border: activeTab === id ? "none" : "1px solid var(--border)",
                cursor: "pointer", fontSize: 12, fontWeight: 600,
              }}
            >
              {label}
            </button>
          ))}
        </div>
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
          ({filteredAvailable.length})
        </span>
        {loadingStore && (
          <Loader2 size={14} style={{ animation: "spin 1s linear infinite", color: "var(--text-muted)" }} />
        )}
      </h2>

      <div style={{ display: "flex", flexDirection: "column", gap: 8, marginBottom: 28 }}>
        {filteredAvailable.map((ext) => {
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
                  {/* Rating — interaktive Sterne */}
                  <span style={{ display: "flex", alignItems: "center", gap: 3, fontSize: 11 }}>
                    {[1, 2, 3, 4, 5].map((star) => {
                      const filled = star <= Math.round(ext.rating);
                      const myRating = myRatings[ext.id];
                      return (
                        <span
                          key={star}
                          onClick={() => handleRate(ext.id, star)}
                          title={myRating ? `Deine Bewertung: ${myRating}★` : `${star} Sterne bewerten`}
                          style={{
                            cursor: "pointer",
                            color: filled ? "var(--accent)" : "var(--text-muted)",
                            fontSize: 14,
                            transition: "transform 0.1s",
                            userSelect: "none",
                          }}
                          onMouseEnter={(e) => {
                            (e.currentTarget as HTMLElement).style.transform = "scale(1.2)";
                          }}
                          onMouseLeave={(e) => {
                            (e.currentTarget as HTMLElement).style.transform = "scale(1)";
                          }}
                        >
                          {filled ? "★" : "☆"}
                        </span>
                      );
                    })}
                    <span style={{ color: "var(--text-muted)", marginLeft: 2 }}>
                      {ext.rating > 0 ? `${ext.rating.toFixed(1)} (${ext.reviews})` : "—"}
                    </span>
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
                    {updates[ext.id] ? (
                      <button
                        onClick={() => handleInstall(ext.id)}
                        disabled={installing === ext.id}
                        style={{
                          display: "flex", alignItems: "center", gap: 4,
                          padding: "8px 14px", borderRadius: 8,
                          background: installing === ext.id ? "rgba(59,130,246,0.3)" : "rgba(59,130,246,0.15)",
                          border: "1px solid rgba(59,130,246,0.3)",
                          color: "#3b82f6", fontSize: 12, fontWeight: 600,
                          cursor: installing === ext.id ? "wait" : "pointer",
                        }}
                      >
                        {installing === ext.id ? (
                          <><Loader2 size={14} style={{ animation: "spin 1s linear infinite" }} /> Update…</>
                        ) : (
                          <><RefreshCw size={14} /> Update auf v{updates[ext.id]}</>
                        )}
                      </button>
                    ) : (
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
                    )}
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

      {/* ── Meine Designs (lokal gespeichert) ──────────────────────── */}
      {activeTab === "designs" && (
        <>
          <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 12, display: "flex", alignItems: "center", gap: 8 }}>
            <Paintbrush size={18} /> Meine Designs
            <span style={{ fontSize: 12, fontWeight: 400, color: "var(--text-muted)" }}>
              ({savedThemes.length})
            </span>
            {loadingSavedThemes && (
              <Loader2 size={14} style={{ animation: "spin 1s linear infinite", color: "var(--text-muted)" }} />
            )}
          </h2>
          {savedThemes.length === 0 && !loadingSavedThemes ? (
            <div style={{
              padding: "24px", textAlign: "center", color: "var(--text-muted)",
              background: "var(--bg-panel)", borderRadius: 12, border: "1px dashed var(--border)",
              marginBottom: 20, fontSize: 13,
            }}>
              <Paintbrush size={24} style={{ marginBottom: 8, opacity: 0.4 }} />
              <p>Noch keine eigenen Designs gespeichert.</p>
              <p style={{ fontSize: 11, marginTop: 4 }}>
                Öffne den Theme-Editor und speichere dein erstes Design mit "💾 Speichern".
              </p>
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 8, marginBottom: 20 }}>
              {savedThemes.map((theme) => (
                <div
                  key={theme.name}
                  style={{
                    display: "flex", alignItems: "center", gap: 14,
                    background: "var(--bg-panel)", border: "1px solid var(--border)",
                    borderRadius: 12, padding: "12px 16px",
                  }}
                >
                  <div style={{
                    width: 44, height: 44, borderRadius: 10,
                    background: "linear-gradient(135deg, var(--accent), var(--green))",
                    display: "flex", alignItems: "center", justifyContent: "center",
                    fontSize: 22, flexShrink: 0,
                  }}>
                    🎨
                  </div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <h3 style={{ fontSize: 14, fontWeight: 600, margin: 0 }}>{theme.name}</h3>
                    <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
                      {(theme.size / 1024).toFixed(1)} KB
                    </span>
                  </div>
                  <div style={{ display: "flex", gap: 6, flexShrink: 0 }}>
                    <button
                      onClick={() => handleApplyLocalTheme(theme.name)}
                      style={{
                        display: "flex", alignItems: "center", gap: 4,
                        padding: "8px 14px", borderRadius: 8,
                        background: "var(--accent)", border: "none",
                        color: "var(--text-inverse)", fontSize: 12, fontWeight: 600,
                        cursor: "pointer",
                      }}
                    >
                      <Eye size={14} /> Anwenden
                    </button>
                    <button
                      onClick={() => handleDeleteSavedTheme(theme.name)}
                      style={{
                        display: "flex", alignItems: "center", gap: 4,
                        padding: "8px 14px", borderRadius: 8,
                        background: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.2)",
                        color: "var(--red)", fontSize: 12, fontWeight: 500,
                        cursor: "pointer",
                      }}
                    >
                      <Trash2 size={14} />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </>
      )}

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
