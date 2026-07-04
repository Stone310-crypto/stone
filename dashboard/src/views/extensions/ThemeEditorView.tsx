import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Paintbrush, Save, Check, RotateCcw, RefreshCw, Trash2, ChevronDown, ChevronRight } from "lucide-react";

interface ExtInfo { id: string; name: string; icon: string }
interface SavedTheme { name: string; path: string; size: number }
interface VarDef { n: string; d: string; l: string }
interface VarGroup { s: string; v: VarDef[] }
interface CompDef { id: string; name: string; css: string }

const VARS: VarGroup[] = [
  { s: "Hintergründe", v: [{ n: "--bg-root", d: "#0f1117", l: "Root" }, { n: "--bg-panel", d: "#1a1c26", l: "Panel" }, { n: "--bg-main", d: "#1e202a", l: "Main" }, { n: "--bg-input", d: "#2f3342", l: "Input" }] },
  { s: "Akzent", v: [{ n: "--accent", d: "#d4a853", l: "Primär" }, { n: "--accent-hover", d: "#e0b864", l: "Hover" }] },
  { s: "Farben", v: [{ n: "--green", d: "#5a9e6f", l: "Erfolg" }, { n: "--red", d: "#d95b5b", l: "Fehler" }, { n: "--blue", d: "#6b9cc4", l: "Info" }] },
  { s: "Text", v: [{ n: "--text-primary", d: "#e8e4df", l: "Primär" }, { n: "--text-secondary", d: "#b8b4ae", l: "Sekundär" }, { n: "--text-muted", d: "#6e6b65", l: "Gedimmt" }, { n: "--text-inverse", d: "#0f1117", l: "Invers" }] },
  { s: "Rahmen", v: [{ n: "--border-default", d: "rgba(255,255,255,0.08)", l: "Default" }, { n: "--border-strong", d: "rgba(255,255,255,0.12)", l: "Strong" }] },
];

const COMPS: CompDef[] = [
  { id: "global", name: "🌐 Global", css: "" }, { id: "wallet", name: "💰 Wallet", css: "" },
  { id: "chat", name: "💬 Chat", css: "" }, { id: "settings", name: "⚙️ Settings", css: "" },
  { id: "navbar", name: "🧭 NavBar", css: "" }, { id: "explorer", name: "🔍 Explorer", css: "" },
  { id: "profile", name: "👤 Profil", css: "" },
];

function hexFromCSS(c: string): string {
  if (c.startsWith("#")) return c;
  const ctx = document.createElement("canvas").getContext("2d");
  if (!ctx) return "#000"; ctx.fillStyle = c; return ctx.fillStyle || "#000";
}

function previewHTML(active: string): string {
  if (active === "global") return `<div class="pv-nav"><span class="pv-nav-item">💬 Chat</span><span class="pv-nav-item pv-active">💰 Wallet</span><span class="pv-nav-item">🔍 Explorer</span></div><div style="display:grid;grid-template-columns:1fr 1fr;gap:8px"><div class="pv-card"><h3>💰 Balance</h3><div class="pv-val">1.234 STONE</div></div><div class="pv-card"><h3>🔗 Block</h3><div class="pv-val">#42</div></div></div><div class="pv-card"><h3>TXs</h3><div class="pv-row"><span>TX abc...</span><span style="color:var(--green)">+50</span></div><div class="pv-row"><span>TX def...</span><span style="color:var(--red)">-10</span></div></div><div style="display:flex;gap:8px;margin-top:8px"><input class="pv-input" placeholder="Empfänger..." style="flex:1"><button class="pv-btn">Senden</button></div>`;
  if (active === "wallet") return `<h3 style="margin-bottom:8px">💰 Wallet</h3><div class="pv-card"><h3>Balance</h3><div class="pv-val">1.234 STONE</div></div><div class="pv-card"><h3>TXs</h3><div class="pv-row"><span>TX abc...</span><span style="color:var(--green)">+50</span></div><div class="pv-row"><span>TX def...</span><span style="color:var(--red)">-10</span></div></div><div style="display:flex;gap:8px"><input class="pv-input" placeholder="Wallet" style="flex:1"><button class="pv-btn">Senden</button></div>`;
  if (active === "chat") return `<h3 style="margin-bottom:8px">💬 Chat</h3><div class="pv-card"><span style="color:var(--accent)">User1:</span> Hey!</div><div class="pv-card"><span style="color:var(--accent)">User2:</span> Alles gut!</div><div style="display:flex;gap:8px;margin-top:8px"><input class="pv-input" placeholder="Nachricht..." style="flex:1"><button class="pv-btn">Senden</button></div>`;
  if (active === "settings") return `<h3 style="margin-bottom:8px">⚙️ Settings</h3><div class="pv-card"><div class="pv-row"><span>Name</span><span>Alice</span></div><div class="pv-row"><span>Sprache</span><span>Deutsch</span></div></div><div style="display:flex;gap:8px"><input class="pv-input" placeholder="Name" style="flex:1"><button class="pv-btn">Speichern</button></div>`;
  if (active === "navbar") return `<h3 style="margin-bottom:8px">🧭 NavBar</h3><div class="pv-nav"><span class="pv-nav-item">🏠 Home</span><span class="pv-nav-item">💬 Chat</span><span class="pv-nav-item pv-active">💰 Wallet</span><span class="pv-nav-item">🔍 Explorer</span></div><div class="pv-card"><div class="pv-val">Seite: Wallet</div></div>`;
  if (active === "explorer") return `<h3 style="margin-bottom:8px">🔍 Explorer</h3><div class="pv-card"><div class="pv-row"><span>Hash</span><span style="font-family:monospace;color:var(--text-muted)">0xabc...</span></div><div class="pv-row"><span>TXs</span><span style="color:var(--green)">12</span></div></div><input class="pv-input" placeholder="Block/Adresse suchen..." style="width:100%">`;
  if (active === "profile") return `<h3 style="margin-bottom:8px">👤 Profil</h3><div class="pv-card"><div class="pv-row"><span>Name</span><span>Alice</span></div><div class="pv-row"><span>Rolle</span><span style="color:var(--accent)">Admin</span></div><div class="pv-row"><span>XP</span><span style="color:var(--green)">1.500</span></div></div><button class="pv-btn">Profil bearbeiten</button>`;
  return "";
}

export default function ThemeEditorView() {
  const [active, setActive] = useState("global");
  const [cv, setCv] = useState<Record<string, string>>({});
  const [comps, setComps] = useState<CompDef[]>(COMPS);
  const [targetExt, setTargetExt] = useState("__dashboard__");
  const [exts, setExts] = useState<ExtInfo[]>([]);
  const [savedThemes, setSavedThemes] = useState<SavedTheme[]>([]);
  const [designsOpen, setDesignsOpen] = useState(true);
  const [loadedDesign, setLoadedDesign] = useState<string | null>(null);
  const [changedCount, setChangedCount] = useState(0);
  const [toast, setToast] = useState<{ msg: string; ok: boolean } | null>(null);
  const [modal, setModal] = useState<{ title: string; msg: string; input?: boolean; value?: string; ph?: string; ok?: string; danger?: string; cb: (v: string | null) => void } | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const showToast = useCallback((msg: string, ok: boolean) => { setToast({ msg, ok }); setTimeout(() => setToast(null), 3000); }, []);

  const updateCount = useCallback((c: Record<string, string>, cps: CompDef[]) => {
    let n = Object.keys(c).length; for (const cp of cps) if (cp.css) n++; setChangedCount(n);
  }, []);

  const genCSS = useCallback((c: Record<string, string>, cps: CompDef[]): string => {
    const lines: string[] = [`/* Ziel: ${targetExt === "__dashboard__" ? "Dashboard" : targetExt} */`, ":root {"];
    for (const g of VARS) { lines.push(`  /* ${g.s} */`); for (const v of g.v) lines.push(`  ${v.n}: ${c[v.n] ?? v.d};`); }
    lines.push("}"); for (const cp of cps) { if (cp.css) { lines.push(""); lines.push(`/* ${cp.name} */`); lines.push(cp.css); } }
    return lines.join("\n");
  }, [targetExt]);

  const applyVar = (n: string, val: string) => document.documentElement.style.setProperty(n, val);

  const handleVarChange = useCallback((n: string, val: string) => {
    const def = (() => { for (const g of VARS) for (const v of g.v) if (v.n === n) return v.d; return ""; })();
    setCv(prev => { const next = { ...prev }; if (val === def) delete next[n]; else next[n] = val; return next; });
    applyVar(n, val === def ? def : val);
  }, []);

  // Update changed count when cv or comps change
  useEffect(() => { updateCount(cv, comps); }, [cv, comps, updateCount]);

  // Load extensions
  useEffect(() => { invoke<ExtInfo[]>("get_installed_extensions").then(setExts).catch(() => {}); refreshDesigns(); }, []);

  const refreshDesigns = async () => { try { setSavedThemes(await invoke<SavedTheme[]>("list_saved_themes")); } catch {} };

  // Load target theme when target changes
  useEffect(() => {
    invoke<string | null>("get_theme_css", { extensionId: targetExt }).then(css => {
      if (!css) return; const m = css.match(/:root\s*\{([^}]+)\}/); if (!m) return;
      const next: Record<string, string> = {};
      for (const g of VARS) for (const v of g.v) {
        const re = new RegExp(v.n + "\\s*:\\s*([^;]+)"), mm = m[1].match(re);
        if (mm) { const val = mm[1].trim(); if (val !== v.d) { next[v.n] = val; applyVar(v.n, val); } }
      }
      setCv(next); setComps(COMPS.map(c => ({ ...c, css: "" }))); setLoadedDesign(null);
    }).catch(() => {});
  }, [targetExt]);

  const handleApply = async () => {
    setBusy("apply");
    try { await invoke("write_theme_css", { extensionId: targetExt, css: genCSS(cv, comps) }); localStorage.setItem("stone-theme", targetExt); showToast("Theme übernommen! ✅", true); }
    catch (e: any) { showToast("Fehler: " + e, false); }
    setBusy(null);
  };

  const handleSave = () => {
    setModal({
      title: "💾 Design speichern", msg: "Name:", input: true, value: loadedDesign || "", ph: "z.B. Dark-Gold", ok: "Speichern",
      cb: async (name) => {
        if (!name) return; setBusy("save");
        try { await invoke("save_theme_file", { name, css: genCSS(cv, comps) }); setLoadedDesign(name); showToast("Gespeichert: " + name + ".css", true); refreshDesigns(); }
        catch (e: any) { showToast("Fehler: " + e, false); }
        setBusy(null);
      }
    });
  };

  const handleReadCurrent = async () => {
    setBusy("read");
    try {
      const css = await invoke<string | null>("get_theme_css", { extensionId: targetExt });
      if (!css) { showToast("Kein Theme gespeichert.", false); setBusy(null); return; }
      const m = css.match(/:root\s*\{([^}]+)\}/);
      if (!m) { showToast("Keine Variablen.", false); setBusy(null); return; }
      const next: Record<string, string> = {};
      for (const g of VARS) for (const v of g.v) {
        const re = new RegExp(v.n + "\\s*:\\s*([^;]+)"), mm = m[1].match(re);
        if (mm) { const val = mm[1].trim(); if (val !== v.d) { next[v.n] = val; applyVar(v.n, val); } }
      }
      setCv(next); showToast("Werte geladen!", true);
    } catch (e: any) { showToast("Fehler: " + e, false); }
    setBusy(null);
  };

  const handleReset = () => {
    setCv({}); setComps(COMPS.map(c => ({ ...c, css: "" }))); setLoadedDesign(null);
    for (const g of VARS) for (const v of g.v) applyVar(v.n, v.d); setChangedCount(0);
  };

  const handleTargetChange = (id: string) => {
    setTargetExt(id); setCv({}); setComps(COMPS.map(c => ({ ...c, css: "" }))); setLoadedDesign(null);
    localStorage.setItem("stone-theme-target", id);
  };

  const handleLoadDesign = async (name: string) => {
    try {
      const css = await invoke<string>("load_saved_theme", { name }); if (!css) return;
      const m = css.match(/:root\s*\{([^}]+)\}/); const next: Record<string, string> = {};
      if (m) for (const g of VARS) for (const v of g.v) {
        const re = new RegExp(v.n + "\\s*:\\s*([^;]+)"), mm = m[1].match(re);
        if (mm) { const val = mm[1].trim(); if (val !== v.d) { next[v.n] = val; applyVar(v.n, val); } }
      }
      setCv(next); setComps(COMPS.map(c => ({ ...c, css: "" }))); setLoadedDesign(name);
      showToast("Geladen: " + name, true); refreshDesigns();
    } catch (e: any) { showToast("Fehler: " + e, false); }
  };

  const handleDeleteDesign = (name: string) => {
    setModal({ title: "🗑 Design löschen?", msg: `"${name}" wirklich löschen?`, danger: "Löschen",
      cb: async (r) => { if (r !== "danger") return; try { await invoke("delete_saved_theme", { name }); if (loadedDesign === name) setLoadedDesign(null); showToast("Gelöscht: " + name, true); refreshDesigns(); } catch (e: any) { showToast("Fehler: " + e, false); } }
    });
  };

  const btn = (bg?: string, fg?: string, disabled?: boolean): React.CSSProperties => ({
    padding: "5px 10px", borderRadius: 6, border: "none", fontSize: 11, fontWeight: 600, cursor: disabled ? "not-allowed" : "pointer",
    display: "inline-flex", alignItems: "center", gap: 4, background: bg || "rgba(255,255,255,0.08)", color: fg || "var(--text-primary)", opacity: disabled ? 0.5 : 1,
  });

  const targetBadge = targetExt === "__dashboard__" ? "🌐 Dashboard" : (() => { const e = exts.find(x => x.id === targetExt); return e ? e.icon + " " + e.name : "📦 " + targetExt; })();

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", background: "var(--bg-root)", color: "var(--text-primary)", fontSize: 12, overflow: "hidden" }}>
      {/* Toolbar */}
      <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "8px 12px", background: "var(--bg-panel)", borderBottom: "1px solid var(--border-default)", flexShrink: 0 }}>
        <span style={{ fontSize: 15, fontWeight: 700 }}>🎨 Theme Editor</span>
        <span style={{ color: "var(--text-muted)", fontSize: 10 }}>🎯</span>
        <select style={{ background: "var(--bg-input)", border: "1px solid var(--border-default)", borderRadius: 6, color: "var(--text-primary)", fontSize: 11, padding: "4px 8px", outline: "none", cursor: "pointer", fontWeight: 600, minWidth: 160 }}
          value={targetExt} onChange={e => handleTargetChange(e.target.value)}>
          <option value="__dashboard__">🌐 Dashboard (Global)</option>
          {exts.map(e => <option key={e.id} value={e.id}>{e.icon} {e.name}</option>)}
        </select>
        <span style={{ flex: 1 }} />
        <button style={btn()} onClick={handleReadCurrent} disabled={busy === "read"}>{busy === "read" ? "⏳..." : "📋 Werte laden"}</button>
        <button style={btn()} onClick={handleReset}><RotateCcw size={12} /> Reset</button>
        <button style={btn("var(--green)", "#fff", busy === "apply")} onClick={handleApply} disabled={busy === "apply"}>
          {busy === "apply" ? <RefreshCw size={12} style={{ animation: "spin 1s linear infinite" }} /> : <Check size={12} />}
          {busy === "apply" ? "..." : "Übernehmen"}
        </button>
        <button style={btn("var(--accent)", "var(--text-inverse)", busy === "save")} onClick={handleSave} disabled={busy === "save"}>
          {busy === "save" ? <RefreshCw size={12} style={{ animation: "spin 1s linear infinite" }} /> : <Save size={12} />}
          {busy === "save" ? "..." : "Speichern"}
        </button>
        <span style={{ fontSize: 10, color: changedCount ? "var(--accent)" : "var(--text-muted)", fontWeight: changedCount ? 600 : 400 }}>
          {changedCount ? changedCount + " Änderungen" : "Keine Änderungen"}
        </span>
      </div>

      {/* Main */}
      <div style={{ display: "flex", flex: 1, overflow: "hidden", minHeight: 0 }}>
        {/* Left */}
        <div style={{ width: 420, flexShrink: 0, display: "flex", flexDirection: "column", overflow: "hidden", borderRight: "1px solid var(--border-default)" }}>
          <div style={{ flex: "1 1 0", overflowY: "auto", padding: 8, minHeight: 0 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
              <span style={{ fontSize: 10, color: "var(--text-muted)" }}>Komponente:</span>
              <span style={{ fontSize: 10, padding: "2px 8px", borderRadius: 10, background: "rgba(212,168,83,0.15)", color: "var(--accent)", fontWeight: 600 }}>{targetBadge}</span>
            </div>
            <div style={{ display: "flex", gap: 3, marginBottom: 8, flexWrap: "wrap" }}>
              {comps.map(c => (
                <button key={c.id} onClick={() => setActive(c.id)}
                  style={{ padding: "4px 10px", borderRadius: 4, border: "1px solid var(--border-strong)", background: active === c.id ? "var(--accent)" : "transparent", color: active === c.id ? "var(--text-inverse)" : "var(--text-secondary)", cursor: "pointer", fontSize: 10, fontWeight: 500 }}>
                  {c.name}
                </button>
              ))}
            </div>

            {active === "global" && VARS.map(g => (
              <div key={g.s}>
                <div style={{ fontSize: 11, fontWeight: 600, color: "var(--text-secondary)", margin: "8px 0 3px" }}>{g.s}</div>
                {g.v.map(v => {
                  const val = cv[v.n] ?? v.d, changed = cv[v.n] !== undefined;
                  return (
                    <div key={v.n} style={{ display: "flex", alignItems: "center", gap: 6, padding: "2px 0" }}>
                      <span style={{ width: 125, fontSize: 10, color: "var(--text-secondary)", fontFamily: "monospace", flexShrink: 0 }} title={v.l}>
                        {v.n}<span style={{ fontSize: 9, color: changed ? "var(--accent)" : "var(--green)", marginLeft: 4 }}>({changed ? "geänd." : "Std"})</span>
                      </span>
                      <div style={{ width: 14, height: 14, borderRadius: 2, border: "1px solid var(--border-strong)", flexShrink: 0, background: val }} />
                      <input type="color" style={{ width: 22, height: 22, borderRadius: 3, border: "1px solid var(--border-strong)", cursor: "pointer", padding: 0, flexShrink: 0 }}
                        value={hexFromCSS(val)} onChange={e => handleVarChange(v.n, e.target.value)} />
                      <input type="text" style={{ flex: 1, padding: "3px 6px", borderRadius: 3, background: "var(--bg-input)", border: "1px solid var(--border-default)", color: "var(--text-primary)", fontSize: 11, fontFamily: "monospace", outline: "none", minWidth: 0 }}
                        value={val} onChange={e => handleVarChange(v.n, e.target.value)} />
                      <span style={{ fontSize: 10, color: "var(--text-muted)", width: 45 }}>{v.l}</span>
                    </div>
                  );
                })}
              </div>
            ))}

            {active !== "global" && (
              <div>
                <div style={{ marginBottom: 6, fontSize: 11, color: "var(--text-secondary)" }}>
                  CSS für <strong>{comps.find(c => c.id === active)?.name || "—"}</strong>
                </div>
                <textarea style={{ width: "100%", minHeight: 80, background: "var(--bg-input)", border: "1px solid var(--border-default)", borderRadius: 6, padding: 10, fontFamily: "monospace", fontSize: 11, color: "var(--text-primary)", resize: "vertical", outline: "none" }}
                  placeholder="/* Custom CSS */" value={comps.find(c => c.id === active)?.css || ""}
                  onChange={e => { const next = comps.map(c => c.id === active ? { ...c, css: e.target.value } : c); setComps(next); }} />
                <div style={{ marginTop: 4, fontSize: 10, color: "var(--text-muted)" }}>Tailwind: <code style={{ color: "var(--accent)" }}>.flex</code> <code style={{ color: "var(--accent)" }}>button</code> <code style={{ color: "var(--accent)" }}>input</code></div>
              </div>
            )}

            <details style={{ marginTop: 8 }}>
              <summary style={{ fontSize: 11, color: "var(--text-secondary)", cursor: "pointer" }}>📝 Generiertes CSS</summary>
              <textarea readOnly style={{ width: "100%", minHeight: 60, background: "var(--bg-input)", border: "1px solid var(--border-default)", borderRadius: 6, padding: 10, fontFamily: "monospace", fontSize: 11, color: "var(--text-primary)", resize: "vertical", outline: "none", marginTop: 4 }}
                value={genCSS(cv, comps)} />
            </details>
          </div>

          {/* My Designs */}
          <div style={{ background: "#14161f", fontSize: 11, flexShrink: 0, borderTop: "1px solid var(--border-default)", maxHeight: designsOpen ? 260 : 34, overflow: designsOpen ? "auto" : "hidden", transition: "max-height .25s" }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "7px 10px", background: "var(--bg-panel)", cursor: "pointer", userSelect: "none", position: "sticky", top: 0, zIndex: 1 }}
              onClick={() => setDesignsOpen(!designsOpen)}>
              <span>🎨 <strong>Meine Designs</strong> <span style={{ color: "var(--text-muted)", fontWeight: 400 }}>({savedThemes.length})</span></span>
              <span style={{ display: "flex", gap: 4, alignItems: "center" }}>
                <button style={btn()} onClick={e => { e.stopPropagation(); refreshDesigns(); }} title="Neu laden"><RefreshCw size={10} /></button>
                {designsOpen ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
              </span>
            </div>
            {savedThemes.length === 0 ? (
              <div style={{ padding: 12, color: "var(--text-muted)", textAlign: "center", fontSize: 11, lineHeight: 1.5 }}>
                <Paintbrush size={24} style={{ opacity: 0.5, marginBottom: 4 }} /><br />Keine Designs.<br /><strong>💾 Speichern</strong> klicken.
              </div>
            ) : savedThemes.map(t => (
              <div key={t.name} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "5px 10px", cursor: "pointer", borderBottom: "1px solid rgba(255,255,255,0.04)", background: t.name === loadedDesign ? "rgba(212,168,83,0.12)" : "transparent", borderLeft: t.name === loadedDesign ? "2px solid var(--accent)" : "2px solid transparent" }}
                onClick={() => handleLoadDesign(t.name)}>
                <span>{t.name}{t.name === loadedDesign ? <span style={{ color: "var(--accent)", marginLeft: 4 }}>*</span> : ""}</span>
                <span style={{ display: "flex", gap: 4, alignItems: "center" }}>
                  <span style={{ fontSize: 10, color: "var(--text-muted)" }}>{(t.size / 1024).toFixed(1)} KB</span>
                  <button style={{ ...btn("rgba(239,68,68,0.15)", "#d95b5b"), fontSize: 10, padding: "1px 5px" }}
                    onClick={e => { e.stopPropagation(); handleDeleteDesign(t.name); }} title="Löschen"><Trash2 size={10} /></button>
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Right: Preview */}
        <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden", minHeight: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 10px", background: "var(--bg-panel)", borderBottom: "1px solid var(--border-default)", fontSize: 11, color: "var(--text-secondary)", flexShrink: 0 }}>
            <span>👁️ Live-Vorschau</span><span style={{ flex: 1 }} />
            <span style={{ fontSize: 10, color: "var(--text-muted)" }}>{comps.find(c => c.id === active)?.name || "Global"}</span>
            <span style={{ fontSize: 10, color: "var(--accent)" }}>({targetBadge})</span>
          </div>
          <div style={{ flex: 1, overflow: "hidden", minHeight: 0 }}>
            <div style={{ padding: 12, height: "100%", overflow: "auto", background: "var(--bg-root)", color: "var(--text-primary)" }}
              dangerouslySetInnerHTML={{
                __html: `<style>
                  .pv-nav{display:flex;gap:8px;padding:8px;border-radius:8px;margin-bottom:8px;background:var(--bg-panel)}
                  .pv-nav-item{padding:4px 10px;border-radius:4px;font-size:11px;color:var(--text-secondary)}
                  .pv-nav-item.pv-active{background:var(--accent);color:var(--text-inverse,#000)}
                  .pv-card{border-radius:8px;padding:12px;margin-bottom:8px;background:var(--bg-panel);border:1px solid var(--border-default)}
                  .pv-card h3{font-size:12px;margin-bottom:4px;color:var(--text-secondary)}
                  .pv-val{font-size:20px;font-weight:700;color:var(--text-primary)}
                  .pv-row{display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--border-default)}
                  .pv-btn{padding:6px 12px;border-radius:6px;color:var(--text-inverse,#000);border:none;font-size:11px;font-weight:600;background:var(--accent)}
                  .pv-input{padding:6px 10px;border-radius:6px;font-size:11px;background:var(--bg-input);border:1px solid var(--border-default);color:var(--text-primary)}
                </style>${previewHTML(active)}`
              }} />
          </div>
        </div>
      </div>

      {/* Toast */}
      {toast && <div style={{ position: "fixed", bottom: 16, right: 16, padding: "10px 16px", borderRadius: 8, fontSize: 12, fontWeight: 600, zIndex: 99, background: toast.ok ? "var(--green)" : "var(--red)", color: "#fff" }}>{toast.msg}</div>}

      {/* Modal */}
      {modal && (
        <div style={{ position: "fixed", top: 0, left: 0, width: "100%", height: "100%", background: "rgba(0,0,0,0.6)", zIndex: 100, display: "flex", alignItems: "center", justifyContent: "center" }}
          onClick={() => { modal.cb(null); setModal(null); }}>
          <div style={{ background: "var(--bg-main)", border: "1px solid var(--border-strong)", borderRadius: 12, padding: 20, minWidth: 300, maxWidth: 400 }} onClick={e => e.stopPropagation()}>
            <h2 style={{ fontSize: 15, marginBottom: 12, fontWeight: 700 }}>{modal.title}</h2>
            {modal.msg && <p style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 12 }}>{modal.msg}</p>}
            {modal.input && <input id="modal-inp" autoFocus defaultValue={modal.value || ""} placeholder={modal.ph || ""}
              style={{ marginBottom: 12, width: "100%", padding: "8px 10px", borderRadius: 6, background: "var(--bg-input)", border: "1px solid var(--border-strong)", color: "var(--text-primary)", fontSize: 13, outline: "none" }}
              onKeyDown={e => { if (e.key === "Enter") { modal.cb((e.target as HTMLInputElement).value); setModal(null); } if (e.key === "Escape") { modal.cb(null); setModal(null); } }} />}
            <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
              <button style={btn()} onClick={() => { modal.cb(null); setModal(null); }}>Abbrechen</button>
              {modal.ok && <button style={btn("var(--accent)", "var(--text-inverse)")} onClick={() => { const v = modal.input ? (document.getElementById("modal-inp") as HTMLInputElement)?.value || "ok" : "ok"; modal.cb(v); setModal(null); }}>{modal.ok}</button>}
              {modal.danger && <button style={btn("rgba(239,68,68,0.15)", "var(--red)")} onClick={() => { modal.cb("danger"); setModal(null); }}>{modal.danger}</button>}
            </div>
          </div>
        </div>
      )}
      <style>{`@keyframes spin{from{transform:rotate(0)}to{transform:rotate(360deg)}}`}</style>
    </div>
  );
}
