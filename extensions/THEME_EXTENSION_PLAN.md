# 🎨 Theme Extension Architecture

## Konzept

Da das Dashboard eine kompilierte Tauri-App ist, können Nutzer HTML/CSS nicht 
direkt bearbeiten. Stattdessen nutzen wir **CSS Custom Properties** (Variablen), 
die von Theme-Extensions überschrieben werden.

## Wie es funktioniert

```
┌─────────────────────────────────────────────────┐
│  Dashboard (Tauri)                              │
│                                                 │
│  :root {                                        │
│    --accent: #d4a853;     ← Standard            │
│    --bg-panel: #1a1a1a;                         │
│    --text-primary: #e0e0e0;                     │
│    ...                                          │
│  }                                              │
│                                                 │
│  ┌─ Theme-Extension "Cyberpunk" ──────────────┐ │
│  │ theme.css:                                  │ │
│  │   :root {                                   │ │
│  │     --accent: #ff00ff;                      │ │
│  │     --bg-panel: #0a0a2e;                    │ │
│  │   }                                         │ │
│  └─────────────────────────────────────────────┘ │
│                                                 │
│  Theme-Engine:                                   │
│    1. Lade theme.css aus Extension               │
│    2. Injiziere als <style id="theme">            │
│    3. CSS-Overrides überschreiben :root           │
└─────────────────────────────────────────────────┘
```

## Implementierung

### 1. Theme-Extension-Format

Jede Theme-Extension hat eine `theme.css`:

```css
/* Dark Neon Theme */
:root {
  --accent: #00ff88;
  --accent-hover: #00cc66;
  --bg-main: #0a0a0a;
  --bg-panel: #111122;
  --bg-input: #1a1a2e;
  --border: #222244;
  --border-strong: #333366;
  --text-primary: #e0e0ff;
  --text-secondary: #8888aa;
  --text-muted: #555577;
  --text-inverse: #0a0a0a;
  --green: #00ff88;
  --red: #ff4466;
  --blue: #4488ff;

  /* Optional: Schriftart */
  --font-family: 'SF Mono', monospace;

  /* Optional: Border-Radius */
  --radius-sm: 4px;
  --radius-md: 8px;
  --radius-lg: 16px;
}
```

### 2. CSS-Variablen, die das Dashboard nutzt

| Variable | Default | Beschreibung |
|---|---|---|
| `--accent` | `#d4a853` | Primärfarbe (Buttons, Links) |
| `--bg-main` | `#0f0f0f` | Hintergrund |
| `--bg-panel` | `#1a1a1a` | Panel-Hintergrund |
| `--bg-input` | `#1e1e1e` | Input-Felder |
| `--border` | `#2a2a2a` | Standard-Rahmen |
| `--border-strong` | `#3a3a3a` | Starker Rahmen |
| `--text-primary` | `#e0e0e0` | Haupttext |
| `--text-secondary` | `#888` | Sekundärtext |
| `--text-muted` | `#555` | Gedimmter Text |
| `--text-inverse` | `#000` | Text auf Akzent |
| `--green` | `#22c55e` | Erfolg |
| `--red` | `#ef4444` | Fehler |
| `--blue` | `#3b82f6` | Info |

### 3. Tauri Commands

```rust
// extensions.rs

/// Lädt die theme.css einer installierten Extension.
#[tauri::command]
pub fn get_theme_css(extension_id: String) -> Option<String> {
    let path = extensions_dir().join(&extension_id).join("theme.css");
    if path.exists() {
        std::fs::read_to_string(&path).ok()
    } else {
        None
    }
}

/// Listet alle installierten Extensions, die eine theme.css haben.
#[tauri::command]
pub fn list_themes() -> Vec<ExtensionManifest> {
    get_installed_extensions()
        .into_iter()
        .filter(|ext| {
            extensions_dir().join(&ext.id).join("theme.css").exists()
        })
        .collect()
}
```

### 4. React ThemeProvider

```tsx
// hooks/useTheme.ts
export function useTheme() {
  const [themeCss, setThemeCss] = useState<string | null>(null);
  const [activeTheme, setActiveTheme] = useState<string | null>(null);

  // Lade gespeichertes Theme
  useEffect(() => {
    const saved = localStorage.getItem("stone-theme");
    if (saved) {
      invoke<string>("get_theme_css", { extensionId: saved })
        .then(setThemeCss)
        .catch(() => {});
      setActiveTheme(saved);
    }
  }, []);

  // Injiziere CSS
  useEffect(() => {
    let styleEl = document.getElementById("stone-theme-css");
    if (!styleEl) {
      styleEl = document.createElement("style");
      styleEl.id = "stone-theme-css";
      document.head.appendChild(styleEl);
    }
    styleEl.textContent = themeCss || "";
  }, [themeCss]);

  const applyTheme = (extensionId: string | null) => {
    if (extensionId) {
      invoke<string>("get_theme_css", { extensionId })
        .then(css => {
          setThemeCss(css);
          setActiveTheme(extensionId);
          localStorage.setItem("stone-theme", extensionId);
        });
    } else {
      setThemeCss(null);
      setActiveTheme(null);
      localStorage.removeItem("stone-theme");
    }
  };

  return { themeCss, activeTheme, applyTheme };
}
```

### 5. Theme-Extension-Store

Der Extension-Store (`index.json`) bekommt eine neue Kategorie:

```json
{
  "id": "cyberpunk-theme",
  "name": "Cyberpunk Theme",
  "description": "Neon-Farben im Cyberpunk-Stil",
  "version": "1.0.0",
  "icon": "🌃",
  "category": "theme",
  "size_mb": 0.1,
  "repository": "Stone310-crypto/cyberpunk-theme",
  "author": "StoneChain"
}
```

### 6. Theme-Marktplatz in der App

Unter 🧩 Erweiterungen ein neuer Tab "🎨 Themes", der:
- Installierte Themes anzeigt
- Theme-Vorschau (Live-Preview beim Hovern)
- "Als Standard" setzen
- Theme deinstallieren
