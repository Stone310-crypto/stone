import { useState, useCallback, useEffect, useRef, type DragEvent } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import {
  Upload,
  File,
  CheckCircle,
  XCircle,
  Shield,
  Trash2,
  FolderOpen,
  Box,
} from "lucide-react";

// ─── Types ──────────────────────────────────────────────────────────────────

interface MagicByteInfo {
  mime_type: string;
  description: string;
  is_executable: boolean;
  is_archive: boolean;
}

interface ValidationResult {
  valid: boolean;
  file_name: string;
  file_size: number;
  magic_info: MagicByteInfo | null;
  error: string | null;
  sha256_hash: string;
}

interface UploadResult {
  success: boolean;
  file_hash: string;
  file_name: string;
  file_size: number;
  magic_info: MagicByteInfo | null;
  error: string | null;
  // Phase 2: Vom Stone-Master-Server zurück
  doc_id: string | null;
  block_index: number | null;
  block_hash: string | null;
  version: number | null;
  encrypted: boolean | null;
  signed: boolean | null;
  shards_distributed: boolean | null;
}

interface FileEntry {
  id: string;
  path: string;
  name: string;
  size: number;
  status: "idle" | "validating" | "validated" | "uploading" | "done" | "error";
  progress: number;
  error: string | null;
  validation?: ValidationResult;
  upload?: UploadResult;
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function formatSize(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return (bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1) + " " + units[i];
}

function shortHash(h: string): string {
  return h.length > 16 ? h.slice(0, 8) + "…" + h.slice(-8) : h;
}

// ─── Component ──────────────────────────────────────────────────────────────

export default function FileUploadView() {
  const [files, setFiles] = useState<FileEntry[]>([]);
  const [dragOver, setDragOver] = useState(false);
  const [uploadedCount, setUploadedCount] = useState(0);
  const [totalUploadedSize, setTotalUploadedSize] = useState(0);
  const dropRef = useRef<HTMLDivElement>(null);
  const dragCounter = useRef(0);

  // ── Drag-and-Drop ───────────────────────────────────────────────────────

  const processFilePaths = useCallback(async (paths: string[]) => {
    const entries: FileEntry[] = paths.map((p) => {
      const parts = p.replace(/\\/g, "/").split("/");
      const name = parts[parts.length - 1] || p;
      return {
        id: crypto.randomUUID?.() ?? `${Date.now()}-${Math.random()}`,
        path: p,
        name,
        size: 0,
        status: "idle" as const,
        progress: 0,
        error: null,
      };
    });

    setFiles((prev) => [...prev, ...entries]);

    for (const entry of entries) {
      await validateFile(entry);
    }
  }, []);

  useEffect(() => {
    const unlisten = async () => {
      try {
        const { listen } = await import("@tauri-apps/api/event");
        const u = await listen<string[]>("tauri://drag-drop", (event) => {
          const paths = event.payload;
          if (paths && paths.length > 0) {
            processFilePaths(paths);
          }
        });
        return u;
      } catch {
        return undefined;
      }
    };
    let cleanup: (() => void) | undefined;
    unlisten().then((u) => {
      cleanup = u;
    });
    return () => {
      cleanup?.();
    };
  }, [processFilePaths]);

  const handleDragEnter = useCallback((e: DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounter.current++;
    setDragOver(true);
  }, []);

  const handleDragLeave = useCallback((e: DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounter.current--;
    if (dragCounter.current <= 0) {
      dragCounter.current = 0;
      setDragOver(false);
    }
  }, []);

  const handleDragOver = useCallback((e: DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
  }, []);

  const handleDrop = useCallback(
    (e: DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      setDragOver(false);
      dragCounter.current = 0;

      const files = Array.from(e.dataTransfer.files ?? []);
      if (files.length > 0) {
        const paths = files
          .map((f: any) => f.path)
          .filter((p: string | undefined) => p) as string[];
        if (paths.length > 0) {
          processFilePaths(paths);
        } else {
          const names = files.map((f) => f.name);
          alert(
            `Drag-and-Drop Pfade nicht verfügbar.\nDateinamen: ${names.join(", ")}\n\nBitte nutze den "Dateien auswählen" Button.`
          );
        }
      }
    },
    [processFilePaths]
  );

  // ── Validation ───────────────────────────────────────────────────────────

  const validateFile = useCallback(async (entry: FileEntry) => {
    setFiles((prev) =>
      prev.map((f) =>
        f.id === entry.id ? { ...f, status: "validating" as const } : f
      )
    );
    try {
      const result: ValidationResult = await invoke("validate_upload_file", {
        path: entry.path,
      });
      setFiles((prev) =>
        prev.map((f) =>
          f.id === entry.id
            ? {
                ...f,
                status: "validated",
                size: result.file_size,
                validation: result,
              }
            : f
        )
      );
    } catch (err) {
      setFiles((prev) =>
        prev.map((f) =>
          f.id === entry.id
            ? {
                ...f,
                status: "error",
                error: String(err),
              }
            : f
        )
      );
    }
  }, []);

  // ── Upload (Phase 2: via Stone Master Server) ────────────────────────────

  const uploadFile = useCallback(async (entry: FileEntry) => {
    setFiles((prev) =>
      prev.map((f) =>
        f.id === entry.id ? { ...f, status: "uploading", progress: 0 } : f
      )
    );

    const progressSteps = [
      { pct: 10, delay: 100 },
      { pct: 25, delay: 200 },
      { pct: 50, delay: 300 },
      { pct: 75, delay: 200 },
      { pct: 90, delay: 150 },
    ];
    for (const step of progressSteps) {
      await new Promise((r) => setTimeout(r, step.delay));
      setFiles((prev) =>
        prev.map((f) =>
          f.id === entry.id ? { ...f, progress: step.pct } : f
        )
      );
    }

    try {
      const result: UploadResult = await invoke("upload_file", {
        path: entry.path,
        masterUrl: "http://127.0.0.1:3080",
        apiKey: "stone-local-dev",
        sessionToken: null,
      });
      setFiles((prev) =>
        prev.map((f) =>
          f.id === entry.id
            ? {
                ...f,
                status: "done",
                progress: 100,
                upload: result,
              }
            : f
        )
      );
      setUploadedCount((c) => c + 1);
      setTotalUploadedSize((s) => s + result.file_size);
    } catch (err) {
      setFiles((prev) =>
        prev.map((f) =>
          f.id === entry.id
            ? {
                ...f,
                status: "error",
                progress: 0,
                error: String(err),
              }
            : f
        )
      );
    }
  }, []);

  const uploadAll = useCallback(async () => {
    const validated = files.filter((f) => f.status === "validated");
    for (const entry of validated) {
      await uploadFile(entry);
    }
  }, [files, uploadFile]);

  // ── File Picker ─────────────────────────────────────────────────────────

  const openFilePicker = useCallback(async () => {
    try {
      const selected = await open({
        multiple: true,
        filters: [],
      });
      if (selected) {
        const paths = Array.isArray(selected) ? selected : [selected];
        if (paths.length > 0) {
          await processFilePaths(paths as string[]);
        }
      }
    } catch (err) {
      console.error("File picker error:", err);
    }
  }, [processFilePaths]);

  // ── Clear ───────────────────────────────────────────────────────────────

  const clearCompleted = useCallback(() => {
    setFiles((prev) =>
      prev.filter((f) => f.status !== "done" && f.status !== "error")
    );
  }, []);

  const clearAll = useCallback(() => {
    setFiles([]);
    setUploadedCount(0);
    setTotalUploadedSize(0);
  }, []);

  const removeFile = useCallback((id: string) => {
    setFiles((prev) => prev.filter((f) => f.id !== id));
  }, []);

  // ── Render ──────────────────────────────────────────────────────────────

  const validCount = files.filter((f) => f.status === "validated").length;
  const errorCount = files.filter((f) => f.status === "error").length;
  const doneCount = files.filter((f) => f.status === "done").length;

  return (
    <div className="flex flex-col h-full" style={{ padding: 24, maxWidth: 900, margin: "0 auto" }}>
      {/* ── Header ────────────────────────────────────────────────────── */}
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, margin: 0 }}>Datei-Upload</h1>
        <p style={{ color: "var(--text-secondary, #888)", margin: "4px 0 0", fontSize: 14 }}>
          Ziehe Dateien per Drag & Drop hierher oder wähle sie aus.{" "}
          <span style={{ fontWeight: 600 }}>Max. 100 MB</span> pro Datei.
          <br />
          Ausführbare Dateien (.exe, ELF, Mach-O) sind blockiert — in ZIP-Archiven jedoch erlaubt.
          <br />
          <span style={{ fontWeight: 600 }}>
            Phase 2: Dateien werden via HTTP an den Stone-Master-Server gesendet,
            <br />
            der sie in Shards zerlegt und dezentral im P2P-Netzwerk verteilt (k=4, m=2).
          </span>
        </p>
      </div>

      {/* ── Stats ─────────────────────────────────────────────────────── */}
      {uploadedCount > 0 && (
        <div
          style={{
            display: "flex",
            gap: 16,
            marginBottom: 16,
            padding: "12px 16px",
            borderRadius: 10,
            background: "rgba(34, 197, 94, 0.08)",
            border: "1px solid rgba(34, 197, 94, 0.2)",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <CheckCircle size={16} color="#22c55e" />
            <span style={{ fontWeight: 600, fontSize: 14 }}>
              {uploadedCount} Datei{uploadedCount !== 1 && "en"} hochgeladen
            </span>
          </div>
          <span style={{ color: "var(--text-secondary, #888)", fontSize: 14 }}>
            {formatSize(totalUploadedSize)}
          </span>
        </div>
      )}

      {/* ── Drop Zone ─────────────────────────────────────────────────── */}
      <div
        ref={dropRef}
        onDragEnter={handleDragEnter}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={openFilePicker}
        style={{
          border: `2px dashed ${dragOver ? "#3b82f6" : "var(--border-color, #444)"}`,
          borderRadius: 14,
          padding: "48px 24px",
          textAlign: "center",
          cursor: "pointer",
          background: dragOver
            ? "rgba(59, 130, 246, 0.06)"
            : "var(--card-bg, rgba(255,255,255,0.03))",
          transition: "all 0.2s",
          marginBottom: 20,
        }}
      >
        <Upload
          size={40}
          style={{ margin: "0 auto 12px", opacity: dragOver ? 1 : 0.5 }}
          color={dragOver ? "#3b82f6" : undefined}
        />
        <p style={{ fontWeight: 600, fontSize: 15, margin: 0 }}>
          {dragOver ? "Jetzt loslassen…" : "Dateien hier ablegen"}
        </p>
        <p style={{ color: "var(--text-secondary, #888)", fontSize: 13, margin: "6px 0 0" }}>
          oder klicken zum Auswählen
        </p>
      </div>

      {/* ── Action Buttons ────────────────────────────────────────────── */}
      {files.length > 0 && (
        <div style={{ display: "flex", gap: 10, marginBottom: 20, flexWrap: "wrap" }}>
          <button
            onClick={openFilePicker}
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 6,
              padding: "8px 16px",
              borderRadius: 8,
              border: "1px solid var(--border-color, #444)",
              background: "var(--card-bg, rgba(255,255,255,0.05))",
              color: "var(--text-primary, #fff)",
              cursor: "pointer",
              fontSize: 13,
            }}
          >
            <FolderOpen size={15} /> Weitere Dateien
          </button>
          {validCount > 0 && (
            <button
              onClick={uploadAll}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 6,
                padding: "8px 20px",
                borderRadius: 8,
                border: "none",
                background: "#3b82f6",
                color: "#fff",
                cursor: "pointer",
                fontSize: 13,
                fontWeight: 600,
              }}
            >
              <Upload size={15} /> {validCount} Datei{validCount !== 1 && "en"} hochladen
            </button>
          )}
          {(doneCount > 0 || errorCount > 0) && (
            <button
              onClick={clearCompleted}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 6,
                padding: "8px 16px",
                borderRadius: 8,
                border: "1px solid var(--border-color, #444)",
                background: "transparent",
                color: "var(--text-secondary, #888)",
                cursor: "pointer",
                fontSize: 13,
              }}
            >
              <Trash2 size={15} /> Erledigte entfernen
            </button>
          )}
          {files.length > 0 && (
            <button
              onClick={clearAll}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 6,
                padding: "8px 16px",
                borderRadius: 8,
                border: "1px solid rgba(239, 68, 68, 0.3)",
                background: "transparent",
                color: "#ef4444",
                cursor: "pointer",
                fontSize: 13,
              }}
            >
              <Trash2 size={15} /> Alle entfernen
            </button>
          )}
        </div>
      )}

      {/* ── File List ─────────────────────────────────────────────────── */}
      {files.length > 0 && (
        <div style={{ display: "flex", flexDirection: "column", gap: 8, overflow: "auto" }}>
          {files.map((entry) => (
            <FileRow
              key={entry.id}
              entry={entry}
              onUpload={() => uploadFile(entry)}
              onRemove={() => removeFile(entry.id)}
            />
          ))}
        </div>
      )}

      {/* ── Empty State ───────────────────────────────────────────────── */}
      {files.length === 0 && (
        <div
          style={{
            textAlign: "center",
            padding: 32,
            color: "var(--text-secondary, #888)",
          }}
        >
          <Shield size={48} style={{ margin: "0 auto 12px", opacity: 0.3 }} />
          <p style={{ fontSize: 14, margin: 0 }}>
            Alle Uploads werden per Magic-Byte-Analyse auf Schadcode geprüft.
          </p>
          <p style={{ fontSize: 13, margin: "4px 0 0" }}>
            Dateien werden via Stone-Master-Server in Shards aufgeteilt und dezentral
            im P2P-Netzwerk verteilt (Reed-Solomon k=4, m=2).
          </p>
        </div>
      )}
    </div>
  );
}

// ─── File Row ───────────────────────────────────────────────────────────────

function FileRow({
  entry,
  onUpload,
  onRemove,
}: {
  entry: FileEntry;
  onUpload: () => void;
  onRemove: () => void;
}) {
  const isError = entry.status === "error";
  const isDone = entry.status === "done";
  const isValidated = entry.status === "validated";
  const isProcessing = entry.status === "validating" || entry.status === "uploading";

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 12,
        padding: "10px 14px",
        borderRadius: 10,
        background: isError
          ? "rgba(239, 68, 68, 0.06)"
          : isDone
            ? "rgba(34, 197, 94, 0.04)"
            : "var(--card-bg, rgba(255,255,255,0.04))",
        border: isError
          ? "1px solid rgba(239, 68, 68, 0.2)"
          : "1px solid var(--border-color, #333)",
        transition: "all 0.2s",
      }}
    >
      {/* Icon */}
      <div style={{ flexShrink: 0 }}>
        {isError ? (
          <XCircle size={22} color="#ef4444" />
        ) : isDone ? (
          <CheckCircle size={22} color="#22c55e" />
        ) : isProcessing ? (
          <Box size={22} style={{ opacity: 0.5, animation: "spin 2s linear infinite" }} />
        ) : (
          <File size={22} style={{ opacity: 0.6 }} />
        )}
      </div>

      {/* Info */}
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span
            style={{
              fontWeight: 600,
              fontSize: 13,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            {entry.name}
          </span>
          {entry.size > 0 && (
            <span style={{ fontSize: 12, color: "var(--text-secondary, #888)", whiteSpace: "nowrap" }}>
              {formatSize(entry.size)}
            </span>
          )}
        </div>

        {/* Magic Byte Info + Phase 2 Ergebnis */}
        {(entry.validation?.magic_info || entry.upload?.magic_info) && (
          <div style={{ fontSize: 11, color: "var(--text-secondary, #888)", marginTop: 2 }}>
            <span
              style={{
                display: "inline-block",
                padding: "1px 6px",
                borderRadius: 4,
                background: "rgba(59, 130, 246, 0.1)",
                color: "#60a5fa",
                marginRight: 6,
              }}
            >
              {(entry.validation?.magic_info || entry.upload?.magic_info)!.description}
            </span>
            {entry.upload && entry.upload.doc_id && (
              <span style={{ marginRight: 6 }}>
                Doc #{entry.upload.doc_id.slice(0, 8)}
              </span>
            )}
            {entry.upload && entry.upload.block_index != null && (
              <span style={{ marginRight: 6 }}>
                Block #{entry.upload.block_index}
              </span>
            )}
            {entry.upload?.shards_distributed && (
              <span style={{ color: "#22c55e", fontWeight: 600 }}>
                ✓ Shards verteilt
              </span>
            )}
          </div>
        )}

        {/* Validation SHA */}
        {entry.validation?.sha256_hash && (
          <div style={{ fontSize: 11, color: "var(--text-secondary, #666)", marginTop: 1, fontFamily: "monospace" }}>
            SHA-256: {shortHash(entry.validation.sha256_hash)}
          </div>
        )}

        {/* Error */}
        {entry.error && (
          <div style={{ fontSize: 12, color: "#ef4444", marginTop: 4, lineHeight: 1.4 }}>{entry.error}</div>
        )}

        {/* Progress Bar */}
        {isProcessing && (
          <div style={{ marginTop: 6 }}>
            <div
              style={{
                height: 4,
                borderRadius: 2,
                background: "var(--border-color, #333)",
                overflow: "hidden",
              }}
            >
              <div
                style={{
                  height: "100%",
                  width: `${entry.progress}%`,
                  background: "#3b82f6",
                  borderRadius: 2,
                  transition: "width 0.3s ease",
                }}
              />
            </div>
          </div>
        )}
      </div>

      {/* Actions */}
      <div style={{ flexShrink: 0, display: "flex", gap: 4 }}>
        {isValidated && !isDone && (
          <button
            onClick={(e) => {
              e.stopPropagation();
              onUpload();
            }}
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 4,
              padding: "5px 10px",
              borderRadius: 6,
              border: "none",
              background: "#3b82f6",
              color: "#fff",
              cursor: "pointer",
              fontSize: 12,
              fontWeight: 600,
            }}
          >
            <Upload size={12} /> Hochladen
          </button>
        )}
        {isError && (
          <button
            onClick={(e) => {
              e.stopPropagation();
              onRemove();
            }}
            style={{
              display: "inline-flex",
              alignItems: "center",
              padding: "5px 10px",
              borderRadius: 6,
              border: "1px solid rgba(239, 68, 68, 0.3)",
              background: "transparent",
              color: "#ef4444",
              cursor: "pointer",
              fontSize: 12,
            }}
          >
            <Trash2 size={12} />
          </button>
        )}
        {isDone && (
          <button
            onClick={(e) => {
              e.stopPropagation();
              onRemove();
            }}
            style={{
              display: "inline-flex",
              alignItems: "center",
              padding: "5px 10px",
              borderRadius: 6,
              border: "1px solid var(--border-color, #444)",
              background: "transparent",
              color: "var(--text-secondary, #888)",
              cursor: "pointer",
              fontSize: 12,
            }}
          >
            <Trash2 size={12} />
          </button>
        )}
      </div>
    </div>
  );
}