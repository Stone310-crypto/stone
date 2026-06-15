package net.stonechain.mcplugin;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/**
 * Startet und verwaltet den Stone-Node als Subprozess.
 *
 * Der Server-Betreiber muss NICHTS manuell tun:
 * 1. Plugin wird in plugins/StoneMC.jar installiert
 * 2. Stone-Node Binary liegt in plugins/StoneMC/stone-node/stone-master
 * 3. Plugin startet den Node automatisch bei Server-Start
 * 4. Plugin stoppt den Node sauber bei Server-Shutdown
 *
 * Der Node läuft auf localhost:3080 und kommuniziert via P2P (Noise/libp2p)
 * mit dem Stone-Netzwerk. Keine Remote-IP-Konfiguration nötig.
 */
public final class NodeLauncher {

    private static final String NODE_BINARY = "stone-master";
    private static final int NODE_PORT = 3080;
    private static final int HEALTH_CHECK_TIMEOUT_SECS = 30;
    private static final int HEALTH_CHECK_INTERVAL_MS = 500;

    private final Logger log;
    private final File pluginDataDir;
    private Process process;
    private Thread shutdownHook;
    private boolean started;

    public NodeLauncher(File pluginDataDir, Logger log) {
        this.pluginDataDir = pluginDataDir;
        this.log = log;
    }

    /**
     * Startet den Stone-Node als Hintergrundprozess und wartet bis der
     * Health-Endpoint antwortet. Gibt true zurück wenn erfolgreich.
     */
    public boolean start() {
        if (started) return true;

        File nodeDir = new File(pluginDataDir, "stone-node");
        File binary = findBinary(nodeDir);

        if (binary == null) {
            log.warning("Stone-Node Binary nicht gefunden in " + nodeDir.getAbsolutePath()
                + "/" + NODE_BINARY + ". Node wird NICHT automatisch gestartet. "
                + "Installiere den Stone-Node manuell oder setze 'auto_start_node: false' in config.yml.");
            return false;
        }

        if (!binary.canExecute() && !binary.setExecutable(true)) {
            log.warning("Stone-Node Binary nicht ausführbar: " + binary.getAbsolutePath());
            return false;
        }

        try {
            ProcessBuilder pb = new ProcessBuilder(
                binary.getAbsolutePath(),
                "--port", String.valueOf(NODE_PORT),
                "--data-dir", new File(nodeDir, "data").getAbsolutePath()
            );
            pb.directory(nodeDir);
            pb.redirectErrorStream(true);

            process = pb.start();

            // Log-Ausgabe des Nodes im Hintergrund einsammeln
            Thread logReader = new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(process.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        log.info("[stone-node] " + line);
                    }
                } catch (Exception ignored) {}
            }, "stone-node-log");
            logReader.setDaemon(true);
            logReader.start();

            // Shutdown-Hook registrieren
            shutdownHook = new Thread(this::stop, "stone-node-shutdown");
            Runtime.getRuntime().addShutdownHook(shutdownHook);

            // Auf Health-Check warten
            log.info("Stone-Node gestartet (PID: " + process.pid() + "), warte auf Health-Check...");
            boolean healthy = waitForHealth();

            if (healthy) {
                started = true;
                log.info("Stone-Node bereit auf http://127.0.0.1:" + NODE_PORT);
                return true;
            } else {
                log.warning("Stone-Node antwortet nicht auf Health-Check nach "
                    + HEALTH_CHECK_TIMEOUT_SECS + "s. Node läuft trotzdem weiter — "
                    + "prüfe die Logs.");
                started = true; // trotzdem als gestartet markieren
                return true;
            }

        } catch (Exception e) {
            log.severe("Stone-Node Start fehlgeschlagen: " + e.getMessage());
            return false;
        }
    }

    /** Stoppt den Node-Prozess sauber (SIGTERM, dann force-kill nach 5s). */
    public void stop() {
        if (process == null || !process.isAlive()) return;

        try {
            process.destroy(); // SIGTERM
            boolean terminated = process.waitFor(5, TimeUnit.SECONDS);
            if (!terminated) {
                process.destroyForcibly(); // SIGKILL
                log.warning("Stone-Node musste hart beendet werden (force-kill).");
            } else {
                log.info("Stone-Node sauber beendet.");
            }
        } catch (InterruptedException e) {
            process.destroyForcibly();
            Thread.currentThread().interrupt();
        }

        if (shutdownHook != null) {
            try { Runtime.getRuntime().removeShutdownHook(shutdownHook); } catch (Exception ignored) {}
        }
        started = false;
    }

    public boolean isRunning() {
        return process != null && process.isAlive();
    }

    // ── interne Hilfsmethoden ──────────────────────────────────────────────

    private File findBinary(File dir) {
        // Plattform-spezifische Namen
        String osName = System.getProperty("os.name", "").toLowerCase();
        String exeSuffix = osName.contains("win") ? ".exe" : "";

        File binary = new File(dir, NODE_BINARY + exeSuffix);
        if (binary.exists()) return binary;

        // Auch im current working directory suchen (Entwicklung)
        binary = new File(NODE_BINARY + exeSuffix);
        if (binary.exists()) return binary;

        return null;
    }

    private boolean waitForHealth() {
        HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

        long deadline = System.currentTimeMillis() + HEALTH_CHECK_TIMEOUT_SECS * 1000L;

        while (System.currentTimeMillis() < deadline) {
            if (process != null && !process.isAlive()) {
                log.warning("Stone-Node Prozess unerwartet beendet (exit=" + process.exitValue() + ")");
                return false;
            }

            try {
                HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create("http://127.0.0.1:" + NODE_PORT + "/api/v1/health"))
                    .timeout(Duration.ofSeconds(2))
                    .GET()
                    .build();

                HttpResponse<String> res = client.send(req, HttpResponse.BodyHandlers.ofString());
                if (res.statusCode() == 200) {
                    return true;
                }
            } catch (Exception ignored) {
                // Node noch nicht bereit
            }

            try {
                Thread.sleep(HEALTH_CHECK_INTERVAL_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        return false;
    }
}