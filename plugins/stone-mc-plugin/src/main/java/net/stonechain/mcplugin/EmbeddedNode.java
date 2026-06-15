package net.stonechain.mcplugin;

import java.io.*;
import java.net.*;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.logging.Logger;

import com.google.gson.*;

/**
 * Embedded HTTP-Proxy für das Stone-Minecraft-Plugin.
 *
 * Nimmt lokale Play-Drop-Anfragen von NodeClient entgegen und leitet sie
 * an den echten Haupt-Node weiter. Der EmbeddedNode signiert KEINE TXs —
 * das macht ausschließlich der Haupt-Node (Gaming-Pool-Key + 70/20/10 Split).
 *
 * Architektur:
 * ┌──────────────┐   HTTP POST         ┌──────────────────┐
 * │ Minecraft    │ ──── :3080 ──────► │ EmbeddedNode      │
 * │ Plugin       │ (play-drop)        │ (Proxy, kein Key) │
 * │ NodeClient   │                    │         │         │
 * │              │ ◄─── response ──── │         │         │
 * └──────────────┘                    │    POST :3080     │
 *                                      │         ▼         │
 *                                      │  Haupt-Node       │
 *                                      │  (signiert TX)    │
 *                                      └──────────────────┘
 */
public final class EmbeddedNode {

    public static final int PORT = 3080;

    private final Logger log;
    private final List<String> bootstrapNodes;
    private final String gameId;
    private final String sdkKey;
    private final int requestTimeoutMs;

    private final HttpClient http;
    private com.sun.net.httpserver.HttpServer server;
    private volatile boolean running;

    public EmbeddedNode(Logger log, List<String> bootstrapNodes, String gameId,
                         String sdkKey, int connectTimeoutMs, int requestTimeoutMs) {
        this.log = log;
        this.bootstrapNodes = bootstrapNodes;
        this.gameId = gameId;
        this.sdkKey = sdkKey;
        this.requestTimeoutMs = requestTimeoutMs;

        this.http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofMillis(connectTimeoutMs))
            .build();
    }

    public void start() {
        if (running) return;
        running = true;

        try {
            server = com.sun.net.httpserver.HttpServer.create(
                new InetSocketAddress("127.0.0.1", PORT), 0);

            server.createContext("/api/v1/sdk/game/play-drop", this::handlePlayDrop);
            server.createContext("/api/v1/health", this::handleHealth);
            server.setExecutor(Executors.newFixedThreadPool(4, r -> {
                Thread t = new Thread(r, "stone-embedded-http");
                t.setDaemon(true);
                return t;
            }));
            server.start();

            log.info("[EmbeddedNode] HTTP-Proxy gestartet auf 127.0.0.1:" + PORT
                + " (forward to " + bootstrapNodes.size() + " bootstrap nodes)");
        } catch (IOException e) {
            log.severe("[EmbeddedNode] HTTP-Server konnte nicht gestartet werden: " + e.getMessage());
        }
    }

    public void stop() {
        running = false;
        if (server != null) {
            server.stop(1);
        }
        log.info("[EmbeddedNode] Gestoppt.");
    }

    // ── HTTP Handlers ───────────────────────────────────────────────────

    private void handleHealth(com.sun.net.httpserver.HttpExchange exchange) throws IOException {
        sendJson(exchange, 200, "{\"status\":\"ok\",\"role\":\"minecraft-embedded-proxy\"}");
    }

    /**
     * Proxy: Nimmt die Play-Drop-Anfrage von NodeClient entgegen und leitet
     * sie an den nächsten erreichbaren Haupt-Node weiter.
     */
    private void handlePlayDrop(com.sun.net.httpserver.HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendJson(exchange, 405, "{\"error\":\"Method not allowed\"}");
            return;
        }

        // Body lesen
        String bodyStr = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);

        // SDK-Key Header durchreichen (vom NodeClient gesetzt)
        String keyHash = exchange.getRequestHeaders().getFirst("X-SDK-Key-Hash");
        String apiKey = exchange.getRequestHeaders().getFirst("X-SDK-Key");

        // An alle Bootstrap-Nodes weiterleiten (best-effort, erster Erfolg zählt)
        for (String nodeUrl : bootstrapNodes) {
            String url = nodeUrl.endsWith("/") ? nodeUrl.substring(0, nodeUrl.length() - 1) : nodeUrl;
            url += "/api/v1/sdk/game/play-drop";

            try {
                HttpRequest.Builder reqBuilder = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofMillis(requestTimeoutMs))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(bodyStr));

                if (keyHash != null && !keyHash.isBlank()) {
                    reqBuilder.header("X-SDK-Key-Hash", keyHash);
                }
                if (apiKey != null && !apiKey.isBlank()) {
                    reqBuilder.header("X-SDK-Key", apiKey);
                }

                HttpResponse<String> res = http.send(reqBuilder.build(), HttpResponse.BodyHandlers.ofString());

                if (res.statusCode() == 200) {
                    // Erfolg — Antwort direkt an NodeClient zurückgeben
                    byte[] respBytes = res.body().getBytes(StandardCharsets.UTF_8);
                    exchange.getResponseHeaders().set("Content-Type", "application/json");
                    exchange.sendResponseHeaders(200, respBytes.length);
                    exchange.getResponseBody().write(respBytes);
                    exchange.getResponseBody().close();
                    return;
                }

                // Fehler vom Haupt-Node loggen und nächsten versuchen
                log.fine("[EmbeddedNode] Play-Drop Proxy zu " + nodeUrl + " fehlgeschlagen: HTTP " + res.statusCode());

            } catch (Exception e) {
                log.fine("[EmbeddedNode] Play-Drop Proxy zu " + nodeUrl + " fehlgeschlagen: " + e.getMessage());
            }
        }

        // Kein Bootstrap-Node erreichbar
        sendJson(exchange, 503, "{\"ok\":false,\"error\":\"Alle Bootstrap-Nodes nicht erreichbar\"}");
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    private void sendJson(com.sun.net.httpserver.HttpExchange exchange, int status, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.getResponseBody().close();
    }
}