package net.stonechain.mcplugin;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Multi-Node SDK client with automatic failover.
 *
 * Wenn ein Node ausfällt, wird automatisch der nächste probiert.
 * Das Plugin bleibt so auch bei Node-Ausfällen funktionsfähig.
 */
public final class NodeClient {

    public final List<String> baseUrls;
    private final String gameId;
    private final String sdkKey;
    private final HttpClient http;
    private final Duration requestTimeout;
    private final Logger log;
    private volatile String lastWorkingUrl;

    public NodeClient(String baseUrl, String gameId, String sdkKey,
                      int connectTimeoutMs, int requestTimeoutMs, Logger log) {
        this(Collections.singletonList(baseUrl), gameId, sdkKey, connectTimeoutMs, requestTimeoutMs, log);
    }

    public NodeClient(List<String> baseUrls, String gameId, String sdkKey,
                      int connectTimeoutMs, int requestTimeoutMs, Logger log) {
        this.baseUrls = new ArrayList<>();
        for (String u : baseUrls) {
            String url = u.endsWith("/") ? u.substring(0, u.length() - 1) : u;
            String lower = url.toLowerCase();
            if (lower.startsWith("http://") && !lower.startsWith("http://127.0.0.1")
                && !lower.startsWith("http://localhost")) {
                log.warning("SECURITY: node_url verwendet HTTP (unverschluesselt): " + url);
            }
            this.baseUrls.add(url);
        }
        this.gameId = gameId;
        this.sdkKey = sdkKey;
        this.requestTimeout = Duration.ofMillis(requestTimeoutMs);
        this.lastWorkingUrl = this.baseUrls.isEmpty() ? "" : this.baseUrls.get(0);
        this.log = log;
        this.http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofMillis(connectTimeoutMs))
            .build();
    }

    // ── Drop / Redeem ──────────────────────────────────────────────────

    public DropResult submitDrop(String playerWallet, double amount, String dropId, String reason) {
        JsonObject body = new JsonObject();
        body.addProperty("game_id", gameId);
        body.addProperty("player_wallet", playerWallet);
        String amt = String.format(java.util.Locale.US, "%.8f", amount);
        if (amt.contains(".")) {
            amt = amt.replaceAll("0+$", "");
            if (amt.endsWith(".")) amt = amt.substring(0, amt.length() - 1);
        }
        body.addProperty("amount", amt);
        if (dropId != null) body.addProperty("drop_id", dropId);
        if (reason != null) body.addProperty("reason", reason);

        String keyHash = sha256Hex(sdkKey);
        String lastError = "";

        for (String nodeUrl : baseUrls) {
            try {
                HttpRequest req = HttpRequest.newBuilder(
                        URI.create(nodeUrl + "/api/v1/sdk/game/play-drop"))
                    .timeout(requestTimeout)
                    .header("Content-Type", "application/json")
                    .header("X-SDK-Key-Hash", keyHash)
                    .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                    .build();

                HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString());
                JsonObject json = JsonParser.parseString(res.body()).getAsJsonObject();
                boolean ok = res.statusCode() >= 200 && res.statusCode() < 300
                    && json.has("ok") && json.get("ok").getAsBoolean();

                if (ok) {
                    lastWorkingUrl = nodeUrl;

                    String txId = "";
                    if (json.has("tx_id") && !json.get("tx_id").isJsonNull())
                        txId = json.get("tx_id").getAsString();

                    String txIds = "";
                    if (json.has("tx_ids") && json.get("tx_ids").isJsonArray()) {
                        JsonArray arr = json.getAsJsonArray("tx_ids");
                        StringBuilder sb = new StringBuilder();
                        for (JsonElement el : arr) {
                            if (!el.isJsonNull()) {
                                String s = el.getAsString();
                                if (!s.isBlank()) {
                                    if (sb.length() > 0) sb.append(",");
                                    sb.append(s);
                                    if (txId.isBlank()) txId = s;
                                }
                            }
                        }
                        txIds = sb.toString();
                    }

                    log.info("play-drop accepted: game_id=" + gameId
                        + " player=" + playerWallet + " amount=" + amt
                        + " tx_id=" + (txId.isBlank() ? "n/a" : txId)
                        + " node=" + nodeUrl);
                    return DropResult.success(txId, txIds);
                }
                lastError = json.has("error") ? json.get("error").getAsString()
                    : ("HTTP " + res.statusCode());
                log.fine("play-drop failed on " + nodeUrl + ": " + lastError);

            } catch (Exception e) {
                lastError = e.getClass().getSimpleName() + ": " + e.getMessage();
                log.warning("play-drop CONNECT FAILED " + nodeUrl + " → " + lastError);
            }
        }

        log.severe("play-drop: ALL " + baseUrls.size() + " NODES FAILED. Last: " + lastError
            + ". Check network and bootstrap_nodes in config.yml.");
        return DropResult.failure(lastError.isEmpty() ? "Kein Node erreichbar" : lastError);
    }

    // ── Auth / Dashboard ───────────────────────────────────────────────

    public AuthCheckResult checkDeveloperAuth() {
        for (String nodeUrl : baseUrls) {
            try {
                HttpRequest req = HttpRequest.newBuilder(
                        URI.create(nodeUrl + "/api/v1/sdk/developer/dashboard"))
                    .timeout(requestTimeout)
                    .header("X-SDK-Key", sdkKey)
                    .GET()
                    .build();

                HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString());
                JsonObject json = JsonParser.parseString(res.body()).getAsJsonObject();
                boolean ok = res.statusCode() >= 200 && res.statusCode() < 300
                    && json.has("ok") && json.get("ok").getAsBoolean();
                if (ok) {
                    lastWorkingUrl = nodeUrl;
                    return new AuthCheckResult(true, res.statusCode(), null);
                }
                String error = json.has("error") ? json.get("error").getAsString() : null;
                return new AuthCheckResult(false, res.statusCode(), error);
            } catch (Exception e) {
                // try next
            }
        }
        return new AuthCheckResult(false, -1, "Kein Node erreichbar");
    }

    // ── PoolCoin Sell ─────────────────────────────────────────────────

    /** Sendet PoolCoins zum Node → 80% Recycling + 20% STONE-Auszahlung. */
    public SellResult submitSell(String playerWallet, long poolCoins, String reason) {
        JsonObject body = new JsonObject();
        body.addProperty("game_id", gameId);
        body.addProperty("player_wallet", playerWallet);
        body.addProperty("pool_coins", poolCoins);
        if (reason != null) body.addProperty("reason", reason);

        String keyHash = sha256Hex(sdkKey);
        String lastError = "";

        for (String nodeUrl : baseUrls) {
            try {
                HttpRequest req = HttpRequest.newBuilder(
                        URI.create(nodeUrl + "/api/v1/sdk/game/play-sell"))
                    .timeout(requestTimeout)
                    .header("Content-Type", "application/json")
                    .header("X-SDK-Key-Hash", keyHash)
                    .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                    .build();

                HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString());
                JsonObject json = JsonParser.parseString(res.body()).getAsJsonObject();
                boolean ok = res.statusCode() >= 200 && res.statusCode() < 300
                    && json.has("ok") && json.get("ok").getAsBoolean();

                if (ok) {
                    lastWorkingUrl = nodeUrl;
                    double stone = json.has("stone_received") ? json.get("stone_received").getAsDouble() : 0.0;
                    log.info("play-sell accepted: game_id=" + gameId
                        + " player=" + playerWallet + " coins=" + poolCoins
                        + " stone=" + stone + " node=" + nodeUrl);
                    return SellResult.success(stone);
                }
                lastError = json.has("error") ? json.get("error").getAsString() : ("HTTP " + res.statusCode());
            } catch (Exception e) {
                lastError = e.getMessage();
            }
        }

        log.warning("play-sell: ALL NODES FAILED. Last: " + lastError);
        return SellResult.failure(lastError);
    }

    // ── Config Upload ──────────────────────────────────────────────────

    public ConfigUploadResult uploadConfig(JsonObject configJson) {
        String keyHash = sha256Hex(sdkKey);
        for (String nodeUrl : baseUrls) {
            try {
                HttpRequest req = HttpRequest.newBuilder(
                        URI.create(nodeUrl + "/api/v1/sdk/game/config/upload"))
                    .timeout(requestTimeout)
                    .header("Content-Type", "application/json")
                    .header("X-SDK-Key-Hash", keyHash)
                    .POST(HttpRequest.BodyPublishers.ofString(configJson.toString()))
                    .build();

                HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString());
                JsonObject json = JsonParser.parseString(res.body()).getAsJsonObject();
                boolean ok = res.statusCode() >= 200 && res.statusCode() < 300
                    && json.has("ok") && json.get("ok").getAsBoolean();
                if (ok) {
                    log.info("config-upload: game_id=" + gameId + " stored=true node=" + nodeUrl);
                    return ConfigUploadResult.success();
                }
            } catch (Exception e) {
                // try next
            }
        }
        log.warning("config-upload: ALL NODES FAILED");
        return ConfigUploadResult.failure("Kein Node erreichbar");
    }

    // ── Utils ──────────────────────────────────────────────────────────

    private static String sha256Hex(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    // ── Result types ───────────────────────────────────────────────────

    public static final class DropResult {
        public final boolean ok;
        public final String txId;
        public final String txIdsCsv;
        public final String error;
        private DropResult(boolean ok, String txId, String txIdsCsv, String error) {
            this.ok = ok; this.txId = txId; this.txIdsCsv = txIdsCsv; this.error = error;
        }
        public static DropResult success(String txId, String txIdsCsv) {
            return new DropResult(true, txId, txIdsCsv, null);
        }
        public static DropResult failure(String err) {
            return new DropResult(false, "", "", err);
        }
    }

    public static final class SellResult {
        public final boolean ok;
        public final double stoneReceived;
        public final String error;
        private SellResult(boolean ok, double stone, String error) {
            this.ok = ok; this.stoneReceived = stone; this.error = error;
        }
        public static SellResult success(double stone) { return new SellResult(true, stone, null); }
        public static SellResult failure(String err) { return new SellResult(false, 0, err); }
    }

    public static final class ConfigUploadResult {
        public final boolean ok;
        public final String error;
        private ConfigUploadResult(boolean ok, String error) { this.ok = ok; this.error = error; }
        public static ConfigUploadResult success() { return new ConfigUploadResult(true, null); }
        public static ConfigUploadResult failure(String err) { return new ConfigUploadResult(false, err); }
    }

    public static final class AuthCheckResult {
        public final boolean ok;
        public final int httpStatus;
        public final String error;
        public AuthCheckResult(boolean ok, int httpStatus, String error) {
            this.ok = ok; this.httpStatus = httpStatus; this.error = error;
        }
    }
}