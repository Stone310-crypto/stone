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
                log.warning("play-drop CONNECT FAILED " + nodeUrl + " -> " + lastError);
            }
        }

        log.severe("play-drop: ALL " + baseUrls.size() + " NODES FAILED. Last: " + lastError
            + ". Check network and bootstrap_nodes in config.yml.");
        return DropResult.failure(lastError.isEmpty() ? "Kein Node erreichbar" : lastError);
    }

    // ── Heartbeat ────────────────────────────────────────────────────

    /** Sendet Server-Heartbeat mit Game-Typ-Erkennung. */
    public boolean sendHeartbeat(boolean online, int playerCount, String gameType) {
        JsonObject body = new JsonObject();
        body.addProperty("game_id", gameId);
        body.addProperty("online", online);
        body.addProperty("player_count", playerCount);
        body.addProperty("game_type", gameType != null ? gameType : "minecraft");

        String keyHash = sha256Hex(sdkKey);
        for (String nodeUrl : baseUrls) {
            try {
                HttpRequest req = HttpRequest.newBuilder(
                        URI.create(nodeUrl + "/api/v1/sdk/game/heartbeat"))
                    .timeout(Duration.ofSeconds(3))
                    .header("Content-Type", "application/json")
                    .header("X-SDK-Key-Hash", keyHash)
                    .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                    .build();
                HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString());
                if (res.statusCode() == 200) {
                    lastWorkingUrl = nodeUrl;
                    return true;
                }
            } catch (Exception ignored) {}
        }
        return false;
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

    // ── Server Heartbeat ───────────────────────────────────────────────

    /** Sendet Server-Infos (IP, Port, Spielerzahl, MOTD) an den Node. */
    public boolean reportServerInfo(String ip, int port, int playerCount, int maxPlayers, String motd) {
        JsonObject body = new JsonObject();
        body.addProperty("game_id", gameId);
        body.addProperty("ip", ip);
        body.addProperty("port", port);
        body.addProperty("player_count", playerCount);
        body.addProperty("max_players", maxPlayers);
        body.addProperty("motd", motd);

        String keyHash = sha256Hex(sdkKey);

        for (String nodeUrl : baseUrls) {
            try {
                HttpRequest req = HttpRequest.newBuilder(
                        URI.create(nodeUrl + "/api/v1/sdk/game/server/heartbeat"))
                    .timeout(requestTimeout)
                    .header("Content-Type", "application/json")
                    .header("X-SDK-Key-Hash", keyHash)
                    .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                    .build();

                HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString());
                if (res.statusCode() >= 200 && res.statusCode() < 300) {
                    lastWorkingUrl = nodeUrl;
                    return true;
                }
                log.fine("heartbeat failed on " + nodeUrl + " HTTP " + res.statusCode());
            } catch (Exception e) {
                log.fine("heartbeat exception on " + nodeUrl + ": " + e.getMessage());
            }
        }
        return false;
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

    // ── Watchdog: Behavior Violations ────────────────────────────────

    /**
     * Sendet eine Batch-Liste von Spieler-Violations (X-ray, Auto-Clicker, Reach) an den Node.
     */
    public boolean submitViolationBatch(String serverGameId, List<ClientViolationDetector.Violation> violations) {
        if (violations.isEmpty()) return true;

        com.google.gson.JsonArray arr = new com.google.gson.JsonArray();
        for (ClientViolationDetector.Violation v : violations) {
            JsonObject o = new JsonObject();
            o.addProperty("player_id",   v.playerId.toString());
            o.addProperty("player_name", v.playerName);
            o.addProperty("game_id",     serverGameId);
            o.addProperty("violation",   v.type.name());
            o.addProperty("confidence",  v.confidence);
            o.addProperty("details",     v.details);
            o.addProperty("timestamp",   v.timestamp);
            arr.add(o);
        }
        JsonObject body = new JsonObject();
        body.addProperty("game_id", serverGameId);
        body.add("violations", arr);

        String keyHash = sha256Hex(sdkKey);
        for (String nodeUrl : baseUrls) {
            try {
                HttpRequest req = HttpRequest.newBuilder(
                        URI.create(nodeUrl + "/api/v1/sdk/watchdog/behavior-report"))
                    .timeout(requestTimeout)
                    .header("Content-Type", "application/json")
                    .header("X-SDK-Key-Hash", keyHash)
                    .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                    .build();
                HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString());
                if (res.statusCode() >= 200 && res.statusCode() < 300) {
                    lastWorkingUrl = nodeUrl;
                    return true;
                }
            } catch (Exception e) {
                log.fine("[watchdog] behavior-report FAILED " + nodeUrl + ": " + e.getMessage());
            }
        }
        log.warning("[watchdog] behavior-report: alle Nodes nicht erreichbar");
        return false;
    }

    // ── Watchdog: Proof-of-Client-Hash ────────────────────────────────

    /**
     * Sendet einen signierten Proof-of-Client-Hash an den Watchdog-Endpoint.
     *
     * @param proof Signierter Proof (erstellt von ProofOfClientHash)
     * @return ClientProofResult mit ok, trust_level, optional rejection_reason
     */
    public ClientProofResult submitClientProof(ProofOfClientHash.ClientProofPayload proof) {
        JsonObject body = new JsonObject();
        body.addProperty("game_id", proof.gameId);
        body.addProperty("plugin_hash", proof.pluginHash);
        body.addProperty("system_fingerprint", proof.systemFingerprint);
        body.addProperty("timestamp", proof.timestamp);
        body.addProperty("signature", proof.signature);
        body.addProperty("public_key_hex", proof.publicKeyHex);
        JsonArray flags = new JsonArray();
        for (String f : proof.suspiciousFlags) flags.add(f);
        body.add("suspicious_flags", flags);

        String keyHash = sha256Hex(sdkKey);
        String lastError = "";

        for (String nodeUrl : baseUrls) {
            try {
                HttpRequest req = HttpRequest.newBuilder(
                        URI.create(nodeUrl + "/api/v1/sdk/watchdog/client-proof"))
                    .timeout(requestTimeout)
                    .header("Content-Type", "application/json")
                    .header("X-SDK-Key-Hash", keyHash)
                    .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                    .build();

                HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString());
                JsonObject json = JsonParser.parseString(res.body()).getAsJsonObject();
                boolean ok = res.statusCode() >= 200 && res.statusCode() < 300
                    && json.has("ok") && json.get("ok").getAsBoolean();

                String trustLevel = json.has("trust_level")
                    ? json.get("trust_level").getAsString() : "unknown";
                String rejectionReason = json.has("rejection_reason") && !json.get("rejection_reason").isJsonNull()
                    ? json.get("rejection_reason").getAsString() : null;

                if (ok) {
                    lastWorkingUrl = nodeUrl;
                    log.info("[watchdog] client-proof accepted: trust=" + trustLevel
                        + " game=" + proof.gameId + " node=" + nodeUrl);
                    return ClientProofResult.success(trustLevel);
                }
                lastError = rejectionReason != null ? rejectionReason
                    : (json.has("error") ? json.get("error").getAsString() : "HTTP " + res.statusCode());
                log.warning("[watchdog] client-proof REJECTED: " + lastError + " node=" + nodeUrl);

            } catch (Exception e) {
                lastError = e.getClass().getSimpleName() + ": " + e.getMessage();
                log.fine("[watchdog] client-proof CONNECT FAILED " + nodeUrl + " -> " + lastError);
            }
        }

        log.warning("[watchdog] client-proof: ALL NODES FAILED. Last: " + lastError);
        return ClientProofResult.failure(lastError.isEmpty() ? "Kein Node erreichbar" : lastError);
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

    public static final class ClientProofResult {
        public final boolean ok;
        public final String trustLevel;
        public final String error;
        private ClientProofResult(boolean ok, String trustLevel, String error) {
            this.ok = ok; this.trustLevel = trustLevel; this.error = error;
        }
        public static ClientProofResult success(String trustLevel) {
            return new ClientProofResult(true, trustLevel, null);
        }
        public static ClientProofResult failure(String err) {
            return new ClientProofResult(false, "rejected", err);
        }
    }

    // ── PoP Mining ────────────────────────────────────────────────────────────

    /**
     * Signals to the node that this Minecraft server has active players mining.
     * Called by PopMiner when a player breaks a block (throttled to 1/15s).
     * The node uses this to suppress auto-block production while players are active.
     */
    public boolean sendMiningActivity() {
        String keyHash = sha256Hex(sdkKey);
        for (String nodeUrl : baseUrls) {
            try {
                HttpRequest req = HttpRequest.newBuilder(
                        URI.create(nodeUrl + "/api/v1/sdk/mining/activity"))
                    .timeout(requestTimeout)
                    .header("Content-Type", "application/json")
                    .header("X-SDK-Key-Hash", keyHash)
                    .POST(HttpRequest.BodyPublishers.ofString("{}"))
                    .build();
                HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString());
                if (res.statusCode() >= 200 && res.statusCode() < 300) {
                    lastWorkingUrl = nodeUrl;
                    return true;
                }
            } catch (Exception e) {
                log.fine("[pop-mining] activity ping failed " + nodeUrl + ": " + e.getMessage());
            }
        }
        return false;
    }

    /** Fetches the current mining challenge (chain tip + slot + difficulty). */
    public PopMiner.Challenge fetchMiningChallenge() {
        String keyHash = sha256Hex(sdkKey);
        String lastError = "";

        for (String nodeUrl : baseUrls) {
            try {
                HttpRequest req = HttpRequest.newBuilder(
                        URI.create(nodeUrl + "/api/v1/sdk/mining/challenge"))
                    .timeout(requestTimeout)
                    .header("X-SDK-Key-Hash", keyHash)
                    .GET()
                    .build();

                HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString());
                JsonObject json = JsonParser.parseString(res.body()).getAsJsonObject();

                if (res.statusCode() >= 200 && res.statusCode() < 300
                        && json.has("ok") && json.get("ok").getAsBoolean()) {
                    lastWorkingUrl = nodeUrl;
                    return new PopMiner.Challenge(
                        json.get("chain_tip_hash").getAsString(),
                        json.get("slot_id").getAsLong(),
                        json.get("slot_expires_at").getAsLong(),
                        json.get("difficulty_target").getAsString(),
                        json.get("min_activity_events").getAsInt(),
                        json.has("reward_stone") ? json.get("reward_stone").getAsDouble() : 10.0
                    );
                }
                lastError = json.has("error") ? json.get("error").getAsString() : "HTTP " + res.statusCode();
            } catch (Exception e) {
                lastError = e.getClass().getSimpleName() + ": " + e.getMessage();
            }
        }
        log.fine("[pop-mining] challenge fetch failed: " + lastError);
        return null;
    }

    /** Submits a PoP block-find proof to the node. */
    public MiningResult submitMiningProof(MiningProofPayload proof) {
        JsonObject body = new JsonObject();
        body.addProperty("game_id",              proof.gameId);
        body.addProperty("player_wallet",        proof.playerWallet);
        body.addProperty("slot_id",              proof.slotId);
        body.addProperty("vrf_input_hash",       proof.vrfInputHash);
        body.addProperty("vrf_output",           proof.vrfOutput);
        body.addProperty("plugin_pubkey",        proof.pluginPubkey);
        body.addProperty("plugin_hash",          proof.pluginHash);
        body.addProperty("activity_event_count", proof.activityEventCount);
        body.addProperty("timestamp",            proof.timestamp);

        String keyHash = sha256Hex(sdkKey);
        String lastError = "";

        for (String nodeUrl : baseUrls) {
            try {
                HttpRequest req = HttpRequest.newBuilder(
                        URI.create(nodeUrl + "/api/v1/sdk/mining/submit"))
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
                    double reward = json.has("reward_stone") ? json.get("reward_stone").getAsDouble() : 0.0;
                    String txId   = json.has("tx_id") && !json.get("tx_id").isJsonNull()
                        ? json.get("tx_id").getAsString() : "";
                    return MiningResult.success(reward, txId);
                }
                lastError = json.has("error") ? json.get("error").getAsString() : "HTTP " + res.statusCode();
                log.warning("[pop-mining] submit rejected: " + lastError + " node=" + nodeUrl);

            } catch (Exception e) {
                lastError = e.getClass().getSimpleName() + ": " + e.getMessage();
            }
        }

        log.warning("[pop-mining] submit: ALL NODES FAILED. Last: " + lastError);
        return MiningResult.failure(lastError.isEmpty() ? "Kein Node erreichbar" : lastError);
    }

    /** Returns the game_id associated with this NodeClient. */
    public String gameId() { return gameId; }

    // ── PoP Mining result types ───────────────────────────────────────────────

    public static final class MiningProofPayload {
        public final String gameId;
        public final String playerWallet;
        public final long   slotId;
        public final String vrfInputHash;
        public final String vrfOutput;
        public final String pluginPubkey;
        public final String pluginHash;
        public final int    activityEventCount;
        public final long   timestamp;

        public MiningProofPayload(String gameId, String playerWallet, long slotId,
                                  String vrfInputHash, String vrfOutput, String pluginPubkey,
                                  String pluginHash, int activityEventCount, long timestamp) {
            this.gameId             = gameId;
            this.playerWallet       = playerWallet;
            this.slotId             = slotId;
            this.vrfInputHash       = vrfInputHash;
            this.vrfOutput          = vrfOutput;
            this.pluginPubkey       = pluginPubkey;
            this.pluginHash         = pluginHash;
            this.activityEventCount = activityEventCount;
            this.timestamp          = timestamp;
        }
    }

    public static final class MiningResult {
        public final boolean ok;
        public final double  rewardStone;
        public final String  txId;
        public final String  error;

        private MiningResult(boolean ok, double rewardStone, String txId, String error) {
            this.ok          = ok;
            this.rewardStone = rewardStone;
            this.txId        = txId;
            this.error       = error;
        }
        public static MiningResult success(double reward, String txId) {
            return new MiningResult(true, reward, txId, null);
        }
        public static MiningResult failure(String err) {
            return new MiningResult(false, 0, "", err);
        }
    }
}