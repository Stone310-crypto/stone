package net.stonechain.mcplugin;

import java.io.*;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.WebSocket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Logger;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * libp2p-lite: Echter P2P-Teilnehmer mit Ed25519-PeerId im Stone-Netzwerk.
 *
 * Architektur:
 * ┌──────────────┐   libp2p-identity   ┌────────────────┐
 * │ Minecraft    │ ◄── WebSocket ──► │ Haupt-Nodes    │
 * │ Plugin       │   (TX/Block-Relay) │ (Gossipsub)    │
 * │ PeerId: ...  │                    │                │
 * └──────────────┘                    └────────────────┘
 *
 * Features:
 * - Ed25519-Keypair + PeerId (kompatibel mit Rust-Stone-Node)
 * - WebSocket-Verbindung zu Bootstrap-Nodes
 * - Echtzeit Mempool/Block-Empfang (kein Polling)
 * - Auto-Reconnect mit Exponential-Backoff
 * - Resource-Limits: CPU%, RAM-MB, Network-KB/s
 * - Deaktivierbar via config.yml: p2p_node.enabled: false
 */
public final class LightP2pNode {

    // ── Konstanten ───────────────────────────────────────────────────────
    static final int TX_CACHE_SIZE = 1000;
    private static final int PEER_ID_MULTIHASH_CODE = 0x12; // sha2-256
    private static final int PEER_ID_LENGTH = 32;

    // ── Resource-Limit-Tracker ───────────────────────────────────────────
    static class ResourceLimits {
        /** 0-100 (0 = unlimitiert) */
        int cpuPercent = 0;
        /** 0 = unlimitiert, sonst MB */
        int ramMb = 0;
        /** 0 = unlimitiert, sonst KB/s */
        int networkKbps = 0;
        // Current usage trackers
        final AtomicLong bytesSent = new AtomicLong(0);
        final AtomicLong bytesReceived = new AtomicLong(0);
        final AtomicLong lastResetMs = new AtomicLong(System.currentTimeMillis());

        boolean isExceeded() {
            if (networkKbps <= 0) return false;
            long now = System.currentTimeMillis();
            long elapsed = now - lastResetMs.get();
            if (elapsed >= 1000) {
                bytesSent.set(0);
                bytesReceived.set(0);
                lastResetMs.set(now);
            }
            long totalKb = (bytesSent.get() + bytesReceived.get()) / 1024;
            return totalKb > networkKbps;
        }
    }

    // ── Fields ──────────────────────────────────────────────────────────
    private final Logger log;
    private final ResourceLimits limits = new ResourceLimits();
    private final HttpClient http;
    private final ScheduledExecutorService scheduler;

    // Identity
    private String peerId;
    private byte[] publicKeyBytes;
    private PrivateKey privateKey;

    // Bootstrap
    private final List<String> bootstrapNodes;
    private final int requestTimeoutMs;

    // State
    private final Set<String> knownTxIds;
    private final List<JsonObject> recentTransactions;
    private final Map<String, WebSocket> activeSockets;
    private final AtomicInteger reconnectAttempts = new AtomicInteger(0);

    private volatile boolean running;
    private volatile boolean connected;

    // ── Constructor ─────────────────────────────────────────────────────
    public LightP2pNode(
        List<String> bootstrapNodes,
        int connectTimeoutMs,
        int requestTimeoutMs,
        int cpuLimit,
        int ramLimitMb,
        int networkLimitKbps,
        Logger log
    ) {
        this.bootstrapNodes = new ArrayList<>(bootstrapNodes);
        this.requestTimeoutMs = requestTimeoutMs;
        this.log = log;

        this.limits.cpuPercent = cpuLimit;
        this.limits.ramMb = ramLimitMb;
        this.limits.networkKbps = networkLimitKbps;

        this.http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofMillis(connectTimeoutMs))
            .build();

        this.knownTxIds = ConcurrentHashMap.newKeySet(TX_CACHE_SIZE);
        this.recentTransactions = Collections.synchronizedList(new ArrayList<>(TX_CACHE_SIZE));
        this.activeSockets = new ConcurrentHashMap<>();

        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "stone-p2p");
            t.setDaemon(true);
            t.setPriority(Thread.NORM_PRIORITY - 1);
            return t;
        });
    }

    // ── Public API ──────────────────────────────────────────────────────

    public void start() {
        if (running) return;
        running = true;

        // 1. Ed25519 Identity laden oder generieren
        loadOrGenerateIdentity();

        log.info("[LightP2pNode] PeerId: " + peerId);
        log.info("[LightP2pNode] Bootstrap: " + bootstrapNodes.size() + " Nodes");

        if (limits.networkKbps > 0) {
            log.info("[LightP2pNode] Network-Limit: " + limits.networkKbps + " KB/s");
        }
        if (limits.ramMb > 0) {
            log.info("[LightP2pNode] RAM-Limit: " + limits.ramMb + " MB");
        }

        // 2. Verbindung zu Bootstrap-Nodes aufbauen
        for (String nodeUrl : bootstrapNodes) {
            connectToNode(nodeUrl);
        }

        // 3. Periodischer Reconnect + Health-Check
        scheduler.scheduleWithFixedDelay(() -> {
            if (!running) return;
            for (String node : bootstrapNodes) {
                if (!activeSockets.containsKey(node)) {
                    log.fine("[LightP2pNode] Reconnect zu " + node + "...");
                    connectToNode(node);
                }
            }
        }, 30, 30, TimeUnit.SECONDS);

        log.info("[LightP2pNode] libp2p-lite Relay aktiv (peer=" + peerId + ")");
    }

    public void stop() {
        running = false;
        // Alle WebSockets schließen
        for (WebSocket ws : activeSockets.values()) {
            try { ws.sendClose(1000, "shutdown"); } catch (Exception ignored) {}
        }
        activeSockets.clear();
        if (scheduler != null && !scheduler.isShutdown()) {
            scheduler.shutdownNow();
        }
        log.info("[LightP2pNode] Gestoppt.");
    }

    public String getPeerId() { return peerId; }
    public byte[] getPublicKey() { return publicKeyBytes; }
    public List<JsonObject> getRecentTransactions() {
        synchronized (recentTransactions) { return new ArrayList<>(recentTransactions); }
    }
    public int knownTxCount() { return knownTxIds.size(); }
    public boolean isConnected() { return connected; }
    public ResourceLimits getLimits() { return limits; }

    /** Broadcastet eine Nachricht an alle verbundenen WebSocket-Nodes. */
    public void broadcast(String message) {
        if (!running) return;
        if (limits.isExceeded()) return;
        for (Map.Entry<String, WebSocket> entry : activeSockets.entrySet()) {
            try {
                entry.getValue().sendText(message, true);
                limits.bytesSent.addAndGet(message.length());
            } catch (Exception ignored) {
                activeSockets.remove(entry.getKey());
            }
        }
    }

    // ── Identity ────────────────────────────────────────────────────────

    private void loadOrGenerateIdentity() {
        File keyFile = new File("stone_data", "p2p.key");
        try {
            if (keyFile.exists()) {
                // Bestehenden Key laden
                byte[] raw = java.nio.file.Files.readAllBytes(keyFile.toPath());
                if (raw.length == 32) {
                    PrivateKey sk = KeyFactory.getInstance("Ed25519")
                        .generatePrivate(new PKCS8EncodedKeySpec(wrapPkcs8(raw)));
                    PublicKey pk = KeyFactory.getInstance("Ed25519")
                        .generatePublic(new X509EncodedKeySpec(wrapX509(raw)));
                    this.privateKey = sk;
                    this.publicKeyBytes = pk.getEncoded();
                    // Ed25519 X.509 key: the raw key bytes are the last 32 bytes
                    byte[] rawPub = new byte[32];
                    System.arraycopy(pk.getEncoded(), pk.getEncoded().length - 32, rawPub, 0, 32);
                    this.publicKeyBytes = rawPub;
                }
            }
        } catch (Exception e) {
            log.warning("[LightP2pNode] Konnte p2p.key nicht laden: " + e.getMessage());
        }

        if (this.privateKey == null) {
            // Neu generieren
            try {
                KeyPairGenerator gen = KeyPairGenerator.getInstance("Ed25519");
                KeyPair kp = gen.generateKeyPair();
                this.privateKey = kp.getPrivate();
                PublicKey pk = kp.getPublic();
                // Rohe 32-Byte Public Key extrahieren
                byte[] encoded = pk.getEncoded();
                this.publicKeyBytes = new byte[32];
                System.arraycopy(encoded, encoded.length - 32, this.publicKeyBytes, 0, 32);
                // Raw Private Key speichern (32 Bytes)
                // Ed25519 private key is 32 bytes seed
                byte[] rawPriv = new byte[32];
                // Extract seed from PKCS8
                byte[] pkcs8 = privateKey.getEncoded();
                System.arraycopy(pkcs8, pkcs8.length - 32, rawPriv, 0, 32);
                File dir = new File("stone_data");
                if (!dir.exists()) dir.mkdirs();
                java.nio.file.Files.write(keyFile.toPath(), rawPriv);
                log.info("[LightP2pNode] Neues Ed25519-Keypair generiert → stone_data/p2p.key");
            } catch (Exception e) {
                log.severe("[LightP2pNode] Key-Generierung fehlgeschlagen: " + e.getMessage());
                this.publicKeyBytes = new byte[32];
            }
        }

        // PeerId = multihash(SHA-256(pubkey))
        this.peerId = computePeerId(this.publicKeyBytes);
    }

    /** Multihash: 0x12 (sha2-256) + 0x20 (32 bytes) + SHA-256(pubkey) → hex → base58 */
    private static String computePeerId(byte[] pubkey) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha.digest(pubkey);
            // Multihash: [code][len][digest]
            byte[] mh = new byte[2 + hash.length];
            mh[0] = (byte) PEER_ID_MULTIHASH_CODE;
            mh[1] = (byte) PEER_ID_LENGTH;
            System.arraycopy(hash, 0, mh, 2, hash.length);
            // Base58 encode
            return base58Encode(mh);
        } catch (Exception e) {
            return "unknown";
        }
    }

    // ── WebSocket ────────────────────────────────────────────────────────

    private void connectToNode(String nodeUrl) {
        if (limits.isExceeded()) {
            log.fine("[LightP2pNode] Network-Limit erreicht, überspringe Connect");
            return;
        }
        try {
            String wsUrl = nodeUrl
                .replace("http://", "ws://")
                .replace("https://", "wss://");
            if (!wsUrl.endsWith("/")) wsUrl += "/";
            wsUrl += "ws"; // Rust-Node WebSocket endpoint

            URI uri = URI.create(wsUrl);
            WebSocket.Builder builder = HttpClient.newHttpClient().newWebSocketBuilder();
            builder.connectTimeout(Duration.ofMillis(requestTimeoutMs));

            AtomicInteger retries = new AtomicInteger(0);
            builder.buildAsync(uri, new WebSocket.Listener() {
                private final StringBuilder buffer = new StringBuilder();

                public void onOpen(WebSocket webSocket) {
                    activeSockets.put(nodeUrl, webSocket);
                    connected = true;
                    reconnectAttempts.set(0);
                    log.info("[LightP2pNode] WebSocket verbunden: " + nodeUrl);

                    // Peer-Info senden
                    JsonObject hello = new JsonObject();
                    hello.addProperty("type", "hello");
                    hello.addProperty("peer_id", peerId);
                    hello.addProperty("role", "minecraft-light-node");
                    hello.addProperty("game_id", ""); // wird später gesetzt
                    webSocket.sendText(hello.toString(), true);
                    webSocket.request(1);
                }

                public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
                    buffer.append(data);
                    if (last) {
                        String msg = buffer.toString();
                        buffer.setLength(0);
                        limits.bytesReceived.addAndGet(msg.length());
                        handleMessage(msg);
                        webSocket.request(1);
                    }
                    return null;
                }

                public CompletionStage<?> onClose(WebSocket webSocket, int statusCode, String reason) {
                    activeSockets.remove(nodeUrl);
                    log.fine("[LightP2pNode] WebSocket geschlossen: " + nodeUrl + " (" + statusCode + ")");
                    scheduleReconnect(nodeUrl);
                    return null;
                }

                public void onError(WebSocket webSocket, Throwable error) {
                    activeSockets.remove(nodeUrl);
                    log.fine("[LightP2pNode] WebSocket-Fehler: " + error.getMessage());
                    scheduleReconnect(nodeUrl);
                }
            }).join();

        } catch (Exception e) {
            log.fine("[LightP2pNode] Connect zu " + nodeUrl + " fehlgeschlagen: " + e.getMessage());
        }
    }

    private void scheduleReconnect(String nodeUrl) {
        int attempt = reconnectAttempts.incrementAndGet();
        long delay = Math.min(60, (long) Math.pow(2, Math.min(attempt, 6)));
        scheduler.schedule(() -> {
            if (running && !activeSockets.containsKey(nodeUrl)) {
                log.fine("[LightP2pNode] Reconnect-Versuch #" + attempt + " zu " + nodeUrl);
                connectToNode(nodeUrl);
            }
        }, delay, TimeUnit.SECONDS);
    }

    private void handleMessage(String msg) {
        try {
            JsonElement el = JsonParser.parseString(msg);
            if (!el.isJsonObject()) return;
            JsonObject obj = el.getAsJsonObject();
            String type = obj.has("type") ? obj.get("type").getAsString() : "";

            switch (type) {
                case "tx": // Neue Mempool-TX
                    if (obj.has("tx")) {
                        JsonObject tx = obj.getAsJsonObject("tx");
                        String txId = tx.has("tx_id") ? tx.get("tx_id").getAsString() : "";
                        if (!txId.isEmpty() && knownTxIds.add(txId)) {
                            synchronized (recentTransactions) {
                                recentTransactions.add(tx);
                                if (recentTransactions.size() > TX_CACHE_SIZE) {
                                    recentTransactions.remove(0);
                                }
                            }
                        }
                    }
                    break;
                case "block": // Neuer Block
                    if (obj.has("block")) {
                        JsonObject block = obj.getAsJsonObject("block");
                        // TXs aus dem Block extrahieren und cachen
                        if (block.has("transactions") && block.get("transactions").isJsonArray()) {
                            JsonArray txs = block.getAsJsonArray("transactions");
                            for (var txEl : txs) {
                                JsonObject tx = txEl.getAsJsonObject();
                                String txId = tx.has("tx_id") ? tx.get("tx_id").getAsString() : "";
                                if (!txId.isEmpty() && knownTxIds.add(txId)) {
                                    synchronized (recentTransactions) {
                                        recentTransactions.add(tx);
                                        if (recentTransactions.size() > TX_CACHE_SIZE) {
                                            recentTransactions.remove(0);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    break;
                case "welcome":
                    log.info("[LightP2pNode] Vom Node registriert: " +
                        (obj.has("node_id") ? obj.get("node_id").getAsString() : "unknown"));
                    break;
                default:
                    // Unbekannte Nachrichtentypen ignorieren
                    break;
            }
        } catch (Exception ignored) {
            // Malformed JSON — ignorieren
        }
    }

    // ── Utils ───────────────────────────────────────────────────────────

    /** Minimal Base58 encoder (Bitcoin Alphabet) */
    private static String base58Encode(byte[] data) {
        String alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        // Count leading zeros
        int zeros = 0;
        while (zeros < data.length && data[zeros] == 0) zeros++;

        byte[] tmp = new byte[data.length * 138 / 100 + 1];
        int tmpLen = 0;
        for (int i = zeros; i < data.length; i++) {
            int carry = data[i] & 0xFF;
            for (int j = 0; j < tmpLen; j++) {
                carry += (tmp[j] & 0xFF) * 256;
                tmp[j] = (byte)(carry % 58);
                carry /= 58;
            }
            while (carry > 0) {
                if (tmpLen >= tmp.length) {
                    byte[] bigger = new byte[tmp.length * 2];
                    System.arraycopy(tmp, 0, bigger, 0, tmp.length);
                    tmp = bigger;
                }
                tmp[tmpLen++] = (byte)(carry % 58);
                carry /= 58;
            }
        }

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < zeros; i++) sb.append('1');
        for (int i = tmpLen - 1; i >= 0; i--) {
            sb.append(alphabet.charAt(tmp[i] & 0xFF));
        }
        return sb.toString();
    }

    /** Minimal PKCS8 wrapper für Ed25519 Private Key (32 Bytes Seed) */
    private static byte[] wrapPkcs8(byte[] rawSeed) {
        // Ed25519 PKCS8: 302e020100300506032b657004220420 + 32 bytes seed
        byte[] prefix = hexToBytes("302e020100300506032b657004220420");
        byte[] wrapped = new byte[prefix.length + 32];
        System.arraycopy(prefix, 0, wrapped, 0, prefix.length);
        System.arraycopy(rawSeed, 0, wrapped, prefix.length, 32);
        return wrapped;
    }

    /** Minimal X.509 SPKI wrapper für Ed25519 Public Key (32 Bytes) */
    private static byte[] wrapX509(byte[] rawPub) {
        // Ed25519 SPKI: 302a300506032b6570032100 + 32 bytes pubkey
        byte[] prefix = hexToBytes("302a300506032b6570032100");
        byte[] wrapped = new byte[prefix.length + 32];
        System.arraycopy(prefix, 0, wrapped, 0, prefix.length);
        System.arraycopy(rawPub, 0, wrapped, prefix.length, 32);
        return wrapped;
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}