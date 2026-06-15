package net.stonechain.mcplugin;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

/**
 * Anti-dupe ledger for Stone Shards.
 *
 * Shards sind pro Owner fungibel und sollen normal stacken. Deshalb wird
 * dieselbe owner-gebundene Ledger-ID fuer alle Shards eines Spielers genutzt.
 * Die verbleibende Menge wird im Ledger aggregiert und beim Craft dekrementiert.
 *
 * Folge: Creative-Klone teilen sich dieselbe owner-gebundene Ledger-ID. Sobald
 * die legitim erspielte Gesamtmenge verbraucht ist, schlagen Crafts mit geklonten
 * Shards fehl — der Dupe wird erkannt, ohne das normale Stacken zu brechen.
 */
public final class ShardLedger {

    public static final class Entry {
        public String nonce;
        public String player;
        public long issuedAt;
        public int remaining;
    }

    private final File file;
    private final Logger log;
    private final Map<UUID, Entry> entries = new ConcurrentHashMap<>();
    private final Gson gson = new GsonBuilder().setPrettyPrinting().create();

    public ShardLedger(File dataFolder, Logger log) {
        this.file = new File(dataFolder, "shard_ledger.json");
        this.log = log;
    }

    @SuppressWarnings("unchecked")
    public synchronized void load() {
        if (!file.exists()) return;
        try {
            String s = new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
            Map<String, Entry> raw = gson.fromJson(s, new com.google.gson.reflect.TypeToken<Map<String, Entry>>(){}.getType());
            if (raw == null) return;
            for (var e : raw.entrySet()) {
                try { entries.put(UUID.fromString(e.getKey()), e.getValue()); }
                catch (IllegalArgumentException ignored) {}
            }
            log.info("ShardLedger loaded: " + entries.size() + " entries");
        } catch (Exception ex) {
            log.warning("ShardLedger load failed: " + ex.getMessage());
        }
    }

    public synchronized void save() {
        try {
            Map<String, Entry> raw = new HashMap<>();
            for (var e : entries.entrySet()) raw.put(e.getKey().toString(), e.getValue());
            String json = gson.toJson(raw);
            Path tmp = file.toPath().resolveSibling(file.getName() + ".tmp");
            Files.write(tmp, json.getBytes(StandardCharsets.UTF_8));
            Files.move(tmp, file.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (Exception ex) {
            log.warning("ShardLedger save failed: " + ex.getMessage());
        }
    }

    /**
     * Registriert neue Shards fuer einen Owner und gibt die owner-gebundene
     * Ledger-ID zurueck. Dieselbe ID wird fuer alle Shards des Players genutzt,
     * damit Minecraft die Stacks zusammenlegen kann.
     */
    public UUID issue(UUID player, int amount) {
        Entry e = entries.get(player);
        if (e == null) {
            e = new Entry();
            e.nonce = player.toString();
            e.player = player.toString();
            e.issuedAt = System.currentTimeMillis();
            e.remaining = 0;
            entries.put(player, e);
        }
        e.remaining += amount;
        return player;
    }

    /**
     * Versucht {@code amount} Shards aus der Nonce zu konsumieren.
     * Gibt {@code true} zurück wenn ok, {@code false} wenn die Nonce
     * unbekannt ist oder zu wenig "remaining" hat (= Dupe-Verdacht).
     */
    public synchronized boolean consume(UUID nonce, int amount) {
        Entry e = entries.get(nonce);
        if (e == null) return false;
        if (e.remaining < amount) return false;
        e.remaining -= amount;
        if (e.remaining <= 0) entries.remove(nonce);
        return true;
    }

    public Entry peek(UUID nonce) { return entries.get(nonce); }

    public int size() { return entries.size(); }
}
