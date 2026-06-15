package net.stonechain.mcplugin;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Persists per-player pending balance + linked Stonechain address as JSON in
 * the plugin's data folder. Atomic save via tmp file + rename.
 */
public final class PlayerWalletStore {

    private static final Gson GSON = new Gson();

    private final File dataFolder;
    private final File file;
    private final Map<UUID, Double> pending = new ConcurrentHashMap<>();
    private final Map<UUID, String> linked  = new ConcurrentHashMap<>();
    private final Map<UUID, Double> totalEarned = new ConcurrentHashMap<>();
    private final Map<UUID, Double> totalRedeemed = new ConcurrentHashMap<>();
    private final Map<UUID, Long>   totalShards   = new ConcurrentHashMap<>();
    private final Map<UUID, Long>   totalCoins    = new ConcurrentHashMap<>();
    private final Map<UUID, Long>   totalCoinsRedeemed = new ConcurrentHashMap<>();
    // Daily redeem tracking (epoch-day bucket, UTC)
    private final Map<UUID, Long>   redeemDayEpoch  = new ConcurrentHashMap<>();
    private final Map<UUID, Double> redeemDayAmount = new ConcurrentHashMap<>();

    public PlayerWalletStore(File dataFolder) {
        this.dataFolder = dataFolder;
        this.file = new File(dataFolder, "wallets.json");
    }

    public synchronized void load() {
        pending.clear();
        linked.clear();
        totalEarned.clear();
        totalRedeemed.clear();
        totalShards.clear();
        totalCoins.clear();
        totalCoinsRedeemed.clear();
        redeemDayEpoch.clear();
        redeemDayAmount.clear();

        if (!file.exists()) return;
        try (FileReader r = new FileReader(file)) {
            Type t = new TypeToken<PersistedState>(){}.getType();
            PersistedState st = GSON.fromJson(r, t);
            if (st != null) {
                if (st.pending != null) for (var e : st.pending.entrySet())
                    pending.put(UUID.fromString(e.getKey()), e.getValue());
                if (st.linked  != null) for (var e : st.linked.entrySet())
                    linked.put(UUID.fromString(e.getKey()), e.getValue());
                if (st.totalEarned != null) for (var e : st.totalEarned.entrySet())
                    totalEarned.put(UUID.fromString(e.getKey()), e.getValue());
                if (st.totalRedeemed != null) for (var e : st.totalRedeemed.entrySet())
                    totalRedeemed.put(UUID.fromString(e.getKey()), e.getValue());
                if (st.totalShards != null) for (var e : st.totalShards.entrySet())
                    totalShards.put(UUID.fromString(e.getKey()), e.getValue());
                if (st.totalCoins != null) for (var e : st.totalCoins.entrySet())
                    totalCoins.put(UUID.fromString(e.getKey()), e.getValue());
                if (st.totalCoinsRedeemed != null) for (var e : st.totalCoinsRedeemed.entrySet())
                    totalCoinsRedeemed.put(UUID.fromString(e.getKey()), e.getValue());
                if (st.redeemDayEpoch != null) for (var e : st.redeemDayEpoch.entrySet())
                    redeemDayEpoch.put(UUID.fromString(e.getKey()), e.getValue());
                if (st.redeemDayAmount != null) for (var e : st.redeemDayAmount.entrySet())
                    redeemDayAmount.put(UUID.fromString(e.getKey()), e.getValue());
            }
        } catch (IOException | RuntimeException e) {
            // first run / unreadable — ignore, start fresh
        }
    }

    public synchronized void save() {
        if (!dataFolder.exists()) dataFolder.mkdirs();
        PersistedState st = new PersistedState();
        st.pending = new HashMap<>();
        for (var e : pending.entrySet()) st.pending.put(e.getKey().toString(), e.getValue());
        st.linked  = new HashMap<>();
        for (var e : linked.entrySet())  st.linked.put(e.getKey().toString(), e.getValue());
        st.totalEarned = new HashMap<>();
        for (var e : totalEarned.entrySet()) st.totalEarned.put(e.getKey().toString(), e.getValue());
        st.totalRedeemed = new HashMap<>();
        for (var e : totalRedeemed.entrySet()) st.totalRedeemed.put(e.getKey().toString(), e.getValue());
        st.totalShards = new HashMap<>();
        for (var e : totalShards.entrySet()) st.totalShards.put(e.getKey().toString(), e.getValue());
        st.totalCoins = new HashMap<>();
        for (var e : totalCoins.entrySet()) st.totalCoins.put(e.getKey().toString(), e.getValue());
        st.totalCoinsRedeemed = new HashMap<>();
        for (var e : totalCoinsRedeemed.entrySet()) st.totalCoinsRedeemed.put(e.getKey().toString(), e.getValue());
        st.redeemDayEpoch = new HashMap<>();
        for (var e : redeemDayEpoch.entrySet()) st.redeemDayEpoch.put(e.getKey().toString(), e.getValue());
        st.redeemDayAmount = new HashMap<>();
        for (var e : redeemDayAmount.entrySet()) st.redeemDayAmount.put(e.getKey().toString(), e.getValue());

        File tmp = new File(file.getAbsolutePath() + ".tmp");
        try (FileWriter w = new FileWriter(tmp)) {
            GSON.toJson(st, w);
        } catch (IOException e) {
            return;
        }
        try {
            Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException ex) {
            try {
                Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException ignored) { }
        } catch (IOException ignored) { }
    }

    public void credit(UUID id, double amount) {
        pending.merge(id, amount, Double::sum);
        totalEarned.merge(id, amount, Double::sum);
    }

    /** Refund a previously debited amount without affecting totalEarned (rollback). */
    public void refund(UUID id, double amount) {
        pending.merge(id, amount, Double::sum);
    }

    public synchronized void debit(UUID id, double amount) {
        double cur = pending.getOrDefault(id, 0.0);
        double next = Math.max(0.0, cur - amount);
        if (next == 0.0) pending.remove(id);
        else pending.put(id, next);
    }

    /** Called after a successful on-chain redeem to track lifetime payouts. */
    public void markRedeemed(UUID id, double amount) {
        totalRedeemed.merge(id, amount, Double::sum);
    }

    public double pendingBalance(UUID id) {
        return pending.getOrDefault(id, 0.0);
    }

    public double totalEarned(UUID id) {
        return totalEarned.getOrDefault(id, 0.0);
    }

    public double totalRedeemed(UUID id) {
        return totalRedeemed.getOrDefault(id, 0.0);
    }

    public void addShards(UUID id, int n) {
        if (n <= 0) return;
        totalShards.merge(id, (long) n, Long::sum);
    }

    public void addCoinsCrafted(UUID id, int n) {
        if (n <= 0) return;
        totalCoins.merge(id, (long) n, Long::sum);
    }

    public long totalShards(UUID id) {
        return totalShards.getOrDefault(id, 0L);
    }

    public long totalCoinsCrafted(UUID id) {
        return totalCoins.getOrDefault(id, 0L);
    }

    public void markCoinsRedeemed(UUID id, int n) {
        if (n <= 0) return;
        totalCoinsRedeemed.merge(id, (long) n, Long::sum);
    }

    public long totalCoinsRedeemed(UUID id) {
        return totalCoinsRedeemed.getOrDefault(id, 0L);
    }

    /** How much STONE this player has redeemed today (UTC day bucket). */
    public double redeemedToday(UUID id) {
        long today = java.time.LocalDate.now(java.time.ZoneOffset.UTC).toEpochDay();
        Long day = redeemDayEpoch.get(id);
        if (day == null || day != today) return 0.0;
        return redeemDayAmount.getOrDefault(id, 0.0);
    }

    /** Records a successful redeem against today's daily bucket. */
    public void markRedeemedToday(UUID id, double amount) {
        long today = java.time.LocalDate.now(java.time.ZoneOffset.UTC).toEpochDay();
        Long existing = redeemDayEpoch.get(id);
        if (existing == null || existing != today) {
            redeemDayEpoch.put(id, today);
            redeemDayAmount.put(id, amount);
        } else {
            redeemDayAmount.merge(id, amount, Double::sum);
        }
    }

    public void link(UUID id, String address) {
        linked.put(id, address);
    }

    public void unlink(UUID id) {
        linked.remove(id);
    }

    public String linkedAddress(UUID id) {
        return linked.get(id);
    }

    private static final class PersistedState {
        Map<String, Double> pending;
        Map<String, String> linked;
        Map<String, Double> totalEarned;
        Map<String, Double> totalRedeemed;
        Map<String, Long>   totalShards;
        Map<String, Long>   totalCoins;
        Map<String, Long>   totalCoinsRedeemed;
        Map<String, Long>   redeemDayEpoch;
        Map<String, Double> redeemDayAmount;
    }
}
