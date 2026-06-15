package net.stonechain.mcplugin;

import org.bukkit.entity.Player;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

/**
 * Proof-of-Play (PoP) Mining
 *
 * Players "find blocks" while playing the game. The randomness comes from the
 * current chain tip, making it impossible to predict or pre-compute a win.
 *
 * Protocol per slot (default 60 s):
 *   1. Fetch challenge from node (chain_tip_hash + slot_id + difficulty_target)
 *   2. Each time a player acts AND hasn't tried this slot yet:
 *      vrf_input  = SHA-256(chain_tip | player_wallet | slot_id | game_id)
 *      vrf_output = Ed25519_sign(proof_key, vrf_input)     ← deterministic VRF
 *      found      = SHA-256(vrf_output)[0..4] as u32 < difficulty_target_u32
 *   3. If found: submit proof → node issues STONE reward
 */
public final class PopMiner {

    private static final long SLOT_SECS = 60L;

    // ── State ────────────────────────────────────────────────────────────────

    private final StoneMcPlugin plugin;
    private final NodeClient nodeClient;
    private final ProofOfClientHash proofIdentity;
    private final Logger log;

    // Cached challenge (refreshed once per slot)
    private volatile Challenge currentChallenge = null;

    // Per-player: slot_id of last mining attempt (to guarantee one attempt per slot)
    private final Map<UUID, Long> lastAttemptSlot = new ConcurrentHashMap<>();

    // Per-player: event count in the current slot (reset when slot changes)
    private final Map<UUID, Integer> slotActivity  = new ConcurrentHashMap<>();
    private volatile long activitySlot = 0L;

    // Throttle for activity pings to the node (max 1 per ACTIVITY_PING_INTERVAL_MS)
    private static final long ACTIVITY_PING_INTERVAL_MS = 15_000L;
    private volatile long lastActivityPingMs = 0L;

    public PopMiner(StoneMcPlugin plugin, NodeClient nodeClient, ProofOfClientHash proofIdentity) {
        this.plugin        = plugin;
        this.nodeClient    = nodeClient;
        this.proofIdentity = proofIdentity;
        this.log           = plugin.getLogger();
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Called for every meaningful gameplay event (block break, mob kill, …).
     * Safe to call from Bukkit's main thread; VRF computation runs async.
     */
    public void onPlayerActivity(Player player) {
        long slot = currentSlot();

        // Reset activity counters when a new slot begins
        if (slot != activitySlot) {
            slotActivity.clear();
            activitySlot = slot;
        }
        slotActivity.merge(player.getUniqueId(), 1, Integer::sum);

        // Only one VRF attempt per player per slot
        Long last = lastAttemptSlot.get(player.getUniqueId());
        if (last != null && last == slot) return;

        Challenge challenge = currentChallenge;
        if (challenge == null || challenge.slotId != slot) return; // no fresh challenge yet

        int activity = slotActivity.getOrDefault(player.getUniqueId(), 0);
        if (activity < challenge.minActivityEvents) return; // not enough gameplay yet

        String wallet = plugin.wallets().linkedAddress(player.getUniqueId());
        if (wallet == null || wallet.isBlank()) return; // wallet not linked

        // Activity ping to node: suppresses auto-block while players are mining.
        // Throttled to one HTTP request per ACTIVITY_PING_INTERVAL_MS per server.
        long nowMs = System.currentTimeMillis();
        if (nowMs - lastActivityPingMs >= ACTIVITY_PING_INTERVAL_MS) {
            lastActivityPingMs = nowMs;
            plugin.getServer().getScheduler().runTaskAsynchronously(plugin, () ->
                nodeClient.sendMiningActivity()
            );
        }

        // Mark as attempted now (before async to prevent double-dispatch)
        lastAttemptSlot.put(player.getUniqueId(), slot);
        final int finalActivity = activity;
        final Challenge finalChallenge = challenge;
        final String finalWallet = wallet;

        plugin.getServer().getScheduler().runTaskAsynchronously(plugin, () ->
            attempt(player, finalWallet, finalChallenge, finalActivity)
        );
    }

    /**
     * Refresh the challenge from the node. Should be called once per slot
     * (60 s) from a scheduled async task.
     */
    public void refreshChallenge() {
        plugin.getServer().getScheduler().runTaskAsynchronously(plugin, () -> {
            try {
                Challenge c = nodeClient.fetchMiningChallenge();
                if (c != null) {
                    currentChallenge = c;
                    log.fine("[pop-mining] challenge slot=" + c.slotId
                        + " diff=" + c.difficultyTarget
                        + " tip=" + c.chainTipHash.substring(0, Math.min(16, c.chainTipHash.length())) + "...");
                }
            } catch (Exception e) {
                log.warning("[pop-mining] challenge fetch fehlgeschlagen: " + e.getMessage());
            }
        });
    }

    // ── VRF attempt (runs on async thread) ───────────────────────────────────

    private void attempt(Player player, String wallet, Challenge challenge, int activity) {
        try {
            String gameId = nodeClient.gameId();

            // VRF input: deterministic, no parameter the plugin can manipulate
            String vrfInputStr = challenge.chainTipHash + "|" + wallet + "|" + challenge.slotId + "|" + gameId;
            byte[] vrfInputHash = sha256(vrfInputStr.getBytes(StandardCharsets.UTF_8));

            // VRF output: Ed25519 signature over vrf_input_hash (deterministic with same key)
            byte[] vrfOutput = proofIdentity.sign(vrfInputHash);

            // Difficulty check: first 4 bytes of SHA-256(vrf_output) < target
            byte[] vrfHash = sha256(vrfOutput);
            if (!meetsTarget(vrfHash, challenge.difficultyTarget)) {
                return; // no block found this slot — silent
            }

            log.info("[pop-mining] ⛏ Block gefunden! Spieler=" + player.getName()
                + " wallet=" + wallet + " slot=" + challenge.slotId);

            // Submit proof to node
            NodeClient.MiningProofPayload proof = new NodeClient.MiningProofPayload(
                gameId,
                wallet,
                challenge.slotId,
                hexEncode(vrfInputHash),
                hexEncode(vrfOutput),
                proofIdentity.getPublicKeyHex(),
                proofIdentity.getPluginHash(),
                activity,
                System.currentTimeMillis() / 1000L
            );

            NodeClient.MiningResult result = nodeClient.submitMiningProof(proof);

            if (result.ok) {
                String msg = "§b§l⛏ Block gefunden! §r§b+" + result.rewardStone + " STONE gutgeschrieben!";
                plugin.getServer().getScheduler().runTask(plugin, () -> {
                    if (player.isOnline()) player.sendMessage(msg);
                });
                log.info("[pop-mining] reward player=" + player.getName()
                    + " stone=" + result.rewardStone + " tx=" + result.txId);
            } else {
                log.warning("[pop-mining] proof rejected: " + result.error);
            }

        } catch (Exception e) {
            log.warning("[pop-mining] VRF-Fehler: " + e.getMessage());
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Returns true if the first 4 bytes of hash (as big-endian u32) are less than
     * the 8-char hex difficulty target.
     */
    private static boolean meetsTarget(byte[] hash, String difficultyTarget) {
        long hashVal = ((hash[0] & 0xFFL) << 24)
                     | ((hash[1] & 0xFFL) << 16)
                     | ((hash[2] & 0xFFL) <<  8)
                     |  (hash[3] & 0xFFL);
        long targetVal = Long.parseLong(difficultyTarget, 16);
        return hashVal < targetVal;
    }

    private static byte[] sha256(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    private static String hexEncode(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }

    private static long currentSlot() {
        return System.currentTimeMillis() / 1000L / SLOT_SECS;
    }

    // ── Challenge DTO ─────────────────────────────────────────────────────────

    public static final class Challenge {
        public final String chainTipHash;
        public final long   slotId;
        public final long   slotExpiresAt;
        public final String difficultyTarget;
        public final int    minActivityEvents;
        public final double rewardStone;

        public Challenge(String chainTipHash, long slotId, long slotExpiresAt,
                         String difficultyTarget, int minActivityEvents, double rewardStone) {
            this.chainTipHash      = chainTipHash;
            this.slotId            = slotId;
            this.slotExpiresAt     = slotExpiresAt;
            this.difficultyTarget  = difficultyTarget;
            this.minActivityEvents = minActivityEvents;
            this.rewardStone       = rewardStone;
        }
    }
}
