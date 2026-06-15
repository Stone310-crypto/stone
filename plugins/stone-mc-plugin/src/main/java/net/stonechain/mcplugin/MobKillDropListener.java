package net.stonechain.mcplugin;

import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.entity.EntityDeathEvent;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Awards STONE on mob kills (entity types listed in {@code mobs.tiers}).
 * Only kills with a player as killer count.
 */
public final class MobKillDropListener implements Listener {

    private final StoneMcPlugin plugin;
    private final Map<String, Double> tiers;
    private final double chance;
    private final int cooldownSecs;
    private final PlayerWalletStore wallets;
    private final ScoreboardManager scoreboard;
    private final ConcurrentHashMap<UUID, Long> lastDropMs = new ConcurrentHashMap<>();

    public MobKillDropListener(
        StoneMcPlugin plugin,
        Map<String, Double> tiers,
        double chance,
        int cooldownSecs,
        PlayerWalletStore wallets,
        ScoreboardManager scoreboard
    ) {
        this.plugin = plugin;
        this.tiers = tiers;
        this.chance = chance;
        this.cooldownSecs = cooldownSecs;
        this.wallets = wallets;
        this.scoreboard = scoreboard;
    }

    @EventHandler(priority = EventPriority.MONITOR, ignoreCancelled = true)
    public void onDeath(EntityDeathEvent event) {
        Player killer = event.getEntity().getKiller();
        if (killer == null) return;
        if (killer.getGameMode().name().equals("CREATIVE")) return;

        // PoP Mining: mob kills count as gameplay activity
        if (plugin.popMiner() != null) plugin.popMiner().onPlayerActivity(killer);

        String type = event.getEntityType().name();
        Double amount = tiers.get(type);
        if (amount == null || amount <= 0.0) return;

        long now = System.currentTimeMillis();
        Long last = lastDropMs.get(killer.getUniqueId());
        if (last != null && (now - last) < cooldownSecs * 1000L) return;

        if (ThreadLocalRandom.current().nextDouble() >= StoneMcPlugin.clamp(chance, 0.0, 1.0)) return;

        lastDropMs.put(killer.getUniqueId(), now);

        int shardCount = (int) Math.max(1, Math.round(amount));
        org.bukkit.inventory.ItemStack shards = StoneShard.create(plugin.shardLedger(), killer.getUniqueId(), shardCount);
        plugin.shardLedger().save();
        java.util.Map<Integer, org.bukkit.inventory.ItemStack> overflow = killer.getInventory().addItem(shards);
        for (org.bukkit.inventory.ItemStack o : overflow.values()) {
            killer.getWorld().dropItemNaturally(killer.getLocation(), o);
        }
        wallets.addShards(killer.getUniqueId(), shardCount);

        long shardsTotal = wallets.totalShards(killer.getUniqueId());
        String msg = "§b+ " + shardCount + " Stone Shard" + (shardCount > 1 ? "s" : "")
                   + "  §7(" + type + ")  §7| §eGesamt: §f" + shardsTotal;
        killer.sendActionBar(net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer.legacySection().deserialize(msg));
        scoreboard.refresh(killer);
    }
}
