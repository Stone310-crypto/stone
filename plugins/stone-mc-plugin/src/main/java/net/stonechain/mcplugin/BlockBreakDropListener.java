package net.stonechain.mcplugin;

import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.block.BlockBreakEvent;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Hooks BlockBreakEvent and credits the player's local pending balance with a
 * configurable probability. Drop amount is determined by the per-block tier
 * map. The actual on-chain payout happens lazily on /stoneredeem.
 */
public final class BlockBreakDropListener implements Listener {

    private final StoneMcPlugin plugin;
    private final StoneMcPlugin.DropConfig cfg;
    private final NodeClient node;             // reserved for future direct payout
    private final PlayerWalletStore wallets;
    private final ScoreboardManager scoreboard;
    private final Map<String, Double> tiers;
    private final ConcurrentHashMap<UUID, Long> lastDropMs = new ConcurrentHashMap<>();

    public BlockBreakDropListener(
        StoneMcPlugin plugin,
        StoneMcPlugin.DropConfig cfg,
        NodeClient node,
        PlayerWalletStore wallets,
        ScoreboardManager scoreboard
    ) {
        this.plugin = plugin;
        this.cfg    = cfg;
        this.node   = node;
        this.wallets = wallets;
        this.scoreboard = scoreboard;
        this.tiers  = cfg.tiers();
    }

    @EventHandler(priority = EventPriority.MONITOR, ignoreCancelled = true)
    public void onBreak(BlockBreakEvent event) {
        Player player = event.getPlayer();
        if (player.getGameMode().name().equals("CREATIVE")) return;

        String type = event.getBlock().getType().name();
        Double tierAmount = tiers.get(type);
        if (tierAmount == null || tierAmount <= 0.0) return;

        long now = System.currentTimeMillis();
        Long last = lastDropMs.get(player.getUniqueId());
        if (last != null && (now - last) < cfg.cooldownSecs() * 1000L) return;

        double roll = ThreadLocalRandom.current().nextDouble();
        if (roll >= StoneMcPlugin.clamp(cfg.chance(), 0.0, 1.0)) return;

        lastDropMs.put(player.getUniqueId(), now);

        int shardCount = (int) Math.max(1, Math.round(tierAmount));
        org.bukkit.inventory.ItemStack shards = StoneShard.create(plugin.shardLedger(), player.getUniqueId(), shardCount);
        plugin.shardLedger().save();
        java.util.Map<Integer, org.bukkit.inventory.ItemStack> overflow = player.getInventory().addItem(shards);
        for (org.bukkit.inventory.ItemStack o : overflow.values()) {
            player.getWorld().dropItemNaturally(player.getLocation(), o);
        }
        wallets.addShards(player.getUniqueId(), shardCount);

        long shardsTotal = wallets.totalShards(player.getUniqueId());
        String msg = "§b+ " + shardCount + " Stone Shard" + (shardCount > 1 ? "s" : "")
                   + "  §7| §eGesamt: §f" + shardsTotal;
        player.sendActionBar(net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer.legacySection().deserialize(msg));
        scoreboard.refresh(player);

        if (plugin.rareBlocks() != null) {
            plugin.rareBlocks().maybeAwardRareBlock(player);
        }
    }
}
