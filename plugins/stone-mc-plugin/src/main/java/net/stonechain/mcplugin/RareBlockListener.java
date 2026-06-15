package net.stonechain.mcplugin;

import org.bukkit.ChatColor;
import org.bukkit.enchantments.Enchantment;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.block.BlockBreakEvent;
import org.bukkit.event.block.BlockPlaceEvent;
import org.bukkit.inventory.ItemStack;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Handles rare block placement, harvest rewards, and rare item drops.
 */
public final class RareBlockListener implements Listener {

    private final StoneMcPlugin plugin;
    private final RareBlockStore store;
    private final Map<UUID, Long> lastRareMs = new ConcurrentHashMap<>();

    public RareBlockListener(StoneMcPlugin plugin, RareBlockStore store) {
        this.plugin = plugin;
        this.store = store;
    }

    public RareBlockStore store() {
        return store;
    }

    public void maybeAwardRareBlock(Player player) {
        if (!plugin.getConfig().getBoolean("rare_block.enabled", true)) return;

        int cooldown = plugin.getConfig().getInt("rare_block.drop_cooldown_secs", 15);
        long now = System.currentTimeMillis();
        Long last = lastRareMs.get(player.getUniqueId());
        if (last != null && now - last < cooldown * 1000L) return;

        double chance = plugin.getConfig().getDouble("rare_block.find_chance", 0.0005D);
        if (ThreadLocalRandom.current().nextDouble() >= StoneMcPlugin.clamp(chance, 0.0, 1.0)) return;

        lastRareMs.put(player.getUniqueId(), now);
        ItemStack item = RareBlock.create(1);
        Map<Integer, ItemStack> overflow = player.getInventory().addItem(item);
        for (ItemStack rest : overflow.values()) {
            player.getWorld().dropItemNaturally(player.getLocation(), rest);
        }
        player.sendMessage(ChatColor.LIGHT_PURPLE + "Du hast einen seltenen Stone Core gefunden!");
    }

    @EventHandler(ignoreCancelled = true)
    public void onPlace(BlockPlaceEvent e) {
        ItemStack hand = e.getItemInHand();
        if (!RareBlock.is(hand)) return;
        store.mark(e.getBlockPlaced().getLocation());
        e.getPlayer().sendMessage(ChatColor.GRAY + "Stone Core platziert.");
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onBreak(BlockBreakEvent e) {
        if (!store.isRare(e.getBlock().getLocation())) return;

        store.unmark(e.getBlock().getLocation());

        if (e.getPlayer().getGameMode().name().equals("CREATIVE")) {
            e.setDropItems(false);
            return;
        }

        ItemStack tool = e.getPlayer().getInventory().getItemInMainHand();
        boolean silk = tool != null && tool.containsEnchantment(Enchantment.SILK_TOUCH);

        e.setDropItems(false);
        e.setExpToDrop(0);

        if (silk) {
            Map<Integer, ItemStack> overflow = e.getPlayer().getInventory().addItem(RareBlock.create(1));
            for (ItemStack rest : overflow.values()) {
                e.getPlayer().getWorld().dropItemNaturally(e.getBlock().getLocation(), rest);
            }
            e.getPlayer().sendMessage(ChatColor.AQUA + "Stone Core mit Silk Touch geborgen.");
            return;
        }

        int reward = plugin.getConfig().getInt("rare_block.shard_reward", 32);
        reward = Math.max(1, Math.min(64, reward));

        ItemStack shards = StoneShard.create(plugin.shardLedger(), e.getPlayer().getUniqueId(), reward);
        plugin.shardLedger().save();
        Map<Integer, ItemStack> overflow = e.getPlayer().getInventory().addItem(shards);
        for (ItemStack rest : overflow.values()) {
            e.getPlayer().getWorld().dropItemNaturally(e.getBlock().getLocation(), rest);
        }
        plugin.wallets().addShards(e.getPlayer().getUniqueId(), reward);
        plugin.wallets().save();
        plugin.scoreboard().refresh(e.getPlayer());
        e.getPlayer().sendMessage(ChatColor.GREEN + "+" + reward + " Stone Shards aus Stone Core");
    }
}
