package net.stonechain.mcplugin;

import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.entity.HumanEntity;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.event.inventory.InventoryCloseEvent;
import org.bukkit.event.inventory.InventoryDragEvent;
import org.bukkit.inventory.Inventory;
import org.bukkit.inventory.InventoryHolder;
import org.bukkit.inventory.ItemStack;

import java.util.UUID;

/**
 * Per-player virtual vault that can store only Stone Shards and owned Stone Coins.
 */
public final class PersonalVault {

    public static final int SIZE = 54;

    public static void open(StoneMcPlugin plugin, Player player) {
        UUID owner = player.getUniqueId();
        Inventory inv = Bukkit.createInventory(new Holder(owner), SIZE,
            ChatColor.DARK_AQUA + "Personal Vault");
        inv.setContents(plugin.vaultStore().getContents(owner, SIZE));
        player.openInventory(inv);
    }

    private static boolean isAllowedVaultItem(ItemStack item, UUID owner) {
        if (item == null || item.getType().isAir()) return true;
        if (StoneShard.is(item)) return true;
        return StoneCoin.is(item) && StoneCoin.ownedBy(item, owner);
    }

    public static final class Holder implements InventoryHolder {
        private final UUID owner;
        public Holder(UUID owner) { this.owner = owner; }
        public UUID owner() { return owner; }
        @Override public Inventory getInventory() { return null; }
    }

    public static final class ClickListener implements Listener {
        private final StoneMcPlugin plugin;
        public ClickListener(StoneMcPlugin plugin) { this.plugin = plugin; }

        @EventHandler(ignoreCancelled = true)
        public void onClick(InventoryClickEvent e) {
            if (!(e.getWhoClicked() instanceof Player p)) return;
            if (e.getView() == null) return;
            Inventory top = e.getView().getTopInventory();
            if (top == null || !(top.getHolder() instanceof Holder h)) return;

            UUID owner = h.owner();
            HumanEntity who = e.getWhoClicked();
            if (!who.getUniqueId().equals(owner)) {
                e.setCancelled(true);
                return;
            }

            int raw = e.getRawSlot();
            boolean clickTop = raw >= 0 && raw < top.getSize();

            // Shift-click from player inventory into vault.
            if (!clickTop && e.isShiftClick()) {
                ItemStack moving = e.getCurrentItem();
                if (!isAllowedVaultItem(moving, owner)) {
                    e.setCancelled(true);
                    p.sendMessage(ChatColor.RED + "In die Vault dürfen nur Stone Shards und deine Stone Coins.");
                }
                return;
            }

            // Placing into vault (cursor -> top slot) must be allowed.
            if (clickTop) {
                ItemStack cursor = e.getCursor();
                if (!isAllowedVaultItem(cursor, owner)) {
                    e.setCancelled(true);
                    p.sendMessage(ChatColor.RED + "In die Vault dürfen nur Stone Shards und deine Stone Coins.");
                }
            }
        }

        @EventHandler(ignoreCancelled = true)
        public void onDrag(InventoryDragEvent e) {
            Inventory top = e.getView() == null ? null : e.getView().getTopInventory();
            if (top == null || !(top.getHolder() instanceof Holder h)) return;

            UUID owner = h.owner();
            if (!e.getWhoClicked().getUniqueId().equals(owner)) {
                e.setCancelled(true);
                return;
            }

            // If any dragged slot touches top inventory, validate dragged item.
            for (int raw : e.getRawSlots()) {
                if (raw < top.getSize()) {
                    if (!isAllowedVaultItem(e.getOldCursor(), owner)) {
                        e.setCancelled(true);
                    }
                    return;
                }
            }
        }

        @EventHandler
        public void onClose(InventoryCloseEvent e) {
            Inventory top = e.getView() == null ? null : e.getView().getTopInventory();
            if (top == null || !(top.getHolder() instanceof Holder h)) return;
            plugin.vaultStore().setContents(h.owner(), top.getContents());
            plugin.vaultStore().save();
        }
    }
}
