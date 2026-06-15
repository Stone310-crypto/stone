package net.stonechain.mcplugin;

import org.bukkit.ChatColor;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.entity.EntityPickupItemEvent;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.event.player.PlayerDropItemEvent;
import org.bukkit.event.player.PlayerInteractEvent;
import org.bukkit.inventory.EquipmentSlot;
import org.bukkit.inventory.ItemStack;

/**
 * Interaction and soulbound protection for Stone Scroll.
 */
public final class StoneMenuScrollListener implements Listener {

    private final StoneMcPlugin plugin;

    public StoneMenuScrollListener(StoneMcPlugin plugin) {
        this.plugin = plugin;
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onUse(PlayerInteractEvent e) {
        ItemStack it;
        if (e.getHand() == EquipmentSlot.HAND) {
            it = e.getPlayer().getInventory().getItemInMainHand();
        } else if (e.getHand() == EquipmentSlot.OFF_HAND) {
            it = e.getPlayer().getInventory().getItemInOffHand();
        } else {
            it = e.getItem();
        }
        if (!StoneMenuScroll.is(it)) return;

        Player p = e.getPlayer();
        if (!StoneMenuScroll.ownedBy(it, p.getUniqueId())) {
            e.setCancelled(true);
            ItemStack fixed = StoneMenuScroll.create(p);
            if (e.getHand() == EquipmentSlot.OFF_HAND) {
                p.getInventory().setItemInOffHand(fixed);
            } else {
                p.getInventory().setItemInMainHand(fixed);
            }
            p.sendMessage(ChatColor.YELLOW + "Stone Scroll wurde auf dein Profil aktualisiert. Bitte erneut rechtsklicken.");
            return;
        }

        // Right-click opens menu; cancel to avoid accidental vanilla interactions.
        switch (e.getAction()) {
            case RIGHT_CLICK_AIR:
            case RIGHT_CLICK_BLOCK:
                e.setCancelled(true);
                // Use next tick + command fallback to survive conflicts with other listeners.
                plugin.getServer().getScheduler().runTask(plugin, () -> {
                    p.performCommand("smenu");
                });
                break;
            default:
                break;
        }
    }

    @EventHandler(priority = EventPriority.HIGH, ignoreCancelled = true)
    public void onDrop(PlayerDropItemEvent e) {
        ItemStack it = e.getItemDrop().getItemStack();
        if (!StoneMenuScroll.is(it)) return;
        e.setCancelled(true);
        e.getPlayer().sendMessage(ChatColor.RED + "Die Stone Scroll kann nicht weggeworfen werden.");
    }

    @EventHandler(priority = EventPriority.HIGH, ignoreCancelled = true)
    public void onPickup(EntityPickupItemEvent e) {
        ItemStack it = e.getItem().getItemStack();
        if (!StoneMenuScroll.is(it)) return;
        if (!(e.getEntity() instanceof Player p)) {
            e.setCancelled(true);
            return;
        }
        if (!StoneMenuScroll.ownedBy(it, p.getUniqueId())) {
            e.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.HIGH, ignoreCancelled = true)
    public void onClick(InventoryClickEvent e) {
        ItemStack current = e.getCurrentItem();
        ItemStack cursor = e.getCursor();
        if (current != null && StoneMenuScroll.is(current) && !StoneMenuScroll.ownedBy(current, e.getWhoClicked().getUniqueId())) {
            e.setCancelled(true);
            return;
        }
        if (cursor != null && StoneMenuScroll.is(cursor) && !StoneMenuScroll.ownedBy(cursor, e.getWhoClicked().getUniqueId())) {
            e.setCancelled(true);
        }
    }
}
