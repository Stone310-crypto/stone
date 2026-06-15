package net.stonechain.mcplugin;

import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.Material;
import org.bukkit.NamespacedKey;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.inventory.Inventory;
import org.bukkit.inventory.ItemStack;
import org.bukkit.inventory.meta.ItemMeta;
import org.bukkit.persistence.PersistentDataContainer;
import org.bukkit.persistence.PersistentDataType;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Browse + Buy GUI für den Server-Shop. Spieler bezahlen mit StoneShards.
 */
public final class ShopMenu {

    public static final String TITLE = ChatColor.DARK_AQUA + "" + ChatColor.BOLD + "Stone Shop";
    private static final int SIZE = 54; // 6 Reihen
    private static NamespacedKey KEY_SHOP_ITEM_ID;

    public static void init(StoneMcPlugin plugin) {
        KEY_SHOP_ITEM_ID = new NamespacedKey(plugin, "shop_item_id");
    }

    public static void open(StoneMcPlugin plugin, Player player) {
        Inventory inv = Bukkit.createInventory(player, SIZE, TITLE);
        List<ShopStore.Item> items = plugin.shopStore().snapshot();
        int max = Math.min(items.size(), SIZE - 9); // letzte Zeile = Footer
        for (int i = 0; i < max; i++) {
            inv.setItem(i, render(items.get(i)));
        }
        // Footer-Info (Slot 49 = Mitte der letzten Reihe)
        long shardsInv = countShards(player);
        ItemStack info = new ItemStack(Material.PRISMARINE_SHARD);
        ItemMeta im = info.getItemMeta();
        if (im != null) {
            im.setDisplayName(ChatColor.AQUA + "" + ChatColor.BOLD + "Deine Shards: " + shardsInv);
            im.setLore(Arrays.asList(
                ChatColor.GRAY + "Klicke ein Item um es zu kaufen.",
                ChatColor.GRAY + "Bezahlt wird mit Stone Shards."
            ));
            info.setItemMeta(im);
        }
        inv.setItem(49, info);
        player.openInventory(inv);
    }

    private static ItemStack render(ShopStore.Item it) {
        StoneMcPlugin plugin = (StoneMcPlugin) Bukkit.getPluginManager().getPlugin("StoneMC");
        ItemStack stack = plugin == null ? null : plugin.shopStore().materialize(it);
        if (stack == null) stack = new ItemStack(Material.BARRIER);
        ItemMeta m = stack.getItemMeta();
        if (m != null) {
            List<String> lore = new ArrayList<>();
            if (m.hasLore() && m.getLore() != null) lore.addAll(m.getLore());
            if (!lore.isEmpty()) lore.add("");
            lore.add(ChatColor.YELLOW + "Preis: " + ChatColor.AQUA + it.priceShards + " Shards");
            lore.add(ChatColor.GRAY + "Klick: kaufen");
            lore.add(ChatColor.DARK_GRAY + "ID: " + it.id);
            m.setLore(lore);
            PersistentDataContainer pdc = m.getPersistentDataContainer();
            pdc.set(KEY_SHOP_ITEM_ID, PersistentDataType.STRING, it.id);
            stack.setItemMeta(m);
        }
        return stack;
    }

    private static long countShards(Player p) {
        return countValidShards(p, null);
    }

    /** Zählt nur Shards deren Nonce im Ledger gültig ist (Anti-Dupe). */
    private static long countValidShards(Player p, ShardLedger ledger) {
        long c = 0;
        for (ItemStack s : p.getInventory().getStorageContents()) {
            if (StoneShard.is(s)) {
                java.util.UUID nonce = StoneShard.nonce(s);
                if (ledger == null || nonce == null || ledger.peek(nonce) != null) {
                    c += s.getAmount();
                }
            }
        }
        return c;
    }

    /** Zieht `shards` Stone-Shards aus dem Inventar. Gibt true wenn erfolgreich. */
    private static boolean removeShards(Player p, long shards) {
        return removeShards(p, shards, null);
    }

    /**
     * Zieht Shards mit Anti-Dupe-Check gegen das ShardLedger.
     * Shards mit ungültiger/fehlender Nonce werden übersprungen und geloggt.
     */
    private static boolean removeShards(Player p, long shards, ShardLedger ledger) {
        if (countValidShards(p, ledger) < shards) return false;
        long remaining = shards;
        ItemStack[] inv = p.getInventory().getStorageContents();
        for (int i = 0; i < inv.length && remaining > 0; i++) {
            ItemStack s = inv[i];
            if (!StoneShard.is(s)) continue;
            // Anti-Dupe: überspringe Shards mit invalider Nonce im Ledger
            if (ledger != null) {
                java.util.UUID nonce = StoneShard.nonce(s);
                if (nonce != null && ledger.peek(nonce) == null) {
                    inv[i] = null; // Gefälschten Shard entfernen
                    p.sendMessage(ChatColor.RED + "Gefälschter Shard (Nonce=" + nonce + ") aus Inventar entfernt.");
                    continue;
                }
            }
            int take = (int) Math.min(s.getAmount(), remaining);
            if (take >= s.getAmount()) {
                inv[i] = null;
            } else {
                s.setAmount(s.getAmount() - take);
            }
            remaining -= take;
        }
        p.getInventory().setStorageContents(inv);
        return remaining == 0;
    }

    public static final class ClickListener implements Listener {
        private final StoneMcPlugin plugin;
        public ClickListener(StoneMcPlugin plugin) { this.plugin = plugin; }

        @EventHandler
        public void onClick(InventoryClickEvent e) {
            if (e.getView() == null) return;
            String title = e.getView().getTitle();
            if (!TITLE.equals(title)) return;
            e.setCancelled(true);
            if (!(e.getWhoClicked() instanceof Player p)) return;
            if (e.getClickedInventory() == null
                || !e.getClickedInventory().equals(e.getView().getTopInventory())) {
                return;
            }
            ItemStack clicked = e.getCurrentItem();
            if (clicked == null || clicked.getType() == Material.AIR) return;
            ItemMeta m = clicked.getItemMeta();
            if (m == null) return;
            String id = m.getPersistentDataContainer().get(KEY_SHOP_ITEM_ID, PersistentDataType.STRING);
            if (id == null) return;
            ShopStore.Item it = plugin.shopStore().byId(id);
            if (it == null) {
                p.sendMessage(ChatColor.RED + "Item nicht mehr verfügbar.");
                p.closeInventory();
                return;
            }
            ItemStack give = plugin.shopStore().materialize(it);
            if (give == null) {
                p.sendMessage(ChatColor.RED + "Item-Daten kaputt.");
                return;
            }
            if (countShards(p) < it.priceShards) {
                p.sendMessage(ChatColor.RED + "Du brauchst " + it.priceShards
                    + " Shards (du hast " + countShards(p) + ").");
                return;
            }
            if (p.getInventory().firstEmpty() == -1) {
                p.sendMessage(ChatColor.RED + "Inventar voll.");
                return;
            }
            if (!removeShards(p, it.priceShards)) {
                p.sendMessage(ChatColor.RED + "Bezahlung fehlgeschlagen.");
                return;
            }
            p.getInventory().addItem(give);
            p.sendMessage(ChatColor.GREEN + "✓ " + it.displayName
                + ChatColor.GREEN + " gekauft für " + ChatColor.AQUA + it.priceShards + " Shards");
            // Sidebar refresh (Shard count changed)
            plugin.scoreboard().refresh(p);
            // Re-open mit neuem Stand
            open(plugin, p);
        }
    }
}
