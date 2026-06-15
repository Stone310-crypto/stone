package net.stonechain.mcplugin;

import org.bukkit.ChatColor;
import org.bukkit.Material;
import org.bukkit.NamespacedKey;
import org.bukkit.OfflinePlayer;
import org.bukkit.entity.Player;
import org.bukkit.inventory.ItemStack;
import org.bukkit.inventory.meta.ItemMeta;
import org.bukkit.persistence.PersistentDataContainer;
import org.bukkit.persistence.PersistentDataType;
import org.bukkit.plugin.Plugin;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Stone Coin — soulbound In-Game Item, account-bound an Owner-UUID.
 * 1 Coin = 1.0 STONE on-chain (über /smenu einlösbar).
 */
public final class StoneCoin {

    private static NamespacedKey TAG_KEY;
    private static NamespacedKey OWNER_KEY;
    public static final Material MATERIAL = Material.NETHER_STAR;
    public static final String DISPLAY_NAME = ChatColor.GOLD + "" + ChatColor.BOLD + "Stone Coin";

    public static void init(Plugin plugin) {
        TAG_KEY   = new NamespacedKey(plugin, "stone_coin");
        OWNER_KEY = new NamespacedKey(plugin, "stone_coin_owner");
    }

    public static ItemStack create(Player owner, int amount) {
        ItemStack s = new ItemStack(MATERIAL, Math.max(1, Math.min(64, amount)));
        ItemMeta m = s.getItemMeta();
        if (m != null) {
            m.setDisplayName(DISPLAY_NAME);
            List<String> lore = new ArrayList<>();
            lore.add(ChatColor.GRAY + "Wert: " + ChatColor.WHITE + "1.00" + ChatColor.GRAY + " STONE pro Coin");
            lore.add("");
            lore.add(ChatColor.GRAY + "" + ChatColor.ITALIC + "Soulbound an: " + ChatColor.WHITE + owner.getName());
            lore.add(ChatColor.GRAY + "" + ChatColor.ITALIC + "Einloesen mit /smenu");
            lore.add("");
            lore.add(ChatColor.DARK_GRAY + "Stonechain");
            m.setLore(lore);
            PersistentDataContainer pdc = m.getPersistentDataContainer();
            pdc.set(TAG_KEY, PersistentDataType.BYTE, (byte) 1);
            pdc.set(OWNER_KEY, PersistentDataType.STRING, owner.getUniqueId().toString());
            s.setItemMeta(m);
        }
        return s;
    }

    public static boolean is(ItemStack item) {
        if (item == null || item.getType() != MATERIAL) return false;
        ItemMeta m = item.getItemMeta();
        if (m == null) return false;
        Byte v = m.getPersistentDataContainer().get(TAG_KEY, PersistentDataType.BYTE);
        return v != null && v == (byte) 1;
    }

    public static UUID owner(ItemStack item) {
        if (!is(item)) return null;
        ItemMeta m = item.getItemMeta();
        if (m == null) return null;
        String s = m.getPersistentDataContainer().get(OWNER_KEY, PersistentDataType.STRING);
        if (s == null) return null;
        try { return UUID.fromString(s); } catch (IllegalArgumentException e) { return null; }
    }

    public static boolean ownedBy(ItemStack item, UUID uuid) {
        UUID o = owner(item);
        return o != null && o.equals(uuid);
    }
}
