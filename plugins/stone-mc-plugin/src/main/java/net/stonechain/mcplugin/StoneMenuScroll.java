package net.stonechain.mcplugin;

import org.bukkit.ChatColor;
import org.bukkit.Material;
import org.bukkit.NamespacedKey;
import org.bukkit.entity.Player;
import org.bukkit.inventory.ItemStack;
import org.bukkit.inventory.meta.ItemMeta;
import org.bukkit.persistence.PersistentDataContainer;
import org.bukkit.persistence.PersistentDataType;
import org.bukkit.plugin.Plugin;

import java.util.List;
import java.util.UUID;

/**
 * Soulbound menu opener item (scroll/book style).
 */
public final class StoneMenuScroll {

    private static NamespacedKey TAG_KEY;
    private static NamespacedKey OWNER_KEY;
    public static final Material MATERIAL = Material.PAPER;

    private StoneMenuScroll() { }

    public static void init(Plugin plugin) {
        TAG_KEY = new NamespacedKey(plugin, "stone_menu_scroll");
        OWNER_KEY = new NamespacedKey(plugin, "stone_menu_scroll_owner");
    }

    public static ItemStack create(Player owner) {
        ItemStack out = new ItemStack(MATERIAL, 1);
        ItemMeta meta = out.getItemMeta();
        if (meta != null) {
            meta.setDisplayName(ChatColor.GOLD + "" + ChatColor.BOLD + "Stone Scroll");
            meta.setLore(List.of(
                ChatColor.GRAY + "Rechtsklick: Stone-Menue oeffnen",
                ChatColor.GRAY + "Soulbound und todsicher"
            ));
            PersistentDataContainer pdc = meta.getPersistentDataContainer();
            pdc.set(TAG_KEY, PersistentDataType.BYTE, (byte) 1);
            pdc.set(OWNER_KEY, PersistentDataType.STRING, owner.getUniqueId().toString());
            out.setItemMeta(meta);
        }
        return out;
    }

    public static boolean is(ItemStack stack) {
        if (stack == null || stack.getType().isAir()) return false;
        ItemMeta meta = stack.getItemMeta();
        if (meta == null) return false;
        Byte tag = meta.getPersistentDataContainer().get(TAG_KEY, PersistentDataType.BYTE);
        return tag != null && tag == (byte) 1;
    }

    public static boolean isLegacyWrittenBook(ItemStack stack) {
        return is(stack) && (stack.getType() == Material.WRITTEN_BOOK || stack.getType() == Material.WRITABLE_BOOK);
    }

    public static boolean ownedBy(ItemStack stack, UUID playerId) {
        if (!is(stack) || playerId == null) return false;
        ItemMeta meta = stack.getItemMeta();
        if (meta == null) return false;
        String owner = meta.getPersistentDataContainer().get(OWNER_KEY, PersistentDataType.STRING);
        return playerId.toString().equals(owner);
    }
}
