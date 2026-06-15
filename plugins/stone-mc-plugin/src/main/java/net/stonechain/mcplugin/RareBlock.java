package net.stonechain.mcplugin;

import org.bukkit.ChatColor;
import org.bukkit.Material;
import org.bukkit.NamespacedKey;
import org.bukkit.inventory.ItemStack;
import org.bukkit.inventory.meta.ItemMeta;
import org.bukkit.persistence.PersistentDataContainer;
import org.bukkit.persistence.PersistentDataType;
import org.bukkit.plugin.Plugin;

import java.util.List;

/**
 * Placeable rare block that can be mined for shard rewards.
 */
public final class RareBlock {

    private static NamespacedKey TAG_KEY;
    private static Material MATERIAL = Material.CRYING_OBSIDIAN;

    private RareBlock() { }

    public static void init(Plugin plugin, String configuredMaterial) {
        TAG_KEY = new NamespacedKey(plugin, "stone_rare_block");
        Material m = configuredMaterial == null ? null : Material.matchMaterial(configuredMaterial);
        if (m != null && m.isBlock()) MATERIAL = m;
    }

    public static ItemStack create(int amount) {
        ItemStack out = new ItemStack(MATERIAL, Math.max(1, Math.min(64, amount)));
        ItemMeta meta = out.getItemMeta();
        if (meta != null) {
            meta.setDisplayName(ChatColor.LIGHT_PURPLE + "" + ChatColor.BOLD + "Stone Core");
            meta.setLore(List.of(
                ChatColor.GRAY + "Sehr seltenes Stone-Objekt.",
                ChatColor.GRAY + "Abbauen: " + ChatColor.AQUA + "32 Shards",
                ChatColor.GRAY + "Mit " + ChatColor.WHITE + "Silk Touch" + ChatColor.GRAY + " wieder aufhebbar."
            ));
            PersistentDataContainer pdc = meta.getPersistentDataContainer();
            pdc.set(TAG_KEY, PersistentDataType.BYTE, (byte) 1);
            out.setItemMeta(meta);
        }
        return out;
    }

    public static boolean is(ItemStack stack) {
        if (stack == null || stack.getType() != MATERIAL) return false;
        ItemMeta meta = stack.getItemMeta();
        if (meta == null) return false;
        Byte v = meta.getPersistentDataContainer().get(TAG_KEY, PersistentDataType.BYTE);
        return v != null && v == (byte) 1;
    }

    public static Material material() {
        return MATERIAL;
    }
}
