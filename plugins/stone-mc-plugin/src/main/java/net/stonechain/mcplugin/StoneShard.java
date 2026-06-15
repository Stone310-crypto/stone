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
 * Stone Shard — handelbares In-Game Item.
 * 64 Shards craften zu 1 StoneCoin (siehe StoneCoin / CraftingHandler).
 */
public final class StoneShard {

    private static NamespacedKey TAG_KEY;
    private static NamespacedKey NONCE_KEY;
    private static NamespacedKey OWNER_KEY;
    public static final Material MATERIAL = Material.PRISMARINE_SHARD;
    public static final String DISPLAY_NAME = ChatColor.AQUA + "" + ChatColor.BOLD + "Stone Shard";

    public static void init(Plugin plugin) {
        TAG_KEY = new NamespacedKey(plugin, "stone_shard");
        NONCE_KEY = new NamespacedKey(plugin, "stone_shard_nonce");
        OWNER_KEY = new NamespacedKey(plugin, "stone_shard_owner");
    }

    /** Recipe-Template only — keine Nonce, niemals an Spieler ausgeben. */
    public static ItemStack create(int amount) {
        return build(amount, null, null);
    }

    /**
     * Erzeugt einen erspielten Shard-Stack. Registriert eine frische Nonce im
     * Ledger und stempelt sie in den NBT (Anti-Dupe).
     */
    public static ItemStack create(ShardLedger ledger, java.util.UUID owner, int amount) {
        int amt = Math.max(1, Math.min(64, amount));
        java.util.UUID nonce = ledger.issue(owner, amt);
        return build(amt, nonce, owner);
    }

    private static ItemStack build(int amount, java.util.UUID nonce, java.util.UUID owner) {
        ItemStack s = new ItemStack(MATERIAL, Math.max(1, Math.min(64, amount)));
        ItemMeta m = s.getItemMeta();
        if (m != null) {
            m.setDisplayName(DISPLAY_NAME);
            m.setLore(List.of(
                ChatColor.GRAY + "Sammle " + ChatColor.WHITE + "64" + ChatColor.GRAY + " um einen",
                ChatColor.GRAY + "Stone Coin zu craften.",
                "",
                ChatColor.DARK_GRAY + "Stonechain"
            ));
            PersistentDataContainer pdc = m.getPersistentDataContainer();
            pdc.set(TAG_KEY, PersistentDataType.BYTE, (byte) 1);
            if (nonce != null) pdc.set(NONCE_KEY, PersistentDataType.STRING, nonce.toString());
            if (owner != null) pdc.set(OWNER_KEY, PersistentDataType.STRING, owner.toString());
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

    /** Nonce des Shards (oder null, falls nicht registriert / Template / forged). */
    public static java.util.UUID nonce(ItemStack item) {
        if (item == null) return null;
        ItemMeta m = item.getItemMeta();
        if (m == null) return null;
        String s = m.getPersistentDataContainer().get(NONCE_KEY, PersistentDataType.STRING);
        if (s == null) return null;
        try { return java.util.UUID.fromString(s); } catch (IllegalArgumentException ex) { return null; }
    }
}
