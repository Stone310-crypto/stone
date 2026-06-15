package net.stonechain.mcplugin;

import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.Material;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.inventory.Inventory;
import org.bukkit.inventory.ItemStack;
import org.bukkit.inventory.meta.ItemMeta;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public final class StoneMenu {

    public static final String TITLE = ChatColor.GOLD + "" + ChatColor.BOLD + "Stone-Coins";

    public static final int SLOT_STATS  = 4;
    public static final int SLOT_REDEEM = 11;
    public static final int SLOT_LINK   = 13;
    public static final int SLOT_BOARD  = 15;
    public static final int SLOT_CLAIM  = 20;
    public static final int SLOT_SCROLL = 26;
    public static final int SLOT_VAULT  = 24;
    public static final int SLOT_CLOSE  = 22;

    public static void open(StoneMcPlugin plugin, Player player, PlayerWalletStore wallets) {
        Inventory inv = Bukkit.createInventory(null, 27, TITLE);
        UUID id = player.getUniqueId();

        int shardCount = countShards(player);
        int coinCount  = countOwnedCoins(player);
        long shardsLifetime = wallets.totalShards(id);
        long coinsLifetime  = wallets.totalCoinsCrafted(id);
        double redeemed = wallets.totalRedeemed(id);
        String linked   = wallets.linkedAddress(id);

        inv.setItem(SLOT_STATS, item(Material.EMERALD,
            ChatColor.GOLD + "Deine Stone-Stats",
            ChatColor.AQUA   + "Shards (Inventar): " + ChatColor.WHITE + shardCount + ChatColor.GRAY + "  /  64 = 1 Coin",
            ChatColor.GOLD   + "Coins  (Inventar): " + ChatColor.WHITE + coinCount,
            "",
            ChatColor.GRAY + "Lifetime Shards: " + ChatColor.WHITE + shardsLifetime,
            ChatColor.GRAY + "Lifetime Coins:  " + ChatColor.WHITE + coinsLifetime,
            ChatColor.GREEN + "Eingeloest: "      + ChatColor.WHITE + StoneMcPlugin.fmt(redeemed) + ChatColor.GRAY + " STONE",
            "",
            ChatColor.GRAY + "Wallet: " + (linked == null ? ChatColor.RED + "nicht verknuepft" : ChatColor.WHITE + linked)
        ));

        inv.setItem(SLOT_REDEEM, item(Material.GOLD_INGOT,
            ChatColor.GOLD + "" + ChatColor.BOLD + "Coins einloesen",
            ChatColor.GRAY + "Tauscht " + ChatColor.WHITE + coinCount + ChatColor.GRAY + " Stone Coin(s)",
            ChatColor.GRAY + "in on-chain STONE.",
            "",
            ChatColor.YELLOW + "Klick: alle Coins einloesen",
            (linked == null ? ChatColor.RED + "Erst Wallet verknuepfen!" : "")
        ));

        inv.setItem(SLOT_LINK, item(Material.NAME_TAG,
            ChatColor.AQUA + "" + ChatColor.BOLD + "Wallet verknuepfen",
            ChatColor.GRAY + "Aktuell: " + (linked == null ? ChatColor.RED + "keine" : ChatColor.WHITE + linked),
            "",
            ChatColor.YELLOW + "Klick: Anleitung anzeigen"
        ));

        inv.setItem(SLOT_BOARD, item(Material.ITEM_FRAME,
            ChatColor.LIGHT_PURPLE + "" + ChatColor.BOLD + "Sidebar umschalten",
            ChatColor.GRAY + "Zeigt/versteckt das",
            ChatColor.GRAY + "Stone-Coins-Scoreboard."
        ));

        inv.setItem(SLOT_CLOSE, item(Material.BARRIER,
            ChatColor.RED + "Schliessen"
        ));

        inv.setItem(SLOT_VAULT, item(Material.ENDER_CHEST,
            ChatColor.DARK_AQUA + "" + ChatColor.BOLD + "Personal Vault",
            ChatColor.GRAY + "Nur du kannst diese Vault nutzen.",
            ChatColor.GRAY + "Erlaubt: Stone Shards + deine Stone Coins.",
            "",
            ChatColor.YELLOW + "Klick: Vault öffnen"
        ));

        inv.setItem(SLOT_CLAIM, item(Material.GOLDEN_SHOVEL,
            ChatColor.GREEN + "" + ChatColor.BOLD + "Chunk Claim",
            ChatColor.GRAY + "Claimt dein aktuelles Chunk direkt",
            ChatColor.GRAY + "fuer Spieler ohne Tool-Auswahl.",
            "",
            ChatColor.YELLOW + "Klick: aktuelles Chunk claimen"
        ));

        inv.setItem(SLOT_SCROLL, item(Material.PAPER,
            ChatColor.GOLD + "" + ChatColor.BOLD + "Stone Scroll",
            ChatColor.GRAY + "Soulbound Menue-Item",
            ChatColor.GRAY + "geht beim Tod nicht verloren.",
            "",
            ChatColor.YELLOW + "Klick: Scroll erhalten"
        ));

        ItemStack filler = item(Material.GRAY_STAINED_GLASS_PANE, " ");
        for (int i = 0; i < inv.getSize(); i++) {
            if (inv.getItem(i) == null) inv.setItem(i, filler);
        }

        player.openInventory(inv);
    }

    private static int countShards(Player p) {
        int n = 0;
        for (ItemStack it : p.getInventory().getContents()) {
            if (StoneShard.is(it)) n += it.getAmount();
        }
        return n;
    }

    private static int countOwnedCoins(Player p) {
        int n = 0;
        UUID id = p.getUniqueId();
        for (ItemStack it : p.getInventory().getContents()) {
            if (StoneCoin.is(it) && StoneCoin.ownedBy(it, id)) n += it.getAmount();
        }
        return n;
    }

    private static int removeOwnedCoins(Player p, int want) {
        if (want <= 0) return 0;
        UUID id = p.getUniqueId();
        int removed = 0;
        ItemStack[] contents = p.getInventory().getContents();
        for (int i = 0; i < contents.length && removed < want; i++) {
            ItemStack it = contents[i];
            if (StoneCoin.is(it) && StoneCoin.ownedBy(it, id)) {
                int take = Math.min(it.getAmount(), want - removed);
                int newAmt = it.getAmount() - take;
                if (newAmt <= 0) p.getInventory().setItem(i, null);
                else { it.setAmount(newAmt); p.getInventory().setItem(i, it); }
                removed += take;
            }
        }
        return removed;
    }

    private static ItemStack item(Material mat, String name, String... lore) {
        ItemStack s = new ItemStack(mat);
        ItemMeta m = s.getItemMeta();
        if (m != null) {
            m.setDisplayName(name);
            if (lore.length > 0) {
                List<String> list = new ArrayList<>();
                for (String l : lore) {
                    if (l == null) continue;
                    list.add(l);
                }
                m.setLore(list);
            }
            s.setItemMeta(m);
        }
        return s;
    }

    public static final class ClickListener implements Listener {
        private final StoneMcPlugin plugin;
        public ClickListener(StoneMcPlugin plugin) { this.plugin = plugin; }

        @EventHandler
        public void onClick(InventoryClickEvent ev) {
            if (ev.getView() == null) return;
            String title = ev.getView().getTitle();
            if (!TITLE.equals(title)) return;
            ev.setCancelled(true);
            if (!(ev.getWhoClicked() instanceof Player p)) return;
            int slot = ev.getRawSlot();
            if (slot < 0 || slot >= 27) return;

            PlayerWalletStore wallets = plugin.wallets();
            switch (slot) {
                case SLOT_REDEEM -> {
                    String target = wallets.linkedAddress(p.getUniqueId());
                    if (target == null) {
                        p.sendMessage(ChatColor.RED + "Keine Wallet verknuepft. /stonelink <stone1...>");
                        return;
                    }
                    int have = countOwnedCoins(p);
                    if (have <= 0) {
                        p.sendMessage(ChatColor.YELLOW + "Du hast keine Stone Coins zum Einloesen.");
                        return;
                    }
                    int removed = removeOwnedCoins(p, have);
                    if (removed <= 0) {
                        p.sendMessage(ChatColor.RED + "Konnte keine Coins entfernen.");
                        return;
                    }
                    p.closeInventory();
                    plugin.redeemCoins(p, target, removed, "menu");
                }
                case SLOT_LINK -> {
                    p.closeInventory();
                    p.sendMessage(ChatColor.AQUA + "Wallet verknuepfen:");
                    p.sendMessage(ChatColor.GRAY + "  /stonelink " + ChatColor.WHITE + "<stone1...address>");
                }
                case SLOT_BOARD -> p.performCommand("stoneboard");
                case SLOT_VAULT -> {
                    p.closeInventory();
                    PersonalVault.open(plugin, p);
                }
                case SLOT_CLAIM -> {
                    p.closeInventory();
                    plugin.getServer().getScheduler().runTask(plugin, () -> p.performCommand("stoneclaim gui"));
                }
                case SLOT_SCROLL -> {
                    p.closeInventory();
                    org.bukkit.inventory.ItemStack scroll = StoneMenuScroll.create(p);
                    java.util.Map<Integer, org.bukkit.inventory.ItemStack> overflow = p.getInventory().addItem(scroll);
                    for (org.bukkit.inventory.ItemStack rest : overflow.values()) {
                        p.getWorld().dropItemNaturally(p.getLocation(), rest);
                    }
                    p.sendMessage(ChatColor.GREEN + "Stone Scroll erhalten.");
                }
                case SLOT_CLOSE -> p.closeInventory();
                default -> { /* ignore */ }
            }
        }
    }
}
