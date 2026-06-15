package net.stonechain.mcplugin;

import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.NamespacedKey;
import org.bukkit.entity.HumanEntity;
import org.bukkit.entity.Item;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.entity.EntityPickupItemEvent;
import org.bukkit.event.entity.PlayerDeathEvent;
import org.bukkit.event.inventory.InventoryAction;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.event.inventory.InventoryDragEvent;
import org.bukkit.event.inventory.InventoryMoveItemEvent;
import org.bukkit.event.inventory.InventoryType;
import org.bukkit.event.player.PlayerDropItemEvent;
import org.bukkit.event.player.PlayerRespawnEvent;
import org.bukkit.inventory.Inventory;
import org.bukkit.inventory.ItemStack;
import org.bukkit.inventory.PlayerInventory;
import org.bukkit.inventory.ShapedRecipe;
import org.bukkit.inventory.RecipeChoice;
import org.bukkit.event.inventory.PrepareItemCraftEvent;
import org.bukkit.event.inventory.CraftItemEvent;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Schützt Stone Coins (Soulbound) und registriert das Crafting-Rezept
 * 64 Shards (4×16 in 2x2 Grid) → 1 Stone Coin.
 */
public final class SoulboundCoinHandler implements Listener {

    private final StoneMcPlugin plugin;
    private final NamespacedKey recipeKey;
    private final Map<UUID, List<ItemStack>> deathRestore = new HashMap<>();

    public SoulboundCoinHandler(StoneMcPlugin plugin) {
        this.plugin = plugin;
        this.recipeKey = new NamespacedKey(plugin, "shard_to_coin");
    }

    public void registerRecipe() {
        // Output ist ein "Template"-Coin ohne Owner; Owner wird beim CraftItemEvent gesetzt.
        ItemStack template = new ItemStack(StoneCoin.MATERIAL, 1);
        ShapedRecipe r = new ShapedRecipe(recipeKey, template);
        r.shape("AB", "CD");
        // MaterialChoice — Validierung (Tag, Amount, Nonce) erfolgt in onPrepare/onCraft.
        RecipeChoice choice = new RecipeChoice.MaterialChoice(StoneShard.MATERIAL);
        r.setIngredient('A', choice);
        r.setIngredient('B', choice);
        r.setIngredient('C', choice);
        r.setIngredient('D', choice);
        Bukkit.removeRecipe(recipeKey);
        Bukkit.addRecipe(r);
    }

    public void unregisterRecipe() {
        Bukkit.removeRecipe(recipeKey);
    }

    // ---- Recipe matcher: alle 4 Slots müssen exakt 16 Shards sein ----
    @EventHandler
    public void onPrepare(PrepareItemCraftEvent ev) {
        if (ev.getRecipe() == null) return;
        org.bukkit.inventory.Recipe rec = ev.getRecipe();
        if (!(rec instanceof ShapedRecipe sr)) return;
        if (!recipeKey.equals(sr.getKey())) return;

        ItemStack[] m = ev.getInventory().getMatrix();
        // Akzeptiere die 4 Ecken des 2x2 (oder 3x3 mit nur 4 Shards in Quadrat).
        int shardSlots = 0;
        int total = 0;
        for (ItemStack it : m) {
            if (it == null || it.getType().isAir()) continue;
            if (!StoneShard.is(it)) {
                ev.getInventory().setResult(null);
                return;
            }
            if (it.getAmount() != 16) {
                ev.getInventory().setResult(null);
                return;
            }
            shardSlots++;
            total += it.getAmount();
        }
        if (shardSlots != 4 || total != 64) {
            ev.getInventory().setResult(null);
        }
    }

    @EventHandler
    public void onCraft(CraftItemEvent ev) {
        if (ev.getRecipe() == null) return;
        if (!(ev.getRecipe() instanceof ShapedRecipe sr)) return;
        if (!recipeKey.equals(sr.getKey())) return;
        if (!(ev.getWhoClicked() instanceof Player p)) return;

        // Creative-Mode Spieler dürfen NIE Stone Coins craften (Anti-Dupe).
        if (p.getGameMode() == org.bukkit.GameMode.CREATIVE) {
            ev.setCancelled(true);
            p.sendMessage(ChatColor.RED + "Stone Coins koennen nicht im Creative-Mode gecraftet werden.");
            return;
        }

        // Verhindere Shift-Click Massen-Craft (Stack-Math wird unzuverlässig mit owner-binding).
        if (ev.isShiftClick()) {
            ev.setCancelled(true);
            p.sendMessage(ChatColor.YELLOW + "Stone Coins muessen einzeln gecraftet werden.");
            return;
        }
        // Cursor muss leer sein oder Coin sein
        ItemStack cursor = ev.getCursor();
        if (cursor != null && !cursor.getType().isAir() && !StoneCoin.is(cursor)) {
            ev.setCancelled(true);
            return;
        }

        // Anti-Dupe: jede der 4 Slot-Nonces im Ledger mit -16 buchen.
        // Schlägt eine Buchung fehl (Nonce unbekannt oder remaining<16) → Craft abbrechen.
        ItemStack[] matrix = ev.getInventory().getMatrix();
        java.util.List<UUID> consumed = new java.util.ArrayList<>(4);
        ShardLedger ledger = plugin.shardLedger();
        for (ItemStack it : matrix) {
            if (it == null || it.getType().isAir()) continue;
            if (!StoneShard.is(it) || it.getAmount() < 16) {
                ev.setCancelled(true);
                return;
            }
            UUID nonce = StoneShard.nonce(it);
            if (nonce == null || !ledger.consume(nonce, 16)) {
                ev.setCancelled(true);
                p.sendMessage(ChatColor.RED + "⚠ Diese Shards konnten nicht verifiziert werden (moegliche Duplikate).");
                plugin.getLogger().warning("[anti-dupe] craft rejected for " + p.getName()
                    + " — nonce=" + nonce + " not consumable");
                return;
            }
            consumed.add(nonce);
        }
        if (consumed.size() != 4) {
            ev.setCancelled(true);
            return;
        }
        ledger.save();

        ev.setCancelled(true);
        // Manuell: 16 aus jedem der 4 Matrix-Slots abziehen
        for (int i = 0; i < matrix.length; i++) {
            ItemStack it = matrix[i];
            if (it != null && !it.getType().isAir() && StoneShard.is(it) && it.getAmount() >= 16) {
                int newAmt = it.getAmount() - 16;
                if (newAmt <= 0) matrix[i] = null;
                else { it.setAmount(newAmt); matrix[i] = it; }
            }
        }
        ev.getInventory().setMatrix(matrix);

        ItemStack coin = StoneCoin.create(p, 1);
        // Coin in Cursor setzen (wie normaler Craft-Output)
        if (cursor == null || cursor.getType().isAir()) {
            ev.setCursor(coin);
        } else if (StoneCoin.is(cursor) && StoneCoin.ownedBy(cursor, p.getUniqueId())) {
            cursor.setAmount(Math.min(64, cursor.getAmount() + 1));
            ev.setCursor(cursor);
        } else {
            // gib direkt ins Inventar
            Map<Integer, ItemStack> overflow = p.getInventory().addItem(coin);
            if (!overflow.isEmpty()) {
                p.getWorld().dropItemNaturally(p.getLocation(), coin);
            }
        }
        p.sendMessage(ChatColor.GOLD + "+1 Stone Coin " + ChatColor.GRAY + "(soulbound)");
        plugin.wallets().addCoinsCrafted(p.getUniqueId(), 1);
        plugin.wallets().save();
        plugin.scoreboard().refresh(p);
    }

    // ---- Soulbound protections ----

    @EventHandler(priority = EventPriority.HIGH, ignoreCancelled = true)
    public void onDrop(PlayerDropItemEvent ev) {
        ItemStack it = ev.getItemDrop().getItemStack();
        if (!StoneCoin.is(it)) return;
        if (!StoneCoin.ownedBy(it, ev.getPlayer().getUniqueId())) {
            ev.setCancelled(true);
            return;
        }
        // Eigener Spieler darf nicht droppen (sonst kann jemand anders es aufheben? wir blocken Pickup eh,
        // aber zur Sicherheit komplett unterbinden):
        ev.setCancelled(true);
        ev.getPlayer().sendMessage(ChatColor.RED + "Stone Coins koennen nicht weggeworfen werden.");
    }

    @EventHandler(priority = EventPriority.HIGH, ignoreCancelled = true)
    public void onPickup(EntityPickupItemEvent ev) {
        ItemStack it = ev.getItem().getItemStack();
        if (!StoneCoin.is(it)) return;
        if (!(ev.getEntity() instanceof Player p)) {
            ev.setCancelled(true);
            return;
        }
        if (!StoneCoin.ownedBy(it, p.getUniqueId())) {
            ev.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.HIGH, ignoreCancelled = true)
    public void onClick(InventoryClickEvent ev) {
        ItemStack current = ev.getCurrentItem();
        ItemStack cursor  = ev.getCursor();
        UUID who = ev.getWhoClicked().getUniqueId();

        if (current != null && StoneCoin.is(current) && !StoneCoin.ownedBy(current, who)) {
            ev.setCancelled(true);
            return;
        }
        if (cursor != null && StoneCoin.is(cursor) && !StoneCoin.ownedBy(cursor, who)) {
            ev.setCancelled(true);
            return;
        }

        Inventory top = ev.getView().getTopInventory();
        if (top == null) return;
        InventoryType tt = top.getType();

        // Block Coins from leaving the player inventory into external containers.
        boolean movingCoinIntoTop =
            (current != null && StoneCoin.is(current) && ev.isShiftClick() && ev.getClickedInventory() != top)
            || (cursor != null && StoneCoin.is(cursor) && ev.getClickedInventory() == top);
        if (movingCoinIntoTop) {
            switch (tt) {
                case CRAFTING:
                case WORKBENCH:
                case PLAYER:
                case ENDER_CHEST:
                    break; // ok
                default:
                    ev.setCancelled(true);
                    if (ev.getWhoClicked() instanceof Player p) {
                        p.sendMessage(ChatColor.RED + "Stone Coins koennen nicht abgelegt werden.");
                    }
                    return;
            }
        }

        // Block Shards AND Scroll from entering Shulker Boxes (dupe exploit vector).
        boolean movingShardOrScrollIntoShulker =
            isShulkerBox(tt)
            && ((current != null && (StoneShard.is(current) || StoneMenuScroll.is(current)) && ev.isShiftClick() && ev.getClickedInventory() != top)
             || (cursor != null && (StoneShard.is(cursor) || StoneMenuScroll.is(cursor)) && ev.getClickedInventory() == top));
        if (movingShardOrScrollIntoShulker) {
            ev.setCancelled(true);
            if (ev.getWhoClicked() instanceof Player p) {
                p.sendMessage(ChatColor.RED + "Stone Items koennen nicht in Shulker Boxes gelegt werden.");
            }
        }
    }

    private static boolean isShulkerBox(InventoryType t) {
        return t == InventoryType.SHULKER_BOX;
    }

    @EventHandler(priority = EventPriority.HIGH, ignoreCancelled = true)
    public void onDrag(InventoryDragEvent ev) {
        ItemStack it = ev.getOldCursor();
        if (it == null || !StoneCoin.is(it)) return;
        UUID who = ev.getWhoClicked().getUniqueId();
        if (!StoneCoin.ownedBy(it, who)) {
            ev.setCancelled(true);
            return;
        }
        Inventory top = ev.getView().getTopInventory();
        if (top == null) return;
        InventoryType tt = top.getType();
        // Drag in fremdes Top-Inventar verhindern:
        switch (tt) {
            case CRAFTING:
            case WORKBENCH:
            case PLAYER:
            case ENDER_CHEST:
                return;
            default:
                // Drag betrifft mehrere Slots, blockiere wenn Top involviert ist.
                for (int slot : ev.getRawSlots()) {
                    if (slot < top.getSize()) {
                        ev.setCancelled(true);
                        return;
                    }
                }
        }
    }

    @EventHandler(priority = EventPriority.HIGH, ignoreCancelled = true)
    public void onHopper(InventoryMoveItemEvent ev) {
        ItemStack it = ev.getItem();
        if (isStoneItem(it)) ev.setCancelled(true);
    }

    /** Anti-Dupe: Stone items duerfen nie im Creative-Modus dupliziert werden. */
    @EventHandler(priority = EventPriority.HIGH, ignoreCancelled = true)
    public void onCreative(org.bukkit.event.inventory.InventoryCreativeEvent ev) {
        ItemStack cur = ev.getCursor();
        ItemStack cli = ev.getCurrentItem();
        boolean stoneItem =
            (cur != null && isStoneItem(cur)) || (cli != null && isStoneItem(cli));
        if (!stoneItem) return;

        ev.setCancelled(true);
        ev.setCursor(null);
        // Extra: wenn das Slot-Item ein Stone-Item ist, nicht ersetzen lassen.
        if (ev.getWhoClicked() instanceof Player p) {
            p.sendMessage(ChatColor.RED + "Stone Items koennen nicht im Creative-Modus dupliziert werden.");
            // Kick any stone item out of the Shulker Box if player has one open.
            Inventory top = ev.getView().getTopInventory();
            if (top != null && isShulkerBox(top.getType())) {
                for (int i = 0; i < top.getSize(); i++) {
                    ItemStack s = top.getItem(i);
                    if (s != null && isStoneItem(s)) {
                        top.setItem(i, null);
                        plugin.getLogger().warning("[anti-dupe] removed " + s.getType().name() + " x" + s.getAmount()
                            + " from shulker for " + p.getName());
                    }
                }
            }
        }
    }

    private static boolean isStoneItem(ItemStack s) {
        return StoneCoin.is(s) || StoneShard.is(s) || StoneMenuScroll.is(s);
    }

    @EventHandler
    public void onDeath(PlayerDeathEvent ev) {
        boolean protectCoins = plugin.getConfig().getBoolean("death_protect.coins", true);
        boolean protectShards = plugin.getConfig().getBoolean("death_protect.shards", true);

        if (!protectCoins && !protectShards) return;

        List<ItemStack> kept = new ArrayList<>();
        ev.getDrops().removeIf(it -> {
            boolean keepCoin = protectCoins && StoneCoin.is(it);
            boolean keepShard = protectShards && StoneShard.is(it);
            boolean keepScroll = StoneMenuScroll.is(it);
            if (keepCoin || keepShard || keepScroll) {
                kept.add(it.clone());
                return true;
            }
            return false;
        });
        if (!kept.isEmpty()) {
            deathRestore.put(ev.getEntity().getUniqueId(), kept);
        }
    }

    @EventHandler
    public void onRespawn(PlayerRespawnEvent ev) {
        List<ItemStack> kept = deathRestore.remove(ev.getPlayer().getUniqueId());
        if (kept == null || kept.isEmpty()) return;
        PlayerInventory inv = ev.getPlayer().getInventory();
        for (ItemStack it : kept) {
            Map<Integer, ItemStack> overflow = inv.addItem(it);
            for (ItemStack o : overflow.values()) {
                ev.getPlayer().getWorld().dropItemNaturally(ev.getPlayer().getLocation(), o);
            }
        }
        ev.getPlayer().sendMessage(ChatColor.GREEN + "Deine geschützten Stone-Items wurden wiederhergestellt.");
    }
}
