package net.stonechain.mcplugin;

import org.bukkit.ChatColor;
import org.bukkit.Location;
import org.bukkit.Material;
import org.bukkit.NamespacedKey;
import org.bukkit.Bukkit;
import org.bukkit.block.data.BlockData;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.block.BlockBreakEvent;
import org.bukkit.event.block.BlockPlaceEvent;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.event.player.AsyncPlayerChatEvent;
import org.bukkit.event.player.PlayerMoveEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.inventory.Inventory;
import org.bukkit.inventory.ItemStack;
import org.bukkit.inventory.meta.ItemMeta;
import org.bukkit.persistence.PersistentDataType;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.event.ClickEvent;
import net.kyori.adventure.text.format.NamedTextColor;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * GUI-based chunk claims with build protection/trust.
 */
public final class ClaimManager implements Listener {

    private static final String CHUNK_GUI_TITLE = ChatColor.DARK_GREEN + "Chunk Claim Map";

    private final StoneMcPlugin plugin;
    private final ClaimStore store;
    private final NamespacedKey keyGuiGroup;
    private final Map<UUID, Long> notifyCooldown = new ConcurrentHashMap<>();
    private final Map<UUID, TrustInvite> pendingTrustInvites = new ConcurrentHashMap<>();
    private final Map<UUID, String> lastChunkClaim = new ConcurrentHashMap<>();
    private final Map<UUID, List<Location>> boundaryOverlays = new ConcurrentHashMap<>();
    private final Map<UUID, String> selectedGroup = new ConcurrentHashMap<>();
    private final Map<UUID, String> pendingGroupRename = new ConcurrentHashMap<>();
    private final Map<UUID, int[]> mapCenter = new ConcurrentHashMap<>();

    private static final class TrustInvite {
        final String claimId;
        final UUID owner;
        final long createdAt;

        TrustInvite(String claimId, UUID owner) {
            this.claimId = claimId;
            this.owner = owner;
            this.createdAt = System.currentTimeMillis();
        }
    }

    public ClaimManager(StoneMcPlugin plugin, ClaimStore store) {
        this.plugin = plugin;
        this.store = store;
        this.keyGuiGroup = new NamespacedKey(plugin, "claim_gui_group");
    }

    public ClaimStore store() {
        return store;
    }

    // 54-slot map: left control column (slots 0/9/18/27/36), map columns 1..8 over rows 0..4.
    private static final int MAP_COLS  = 8;
    private static final int MAP_ROWS  = 5;
    private static final int CLOSE_SLOT = 49; // center of control row
    // Cardinal points on the map itself (N top, S bottom, W left, E right)
    private static final int NAV_NORTH_SLOT = 4;
    private static final int NAV_SOUTH_SLOT = 40;
    private static final int NAV_WEST_SLOT = 19;
    private static final int NAV_EAST_SLOT = 26;

    public void openChunkMapGui(Player p) {
        openChunkMapGui(p, true);
    }

    private void openChunkMapGui(Player p, boolean resetCenterToPlayer) {
        ensureDefaultGroups(p.getUniqueId());
        Inventory inv = Bukkit.createInventory(null, 54, CHUNK_GUI_TITLE);
        ItemStack filler = named(Material.BLACK_STAINED_GLASS_PANE, " ");
        for (int i = 45; i < 54; i++) inv.setItem(i, filler);

        List<ClaimStore.ClaimGroup> groups = store.groupsByOwner(p.getUniqueId());
        String activeGroup = selectedGroup.get(p.getUniqueId());
        if (activeGroup == null && !groups.isEmpty()) {
            activeGroup = groups.get(0).name;
            selectedGroup.put(p.getUniqueId(), activeGroup);
        }

        int[] groupSlots = {0, 9, 18, 27};
        for (int i = 0; i < groupSlots.length; i++) {
            if (i >= groups.size()) {
                inv.setItem(groupSlots[i], named(Material.GRAY_STAINED_GLASS_PANE, ChatColor.DARK_GRAY + "Leer"));
                continue;
            }
            ClaimStore.ClaimGroup g = groups.get(i);
            boolean selected = g.name.equalsIgnoreCase(activeGroup);
            Material mat = groupMaterial(g.color, true);
            String title = (selected ? ChatColor.GOLD + "* " : ChatColor.YELLOW + "") + g.name;
            ItemStack groupItem = namedWithLore(mat, title, List.of(
                ChatColor.GRAY + "Klick: als aktiv setzen",
                ChatColor.GRAY + "Rechtsklick: Namen aendern"
            ));
            ItemMeta im = groupItem.getItemMeta();
            if (im != null) {
                im.getPersistentDataContainer().set(keyGuiGroup, PersistentDataType.STRING, g.name);
                groupItem.setItemMeta(im);
            }
            inv.setItem(groupSlots[i], groupItem);
        }
        inv.setItem(36, namedWithLore(Material.ANVIL, ChatColor.AQUA + "Gruppe erstellen", List.of(
            ChatColor.GRAY + "Klick: erstellt naechste Farbe",
            ChatColor.DARK_GRAY + "Action: create_group"
        )));

        int playerCx = p.getLocation().getChunk().getX();
        int playerCz = p.getLocation().getChunk().getZ();
        int[] center = mapCenter.get(p.getUniqueId());
        if (resetCenterToPlayer || center == null || center.length < 2) {
            center = new int[]{playerCx, playerCz};
            mapCenter.put(p.getUniqueId(), center);
        }
        int centerCx = center[0];
        int centerCz = center[1];

        for (int row = 0; row < MAP_ROWS; row++) {
            int dz = row - 2;                 // dz: -2,-1,0,+1,+2
            for (int col = 0; col < MAP_COLS; col++) {
                int dx = col - 3;             // dx: -3..+4
                int cx = centerCx + dx;
                int cz = centerCz + dz;
                int slot = row * 9 + (col + 1);
                if (slot == NAV_NORTH_SLOT || slot == NAV_SOUTH_SLOT || slot == NAV_WEST_SLOT || slot == NAV_EAST_SLOT) {
                    continue;
                }
                inv.setItem(slot, chunkButton(p, cx, cz, dx == 0 && dz == 0));
            }
        }

        inv.setItem(NAV_WEST_SLOT, namedWithLore(Material.ARROW, ChatColor.YELLOW + "Westen", List.of(ChatColor.GRAY + "Klick: 1 Feld nach Westen")));
        inv.setItem(NAV_NORTH_SLOT, namedWithLore(Material.ARROW, ChatColor.YELLOW + "Norden", List.of(ChatColor.GRAY + "Klick: 1 Feld nach Norden")));
        inv.setItem(NAV_SOUTH_SLOT, namedWithLore(Material.ARROW, ChatColor.YELLOW + "Sueden", List.of(ChatColor.GRAY + "Klick: 1 Feld nach Sueden")));
        inv.setItem(NAV_EAST_SLOT, namedWithLore(Material.ARROW, ChatColor.YELLOW + "Osten", List.of(ChatColor.GRAY + "Klick: 1 Feld nach Osten")));

        inv.setItem(CLOSE_SLOT, named(Material.BARRIER, ChatColor.RED + "Schliessen"));
        // legend + status row
        inv.setItem(47, namedWithLore(Material.LIME_STAINED_GLASS_PANE,  ChatColor.GREEN + "Frei",  List.of(ChatColor.GRAY + "Klick: Chunk claimen")));
        inv.setItem(48, namedWithLore(Material.YELLOW_STAINED_GLASS_PANE, ChatColor.GOLD  + "Dein Claim", List.of(ChatColor.GRAY + "Mit aktiver Gruppe: zuweisen")));
        inv.setItem(50, namedWithLore(Material.RED_STAINED_GLASS_PANE,   ChatColor.RED   + "Fremd",  List.of(ChatColor.GRAY + "Nicht claimbar")));
        inv.setItem(51, namedWithLore(Material.COMPASS,
            ChatColor.GOLD + "Kartenzentrum: " + centerCx + "," + centerCz,
            List.of(
                ChatColor.GRAY + "Spieler: " + playerCx + "," + playerCz,
                ChatColor.GRAY + "Aktiv: " + (activeGroup == null ? "-" : activeGroup)
            )));
        inv.setItem(52, namedWithLore(Material.PAPER, ChatColor.GRAY + "Navigation", List.of(ChatColor.GRAY + "Pfeile liegen auf N/S/W/O")));
        p.openInventory(inv);
    }

    private ItemStack chunkButton(Player viewer, int cx, int cz, boolean center) {
        // probe the center block of this chunk at player Y
        int worldX = (cx << 4) + 8;
        int worldZ = (cz << 4) + 8;
        Location probe = new Location(viewer.getWorld(), worldX, viewer.getLocation().getY(), worldZ);
        ClaimStore.Claim claim = store.byLocation(probe);
        boolean own  = claim != null && claim.ownedBy(viewer.getUniqueId());
        boolean free = claim == null;

        Material mat;
        String title;
        List<String> lore = new ArrayList<>();

        if (free) {
            mat = center ? Material.LIME_STAINED_GLASS : Material.LIME_STAINED_GLASS_PANE;
            title = ChatColor.GREEN + "Chunk " + cx + "," + cz;
            lore.add(ChatColor.YELLOW + "Klick: Chunk claimen");
        } else if (own) {
            String colorName = own && claim.group != null ? colorForOwnGroup(viewer.getUniqueId(), claim.group) : "YELLOW";
            mat = groupMaterial(colorName, center);
            title = ChatColor.GOLD + "Chunk " + cx + "," + cz;
            lore.add(ChatColor.YELLOW + "Klick: Gruppe zuweisen (wenn aktiv)");
            lore.add(ChatColor.YELLOW + "Ohne aktive Gruppe: Claim entfernen");
            if (claim.group != null) lore.add(ChatColor.GRAY + "Gruppe: " + claim.group);
        } else {
            mat = center ? Material.RED_STAINED_GLASS : Material.RED_STAINED_GLASS_PANE;
            title = ChatColor.RED + "Chunk " + cx + "," + cz;
            lore.add(ChatColor.DARK_GRAY + "Nicht claimbar");
        }

        if (center) title += ChatColor.WHITE + " ◄ Du";
        lore.add(ChatColor.DARK_GRAY + "Chunk: " + cx + "," + cz);
        return namedWithLore(mat, title, lore);
    }

    private static ItemStack named(Material mat, String name) {
        ItemStack s = new ItemStack(mat);
        ItemMeta m = s.getItemMeta();
        if (m != null) {
            m.setDisplayName(name);
            s.setItemMeta(m);
        }
        return s;
    }

    private static ItemStack namedWithLore(Material mat, String name, List<String> lore) {
        ItemStack s = new ItemStack(mat);
        ItemMeta m = s.getItemMeta();
        if (m != null) {
            m.setDisplayName(name);
            m.setLore(lore);
            s.setItemMeta(m);
        }
        return s;
    }

    @EventHandler(priority = EventPriority.HIGH, ignoreCancelled = true)
    public void onChunkGuiClick(InventoryClickEvent e) {
        if (e.getView() == null || !CHUNK_GUI_TITLE.equals(e.getView().getTitle())) return;
        e.setCancelled(true);
        if (!(e.getWhoClicked() instanceof Player p)) return;
        int slot = e.getRawSlot();
        if (slot < 0 || slot >= 54) return;
        if (slot == CLOSE_SLOT) {
            p.closeInventory();
            return;
        }
        if (slot == NAV_WEST_SLOT || slot == NAV_NORTH_SLOT || slot == NAV_SOUTH_SLOT || slot == NAV_EAST_SLOT) {
            int[] center = mapCenter.getOrDefault(p.getUniqueId(), new int[]{p.getLocation().getChunk().getX(), p.getLocation().getChunk().getZ()});
            int cx = center[0];
            int cz = center[1];
            if (slot == NAV_WEST_SLOT) cx -= 1;
            if (slot == NAV_EAST_SLOT) cx += 1;
            if (slot == NAV_NORTH_SLOT) cz -= 1;
            if (slot == NAV_SOUTH_SLOT) cz += 1;
            mapCenter.put(p.getUniqueId(), new int[]{cx, cz});
            plugin.getServer().getScheduler().runTask(plugin, () -> openChunkMapGui(p, false));
            return;
        }
        if (slot == 36) {
            createNextDefaultGroup(p);
            plugin.getServer().getScheduler().runTask(plugin, () -> openChunkMapGui(p, false));
            return;
        }
        if (slot == 0 || slot == 9 || slot == 18 || slot == 27) {
            ItemStack clicked = e.getCurrentItem();
            if (clicked == null) return;
            ItemMeta meta = clicked.getItemMeta();
            if (meta == null) return;
            String groupName = meta.getPersistentDataContainer().get(keyGuiGroup, PersistentDataType.STRING);
            if (groupName != null && !groupName.isBlank()) {
                if (e.getClick().isRightClick()) {
                    pendingGroupRename.put(p.getUniqueId(), groupName);
                    p.closeInventory();
                    p.sendMessage(ChatColor.AQUA + "Neuen Gruppennamen in den Chat schreiben (oder 'cancel').");
                    return;
                }
                selectedGroup.put(p.getUniqueId(), groupName);
                p.sendMessage(ChatColor.GREEN + "Aktive Gruppe: " + groupName);
                plugin.getServer().getScheduler().runTask(plugin, () -> openChunkMapGui(p, false));
                return;
            }
            return;
        }
        // ignore legend/filler in control row (except close already handled)
        if (slot >= 45) return;
        if ((slot % 9) == 0) return;
        // only map slots in columns 1..8, rows 0..4

        ItemStack clicked = e.getCurrentItem();
        if (clicked == null) return;
        ItemMeta meta = clicked.getItemMeta();
        if (meta == null || meta.getLore() == null) return;

        Integer cx = null;
        Integer cz = null;
        for (String line : meta.getLore()) {
            String plain = ChatColor.stripColor(line == null ? "" : line).trim();
            if (!plain.startsWith("Chunk:")) continue;
            String[] parts = plain.substring("Chunk:".length()).trim().split(",");
            if (parts.length != 2) continue;
            try {
                cx = Integer.parseInt(parts[0].trim());
                cz = Integer.parseInt(parts[1].trim());
            } catch (NumberFormatException ignored) {
                return;
            }
        }
        if (cx == null || cz == null) return;

        handleChunkMapAction(p, cx, cz);
        plugin.getServer().getScheduler().runTask(plugin, () -> openChunkMapGui(p, false));
    }

    private void handleChunkMapAction(Player p, int cx, int cz) {
        int minX = cx << 4;
        int maxX = minX + 15;
        int minZ = cz << 4;
        int maxZ = minZ + 15;
        Location probe = new Location(p.getWorld(), minX + 8, p.getLocation().getY(), minZ + 8);
        ClaimStore.Claim existing = store.byLocation(probe);

        String activeGroup = selectedGroup.get(p.getUniqueId());

        if (existing == null) {
            int maxClaims = plugin.getConfig().getInt("claims.max_claims_per_player", 5);
            if (!p.hasPermission("stone.admin") && store.byOwner(p.getUniqueId()).size() >= maxClaims) {
                p.sendMessage(ChatColor.RED + "Maximale Claims erreicht (" + maxClaims + ").");
                return;
            }
            if (store.overlaps(p.getWorld().getName(), minX, maxX, minZ, maxZ)) {
                p.sendMessage(ChatColor.RED + "Chunk ist bereits belegt.");
                return;
            }
            ClaimStore.Claim c = store.create(p.getUniqueId(), p.getWorld().getName(), minX, maxX, minZ, maxZ);
            if (c != null && activeGroup != null) {
                store.assignGroup(c.id, p.getUniqueId(), activeGroup);
                c.group = activeGroup;
            }
            p.sendMessage(ChatColor.GREEN + "Chunk geclaimt: " + cx + "," + cz + ChatColor.GRAY + " (ID=" + c.id + ")");
            return;
        }

        if (existing.ownedBy(p.getUniqueId()) || p.hasPermission("stone.admin")) {
            if (activeGroup != null) {
                if (store.assignGroup(existing.id, p.getUniqueId(), activeGroup)) {
                    p.sendMessage(ChatColor.GREEN + "Chunk " + cx + "," + cz + " Gruppe: " + activeGroup);
                } else {
                    p.sendMessage(ChatColor.RED + "Konnte Gruppe nicht zuweisen.");
                }
                return;
            }
            if (store.remove(existing.id)) {
                p.sendMessage(ChatColor.YELLOW + "Chunk entfernt: " + cx + "," + cz + ChatColor.GRAY + " (ID=" + existing.id + ")");
            } else {
                p.sendMessage(ChatColor.RED + "Konnte Claim nicht entfernen.");
            }
            return;
        }

        p.sendMessage(ChatColor.RED + "Dieses Chunk gehoert einem anderen Spieler.");
    }

    private void ensureDefaultGroups(UUID owner) {
        if (owner == null) return;
        createGroupIfMissing(owner, "rot", "RED");
        createGroupIfMissing(owner, "gruen", "GREEN");
        createGroupIfMissing(owner, "blau", "BLUE");
        createGroupIfMissing(owner, "gelb", "YELLOW");
    }

    private void createGroupIfMissing(UUID owner, String name, String color) {
        if (store.byGroup(owner, name) == null) store.createGroup(owner, name, color);
    }

    private void createNextDefaultGroup(Player p) {
        UUID owner = p.getUniqueId();
        ensureDefaultGroups(owner);
        List<String> names = List.of("rot", "gruen", "blau", "gelb", "lila", "orange");
        List<String> colors = List.of("RED", "GREEN", "BLUE", "YELLOW", "PURPLE", "ORANGE");
        for (int i = 0; i < names.size(); i++) {
            if (store.byGroup(owner, names.get(i)) != null) continue;
            store.createGroup(owner, names.get(i), colors.get(i));
            selectedGroup.put(owner, names.get(i));
            p.sendMessage(ChatColor.GREEN + "Gruppe erstellt: " + names.get(i));
            return;
        }
        p.sendMessage(ChatColor.YELLOW + "Alle Standard-Gruppen sind bereits vorhanden.");
    }

    private String colorForOwnGroup(UUID owner, String groupName) {
        ClaimStore.ClaimGroup g = store.byGroup(owner, groupName);
        return g == null ? "YELLOW" : g.color;
    }

    private Material groupMaterial(String colorName, boolean center) {
        String c = colorName == null ? "YELLOW" : colorName.toUpperCase(Locale.ROOT);
        return switch (c) {
            case "RED" -> center ? Material.RED_STAINED_GLASS : Material.RED_STAINED_GLASS_PANE;
            case "GREEN" -> center ? Material.GREEN_STAINED_GLASS : Material.GREEN_STAINED_GLASS_PANE;
            case "BLUE" -> center ? Material.BLUE_STAINED_GLASS : Material.BLUE_STAINED_GLASS_PANE;
            case "PURPLE", "LILA" -> center ? Material.PURPLE_STAINED_GLASS : Material.PURPLE_STAINED_GLASS_PANE;
            case "ORANGE" -> center ? Material.ORANGE_STAINED_GLASS : Material.ORANGE_STAINED_GLASS_PANE;
            case "YELLOW" -> center ? Material.YELLOW_STAINED_GLASS : Material.YELLOW_STAINED_GLASS_PANE;
            default -> center ? Material.WHITE_STAINED_GLASS : Material.WHITE_STAINED_GLASS_PANE;
        };
    }

    public void claimCurrentChunk(Player p) {
        claimCurrentChunk(p, null);
    }

    public void claimCurrentChunk(Player p, String preferredId) {
        org.bukkit.Chunk chunk = p.getLocation().getChunk();
        int minX = chunk.getX() << 4;
        int maxX = minX + 15;
        int minZ = chunk.getZ() << 4;
        int maxZ = minZ + 15;
        int maxClaims = plugin.getConfig().getInt("claims.max_claims_per_player", 5);

        if (!p.hasPermission("stone.admin") && store.byOwner(p.getUniqueId()).size() >= maxClaims) {
            p.sendMessage(ChatColor.RED + "Du hast bereits das Maximum an Claims erreicht (" + maxClaims + ").");
            return;
        }
        if (store.overlaps(p.getWorld().getName(), minX, maxX, minZ, maxZ)) {
            p.sendMessage(ChatColor.RED + "Dieses Chunk ist bereits geclaimt.");
            return;
        }

        String claimId = ClaimStore.normalizeId(preferredId);
        if (preferredId != null && !preferredId.isBlank() && claimId == null) {
            p.sendMessage(ChatColor.RED + "Ungueltige Claim-ID. Erlaubt: a-z, 0-9, - und _");
            return;
        }
        if (claimId != null && store.byId(claimId) != null) {
            p.sendMessage(ChatColor.RED + "Claim-ID bereits vergeben: " + claimId);
            return;
        }

        ClaimStore.Claim claim = store.create(p.getUniqueId(), p.getWorld().getName(), minX, maxX, minZ, maxZ, claimId);
        if (claim == null) {
            p.sendMessage(ChatColor.RED + "Konnte Claim nicht erstellen (ID evtl. bereits vergeben).");
            return;
        }
        p.sendMessage(ChatColor.GREEN + "Chunk geclaimt: " + claim.id);
        p.sendMessage(ChatColor.GRAY + "Chunk: " + chunk.getX() + "," + chunk.getZ());
    }

    public void unclaimCurrentChunk(Player p) {
        ClaimStore.Claim claim = store.byLocation(p.getLocation());
        if (claim == null) {
            p.sendMessage(ChatColor.YELLOW + "Du stehst in keinem Claim.");
            return;
        }
        if (!claim.ownedBy(p.getUniqueId()) && !p.hasPermission("stone.admin")) {
            p.sendMessage(ChatColor.RED + "Du kannst nur deine eigenen Claims entfernen.");
            return;
        }
        if (store.remove(claim.id)) {
            p.sendMessage(ChatColor.GREEN + "Aktuelles Chunk/Claim entfernt: " + claim.id);
        } else {
            p.sendMessage(ChatColor.RED + "Konnte den Claim nicht entfernen.");
        }
    }

    public void visualizeClaim(Player p) {
        ClaimStore.Claim claim = store.byLocation(p.getLocation());
        if (claim == null) {
            p.sendMessage(ChatColor.YELLOW + "Du stehst in keinem Claim.");
            return;
        }
        Area area = new Area(claim.world, claim.minX, claim.maxX, claim.minZ, claim.maxZ);
        toggleAreaOverlay(p, area);
    }

    public void listClaims(Player p) {
        List<ClaimStore.Claim> mine = store.byOwner(p.getUniqueId());
        if (mine.isEmpty()) {
            p.sendMessage(ChatColor.YELLOW + "Du hast keine Claims.");
            return;
        }
        p.sendMessage(ChatColor.GOLD + "Deine Claims (" + mine.size() + "):");
        for (ClaimStore.Claim c : mine) {
            p.sendMessage(ChatColor.GRAY + c.id + ChatColor.WHITE + " | " + c.world + " | "
                + c.minX + "," + c.minZ + " -> " + c.maxX + "," + c.maxZ
                + ChatColor.DARK_GRAY + " [" + c.area() + "]"
                + ChatColor.GRAY + " trusted=" + (c.trusted == null ? 0 : c.trusted.size()));
        }
    }

    public void removeClaim(Player p, String id) {
        ClaimStore.Claim c = store.byId(id);
        if (c == null) {
            p.sendMessage(ChatColor.RED + "Claim-ID nicht gefunden.");
            return;
        }
        boolean admin = p.hasPermission("stone.admin");
        if (!admin && !c.ownedBy(p.getUniqueId())) {
            p.sendMessage(ChatColor.RED + "Du kannst nur deine eigenen Claims entfernen.");
            return;
        }
        if (!store.remove(c.id)) {
            p.sendMessage(ChatColor.RED + "Konnte Claim nicht entfernen.");
            return;
        }
        p.sendMessage(ChatColor.GREEN + "Claim entfernt: " + c.id);
        plugin.getLogger().info("[claim] " + p.getName() + " removed claim=" + c.id);
    }

    public void claimInfo(Player p) {
        ClaimStore.Claim c = store.byLocation(p.getLocation());
        if (c == null) {
            p.sendMessage(ChatColor.YELLOW + "Du stehst in keinem Claim.");
            return;
        }
        p.sendMessage(ChatColor.GOLD + "Claim-Info:");
        p.sendMessage(ChatColor.GRAY + "ID: " + ChatColor.WHITE + c.id);
        p.sendMessage(ChatColor.GRAY + "Owner: " + ChatColor.WHITE + c.owner);
        p.sendMessage(ChatColor.GRAY + "Welt: " + ChatColor.WHITE + c.world);
        p.sendMessage(ChatColor.GRAY + "Bereich: " + ChatColor.WHITE + c.minX + "," + c.minZ + " -> " + c.maxX + "," + c.maxZ);
        p.sendMessage(ChatColor.GRAY + "Groesse: " + ChatColor.WHITE + c.width() + " x " + c.length() + " (" + c.area() + ")");
        p.sendMessage(ChatColor.GRAY + "Trusted: " + ChatColor.WHITE + (c.trusted == null ? 0 : c.trusted.size()));
    }

    public void trustClaim(Player owner, String id, String targetName) {
        ClaimStore.Claim claim = store.byId(id);
        if (claim == null) {
            owner.sendMessage(ChatColor.RED + "Claim-ID nicht gefunden.");
            return;
        }
        if (!claim.ownedBy(owner.getUniqueId()) && !owner.hasPermission("stone.admin")) {
            owner.sendMessage(ChatColor.RED + "Du kannst nur deine eigenen Claims verwalten.");
            return;
        }
        Player target = plugin.getServer().getPlayerExact(targetName);
        if (target == null) {
            owner.sendMessage(ChatColor.RED + "Spieler ist nicht online: " + targetName);
            return;
        }
        pendingTrustInvites.put(target.getUniqueId(), new TrustInvite(claim.id, owner.getUniqueId()));
        owner.sendMessage(ChatColor.GREEN + "Trust-Anfrage gesendet an " + target.getName() + ".");
        target.sendMessage(ChatColor.GOLD + owner.getName() + ChatColor.GRAY + " moechte dich fuer Claim "
            + ChatColor.WHITE + claim.id + ChatColor.GRAY + " freischalten.");
        target.sendMessage(Component.text("[Trust annehmen] ", NamedTextColor.GREEN)
            .append(Component.text("(klickbar)", NamedTextColor.GRAY))
            .clickEvent(ClickEvent.runCommand("/stoneclaim accept")));
        target.sendMessage(ChatColor.YELLOW + "Oder nutze /stoneclaim accept");
    }

    public void acceptTrust(Player player) {
        TrustInvite invite = pendingTrustInvites.remove(player.getUniqueId());
        if (invite == null || (System.currentTimeMillis() - invite.createdAt) > 120000L) {
            player.sendMessage(ChatColor.YELLOW + "Keine offene Trust-Anfrage.");
            return;
        }
        if (!store.trust(invite.claimId, player.getUniqueId())) {
            player.sendMessage(ChatColor.RED + "Konnte Trust nicht speichern.");
            return;
        }
        player.sendMessage(ChatColor.GREEN + "Du bist jetzt fuer Claim " + invite.claimId + " freigeschaltet.");
        Player owner = plugin.getServer().getPlayer(invite.owner);
        if (owner != null) owner.sendMessage(ChatColor.GREEN + player.getName() + " hat den Claim-Trust akzeptiert.");
    }

    public void untrustClaim(Player owner, String id, String targetName) {
        ClaimStore.Claim claim = store.byId(id);
        if (claim == null) {
            owner.sendMessage(ChatColor.RED + "Claim-ID nicht gefunden.");
            return;
        }
        if (!claim.ownedBy(owner.getUniqueId()) && !owner.hasPermission("stone.admin")) {
            owner.sendMessage(ChatColor.RED + "Du kannst nur deine eigenen Claims verwalten.");
            return;
        }
        org.bukkit.OfflinePlayer target = plugin.getServer().getOfflinePlayer(targetName);
        if (target.getUniqueId() == null || !store.untrust(id, target.getUniqueId())) {
            owner.sendMessage(ChatColor.RED + "Spieler war nicht getrustet oder konnte nicht entfernt werden.");
            return;
        }
        owner.sendMessage(ChatColor.GREEN + targetName + " wurde aus Claim " + id + " entfernt.");
    }

    public void transferClaim(Player sender, String id, String targetName) {
        ClaimStore.Claim claim = store.byId(id);
        if (claim == null) {
            sender.sendMessage(ChatColor.RED + "Claim-ID nicht gefunden.");
            return;
        }
        if (!claim.ownedBy(sender.getUniqueId()) && !sender.hasPermission("stone.admin")) {
            sender.sendMessage(ChatColor.RED + "Nur Owner oder Admin koennen Claims uebertragen.");
            return;
        }
        org.bukkit.OfflinePlayer target = plugin.getServer().getOfflinePlayer(targetName);
        if (target.getUniqueId() == null) {
            sender.sendMessage(ChatColor.RED + "Spieler nicht gefunden: " + targetName);
            return;
        }
        if (!store.transfer(id, target.getUniqueId())) {
            sender.sendMessage(ChatColor.RED + "Claim konnte nicht uebertragen werden.");
            return;
        }
        sender.sendMessage(ChatColor.GREEN + "Claim " + id + " wurde an " + targetName + " uebertragen.");
    }

    public void trustGroupOrAll(Player owner, String groupOrAll, String targetName) {
        org.bukkit.OfflinePlayer target = plugin.getServer().getOfflinePlayer(targetName);
        if (target.getUniqueId() == null) {
            owner.sendMessage(ChatColor.RED + "Spieler nicht gefunden: " + targetName);
            return;
        }

        String mode = groupOrAll == null ? "" : groupOrAll.toLowerCase(Locale.ROOT);
        if ("all".equals(mode)) {
            int changedGroups = store.trustAllGroups(owner.getUniqueId(), target.getUniqueId());
            int changedClaims = 0;
            for (ClaimStore.Claim c : store.byOwner(owner.getUniqueId())) {
                if (store.trust(c.id, target.getUniqueId())) changedClaims++;
            }
            owner.sendMessage(ChatColor.GREEN + targetName + " hat jetzt Zugriff auf alle Claims/Gruppen"
                + ChatColor.GRAY + " (claims=" + changedClaims + ", groups=" + changedGroups + ")");
            return;
        }

        String group = ClaimStore.normalizeGroupName(groupOrAll);
        if (group == null) {
            owner.sendMessage(ChatColor.RED + "Ungueltiger Gruppenname.");
            return;
        }
        if (store.byGroup(owner.getUniqueId(), group) == null) {
            owner.sendMessage(ChatColor.RED + "Gruppe nicht gefunden: " + group);
            return;
        }
        if (!store.trustGroup(owner.getUniqueId(), group, target.getUniqueId())) {
            owner.sendMessage(ChatColor.RED + "Konnte Gruppen-Trust nicht setzen.");
            return;
        }
        owner.sendMessage(ChatColor.GREEN + targetName + " ist jetzt in Gruppe " + group + " getrustet.");
    }

    public void untrustGroups(Player owner, List<String> groups, String targetName) {
        org.bukkit.OfflinePlayer target = plugin.getServer().getOfflinePlayer(targetName);
        if (target.getUniqueId() == null) {
            owner.sendMessage(ChatColor.RED + "Spieler nicht gefunden: " + targetName);
            return;
        }
        if (groups == null || groups.isEmpty()) {
            owner.sendMessage(ChatColor.RED + "Bitte mindestens eine Gruppe angeben.");
            return;
        }
        boolean all = groups.stream().anyMatch(g -> "all".equalsIgnoreCase(g));
        if (all) {
            List<String> allGroupNames = new ArrayList<>();
            for (ClaimStore.ClaimGroup g : store.groupsByOwner(owner.getUniqueId())) allGroupNames.add(g.name);
            int changedGroups = store.untrustGroups(owner.getUniqueId(), allGroupNames, target.getUniqueId());
            int changedClaims = 0;
            for (ClaimStore.Claim c : store.byOwner(owner.getUniqueId())) {
                if (store.untrust(c.id, target.getUniqueId())) changedClaims++;
            }
            owner.sendMessage(ChatColor.YELLOW + targetName + " aus allen Claims/Gruppen entfernt"
                + ChatColor.GRAY + " (claims=" + changedClaims + ", groups=" + changedGroups + ")");
            return;
        }
        int changed = store.untrustGroups(owner.getUniqueId(), groups, target.getUniqueId());
        owner.sendMessage(ChatColor.YELLOW + targetName + " aus " + changed + " Gruppen entfernt.");
    }

    public void sendHelp(Player p) {
        p.sendMessage(ChatColor.GOLD + "Stone Claim Commands:");
        p.sendMessage(ChatColor.YELLOW + "/stoneclaim gui" + ChatColor.GRAY + " - Chunk-Claim GUI oeffnen");
        p.sendMessage(ChatColor.YELLOW + "/stoneclaim visual [all|claim]" + ChatColor.GRAY + " - Grenzen mit Fackeln an/aus");
        p.sendMessage(ChatColor.YELLOW + "/stoneclaim list" + ChatColor.GRAY + " - eigene Claims");
        p.sendMessage(ChatColor.YELLOW + "/stoneclaim info" + ChatColor.GRAY + " - Claim unter dir anzeigen");
        p.sendMessage(ChatColor.YELLOW + "/stoneclaim remove <id>" + ChatColor.GRAY + " - Claim entfernen");
        p.sendMessage(ChatColor.YELLOW + "/stoneclaim trust <id> <spieler>" + ChatColor.GRAY + " - Trust-Anfrage senden");
        p.sendMessage(ChatColor.YELLOW + "/stoneclaim accept" + ChatColor.GRAY + " - Trust annehmen");
        p.sendMessage(ChatColor.YELLOW + "/stoneclaim untrust <id> <spieler>" + ChatColor.GRAY + " - Trust entfernen");
        p.sendMessage(ChatColor.YELLOW + "/stoneclaim transfer <id> <spieler>" + ChatColor.GRAY + " - Claim uebertragen");
        p.sendMessage(ChatColor.YELLOW + "/stoneclaim <gruppe|all> <spieler>" + ChatColor.GRAY + " - Gruppen-Trust setzen");
        p.sendMessage(ChatColor.YELLOW + "/stoneclaim untrust <gruppe...> <spieler>" + ChatColor.GRAY + " - aus Gruppen entfernen");
    }

    public void visualizeAllClaims(Player p) {
        if (clearBoundaryOverlay(p)) {
            p.sendMessage(ChatColor.YELLOW + "Claim-Grenzen ausgeblendet.");
            return;
        }

        String worldName = p.getWorld().getName();
        List<ClaimStore.Claim> all = store.snapshot();
        List<ClaimStore.Claim> inWorld = new ArrayList<>();
        for (ClaimStore.Claim c : all) {
            if (worldName.equals(c.world)) inWorld.add(c);
        }
        if (inWorld.isEmpty()) {
            p.sendMessage(ChatColor.YELLOW + "Keine Claims in dieser Welt gefunden.");
            return;
        }

        int maxClaims = Math.max(1, plugin.getConfig().getInt("claims.visual.max_claims", 250));
        if (inWorld.size() > maxClaims) {
            inWorld = new ArrayList<>(inWorld.subList(0, maxClaims));
            p.sendMessage(ChatColor.YELLOW + "Viele Claims gefunden - zeige erste " + maxClaims + " an.");
        }

        Set<Location> markers = new LinkedHashSet<>();
        int step = Math.max(1, plugin.getConfig().getInt("claims.visual.step", 2));
        for (ClaimStore.Claim c : inWorld) {
            markers.addAll(collectOutlineLocations(p.getWorld(), c.minX, c.maxX, c.minZ, c.maxZ, step));
        }
        applyBoundaryOverlay(p, new ArrayList<>(markers));
        p.sendMessage(ChatColor.AQUA + "Claim-Grenzen aktiv: " + ChatColor.WHITE + inWorld.size()
            + ChatColor.AQUA + " Claims in " + ChatColor.WHITE + worldName
            + ChatColor.GRAY + " (erneut /stoneclaim visual = aus)");
    }

    private void toggleAreaOverlay(Player p, Area area) {
        if (area == null) return;
        org.bukkit.World world = p.getWorld();
        if (!world.getName().equals(area.world)) {
            p.sendMessage(ChatColor.RED + "Du musst in derselben Welt stehen, um das zu visualisieren.");
            return;
        }

        if (clearBoundaryOverlay(p)) {
            p.sendMessage(ChatColor.YELLOW + "Claim-Grenzen ausgeblendet.");
            return;
        }

        int chunks = chunkCount(area.minX, area.maxX, area.minZ, area.maxZ);
        int step = Math.max(1, plugin.getConfig().getInt("claims.visual.step", 2));
        List<Location> markers = collectOutlineLocations(world, area.minX, area.maxX, area.minZ, area.maxZ, step);
        applyBoundaryOverlay(p, markers);

        p.sendMessage(ChatColor.AQUA + "Grenzen aktiv: " + ChatColor.WHITE + area.width + " x " + area.length
            + ChatColor.GRAY + " (" + area.blockArea + " Bloecke, " + chunks + " Chunks)");
    }

    private List<Location> collectOutlineLocations(org.bukkit.World world, int minX, int maxX, int minZ, int maxZ, int step) {
        Set<Location> out = new LinkedHashSet<>();
        for (int x = minX; x <= maxX; x += step) {
            out.add(markerLocation(world, x, minZ, 1));
            out.add(markerLocation(world, x, maxZ, 1));
        }
        for (int z = minZ; z <= maxZ; z += step) {
            out.add(markerLocation(world, minX, z, 1));
            out.add(markerLocation(world, maxX, z, 1));
        }

        // Ensure corners are always present.
        out.add(markerLocation(world, minX, minZ, 1));
        out.add(markerLocation(world, minX, maxZ, 1));
        out.add(markerLocation(world, maxX, minZ, 1));
        out.add(markerLocation(world, maxX, maxZ, 1));
        return new ArrayList<>(out);
    }

    private Location markerLocation(org.bukkit.World world, int x, int z, int yOffset) {
        int y = Math.max(world.getHighestBlockYAt(x, z) + yOffset, world.getMinHeight() + 2);
        return new Location(world, x, y, z);
    }

    private void applyBoundaryOverlay(Player p, List<Location> markers) {
        clearBoundaryOverlay(p);
        if (markers.isEmpty()) return;
        BlockData torch = Material.TORCH.createBlockData();
        for (Location loc : markers) {
            p.sendBlockChange(loc, torch);
        }
        boundaryOverlays.put(p.getUniqueId(), markers);
    }

    private boolean clearBoundaryOverlay(Player p) {
        List<Location> current = boundaryOverlays.remove(p.getUniqueId());
        if (current == null || current.isEmpty()) return false;
        for (Location loc : current) {
            if (loc.getWorld() == null) continue;
            p.sendBlockChange(loc, loc.getBlock().getBlockData());
        }
        return true;
    }

    private String ownerDisplayName(ClaimStore.Claim claim) {
        if (claim == null || claim.owner == null || claim.owner.isBlank()) return "Unbekannt";
        try {
            UUID id = UUID.fromString(claim.owner);
            org.bukkit.OfflinePlayer op = plugin.getServer().getOfflinePlayer(id);
            if (op != null && op.getName() != null && !op.getName().isBlank()) return op.getName();
        } catch (IllegalArgumentException ignored) {
            // Fallback for legacy/non-UUID owner strings.
        }
        return claim.owner;
    }

    private int chunkCount(int minX, int maxX, int minZ, int maxZ) {
        int startChunkX = Math.floorDiv(minX, 16);
        int endChunkX = Math.floorDiv(maxX, 16);
        int startChunkZ = Math.floorDiv(minZ, 16);
        int endChunkZ = Math.floorDiv(maxZ, 16);
        return (endChunkX - startChunkX + 1) * (endChunkZ - startChunkZ + 1);
    }

    private static final class Area {
        final String world;
        final int minX;
        final int maxX;
        final int minZ;
        final int maxZ;
        final int width;
        final int length;
        final int blockArea;

        Area(String world, int minX, int maxX, int minZ, int maxZ) {
            this.world = world;
            this.minX = minX;
            this.maxX = maxX;
            this.minZ = minZ;
            this.maxZ = maxZ;
            this.width = maxX - minX + 1;
            this.length = maxZ - minZ + 1;
            this.blockArea = width * length;
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onBreak(BlockBreakEvent e) {
        denyIfClaimed(e.getPlayer(), e.getBlock().getLocation(), e);
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onPlace(BlockPlaceEvent e) {
        denyIfClaimed(e.getPlayer(), e.getBlock().getLocation(), e);
    }

    @EventHandler(ignoreCancelled = true)
    public void onMove(PlayerMoveEvent e) {
        if (e.getTo() == null || e.getFrom().getWorld() == null || e.getTo().getWorld() == null) return;
        // Keep it cheap: only react when chunk or world changes.
        if (e.getFrom().getWorld().equals(e.getTo().getWorld())
            && e.getFrom().getChunk().getX() == e.getTo().getChunk().getX()
            && e.getFrom().getChunk().getZ() == e.getTo().getChunk().getZ()) {
            return;
        }

        Player p = e.getPlayer();
        ClaimStore.Claim toClaim = store.byLocation(e.getTo());
        String newId = toClaim == null ? "" : toClaim.id;
        String oldId = lastChunkClaim.getOrDefault(p.getUniqueId(), "");
        if (newId.equals(oldId)) return;
        lastChunkClaim.put(p.getUniqueId(), newId);

        long now = System.currentTimeMillis();
        long last = notifyCooldown.getOrDefault(p.getUniqueId(), 0L);
        if (now - last < 1000L) return;
        notifyCooldown.put(p.getUniqueId(), now);

        if (toClaim == null) {
            p.sendActionBar(Component.text("Freies Land", NamedTextColor.GREEN));
            return;
        }
        String ownerName = ownerDisplayName(toClaim);
        if (toClaim.ownedBy(p.getUniqueId())) {
            p.sendActionBar(Component.text("Land von " + ownerName, NamedTextColor.GOLD));
            return;
        }
        if (toClaim.trusted(p.getUniqueId()) || store.trustedViaGroup(toClaim, p.getUniqueId())) {
            p.sendActionBar(Component.text("Land von " + ownerName, NamedTextColor.YELLOW));
            return;
        }
        p.sendActionBar(Component.text("Land von " + ownerName, NamedTextColor.RED));
    }

    @EventHandler(ignoreCancelled = true)
    public void onGroupRenameChat(AsyncPlayerChatEvent e) {
        String oldName = pendingGroupRename.get(e.getPlayer().getUniqueId());
        if (oldName == null) return;

        e.setCancelled(true);
        String msg = e.getMessage() == null ? "" : e.getMessage().trim();
        Player p = e.getPlayer();
        if (msg.equalsIgnoreCase("cancel")) {
            pendingGroupRename.remove(p.getUniqueId());
            plugin.getServer().getScheduler().runTask(plugin, () -> {
                p.sendMessage(ChatColor.YELLOW + "Gruppen-Umbenennung abgebrochen.");
                openChunkMapGui(p, false);
            });
            return;
        }

        String newName = ClaimStore.normalizeGroupName(msg);
        if (newName == null) {
            plugin.getServer().getScheduler().runTask(plugin, () ->
                p.sendMessage(ChatColor.RED + "Ungueltiger Name. Erlaubt: a-z, 0-9, - und _"));
            return;
        }

        boolean renamed = store.renameGroup(p.getUniqueId(), oldName, newName);
        pendingGroupRename.remove(p.getUniqueId());
        plugin.getServer().getScheduler().runTask(plugin, () -> {
            if (renamed) {
                selectedGroup.put(p.getUniqueId(), newName);
                p.sendMessage(ChatColor.GREEN + "Gruppe umbenannt: " + oldName + " -> " + newName);
            } else {
                p.sendMessage(ChatColor.RED + "Konnte Gruppe nicht umbenennen (Name evtl. vergeben).");
            }
            openChunkMapGui(p, false);
        });
    }

    @EventHandler
    public void onQuit(PlayerQuitEvent e) {
        clearBoundaryOverlay(e.getPlayer());
        lastChunkClaim.remove(e.getPlayer().getUniqueId());
        notifyCooldown.remove(e.getPlayer().getUniqueId());
        pendingGroupRename.remove(e.getPlayer().getUniqueId());
        mapCenter.remove(e.getPlayer().getUniqueId());
    }

    private void denyIfClaimed(Player p, org.bukkit.Location loc, org.bukkit.event.Cancellable c) {
        ClaimStore.Claim claim = store.byLocation(loc);
        if (claim == null) return;
        if (claim.ownedBy(p.getUniqueId())
            || claim.trusted(p.getUniqueId())
            || store.trustedViaGroup(claim, p.getUniqueId())
            || p.hasPermission("stone.admin")) return;

        c.setCancelled(true);
        long now = System.currentTimeMillis();
        long last = notifyCooldown.getOrDefault(p.getUniqueId(), 0L);
        if (now - last > 1200L) {
            p.sendMessage(ChatColor.RED + "Dieser Bereich ist geclaimt.");
            notifyCooldown.put(p.getUniqueId(), now);
        }
    }
}
