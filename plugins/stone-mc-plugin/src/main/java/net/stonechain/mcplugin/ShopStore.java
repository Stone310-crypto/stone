package net.stonechain.mcplugin;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.bukkit.inventory.ItemStack;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Persistenter Shop-Store: Liste von Items mit Shard-Preis.
 *
 * ItemStacks werden via Bukkit `serializeAsBytes()` (Paper API ≥1.20.4)
 * Base64-kodiert, damit der komplette NBT-Inhalt erhalten bleibt.
 */
public final class ShopStore {

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    public static final class Item {
        public String id;
        public String displayName;
        /** Base64 of ItemStack.serializeAsBytes() */
        public String stackB64;
        public long priceShards;
        public String addedBy;
        public long addedAt;
    }

    private static final class State {
        List<Item> items = new ArrayList<>();
    }

    private final File file;
    private final Object lock = new Object();
    private final List<Item> items = new ArrayList<>();
    public ShopStore(File dataFolder) {
        this.file = new File(dataFolder, "shop.json");
    }

    public void load() {
        synchronized (lock) {
            items.clear();
            if (!file.exists()) return;
            try (FileReader r = new FileReader(file)) {
                State st = GSON.fromJson(r, State.class);
                if (st != null) {
                    if (st.items != null) items.addAll(st.items);
                }
            } catch (IOException ignored) { }
        }
    }

    public void save() {
        synchronized (lock) {
            File dir = file.getParentFile();
            if (dir != null && !dir.exists()) dir.mkdirs();
            State st = new State();
            st.items = new ArrayList<>(items);
            File tmp = new File(file.getAbsolutePath() + ".tmp");
            try (FileWriter w = new FileWriter(tmp)) {
                GSON.toJson(st, w);
            } catch (IOException e) { return; }
            //noinspection ResultOfMethodCallIgnored
            tmp.renameTo(file);
        }
    }

    public List<Item> snapshot() {
        synchronized (lock) { return new ArrayList<>(items); }
    }

    public Item byId(String id) {
        synchronized (lock) {
            for (Item it : items) if (it.id.equals(id)) return it;
            return null;
        }
    }

    public Item add(ItemStack stack, long priceShards, UUID adder) {
        if (stack == null || priceShards <= 0) return null;
        Item it = new Item();
        it.id = UUID.randomUUID().toString().substring(0, 8);
        it.displayName = (stack.getItemMeta() != null && stack.getItemMeta().hasDisplayName())
            ? stack.getItemMeta().getDisplayName()
            : stack.getType().name();
        it.stackB64 = Base64.getEncoder().encodeToString(stack.serializeAsBytes());
        it.priceShards = priceShards;
        it.addedBy = adder.toString();
        it.addedAt = System.currentTimeMillis();
        synchronized (lock) { items.add(it); }
        save();
        return it;
    }

    public boolean remove(String id) {
        boolean removed;
        synchronized (lock) { removed = items.removeIf(i -> i.id.equals(id)); }
        if (removed) save();
        return removed;
    }

    public ItemStack materialize(Item it) {
        if (it == null || it.stackB64 == null) return null;
        try {
            return ItemStack.deserializeBytes(Base64.getDecoder().decode(it.stackB64));
        } catch (Exception e) {
            return null;
        }
    }

}
