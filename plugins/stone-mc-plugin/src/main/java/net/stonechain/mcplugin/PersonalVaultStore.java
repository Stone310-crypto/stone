package net.stonechain.mcplugin;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import org.bukkit.inventory.ItemStack;
import org.bukkit.util.io.BukkitObjectInputStream;
import org.bukkit.util.io.BukkitObjectOutputStream;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.Type;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

/**
 * Persistent per-player virtual vault contents.
 *
 * Stores full ItemStack arrays (base64 serialized) so shard/coin metadata
 * is preserved exactly across restarts.
 */
public final class PersonalVaultStore {

    private static final Gson GSON = new Gson();

    private final File dataFolder;
    private final File file;
    private final Logger log;
    private final Map<UUID, String> encoded = new ConcurrentHashMap<>();

    public PersonalVaultStore(File dataFolder, Logger log) {
        this.dataFolder = dataFolder;
        this.file = new File(dataFolder, "vaults.json");
        this.log = log;
    }

    public synchronized void load() {
        if (!file.exists()) return;
        try (FileReader r = new FileReader(file)) {
            Type t = new TypeToken<Map<String, String>>() {}.getType();
            Map<String, String> raw = GSON.fromJson(r, t);
            if (raw == null) return;
            encoded.clear();
            for (var e : raw.entrySet()) {
                try {
                    encoded.put(UUID.fromString(e.getKey()), e.getValue());
                } catch (IllegalArgumentException ignored) {
                    // Ignore malformed keys.
                }
            }
            log.info("PersonalVaultStore loaded: " + encoded.size() + " player vault(s)");
        } catch (IOException ex) {
            log.warning("PersonalVaultStore load failed: " + ex.getMessage());
        }
    }

    public synchronized void save() {
        if (!dataFolder.exists()) dataFolder.mkdirs();
        Map<String, String> raw = new HashMap<>();
        for (var e : encoded.entrySet()) raw.put(e.getKey().toString(), e.getValue());
        File tmp = new File(file.getAbsolutePath() + ".tmp");
        try (FileWriter w = new FileWriter(tmp)) {
            GSON.toJson(raw, w);
        } catch (IOException ex) {
            log.warning("PersonalVaultStore save failed: " + ex.getMessage());
            return;
        }
        //noinspection ResultOfMethodCallIgnored
        tmp.renameTo(file);
    }

    public synchronized ItemStack[] getContents(UUID playerId, int size) {
        String s = encoded.get(playerId);
        if (s == null || s.isBlank()) return new ItemStack[size];
        ItemStack[] decoded = decodeItems(s);
        if (decoded == null) return new ItemStack[size];
        ItemStack[] out = new ItemStack[size];
        System.arraycopy(decoded, 0, out, 0, Math.min(size, decoded.length));
        return out;
    }

    public synchronized void setContents(UUID playerId, ItemStack[] contents) {
        String s = encodeItems(contents);
        if (s == null || s.isBlank()) {
            encoded.remove(playerId);
            return;
        }
        encoded.put(playerId, s);
    }

    private static String encodeItems(ItemStack[] items) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (BukkitObjectOutputStream out = new BukkitObjectOutputStream(baos)) {
                out.writeInt(items.length);
                for (ItemStack item : items) out.writeObject(item);
            }
            return Base64.getEncoder().encodeToString(baos.toByteArray());
        } catch (IOException ex) {
            return null;
        }
    }

    private static ItemStack[] decodeItems(String base64) {
        try {
            byte[] data = Base64.getDecoder().decode(base64);
            try (BukkitObjectInputStream in = new BukkitObjectInputStream(new ByteArrayInputStream(data))) {
                int len = in.readInt();
                ItemStack[] out = new ItemStack[len];
                for (int i = 0; i < len; i++) {
                    Object obj = in.readObject();
                    out[i] = (obj instanceof ItemStack) ? (ItemStack) obj : null;
                }
                return out;
            }
        } catch (Exception ex) {
            return null;
        }
    }
}
