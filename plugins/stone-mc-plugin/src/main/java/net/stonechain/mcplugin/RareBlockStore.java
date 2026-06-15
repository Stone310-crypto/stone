package net.stonechain.mcplugin;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

/**
 * Persists placed rare block coordinates.
 */
public final class RareBlockStore {

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    private static final class State {
        Set<String> positions = new HashSet<>();
    }

    private final File file;
    private final Object lock = new Object();
    private final Set<String> positions = new HashSet<>();

    public RareBlockStore(File dataFolder) {
        this.file = new File(dataFolder, "rare_blocks.json");
    }

    public void load() {
        synchronized (lock) {
            positions.clear();
            if (!file.exists()) return;
            try (FileReader r = new FileReader(file)) {
                State st = GSON.fromJson(r, State.class);
                if (st != null && st.positions != null) positions.addAll(st.positions);
            } catch (IOException ignored) { }
        }
    }

    public void save() {
        synchronized (lock) {
            File dir = file.getParentFile();
            if (dir != null && !dir.exists()) dir.mkdirs();
            State st = new State();
            st.positions = new HashSet<>(positions);
            File tmp = new File(file.getAbsolutePath() + ".tmp");
            try (FileWriter w = new FileWriter(tmp)) {
                GSON.toJson(st, w);
            } catch (IOException e) {
                return;
            }
            //noinspection ResultOfMethodCallIgnored
            tmp.renameTo(file);
        }
    }

    public boolean isRare(org.bukkit.Location loc) {
        if (loc == null || loc.getWorld() == null) return false;
        synchronized (lock) {
            return positions.contains(key(loc));
        }
    }

    public void mark(org.bukkit.Location loc) {
        if (loc == null || loc.getWorld() == null) return;
        synchronized (lock) {
            positions.add(key(loc));
        }
        save();
    }

    public void unmark(org.bukkit.Location loc) {
        if (loc == null || loc.getWorld() == null) return;
        synchronized (lock) {
            positions.remove(key(loc));
        }
        save();
    }

    private String key(org.bukkit.Location loc) {
        return loc.getWorld().getName() + ":" + loc.getBlockX() + ":" + loc.getBlockY() + ":" + loc.getBlockZ();
    }
}
