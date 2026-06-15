package net.stonechain.mcplugin;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.bukkit.Location;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

/**
 * Persistenter 2D-Claim-Store (X/Z, world-spezifisch).
 */
public final class ClaimStore {

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    public static final class Claim {
        public String id;
        public String owner;
        public String world;
        public int minX;
        public int maxX;
        public int minZ;
        public int maxZ;
        public long createdAt;
        public String group;
        public List<String> trusted = new ArrayList<>();

        public boolean contains(Location loc) {
            if (loc == null || loc.getWorld() == null) return false;
            if (!world.equals(loc.getWorld().getName())) return false;
            int x = loc.getBlockX();
            int z = loc.getBlockZ();
            return x >= minX && x <= maxX && z >= minZ && z <= maxZ;
        }

        public int width() { return maxX - minX + 1; }
        public int length() { return maxZ - minZ + 1; }
        public int area() { return width() * length(); }

        public boolean ownedBy(UUID id) {
            return id != null && id.toString().equals(owner);
        }

        public boolean trusted(UUID id) {
            return id != null && trusted != null && trusted.contains(id.toString());
        }
    }

    public static final class ClaimGroup {
        public String owner;
        public String name;
        public String color;
        public List<String> trusted = new ArrayList<>();

        public boolean ownedBy(UUID id) {
            return id != null && id.toString().equals(owner);
        }
    }

    private static final class State {
        List<Claim> claims = new ArrayList<>();
        List<ClaimGroup> groups = new ArrayList<>();
    }

    private final File file;
    private final Object lock = new Object();
    private final List<Claim> claims = new ArrayList<>();
    private final List<ClaimGroup> groups = new ArrayList<>();

    public ClaimStore(File dataFolder) {
        this.file = new File(dataFolder, "claims.json");
    }

    public void load() {
        synchronized (lock) {
            claims.clear();
            groups.clear();
            if (!file.exists()) return;
            try (FileReader r = new FileReader(file)) {
                State st = GSON.fromJson(r, State.class);
                if (st != null && st.claims != null) claims.addAll(st.claims);
                if (st != null && st.groups != null) groups.addAll(st.groups);
            } catch (IOException ignored) { }
        }
    }

    public void save() {
        synchronized (lock) {
            File dir = file.getParentFile();
            if (dir != null && !dir.exists()) dir.mkdirs();
            State st = new State();
            st.claims = new ArrayList<>(claims);
            st.groups = new ArrayList<>(groups);
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

    public List<Claim> snapshot() {
        synchronized (lock) {
            return new ArrayList<>(claims);
        }
    }

    public List<ClaimGroup> groupsByOwner(UUID owner) {
        List<ClaimGroup> out = new ArrayList<>();
        if (owner == null) return out;
        synchronized (lock) {
            for (ClaimGroup g : groups) {
                if (g.ownedBy(owner)) out.add(g);
            }
        }
        return out;
    }

    public List<Claim> byOwner(UUID owner) {
        List<Claim> out = new ArrayList<>();
        if (owner == null) return out;
        synchronized (lock) {
            for (Claim c : claims) {
                if (c.ownedBy(owner)) out.add(c);
            }
        }
        return out;
    }

    public Claim byId(String id) {
        if (id == null || id.isBlank()) return null;
        synchronized (lock) {
            for (Claim c : claims) {
                if (id.equalsIgnoreCase(c.id)) return c;
            }
            return null;
        }
    }

    public Claim byLocation(Location loc) {
        synchronized (lock) {
            for (Claim c : claims) {
                if (c.contains(loc)) return c;
            }
            return null;
        }
    }

    public boolean overlaps(String world, int minX, int maxX, int minZ, int maxZ) {
        synchronized (lock) {
            for (Claim c : claims) {
                if (!c.world.equals(world)) continue;
                boolean disjoint = maxX < c.minX || minX > c.maxX || maxZ < c.minZ || minZ > c.maxZ;
                if (!disjoint) return true;
            }
            return false;
        }
    }

    public Claim create(UUID owner, String world, int minX, int maxX, int minZ, int maxZ) {
        return create(owner, world, minX, maxX, minZ, maxZ, null);
    }

    public Claim create(UUID owner, String world, int minX, int maxX, int minZ, int maxZ, String preferredId) {
        if (owner == null || world == null) return null;
        Claim c = new Claim();
        String requested = normalizeId(preferredId);
        synchronized (lock) {
            if (requested != null) {
                for (Claim existing : claims) {
                    if (requested.equalsIgnoreCase(existing.id)) return null;
                }
                c.id = requested;
            } else {
                String generated;
                do {
                    generated = UUID.randomUUID().toString().substring(0, 8);
                } while (byIdUnsafe(generated) != null);
                c.id = generated;
            }
        }
        c.owner = owner.toString();
        c.world = world;
        c.minX = minX;
        c.maxX = maxX;
        c.minZ = minZ;
        c.maxZ = maxZ;
        c.createdAt = System.currentTimeMillis();
        c.group = null;
        c.trusted = new ArrayList<>();
        synchronized (lock) {
            claims.add(c);
        }
        save();
        return c;
    }

    public static String normalizeGroupName(String raw) {
        return normalizeId(raw);
    }

    public ClaimGroup byGroup(UUID owner, String name) {
        String normalized = normalizeGroupName(name);
        if (owner == null || normalized == null) return null;
        synchronized (lock) {
            for (ClaimGroup g : groups) {
                if (g.ownedBy(owner) && normalized.equalsIgnoreCase(g.name)) return g;
            }
            return null;
        }
    }

    public ClaimGroup createGroup(UUID owner, String name, String color) {
        String normalized = normalizeGroupName(name);
        if (owner == null || normalized == null) return null;
        synchronized (lock) {
            for (ClaimGroup g : groups) {
                if (g.ownedBy(owner) && normalized.equalsIgnoreCase(g.name)) return g;
            }
            ClaimGroup g = new ClaimGroup();
            g.owner = owner.toString();
            g.name = normalized;
            g.color = color == null || color.isBlank() ? "WHITE" : color;
            g.trusted = new ArrayList<>();
            groups.add(g);
            save();
            return g;
        }
    }

    public boolean assignGroup(String claimId, UUID owner, String groupName) {
        String normalized = normalizeGroupName(groupName);
        if (owner == null || normalized == null) return false;
        synchronized (lock) {
            ClaimGroup group = null;
            for (ClaimGroup g : groups) {
                if (g.ownedBy(owner) && normalized.equalsIgnoreCase(g.name)) {
                    group = g;
                    break;
                }
            }
            if (group == null) return false;

            for (Claim c : claims) {
                if (!c.id.equalsIgnoreCase(claimId)) continue;
                if (!c.ownedBy(owner)) return false;
                c.group = group.name;
                save();
                return true;
            }
            return false;
        }
    }

    public boolean renameGroup(UUID owner, String oldName, String newName) {
        String oldNorm = normalizeGroupName(oldName);
        String newNorm = normalizeGroupName(newName);
        if (owner == null || oldNorm == null || newNorm == null) return false;
        synchronized (lock) {
            for (ClaimGroup g : groups) {
                if (!g.ownedBy(owner)) continue;
                if (newNorm.equalsIgnoreCase(g.name) && !oldNorm.equalsIgnoreCase(g.name)) return false;
            }

            ClaimGroup target = null;
            for (ClaimGroup g : groups) {
                if (g.ownedBy(owner) && oldNorm.equalsIgnoreCase(g.name)) {
                    target = g;
                    break;
                }
            }
            if (target == null) return false;

            target.name = newNorm;
            for (Claim c : claims) {
                if (!c.ownedBy(owner)) continue;
                if (c.group != null && oldNorm.equalsIgnoreCase(c.group)) c.group = newNorm;
            }
            save();
            return true;
        }
    }

    public boolean trustGroup(UUID owner, String groupName, UUID player) {
        String normalized = normalizeGroupName(groupName);
        if (owner == null || normalized == null || player == null) return false;
        synchronized (lock) {
            for (ClaimGroup g : groups) {
                if (!g.ownedBy(owner) || !normalized.equalsIgnoreCase(g.name)) continue;
                if (g.trusted == null) g.trusted = new ArrayList<>();
                if (!g.trusted.contains(player.toString())) g.trusted.add(player.toString());
                save();
                return true;
            }
            return false;
        }
    }

    public int untrustGroups(UUID owner, List<String> groupNames, UUID player) {
        if (owner == null || player == null || groupNames == null || groupNames.isEmpty()) return 0;
        List<String> normalizedNames = new ArrayList<>();
        for (String g : groupNames) {
            String n = normalizeGroupName(g);
            if (n != null) normalizedNames.add(n);
        }
        if (normalizedNames.isEmpty()) return 0;

        int changed = 0;
        synchronized (lock) {
            for (ClaimGroup g : groups) {
                if (!g.ownedBy(owner)) continue;
                if (!normalizedNames.contains(g.name.toLowerCase(Locale.ROOT))) continue;
                if (g.trusted != null && g.trusted.remove(player.toString())) changed++;
            }
            if (changed > 0) save();
        }
        return changed;
    }

    public int trustAllGroups(UUID owner, UUID player) {
        if (owner == null || player == null) return 0;
        int changed = 0;
        synchronized (lock) {
            for (ClaimGroup g : groups) {
                if (!g.ownedBy(owner)) continue;
                if (g.trusted == null) g.trusted = new ArrayList<>();
                if (!g.trusted.contains(player.toString())) {
                    g.trusted.add(player.toString());
                    changed++;
                }
            }
            if (changed > 0) save();
        }
        return changed;
    }

    public boolean trustedViaGroup(Claim claim, UUID player) {
        if (claim == null || player == null || claim.group == null || claim.group.isBlank()) return false;
        synchronized (lock) {
            for (ClaimGroup g : groups) {
                if (!claim.owner.equals(g.owner)) continue;
                if (!claim.group.equalsIgnoreCase(g.name)) continue;
                return g.trusted != null && g.trusted.contains(player.toString());
            }
            return false;
        }
    }

    public static String normalizeId(String raw) {
        if (raw == null) return null;
        String s = raw.trim().toLowerCase(Locale.ROOT);
        if (s.isEmpty()) return null;
        s = s.replace(' ', '-');
        s = s.replaceAll("[^a-z0-9_-]", "");
        if (s.isEmpty()) return null;
        if (s.length() > 32) s = s.substring(0, 32);
        return s;
    }

    private Claim byIdUnsafe(String id) {
        if (id == null || id.isBlank()) return null;
        for (Claim c : claims) {
            if (id.equalsIgnoreCase(c.id)) return c;
        }
        return null;
    }

    public boolean remove(String id) {
        boolean removed;
        synchronized (lock) {
            removed = claims.removeIf(c -> c.id.equalsIgnoreCase(id));
        }
        if (removed) save();
        return removed;
    }

    public boolean trust(String id, UUID player) {
        if (player == null) return false;
        synchronized (lock) {
            for (Claim c : claims) {
                if (!c.id.equalsIgnoreCase(id)) continue;
                if (c.trusted == null) c.trusted = new ArrayList<>();
                if (!c.trusted.contains(player.toString())) c.trusted.add(player.toString());
                save();
                return true;
            }
        }
        return false;
    }

    public boolean untrust(String id, UUID player) {
        if (player == null) return false;
        synchronized (lock) {
            for (Claim c : claims) {
                if (!c.id.equalsIgnoreCase(id)) continue;
                if (c.trusted == null) return false;
                boolean removed = c.trusted.remove(player.toString());
                if (removed) save();
                return removed;
            }
        }
        return false;
    }

    public boolean transfer(String id, UUID newOwner) {
        if (newOwner == null) return false;
        synchronized (lock) {
            for (Claim c : claims) {
                if (!c.id.equalsIgnoreCase(id)) continue;
                c.owner = newOwner.toString();
                if (c.trusted == null) c.trusted = new ArrayList<>();
                c.trusted.remove(newOwner.toString());
                save();
                return true;
            }
        }
        return false;
    }
}
