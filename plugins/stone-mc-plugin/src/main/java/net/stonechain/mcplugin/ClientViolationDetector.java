package net.stonechain.mcplugin;

import org.bukkit.Location;
import org.bukkit.Material;
import org.bukkit.entity.Entity;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.block.BlockBreakEvent;
import org.bukkit.event.entity.EntityDamageByEntityEvent;
import org.bukkit.event.player.PlayerInteractEvent;
import org.bukkit.event.player.PlayerQuitEvent;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

/**
 * Server-seitige Erkennung von Client-Modifikationen.
 *
 *  1. X-ray        – Zwei-Stufen-Erkennung: Sliding-Window (schnell) + Kumulativ
 *  2. Auto-Clicker – CPS zu hoch oder mechanisch-gleichmäßig
 *  3. Reach Hack   – Treffer außerhalb erlaubter Reichweite
 *
 * Kein Bannen – nur Reporting + sofortiges Admin-Log.
 */
public final class ClientViolationDetector implements Listener {

    // ── Ore-Klassifikation ────────────────────────────────────────────────────

    private static final Set<String> HIGH_VALUE_ORES = new HashSet<>(Arrays.asList(
        "DIAMOND_ORE", "DEEPSLATE_DIAMOND_ORE",
        "ANCIENT_DEBRIS",
        "EMERALD_ORE", "DEEPSLATE_EMERALD_ORE"
    ));
    private static final Set<String> MEDIUM_VALUE_ORES = new HashSet<>(Arrays.asList(
        "GOLD_ORE", "DEEPSLATE_GOLD_ORE", "NETHER_GOLD_ORE",
        "LAPIS_ORE", "DEEPSLATE_LAPIS_ORE",
        "REDSTONE_ORE", "DEEPSLATE_REDSTONE_ORE"
    ));
    private static final Set<String> ALL_ORES;
    static {
        ALL_ORES = new HashSet<>(HIGH_VALUE_ORES);
        ALL_ORES.addAll(MEDIUM_VALUE_ORES);
        ALL_ORES.addAll(Arrays.asList(
            "IRON_ORE", "DEEPSLATE_IRON_ORE",
            "COPPER_ORE", "DEEPSLATE_COPPER_ORE",
            "COAL_ORE", "DEEPSLATE_COAL_ORE",
            "NETHER_QUARTZ_ORE"
        ));
    }

    // ── Schwellwerte ──────────────────────────────────────────────────────────

    /**
     * SLIDING-WINDOW: Wie viele der letzten N Blöcke auf X-ray geprüft werden.
     * 2+ High-Value-Erze in diesem Fenster = nahezu unmöglich ohne X-ray.
     */
    private static final int  WINDOW_SIZE               = 20;
    private static final int  WINDOW_HIGH_VALUE_TRIGGER = 2;   // 2 Diamanten in 20 Blöcken → Flag

    /**
     * KUMULATIVER CHECK: Erzrate über die gesamte Session.
     * Natürliche Rate: ~1.7 / 1000 Blöcke. Grenzwert: 10× natürlich.
     */
    private static final double CUMULATIVE_RATE_ALERT   = 17.0;  // per 1000 Blöcke
    private static final int    CUMULATIVE_MIN_BLOCKS   = 30;    // erst ab 30 Blöcken prüfen

    /** Session-Timeout (Inaktivität zurücksetzen). */
    private static final long SESSION_TIMEOUT_MS = 3 * 60 * 1000L;

    /** Maximale CPS (Clicks per Second). Mensch: ≤14, Butterfly: ≤18. */
    private static final int    CPS_ALERT_THRESHOLD     = 20;

    /** Maximale Reichweite in Survival. */
    private static final double REACH_MAX_BLOCKS        = 4.5;
    private static final int    REACH_VIOLATIONS_WIN    = 3;   // in 10s

    // ── Interne Session-Klassen ───────────────────────────────────────────────

    static final class MiningSession {
        long lastActivity = System.currentTimeMillis();
        long sessionStart = lastActivity;

        // Sliding Window (letzte WINDOW_SIZE Blöcke)
        final Deque<Boolean> window = new ArrayDeque<>(WINDOW_SIZE + 1); // true = highValue ore
        int windowHighCount;   // Anzahl High-Value-Erze im Fenster

        // Kumulativer Tracker
        int blocksBroken;
        double cumulativeOreScore;
        int totalHighValueOres;

        // Pfad für Geraden-Erkennung
        final Deque<int[]> recentPath = new ArrayDeque<>(30);
        int straightLineCount;
        int[] lastDelta;
    }

    static final class ClickSession {
        final Deque<Long> timestamps = new ArrayDeque<>(120);
        double intervalVariance;
    }

    static final class ReachSession {
        final Deque<Long> violations = new ArrayDeque<>(20);
    }

    // ── Violation ─────────────────────────────────────────────────────────────

    public static final class Violation {
        public enum Type { XRAY, AUTO_CLICKER, REACH_HACK }

        public final Type   type;
        public final UUID   playerId;
        public final String playerName;
        public final double confidence;
        public final String details;
        public final long   timestamp;

        Violation(Type type, UUID id, String name, double conf, String details) {
            this.type = type; this.playerId = id; this.playerName = name;
            this.confidence = conf; this.details = details;
            this.timestamp = System.currentTimeMillis() / 1000L;
        }

        @Override public String toString() {
            return String.format("[%s] %s (%.0f%%) – %s", type, playerName, confidence * 100, details);
        }
    }

    // ── Fields ────────────────────────────────────────────────────────────────

    private final StoneMcPlugin plugin;
    private final Logger log;
    private final Map<UUID, MiningSession> miningSessions  = new ConcurrentHashMap<>();
    private final Map<UUID, ClickSession>  clickSessions   = new ConcurrentHashMap<>();
    private final Map<UUID, ReachSession>  reachSessions   = new ConcurrentHashMap<>();
    private final List<Violation>          pendingViolations = Collections.synchronizedList(new ArrayList<>());
    // Cooldown pro Spieler+Typ damit kein Spam entsteht
    private final Map<String, Long>        violationCooldowns = new ConcurrentHashMap<>();

    public ClientViolationDetector(StoneMcPlugin plugin) {
        this.plugin = plugin;
        this.log    = plugin.getLogger();
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  1. X-RAY – ZWEI-STUFEN-ERKENNUNG
    // ══════════════════════════════════════════════════════════════════════════

    public void trackBlockBreak(Player player, Material material) {
        if (player.getGameMode().name().equals("CREATIVE")) return;

        MiningSession s = miningSessions.computeIfAbsent(player.getUniqueId(), k -> new MiningSession());

        long now = System.currentTimeMillis();
        if (now - s.lastActivity > SESSION_TIMEOUT_MS) resetSession(s, now);
        s.lastActivity = now;
        s.blocksBroken++;

        boolean isHighValue  = HIGH_VALUE_ORES.contains(material.name());
        boolean isMediumValue = MEDIUM_VALUE_ORES.contains(material.name());

        // ── Kumulativer Score ─────────────────────────────────────────────
        if (isHighValue)   { s.cumulativeOreScore += 100.0; s.totalHighValueOres++; }
        else if (isMediumValue) { s.cumulativeOreScore += 20.0; }

        // ── Sliding Window pflegen ────────────────────────────────────────
        if (s.window.size() >= WINDOW_SIZE) {
            Boolean removed = s.window.pollFirst();
            if (Boolean.TRUE.equals(removed)) s.windowHighCount--;
        }
        s.window.addLast(isHighValue);
        if (isHighValue) s.windowHighCount++;

        // ── Pfad für Geraden-Erkennung ────────────────────────────────────
        Location loc = player.getLocation();
        int[] pos = {loc.getBlockX(), loc.getBlockY(), loc.getBlockZ()};
        if (s.recentPath.size() >= 30) s.recentPath.pollFirst();
        s.recentPath.addLast(pos);
        updateStraightLine(s, pos);

        // Debug-Log wenn ein High-Value-Erz gefunden wurde
        if (isHighValue) {
            log.info(String.format(
                "[watchdog-debug] %s brach %s | windowHV=%d/%d | cumOreScore=%.0f/block=%.3f | totalHV=%d",
                player.getName(), material.name(),
                s.windowHighCount, s.window.size(),
                s.cumulativeOreScore,
                s.blocksBroken > 0 ? s.cumulativeOreScore / s.blocksBroken : 0,
                s.totalHighValueOres
            ));
        }

        // ── STUFE 1: Sliding-Window-Check (sofort, ohne Minimum) ──────────
        checkXrayWindow(player, s);

        // ── STUFE 2: Kumulativer Rate-Check (ab 30 Blöcken) ──────────────
        if (s.blocksBroken >= CUMULATIVE_MIN_BLOCKS) {
            checkXrayCumulative(player, s);
        }
    }

    /** STUFE 1: Sofort-Erkennung – 2+ High-Value-Erze im Sliding-Window. */
    private void checkXrayWindow(Player player, MiningSession s) {
        if (s.windowHighCount < WINDOW_HIGH_VALUE_TRIGGER) return;

        // Natürliche Wahrscheinlichkeit 2+ Diamanten in 20 Blöcken ≈ 0.05%
        // Bei X-ray: routinemäßig
        double confidence = Math.min(1.0, 0.8 + (s.windowHighCount - WINDOW_HIGH_VALUE_TRIGGER) * 0.1);

        // Durch gerade Tunnel weiter verstärkt
        if (s.straightLineCount >= 8 && s.totalHighValueOres >= 2) {
            confidence = Math.min(1.0, confidence + 0.1);
        }

        String details = String.format(
            "WINDOW: %d HighValue-Erze in letzten %d Blöcken | gerade=%d | gesamt-HV=%d",
            s.windowHighCount, s.window.size(), s.straightLineCount, s.totalHighValueOres
        );
        flagXray(player, s, confidence, details, "window");
    }

    /** STUFE 2: Kumulativer Rate-Check über die gesamte Session. */
    private void checkXrayCumulative(Player player, MiningSession s) {
        double ratePer1000 = (s.cumulativeOreScore / s.blocksBroken) * 1000.0;
        if (ratePer1000 < CUMULATIVE_RATE_ALERT) return;

        // Confidence: linear von Alert-Wert zu 5×Alert = 100%
        double confidence = Math.min(1.0, (ratePer1000 - CUMULATIVE_RATE_ALERT) / (CUMULATIVE_RATE_ALERT * 4));
        if (s.straightLineCount >= 10) confidence = Math.min(1.0, confidence + 0.15);

        String details = String.format(
            "CUMUL: rate=%.1f/1000 (natürlich≈1.7) | blocks=%d | HV=%d | gerade=%d",
            ratePer1000, s.blocksBroken, s.totalHighValueOres, s.straightLineCount
        );
        flagXray(player, s, confidence, details, "cumul");
    }

    private void flagXray(Player player, MiningSession s, double confidence, String details, String source) {
        String cdKey = player.getUniqueId() + ":XRAY:" + source;
        long now = System.currentTimeMillis();
        Long last = violationCooldowns.get(cdKey);
        if (last != null && now - last < 90_000) return;  // 90s Cooldown pro Quelle
        violationCooldowns.put(cdKey, now);

        addViolation(player, new Violation(Violation.Type.XRAY, player.getUniqueId(), player.getName(), confidence, details));
    }

    // ── Session-Reset ─────────────────────────────────────────────────────────

    private void resetSession(MiningSession s, long now) {
        s.blocksBroken = 0;
        s.cumulativeOreScore = 0;
        s.totalHighValueOres = 0;
        s.window.clear();
        s.windowHighCount = 0;
        s.recentPath.clear();
        s.straightLineCount = 0;
        s.lastDelta = null;
        s.sessionStart = now;
    }

    // ── Gerade-Tunnel-Erkennung ───────────────────────────────────────────────

    private void updateStraightLine(MiningSession s, int[] pos) {
        if (s.recentPath.size() < 2) return;
        // Zweitletztes Element: alles außer dem zuletzt hinzugefügten (pos wurde bereits addLast)
        Iterator<int[]> it = s.recentPath.descendingIterator();
        it.next(); // letztes = gerade hinzugefügtes pos
        int[] prev = it.next();
        int[] delta = {pos[0] - prev[0], pos[1] - prev[1], pos[2] - prev[2]};
        int[] norm = {Integer.compare(delta[0], 0), Integer.compare(delta[1], 0), Integer.compare(delta[2], 0)};
        if (s.lastDelta != null && Arrays.equals(norm, s.lastDelta)) s.straightLineCount++;
        else s.straightLineCount = 1;
        s.lastDelta = norm;
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  2. AUTO-CLICKER
    // ══════════════════════════════════════════════════════════════════════════

    @EventHandler(priority = EventPriority.MONITOR)
    public void onInteract(PlayerInteractEvent event) {
        if (event.getAction().name().startsWith("LEFT_CLICK")) trackClick(event.getPlayer());
    }

    public void trackClick(Player player) {
        if (player.getGameMode().name().equals("CREATIVE")) return;
        ClickSession s = clickSessions.computeIfAbsent(player.getUniqueId(), k -> new ClickSession());
        long now = System.currentTimeMillis();
        while (!s.timestamps.isEmpty() && now - s.timestamps.peekFirst() > 5000) s.timestamps.pollFirst();
        s.timestamps.addLast(now);
        if (s.timestamps.size() < 10) return;

        int cps = s.timestamps.size() / 5;
        long[] intervals = computeIntervals(s.timestamps);
        s.intervalVariance = computeVariance(intervals);

        if (cps > CPS_ALERT_THRESHOLD) {
            double conf = Math.min(1.0, (cps - CPS_ALERT_THRESHOLD) / 10.0);
            String detail = String.format("cps=%d var=%.1fms", cps, Math.sqrt(s.intervalVariance));
            addViolationWithCooldown(player, Violation.Type.AUTO_CLICKER, conf, detail, 60_000);
            return;
        }
        if (cps >= 14 && s.intervalVariance < 400.0) {
            double conf = Math.min(1.0, (1.0 - s.intervalVariance / 400.0) * 0.85);
            if (conf > 0.4) {
                String detail = String.format("cps=%d var=%.1fms (mechanisch)", cps, Math.sqrt(s.intervalVariance));
                addViolationWithCooldown(player, Violation.Type.AUTO_CLICKER, conf, detail, 60_000);
            }
        }
    }

    private long[] computeIntervals(Deque<Long> ts) {
        Long[] arr = ts.toArray(new Long[0]);
        long[] iv = new long[arr.length - 1];
        for (int i = 1; i < arr.length; i++) iv[i-1] = arr[i] - arr[i-1];
        return iv;
    }

    private double computeVariance(long[] iv) {
        if (iv.length == 0) return 0;
        double mean = Arrays.stream(iv).average().orElse(0);
        double sum = 0;
        for (long v : iv) sum += (v - mean) * (v - mean);
        return sum / iv.length;
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  3. REACH HACK
    // ══════════════════════════════════════════════════════════════════════════

    @EventHandler(priority = EventPriority.MONITOR, ignoreCancelled = true)
    public void onEntityDamage(EntityDamageByEntityEvent event) {
        if (!(event.getDamager() instanceof Player attacker)) return;
        if (attacker.getGameMode().name().equals("CREATIVE")) return;
        Entity target = event.getEntity();
        double dist = attacker.getLocation().distance(target.getLocation());
        if (dist <= REACH_MAX_BLOCKS) return;

        ReachSession s = reachSessions.computeIfAbsent(attacker.getUniqueId(), k -> new ReachSession());
        long now = System.currentTimeMillis();
        while (!s.violations.isEmpty() && now - s.violations.peekFirst() > 10_000) s.violations.pollFirst();
        s.violations.addLast(now);

        if (s.violations.size() >= REACH_VIOLATIONS_WIN) {
            double conf = Math.min(1.0, (dist - REACH_MAX_BLOCKS) / 3.0);
            String detail = String.format("dist=%.2f max=%.1f count=%d/10s", dist, REACH_MAX_BLOCKS, s.violations.size());
            addViolationWithCooldown(attacker, Violation.Type.REACH_HACK, conf, detail, 30_000);
            s.violations.clear();
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Violation-Management
    // ══════════════════════════════════════════════════════════════════════════

    private void addViolationWithCooldown(Player player, Violation.Type type, double conf, String detail, long cooldownMs) {
        String cdKey = player.getUniqueId() + ":" + type.name();
        long now = System.currentTimeMillis();
        Long last = violationCooldowns.get(cdKey);
        if (last != null && now - last < cooldownMs) return;
        violationCooldowns.put(cdKey, now);
        addViolation(player, new Violation(type, player.getUniqueId(), player.getName(), conf, detail));
    }

    private void addViolation(Player player, Violation v) {
        pendingViolations.add(v);

        // Sofortiges Server-Log
        String level = v.confidence >= 0.75 ? "🚨 HIGH" : v.confidence >= 0.4 ? "⚠ MED" : "ℹ LOW";
        log.warning(String.format("[WATCHDOG] %s %s", level, v));

        // In-Game-Nachricht an Admins/Ops (sofort, nicht nach Batch)
        String prefix = v.confidence >= 0.75 ? "§c[WATCHDOG]" : v.confidence >= 0.4 ? "§e[WATCHDOG]" : "§7[WATCHDOG]";
        String msg = prefix + " §f" + v;
        plugin.getServer().getScheduler().runTask(plugin, () ->
            plugin.getServer().getOnlinePlayers().stream()
                .filter(p -> p.isOp() || p.hasPermission("stonechain.watchdog"))
                .forEach(op -> op.sendMessage(msg))
        );
    }

    public List<Violation> drainPending() {
        synchronized (pendingViolations) {
            List<Violation> copy = new ArrayList<>(pendingViolations);
            pendingViolations.clear();
            return copy;
        }
    }

    @EventHandler
    public void onQuit(PlayerQuitEvent event) {
        UUID id = event.getPlayer().getUniqueId();
        miningSessions.remove(id);
        clickSessions.remove(id);
        reachSessions.remove(id);
        // Cooldowns bleiben für 5 Minuten im Speicher (für Reconnect-Spam-Schutz)
    }
}
