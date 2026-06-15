package net.stonechain.mcplugin;

import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.configuration.ConfigurationSection;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.plugin.java.JavaPlugin;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.logging.Level;

/**
 * Proof-of-Play MVP plugin: random STONE drops on block-break, /stoneredeem to
 * convert local pending balance to on-chain STONE via the Stonechain node.
 *
 * Anti-cheat is intentionally NOT in this MVP — caps and cooldowns are
 * enforced server-side on the Stonechain node.
 */
public final class StoneMcPlugin extends JavaPlugin {

    private static final Pattern HEX64 = Pattern.compile("^[0-9a-fA-F]{64}$");
    // Bech32 data charset (lowercase), excludes 0,1,b,i,o.
    private static final Pattern STONE1 = Pattern.compile("^stone1[023456789acdefghjklmnpqrstuvwxyz]{20,120}$");

    private NodeLauncher nodeLauncher;
    private NodeClient nodeClient;
    private String gameId;
    private PlayerWalletStore walletStore;
    private PersonalVaultStore vaultStore;
    public PlayerWalletStore wallets() { return walletStore; }
    public PersonalVaultStore vaultStore() { return vaultStore; }
    public ScoreboardManager scoreboard() { return scoreboard; }
    public NodeClient nodeClient() { return nodeClient; }
    private DropConfig dropConfig;
    private ScoreboardManager scoreboard;
    private ShopStore shopStore;
    public ShopStore shopStore() { return shopStore; }
    private ClaimStore claimStore;
    private ClaimManager claimManager;
    public ClaimManager claimManager() { return claimManager; }
    private RareBlockStore rareBlockStore;
    private RareBlockListener rareBlockListener;
    public RareBlockListener rareBlocks() { return rareBlockListener; }
    private ShardLedger shardLedger;
    public ShardLedger shardLedger() { return shardLedger; }
    private LightP2pNode lightNode;
    public LightP2pNode lightNode() { return lightNode; }
    private ProofOfClientHash proofOfClientHash;
    private ClientViolationDetector violationDetector;
    private PopMiner popMiner;
    public PopMiner popMiner() { return popMiner; }
    private double autoRedeemThreshold;
    /** PoolCoin Counter: game_id → player UUID → coin count. Bei 20 → Auto-Sell. */
    private final java.util.Map<String, java.util.Map<java.util.UUID, Integer>> poolCoinCounters = new java.util.concurrent.ConcurrentHashMap<>();
    private int autoSellThreshold = 20;
    public int autoSellThreshold() { return autoSellThreshold; }
    private final java.util.Set<java.util.UUID> redeemInFlight = java.util.concurrent.ConcurrentHashMap.newKeySet();
    // Redeem limits
    private double redeemMaxCoins   = 5.0;
    private String redeemLimitMode  = "per_day"; // per_day | per_transaction | total

    @Override
    public void onEnable() {
        saveDefaultConfig();

        // ── Auto-Start des Stone-Nodes (Zero-Config für Server-Betreiber) ──
        FileConfiguration initialCfg = getConfig();
        boolean autoStartNode = initialCfg.getBoolean("auto_start_node", true);
        if (autoStartNode) {
            this.nodeLauncher = new NodeLauncher(getDataFolder(), getLogger());
            boolean started = nodeLauncher.start();
            if (!started) {
                getLogger().warning("Stone-Node Auto-Start fehlgeschlagen. "
                    + "Plugin versucht trotzdem via HTTP zu verbinden (falls Node manuell läuft).");
            }
        }
        // Auto-merge: add any missing keys from the bundled default config.yml
        FileConfiguration cfg = getConfig();
        cfg.options().copyDefaults(true);
        saveConfig();
        reloadConfig();
        cfg = getConfig();

        String nodeUrl = cfg.getString("node_url", "http://127.0.0.1:3080");
        String gameId  = cfg.getString("game_id", "minecraft-pop-mvp");

        if (nodeUrl != null && nodeUrl.contains(":8080")) {
            getLogger().warning(
                "node_url nutzt Port 8080. In der aktuellen Stone-Server-Konfiguration läuft die SDK-API typischerweise auf 3080. "
                + "Prüfe plugins/StoneMC/config.yml auf den richtigen Port."
            );
        }

        // SDK key: env var wins over config (config may be empty in production).
        String sdkKey = System.getenv("STONE_GAME_API_KEY");
        boolean sdkKeyFromEnv = sdkKey != null && !sdkKey.isBlank();
        if (!sdkKeyFromEnv) {
            sdkKey = cfg.getString("game_api_key", "");
        }
        if (sdkKey.isBlank()) {
            getLogger().log(Level.SEVERE,
                "Kein game_api_key gesetzt (config oder STONE_GAME_API_KEY). Plugin deaktiviert.");
            getServer().getPluginManager().disablePlugin(this);
            return;
        }
        if ("sk_your_game_api_key_here".equalsIgnoreCase(sdkKey.trim())) {
            getLogger().log(Level.SEVERE,
                "game_api_key ist noch Platzhalterwert (sk_your_game_api_key_here). Plugin deaktiviert.");
            getServer().getPluginManager().disablePlugin(this);
            return;
        }

        int connectTimeout = cfg.getInt("http.connect_timeout_ms", 3000);
        int requestTimeout = cfg.getInt("http.request_timeout_ms", 7000);

        // Multi-Node Client: wenn ein Node ausfällt, wird automatisch der nächste probiert
        List<String> playDropNodes = cfg.getStringList("p2p_node.bootstrap_nodes");
        if (playDropNodes == null || playDropNodes.isEmpty()) {
            playDropNodes = new ArrayList<>();
            playDropNodes.add(nodeUrl);
        }
        this.nodeClient = new NodeClient(playDropNodes, gameId, sdkKey, connectTimeout, requestTimeout, getLogger());
        this.gameId = gameId;
        this.walletStore = new PlayerWalletStore(getDataFolder());
        this.walletStore.load();
        this.vaultStore = new PersonalVaultStore(getDataFolder(), getLogger());
        this.vaultStore.load();

        Map<String, Double> tiers = loadTiers(cfg);
        if (tiers.isEmpty()) {
            getLogger().warning("drops.tiers ist leer — keine Blöcke geben STONE.");
        }
        Map<String, Double> mobTiers = loadMobTiers(cfg);
        this.dropConfig = new DropConfig(
            cfg.getDouble("drops.chance", 0.02),
            tiers,
            cfg.getInt("drops.player_cooldown_secs", 5)
        );

        this.scoreboard = new ScoreboardManager(
            cfg.getBoolean("scoreboard.enabled", true),
            cfg.getString("scoreboard.title", "§6§lStone-Coins"),
            walletStore
        );

        this.autoRedeemThreshold = cfg.getDouble("auto_redeem.threshold", 0.0);
        this.redeemMaxCoins  = cfg.getDouble("redeem.max_coins", 5.0);
        this.redeemLimitMode = cfg.getString("redeem.limit_mode", "per_day");

        this.violationDetector = new ClientViolationDetector(this);
        getServer().getPluginManager().registerEvents(violationDetector, this);

        getServer().getPluginManager().registerEvents(
            new BlockBreakDropListener(this, dropConfig, nodeClient, walletStore, scoreboard, violationDetector),
            this
        );
        if (!mobTiers.isEmpty()) {
            double mobChance = cfg.getDouble("mobs.chance", dropConfig.chance());
            int mobCooldown = cfg.getInt("mobs.player_cooldown_secs", dropConfig.cooldownSecs());
            getServer().getPluginManager().registerEvents(
                new MobKillDropListener(this, mobTiers, mobChance, mobCooldown, walletStore, scoreboard),
                this
            );
        }
        getServer().getPluginManager().registerEvents(new JoinQuitListener(), this);

        // Periodic anti-dupe scan for all online players.
        long intervalTicks = cfg.getLong("anti_dupe.scan_interval_seconds", 120L) * 20L;
        if (intervalTicks > 0L) {
            getServer().getScheduler().runTaskTimer(this, () -> {
                for (Player online : getServer().getOnlinePlayers()) {
                    validateInventoryAntiDupe(online, true);
                }
            }, intervalTicks, intervalTicks);
        }

        // Falls das Plugin bei laufendem Server (re)geladen wird, aktive Spieler ausstatten.
        for (Player p : getServer().getOnlinePlayers()) {
            ensureMenuScroll(p);
        }

        // Shards & Coins
        StoneShard.init(this);
        StoneCoin.init(this);
        StoneMenuScroll.init(this);
        RareBlock.init(this, cfg.getString("rare_block.material", "CRYING_OBSIDIAN"));
        this.shardLedger = new ShardLedger(getDataFolder(), getLogger());
        this.shardLedger.load();
        SoulboundCoinHandler soulbound = new SoulboundCoinHandler(this);
        soulbound.registerRecipe();
        getServer().getPluginManager().registerEvents(soulbound, this);
        getServer().getPluginManager().registerEvents(new StoneMenu.ClickListener(this), this);
        getServer().getPluginManager().registerEvents(new StoneMenuScrollListener(this), this);
        getServer().getPluginManager().registerEvents(new PersonalVault.ClickListener(this), this);

        // Shop
        this.shopStore = new ShopStore(getDataFolder());
        this.shopStore.load();
        ShopMenu.init(this);
        getServer().getPluginManager().registerEvents(new ShopMenu.ClickListener(this), this);

        // Claims
        this.claimStore = new ClaimStore(getDataFolder());
        this.claimStore.load();
        this.claimManager = new ClaimManager(this, claimStore);
        getServer().getPluginManager().registerEvents(claimManager, this);

        // Rare block
        this.rareBlockStore = new RareBlockStore(getDataFolder());
        this.rareBlockStore.load();
        this.rareBlockListener = new RareBlockListener(this, rareBlockStore);
        getServer().getPluginManager().registerEvents(rareBlockListener, this);

        // ── Periodischer Config-Upload (alle 6 Stunden) ──
        long configUploadTicks = 6L * 3600L * 20L; // 6h in Minecraft-Ticks
        getServer().getScheduler().runTaskTimerAsynchronously(this, this::uploadConfigToNode,
            configUploadTicks, configUploadTicks);

        // ── Verified Server Heartbeat (alle 30s) ─────────────────────────
        long heartbeatIntervalTicks = 30L * 20L; // 30 Minecraft-Ticks ≈ 30s
        getServer().getScheduler().runTaskTimerAsynchronously(this, () -> {
            try {
                String ip = getServer().getIp();
                if (ip == null || ip.isBlank()) ip = "0.0.0.0";
                int port = getServer().getPort();
                int online = getServer().getOnlinePlayers().size();
                int max = getServer().getMaxPlayers();
                String motd = getServer().getMotd();
                if (motd == null) motd = "";
                nodeClient.reportServerInfo(ip, port, online, max, motd);
            } catch (Exception ignored) {
                // silently ignore heartbeat errors
            }
        }, heartbeatIntervalTicks, heartbeatIntervalTicks);

        // ── libp2p-lite: Echter P2P-Teilnehmer ──────────────────────────
        if (cfg.getBoolean("p2p_node.enabled", true)) {
            List<String> bootstrapNodes = cfg.getStringList("p2p_node.bootstrap_nodes");
            if (bootstrapNodes == null || bootstrapNodes.isEmpty()) {
                // Fallback: single bootstrap_url + node_url
                bootstrapNodes = new ArrayList<>();
                String single = cfg.getString("p2p_node.bootstrap_url",
                    cfg.getString("node_url", "http://127.0.0.1:3080"));
                if (single != null && !single.isBlank()) {
                    bootstrapNodes.add(single);
                }
            }
            int cpuLimit = cfg.getInt("p2p_node.resource_limits.cpu_percent", 10);
            int ramLimit = cfg.getInt("p2p_node.resource_limits.ram_mb", 64);
            int netLimit = cfg.getInt("p2p_node.resource_limits.network_kbps", 256);

            this.lightNode = new LightP2pNode(bootstrapNodes, connectTimeout,
                requestTimeout, cpuLimit, ramLimit, netLimit, getLogger());
            lightNode.start();

            getLogger().info("StoneMC libp2p-lite gestartet (peer=" + lightNode.getPeerId()
                + " bootstrap=" + bootstrapNodes.size() + ")");
        }

        getLogger().info("StoneMC enabled. node=" + nodeUrl + " game_id=" + gameId
            + " block_tiers=" + tiers.size() + " mob_tiers=" + mobTiers.size()
            + " auto_redeem=" + (autoRedeemThreshold > 0 ? autoRedeemThreshold : "off"));
        getLogger().info("StoneMC auth mode: X-SDK-Key (source=" + (sdkKeyFromEnv ? "env:STONE_GAME_API_KEY" : "config:game_api_key") + ")");
        String keyPreview = sdkKey.length() > 10 ? (sdkKey.substring(0, 10) + "...") : "(short)";
        getLogger().info("StoneMC effective sdk key preview: " + keyPreview);

        // ── Proof-of-Client-Hash Watchdog ────────────────────────────────
        final String proofGameId = gameId;
        this.proofOfClientHash = new ProofOfClientHash(getDataFolder(), getLogger());
        getServer().getScheduler().runTaskAsynchronously(this, () -> {
            try {
                proofOfClientHash.init();
                sendClientProof(proofGameId);
            } catch (Exception e) {
                getLogger().warning("[watchdog] Init fehlgeschlagen: " + e.getMessage());
            }
        });
        // Periodische Re-Verifikation alle 10 Minuten (20 Ticks/s * 60s * 10)
        getServer().getScheduler().runTaskTimerAsynchronously(this, () -> {
            try {
                sendClientProof(proofGameId);
            } catch (Exception e) {
                getLogger().warning("[watchdog] Proof fehlgeschlagen: " + e.getMessage());
            }
        }, 20L * 60 * 10, 20L * 60 * 10);

        // Violation-Batch alle 30 Sekunden an Node senden
        getServer().getScheduler().runTaskTimerAsynchronously(this, () -> {
            if (violationDetector == null || nodeClient == null) return;
            java.util.List<ClientViolationDetector.Violation> batch = violationDetector.drainPending();
            if (!batch.isEmpty()) {
                nodeClient.submitViolationBatch(proofGameId, batch);
            }
        }, 20L * 30, 20L * 30);

        // ── Proof-of-Play Mining ─────────────────────────────────────────────
        // PopMiner is initialized once proofOfClientHash is ready (runs async).
        // Challenge refresh every 60 s, activity tracked per block/mob event.
        getServer().getScheduler().runTaskLaterAsynchronously(this, () -> {
            try {
                if (proofOfClientHash == null) return;
                this.popMiner = new PopMiner(this, nodeClient, proofOfClientHash);
                popMiner.refreshChallenge();
                getLogger().info("[pop-mining] Proof-of-Play Mining gestartet.");
            } catch (Exception e) {
                getLogger().warning("[pop-mining] Init fehlgeschlagen: " + e.getMessage());
            }
        }, 20L * 15); // wait 15 s for proof key to be ready

        // Refresh challenge every 60 s (once per slot)
        getServer().getScheduler().runTaskTimerAsynchronously(this, () -> {
            if (popMiner != null) popMiner.refreshChallenge();
        }, 20L * 60, 20L * 60);

        // ── Connectivity Check: alle Bootstrap-Nodes testen ─────────────
        getServer().getScheduler().runTaskAsynchronously(this, () -> {
            getLogger().info("[connectivity] Testing " + nodeClient.baseUrls.size()
                + " bootstrap node(s) via HTTP API (port 3080)...");
            for (String url : nodeClient.baseUrls) {
                String healthUrl = url + "/api/v1/health";
                try {
                    var req = java.net.http.HttpRequest.newBuilder(java.net.URI.create(healthUrl))
                        .timeout(java.time.Duration.ofSeconds(3)).GET().build();
                    var res = java.net.http.HttpClient.newHttpClient()
                        .send(req, java.net.http.HttpResponse.BodyHandlers.ofString());
                    if (res.statusCode() == 200) {
                        var json = com.google.gson.JsonParser.parseString(res.body()).getAsJsonObject();
                        getLogger().info("[connectivity] ✓ " + url
                            + " → height=" + json.get("block_height").getAsLong()
                            + " node=" + json.get("node_id").getAsString());
                    } else {
                        getLogger().warning("[connectivity] ✗ " + url + " → HTTP " + res.statusCode());
                    }
                } catch (Exception e) {
                    getLogger().warning("[connectivity] ✗ " + url + " → " + e.getClass().getSimpleName()
                        + ": " + e.getMessage());
                }
            }
        });

        getServer().getScheduler().runTaskAsynchronously(this, () -> {
            NodeClient.AuthCheckResult auth = nodeClient.checkDeveloperAuth();
            if (auth.ok) {
                getLogger().info("StoneMC SDK auth check OK (dashboard). node=" + nodeUrl + " game_id=" + gameId);
            } else {
                getLogger().warning(
                    "StoneMC SDK auth check FAILED (dashboard): http=" + auth.httpStatus
                    + " error=" + (auth.error == null ? "n/a" : auth.error)
                    + " source=" + (sdkKeyFromEnv ? "env:STONE_GAME_API_KEY" : "config:game_api_key")
                    + " node=" + nodeUrl + " game_id=" + gameId
                );
            }
        });
    }

    private void sendClientProof(String proofGameId) {
        if (proofOfClientHash == null || nodeClient == null) return;
        try {
            ProofOfClientHash.ClientProofPayload payload = proofOfClientHash.buildProof(proofGameId);

            // Flags immer lokal loggen – so sieht man genau was erkannt wurde
            if (!payload.suspiciousFlags.isEmpty()) {
                getLogger().warning("[watchdog] Verdächtige Flags erkannt: " + payload.suspiciousFlags);
            } else {
                getLogger().fine("[watchdog] Keine verdächtigen Flags.");
            }

            NodeClient.ClientProofResult result = nodeClient.submitClientProof(payload);
            if (!result.ok) {
                getLogger().warning("[watchdog] Proof ABGELEHNT: trust=" + result.trustLevel
                    + " reason=" + (result.error != null ? result.error : "unbekannt")
                    + " flags=" + payload.suspiciousFlags);
            } else if ("reduced".equals(result.trustLevel)) {
                getLogger().warning("[watchdog] Trust REDUCED – Flags: " + payload.suspiciousFlags);
            } else {
                getLogger().info("[watchdog] Proof OK: trust=" + result.trustLevel);
            }
        } catch (Exception e) {
            getLogger().warning("[watchdog] Proof-Fehler: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private static Map<String, Double> loadTiers(FileConfiguration cfg) {
        return readTierSection(cfg, "drops.tiers");
    }

    private static Map<String, Double> loadMobTiers(FileConfiguration cfg) {
        return readTierSection(cfg, "mobs.tiers");
    }

    private static Map<String, Double> readTierSection(FileConfiguration cfg, String path) {
        Map<String, Double> out = new LinkedHashMap<>();
        ConfigurationSection sec = cfg.getConfigurationSection(path);
        if (sec == null) return out;
        for (String key : sec.getKeys(false)) {
            double amount = sec.getDouble(key, 0.0);
            if (amount > 0.0) out.put(key.toUpperCase(), amount);
        }
        return out;
    }

    @Override
    public void onDisable() {
        if (walletStore != null) walletStore.save();
        if (vaultStore != null) vaultStore.save();
        if (claimStore != null) claimStore.save();
        if (rareBlockStore != null) rareBlockStore.save();
        // LightP2pNode sauber stoppen
        if (lightNode != null) {
            lightNode.stop();
        }
        // Stone-Node sauber beenden (wenn via NodeLauncher gestartet)
        if (nodeLauncher != null) {
            nodeLauncher.stop();
        }
        getLogger().info("StoneMC disabled.");
    }

    @Override
    public boolean onCommand(CommandSender sender, Command cmd, String label, String[] args) {
        if (!(sender instanceof Player player)) {
            sender.sendMessage("Nur In-Game.");
            return true;
        }

        try {
            switch (cmd.getName().toLowerCase()) {
                case "stonelink": {
                if (args.length != 1 || !isLikelyWalletAddress(args[0])) {
                    player.sendMessage("Usage: /stonelink <stone1... oder 64-hex-address>");
                    player.sendMessage("§7Hinweis: Ungültige stone1-Formate (z.B. mit '0') werden abgelehnt.");
                    return true;
                }
                walletStore.link(player.getUniqueId(), args[0]);
                walletStore.save();
                scoreboard.refresh(player);
                player.sendMessage("§aWallet verknüpft: " + args[0]);
                return true;
            }
            case "stoneunlink":
            case "sunlink": {
                String old = walletStore.linkedAddress(player.getUniqueId());
                if (old == null || old.isBlank()) {
                    player.sendMessage("§eEs ist keine Wallet verknüpft.");
                    return true;
                }
                walletStore.unlink(player.getUniqueId());
                walletStore.save();
                scoreboard.refresh(player);
                player.sendMessage("§aWallet-Verknüpfung entfernt: §7" + old);
                return true;
            }
            case "stoneboard": {
                boolean shown = scoreboard.toggle(player);
                player.sendMessage(shown ? "§aSidebar an." : "§7Sidebar aus.");
                return true;
            }
            case "stonebalance":
            case "sbalance":
            case "stonestats": {
                double pending  = walletStore.pendingBalance(player.getUniqueId());
                double earned   = walletStore.totalEarned(player.getUniqueId());
                double redeemed = walletStore.totalRedeemed(player.getUniqueId());
                String linked   = walletStore.linkedAddress(player.getUniqueId());
                player.sendMessage("§6§l― Stone-Coins ―");
                player.sendMessage("§ePending:    §f" + fmt(pending)  + " §7STONE");
                player.sendMessage("§eGesammelt:  §f" + fmt(earned)   + " §7STONE §8(lifetime)");
                player.sendMessage("§eEingelöst:  §f" + fmt(redeemed) + " §7STONE §8(on-chain)");
                player.sendMessage("§eWallet:     " + (linked == null ? "§cnicht verknüpft" : "§f" + linked));
                return true;
            }
            case "stonerates":
            case "srate": {
                sendMinecraftFairnessConfig(player);
                return true;
            }
            case "stoneredeem":
            case "redeem":
            case "sredeem": {
                // Syntax: /stoneredeem [amount] [wallet]
                //         /stoneredeem [wallet]
                //         /stoneredeem            → redeems up to limit
                double requestedAmount = -1; // -1 = "all available up to limit"
                String explicitWallet  = null;

                if (args.length >= 1) {
                    try {
                        requestedAmount = Double.parseDouble(args[0]);
                        if (args.length >= 2) explicitWallet = args[1];
                    } catch (NumberFormatException nfe) {
                        // first arg is a wallet address
                        explicitWallet = args[0];
                    }
                }

                String target = explicitWallet != null ? explicitWallet
                                                       : walletStore.linkedAddress(player.getUniqueId());
                if (target == null) {
                    player.sendMessage("§cKeine Wallet verknüpft. Erst /stonelink <stone1...> ausführen.");
                    return true;
                }
                if (!isLikelyWalletAddress(target)) {
                    player.sendMessage("§cUngültige Wallet-Adresse: " + target);
                    player.sendMessage("§7Erlaubt: stone1... oder 64-hex.");
                    return true;
                }

                double pending = walletStore.pendingBalance(player.getUniqueId());
                if (pending <= 0.0) {
                    player.sendMessage("§eKeine offenen Drops zum Einlösen.");
                    return true;
                }

                // Compute effective cap based on limit mode
                double effectiveCap = redeemMaxCoins;
                switch (redeemLimitMode) {
                    case "per_day" -> {
                        double todayUsed = walletStore.redeemedToday(player.getUniqueId());
                        double remaining = redeemMaxCoins - todayUsed;
                        if (remaining <= 0) {
                            player.sendMessage("§cTageslimit von §b" + fmt(redeemMaxCoins)
                                + " §cSTONE erreicht. Komme morgen (UTC) wieder.");
                            return true;
                        }
                        effectiveCap = remaining;
                    }
                    case "total" -> {
                        double totalUsed = walletStore.totalRedeemed(player.getUniqueId());
                        double remaining = redeemMaxCoins - totalUsed;
                        if (remaining <= 0) {
                            player.sendMessage("§cGesamtlimit von §b" + fmt(redeemMaxCoins)
                                + " §cSTONE erreicht.");
                            return true;
                        }
                        effectiveCap = remaining;
                    }
                    // "per_transaction" → effectiveCap stays redeemMaxCoins
                }

                double amount = (requestedAmount > 0)
                    ? Math.min(requestedAmount, Math.min(pending, effectiveCap))
                    : Math.min(pending, effectiveCap);

                if (amount <= 0) {
                    player.sendMessage("§eNichts zum Einlösen (Limit oder Guthaben erschöpft).");
                    return true;
                }

                // Show what's left after this redeem if per_day mode
                if (redeemLimitMode.equals("per_day")) {
                    double todayUsed = walletStore.redeemedToday(player.getUniqueId());
                    double afterThis = redeemMaxCoins - todayUsed - amount;
                    player.sendMessage("§7Tageslimit: §b" + fmt(todayUsed + amount) + "§7/§b"
                        + fmt(redeemMaxCoins) + " §7STONE (danach noch §b" + fmt(Math.max(0, afterThis)) + "§7 heute)");
                }

                redeem(player, target, amount, "redeem", true);
                return true;
            }
            case "stonemenu":
            case "smenu": {
                if (args.length >= 1 && args[0].equalsIgnoreCase("item")) {
                    org.bukkit.inventory.ItemStack scroll = StoneMenuScroll.create(player);
                    java.util.Map<Integer, org.bukkit.inventory.ItemStack> overflow = player.getInventory().addItem(scroll);
                    for (org.bukkit.inventory.ItemStack rest : overflow.values()) {
                        player.getWorld().dropItemNaturally(player.getLocation(), rest);
                    }
                    player.sendMessage("§aStone Scroll erhalten. §7Rechtsklick zum Oeffnen des Menues.");
                    return true;
                }
                StoneMenu.open(this, player, walletStore);
                return true;
            }
            case "stoneshop":
            case "shop":
            case "sshop": {
                ShopMenu.open(this, player);
                return true;
            }
            case "stonevault":
            case "svault": {
                PersonalVault.open(this, player);
                return true;
            }
            case "stoneclaim":
            case "sclaim": {
                if (args.length == 0) {
                    claimManager.sendHelp(player);
                    return true;
                }

                if (args.length == 2) {
                    String maybeGroup = args[0].toLowerCase(java.util.Locale.ROOT);
                    java.util.Set<String> reserved = java.util.Set.of(
                        "gui", "map", "visual", "visuel", "view", "preview", "chunks",
                        "list", "info", "trust", "accept", "untrust", "transfer", "remove"
                    );
                    if (!reserved.contains(maybeGroup)) {
                        claimManager.trustGroupOrAll(player, args[0], args[1]);
                        return true;
                    }
                }

                String sub = args[0].toLowerCase(java.util.Locale.ROOT);
                switch (sub) {
                    case "gui", "map" -> claimManager.openChunkMapGui(player);
                    case "visual", "visuel", "view", "preview", "chunks" -> {
                        if (sub.equals("chunks")) {
                            player.sendMessage("§7Chunks werden im Visual-Modus als Grid dargestellt.");
                        }
                        if (args.length >= 2) {
                            String mode = args[1].toLowerCase(java.util.Locale.ROOT);
                            if (mode.equals("claim")) {
                                claimManager.visualizeClaim(player);
                            } else {
                                claimManager.visualizeAllClaims(player);
                            }
                        } else {
                            claimManager.visualizeAllClaims(player);
                        }
                    }
                    case "list" -> claimManager.listClaims(player);
                    case "info" -> claimManager.claimInfo(player);
                    case "trust" -> {
                        if (args.length != 3) {
                            player.sendMessage("§eUsage: /stoneclaim trust <id> <spieler>");
                            return true;
                        }
                        claimManager.trustClaim(player, args[1], args[2]);
                    }
                    case "accept" -> claimManager.acceptTrust(player);
                    case "untrust" -> {
                        if (args.length == 3 && claimManager.store().byId(args[1]) != null) {
                            claimManager.untrustClaim(player, args[1], args[2]);
                            return true;
                        }
                        if (args.length >= 3) {
                            java.util.List<String> groups = java.util.Arrays.asList(java.util.Arrays.copyOfRange(args, 1, args.length - 1));
                            String target = args[args.length - 1];
                            claimManager.untrustGroups(player, groups, target);
                            return true;
                        }
                        if (args.length != 3) {
                            player.sendMessage("§eUsage: /stoneclaim untrust <id> <spieler>");
                            return true;
                        }
                        claimManager.untrustClaim(player, args[1], args[2]);
                    }
                    case "transfer" -> {
                        if (args.length != 3) {
                            player.sendMessage("§eUsage: /stoneclaim transfer <id> <spieler>");
                            return true;
                        }
                        claimManager.transferClaim(player, args[1], args[2]);
                    }
                    case "remove" -> {
                        if (args.length != 2) {
                            player.sendMessage("§eUsage: /stoneclaim remove <id>");
                            return true;
                        }
                        claimManager.removeClaim(player, args[1]);
                    }
                    default -> claimManager.sendHelp(player);
                }
                return true;
            }
            case "stonerareblock":
            case "srare": {
                if (!player.hasPermission("stone.admin")) {
                    player.sendMessage("§cKeine Berechtigung.");
                    return true;
                }
                int amount = 1;
                if (args.length >= 1) {
                    try { amount = Integer.parseInt(args[0]); }
                    catch (NumberFormatException ex) { player.sendMessage("§cUsage: /stonerareblock [amount]"); return true; }
                }
                amount = Math.max(1, Math.min(64, amount));
                org.bukkit.inventory.ItemStack core = RareBlock.create(amount);
                java.util.Map<Integer, org.bukkit.inventory.ItemStack> overflow = player.getInventory().addItem(core);
                for (org.bukkit.inventory.ItemStack rest : overflow.values()) {
                    player.getWorld().dropItemNaturally(player.getLocation(), rest);
                }
                player.sendMessage("§aStone Core x" + amount + " erhalten.");
                return true;
            }
            case "stoneshopadmin": {
                if (!player.hasPermission("stone.admin")) { player.sendMessage("§cKeine Berechtigung."); return true; }
                if (args.length >= 1 && args[0].equalsIgnoreCase("add")) {
                    if (args.length != 2) { player.sendMessage("§eUsage: /stoneshopadmin add <preis_shards>"); return true; }
                    long price; try { price = Long.parseLong(args[1]); } catch (NumberFormatException ex) { player.sendMessage("§cPreis muss Zahl sein."); return true; }
                    if (price <= 0) { player.sendMessage("§cPreis > 0 nötig."); return true; }
                    org.bukkit.inventory.ItemStack hand = player.getInventory().getItemInMainHand();
                    if (hand == null || hand.getType() == org.bukkit.Material.AIR) { player.sendMessage("§cHalte das Item in der Hand."); return true; }
                    if (StoneShard.is(hand) || StoneCoin.is(hand)) { player.sendMessage("§cShards/Coins können nicht verkauft werden."); return true; }
                    ShopStore.Item it = shopStore.add(hand.clone(), price, player.getUniqueId());
                    player.sendMessage("§a✓ §7" + hand.getType().name() + " §aim Shop für §b" + price + " Shards §a(id=" + it.id + ")");
                    return true;
                }
                if (args.length == 2 && args[0].equalsIgnoreCase("remove")) {
                    boolean ok = shopStore.remove(args[1]);
                    player.sendMessage(ok ? "§aEntfernt." : "§cID nicht gefunden.");
                    return true;
                }
                if (args.length >= 1 && args[0].equalsIgnoreCase("list")) {
                    var snap = shopStore.snapshot();
                    player.sendMessage("§6§l― Shop Items (" + snap.size() + ") ―");
                    for (ShopStore.Item it : snap) player.sendMessage("§7" + it.id + " §f" + it.displayName + " §8| §b" + it.priceShards + " Shards");
                    player.sendMessage("§7Hinweis: Shop-Kaeufe sind fee-free; Shards dienen nur als Ingame-Zahlungsmittel.");
                    return true;
                }
                player.sendMessage("§eUsage: /stoneshopadmin <add|remove|list> ...");
                return true;
            }
            case "shopwithdraw": {
                if (!player.hasPermission("stone.admin")) { player.sendMessage("§cKeine Berechtigung."); return true; }
                player.sendMessage("§eShop hat keine Treasury mehr; Shards werden nur als Zahlungsmittel genutzt.");
                return true;
                }
            case "stonedeathprotect":
            case "sdp": {
                if (!player.hasPermission("stone.admin")) {
                    player.sendMessage("§cKeine Berechtigung.");
                    return true;
                }

                if (args.length == 0 || args[0].equalsIgnoreCase("status")) {
                    boolean coins = getConfig().getBoolean("death_protect.coins", true);
                    boolean shards = getConfig().getBoolean("death_protect.shards", true);
                    player.sendMessage("§6Death-Protect Status:");
                    player.sendMessage("§7coins:  " + (coins ? "§aon" : "§coff"));
                    player.sendMessage("§7shards: " + (shards ? "§aon" : "§coff"));
                    return true;
                }

                if (args.length != 2) {
                    player.sendMessage("§eUsage: /stonedeathprotect <coins|shards> <on|off>");
                    player.sendMessage("§eAlias: /sdp <coins|shards> <on|off>");
                    return true;
                }

                String target = args[0].toLowerCase(java.util.Locale.ROOT);
                String toggle = args[1].toLowerCase(java.util.Locale.ROOT);
                if (!target.equals("coins") && !target.equals("shards")) {
                    player.sendMessage("§cErlaubt: coins | shards");
                    return true;
                }
                if (!toggle.equals("on") && !toggle.equals("off")) {
                    player.sendMessage("§cErlaubt: on | off");
                    return true;
                }

                boolean value = toggle.equals("on");
                String key = "death_protect." + target;
                getConfig().set(key, value);
                saveConfig();

                player.sendMessage("§aDeath-Protect " + target + " gesetzt auf: " + (value ? "§aon" : "§coff"));
                getLogger().info("[admin] " + player.getName() + " set " + key + "=" + value);
                return true;
            }
                default:
                    return false;
            }
        } catch (Throwable t) {
            getLogger().log(Level.SEVERE,
                "Command failed: /" + cmd.getName() + " " + String.join(" ", args), t);
            player.sendMessage("§cInterner Plugin-Fehler. Details stehen in der Server-Konsole.");
            return true;
        }
    }

    /**
     * Redeem `amount` STONE to `target` on-chain.
     *
     * @param verbose if true, sends progress + result chat messages to the player
     */
    /** Redeem soulbound coins (already removed from inventory) on-chain. 1 coin = 1 STONE. */
    public void redeemCoins(Player player, String target, int coinCount, String reason) {
        if (coinCount <= 0) return;
        java.util.UUID id = player.getUniqueId();
        if (!redeemInFlight.add(id)) {
            player.sendMessage("§7Redeem läuft bereits — bitte warten.");
            giveCoinsBack(player, coinCount);
            return;
        }
        final double amount = (double) coinCount;
        final String dropId = "coin-redeem-" + id + "-" + System.currentTimeMillis();
        player.sendMessage("§7Sende §b" + coinCount + " Coin(s) §7→ §f" + amount + " STONE §7an " + target + " ...");
        getServer().getScheduler().runTaskAsynchronously(this, () -> {
            NodeClient.DropResult res = nodeClient.submitDrop(target, amount, dropId, reason);
            getServer().getScheduler().runTask(this, () -> {
                try {
                    if (res.ok) {
                        walletStore.markRedeemed(id, amount);
                        walletStore.markCoinsRedeemed(id, coinCount);
                        walletStore.save();
                        String txHint = res.txId == null || res.txId.isBlank()
                            ? "mempool akzeptiert (tx_id folgt nach Block-Commit)"
                            : res.txId;
                        player.sendMessage("§a✓ " + coinCount + " Coin(s) eingelöst → " + fmt(amount) + " STONE. tx_id=" + txHint);
                        if (res.txIdsCsv != null && !res.txIdsCsv.isBlank()) {
                            player.sendMessage("§7tx_ids: §f" + res.txIdsCsv);
                        }
                    } else {
                        giveCoinsBack(player, coinCount);
                        player.sendMessage("§cFehler: " + res.error + " — Coins zurückgegeben.");
                    }
                    scoreboard.refresh(player);
                } finally { redeemInFlight.remove(id); }
            });
        });
    }

    private void giveCoinsBack(Player player, int count) {
        if (count <= 0) return;
        org.bukkit.inventory.ItemStack stack = StoneCoin.create(player, count);
        var leftover = player.getInventory().addItem(stack);
        for (var rest : leftover.values()) player.getWorld().dropItemNaturally(player.getLocation(), rest);
    }

    public void redeem(Player player, String target, double amount, String reason, boolean verbose) {
        java.util.UUID id = player.getUniqueId();
        if (!redeemInFlight.add(id)) {
            if (verbose) player.sendMessage("§7Redeem läuft bereits — bitte warten.");
            return;
        }

        final String dropId = "redeem-" + id + "-" + System.currentTimeMillis();
        walletStore.debit(id, amount);
        walletStore.save();
        scoreboard.refresh(player);
        if (verbose) player.sendMessage("§7Sende " + fmt(amount) + " STONE an " + target + " ...");

        getServer().getScheduler().runTaskAsynchronously(this, () -> {
            NodeClient.DropResult res = nodeClient.submitDrop(target, amount, dropId, reason);
            getServer().getScheduler().runTask(this, () -> {
                try {
                    if (res.ok) {
                        walletStore.markRedeemed(id, amount);
                        walletStore.markRedeemedToday(id, amount);
                        walletStore.save();
                        String txHint = res.txId == null || res.txId.isBlank()
                            ? "mempool akzeptiert (tx_id folgt nach Block-Commit)"
                            : res.txId;
                        player.sendMessage("§a✓ " + fmt(amount) + " STONE eingelöst. tx_id=" + txHint);
                        if (res.txIdsCsv != null && !res.txIdsCsv.isBlank()) {
                            player.sendMessage("§7tx_ids: §f" + res.txIdsCsv);
                        }
                    } else {
                        walletStore.refund(id, amount);
                        walletStore.save();
                        player.sendMessage("§cFehler: " + res.error + " — Drops zurückgebucht.");
                    }
                    scoreboard.refresh(player);
                } finally {
                    redeemInFlight.remove(id);
                }
            });
        });
    }

    /** Trigger an auto-redeem if pending ≥ threshold and a wallet is linked. */
    /** Called by BlockBreakDropListener when a PoolCoin drop happens. Increments counter, triggers auto-sell at threshold. */
    public void onPoolCoinDrop(Player player) {
        java.util.UUID id = player.getUniqueId();
        poolCoinCounters.computeIfAbsent(gameId, k -> new java.util.concurrent.ConcurrentHashMap<>());
        var map = poolCoinCounters.get(gameId);
        int count = map.merge(id, 1, Integer::sum);

        if (count >= autoSellThreshold) {
            map.remove(id); // reset before async call
            String linked = walletStore.linkedAddress(id);
            if (linked == null) {
                player.sendMessage("§e" + autoSellThreshold + " Pool-Coins gesammelt! §7/stonelink <stone1...> um automatisch zu verkaufen.");
                return;
            }
            autoSellCoins(player, linked, count);
        }
    }

    /** Führt einen Auto-Sell von PoolCoins durch (asynchron). */
    private void autoSellCoins(Player player, String target, int coinCount) {
        getServer().getScheduler().runTaskAsynchronously(this, () -> {
            NodeClient.SellResult res = nodeClient.submitSell(target, coinCount, "auto-sell");
            getServer().getScheduler().runTask(this, () -> {
                if (res.ok) {
                    player.sendMessage("§a✓ " + coinCount + " Pool-Coins → §b"
                        + String.format(java.util.Locale.US, "%.4f", res.stoneReceived)
                        + " STONE §a(80% recycled)");
                } else {
                    player.sendMessage("§cAuto-Sell fehlgeschlagen: " + res.error
                        + ". Coins bleiben erhalten.");
                }
            });
        });
    }

    public void maybeAutoRedeem(Player player) {
        if (autoRedeemThreshold <= 0.0) return;
        java.util.UUID id = player.getUniqueId();
        if (redeemInFlight.contains(id)) return;
        double pending = walletStore.pendingBalance(id);
        if (pending < autoRedeemThreshold) return;
        String target = walletStore.linkedAddress(id);
        if (target == null) return;
        redeem(player, target, pending, "auto", false);
    }

    public static double clamp(double v, double lo, double hi) {
        return Math.max(lo, Math.min(hi, v));
    }

    public static String fmt(double v) {
        return String.format(java.util.Locale.US, "%.4f", v);
    }

    private void sendMinecraftFairnessConfig(Player p) {
        var cfg = getConfig();
        p.sendMessage("§6§l― Minecraft Fairness-Parameter ―");
        p.sendMessage("§7drop.chance: §b" + fmt(cfg.getDouble("drops.chance", 0.02)));
        p.sendMessage("§7drop.cooldown_secs: §b" + cfg.getInt("drops.player_cooldown_secs", 5));
        p.sendMessage("§7mob.chance: §b" + fmt(cfg.getDouble("mobs.chance", 0.0)));
        p.sendMessage("§7mob.cooldown_secs: §b" + cfg.getInt("mobs.player_cooldown_secs", 3));
        p.sendMessage("§7redeem.limit_mode: §b" + cfg.getString("redeem.limit_mode", "per_day"));
        p.sendMessage("§7redeem.max_coins: §b" + fmt(cfg.getDouble("redeem.max_coins", 5.0)));
        p.sendMessage("§7anti_dupe.scan_interval_seconds: §b" + cfg.getLong("anti_dupe.scan_interval_seconds", 120L));
        p.sendMessage("§7rare_block.find_chance: §b" + fmt(cfg.getDouble("rare_block.find_chance", 0.0005)));
        p.sendMessage("§7rare_block.shard_reward: §b" + cfg.getInt("rare_block.shard_reward", 32));

        var dropTiers = readTierSection(cfg, "drops.tiers");
        var mobTiers = readTierSection(cfg, "mobs.tiers");
        p.sendMessage("§7drops.tiers.count: §b" + dropTiers.size());
        p.sendMessage("§7mobs.tiers.count: §b" + mobTiers.size());

        if (p.hasPermission("stone.admin")) {
            p.sendMessage("§8-- drops.tiers --");
            for (var e : dropTiers.entrySet()) {
                p.sendMessage("§8" + e.getKey() + "§7 -> §b" + fmt(e.getValue()) + " shards");
            }
            p.sendMessage("§8-- mobs.tiers --");
            for (var e : mobTiers.entrySet()) {
                p.sendMessage("§8" + e.getKey() + "§7 -> §b" + fmt(e.getValue()) + " shards");
            }
        }
    }

    static boolean isLikelyWalletAddress(String s) {
        if (s == null) return false;
        String v = s.trim();
        if (v.isEmpty()) return false;
        return HEX64.matcher(v).matches() || STONE1.matcher(v).matches();
    }

    public record DropConfig(double chance, Map<String, Double> tiers, int cooldownSecs) {}

    /**
     * Baut die aktuelle Plugin-Konfiguration als JSON und sendet sie an den Node.
     * Der Node speichert sie — StoneScan liest sie öffentlich aus.
     */
    private void uploadConfigToNode() {
        var cfg = getConfig();
        var json = new com.google.gson.JsonObject();
        json.addProperty("game_id", gameId);
        json.addProperty("plugin_version", getDescription().getVersion());

        // drops
        var drops = new com.google.gson.JsonObject();
        drops.addProperty("chance", cfg.getDouble("drops.chance", 0.02));
        drops.addProperty("player_cooldown_secs", cfg.getInt("drops.player_cooldown_secs", 5));
        var dropTiers = new com.google.gson.JsonObject();
        for (var e : loadTiers(cfg).entrySet()) {
            dropTiers.addProperty(e.getKey(), e.getValue());
        }
        drops.add("tiers", dropTiers);
        json.add("drops", drops);

        // mobs
        var mobTiersMap = loadMobTiers(cfg);
        if (!mobTiersMap.isEmpty()) {
            var mobs = new com.google.gson.JsonObject();
            mobs.addProperty("chance", cfg.getDouble("mobs.chance", 0.0));
            mobs.addProperty("player_cooldown_secs", cfg.getInt("mobs.player_cooldown_secs", 3));
            var mt = new com.google.gson.JsonObject();
            for (var e : mobTiersMap.entrySet()) {
                mt.addProperty(e.getKey(), e.getValue());
            }
            mobs.add("tiers", mt);
            json.add("mobs", mobs);
        }

        // rare_block
        var rareBlock = new com.google.gson.JsonObject();
        rareBlock.addProperty("enabled", cfg.getBoolean("rare_block.enabled", true));
        rareBlock.addProperty("material", cfg.getString("rare_block.material", "CRYING_OBSIDIAN"));
        rareBlock.addProperty("find_chance", cfg.getDouble("rare_block.find_chance", 0.0005));
        rareBlock.addProperty("drop_cooldown_secs", cfg.getInt("rare_block.drop_cooldown_secs", 15));
        rareBlock.addProperty("shard_reward", cfg.getInt("rare_block.shard_reward", 32));
        json.add("rare_block", rareBlock);

        // redeem
        var redeem = new com.google.gson.JsonObject();
        redeem.addProperty("limit_mode", cfg.getString("redeem.limit_mode", "per_day"));
        redeem.addProperty("max_coins", cfg.getDouble("redeem.max_coins", 5.0));
        json.add("redeem", redeem);

        // scoreboard
        var scoreboard = new com.google.gson.JsonObject();
        scoreboard.addProperty("enabled", cfg.getBoolean("scoreboard.enabled", true));
        scoreboard.addProperty("title", cfg.getString("scoreboard.title", "Stone-Coins"));
        json.add("scoreboard", scoreboard);

        // death_protect
        var deathProtect = new com.google.gson.JsonObject();
        deathProtect.addProperty("coins", cfg.getBoolean("death_protect.coins", true));
        deathProtect.addProperty("shards", cfg.getBoolean("death_protect.shards", true));
        json.add("death_protect", deathProtect);

        // anti_dupe
        var antiDupe = new com.google.gson.JsonObject();
        antiDupe.addProperty("scan_interval_seconds", cfg.getLong("anti_dupe.scan_interval_seconds", 120L));
        json.add("anti_dupe", antiDupe);

        NodeClient.ConfigUploadResult res = nodeClient.uploadConfig(json);
        if (res.ok) {
            getLogger().info("Config-Upload erfolgreich an Node gesendet");
        } else {
            getLogger().warning("Config-Upload fehlgeschlagen: " + res.error);
        }
    }

    /** Listener kept inline because it only forwards to the scoreboard manager. */
    private final class JoinQuitListener implements Listener {
        @EventHandler public void onJoin(PlayerJoinEvent e) {
            Player p = e.getPlayer();
            scoreboard.refresh(p);
            ensureMenuScroll(p);
            // Anti-dupe: run one tick later so inventory is fully loaded.
            getServer().getScheduler().runTaskLater(StoneMcPlugin.this,
                () -> validateInventoryAntiDupe(p, false), 5L);
        }
        @EventHandler public void onQuit(PlayerQuitEvent e) { scoreboard.clear(e.getPlayer()); }

        /** Scan when player enters OR leaves Creative mode. */
        @EventHandler(priority = org.bukkit.event.EventPriority.MONITOR, ignoreCancelled = true)
        public void onGameModeChange(org.bukkit.event.player.PlayerGameModeChangeEvent e) {
            Player p = e.getPlayer();
            org.bukkit.GameMode from = p.getGameMode();
            org.bukkit.GameMode to   = e.getNewGameMode();
            boolean relevantChange =
                to   == org.bukkit.GameMode.CREATIVE   // entering creative
             || from == org.bukkit.GameMode.CREATIVE;  // leaving creative
            if (!relevantChange) return;
            // 1-tick delay so the mode switch is applied first
            getServer().getScheduler().runTaskLater(StoneMcPlugin.this, () -> {
                if (!p.isOnline()) return;
                String direction = (to == org.bukkit.GameMode.CREATIVE) ? "→CREATIVE" : "CREATIVE→" + to.name();
                getLogger().info("[anti-dupe] gamemode scan for " + p.getName() + " (" + direction + ")");
                validateInventoryAntiDupe(p, true);
            }, 1L);
        }
    }

    /**
     * Anti-dupe inventory scan.
     * @param kickOnViolation  if true, the player is kicked when excess items are found
     *                         (used by the periodic scheduler).
     *                         On join (false) we silently clean without kick so a
     *                         legitimate restart/relog is not punished.
     */
    private void validateInventoryAntiDupe(Player p, boolean kickOnViolation) {
        UUID id = p.getUniqueId();
        org.bukkit.inventory.PlayerInventory inv = p.getInventory();
        boolean violation = false;
        StringBuilder logBuf = new StringBuilder();

        // --- Shards ---
        Map<UUID, Integer> shardCountsByNonce = new HashMap<>();
        List<Integer> shardSlotsWithoutNonce = new ArrayList<>();
        org.bukkit.inventory.ItemStack[] contents = inv.getContents();
        for (int i = 0; i < contents.length; i++) {
            org.bukkit.inventory.ItemStack it = contents[i];
            if (it == null || !StoneShard.is(it)) continue;
            UUID nonce = StoneShard.nonce(it);
            if (nonce == null) {
                shardSlotsWithoutNonce.add(i);
                continue;
            }
            shardCountsByNonce.merge(nonce, it.getAmount(), Integer::sum);
        }
        for (Map.Entry<UUID, Integer> e : shardCountsByNonce.entrySet()) {
            ShardLedger.Entry ledgerEntry = shardLedger.peek(e.getKey());
            int ledgerRemaining = ledgerEntry == null ? 0 : ledgerEntry.remaining;
            int invShards = e.getValue();
            if (invShards <= ledgerRemaining) continue;

            int toRemove = invShards - ledgerRemaining;
            logBuf.append("shards(nonce=").append(e.getKey()).append(")=").append(invShards)
                .append("/ledger=").append(ledgerRemaining).append(" -").append(toRemove).append(" removed ");
            violation = true;
            for (int i = 0; i < contents.length && toRemove > 0; i++) {
                org.bukkit.inventory.ItemStack it = contents[i];
                if (it == null || !StoneShard.is(it)) continue;
                if (!e.getKey().equals(StoneShard.nonce(it))) continue;
                if (it.getAmount() <= toRemove) {
                    toRemove -= it.getAmount();
                    inv.setItem(i, null);
                } else {
                    it.setAmount(it.getAmount() - toRemove);
                    inv.setItem(i, it);
                    toRemove = 0;
                }
            }
        }
        if (!shardSlotsWithoutNonce.isEmpty()) {
            getLogger().warning("[anti-dupe] found legacy shard stacks without nonce for " + p.getName()
                + " slots=" + shardSlotsWithoutNonce + " (left untouched)");
        }

        // --- Coins ---
        long crafted  = walletStore.totalCoinsCrafted(id);
        long redeemed = walletStore.totalCoinsRedeemed(id);
        long maxCoins = Math.max(0L, crafted - redeemed);
        long invCoins = 0;
        for (org.bukkit.inventory.ItemStack it : inv.getContents()) {
            if (it != null && StoneCoin.is(it) && StoneCoin.ownedBy(it, id)) invCoins += it.getAmount();
        }
        if (invCoins > maxCoins) {
            long toRemove = invCoins - maxCoins;
            logBuf.append("coins=").append(invCoins).append("/max=").append(maxCoins)
                  .append("(crafted=").append(crafted).append(",redeemed=").append(redeemed).append(") -")
                  .append(toRemove).append("removed");
            violation = true;
            for (org.bukkit.inventory.ItemStack it : inv.getContents()) {
                if (it == null || !StoneCoin.is(it) || toRemove <= 0) continue;
                if (it.getAmount() <= toRemove) {
                    toRemove -= it.getAmount();
                    inv.remove(it);
                } else {
                    it.setAmount((int)(it.getAmount() - toRemove));
                    toRemove = 0;
                }
            }
        }

        if (!violation) return;

        getLogger().warning("[anti-dupe] " + p.getName() + " (" + id + ") " + logBuf
            + (kickOnViolation ? " -> KICKED" : " -> cleaned (join)"));

        if (kickOnViolation) {
            p.kickPlayer(org.bukkit.ChatColor.RED + "[Stone] Ungueltige Items wurden in deinem Inventar gefunden und entfernt.\n"
                + org.bukkit.ChatColor.YELLOW + "Rejoin um fortzufahren.");
        } else {
            p.sendMessage(org.bukkit.ChatColor.RED + "[Anti-Dupe] Ungueltige Stone Items wurden aus deinem Inventar entfernt.");
        }
    }

    private void ensureMenuScroll(Player p) {
        boolean hasValidScroll = false;
        org.bukkit.inventory.ItemStack[] contents = p.getInventory().getContents();
        for (int i = 0; i < contents.length; i++) {
            org.bukkit.inventory.ItemStack it = contents[i];
            if (!StoneMenuScroll.is(it) || !StoneMenuScroll.ownedBy(it, p.getUniqueId())) continue;

            if (StoneMenuScroll.isLegacyWrittenBook(it) || it.getType() != StoneMenuScroll.MATERIAL) {
                contents[i] = StoneMenuScroll.create(p);
                hasValidScroll = true;
                continue;
            }
            hasValidScroll = true;
        }

        p.getInventory().setContents(contents);
        if (hasValidScroll) return;

        org.bukkit.inventory.ItemStack scroll = StoneMenuScroll.create(p);
        java.util.Map<Integer, org.bukkit.inventory.ItemStack> overflow = p.getInventory().addItem(scroll);
        for (org.bukkit.inventory.ItemStack rest : overflow.values()) {
            p.getWorld().dropItemNaturally(p.getLocation(), rest);
        }
        p.sendMessage("§6Stone Scroll erhalten. §7Rechtsklick zum Oeffnen von /smenu.");
    }
}
