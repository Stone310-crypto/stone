package net.stonechain.mcplugin;

import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.entity.Player;
import org.bukkit.inventory.ItemStack;
import org.bukkit.scoreboard.Criteria;
import org.bukkit.scoreboard.DisplaySlot;
import org.bukkit.scoreboard.Objective;
import org.bukkit.scoreboard.Scoreboard;
import org.bukkit.scoreboard.Team;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

public final class ScoreboardManager {

    private final boolean enabled;
    private final String title;
    private final PlayerWalletStore wallets;
    private final Set<UUID> hidden = new HashSet<>();

    public ScoreboardManager(boolean enabled, String title, PlayerWalletStore wallets) {
        this.enabled = enabled;
        this.title = title;
        this.wallets = wallets;
    }

    public boolean enabled() { return enabled; }

    public void refresh(Player player) {
        if (!enabled || hidden.contains(player.getUniqueId())) return;

        Scoreboard board = Bukkit.getScoreboardManager().getNewScoreboard();
        Objective obj = board.registerNewObjective("stonepop", Criteria.DUMMY, title);
        obj.setDisplaySlot(DisplaySlot.SIDEBAR);

        UUID id = player.getUniqueId();
        int shardInv = 0, coinInv = 0;
        for (ItemStack it : player.getInventory().getContents()) {
            if (StoneShard.is(it)) shardInv += it.getAmount();
            else if (StoneCoin.is(it) && StoneCoin.ownedBy(it, id)) coinInv += it.getAmount();
        }
        long shardsLifetime = wallets.totalShards(id);
        long coinsLifetime  = wallets.totalCoinsCrafted(id);
        double redeemed = wallets.totalRedeemed(id);
        String linked   = wallets.linkedAddress(id);

        line(board, obj, 0, ChatColor.DARK_GRAY + "stonechain.net", 9);
        line(board, obj, 1, "" + ChatColor.STRIKETHROUGH + "                 ", 8);
        line(board, obj, 2, ChatColor.AQUA + "Shards: " + ChatColor.WHITE + shardInv + ChatColor.GRAY + " / 64", 7);
        line(board, obj, 3, ChatColor.GOLD + "Coins:  " + ChatColor.WHITE + coinInv, 6);
        line(board, obj, 4, ChatColor.GREEN + "STONE: " + ChatColor.WHITE + StoneMcPlugin.fmt(redeemed), 5);
        line(board, obj, 5, "" + ChatColor.STRIKETHROUGH + "                  ", 4);
        line(board, obj, 6, ChatColor.GRAY + "Lifetime " + ChatColor.WHITE + shardsLifetime + ChatColor.GRAY + " S / " + ChatColor.WHITE + coinsLifetime + ChatColor.GRAY + " C", 3);
        line(board, obj, 7, linked == null ? ChatColor.RED + "Wallet: nicht verknuepft" : ChatColor.GRAY + "Wallet " + ChatColor.GREEN + "OK", 2);

        player.setScoreboard(board);
    }

    public boolean toggle(Player player) {
        UUID id = player.getUniqueId();
        if (hidden.remove(id)) {
            refresh(player);
            return true;
        }
        hidden.add(id);
        player.setScoreboard(Bukkit.getScoreboardManager().getNewScoreboard());
        return false;
    }

    public void clear(Player player) {
        player.setScoreboard(Bukkit.getScoreboardManager().getNewScoreboard());
    }

    private static void line(Scoreboard board, Objective obj, int idx, String text, int score) {
        String hex = Integer.toHexString(idx);
        String entry = ChatColor.COLOR_CHAR + "0" + ChatColor.COLOR_CHAR + hex + ChatColor.RESET;
        if (entry.length() > 16) entry = entry.substring(0, 16);
        Team team = board.registerNewTeam("row" + idx);
        team.addEntry(entry);
        if (text.length() > 64) text = text.substring(0, 64);
        team.setPrefix(text);
        obj.getScore(entry).setScore(score);
    }
}
