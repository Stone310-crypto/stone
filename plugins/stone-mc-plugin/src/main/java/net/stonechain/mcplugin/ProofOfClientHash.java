package net.stonechain.mcplugin;

import java.io.*;
import java.lang.management.ManagementFactory;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import java.util.logging.Logger;
import java.util.HashSet;
import java.util.Set;

/**
 * Proof-of-Client-Hash: Beweist, dass das Plugin unverändert ist.
 *
 * Ablauf:
 *   1. JAR-Hash: SHA-256 des eigenen Plugin-JARs
 *   2. System-Fingerprint: Hash von JVM-Version, OS, CPU-Anzahl
 *   3. Verdächtige Flags: Debugger, JVM-Agenten
 *   4. Signierung: Ed25519 über SHA-256(plugin_hash|fingerprint|timestamp)
 *
 * Der Proof-Key wird in stone_data/proof.key (PKCS8) und
 * stone_data/proof.pub (32-Byte raw) gespeichert.
 */
public final class ProofOfClientHash {

    // ── PKCS8-Header für Ed25519 (RFC 8410) ──────────────────────────────────
    private static final byte[] PKCS8_HEADER = {
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
        0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20
    };
    // X.509 SubjectPublicKeyInfo-Header für Ed25519
    private static final byte[] X509_HEADER = {
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
        0x70, 0x03, 0x21, 0x00
    };

    private final Logger log;
    private final File dataDir;

    private PrivateKey privateKey;
    private String publicKeyHex;

    public ProofOfClientHash(File dataDir, Logger log) {
        this.dataDir = dataDir;
        this.log = log;
    }

    /** Lädt oder generiert den Proof-Key. Muss einmalig vor buildProof() aufgerufen werden. */
    public void init() throws Exception {
        File stoneDataDir = new File(dataDir, "stone_data");
        stoneDataDir.mkdirs();

        File privFile = new File(stoneDataDir, "proof.key");
        File pubFile  = new File(stoneDataDir, "proof.pub");

        if (privFile.exists() && pubFile.exists()) {
            loadKey(privFile, pubFile);
            log.info("[watchdog] Proof-Key geladen (pub=" + publicKeyHex.substring(0, 16) + "...)");
        } else {
            generateKey(privFile, pubFile);
            log.info("[watchdog] Neuer Proof-Key generiert (pub=" + publicKeyHex.substring(0, 16) + "...)");
        }
    }

    // ── Proof erstellen ───────────────────────────────────────────────────────

    /** Erstellt einen signierten Client-Hash-Proof. */
    public ClientProofPayload buildProof(String gameId) throws Exception {
        String pluginHash = computePluginHash();
        String systemFingerprint = computeSystemFingerprint();
        long timestamp = System.currentTimeMillis() / 1000L;
        List<String> suspiciousFlags = detectSuspiciousEnvironment();

        String signInput = pluginHash + "|" + systemFingerprint + "|" + timestamp;
        byte[] signHash = sha256(signInput.getBytes(StandardCharsets.UTF_8));

        Signature sig = Signature.getInstance("Ed25519");
        sig.initSign(privateKey);
        sig.update(signHash);
        byte[] signatureBytes = sig.sign();

        return new ClientProofPayload(
            gameId,
            pluginHash,
            systemFingerprint,
            timestamp,
            suspiciousFlags,
            hexEncode(signatureBytes),
            publicKeyHex
        );
    }

    // ── JAR-Hash ──────────────────────────────────────────────────────────────

    private String computePluginHash() {
        try {
            URI loc = ProofOfClientHash.class
                .getProtectionDomain()
                .getCodeSource()
                .getLocation()
                .toURI();
            File jarFile = new File(loc);
            if (!jarFile.exists() || !jarFile.isFile()) {
                // In IDE/Test-Umgebung: Klassen-Verzeichnis hashen
                return hashDirectory(jarFile);
            }
            byte[] jarBytes = Files.readAllBytes(jarFile.toPath());
            return hexEncode(sha256(jarBytes));
        } catch (Exception e) {
            log.warning("[watchdog] JAR-Hash fehlgeschlagen: " + e.getMessage());
            try {
                return "UNKNOWN_" + hexEncode(sha256(("unknown:" + e.getMessage()).getBytes(StandardCharsets.UTF_8)));
            } catch (Exception ignored) {
                return "UNKNOWN_HASH_ERROR";
            }
        }
    }

    private String hashDirectory(File dir) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        if (dir.isDirectory()) {
            File[] files = dir.listFiles();
            if (files != null) {
                Arrays.sort(files, Comparator.comparing(File::getName));
                for (File f : files) {
                    if (f.isFile()) {
                        md.update(Files.readAllBytes(f.toPath()));
                    }
                }
            }
        }
        return hexEncode(md.digest());
    }

    // ── System-Fingerprint ────────────────────────────────────────────────────

    private String computeSystemFingerprint() throws Exception {
        String sysInfo = String.join("|",
            System.getProperty("java.version", ""),
            System.getProperty("os.name", ""),
            System.getProperty("os.arch", ""),
            String.valueOf(Runtime.getRuntime().availableProcessors())
        );
        return hexEncode(sha256(sysInfo.getBytes(StandardCharsets.UTF_8)));
    }

    // ── Verdächtige Umgebung erkennen ─────────────────────────────────────────

    /**
     * Bekannte legitime JVM-Agenten, die von Paper/JVM selbst geladen werden.
     * Diese werden NICHT als verdächtig markiert.
     */
    private static final Set<String> KNOWN_SAFE_AGENTS = new HashSet<>(Arrays.asList(
        "jdwp",            // Java Debugger Wire Protocol (nur mit explizitem -agentlib:jdwp verdächtig)
        "javaagent",       // Generic
        "nashorn",         // Nashorn JS engine
        "jvmtiagent",      // Standard JVM agent
        "hprof"            // Heap profiler (kommt in GC-Flags vor, kein echter Agent)
    ));

    private List<String> detectSuspiciousEnvironment() {
        List<String> flags = new ArrayList<>();

        List<String> jvmArgs = ManagementFactory.getRuntimeMXBean().getInputArguments();
        boolean debuggerConfigured = false;

        for (String arg : jvmArgs) {
            String lower = arg.toLowerCase();

            // Debugger-Protokoll aktiv (JDWP configured = verdächtig, unabhängig ob verbunden)
            if (lower.contains("-agentlib:jdwp") || lower.contains("-xdebug") || lower.contains("-xrunjdwp")) {
                if (!debuggerConfigured) {
                    debuggerConfigured = true;
                    // Extrahiere Transportdetails ohne sensitive Adressen
                    String detail = arg.contains("transport=") ? extractJdwpParam(arg, "transport") : "configured";
                    flags.add("DEBUGGER_JDWP:" + detail);
                }
                continue;
            }

            // Externe Java-Agenten (-javaagent:pfad.jar)
            if (lower.startsWith("-javaagent:")) {
                String agentPath = arg.substring(11);
                int eqIdx = agentPath.indexOf('=');
                String agentName = new File(eqIdx > 0 ? agentPath.substring(0, eqIdx) : agentPath)
                    .getName().toLowerCase();

                // Nur unbekannte Agenten melden
                boolean knownSafe = KNOWN_SAFE_AGENTS.stream().anyMatch(agentName::contains);
                if (!knownSafe) {
                    flags.add("AGENT_LOADED:" + new File(eqIdx > 0 ? agentPath.substring(0, eqIdx) : agentPath).getName());
                }
                continue;
            }

            // Explizites Bytecode-Instrumentation-Flag (nicht: normale GC/perf flags)
            // Nur flaggen wenn -XX:+... oder direkte instrumentation flags, NICHT GC-Parameter
            if (lower.startsWith("-xbootclasspath/p:") || lower.startsWith("-xbootclasspath/a:")) {
                flags.add("BOOTCLASSPATH_MODIFIED");
            }
        }

        // AttachMechanism: Prüfen ob jemand sich per JVM Attach API verbinden kann
        // (ohne die JDI-Klasse zu laden, die auf jedem JDK verfügbar ist)
        checkAttachMechanism(flags, jvmArgs);

        return flags;
    }

    private void checkAttachMechanism(List<String> flags, List<String> jvmArgs) {
        // Wenn DisableAttachMechanism NICHT gesetzt ist, kann sich jemand zur Laufzeit anhängen.
        // Das ist in Produktionsumgebungen normal – wir loggen es nur auf DEBUG-Level.
        boolean attachDisabled = jvmArgs.stream()
            .anyMatch(a -> a.contains("DisableAttachMechanism"));

        // Prüfen ob tatsächlich ein Prozess aktiv verbunden ist via /proc/self/fd (Linux only)
        if (System.getProperty("os.name", "").toLowerCase().contains("linux")) {
            try {
                File fdDir = new File("/proc/self/fd");
                File[] fds = fdDir.listFiles();
                if (fds != null) {
                    for (File fd : fds) {
                        try {
                            String target = fd.getCanonicalPath();
                            // Typische Profiler/Debugger öffnen Sockets oder tmpfiles
                            if (target.contains("jdwp") || target.contains("jvmti")) {
                                flags.add("ACTIVE_DEBUGGER_SOCKET");
                                break;
                            }
                        } catch (IOException ignored) {}
                    }
                }
            } catch (Exception ignored) {}
        }
    }

    private static String extractJdwpParam(String jdwpArg, String param) {
        for (String part : jdwpArg.split(",")) {
            if (part.startsWith(param + "=")) {
                return part.substring(param.length() + 1).trim();
            }
        }
        return "unknown";
    }

    // ── Key-Management ────────────────────────────────────────────────────────

    private void generateKey(File privFile, File pubFile) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("Ed25519");
        KeyPair kp = gen.generateKeyPair();

        // Private Key als PKCS8 speichern
        byte[] pkcs8 = kp.getPrivate().getEncoded();
        Files.write(privFile.toPath(), pkcs8,
            StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

        // Public Key: letzten 32 Bytes aus X.509-Encoding extrahieren
        byte[] x509 = kp.getPublic().getEncoded();
        byte[] pubRaw = Arrays.copyOfRange(x509, x509.length - 32, x509.length);
        Files.write(pubFile.toPath(), pubRaw,
            StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

        this.privateKey = kp.getPrivate();
        this.publicKeyHex = hexEncode(pubRaw);
    }

    private void loadKey(File privFile, File pubFile) throws Exception {
        byte[] pkcs8 = Files.readAllBytes(privFile.toPath());

        // Unterstützt sowohl rohen 32-Byte-Seed (LightP2pNode-Format) als auch PKCS8 (48 Bytes)
        if (pkcs8.length == 32) {
            pkcs8 = wrapPkcs8(pkcs8);
        }

        this.privateKey = KeyFactory.getInstance("Ed25519")
            .generatePrivate(new PKCS8EncodedKeySpec(pkcs8));

        byte[] pubRaw = Files.readAllBytes(pubFile.toPath());
        this.publicKeyHex = hexEncode(pubRaw);
    }

    /** Wraps einen 32-Byte-Seed in PKCS8-Format. */
    static byte[] wrapPkcs8(byte[] seed32) {
        byte[] pkcs8 = new byte[PKCS8_HEADER.length + seed32.length];
        System.arraycopy(PKCS8_HEADER, 0, pkcs8, 0, PKCS8_HEADER.length);
        System.arraycopy(seed32, 0, pkcs8, PKCS8_HEADER.length, seed32.length);
        return pkcs8;
    }

    // ── Utilities ─────────────────────────────────────────────────────────────

    static byte[] sha256(byte[] input) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(input);
    }

    static String hexEncode(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    // ── PoP Mining helpers ────────────────────────────────────────────────────

    /** Signs arbitrary data with the plugin's proof key (deterministic Ed25519). */
    public byte[] sign(byte[] data) throws Exception {
        Signature sig = Signature.getInstance("Ed25519");
        sig.initSign(privateKey);
        sig.update(data);
        return sig.sign();
    }

    public String getPublicKeyHex() { return publicKeyHex; }

    public String getPluginHash() { return computePluginHash(); }

    // ── Payload-Klasse ────────────────────────────────────────────────────────

    public static final class ClientProofPayload {
        public final String gameId;
        public final String pluginHash;
        public final String systemFingerprint;
        public final long timestamp;
        public final List<String> suspiciousFlags;
        public final String signature;
        public final String publicKeyHex;

        ClientProofPayload(String gameId, String pluginHash, String systemFingerprint,
                           long timestamp, List<String> suspiciousFlags,
                           String signature, String publicKeyHex) {
            this.gameId = gameId;
            this.pluginHash = pluginHash;
            this.systemFingerprint = systemFingerprint;
            this.timestamp = timestamp;
            this.suspiciousFlags = suspiciousFlags;
            this.signature = signature;
            this.publicKeyHex = publicKeyHex;
        }
    }
}
