package me.vibing.tcpshield.core;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.Path;

public final class TCPShield {
    static final String VERSION = "2.0.0";
    private static final System.Logger LOGGER = System.getLogger("TCPShield");
    private static volatile CidrSet policy;

    private TCPShield() {
    }

    public static synchronized void initialize() {
        if (policy != null) {
            return;
        }
        String configuredPath = System.getProperty("tcpshield.config", "config/tcpshield.properties");
        if (configuredPath.isBlank()) {
            throw new IllegalStateException("tcpshield.config cannot be blank");
        }
        Path configPath = Path.of(configuredPath).toAbsolutePath().normalize();
        try {
            Configuration configuration = Configuration.load(configPath);
            PolicyLoader.LoadedPolicy loaded = PolicyLoader.load(configuration, configPath);
            policy = loaded.policy();
            LOGGER.log(System.Logger.Level.INFO,
                    "Loaded {0} allowed ranges ({1} fresh sources, {2} cached sources)",
                    loaded.policy().rangeCount(), loaded.freshSources(), loaded.cachedSources());
        } catch (IOException | RuntimeException exception) {
            LOGGER.log(System.Logger.Level.ERROR,
                    "No valid TCPShield policy is available; server startup is being aborted", exception);
            throw new IllegalStateException("Unable to initialize TCPShield from " + configPath, exception);
        }
    }

    public static boolean allows(InetAddress address) {
        CidrSet current = policy;
        return current != null && address != null && current.contains(address);
    }
}
