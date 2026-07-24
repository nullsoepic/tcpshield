package me.vibing.tcpshield.core;

import java.io.IOException;
import java.io.Reader;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Pattern;

final class Configuration {
    private static final Pattern SOURCE_KEY = Pattern.compile("source\\.\\d+");
    private static final Pattern ALLOW_KEY = Pattern.compile("allow\\.\\d+");
    private static final Set<String> OPTION_KEYS = Set.of(
            "allow-insecure-http",
            "cache-max-age-hours",
            "connect-timeout-ms",
            "request-timeout-ms",
            "minimum-ipv4-prefix",
            "minimum-ipv6-prefix");
    private static final String DEFAULT_CONFIG = """
            # Each source must return one numeric IPv4 or IPv6 CIDR per line.
            source.1=https://tcpshield.com/v4/
            source.2=https://tcpshield.com/v4-cf/

            # Add fixed addresses or CIDRs with allow.1, allow.2, and so on.
            # Remove every source.* entry to use only fixed entries.

            allow-insecure-http=false
            cache-max-age-hours=168
            connect-timeout-ms=5000
            request-timeout-ms=10000
            minimum-ipv4-prefix=8
            minimum-ipv6-prefix=16
            """;

    final List<URI> sources;
    final List<String> manualRanges;
    final boolean allowInsecureHttp;
    final long cacheMaxAgeMillis;
    final int connectTimeoutMillis;
    final int requestTimeoutMillis;
    final int minimumIpv4Prefix;
    final int minimumIpv6Prefix;

    private Configuration(
            List<URI> sources,
            List<String> manualRanges,
            boolean allowInsecureHttp,
            long cacheMaxAgeMillis,
            int connectTimeoutMillis,
            int requestTimeoutMillis,
            int minimumIpv4Prefix,
            int minimumIpv6Prefix) {
        this.sources = List.copyOf(sources);
        this.manualRanges = List.copyOf(manualRanges);
        this.allowInsecureHttp = allowInsecureHttp;
        this.cacheMaxAgeMillis = cacheMaxAgeMillis;
        this.connectTimeoutMillis = connectTimeoutMillis;
        this.requestTimeoutMillis = requestTimeoutMillis;
        this.minimumIpv4Prefix = minimumIpv4Prefix;
        this.minimumIpv6Prefix = minimumIpv6Prefix;
    }

    static Configuration load(Path path) throws IOException {
        createDefaultIfMissing(path);

        Properties properties = new Properties();
        try (Reader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            properties.load(reader);
        }

        rejectUnknownKeys(properties);
        boolean allowHttp = booleanValue(properties, "allow-insecure-http", false);
        int cacheHours = intValue(properties, "cache-max-age-hours", 168, 0, 8760);
        int connectTimeout = intValue(properties, "connect-timeout-ms", 5000, 250, 30_000);
        int requestTimeout = intValue(properties, "request-timeout-ms", 10_000, 500, 120_000);
        int minimumIpv4Prefix = intValue(properties, "minimum-ipv4-prefix", 8, 0, 32);
        int minimumIpv6Prefix = intValue(properties, "minimum-ipv6-prefix", 16, 0, 128);

        List<URI> sources = new ArrayList<>();
        for (String value : values(properties, SOURCE_KEY)) {
            URI uri;
            try {
                uri = URI.create(value);
            } catch (IllegalArgumentException exception) {
                throw new IOException("Invalid source URI", exception);
            }
            validateSource(uri, allowHttp);
            sources.add(uri.normalize());
        }
        if (new HashSet<>(sources).size() != sources.size()) {
            throw new IOException("Duplicate source URI");
        }

        List<String> manualRanges = values(properties, ALLOW_KEY);
        if (sources.isEmpty() && manualRanges.isEmpty()) {
            throw new IOException("At least one source.* or allow.* entry is required");
        }

        return new Configuration(
                sources,
                manualRanges,
                allowHttp,
                Math.multiplyExact(cacheHours, 3_600_000L),
                connectTimeout,
                requestTimeout,
                minimumIpv4Prefix,
                minimumIpv6Prefix);
    }

    private static void createDefaultIfMissing(Path path) throws IOException {
        if (Files.exists(path)) {
            return;
        }
        Path parent = path.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Path directory = parent == null ? Path.of(".") : parent;
        Path temporary = Files.createTempFile(directory, ".tcpshield-config-", ".tmp");
        try {
            Files.writeString(temporary, DEFAULT_CONFIG, StandardCharsets.UTF_8,
                    StandardOpenOption.TRUNCATE_EXISTING);
            try {
                Files.move(temporary, path, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException unsupported) {
                Files.move(temporary, path);
            } catch (FileAlreadyExistsException ignored) {
                // Another initializer won the race.
            }
        } catch (FileAlreadyExistsException ignored) {
            // Another initializer won the race after an atomic move fallback.
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private static void rejectUnknownKeys(Properties properties) throws IOException {
        for (String key : properties.stringPropertyNames()) {
            if (!OPTION_KEYS.contains(key) && !SOURCE_KEY.matcher(key).matches() && !ALLOW_KEY.matcher(key).matches()) {
                throw new IOException("Unknown configuration key: " + key);
            }
        }
    }

    private static List<String> values(Properties properties, Pattern pattern) throws IOException {
        List<String> keys = properties.stringPropertyNames().stream()
                .filter(key -> pattern.matcher(key).matches())
                .sorted(Comparator.comparingInt(key -> Integer.parseInt(key.substring(key.indexOf('.') + 1))))
                .toList();
        List<String> values = new ArrayList<>(keys.size());
        for (String key : keys) {
            String value = properties.getProperty(key).trim();
            if (value.isEmpty()) {
                throw new IOException("Empty configuration value: " + key);
            }
            values.add(value);
        }
        return values;
    }

    private static boolean booleanValue(Properties properties, String key, boolean fallback) throws IOException {
        String value = properties.getProperty(key);
        if (value == null) {
            return fallback;
        }
        if (value.equalsIgnoreCase("true")) {
            return true;
        }
        if (value.equalsIgnoreCase("false")) {
            return false;
        }
        throw new IOException(key + " must be true or false");
    }

    private static int intValue(Properties properties, String key, int fallback, int minimum, int maximum)
            throws IOException {
        String value = properties.getProperty(key);
        if (value == null) {
            return fallback;
        }
        try {
            int parsed = Integer.parseInt(value.trim());
            if (parsed < minimum || parsed > maximum) {
                throw new IOException(key + " must be between " + minimum + " and " + maximum);
            }
            return parsed;
        } catch (NumberFormatException exception) {
            throw new IOException(key + " must be an integer", exception);
        }
    }

    private static void validateSource(URI uri, boolean allowHttp) throws IOException {
        String scheme = uri.getScheme();
        if (scheme == null || (!scheme.equalsIgnoreCase("https") && !(allowHttp && scheme.equalsIgnoreCase("http")))) {
            throw new IOException("Source URIs must use HTTPS unless allow-insecure-http is true");
        }
        if (!uri.isAbsolute() || uri.getHost() == null || uri.getHost().isBlank()) {
            throw new IOException("Source URI must be absolute and include a host");
        }
        if (uri.getUserInfo() != null || uri.getFragment() != null) {
            throw new IOException("Source URI cannot include user information or a fragment");
        }
    }
}
