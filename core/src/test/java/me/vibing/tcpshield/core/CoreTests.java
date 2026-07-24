package me.vibing.tcpshield.core;

import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

public final class CoreTests {
    private int assertions;

    public static void main(String[] args) throws Exception {
        CoreTests tests = new CoreTests();
        tests.cidrMatching();
        tests.strictParsing();
        tests.configuration();
        tests.fetchAndCacheFallback();
        tests.requestTimeoutCoversResponseBody();
        tests.failClosedWithoutPolicy();
        System.out.println("Core tests passed (" + tests.assertions + " assertions)");
    }

    private void cidrMatching() throws Exception {
        CidrSet.Builder builder = CidrSet.builder();
        builder.add(Cidr.parse("198.51.100.0/24", 8, 16));
        builder.add(Cidr.parse("2001:db8::/32", 8, 16));
        CidrSet ranges = builder.build();

        check(ranges.contains(address("198.51.100.0")), "IPv4 network boundary must match");
        check(ranges.contains(address("198.51.100.255")), "IPv4 broadcast boundary must match");
        check(!ranges.contains(address("198.51.101.0")), "Adjacent IPv4 network must not match");
        check(ranges.contains(address("2001:db8:ffff::1")), "IPv6 range must match");
        check(!ranges.contains(address("2001:db9::1")), "Adjacent IPv6 range must not match");

        byte[] mapped = new byte[16];
        mapped[10] = (byte) 0xff;
        mapped[11] = (byte) 0xff;
        byte[] ipv4 = address("198.51.100.42").getAddress();
        System.arraycopy(ipv4, 0, mapped, 12, ipv4.length);
        InetAddress mappedAddress = Inet6Address.getByAddress(null, mapped, -1);
        check(ranges.contains(mappedAddress), "IPv4-mapped IPv6 peers must be normalized");
    }

    private void strictParsing() {
        expectFailure(() -> Cidr.parse("example.com/24", 8, 16), "Hostnames must not be resolved");
        expectFailure(() -> Cidr.parse("010.0.0.1/32", 8, 16), "Ambiguous IPv4 octets must be rejected");
        expectFailure(() -> Cidr.parse("10.0.0.0/7", 8, 16), "Overly broad IPv4 ranges must be rejected");
        expectFailure(() -> Cidr.parse("fe80::1%1/128", 8, 16), "Scoped IPv6 ranges must be rejected");
        expectFailure(() -> Cidr.parse("::ffff:c633:6400/120", 8, 16),
                "Mapped IPv6 policies must use their IPv4 equivalent");
        expectFailure(() -> Cidr.parse("2001:db8::/129", 8, 16), "Invalid IPv6 prefixes must be rejected");
        check(Cidr.parse("203.0.113.4", 8, 16).toString().equals("203.0.113.4/32"),
                "Bare addresses must become host ranges");
    }

    private void configuration() throws Exception {
        Path directory = Files.createTempDirectory("tcpshield-config-test");
        try {
            Path generated = directory.resolve("generated.properties");
            Configuration defaults = Configuration.load(generated);
            check(Files.isRegularFile(generated), "Missing configuration must be generated");
            check(defaults.sources.size() == 2, "Default configuration must use both TCPShield feeds");

            Path manual = directory.resolve("manual.properties");
            Files.writeString(manual, "allow.1=192.0.2.7\n", StandardCharsets.UTF_8);
            Configuration manualConfiguration = Configuration.load(manual);
            check(manualConfiguration.sources.isEmpty(), "Manual-only mode must not require a source");
            check(manualConfiguration.manualRanges.size() == 1, "Manual ranges must load");

            Path typo = directory.resolve("typo.properties");
            Files.writeString(typo, "allow.1=192.0.2.7\nrequest-timeot-ms=1\n", StandardCharsets.UTF_8);
            expectIOException(() -> Configuration.load(typo), "Unknown options must fail instead of being ignored");
        } finally {
            deleteTree(directory);
        }
    }

    private void fetchAndCacheFallback() throws Exception {
        AtomicReference<String> response = new AtomicReference<>("198.51.100.0/24\n2001:db8::/32\n");
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/ranges", exchange -> {
            byte[] body = response.get().getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();

        Path directory = Files.createTempDirectory("tcpshield-fetch-test");
        try {
            Path configPath = directory.resolve("tcpshield.properties");
            Files.writeString(configPath, """
                    source.1=http://localhost:%d/ranges
                    allow-insecure-http=true
                    cache-max-age-hours=1
                    connect-timeout-ms=1000
                    request-timeout-ms=2000
                    minimum-ipv4-prefix=8
                    minimum-ipv6-prefix=16
                    """.formatted(server.getAddress().getPort()), StandardCharsets.UTF_8);
            Configuration configuration = Configuration.load(configPath);
            PolicyLoader.LoadedPolicy fresh = PolicyLoader.load(configuration, configPath);
            check(fresh.freshSources() == 1 && fresh.cachedSources() == 0, "Healthy source must be fetched");
            check(fresh.policy().contains(address("198.51.100.23")), "Fetched IPv4 range must be active");

            response.set("not-a-cidr\n");
            PolicyLoader.LoadedPolicy cached = PolicyLoader.load(configuration, configPath);
            check(cached.freshSources() == 0 && cached.cachedSources() == 1,
                    "Malformed refresh must fall back to complete last-known-good data");
            check(cached.policy().contains(address("2001:db8::7")), "Cached IPv6 range must remain active");

            Path cachePath = directory.resolve("tcpshield-cache");
            deleteTree(cachePath);
            Files.writeString(cachePath, "not-a-directory", StandardCharsets.UTF_8);
            response.set("203.0.113.0/24\n");
            PolicyLoader.LoadedPolicy uncached = PolicyLoader.load(configuration, configPath);
            check(uncached.freshSources() == 1 && uncached.policy().contains(address("203.0.113.8")),
                    "A cache write failure must not discard a valid fresh policy");
        } finally {
            server.stop(0);
            deleteTree(directory);
        }
    }

    private void requestTimeoutCoversResponseBody() throws Exception {
        CountDownLatch releaseResponse = new CountDownLatch(1);
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/ranges", exchange -> {
            exchange.sendResponseHeaders(200, 0);
            exchange.getResponseBody().write('1');
            exchange.getResponseBody().flush();
            try {
                releaseResponse.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            } finally {
                exchange.close();
            }
        });
        server.start();

        Path directory = Files.createTempDirectory("tcpshield-timeout-test");
        try {
            Path configPath = directory.resolve("tcpshield.properties");
            Files.writeString(configPath, """
                    source.1=http://localhost:%d/ranges
                    allow-insecure-http=true
                    cache-max-age-hours=0
                    connect-timeout-ms=1000
                    request-timeout-ms=500
                    """.formatted(server.getAddress().getPort()), StandardCharsets.UTF_8);
            Configuration configuration = Configuration.load(configPath);
            long started = System.nanoTime();
            expectIOException(() -> PolicyLoader.load(configuration, configPath),
                    "A stalled response body must time out");
            long elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);
            check(elapsedMillis < 3_000, "The request timeout must cover the complete response body");
        } finally {
            releaseResponse.countDown();
            server.stop(0);
            deleteTree(directory);
        }
    }

    private void failClosedWithoutPolicy() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/ranges", exchange -> {
            byte[] body = "not-a-cidr\n".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();

        Path directory = Files.createTempDirectory("tcpshield-failure-test");
        try {
            Path configPath = directory.resolve("tcpshield.properties");
            Files.writeString(configPath, """
                    source.1=http://localhost:%d/ranges
                    allow-insecure-http=true
                    cache-max-age-hours=1
                    """.formatted(server.getAddress().getPort()), StandardCharsets.UTF_8);
            Configuration configuration = Configuration.load(configPath);
            expectIOException(() -> PolicyLoader.load(configuration, configPath),
                    "Invalid source without cache must fail startup");
        } finally {
            server.stop(0);
            deleteTree(directory);
        }
    }

    private InetAddress address(String value) throws Exception {
        return InetAddress.getByName(value);
    }

    private void check(boolean condition, String message) {
        assertions++;
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private void expectFailure(ThrowingAction action, String message) {
        assertions++;
        try {
            action.run();
            throw new AssertionError(message);
        } catch (IllegalArgumentException expected) {
            // Expected.
        } catch (Exception unexpected) {
            throw new AssertionError(message, unexpected);
        }
    }

    private void expectIOException(ThrowingAction action, String message) {
        assertions++;
        try {
            action.run();
            throw new AssertionError(message);
        } catch (IOException expected) {
            // Expected.
        } catch (Exception unexpected) {
            throw new AssertionError(message, unexpected);
        }
    }

    private static void deleteTree(Path root) throws IOException {
        if (!Files.exists(root)) {
            return;
        }
        try (var paths = Files.walk(root)) {
            for (Path path : paths.sorted((left, right) -> right.compareTo(left)).toList()) {
                Files.deleteIfExists(path);
            }
        }
    }

    @FunctionalInterface
    private interface ThrowingAction {
        void run() throws Exception;
    }
}
