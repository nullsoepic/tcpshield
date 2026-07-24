package me.vibing.tcpshield.core;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

final class PolicyLoader {
    private static final System.Logger LOGGER = System.getLogger("TCPShield");
    private static final int MAX_RESPONSE_BYTES = 256 * 1024;
    private static final int MAX_RANGES_PER_SOURCE = 4096;
    private static final int MAX_LINE_LENGTH = 512;
    private static final long MAX_FUTURE_CLOCK_SKEW_MILLIS = 5 * 60_000L;
    private static final String CACHE_VERSION = "# tcpshield-cache-v1";

    private PolicyLoader() {
    }

    static LoadedPolicy load(Configuration configuration, Path configPath) throws IOException {
        CidrSet.Builder policy = CidrSet.builder();
        for (String manualRange : configuration.manualRanges) {
            policy.add(parseRange(manualRange, configuration));
        }

        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(configuration.connectTimeoutMillis))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        Path cacheDirectory = configPath.resolveSibling("tcpshield-cache");
        int freshSources = 0;
        int cachedSources = 0;

        for (int index = 0; index < configuration.sources.size(); index++) {
            URI source = configuration.sources.get(index);
            List<Cidr> ranges;
            try {
                ranges = fetch(client, source, configuration);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted while fetching source " + (index + 1), interrupted);
            } catch (IOException fetchFailure) {
                ranges = readCache(cacheDirectory, source, configuration);
                if (ranges == null) {
                    throw new IOException(
                            "Source " + (index + 1) + " failed and has no valid cache (" + display(source) + ")",
                            fetchFailure);
                }
                cachedSources++;
                LOGGER.log(System.Logger.Level.WARNING,
                        "Range source {0} failed; using its last-known-good cache", index + 1);
                for (Cidr range : ranges) {
                    policy.add(range);
                }
                continue;
            }

            freshSources++;
            try {
                writeCache(cacheDirectory, source, ranges);
            } catch (IOException cacheFailure) {
                LOGGER.log(System.Logger.Level.WARNING,
                        "Range source {0} was fetched, but its cache could not be updated: {1}",
                        index + 1, cacheFailure.getMessage());
            }
            for (Cidr range : ranges) {
                policy.add(range);
            }
        }

        CidrSet built = policy.build();
        if (built.rangeCount() == 0) {
            throw new IOException("The resulting allow policy is empty");
        }
        return new LoadedPolicy(built, freshSources, cachedSources);
    }

    private static List<Cidr> fetch(HttpClient client, URI source, Configuration configuration)
            throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(source)
                .timeout(Duration.ofMillis(configuration.requestTimeoutMillis))
                .header("Accept", "text/plain")
                .header("Accept-Encoding", "identity")
                .header("User-Agent", "tcpshield-minecraft/" + TCPShield.VERSION)
                .GET()
                .build();
        CompletableFuture<HttpResponse<byte[]>> pending =
                client.sendAsync(request, ignored -> new LimitedBodySubscriber());
        HttpResponse<byte[]> response;
        try {
            response = pending.get(configuration.requestTimeoutMillis, TimeUnit.MILLISECONDS);
        } catch (TimeoutException timeout) {
            pending.cancel(true);
            throw new HttpTimeoutException("Range request timed out");
        } catch (ExecutionException failure) {
            Throwable cause = failure.getCause();
            if (cause instanceof IOException ioFailure) {
                throw ioFailure;
            }
            throw new IOException("Range request failed", cause);
        } catch (InterruptedException interrupted) {
            pending.cancel(true);
            throw interrupted;
        }
        if (response.statusCode() != 200) {
            throw new IOException("Unexpected HTTP status " + response.statusCode());
        }
        long contentLength = response.headers().firstValueAsLong("Content-Length").orElse(-1);
        if (contentLength > MAX_RESPONSE_BYTES) {
            throw new IOException("Range response exceeds " + MAX_RESPONSE_BYTES + " bytes");
        }
        return parseRanges(response.body(), configuration);
    }

    private static List<Cidr> parseRanges(byte[] bytes, Configuration configuration) throws IOException {
        String text = decodeUtf8(bytes);
        List<Cidr> ranges = new ArrayList<>();
        for (String rawLine : text.split("\\R", -1)) {
            if (rawLine.length() > MAX_LINE_LENGTH) {
                throw new IOException("Range line exceeds " + MAX_LINE_LENGTH + " characters");
            }
            String line = rawLine.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            ranges.add(parseRange(line, configuration));
            if (ranges.size() > MAX_RANGES_PER_SOURCE) {
                throw new IOException("Range source exceeds " + MAX_RANGES_PER_SOURCE + " entries");
            }
        }
        if (ranges.isEmpty()) {
            throw new IOException("Range source is empty");
        }
        return List.copyOf(ranges);
    }

    private static Cidr parseRange(String value, Configuration configuration) throws IOException {
        try {
            return Cidr.parse(value, configuration.minimumIpv4Prefix, configuration.minimumIpv6Prefix);
        } catch (IllegalArgumentException exception) {
            throw new IOException("Invalid CIDR: " + value, exception);
        }
    }

    private static String decodeUtf8(byte[] bytes) throws IOException {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes))
                    .toString();
        } catch (CharacterCodingException exception) {
            throw new IOException("Range data is not valid UTF-8", exception);
        }
    }

    private static void writeCache(Path directory, URI source, List<Cidr> ranges) throws IOException {
        ensureCacheDirectory(directory);
        StringBuilder content = new StringBuilder(CACHE_VERSION)
                .append('\n')
                .append("# fetched-at=")
                .append(Instant.now().toEpochMilli())
                .append('\n');
        for (Cidr range : ranges) {
            content.append(range).append('\n');
        }
        byte[] bytes = content.toString().getBytes(StandardCharsets.UTF_8);
        Path destination = directory.resolve(cacheKey(source) + ".cidr");
        Path temporary = Files.createTempFile(directory, ".ranges-", ".tmp");
        setOwnerOnlyFilePermissions(temporary);
        boolean moved = false;
        try {
            try (FileChannel channel = FileChannel.open(
                    temporary, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
                ByteBuffer buffer = ByteBuffer.wrap(bytes);
                while (buffer.hasRemaining()) {
                    channel.write(buffer);
                }
                channel.force(true);
            }
            try {
                Files.move(temporary, destination,
                        StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException unsupported) {
                Files.move(temporary, destination, StandardCopyOption.REPLACE_EXISTING);
            }
            moved = true;
            setOwnerOnlyFilePermissions(destination);
        } finally {
            if (!moved) {
                Files.deleteIfExists(temporary);
            }
        }
    }

    private static List<Cidr> readCache(Path directory, URI source, Configuration configuration) {
        if (configuration.cacheMaxAgeMillis == 0) {
            return null;
        }
        Path cache = directory.resolve(cacheKey(source) + ".cidr");
        try {
            if (!Files.isRegularFile(cache, LinkOption.NOFOLLOW_LINKS) || Files.size(cache) > MAX_RESPONSE_BYTES) {
                return null;
            }
            byte[] bytes = Files.readAllBytes(cache);
            String text = decodeUtf8(bytes);
            String[] lines = text.split("\\R", -1);
            if (lines.length < 3 || !lines[0].equals(CACHE_VERSION) || !lines[1].startsWith("# fetched-at=")) {
                return null;
            }
            long fetchedAt = Long.parseLong(lines[1].substring("# fetched-at=".length()));
            long now = Instant.now().toEpochMilli();
            if (fetchedAt > now + MAX_FUTURE_CLOCK_SKEW_MILLIS || now - fetchedAt > configuration.cacheMaxAgeMillis) {
                return null;
            }
            return parseRanges(bytes, configuration);
        } catch (IOException | NumberFormatException ignored) {
            return null;
        }
    }

    private static void ensureCacheDirectory(Path directory) throws IOException {
        Files.createDirectories(directory);
        if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Cache path is not a directory: " + directory);
        }
        try {
            Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"));
        } catch (UnsupportedOperationException ignored) {
            // Non-POSIX filesystems use their native ACLs.
        }
    }

    private static void setOwnerOnlyFilePermissions(Path file) throws IOException {
        try {
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException ignored) {
            // Non-POSIX filesystems use their native ACLs.
        }
    }

    private static String cacheKey(URI source) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(source.toASCIIString().getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException impossible) {
            throw new AssertionError(impossible);
        }
    }

    private static String display(URI source) {
        int port = source.getPort();
        return source.getScheme() + "://" + source.getHost() + (port < 0 ? "" : ":" + port) + source.getPath();
    }

    private static final class LimitedBodySubscriber implements HttpResponse.BodySubscriber<byte[]> {
        private final CompletableFuture<byte[]> body = new CompletableFuture<>();
        private final ByteArrayOutputStream output = new ByteArrayOutputStream();
        private Flow.Subscription subscription;
        private int total;

        @Override
        public CompletionStage<byte[]> getBody() {
            return body;
        }

        @Override
        public void onSubscribe(Flow.Subscription subscription) {
            if (this.subscription != null) {
                subscription.cancel();
                return;
            }
            this.subscription = subscription;
            subscription.request(1);
        }

        @Override
        public void onNext(List<ByteBuffer> buffers) {
            for (ByteBuffer buffer : buffers) {
                int length = buffer.remaining();
                if (length > MAX_RESPONSE_BYTES - total) {
                    subscription.cancel();
                    body.completeExceptionally(
                            new IOException("Range response exceeds " + MAX_RESPONSE_BYTES + " bytes"));
                    return;
                }
                byte[] bytes = new byte[length];
                buffer.get(bytes);
                output.write(bytes, 0, bytes.length);
                total += length;
            }
            subscription.request(1);
        }

        @Override
        public void onError(Throwable failure) {
            body.completeExceptionally(failure);
        }

        @Override
        public void onComplete() {
            body.complete(output.toByteArray());
        }
    }

    record LoadedPolicy(CidrSet policy, int freshSources, int cachedSources) {
    }
}
