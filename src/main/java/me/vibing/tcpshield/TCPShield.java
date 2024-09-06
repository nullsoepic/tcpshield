package me.vibing.tcpshield;

import net.fabricmc.api.ModInitializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class TCPShield implements ModInitializer {

    private static final Logger LOGGER = LoggerFactory.getLogger("TCPShield");
    public static final List<String> ALLOWED_IP_RANGES = new ArrayList<>();

    @Override
    public void onInitialize() {
        List<String> ipRanges = fetchIpRanges("https://tcpshield.com/v4/");
        ipRanges.addAll(fetchIpRanges("https://tcpshield.com/v4-cf/"));

        ALLOWED_IP_RANGES.addAll(ipRanges);

        LOGGER.info("Successfully updated TCPShield IP ranges.");
    }

    private List<String> fetchIpRanges(String urlString) {
        List<String> ipRanges = new ArrayList<>();
        try {
            URL url = new URI(urlString).toURL();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream()))) {
                ipRanges = reader.lines().collect(Collectors.toList());
            }
        } catch (Exception e) {
            LOGGER.error("Failed to fetch IP ranges from {}: {}", urlString, e.getMessage());
        }
        return ipRanges;
    }
}