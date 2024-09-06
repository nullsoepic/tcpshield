package me.vibing.tcpshield;

import net.fabricmc.api.ModInitializer;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class TCPShield implements ModInitializer {

    public static final List<String> ALLOWED_IP_RANGES = new ArrayList<>();

    @Override
    public void onInitialize() {
        // Fetch list of IPs from the specified URLs
        List<String> ipRanges = fetchIpRanges("https://tcpshield.com/v4/");
        ipRanges.addAll(fetchIpRanges("https://tcpshield.com/v4-cf/"));

        // Add the fetched IP ranges to the allowed IP ranges list
        ALLOWED_IP_RANGES.addAll(ipRanges);
    }

    private List<String> fetchIpRanges(String urlString) {
        List<String> ipRanges = new ArrayList<>();
        try {
            URL url = new URL(urlString);
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream()))) {
                ipRanges = reader.lines().collect(Collectors.toList());
            }
        } catch (Exception e) {
            System.out.println("Failed to fetch IP ranges from " + urlString + ": " + e.getMessage());
        }
        return ipRanges;
    }
}