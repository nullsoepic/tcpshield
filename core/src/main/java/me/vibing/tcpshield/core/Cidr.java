package me.vibing.tcpshield.core;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;

final class Cidr {
    private final byte[] network;
    private final int prefixLength;

    private Cidr(byte[] network, int prefixLength) {
        this.network = network;
        this.prefixLength = prefixLength;
    }

    static Cidr parse(String input, int minimumIpv4Prefix, int minimumIpv6Prefix) {
        String value = input.trim();
        if (value.isEmpty() || value.chars().anyMatch(Character::isWhitespace)) {
            throw new IllegalArgumentException("CIDR cannot be empty or contain whitespace");
        }

        int slash = value.indexOf('/');
        if (slash != value.lastIndexOf('/')) {
            throw new IllegalArgumentException("CIDR has more than one prefix separator");
        }
        String addressPart = slash < 0 ? value : value.substring(0, slash);
        byte[] address = parseAddress(addressPart);
        int maximum = address.length * 8;
        int prefix = slash < 0 ? maximum : parsePrefix(value.substring(slash + 1), maximum);
        int minimum = address.length == 4 ? minimumIpv4Prefix : minimumIpv6Prefix;
        if (prefix < minimum) {
            throw new IllegalArgumentException("CIDR prefix /" + prefix + " is broader than configured minimum /" + minimum);
        }

        byte[] network = address.clone();
        clearHostBits(network, prefix);
        return new Cidr(network, prefix);
    }

    byte[] network() {
        return network;
    }

    int prefixLength() {
        return prefixLength;
    }

    private static byte[] parseAddress(String value) {
        if (value.indexOf(':') >= 0) {
            return parseIpv6(value);
        }
        return parseIpv4(value);
    }

    private static byte[] parseIpv4(String value) {
        String[] parts = value.split("\\.", -1);
        if (parts.length != 4) {
            throw new IllegalArgumentException("Invalid IPv4 address");
        }
        byte[] result = new byte[4];
        for (int index = 0; index < parts.length; index++) {
            String part = parts[index];
            if (part.isEmpty() || part.length() > 3 || (part.length() > 1 && part.charAt(0) == '0')) {
                throw new IllegalArgumentException("Invalid IPv4 address");
            }
            int octet = 0;
            for (int character = 0; character < part.length(); character++) {
                char digit = part.charAt(character);
                if (digit < '0' || digit > '9') {
                    throw new IllegalArgumentException("Invalid IPv4 address");
                }
                octet = octet * 10 + digit - '0';
            }
            if (octet > 255) {
                throw new IllegalArgumentException("Invalid IPv4 address");
            }
            result[index] = (byte) octet;
        }
        return result;
    }

    private static byte[] parseIpv6(String value) {
        if (value.isEmpty() || value.indexOf('%') >= 0 || value.indexOf('.') >= 0) {
            throw new IllegalArgumentException("Invalid IPv6 address");
        }
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (character != ':' && Character.digit(character, 16) < 0) {
                throw new IllegalArgumentException("Invalid IPv6 address");
            }
        }
        try {
            InetAddress parsed = InetAddress.getByName(value);
            if (!(parsed instanceof Inet6Address)) {
                throw new IllegalArgumentException("Invalid IPv6 address");
            }
            return parsed.getAddress();
        } catch (UnknownHostException exception) {
            throw new IllegalArgumentException("Invalid IPv6 address", exception);
        }
    }

    private static int parsePrefix(String value, int maximum) {
        if (value.isEmpty()) {
            throw new IllegalArgumentException("Missing CIDR prefix");
        }
        try {
            int parsed = Integer.parseInt(value);
            if (parsed < 0 || parsed > maximum) {
                throw new IllegalArgumentException("CIDR prefix must be between 0 and " + maximum);
            }
            return parsed;
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException("Invalid CIDR prefix", exception);
        }
    }

    private static void clearHostBits(byte[] address, int prefixLength) {
        int fullBytes = prefixLength / 8;
        int remainingBits = prefixLength % 8;
        if (remainingBits != 0) {
            address[fullBytes] &= (byte) (0xFF << (8 - remainingBits));
            fullBytes++;
        }
        Arrays.fill(address, fullBytes, address.length, (byte) 0);
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof Cidr cidr
                && prefixLength == cidr.prefixLength
                && Arrays.equals(network, cidr.network);
    }

    @Override
    public int hashCode() {
        return 31 * Arrays.hashCode(network) + prefixLength;
    }

    @Override
    public String toString() {
        try {
            return InetAddress.getByAddress(network).getHostAddress() + "/" + prefixLength;
        } catch (UnknownHostException impossible) {
            throw new AssertionError(impossible);
        }
    }
}
