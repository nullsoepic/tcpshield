package me.vibing.tcpshield.core;

import java.net.InetAddress;
import java.util.HashSet;
import java.util.Set;

final class CidrSet {
    private final Node ipv4;
    private final Node ipv6;
    private final int rangeCount;

    private CidrSet(Node ipv4, Node ipv6, int rangeCount) {
        this.ipv4 = ipv4;
        this.ipv6 = ipv6;
        this.rangeCount = rangeCount;
    }

    boolean contains(InetAddress address) {
        byte[] bytes = normalize(address.getAddress());
        Node node = bytes.length == 4 ? ipv4 : ipv6;
        if (node == null) {
            return false;
        }
        if (node.allowed) {
            return true;
        }
        for (int bitIndex = 0; bitIndex < bytes.length * 8; bitIndex++) {
            node = bit(bytes, bitIndex) == 0 ? node.zero : node.one;
            if (node == null) {
                return false;
            }
            if (node.allowed) {
                return true;
            }
        }
        return false;
    }

    int rangeCount() {
        return rangeCount;
    }

    static Builder builder() {
        return new Builder();
    }

    private static byte[] normalize(byte[] bytes) {
        if (bytes.length != 16) {
            return bytes;
        }
        for (int index = 0; index < 10; index++) {
            if (bytes[index] != 0) {
                return bytes;
            }
        }
        if (bytes[10] != (byte) 0xFF || bytes[11] != (byte) 0xFF) {
            return bytes;
        }
        return new byte[]{bytes[12], bytes[13], bytes[14], bytes[15]};
    }

    private static int bit(byte[] address, int bitIndex) {
        return (address[bitIndex / 8] >>> (7 - bitIndex % 8)) & 1;
    }

    static final class Builder {
        private final Node ipv4 = new Node();
        private final Node ipv6 = new Node();
        private final Set<Cidr> ranges = new HashSet<>();

        void add(Cidr range) {
            if (!ranges.add(range)) {
                return;
            }
            byte[] address = range.network();
            Node node = address.length == 4 ? ipv4 : ipv6;
            for (int bitIndex = 0; bitIndex < range.prefixLength(); bitIndex++) {
                if (node.allowed) {
                    return;
                }
                if (bit(address, bitIndex) == 0) {
                    if (node.zero == null) {
                        node.zero = new Node();
                    }
                    node = node.zero;
                } else {
                    if (node.one == null) {
                        node.one = new Node();
                    }
                    node = node.one;
                }
            }
            node.allowed = true;
            node.zero = null;
            node.one = null;
        }

        CidrSet build() {
            return new CidrSet(ipv4.empty() ? null : ipv4, ipv6.empty() ? null : ipv6, ranges.size());
        }
    }

    private static final class Node {
        private boolean allowed;
        private Node zero;
        private Node one;

        private boolean empty() {
            return !allowed && zero == null && one == null;
        }
    }
}
