package me.vibing.tcpshield.mixin;

import net.minecraft.network.ClientConnection;
import net.minecraft.network.packet.c2s.handshake.HandshakeC2SPacket;
import net.minecraft.server.network.ServerHandshakeNetworkHandler;
import org.spongepowered.asm.mixin.Final;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

import java.net.InetAddress;
import java.net.UnknownHostException;

import static me.vibing.tcpshield.TCPShield.ALLOWED_IP_RANGES;

@Mixin(ServerHandshakeNetworkHandler.class)
public class ServerHandshakeNetworkHandlerMixin {
    @Shadow @Final private ClientConnection connection;

    @Inject(method = "onHandshake", at = @At("HEAD"), cancellable = true)
    public void onHandshake(HandshakeC2SPacket packet, CallbackInfo ci) {
        String clientIp = connection.getAddress().toString().split(":")[0].replace("/", "");

        boolean isAllowed = ALLOWED_IP_RANGES.stream()
                .anyMatch(cidr -> isInRange(cidr, clientIp));

        if (!isAllowed) {
//            System.out.println("Connection rejected: IP " + clientIp + " is not in the allow list");
            ci.cancel();
        }
    }

    private static long ipToLong(byte[] ip) {
        long result = 0;
        for (byte b : ip) {
            result <<= 8;
            result |= b & 0xFF;
        }
        return result;
    }

    private static long createMask(int prefixLength) {
        return (0xFFFFFFFFL << (32 - prefixLength)) & 0xFFFFFFFFL;
    }

    private static boolean isInRange(String cidr, String clientIp) {
        String[] parts = cidr.split("/");
        String ipRange = parts[0];
        int prefixLength = Integer.parseInt(parts[1]);

        try {
            byte[] rangeAddress = InetAddress.getByName(ipRange).getAddress();
            byte[] clientAddress = InetAddress.getByName(clientIp).getAddress();

            long rangeLong = ipToLong(rangeAddress);
            long clientLong = ipToLong(clientAddress);
            long mask = createMask(prefixLength);

            return (rangeLong & mask) == (clientLong & mask);
        } catch (UnknownHostException e) {
            e.printStackTrace();
            return false;
        }
    }
}
