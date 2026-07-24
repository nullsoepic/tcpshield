package me.vibing.tcpshield.mixin;

import io.netty.channel.ChannelHandlerContext;
import me.vibing.tcpshield.core.TCPShield;
import net.minecraft.network.ClientConnection;
import net.minecraft.network.NetworkSide;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

import java.net.InetSocketAddress;
import java.net.SocketAddress;

@Mixin(ClientConnection.class)
abstract class ConnectionMixin {
    @Inject(
            method = "channelActive(Lio/netty/channel/ChannelHandlerContext;)V",
            at = @At("TAIL"),
            remap = false)
    private void tcpshield$authorizeInboundConnection(ChannelHandlerContext context, CallbackInfo callback) {
        ClientConnection connection = (ClientConnection) (Object) this;
        if (connection.getSide() != NetworkSide.SERVERBOUND || connection.isLocal()) {
            return;
        }

        SocketAddress remote = context.channel().remoteAddress();
        if (!(remote instanceof InetSocketAddress socketAddress)
                || socketAddress.getAddress() == null
                || !TCPShield.allows(socketAddress.getAddress())) {
            context.close();
        }
    }
}
