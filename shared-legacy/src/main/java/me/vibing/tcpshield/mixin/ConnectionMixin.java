package me.vibing.tcpshield.mixin;

import io.netty.channel.ChannelHandlerContext;
import me.vibing.tcpshield.core.TCPShield;
import net.minecraft.network.Connection;
import net.minecraft.network.protocol.PacketFlow;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

import java.net.InetSocketAddress;
import java.net.SocketAddress;

@Mixin(Connection.class)
abstract class ConnectionMixin {
    @Inject(
            method = "channelActive(Lio/netty/channel/ChannelHandlerContext;)V",
            at = @At("TAIL"),
            remap = false)
    private void tcpshield$authorizeInboundConnection(ChannelHandlerContext context, CallbackInfo callback) {
        Connection connection = (Connection) (Object) this;
        if (connection.getReceiving() != PacketFlow.SERVERBOUND || connection.isMemoryConnection()) {
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
