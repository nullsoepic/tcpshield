package me.vibing.tcpshield.mixin;

import me.vibing.tcpshield.core.TCPShield;
import net.minecraft.server.MinecraftServer;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

@Mixin(MinecraftServer.class)
abstract class MinecraftServerMixin {
    @Inject(method = "runServer", at = @At("HEAD"))
    private void tcpshield$initialize(CallbackInfo callback) {
        TCPShield.initialize();
    }
}
