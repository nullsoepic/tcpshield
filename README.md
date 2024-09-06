# TCPShield

<center>
  <img src="https://cdn.modrinth.com/data/cached_images/2a6a3fda442cad3deea84d74f51b8eb9665b8b23.png" alt="Available for Fabric">
  <a href="https://github.com/nullsoepic/tcpshield"><img src="https://cdn.modrinth.com/data/cached_images/38096c06b1420ee71402de9bfd02e1b2affed8ca.png" alt="See me on Github"></a>
  <a href="https://ko-fi.com/vibing"><img src="https://cdn.modrinth.com/data/cached_images/1c1ecf4b2b68094dc8305cc92776decde6873df8.png" alt="Support me on Ko-fi"></a>

  <br>
  <img src="https://cdn.modrinth.com/data/cached_images/75d1334959fb500ebccac9c71149e24474e5b803.png" alt="If you ask for Forge I will steal your Kneecaps">
</center>

<hr>

A simple Fabric mod to help secure your Minecraft server by blocking incoming connections unless they come from TCPShield proxies.

### Features
- **No Config Needed**: The mod automatically fetches TCPShield proxy ranges.
- **Blocks Early**: Unauthorized connections are blocked at the handshake packet.
- **Just works**: Just drop it in and it's good to go.

### How It Works
The mod pulls TCPShield proxy ranges when your server starts and blocks any incoming traffic that doesn't come from these proxies at the handshake packet.

### Important Note
I'm not affiliated with TCPShield; this is just a passion project to help keep servers secure. I made it because I needed something like it and couldn't find a good option.

### Support
For any issues or questions, please open a GitHub issue on the [GitHub page](https://github.com/nullsoepic/tcpshield/issues/new).