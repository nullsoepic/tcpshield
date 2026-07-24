# <center>TCPShield

A server-side mod that blocks direct connections to Minecraft servers behind TCPShield.

It downloads TCPShield's IP ranges at startup and closes connections from addresses outside the allow-list before the Minecraft handshake.

## Configuration

While made to work with TCPShield, you can use this as a general ip allow-list

```properties
source.1=https://tcpshield.com/v4/
source.2=https://tcpshield.com/v4-cf/

allow-insecure-http=false
cache-max-age-hours=168
connect-timeout-ms=5000
request-timeout-ms=10000
minimum-ipv4-prefix=8
minimum-ipv6-prefix=16
```

Add trusted addresses or CIDRs with `allow.*` entries:

```properties
allow.1=127.0.0.1/32
allow.2=10.20.0.0/16
allow.3=2001:db8:1234::/48
```

Custom `source.*` URLs may also be used. Each source must return plain text with one numeric IP or CIDR per line. Remove the default sources if you want a manual-only allow-list.

<blockquote>
This mod was made primarily for personal use. It is not a replacement for an actual firewall. Netty channels are as early as a mod can realistically block connections, but you know.. you should probably use an actual firewall when possible.
</blockquote>

---

<sub>This project is not endorsed by or affiliated with the TCPShield service. The TCPShield logo and trademark used in the project icon and name are the intellectual property of DatPixel Entertainment, Inc.</sub>
