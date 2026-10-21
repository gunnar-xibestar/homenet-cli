# DNS

## `homenet dns`

Lists each DNS server and who it likely belongs to:

- the gateway address is **your router**
- a loopback address, such as `127.0.0.53`, is **this computer (local resolver)**. The upstream servers are listed too.
- Cloudflare (`1.1.1.1`, `1.0.0.1`, `2606:4700:4700::/48`), Google (`8.8.8.8`, `8.8.4.4`, `2001:4860:4860::/48`), and Quad9 (`9.9.9.9`, `149.112.112.112`, `2620:fe::/48`) are named public resolvers
- another private or link-local address, such as `192.168.1.2` or `fe80::1`, is **a device on your network**
- any other public address is **likely your internet provider**

The last line is a lookup of `example.com`: whether it succeeded, how long it took, and the address it found. `dns` does not need sudo. It exits 0 even when the lookup fails, so you can read the reason.

```text
DNS servers

Server       Who it is
192.168.1.1  your router
1.1.1.1      Cloudflare (public)
8.8.8.8      Google (public)

Lookup of example.com succeeded in 18.2 ms (93.184.216.34).
```

A local resolver lists the upstream servers under the table:

```text
Server      Who it is
127.0.0.53  this computer (local resolver)

Upstream servers: 192.168.1.1 (your router), 1.1.1.1 (Cloudflare (public)).
```

## See also

- [See the real command](explain.md)
- [Commands](commands.md)
- [README](../README.md)
