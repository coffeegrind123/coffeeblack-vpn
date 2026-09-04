# Transports

Five transports share one admin UI, user roster, auth layer and database. Only Gaming mode
is on by default; each of the others is enabled independently and fails independently.

- [Gaming — AmneziaWG](#gaming--amneziawg)
  - [AmneziaWG 3](#amneziawg-3)
- [Browsing — Xray VLESS + Reality + Vision](#browsing--xray-vless--reality--vision)
- [Telegram — MTProxy via telemt](#telegram--mtproxy-via-telemt)
- [DNS tunnel — MasterDnsVPN](#dns-tunnel--masterdnsvpn)
- [UDP over DNS — QQ-DNS](#udp-over-dns--qq-dns)
- [DNS bundle](#dns-bundle)
- [DPI-imitation proxy](#dpi-imitation-proxy)
- [Which client eats which share format](#which-client-eats-which-share-format)

---

## Gaming — AmneziaWG

Obfuscated WireGuard over UDP. The default transport and the one to reach for first:
lowest latency, full tunnel, and the only one with per-peer L3/L4 firewall rules and live
transfer rates.

The full 2.x obfuscation set is supported: `Jc` / `Jmin` / `Jmax`, `S1`–`S4`, `H1`–`H4`
with non-overlapping ranges, and `I1`–`I5` with CPS tag-grammar validation
(`<b 0xHEX>`, `<r N>`, `<rc N>`, `<rd N>`, `<t>`, `<c>`). `AdvancedSecurity` is a per-peer
opt-in: on, off, or auto-detected from the H1 magic header.

Peers get a `.conf` file, a QR code, or a one-time download link.

**Per-client firewall rules are a Gaming-mode-only feature.** Rules are `IP:port[/tcp|udp]`,
default-deny, and live in an nftables `wg-clients` chain rebuilt atomically in a single
transaction. They do not exist for the other transports and cannot: Xray, telemt and
MasterDnsVPN each multiplex every user through one socket, so per-peer L3/L4 filtering has
nothing to key on — a VLESS UUID, an MTProxy secret and a DNS-tunnel envelope are all
above the layer nftables sees.

### AmneziaWG 3

The bundled `amneziawg-go` and `amneziawg-tools` are 3.x, which adds nine `[Interface]`
keys on top of the 2.x set. All of them are **off by default, and an unset knob emits no
config line at all** — upgrading does not change a single byte of your rendered configs
until you turn one on.

These are set once on the interface (Admin → Interface → *AmneziaWG 3*) and rendered into
both the server config and every peer config, because the values either have to match on
both ends or express the operator's intent for the tunnel as a whole. There is no per-peer
override.

| Knob | What it does | Notes |
|---|---|---|
| **Header protection** | Encrypts the message header with a shared key, using the S1–S4 padding as the cipher nonce, so the low-entropy header fields stop being a fingerprint. | The key is generated server-side and **never displayed**. It is stored AES-256-GCM-encrypted like the device private key and reaches peers only inside their generated config. Requires **every** one of S1–S4 to be ≥ 12, the nonce size; the API rejects the combination rather than letting the interface fail to come up. Re-enabling an already-enabled key does not rotate it. |
| **Random trailers** | Appends a random-length trailer to every packet, so packet sizes stop being a fingerprint. | |
| **Disable cookies** | Stops the server emitting cookie replies, removing that message type from the wire. | Also removes WireGuard's under-load DoS mitigation. |
| **Content padding** | Extra random padding on data packets. | A number or an `N-M` range. |
| **Rekey after / Rekey timeout / Reject after / Keepalive timeout / Max handshake attempts** | Override WireGuard's built-in timers. | A number or an `N-M` range; blank keeps the protocol default. |

Ranges are validated as `N` or `N-M`, each side 0–65535 with `M >= N`. This is not
pedantry: `amneziawg-tools` parses them with `strtoul` into a `uint16_t` and **truncates
silently**, so an unvalidated `70000` would reach the wire as `4464`.

#### Not compatible with the DPI-imitation proxy

**Header protection** and **random trailers** cannot be combined with the
[DPI-imitation proxy](#dpi-imitation-proxy). This is structural, not policy:

- The proxy *rewrites* the S1–S4 padding to imitate QUIC/DNS/STUN/SIP, and that padding is
  the header cipher's nonce. The peer would derive a different keystream and drop every
  packet — and the header the proxy classifies on is itself ciphertext under that key.
- The proxy recognises AmneziaWG handshakes by their **exact** length (`S + 148` for an
  initiation, and so on), so a random trailer makes every handshake look like an
  unauthenticated probe and get answered as one.

The admin API refuses the combination from both directions, the proxy supervisor refuses
to start against an interface with either set, and the config renderer drops them with a
warning if a database ever arrives in that state some other way. The other seven knobs are
unaffected: content padding only grows data packets, which the proxy classifies by a
minimum size, and the timers and cookie switch do not change packet shape at all.

#### If your `awg` is older than 3.x

The admin UI shows a capability badge read from `awg --version`. On a pre-3.x install these
keys would abort interface bring-up as unknown directives, so the section is labelled
accordingly. The Docker image always ships 3.x; a bare-metal install uses whatever
`amneziawg-tools` the distro package provides.

---

## Browsing — Xray VLESS + Reality + Vision

Camouflaged as a real TLS connection to a public CDN host, over TCP/443. Browser-friendly,
and the transport to use when UDP is blocked or throttled. Reality and Vision are
Xray-core extensions and do not exist outside it.

Off by default. To enable:

1. **Admin → Inbound** in the web UI.
2. **Generate** a fresh x25519 keypair.
3. Pick a `dest` from the curated dropdown (default `www.microsoft.com:443`) and hit
   **Probe**. The backend opens a real TLS 1.3 handshake to verify the dest is reachable,
   that the certificate SAN matches the SNI, and that ALPN is `h2`. A probe must come back
   green or the save is refused.
4. Toggle **Enabled** and **Save**. The supervisor extracts the bundled ELF on first run,
   writes `server.json`, and brings up the listener.
5. Switch to **Browsing** in the top nav, **New peer**, and hand over the `vless://` URL
   or QR.

Expose the inbound port on your reverse proxy or cloud firewall. **Keep it on 443** —
Reality on a non-443 port is the single biggest telltale.

Each client gets its own UUID **and** its own `shortId`, so either can be revoked
individually. The supervisor handles SIGHUP reload, SIGTERM with a 10 s grace period, and
capped exponential backoff on crash. A free-form `additional_config` JSON object is
deep-merged into the inbound if you need something the UI does not expose.

### Why bundle the Xray binary?

Reality + Vision is non-trivial and there is no production-quality Rust reimplementation.
Embedding the upstream Go binary and supervising it as a Tokio child gives the
single-binary experience without forking the protocol. The trade-off is binary size and a
version pinned at compile time. Set `XRAY_BIN_PATH` to track upstream yourself.

### What it deliberately does not do

- **No `fallbacks` array.** With Vision and a real `dest`, the camouflage *is* the dest.
- **No GeoIP rules.** An explicit RFC1918 / loopback / ULA blocklist instead, which avoids
  shipping `geoip.dat`.
- **No per-client traffic stats.** Xray's stats API would add gRPC dependencies. The
  AmneziaWG side has live rates from `awg dump`.

### Compatibility with the Amnezia VPN client

The official Amnezia VPN app on iOS, Android, Windows, macOS and Linux **consumes** the
configs generated here — paste the `vless://` URL, scan the QR, or paste the native JSON
from `/api/xray/clients/:id/json`.

It cannot **provision** peers on CoffeeBlack; its self-hosting flow expects SSH access to
a Docker host. That is by design. Peer management lives in the CoffeeBlack admin UI, and
the Amnezia app is one of several supported clients.

---

## Telegram — MTProxy via telemt

Fake-TLS / SNI fronting — the `secret=ee<…>` link variant — for Telegram specifically.
This is not a general-purpose tunnel.

Off by default. To enable:

1. **Admin → Telegram (MTProxy) → Inbound**.
2. Pick a **TLS-front domain**: a popular HTTPS site reachable from this server, such as
   `www.cloudflare.com`. It appears hex-encoded in every Fake-TLS link's secret suffix, so
   **changing it invalidates every previously generated `tg://` link.** Fake-TLS is on by
   default; classic and `dd`-prefix modes are available but off.
3. Set the listen port — default `8080`, to avoid colliding with Xray on 443 — plus
   optional `publicHost` / `publicPort` for the share links. Toggle **Enabled** and
   **Save**.
4. **Telegram → Users → Add user**, then hand over the `tg://proxy?…&secret=ee<…>` link
   or QR.

Unlike Reality, MTProxy on a non-443 port is not a fingerprint. Pick whatever does not
conflict.

CoffeeBlack is the **durable source of truth** for the user roster. The supervisor
reconciles the user table into telemt's `127.0.0.1:9091/v1/users` control plane after every
spawn, so wiping telemt's state file does not lose the operator's users. Subsequent saves
rewrite `config.toml` and telemt's `notify`-based hot-reload picks the changes up without a
restart.

### Why bundle telemt?

MTProto plus Fake-TLS plus middle-end pool integration is non-trivial, and there is no
production-ready Rust MTProxy library. Same trade-off as Xray — except telemt has a real
loopback HTTP control plane (`/v1/users`, `/v1/stats/*`, `/v1/health`), so the supervisor
drives that rather than rewriting `config.toml` on every roster change.

---

## DNS tunnel — MasterDnsVPN

Clients pack encrypted TCP/SOCKS5 traffic into DNS queries through public resolvers; the
server listens on UDP/53 for tunnel envelopes via an NS-delegated subdomain and re-emits
the inner TCP through SOCKS5 or a fixed TCP forwarder. This survives total egress
blackouts where only DNS is allowed.

**Hard prerequisite:** you must own a real domain and create an `NS` delegation pointing a
tunnel subdomain at this server's public IP. There is no way around it.

Off by default. Once the delegation is live:

1. **Admin → DNS Tunnel (MasterDnsVPN) → Inbound**.
2. **Regenerate** to mint a fresh 16-byte shared encryption key.
3. Paste the NS-delegated FQDNs into **Tunnel domains**, one per line. Pick an encryption
   method — XOR for low CPU on weak hardware, AES-256-GCM otherwise — and a protocol type.
   `SOCKS5` lets clients choose the destination per stream; `TCP` forwards everything to a
   fixed `forwardIp:forwardPort`, which is useful for chaining into a Shadowsocks or 3X-UI
   panel.
4. Set the UDP listen port, default 53. Running unprivileged needs `CAP_NET_BIND_SERVICE`
   or a port forward; the shipped compose file's `NET_ADMIN` is already broad enough.
5. Toggle **Enabled** and **Save**.
6. **DNS Tunnel → Clients → Add client**, then hand over `client_config.toml` +
   `client_resolvers.txt`, or the single-string `mdnsvpn://b64?<base64>` blob that pastes
   straight into `mdnsvpn -json_base64`.

**Every client shares one encryption key.** That is a property of the underlying protocol,
not a limitation of this implementation. Per-client rows are pure bookkeeping — display
name, custom resolver list, local SOCKS5 port, expiry. Disabling a client revokes its
config bundle from the download URLs but does **not** break the tunnel for anyone who
already has a copy. Rolling the key with **Regenerate** is what actually revokes every
issued config.

### Why bundle MasterDnsVPN?

The protocol — encrypted fragments packed into DNS labels, ARQ reliability over a UDP-only
transport, MTU discovery across heterogeneous resolvers — is not trivial to reimplement,
and the upstream Go binary is small and already statically linked.

---

## UDP over DNS — QQ-DNS

An in-process Rust port of [QQ-Tunnel](https://github.com/patterniha/QQ-Tunnel) that
carries **raw UDP** — the AmneziaWG datapath itself — inside DNS query names. Where
MasterDnsVPN tunnels TCP/SOCKS5, this tunnels the native WireGuard UDP, so it is
effectively *AmneziaWG-over-DNS*: the low-latency Gaming config, reachable when only port
53 escapes.

It is a symmetric duplex engine, with both ends authoritative for an NS-delegated
subdomain, and it runs as a supervised Tokio task — no subprocess, no bundled blob. It
performs **no AmneziaWG rebind**: it is a side channel onto the existing datapath, so
direct clients keep working unchanged while it is on.

Two limits worth knowing before you deploy it:

- **This is blackout survival, not low latency.** Base32 encoding, fragmentation and
  retries multiply overhead.
- **One instance serves one client endpoint.** The wire format carries no client
  identifier.

The wire format is byte-identical to upstream and pinned by parity tests, so it also
interoperates with the reference Python client. The matching first-party client is a
standalone Rust binary maintained separately.

---

## DNS bundle

Optional, off by default: bundled `dnscrypt-proxy` for DoH/DNSCrypt egress, with optional
`tor` plus lyrebird (obfs4), snowflake or webtunnel pluggable transports. Tor stays off
independently of the dnscrypt-proxy master switch.

It pairs with an nftables `dns-prerouting` chain that DNATs every peer `:53`/`:853` UDP and
TCP packet to the configured resolver, plus an optional `dns-lockdown` filter chain that
drops residual external DNS. Together those give server-enforced leak prevention even when
a client honours the WireGuard `DNS =` line only loosely — which many do.

---

## DPI-imitation proxy

An in-process async UDP proxy that *fronts the AmneziaWG port itself* and rewrites each
packet's S1–S4 padding so the datagrams look like a real **QUIC / DNS / STUN / SIP**
service to deep packet inspection, while answering active protocol probes with valid
responses: QUIC Version Negotiation and a full TLS 1.3 handshake, DNS SERVFAIL or a
forwarded answer, STUN Binding Success, and a stateful SIP dialog.

Unlike the transports above, which move you onto a *different* protocol, this hardens the
native low-latency AmneziaWG datapath in place. Enabling it transparently rebinds
AmneziaWG onto a loopback backend port, confined to `lo` by an nftables `proxy-lockdown`
chain, and the proxy takes the public port. **Client `Endpoint` lines are unchanged.**

Modes are `quic`, `dns`, `stun`, `sip`, or `auto`. It is supervised as a Tokio task with
no subprocess and no bundled blob. Ported in-process from
[wiresock/amneziawg-proxy](https://github.com/wiresock/amneziawg-install), synced to
v0.1.9 — including the global probe-reply byte budget, a source-independent amplification
ceiling that source spoofing cannot refresh, unlike a per-source rate limiter.
Bidirectional imitation is fully unlocked with
[WireSock Secure Connect 3.5+](https://www.wiresock.net/) on the client.

### Detection trade-off

**This is protocol *mimicry*, not a crypto layer, and it is off by default.**

It cannot weaken WireGuard's encryption — the proxy holds no keys and rewrites only the
random junk-padding prefix, never the authenticated region. What it changes is
*detectability*, and the direction depends on who is looking:

- Against **commodity entropy or whitelist DPI and shallow active probers**, it helps.
  Plain AmneziaWG reads as suspicious high-entropy UDP; this does not.
- Against an adversary **fingerprinting this specific tool**, it can make you **more**
  detectable than plain AmneziaWG. The imitation adds fixed protocol markers, and leaves
  AmneziaWG's own handshake-size tells intact underneath.

This is the well-known ["Parrot is Dead"](https://people.cs.umass.edu/~amir/papers/parrot.pdf)
limitation of all unauthenticated mimicry, not a flaw specific to this tool. Prefer `quic`
mode, which has the weakest static signature; `dns` and `sip` carry stronger fixed tells.
Enable it only when you are countering commodity blocking.

See also: [not compatible with header protection or random trailers](#not-compatible-with-the-dpi-imitation-proxy).

---

## Which client eats which share format

| Transport | Share formats | Known-good clients |
|---|---|---|
| Gaming (AmneziaWG) | `.conf` file, QR, one-time link | Amnezia VPN |
| Browsing (Xray) | `vless://` URL (emits both `spx` and `spiderX` for compatibility), QR, native Amnezia-format JSON | Amnezia VPN, v2rayN, v2rayNG, NekoBox, Hiddify, Streisand, Shadowrocket, FoXray |
| Telegram | `tg://proxy?…&secret=ee<…>`, plus `dd`-prefix and classic variants of the same user, QR | Telegram desktop and mobile |
| DNS tunnel | `client_config.toml` + `client_resolvers.txt`, JSON, `mdnsvpn://b64?<base64>`, QR | MasterDnsVPN client |

The web UI carries the same guidance inline, next to each share button.
