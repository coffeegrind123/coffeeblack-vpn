# CoffeeBlack VPN

A standalone, single-binary VPN + censorship-resistant proxy manager with a built-in web UI. Pure Rust port of [wg-easy](https://github.com/wg-easy/wg-easy) / [awg-easy](https://github.com/coffeegrind123/awg-easy) — no Node.js, no npm, no JS toolchain in the container.

Four transports + an optional bundled resolver, all sharing one admin UI, user accounts, session/auth, and SQLite DB:

- **Gaming mode** — [AmneziaWG](https://docs.amnezia.org/documentation/amnezia-wg/) (obfuscated WireGuard over UDP). Low-latency, full-tunnel.
- **Browsing mode** — [Xray](https://github.com/XTLS/Xray-core) VLESS + Reality + Vision over TCP/443. Camouflaged as a real TLS connection to a public CDN host. Browser-friendly. (Reality and Vision are Xray-core extensions and don't exist outside it.)
- **Telegram MTProxy** — [telemt](https://github.com/telemt/telemt) Fake-TLS / SNI fronting (the `secret=ee<…>` link variant). Per-user 32-hex secrets, optional traffic masking. Tokio-supervised; users are reconciled into telemt's `127.0.0.1:9091` HTTP control plane on every spawn.
- **DNS-tunnel mode** — [MasterDnsVPN](https://github.com/masterking32/MasterDnsVPN) DNS-over-DNS tunnel: clients pack encrypted TCP/SOCKS5 traffic into DNS queries through public resolvers, the server listens on UDP/53 for tunnel envelopes (via NS-delegated subdomain) and re-emits the inner TCP through SOCKS5 or a fixed TCP forwarder. Survives total egress blackouts where only DNS is allowed.
- **UDP-over-DNS mode (QQ-DNS)** — an in-process Rust port of [patterniha/QQ-Tunnel](https://github.com/patterniha/QQ-Tunnel) that carries **raw UDP** — the AmneziaWG datapath *itself* — inside DNS query names. Where MasterDnsVPN tunnels TCP/SOCKS5, this tunnels the native WireGuard UDP, so it's *"AmneziaWG-over-DNS"*: the low-latency Gaming config, reachable when only port 53 escapes. Symmetric duplex engine (both ends authoritative for an NS-delegated subdomain); runs as a supervised Tokio task, no subprocess, no blob, and **no AmneziaWG rebind** — it's a side-channel that reaches the existing datapath, so direct clients keep working. The matching client is a standalone `amnezia-client` Rust binary (maintained separately). **Blackout-survival, not low-latency** (base32 + fragmentation + retries multiply overhead), and **one instance = one client endpoint** (the wire format has no client id). Wire format is byte-identical to upstream (pinned by parity tests), so it also interoperates with the reference Python client.
- **DNS bundle (optional)** — bundled [dnscrypt-proxy](https://github.com/DNSCrypt/dnscrypt-proxy) with optional [tor](https://www.torproject.org/) + lyrebird/snowflake/webtunnel pluggable transports for DoH/DNSCrypt egress, plus an nftables `dns-prerouting` DNAT chain that catches peer-side `:53/:853` leaks before they reach the WAN.

- **DPI-imitation proxy (optional)** — an in-process async UDP proxy that *fronts the AmneziaWG port itself* and rewrites each packet's S1–S4 padding so the datagrams look like a real **QUIC / DNS / STUN / SIP** service to Deep Packet Inspection — while answering active protocol probes with valid responses (QUIC Version Negotiation / a full TLS 1.3 handshake, DNS SERVFAIL-or-forwarded-answer, STUN Binding Success, a stateful SIP dialog). Unlike the four transports above (which move you onto a *different* protocol), this hardens the native low-latency AmneziaWG datapath in place. When enabled, AmneziaWG is transparently rebound to a loopback backend port (firewalled to `lo`) and the proxy takes the public port — **client configs are unchanged**. Ported in-process from [wiresock/amneziawg-proxy](https://github.com/wiresock/amneziawg-install) (synced to v0.1.9, incl. the *global probe-reply byte budget* — a source-independent amplification ceiling that source-spoofing can't refresh, unlike the per-source rate limiter); bidirectional imitation is fully unlocked with [WireSock Secure Connect 3.5+](https://www.wiresock.net/) on the client.

  > **Detection trade-off — this is protocol *mimicry*, not a crypto layer, and it is off by default.** It cannot weaken WireGuard's encryption (the proxy holds no keys and rewrites only the random junk-padding prefix; the audit confirms it never touches the authenticated region). What it changes is *detectability*, and the direction depends on the adversary: it **helps** against commodity entropy/whitelist DPI and shallow active probers (where plain AmneziaWG reads as suspicious high-entropy UDP), but against an adversary who fingerprints *this specific tool* it can be **more** detectable than plain AmneziaWG — the imitation adds fixed protocol markers (and leaves AmneziaWG's own handshake-size tells intact underneath). This is the well-known ["Parrot is Dead"](https://people.cs.umass.edu/~amir/papers/parrot.pdf) limitation of all unauthenticated mimicry, not a flaw unique to this tool. Prefer `quic` mode (weakest static signature); `dns`/`sip` carry stronger fixed tells. Enable it only when countering commodity blocking.

- **~20 MB stripped release binary** (musl-static, distro-agnostic — runs unchanged on glibc, musl, or any other libc x86_64 host). Bundled Xray accounts for ~13 MB; telemt adds ~6 MB; MasterDnsVPN adds ~2 MB; the DNS bundle adds another ~20 MB when curated.
- **800+ unit + integration tests** (DB, auth, security, API, activity accounting + retention, AmneziaWG kernel-parity, Xray Reality e2e, telemt + MasterDnsVPN config-gen smoke, plus parity suites pinning every in-house replacement against the crate it replaced — QR symbols, gzip blobs, the QUIC flight, HTTP wire behaviour).
- **Native nftables firewall** — single `inet coffeeblack` table with atomic transactions. Transparent compat shim for hosts still on `iptables-legacy`: detected at startup, three FORWARD/INPUT accept rules mirrored into the legacy backend, removed on graceful shutdown.

---

## Features

| Area | What's included |
|---|---|
| **AmneziaWG 2.0 (Gaming)** | Full obfuscation set: `Jc / Jmin / Jmax`, `S1‑S4`, `H1‑H4` (with non-overlapping ranges), `I1‑I5` (with CPS tag-grammar validation: `<b 0xHEX>`, `<r N>`, `<rc N>`, `<rd N>`, `<t>`, `<c>`). Per-peer `AdvancedSecurity` opt-in (on / off / auto-detect from H1 magic header). **AmneziaWG 3** (built into the image as amneziawg-go v3.1.20260828 + amneziawg-tools v3.1.20260812): header protection (server-generated key, never displayed; enforces the S1–S4 ≥ 12 nonce floor upstream requires), `ContentPaddingAddition`, the `RekeyAfterTime` / `RekeyTimeout` / `RejectAfterTime` / `KeepaliveTimeout` / `MaxHandshakeAttempts` timers (single value or `N-M` range), `RandomTrailers` and `DisableCookies` — all off by default, and an unset knob emits no config line, so an upgraded deployment's wire format is unchanged until you turn one on. Header protection and random trailers are mutually exclusive with the DPI-imitation proxy and the admin API refuses the combination from either side — see [AmneziaWG 3](#amneziawg-3). |
| **Xray VLESS+Reality+Vision (Browsing)** | Bundled Xray-core v26.3.27 ELF (vendored, gzipped, SHA-verified, ~13 MB compressed). Vision flow hardcoded. Per-client UUID **and** per-client `shortId` (revocable individually). TLS 1.3 dest probe with SAN-match enforcement (rejects burned-IP / private-CN destinations before save). Tokio-supervised subprocess: SIGHUP reload, SIGTERM+10s grace shutdown, capped exponential backoff on crash. Free-form `additional_config` JSON deep-merged into the inbound. |
| **Telegram MTProxy** | Bundled [telemt](https://github.com/telemt/telemt) v3.5.5 ELF (vendored, gzipped, SHA-verified, ~6 MB compressed). Fake-TLS / SNI fronting (`secret=ee<…>` link variant), per-user 32-hex secrets, optional `dd`-prefix and classic modes, traffic masking. Tokio-supervised subprocess; users live durably in the coffeeblack-vpn DB and reconcile into telemt's `127.0.0.1:9091` HTTP control plane after every spawn so a telemt state-file wipe doesn't lose the operator's roster. `tg://proxy?…` share links rendered server-side, QR via `qr.rs`. |
| **MasterDnsVPN (DNS-tunnel)** | Bundled [MasterDnsVPN](https://github.com/masterking32/MasterDnsVPN) v2026.06.13 ELF (vendored, gzipped, SHA-verified, ~2 MB compressed). Encryption: XOR / ChaCha20 / AES-128/192/256-GCM (selectable). SOCKS5 or fixed-TCP forwarding. Per-client bookkeeping (display name, custom resolver list, local SOCKS5 port, expiry) — but every client uses the same singleton encryption key (a property of the underlying protocol). Share format: downloadable `client_config.toml` + `client_resolvers.txt`, plus a `mdnsvpn://b64?<base64>` single-string variant for `mdnsvpn -json_base64`. **Requires** the operator to own a domain and create an `NS` delegation to this server. |
| **DNS bundle (optional)** | Bundled `dnscrypt-proxy` 2.1.18 + `tor` 0.4.9.11 + `lyrebird` 0.8.1 (obfs4) + `snowflake` v2.14.1 + `webtunnel` v0.0.6 — ~20 MB additional, curated as static-musl ELFs. Off by default; tor stays off independent of the dnscrypt-proxy master switch. Pairs with an nftables `dns-prerouting` chain that DNATs every peer `:53/:853` UDP+TCP packet to the configured resolver, plus an optional `dns-lockdown` filter chain that drops residual external DNS — gives belt-and-braces leak prevention even when the WireGuard `DNS = …` line is honored only loosely by the client. |
| **Build & release** | Vendored binary blobs (`vendor/*.gz`) are CI artifacts, **not committed**. `vendor/*_VERSION` pin files (versions + SHA-256) are the audited spec. `scripts/build.sh` materialises the blobs from the pin files and produces a fully static `x86_64-unknown-linux-musl` ELF locally; `.github/workflows/build-release.yml` runs the same flow in CI on every push to `main` (or manually) and publishes a release with the binary, SHA-256, and a per-component versions table. |
| **Target** | x86_64 Linux only. arm64 was dropped intentionally — see `vendor/README.md` for the rationale. |
| **Web UI** | Single embedded SPA (HTML + `app.js`). Top-nav Gaming / Browsing toggle, plus admin sub-tabs for Telegram (MTProxy), DNS Tunnel (MasterDnsVPN), and DNS bundle. Live transfer rates (AmneziaWG side), QR codes, one-time download links, admin panels for interface / hooks / general / user-config / Xray inbound / MTProxy inbound + users / DNS Tunnel inbound + clients / DNS bundle. Inline guidance on which client app eats which share format (Amnezia VPN, v2rayN, v2rayNG, NekoBox, Hiddify, Streisand, Shadowrocket, FoXray, Telegram desktop / mobile, MasterDnsVPN client). |
| **Share formats** | AmneziaWG: `.conf` file, QR, one-time link. Xray: `vless://` URL (with both `spx` and `spiderX` for max compat), QR, native Amnezia-format JSON. Telegram: `tg://proxy?…&secret=ee<…>` link (Fake-TLS) + `dd`-prefix and classic variants for the same user, QR. MasterDnsVPN: downloadable `client_config.toml` + `client_resolvers.txt`, JSON, `mdnsvpn://b64?<base64>` single-string blob (for `mdnsvpn -json_base64`), QR. |
| **Peer key handling** | Private keys are **issued once and not stored** by default (`private_key_retention = never`): the config + QR come back in the create response and can never be re-displayed, so a compromise of the database yields no peer keys. Optional `plaintext` mode restores upstream re-display behaviour behind a permanent admin banner; switching back purges. Peers may also **bring their own public key**, so the server never sees a private half at all. `rotateKey` is the recovery and revocation path. See [Peer private keys](#peer-private-keys-issued-once-not-stored). |
| **Auth** | Argon2id password hashing, server-side session cookies (`SameSite=Strict`, `HttpOnly`, `Secure` unless `INSECURE=true`). Per-username (10/min) **and** per-source-IP (50/min) login rate limit. Constant-time username-not-found path (no enumeration via timing). |
| **Secrets at rest** | Every stored credential is AES-256-GCM encrypted **when `COFFEEBLACK_SECRET_KEY` (or `COFFEEBLACK_SECRET_KEY_PATH`) is set** — it is not set by the shipped `docker-compose.yml`, and without it these columns are stored in cleartext with a warning at startup — peer private and pre-shared keys, the server's WireGuard key, the Reality key, VLESS UUIDs/shortIds, MTProxy secrets, the DNS-tunnel key, TOTP seeds — with the full list in one auditable registry. One-time-link tokens are stored as SHA-256 digests. Generated transport configs are written `0600` in `0700` dirs (they were world-readable). See [Generated config files](#generated-config-files) and [Secret encryption](#secret-encryption-at-rest). |
| **2FA / TOTP** | Server-generated 20-byte secrets, **encrypted at rest** (AES-256-GCM, key supplied out of band via systemd credentials or env — see [Secret encryption](#secret-encryption-at-rest)), RFC 6238 verification, separate 5/5min rate limit on TOTP code attempts. `setup` / `create` / `delete` API contract. |
| **Setup wizard** | 4-step first-run flow. `INIT_ENABLED` env-var auto-setup for Kubernetes/CI deployments. |
| **DPI-imitation proxy** | In-process async UDP proxy (ported from [amneziawg-proxy](https://github.com/wiresock/amneziawg-install)) fronting the AmneziaWG port. Protocol modes `quic` / `dns` / `stun` / `sip` / `auto`; per-packet S1–S4 padding transform driven by the interface's live S/H params; active-probe responders including a stateful `quinn-proto` QUIC/TLS-1.3 handshake responder (self-signed per-SNI cert) and a stateful SIP dialog machine; optional real DNS-upstream forwarding. Supervised as a Tokio task (no subprocess, no blob). Enabling it rebinds AmneziaWG onto a loopback backend port + an nftables `proxy-lockdown` input chain confining that port to `lo`; client `Endpoint` lines are untouched. |
| **Per-client firewall** | Native nftables `wg-clients` chain inside the `inet coffeeblack` table. `IP:port[/tcp\|udp]` rules, default-deny, atomic rebuild via a single `nft -f -` transaction. (AmneziaWG side only; Xray, telemt, and MasterDnsVPN multiplex through one socket each, so per-peer L3/L4 filtering doesn't compose with VLESS UUIDs / MTProxy secrets / DNS-tunnel envelopes.) |
| **Metrics** | `/metrics/json` and `/metrics/prometheus`, gated by hashed Bearer token (when `metricsPassword` is set). Exposes per-peer rx/tx, last-handshake, online state, plus the poller's `wireguard_peer_total_rx_bytes` / `_total_tx_bytes` counters (unaffected by the interface restarts that zero the raw ones) and `wireguard_peer_last_seen`. |
| **Activity history (RAM-only)** | 30 s poller folds `awg show dump` into monotonic per-peer lifetime totals (immune to the counter reset an interface restart causes) and a bounded one-bucket-per-peer-per-UTC-day rollup. Drives a GitHub-contribution-style heatmap on the clients page — shaded by time connected or by traffic volume, 30/60/90-day windows. **None of it enters SQLite**: connection history is held in process memory, so no `IN_MEMORY=false` or `COFFEEBLACK_PERSIST_DB` setting can turn it into an on-disk record. The peer's **source address is never recorded** — the live endpoint is shown straight from the kernel but never accumulated into history. Retention is operator-set (default 30 days); `0` disables collection **and** purges, plus an explicit *Erase activity history* action. See [Activity history](#activity-history-and-the-connection-heatmap). |
| **Privilege separation** | Optional `--privileged-helper` mode: a root helper on a Unix socket serving a **fixed six-operation allowlist** as argument vectors, with the interface name and all paths fixed at startup and never read from a request. The web process then runs unprivileged with no `CAP_NET_ADMIN`, so an RCE in the HTTP layer no longer means root. Ported from [islandr-proxy](https://github.com/chriscohnen/islandr)'s model. See [Privilege separation](#privilege-separation-optional). |
| **Operational** | Background cron expires clients/one-time-links every 60 s. `/health` endpoint (always 200). Persistent SQLite (WAL mode, foreign keys on). Idempotent schema migrations. |
| **Run-in-RAM mode** | `IN_MEMORY=true` (default in the Docker image): `:memory:` SQLite + every bundled subprocess ELF exec'd from an anonymous, sealed `memfd` — nothing on the request path or `exec` path touches disk. Optional async snapshot/restore (`COFFEEBLACK_PERSIST_DB`) keeps the roster across restarts without ever blocking the data plane on a failing disk. See [Run entirely in memory](#run-entirely-in-memory). |

---

## Quick start

### Docker

```bash
docker compose up -d
```

Open `https://YOUR_HOST:51821/` (place a reverse proxy in front — see [TLS](#tls)).

### Prebuilt binary

Each push to `main` produces a tagged release with a fully-static `coffeeblack-vpn` ELF on the [Releases page](https://github.com/coffeegrind123/coffeeblack-vpn/releases). The binary runs on any x86_64 Linux distro — no glibc / musl mismatch:

```bash
curl -fsSL -o /usr/local/bin/coffeeblack-vpn \
  https://github.com/coffeegrind123/coffeeblack-vpn/releases/latest/download/coffeeblack-vpn
chmod +x /usr/local/bin/coffeeblack-vpn
sudo /usr/local/bin/coffeeblack-vpn
```

The release page lists SHA-256 hashes and the version of every bundled component (Xray, telemt, dnscrypt-proxy, tor, etc.) sourced from the `vendor/*_VERSION` pin files at build time.

### Bare-metal install (systemd)

For a host install without Docker, `scripts/install.sh` provisions the AmneziaWG kernel module (DKMS via the distro's package repos), installs the `coffeeblack-vpn` binary, and runs it as a systemd service:

```bash
curl -O https://raw.githubusercontent.com/coffeegrind123/coffeeblack-vpn/main/scripts/install.sh
chmod +x install.sh
sudo ./install.sh              # guided; or: sudo AUTO_INSTALL=y ./install.sh
```

Supports Debian ≥11 / Ubuntu ≥22.04 / Mint ≥21 (Fedora/RHEL-family code paths are present but gated until verified AmneziaWG 2.0 RPMs ship). Subcommands: `install` / `upgrade` / `uninstall` / `status`. Migrating a pre-2.0 on-disk AmneziaWG server? `scripts/migrate-pre2.sh` backfills S3/S4 and converts H1–H4 to non-overlapping ranges in place, with `.bak` backup and rollback. Full reference: [`docs/INSTALL.md`](docs/INSTALL.md).

### First-run

The setup wizard prompts for an admin user, host endpoint, and AmneziaWG parameters (auto-generated). Or pre-populate via env vars:

```yaml
environment:
  - INIT_ENABLED=true
  - INIT_USERNAME=admin
  - INIT_PASSWORD=use-a-real-password-please
  - INIT_HOST=vpn.example.com
  - INIT_PORT=51820
```

---

## Configuration

All configuration is via environment variables.

### Server

| Variable | Default | Description |
|---|---|---|
| `PORT` | `51821` | Web UI listen port |
| `HOST` | `0.0.0.0` | Web UI bind address |
| `INSECURE` | `false` | If `true`, drops the `Secure` flag from the session cookie. **Only set this when running on a trusted local network without TLS.** Production deployments should leave this `false` and terminate TLS upstream. |
| `DISABLE_IPV6` | `false` | Skip IPv6 in generated configs / firewall rules |
| `COFFEEBLACK_DB_PATH` | `/etc/coffeeblack/conf/coffeeblack.db` | SQLite database path |
| `COFFEEBLACK_HELPER_SOCKET` | — | Path to the privileged helper's Unix socket. Set it and this process routes every `awg`/`nft` call and the interface config write through the helper, needing no capabilities itself. Unset means execute directly (the original behaviour). |
| `COFFEEBLACK_HELPER_INTERFACE` | `cb0` | Helper only: the one interface it will act on. Never read from a request. |
| `COFFEEBLACK_HELPER_GID` | — | Helper only: gid allowed to connect. Sets the socket to 0660 and chowns it to that group; unset leaves it 0600 (root only). |
| `COFFEEBLACK_SECRET_KEY_PATH` | — | Path to a file holding the base64 AES-256 key used to encrypt secrets at rest (TOTP seeds). Intended for `LoadCredentialEncrypted=` under systemd. Takes precedence over `COFFEEBLACK_SECRET_KEY`. |
| `COFFEEBLACK_SECRET_KEY` | — | The base64 AES-256 key itself (32 bytes: `openssl rand -base64 32`). For Docker/dev. Unset means secrets are stored in plaintext, with a startup warning. |
| `COFFEEBLACK_CONF_DIR` | `/etc/coffeeblack/conf` | Where the generated `cb0.conf` is written |
| `COFFEEBLACK_XRAY_DIR` | `<COFFEEBLACK_CONF_DIR>/xray` | Where the bundled Xray ELF is extracted and `server.json` written. Persist this on a docker volume so the binary doesn't re-extract on every restart. |
| `XRAY_BIN_PATH` | — | If set, the supervisor uses this `xray` binary instead of extracting the bundled one. Useful for operators tracking upstream Xray independently of coffeeblack-vpn releases. |
| `COFFEEBLACK_MTPROXY_DIR` | `<COFFEEBLACK_CONF_DIR>/mtproxy` | Where the bundled `telemt` ELF is extracted, plus the generated `config.toml`, telemt's PID file, and the `tlsfront` cache (real TLS records fetched from the masking domain). Persist on a docker volume to avoid re-extraction + tlsfront rebuilds across restarts. |
| `COFFEEBLACK_DNS_DIR` | `<COFFEEBLACK_CONF_DIR>/dns` | Where the bundled DNS-stack ELFs (dnscrypt-proxy, tor, lyrebird, snowflake, webtunnel) are extracted, plus generated configs (`dnscrypt-proxy.toml`, `torrc`, etc.) and tor's data directory. Persist to keep tor's onion descriptors / consensus across restarts. |
| `COFFEEBLACK_MDNSVPN_DIR` | `<COFFEEBLACK_CONF_DIR>/mdnsvpn` | Where the bundled MasterDnsVPN ELF is extracted, plus the generated `server_config.toml` and the singleton `encrypt_key.txt`. Persist on a docker volume to avoid re-extraction across restarts. |

### Run entirely in memory

| Variable | Default | Description |
|---|---|---|
| `IN_MEMORY` | `true` (set `IN_MEMORY=false` to opt out) | Run with the data plane fully RAM-resident. SQLite is opened `:memory:`, and every bundled subprocess ELF (Xray, telemt, MasterDnsVPN, dnscrypt-proxy, tor) is exec'd from an anonymous `memfd_create(2)` object instead of being written to disk. No query and no `exec` touches a block device. Set `IN_MEMORY=false` for the classic durable on-disk database under `COFFEEBLACK_DB_PATH`. |
| `COFFEEBLACK_PERSIST_DB` | — (`/data/coffeeblack.db` in the image) | Durable snapshot file for the RAM database. Restored on boot (the only time it's read) and re-written by a background task + on graceful shutdown via SQLite's online-backup API. Unset ⇒ pure RAM, state lost on restart. Only consulted when `IN_MEMORY=true`. |
| `COFFEEBLACK_PERSIST_INTERVAL` | `30` | Seconds between RAM→disk snapshots. `0` disables periodic snapshots (shutdown still snapshots). |

When `IN_MEMORY=true`:

- **Database** — `:memory:`, so no SQLite query ever blocks on disk. If `COFFEEBLACK_PERSIST_DB` is set, the full roster (clients, Reality keys, MTProxy secrets, the MasterDnsVPN key, accounts, 2FA) is restored from that file at boot and snapshotted back out-of-band. Every snapshot is best-effort and off the request path — a degraded or read-only disk demotes you to "no fresh snapshot", it never stalls or crashes the data plane. This is the WireGuard property the mode is built for: the service comes up and stays up from RAM regardless of disk health.
- **Subprocess binaries** — decompressed, SHA-256-verified, and sealed (`F_SEAL_WRITE`) inside an anonymous memfd, then exec'd via `/proc/self/fd/N`. The binary has no name in any filesystem and is immutable. The memfd is cached for the process lifetime, so a crash-looping child re-`exec`s the same in-RAM image with zero re-extraction. (`XRAY_BIN_PATH` still overrides Xray with a real on-disk binary if you want to track upstream yourself.)
- **Config files / `.conf` / tor data dir / PT plugins** — these still need real paths (tor `exec`s its lyrebird/snowflake/webtunnel plugins by the path written into `torrc`, and `awg-quick` reads `/etc/coffeeblack/conf/<iface>.conf`). Mount the runtime root (`COFFEEBLACK_CONF_DIR`, default `/etc/coffeeblack/conf`) as a **tmpfs** so those live in RAM too. The bundled `docker-compose.yml` does exactly that (`tmpfs: /etc/coffeeblack/conf`, durable volume only at `/data`). The server logs a warning at startup if `IN_MEMORY=true` but the runtime root isn't tmpfs.

No extra Linux capabilities are required — memfd needs none, and the tmpfs is supplied by the container runtime, so the cap set stays `NET_ADMIN` alone — the shipped `docker-compose.yml` does `cap_drop: ALL` and re-adds only that. (`SYS_MODULE` was dropped: it let the container load kernel modules into the host kernel, and amneziawg-go is userspace, so it was never needed.)

### First-run auto-setup

These take effect only when no admin user exists. They make `INIT_ENABLED=true` deployments idempotent — restarting the container with the same env doesn't recreate the user.

| Variable | Default | Description |
|---|---|---|
| `INIT_ENABLED` | `false` | Master switch for the auto-setup |
| `INIT_USERNAME` | — | Initial admin username (required when `INIT_ENABLED=true`) |
| `INIT_PASSWORD` | — | Initial admin password (≥12 chars; required when `INIT_ENABLED=true`). A shorter value is rejected and the server refuses to start rather than leaving the setup wizard open. |
| `INIT_HOST` | — | WireGuard endpoint hostname (DNS or IP) |
| `INIT_PORT` | `51820` | WireGuard listen port |
| `INIT_DNS` | — | Comma-separated DNS servers pushed to clients |
| `INIT_IPV4_CIDR` | `10.8.0.0/24` | IPv4 pool for clients |
| `INIT_IPV6_CIDR` | `fdcc:ad94:bacf:61a4::cafe:0/112` | IPv6 pool for clients |
| `INIT_ALLOWED_IPS` | — | Comma-separated default `AllowedIPs` for clients |

### Runtime tunables (admin UI)

Stored in SQLite, editable via the admin panel:

- `metricsPrometheus`, `metricsJson`, `metricsPassword` (hashed)
- `sessionTimeout` (seconds)
- `privateKeyRetention` — `never` (default, keys issued once and never stored) or `plaintext` (stored, re-displayable). Switching to `never` erases the keys already held.
- `activityRetentionDays` — days of in-memory per-peer activity history to keep (0-365, default 30; `0` disables collection and purges). The only part of the feature that is persisted, and deliberately so — see below.
- AmneziaWG params (Jc/Jmin/Jmax, S1-S4, H1-H4, I1-I5)
- AmneziaWG 3 device knobs (header protection, content padding, five timers, random trailers, disable cookies) — see [AmneziaWG 3](#amneziawg-3)
- Per-client `AdvancedSecurity` (on / off / auto)
- Per-client firewall rules
- Free-form `additional_config` append for AmneziaWG `[Interface]` (server + per-peer)
- DNS lockdown (master switch + redirect target IP + drop-residual toggle)
- Xray Reality inbound (port, dest, server names, fingerprint, additional_config) and per-peer expiry / additional config
- MTProxy inbound (port, public host/port, TLS-front domain, mask toggle, mode flags, use_middle_proxy, default ad_tag, additional_config) and per-user secret + ad_tag override + enabled state
- DNS bundle (master switch, listen port, upstream resolvers, DNSSEC/no-log/no-filter requirements, optional Tor SOCKS routing with exit-country selectors and pluggable-transport choice)

---

## AmneziaWG 3

The bundled `amneziawg-go` / `amneziawg-tools` are 3.x, which adds nine
`[Interface]` keys on top of the 2.x junk-and-magic-header set. All of them are
**off by default, and an unset knob emits no config line at all** — upgrading
does not change a single byte of your rendered configs until you turn one on.
Everything below is set once on the interface (admin UI → Interface →
*AmneziaWG 3*) and is rendered into both the server config and every peer
config, because the values either have to match on both ends or are the
operator's intent for the tunnel as a whole. There is no per-peer override.

| Knob | What it does | Notes |
|---|---|---|
| **Header protection** | Encrypts the message header with a shared key, using the S1–S4 padding as the cipher nonce — the low-entropy header fields stop being a fingerprint. | The key is generated server-side and **never displayed**; it is stored AES-256-GCM-encrypted like the device private key, and reaches peers only inside their generated config. Requires **every** one of S1–S4 to be ≥ 12 (the nonce size); the API rejects the combination rather than letting the interface fail to come up. Re-enabling an already-enabled key does not rotate it. |
| **Random trailers** | Appends a random-length trailer to every packet, so packet sizes stop being a fingerprint. | |
| **Disable cookies** | Stops the server emitting cookie replies, removing that message type from the wire. | Also removes WireGuard's under-load DoS mitigation. |
| **Content padding** | Extra random padding on data packets. | Number or `N-M` range. |
| **Rekey after / Rekey timeout / Reject after / Keepalive timeout / Max handshake attempts** | Override WireGuard's built-in timers. | Number or `N-M` range; blank keeps the protocol default. |

Ranges are validated as `N` or `N-M`, each side 0–65535 with `M >= N`, because
`amneziawg-tools` parses them with `strtoul` into a `uint16_t` and **truncates
silently** — `70000` would otherwise reach the wire as `4464`.

### Not compatible with the DPI-imitation proxy

**Header protection** and **random trailers** cannot be combined with the
[DPI-imitation proxy](#features). This is structural, not policy:

- the proxy *rewrites* the S1–S4 padding to imitate QUIC/DNS/STUN/SIP, and that
  padding is the header cipher's nonce — the peer would derive a different
  keystream and drop every packet (the header the proxy classifies on is
  ciphertext under that key too);
- the proxy recognises AmneziaWG handshakes by their **exact** length
  (`S + 148` for an initiation, and so on), so a random trailer makes every
  handshake look like an unauthenticated probe and get answered as one.

The admin API refuses the combination from both directions, the proxy
supervisor refuses to start against an interface that has either set, and the
config renderer drops them (with a warning) if a database ever arrives in that
state some other way. The other seven knobs are unaffected: content padding
only grows data packets, which the proxy classifies by a minimum size, and the
timers and cookie switch don't change packet shape at all.

### If your `awg` is older than 3.x

The admin UI shows a capability badge read from `awg --version`. On a
pre-3.x install these keys would abort interface bring-up as unknown
directives, so the section is labelled accordingly — the Docker image always
ships 3.x, but a bare-metal install uses whatever `amneziawg-tools` the distro
package provides.

---

## Browsing mode (Xray VLESS+Reality+Vision)

Browsing mode is **off by default**. To enable it:

1. Open **Admin → Inbound** in the web UI.
2. Click **Generate** to produce a fresh x25519 keypair.
3. Pick a `dest` from the curated dropdown (default: `www.microsoft.com:443`) and click **Probe** — the backend opens a real TLS 1.3 handshake to verify the dest is reachable, the cert SAN matches the SNI, and ALPN is `h2`. Probes must come back green or save will fail.
4. Toggle **Enabled** and **Save**. The supervisor extracts the bundled Xray ELF on first run, writes `server.json`, and brings up the listener.
5. Switch to **Browsing** in the top nav, click **New peer**, hand the user the `vless://` URL or QR.

Expose the inbound port (default `443/tcp`) on your reverse proxy / cloud firewall for clients to reach. Reality runs on port 443 by design — non-443 ports are the #1 telltale.

### Why bundle the Xray binary?

Reality + Vision is non-trivial and there's no production-quality Rust reimplementation. Embedding the upstream Go binary as a `include_bytes!` blob and supervising it as a tokio child process gives the "single binary" UX without forking the protocol. The trade-off is a 15 MB binary-size increase and a Xray version that's pinned at compile time. Operators who want to track upstream Xray independently can set `XRAY_BIN_PATH` to their own `xray`.

### What it doesn't do

- **No `fallbacks` array** — surveyed every focused Reality reference impl; with Vision + a real `dest`, the camouflage *is* the dest.
- **No GeoIP rules** — explicit RFC1918/loopback/ULA blocklist (avoids needing to ship `geoip.dat`).
- **No per-client traffic stats** — Xray's stats API is enableable but adds gRPC dependencies; deferred. AmneziaWG side has live rates via `wg dump`.

### Compatibility with the Amnezia VPN client

The official Amnezia VPN app (iOS/Android/Win/Mac/Linux) **consumes** the configs we generate via:

1. Paste `vless://` URL → "Add server → Configuration file or text"
2. Scan QR
3. Paste the native JSON we expose at `/api/xray/clients/:id/json`

It cannot **provision** peers on coffeeblack-vpn (its self-hosting flow expects SSH access to a Docker host). That's by design — peer management lives in the coffeeblack-vpn admin UI; the Amnezia app is just one of several supported clients.

---

## Telegram MTProxy (telemt)

Telemt is **off by default**. To enable it:

1. Open **Admin → Telegram (MTProxy) → Inbound** in the web UI.
2. Pick a **TLS-front domain** (a popular HTTPS site reachable from this server — `www.cloudflare.com`, `petrovich.ru`, etc.). The domain shows up hex-encoded in every Fake-TLS link's secret suffix; changing it invalidates all previously generated `tg://` links. Fake-TLS mode is on by default; classic / `dd`-prefix modes are off but available.
3. Set the listen port (default `8080` to avoid the 443 collision with Xray Reality) and optional `publicHost` / `publicPort` for the share links. Toggle **Enabled** and **Save** — telemt extracts on first start, writes `config.toml`, and brings up the listener. Subsequent saves rewrite `config.toml`; telemt's `notify`-based hot-reload picks up changes without a restart.
4. Switch to **Telegram → Users**, click **Add user**, and hand over the auto-generated `tg://proxy?…&secret=ee<…>` link or QR.

Coffeeblack-vpn is the **durable source of truth** for the user roster. The supervisor reconciles `mtproxy_users_table` into telemt's `127.0.0.1:9091/v1/users` HTTP control plane after every spawn, so a telemt state-file wipe doesn't lose the operator's users — same model as Xray's per-peer UUID/shortId lifecycle.

Expose the listening port on your reverse proxy / cloud firewall for Telegram clients to reach. Unlike Xray Reality, MTProxy on a non-443 port isn't a fingerprint; pick whatever doesn't conflict.

### Why bundle telemt?

Telemt's MTProto + Fake-TLS + middle-end pool integration is non-trivial and there's no Rust-native MTProxy library that's actually production-ready. Embedding a pinned static-musl ELF + supervising via tokio gives the "single binary" UX without forking the protocol — same trade-off Xray made, except telemt has a real loopback HTTP control plane (`/v1/users`, `/v1/stats/*`, `/v1/health`) so the supervisor only needs to drive that rather than rewrite `config.toml` on every roster change.

---

## DNS-tunnel mode (MasterDnsVPN)

MasterDnsVPN is **off by default** — and unlike the other transports it has a hard infrastructure prerequisite: you need to own a real domain and create an `NS` delegation pointing a tunnel subdomain at this server's public IP. There's no way to short-cut that. The upstream README walks through the DNS-record setup; once it's live:

1. Open **Admin → DNS Tunnel (MasterDnsVPN) → Inbound** in the web UI.
2. Click **Regenerate** to mint a fresh 16-byte shared encryption key. The same key is baked into every client's `client_config.toml` (MasterDnsVPN has no per-user secret slot — that's a property of the underlying protocol).
3. Paste the NS-delegated FQDN(s) into **Tunnel domains** (one per line). Pick an encryption method (XOR for low CPU on weak hardware, AES-256-GCM otherwise) and a protocol type — `SOCKS5` lets clients pick the destination per-stream; `TCP` forwards every connection to a fixed `forwardIp:forwardPort` (useful for chaining mdnsvpn into a Shadowsocks / 3X-UI panel).
4. Set the UDP listen port (default 53). On hosts where coffeeblack-vpn runs unprivileged, the binary needs `CAP_NET_BIND_SERVICE` or a port-forward (since :53 is privileged); on a `docker compose up -d` deployment the default `cap_add: NET_ADMIN` is already broad enough.
5. Toggle **Enabled** and **Save** — mdnsvpn extracts on first start, writes `server_config.toml` + `encrypt_key.txt`, and binds the UDP listener.
6. Switch to **DNS Tunnel → Clients**, click **Add client**, and hand over the auto-generated `client_config.toml` + `client_resolvers.txt` (or the single-string `mdnsvpn://b64?<base64>` blob — paste straight into `mdnsvpn -json_base64 <blob>` on the client side).

Coffeeblack-vpn is the **bookkeeping source of truth** for the client roster — but MasterDnsVPN itself authenticates every tunnel with the singleton encryption key, so per-client rows are pure UX state (share-link slot, expiry, enabled toggle). Disabling a client in the admin UI revokes its config bundle from the download URLs but doesn't break the underlying tunnel for someone who already has a copy; rolling the encryption key (**Regenerate**) is what revokes every issued config.

### Why bundle MasterDnsVPN?

The custom protocol — packed encrypted fragments stuffed into DNS labels, ARQ-based reliability over a UDP-only transport, MTU discovery across heterogeneous resolvers — isn't trivial to reimplement, and the upstream Go binary is small (~2 MB compressed) and already statically linked. Embedding it + supervising via tokio matches the Xray and telemt pattern: "single binary" UX without forking the protocol. The trade-off is the same as the others — bundled version is pinned in `vendor/MDNSVPN_VERSION` and bumped via `vendor/update.sh mdnsvpn <ver>`.

---

## TLS

The binary ships **without** TLS termination — put a reverse proxy in front of it. Caddy is the easiest:

```caddy
vpn.example.com {
    reverse_proxy coffeeblack-vpn:51821
}
```

Or nginx:

```nginx
server {
    listen 443 ssl http2;
    server_name vpn.example.com;
    ssl_certificate /etc/letsencrypt/live/vpn.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/vpn.example.com/privkey.pem;
    location / {
        proxy_pass http://127.0.0.1:51821;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Real-IP       $remote_addr;
    }
}
```

The login rate limiter honours `X-Forwarded-For` / `X-Real-IP` for per-source-IP buckets — set them on the proxy so individual IPs are throttled correctly.

If you really must run without a proxy on a trusted network: set `INSECURE=true`. **Do not** leave that on for an Internet-facing deployment — the session cookie then travels over plain HTTP and any on-path observer steals the session.

---

## Upgrades

coffeeblack-vpn is a **standalone project** — not a drop-in for upstream `awg-easy` (Node.js) or `wg-easy`. It runs against its own SQLite database at `/etc/coffeeblack/conf/coffeeblack.db` (override via `COFFEEBLACK_DB_PATH`).

For upgrades between coffeeblack-vpn versions, idempotent `ALTER TABLE` migrations apply on first boot; no manual DDL.

---

## Building from source

The toolchain is pinned by [`rust-toolchain.toml`](rust-toolchain.toml) (currently **1.98.1**); rustup installs that exact stable automatically when you build in the repo, so CI, dev machines, and the Docker builder all compile with the same `rustc`. The code itself needs 1.80+ (`LazyLock`, `OnceLock`, edition 2021).

### Dependency policy (frozen + gated)

Builds are reproducible down to the crate: [`Cargo.lock`](Cargo.lock) is committed, and every build path (`Dockerfile`, `scripts/install.sh`, CI) passes `--locked` so a build **fails** rather than silently resolving to versions that weren't tested. A [`deny.toml`](deny.toml) enforced by [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny) in CI is the "known-good versions" gate — it fails on any RUSTSEC advisory, a yanked crate, a license outside an explicit allowlist, an unexpected duplicate crate version, or a non-crates.io source. Run it locally with:

```bash
cargo deny check
```

The tree is deliberately lean — **69 crates in the release build, with no crate present at two versions** — because most of what a project like this would normally pull in is a general-purpose library used through one narrow corner. Where that corner is small and testable against the crate it replaces, it lives here instead:

| In-house | Replaces | Why |
|---|---|---|
| `src/http/` — HTTP/1.1 server, router, extractors, responses, cookies, query deserializer | `axum`, `hyper`, `tower`, `axum-extra` (~32 crates) | The panel speaks plaintext HTTP/1.1 behind a reverse proxy, with in-memory bodies of a few kilobytes. The parser is deliberately strict where request smuggling lives (no obs-fold, no `Content-Length` + `Transfer-Encoding`, no conflicting lengths, explicit limits and timeouts) and `tests/http_server.rs` drives those cases as raw bytes over TCP. `http` itself is kept: it is the ecosystem's shared `Request`/`Response`/`HeaderMap` and costs one crate. |
| `src/proxy/quic_handshake.rs` + `src/proxy/x509.rs` — QUIC v1 packet layer and self-signed certificates | `quinn-proto`, `rcgen` (14 crates) | The DPI responder emits one server flight and forgets the peer; it never needs congestion control, loss recovery or streams. rustls's `quic` module supplies the Initial key schedule, header protection and the TLS state machine. `quinn-proto` stays a **dev-dependency**, and a real QUIC client must accept our flight for the tests to pass. |
| `src/qr.rs` — QR encoder (byte mode, level M, ISO/IEC 18004) | `qrcode` | `tests/qr_parity.rs` asserts our symbol is module-for-module identical to the crate's, and the rendered SVG byte-for-byte identical. The crate stays a dev-dependency as the reference. |
| `src/inflate.rs` — gzip/DEFLATE decoder | `flate2`, `miniz_oxide`, `adler2`, `crc32fast`, `simd-adler32` | The only runtime use was expanding the vendored ELFs; nothing compresses outside tests. `tests/vendor_blobs.rs` decompresses every real `vendor/*.gz` and checks the SHA-256 against its pin file. |
| `src/log.rs` — level filter, formatter, `RUST_LOG` parsing, event macros | `tracing`, `tracing-subscriber` (~11 crates, including a regex engine for `EnvFilter`) | The codebase never opens a span; every call site is a flat event. |
| `src/proxy/shardmap.rs` — sharded concurrent map | `dashmap`, `crossbeam-utils` | Over `parking_lot`, which tokio already compiles in. |
| `src/cidr.rs`, `src/encoding.rs`, `src/rng.rs::uuid_v4`, hand-written error impls | `ipnet`, `hex`, `base64`, `uuid`, `thiserror` | Each was a few dozen lines used through a handful of calls. Base64 now comes from `base64ct`, which argon2 already compiles in. |

Earlier passes did the same for 2FA (hand-rolled HMAC-SHA1 TOTP over `hmac`/`sha1` rather than a TOTP crate dragging in the `url`/ICU stack), the Reality dest-probe's certificate SAN extraction (a small in-house DER walk instead of a full X.509 parser), date handling (`time` rather than a second `chrono` tree) and randomness (the OS CSPRNG via `getrandom`, see `src/rng.rs`, instead of the `rand` userspace generator).

Two consequences worth stating plainly:

- **QR codes for payloads with long digit runs may be one version larger.** The `qrcode` crate ran a segment optimiser that could encode a run of digits in numeric mode; ours is byte-mode only. The AmneziaWG config, `vless://` and `mdnsvpn://` payloads are unaffected (they are mixed-case throughout, so the optimiser chose byte mode too); a `tg://proxy` link with a 70-hex-digit secret renders at 49 modules instead of 45. Both scan.
- **The HTTP server is ours now.** It is the most exposed code in the project. It is strict by construction (see `src/http/server.rs`), covered by wire-level tests, and unchanged in behaviour for every route the panel serves — but it is a hand-written parser on an internet-facing port, and it should be read as such. Keep the reverse proxy in front of it.

The bundled binary blobs (`vendor/*.gz`) are **not** committed to the repo — they're CI artifacts produced from the audited pin files in `vendor/*_VERSION`. To get a fully-bundled release binary, run:

```bash
scripts/build.sh
```

That:

1. Reads each pinned version from `vendor/{XRAY,DNS_BUNDLE,TELEMT}_VERSION`.
2. Materialises `vendor/<name>-linux-amd64.gz` for each entry by delegating to `vendor/update.sh` (downloads pre-built artifacts where upstream publishes them; builds from source in Alpine Docker for `tor` and the Go pluggable transports). Skips binaries whose `.gz` already round-trips to the pinned SHA.
3. Builds coffeeblack-vpn as a fully static **x86_64-linux-musl** ELF (`target/x86_64-unknown-linux-musl/release/coffeeblack-vpn`, ~18 MB stripped, runs unchanged on glibc / musl / any libc).

For the workflow that does the same thing in CI + publishes a release, see [`.github/workflows/build-release.yml`](.github/workflows/build-release.yml).

For a quick iterating-on-Rust loop without re-fetching upstreams, the .gz blobs can stay on disk between runs:

```bash
scripts/build.sh --cargo-only          # use cached vendor blobs
scripts/build.sh --skip tor --skip xray  # skip specific binaries
cargo test                              # 800+ tests, ~4 minutes
cargo build                             # plain debug build
                                        # (build.rs is tolerant of
                                        # missing blobs — code paths
                                        # gate on cfg(*_bundled))
```

### Updating bundled component versions

Versions are pinned in:

- `vendor/XRAY_VERSION` (Xray-core)
- `vendor/TELEMT_VERSION` (telemt MTProxy)
- `vendor/MDNSVPN_VERSION` (MasterDnsVPN DNS-tunnel server)
- `vendor/DNS_BUNDLE_VERSION` (dnscrypt-proxy + tor + lyrebird + snowflake + webtunnel)

To bump, run `vendor/update.sh <binary> <version>`. The script downloads / builds, SHA-verifies, and rewrites the matching pin file. For example:

```bash
vendor/update.sh xray            v26.3.28
vendor/update.sh telemt          3.4.12
vendor/update.sh mdnsvpn         v2026.06.01.000000-abcdef0
vendor/update.sh dnscrypt-proxy  2.1.16
vendor/update.sh tor             0.4.9.9     # Alpine Docker build, ~10 min
vendor/update.sh lyrebird        0.8.2       # Go static, ~2 min
vendor/update.sh snowflake       v2.13.2
vendor/update.sh webtunnel       v0.0.5
```

Then commit the updated pin file (the `.gz` itself stays out of git). `build.rs` refuses to build if a pin's SHA doesn't match the actual blob; runtime extraction refuses to install a binary whose SHA doesn't match the embedded constant.

### Running without Docker

Gaming mode requires `awg`, `awg-quick`, and the AmneziaWG kernel module on the host. The other four subsystems are self-contained — the bundled `xray`, `telemt`, `mdnsvpn`, and DNS-stack ELFs are extracted to `COFFEEBLACK_XRAY_DIR` / `COFFEEBLACK_MTPROXY_DIR` / `COFFEEBLACK_MDNSVPN_DIR` / `COFFEEBLACK_DNS_DIR` on first start and don't need anything else on the host. Only the firewall stage needs `nft` available.

```bash
sudo ./target/x86_64-unknown-linux-musl/release/coffeeblack-vpn
```

`/etc/coffeeblack/conf/` must be writable by the user the binary runs as. If `awg-quick up cb0` fails the binary still starts and exposes the web UI — fix the host config and click *Restart Interface* in the admin panel. Per-supervisor failures surface in their respective admin tabs (`Admin → Browsing → Inbound`, `Admin → Telegram → Inbound`, `Admin → DNS Tunnel → Inbound`, `Admin → DNS bundle`). All five are independently disable-able and degrade gracefully — a misconfigured Browsing inbound doesn't block AmneziaWG, etc.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│ Single binary (~20 MB stripped, musl-static, distro-agnostic)│
│                                                              │
│  src/http/ ─── in-house HTTP/1.1 server + router             │
│  rusqlite ──── SQLite (WAL, FK on)                           │
│  argon2 ────── password hashing                              │
│  hmac+sha1 ─── in-house RFC 6238 TOTP 2FA                    │
│  src/qr.rs ─── in-house SVG QR (vless:// tg:// mdnsvpn:// AWG)│
│  tokio-rustls ─ TLS 1.3 dest probe for Reality               │
│                                                              │
│  Static UI: index.html + app.js (embedded via include_str!)  │
│  Bundled ELFs (include_bytes!(vendor/<name>-linux-amd64.gz)):│
│    xray-core, telemt, MasterDnsVPN, dnscrypt-proxy, tor,     │
│    lyrebird, snowflake, webtunnel — all extracted on first   │
│    start, SHA-verified against the embedded constant.        │
└─┬─────────┬──────────────┬─────────────┬─────────────────────┘
  │         │              │             │            │
  │ Gaming  │ Browsing     │ Telegram    │ DNS-tunnel │ DNS bundle
  │ argv    │ tokio Child  │ tokio Child │ tokio Child│ tokio Child
  ▼         ▼              ▼             ▼            ▼
awg /     xray (SIGHUP   telemt        MasterDnsVPN  dnscrypt-proxy
awg-quick reload, ...)   (notify       (rewrite +    (+ optional tor
/ nft     │              hot-reload    restart on    with PT plugin)
  │       ▼              of config)    config change)    │
  ▼      VLESS+Reality+    │              │              ▼
AWG      Vision listener   ▼              ▼          DoH / DNSCrypt
kernel   on TCP/443      MTProto      DNS-tunnel     egress, opt. via
module                   listener     listener       tor SOCKS :9053
                         on TCP/8080  on UDP/53
                         (Fake-TLS)   (NS-delegated)

  Firewall: single `inet coffeeblack` nftables table.
  PostUp creates: forward / nat-postrouting / filter-input.
  firewall.rs owns: wg-clients chain (per-peer rules) +
  dns-prerouting (DNS-leak DNAT) + dns-lockdown (residual drop).
  PostDown atomically deletes the whole table.
```

### Source layout

```
src/
  main.rs          # entrypoint, env→config, INIT_ENABLED auto-setup,
                   # AWG + Xray + DNS bundle + telemt + MasterDnsVPN
                   # supervisor startup
  config.rs        # env-var Config (LazyLock)
  db.rs            # rusqlite + schema + idempotent migrations
                   # (interfaces, clients, xray_inbound, xray_clients,
                   #  dns_bundle, mtproxy_inbound, mtproxy_users,
                   #  mdnsvpn_inbound, mdnsvpn_clients, …)
  crypto.rs        # AES-256-GCM (ring) for secrets at rest; key from
                   # systemd-creds / env, never from the database
  secretfile.rs    # atomic 0600 writes for rendered configs that carry
                   # credentials (they were 0644 / world-readable)
  privhelper.rs    # optional root helper: fixed allowlist over a Unix
                   # socket, so the web process needs no CAP_NET_ADMIN
  activity.rs      # RAM-only activity store + 30s poller: awg dump →
                   # monotonic per-peer totals + per-UTC-day rollup,
                   # retention, purge. Never touches SQLite (see module doc)
  auth.rs          # Argon2id wrappers, SHA-256, session-token gen
  datetime.rs      # RFC 3339 / expiry helpers + UTC day keys over `time`
  rng.rs           # OS CSPRNG + unbiased int ranges over `getrandom` (no rand)
  qr.rs            # SVG QR codes
  firewall.rs      # native nftables; manages inet coffeeblack table:
                   #   wg-clients chain (per-peer rules)
                   #   dns-prerouting chain (DNS-leak DNAT)
                   #   dns-lockdown chain (residual drop)
  wg/              # — Gaming mode (AmneziaWG) —
    cli.rs         # argv-only awg/awg-quick wrappers
    params.rs      # AmneziaWG param generation + CPS tag validator
    config_gen.rs  # server/client .conf generation
    mod.rs         # startup, save_config, cron
  xray/            # — Browsing mode (Xray VLESS+Reality+Vision) —
    runtime.rs     # include_bytes! the gzipped ELF, decompress to disk
    keys.rs        # `xray x25519` wrapper + UUID/short-id generators
    config_gen.rs  # server.json generator (multi-client, per-peer sid)
    share.rs       # vless:// URL builder + Amnezia JSON template
    probe.rs       # TLS 1.3 dest probe (rustls + in-house DER SAN parse)
    supervisor.rs  # tokio::process::Child + SIGHUP/SIGTERM lifecycle
    mod.rs
  mtproxy/         # — Telegram MTProxy (telemt) —
    runtime.rs     # include_bytes! the gzipped ELF, decompress to disk
    config.rs      # config.toml generator (no [access.users] —
                   # users go via the runtime API)
    client.rs      # minimal HTTP/1.1 client for 127.0.0.1:9091/v1/*
    supervisor.rs  # spawn telemt, reconcile users on every start
    mod.rs
  mdnsvpn/         # — DNS-tunnel mode (MasterDnsVPN) —
    runtime.rs     # include_bytes! the gzipped ELF, decompress to disk
    keys.rs        # 16-byte hex shared-key generator + validator
    config.rs      # server_config.toml generator (singleton inbound)
    share.rs       # per-client client_config.toml + resolvers.txt +
                   # JSON + mdnsvpn://b64?<base64> share blob
    supervisor.rs  # tokio Child; rewrite-and-restart on config change
                   # (no upstream SIGHUP)
    mod.rs
  dns/             # — Bundled DNS stack (dnscrypt-proxy + tor + PTs) —
    runtime.rs     # extract bundled ELFs (5 binaries, all optional)
    dnscrypt.rs    # dnscrypt-proxy.toml generator
    tor.rs         # torrc + BridgeDB scraping for PT support
    supervisor.rs  # tokio Children for dnscrypt-proxy + tor (opt-in)
    mod.rs
  api/
    mod.rs         # router, AppState, require_auth
    session.rs     # /api/session, /api/me, TOTP, rate limiter
    clients.rs     # /api/client/* CRUD (AWG), IDOR enforcement
    activity.rs    # /api/activity/heatmap (matrix), DELETE /api/activity
    admin.rs       # /api/admin/* (admin role required)
    xray.rs        # /api/admin/xray/* + /api/xray/clients/*
    mtproxy.rs     # /api/admin/mtproxy/* (inbound, users, stats, QR)
    mdnsvpn.rs     # /api/admin/mdnsvpn/* + /api/mdnsvpn/clients/*
                   # (inbound, key regen, per-client config downloads)
    dns.rs         # /api/admin/dns/* (bundle config, status, restart)
    setup.rs       # /api/setup/* wizard + v3 backup migrate
    routes.rs      # /api/information, /metrics/*, /cnf/:token
static/
  index.html       # SPA shell + inline CSS
  app.js           # SPA logic
  *.png *.svg      # branding
vendor/
  XRAY_VERSION          # pinned Xray-core version + uncompressed-ELF SHA-256
  TELEMT_VERSION        # pinned telemt version + SHA
  MDNSVPN_VERSION       # pinned MasterDnsVPN version + SHA
  DNS_BUNDLE_VERSION    # pinned dnscrypt-proxy / tor / PTs versions + SHAs
  LICENSES/             # preserved upstream LICENSE files (legal attribution)
  update.sh             # curation tool — bumps a binary to a new version
                        # (download/build, SHA-verify, gzip, rewrite pin)
  README.md             # provenance + curation procedure
  *.gz                  # IMMATERIAL — produced by scripts/build.sh from
                        # the pin files; gitignored, not committed
build.rs                # validates pin SHAs, embeds via include_bytes!,
                        # tolerates missing blobs (warns + disables cfg)
scripts/
  build.sh              # local end-to-end build: scripts/build.sh wraps
                        # vendor/update.sh per pinned binary, then runs
                        # cargo build --release --target …-musl
.github/workflows/
  build-release.yml     # CI: cargo-deny gate → clippy/test → musl build
                        # + tag + GitHub release
deny.toml               # cargo-deny policy: advisories, license allowlist,
                        # duplicate-version allowlist, crates.io-only sources
rust-toolchain.toml     # pins rustc (reproducible builds)
```

---

## Privilege separation (optional)

The web UI and the interface manager are the same process, and that process runs as root because `awg-quick`, `awg` and `nft` need `CAP_NET_ADMIN`. So a remote-code-execution bug anywhere in the HTTP layer — a handler, a parser, a dependency — is immediately full control of the host. The privileged work is six operations; the surface carrying that privilege is an entire web application.

`coffeeblack-vpn --privileged-helper` splits them. It runs as root on a Unix socket, speaks one line-delimited JSON request per connection, and accepts a **fixed allowlist**:

| Op | Runs |
|---|---|
| `wg_up` / `wg_down` | `awg-quick up\|down <iface>` |
| `wg_sync` | writes `<conf_dir>/<iface>.conf` (0600), then `awg-quick strip` → `awg syncconf` |
| `wg_show` | `awg show <iface> dump` |
| `nft_apply` | `nft -c -f -` to validate, then `nft -f -` to apply |
| `nft_list` | `nft list table inet coffeeblack` |
| `ping` | liveness |

Everything is executed as an **argument vector** — never a shell string, and `argv[0]` always comes from a literal in the helper. The interface name and every filesystem path are fixed when the helper starts and are never read from a request, so `wg_sync` cannot be turned into an arbitrary-file-write primitive no matter what fields a caller adds. Operations that need no privilege at all (`genkey`, `pubkey`, `genpsk` — pure crypto) stay in the main process and are not forwardable.

Enable it with `COFFEEBLACK_HELPER_SOCKET`; unset, the binary behaves exactly as before and executes the commands itself, so an upgrade changes nothing until you opt in. See `packaging/coffeeblack-vpn-helper.service` and the commented block in `packaging/coffeeblack-vpn.service`.

**What it buys, stated honestly.** It removes arbitrary code execution as root, arbitrary file read and write, module loading, and persistence — the things an attacker actually wants out of an RCE. It does **not** remove control of the VPN: a compromised main process can still ask for a ruleset to be applied and an interface to be reconfigured, because that is the product's entire purpose. The helper validates that a ruleset parses; it cannot judge whether the operator wanted it. The pattern converts *root on the box* into *control of the tunnel* — a large reduction, not containment.

Still privileged and out of scope: loading the `amneziawg` kernel module (done once via `ExecStartPre=`), and binding the low ports the optional bundled transports use (Xray on 443, MasterDnsVPN on 53) — grant `CAP_NET_BIND_SERVICE` or leave those transports off.

---

## Generated config files

Every bundled transport is configured by a file this service renders, and each one carries credentials: `xray/server.json` holds the Reality private key **and every client's UUID and shortId**, `mtproxy/config.toml` holds every user's secret, `mdnsvpn/server_config.toml` holds the tunnel key.

These were written with `tokio::fs::write`, which creates a file at `0666 & ~umask` — **0644 under the usual 0022**. On a bare-metal install that handed any local account a working VLESS UUID (free tunnel access as an existing client) and the Reality private key. That was a live exposure, not an at-rest one: no stolen disk required, just a shell on the box.

They now go through `crate::secretfile`, which creates them **0600 at `open(2)`** — not written-then-chmod'ed, which leaves a window where the file exists at the umask-derived mode and already holds the secret — inside a `0700` directory, written atomically via a sibling temp file and a rename. Existing directories left world-traversable by an older version are tightened on every write, since `create_dir_all` reports success on an already-loose directory without touching it.

**These files cannot be encrypted**: the subprocesses parse them, so they must be plaintext by design. Encrypting the corresponding database column does nothing for them. File permissions are the only available control, which is exactly why they are worth getting right.

### Why not keep them in memory instead?

Partly they already are. Under `IN_MEMORY=true` (the Docker default) these directories are meant to be tmpfs, and the startup check now verifies **every** secret-bearing directory rather than only the WireGuard one — it previously reported "RAM-backed" based on a directory that does not contain most of these files. A tmpfs file is still a file with a mode, though, so `0600` matters in that mode too.

Going further — rendering the configs into anonymous `memfd` objects, as `memexec.rs` already does for the bundled *binaries*, so they have no name in any filesystem — is possible in principle but is not implemented, for a specific reason: **Xray reloads by re-reading its config path on SIGHUP** (`xray/supervisor.rs`). A fresh memfd per render would leave the child re-reading its original descriptor and silently applying a stale config, which is worse than a visible failure. Doing it correctly means rewriting one long-lived unsealed memfd in place, and whether Xray and telemt tolerate a `/proc/self/fd/N` config path at all is external behaviour that has to be *measured*, not assumed — and the vendored blobs needed to measure it are CI artifacts, not in the tree. The `0600` fix closes the actual hole in every mode; memfd would remove the filesystem entry as well.

---

## Secret encryption at rest

Every credential the service stores is now encrypted at rest. Previously they were plaintext columns: peer private keys and pre-shared keys, the server's own WireGuard key, the Reality private key, every VLESS UUID and shortId, MTProxy user secrets, the DNS-tunnel key, and TOTP seeds. Anyone holding the database file — or a backup, or a snapshot — held all of them. TOTP was the worst of the set: a second factor is meant to survive a password compromise, but a stolen database let an attacker mint valid codes forever, and unlike a password the user gets no signal and no reason to re-enrol.

The full list lives in one place, `db::ENCRYPTED_COLUMNS`, so "what does a stolen database yield?" has an auditable answer rather than one assembled by grepping. Deliberately excluded: `users_table.password` and `metrics_password` are already hashes (argon2id / SHA-256), and encrypting a hash protects nothing the hash does not.

**One-time-link tokens are hashed, not encrypted.** They are looked up *by value*, so randomised encryption cannot work — but the server only ever needs to *recognise* a token, never reproduce it, so the lookup column holds a SHA-256 digest. A separate encrypted copy is kept purely so an active link stays displayable in the UI during its five-minute life.

Values are encrypted with **AES-256-GCM** (via `ring`, already in the dependency graph through rustls, so this adds no crate). Stored form is `enc$` + base64(12-byte nonce ‖ ciphertext ‖ 16-byte tag).

### Supplying the key

| Source | Use |
|---|---|
| `COFFEEBLACK_SECRET_KEY_PATH` | Path to a file holding the base64 key. Intended for systemd credentials — `LoadCredentialEncrypted=SECRET_KEY:…` decrypts a machine-bound blob into `/run/credentials/coffeeblack-vpn.service/SECRET_KEY` at start, so the key never exists as plaintext on disk. |
| `COFFEEBLACK_SECRET_KEY` | The base64 key itself (32 bytes). For Docker and development. |

```bash
# generate one
openssl rand -base64 32
```

With neither set the service still starts and stores plaintext, logging a warning at startup — an operator upgrading into this feature should not find their VPN down because a new variable is missing. Which mode an instance is in is visible in the journal without reading the database.

Encryption is transparent at the storage layer: the row mappers decrypt, and `exec_update` — which every update in the codebase funnels through, and which already receives the table name — encrypts. The handful of raw `INSERT`/`UPDATE` statements that bypass it encrypt explicitly. No call site can introduce a plaintext write by forgetting a step.

**Decryption failure is a hard error, never a fallback.** An earlier revision returned `None` for an undecryptable TOTP secret, which meant the login path saw no second factor, skipped the check, and accepted a password alone — a key misconfiguration silently becoming a 2FA bypass. Failing the row load instead means such an account simply cannot authenticate until the key is fixed. Handing ciphertext to a config generator would be the same class of bug: a peer that imports cleanly and never connects. Values written before a key was configured have no `enc$` prefix and keep working, and a startup pass upgrades them in place once a key is present — otherwise enabling encryption would protect only secrets created afterwards while every existing one stayed readable.

### What this is and isn't worth

This defends **a stolen database or backup**: the key is delivered out of band and never written into the database, so the file alone yields nothing.

It does **not** defend a live compromise of the running service. The process must hold the key to verify a code, so an attacker with code execution as this user can decrypt anything the process can — often by calling straight into the same module. Encrypting a value the process can decrypt on demand raises effort; it does not move the boundary. Where a secret can be **eliminated** rather than encrypted — as peer private keys now are — that is strictly better, and the two features are deliberately different in kind for that reason.

---

## Peer private keys: issued once, not stored

Upstream `wg-easy` (and this project, before) generates each peer's keypair server-side and keeps the **private** key in the database forever, so the config and QR can be re-displayed on demand. That is convenient and it is the single worst thing a compromise of this box can yield: whoever reaches the database — or any backup of it — can impersonate every peer.

The load-bearing fact is that they never needed to be there. `generate_server_peer` uses only `public_key` and `pre_shared_key`: **the server does not need a peer's private key after the config has been rendered.** Keeping it buys re-display and nothing else.

### Modes

Instance-wide, set in Admin → General (`general_table.private_key_retention`):

| Mode | Behaviour |
|---|---|
| **`never`** (default) | The keypair is generated, the config + QR are returned **once** in the create response, and only the public key is stored. `GET /configuration`, `/qrcode.svg` and `generateOneTimeLink` answer **409** afterwards. Recovery from a lost config is rotation, exactly like a lost API key. |
| **`plaintext`** | The private key is stored, so the config can be re-rendered on demand. Upstream-equivalent behaviour. The admin console shows a permanent banner naming the exposure. |

Instance-wide rather than per-peer on purpose: a per-peer toggle makes "does this server hold key material?" unanswerable without auditing every row, when it should have exactly one answer for the whole box.

**Switching to `never` purges the keys already stored.** Otherwise the setting would describe an intention rather than a fact — every peer created before the switch would keep its key on disk while the UI claimed otherwise. The admin form names how many peers are affected and confirms before doing it. Their tunnels keep working; only re-display is lost.

### Bring your own key (strongest)

Pass `publicKey` when creating a peer — generated on the device with `wg genkey | wg pubkey` — and the server never sees the private half **at all**, in any retention mode. There is nothing to leak, nothing to purge, and no window in which key material exists off the device. The create form accepts it in the *Device public key* field.

### Rotation

`POST /api/client/:id/rotateKey` issues a fresh keypair, returns the new config once, and invalidates the old public key at the next interface reload. It is both the recovery path (config lost) and the revocation path (device compromised), and it drops any outstanding one-time link, which would otherwise serve a config that can no longer connect.

### What this does not fix

Pre-shared keys, Xray UUIDs and short IDs, MTProxy secrets, and the MasterDnsVPN encryption key are **symmetric or server-verified** — the server needs them on every handshake, so they cannot be issued-and-forgotten the way an asymmetric private key can. They remain in the database, and a compromise still yields them. This feature removes peer private keys from the blast radius; it does not empty it.

Note also that WireGuard's forward secrecy means static keys never decrypt *previously recorded* traffic. What a stolen server key does buy an adversary is impersonation, active MITM, and — because the initiator's static public key in handshake message 1 is encrypted only to the responder's static key — the ability to identify which peer initiated each recorded handshake, and when.

---

## Activity history and the connection heatmap

`awg show <if> dump` is a snapshot, not a record. Two things follow, and both used to be visible in the UI:

1. Its byte counters restart at zero whenever the interface is torn down, so a figure labelled "lifetime transfer" silently collapsed after every `awg-quick down/up`.
2. Nothing answered a question about the past — *was this peer connected last Tuesday? which peers went quiet three weeks ago?* — because nothing was ever kept.

A background poller (`src/activity.rs`) samples the same dump every 30 s and folds each tick into two things, per peer:

- **Monotonic lifetime totals.** Only the non-negative delta between consecutive readings is accumulated, so a counter reset contributes 0 instead of driving the total backwards. These are what the UI labels "lifetime", and what `wireguard_peer_total_rx_bytes` / `_total_tx_bytes` export.
- **One bucket per UTC day**, holding a count of ticks that saw a live handshake plus that day's rx/tx deltas. This backs the **Connection activity** heatmap on the clients page: peers × days, GitHub-contribution style, shaded either by time connected or by traffic volume, over a 30/60/90-day window.

### None of it is in the database

Per-peer connection history is the most sensitive thing this service could accumulate: who connected, when, from where, and how much they moved. Everything in the SQLite schema is written to a file when `IN_MEMORY=false`, and is copied verbatim into the durable snapshot when `COFFEEBLACK_PERSIST_DB` is set — so a table, *even one in the `:memory:` database*, is one operator setting away from becoming a durable record of exactly that.

So the history is not in the schema at all. It lives in a process-memory store (`RwLock<HashMap<client_id, ClientActivity>>`), which makes the guarantee structural rather than conditional: **there is no code path from this data to a file, in any mode.** It dies with the process, which is the intended lifetime. `tests/activity.rs` asserts this against the live schema — no table may be named for activity, and no `total_*` / `last_seen*` / `last_sampled_*` column may appear on `clients_table` — so a future change cannot quietly reintroduce on-disk history.

Two consequences worth stating plainly:

- **A service restart starts the heatmap empty.** That is the trade, not a bug. The peer roster, keys and settings still persist exactly as before; only the connection history does not.
- Because the store is keyed on client id with no foreign key to cascade it, deleting a peer drops its record immediately (`db::delete_client`), and every poll tick additionally reconciles the store against the live client list — closing the window where a peer deleted mid-tick could have its record recreated by the write that follows.

The one thing that *does* persist is the retention **setting** (`general_table.activity_retention_days`). That is configuration, not a record of anyone's connections, and it has to survive a restart: an operator who set it to `0` must not find collection switched back on by the next reboot.

### Why a daily rollup rather than raw samples

Keeping every tick would cost `peers × 2,880` entries/day and grow without bound; the rollup is `peers × retention_days` no matter how often the poller runs, so retuning the cadence never changes the memory bill. A per-client hard cap of 366 days backstops the retention prune, so the store stays bounded even if that prune never runs.

The trade-off is real and permanent: **intra-day resolution does not exist.** A peer that connected once for ten minutes and one that connected three times for ten minutes look alike within a day's bucket. Anything needing per-session detail needs its own storage, not a cleverer query against this one.

`sample_hits` is likewise **a count of poll ticks, not a measured duration** — there are no connect/disconnect events to work from. The UI presents `hits × 30 s` as an estimate ("connected ~2h 15m") and the API ships `pollIntervalSeconds` so that estimate tracks the real cadence rather than a hardcoded constant.

### Privacy controls

- **`activityRetentionDays = 0`** (Admin → General) stops collection *and* purges everything already held — not merely "stop writing more".
- **Erase activity history** (same panel, `DELETE /api/activity`, admin only) drops the day buckets, the accumulated totals, and the last-seen timestamps and endpoints, then re-anchors the sampler so the next tick books nothing rather than crediting the whole pre-purge counter.
- The heatmap follows the same visibility rule as the peer list: a role-0 user sees only their own peers, never anyone else's connection pattern.
- **No source addresses.** `awg show dump` reports the endpoint a peer was reached from, and it is deliberately dropped rather than accumulated: a peer's real public IP is the most identifying field available here, it is exactly what a VPN exists not to retain, and unlike a key it cannot be rotated after a compromise. The current endpoint is still shown live in the peer list; it simply never enters a history that outlives the connection.

Retention defaults to 30 days and is capped at 365. It is deliberately short: the heatmap's operational value — spotting a peer gone quiet, or one suddenly moving far more than usual — is served by a few weeks, while the months beyond mostly add retroactive exposure if the box is ever seized.

---

## Security model

- **Auth**: session cookies, server-side session table (in-memory), argon2id password hashes, optional TOTP.
- **CSRF**: relies on `SameSite=Strict` cookie + JSON-only request bodies. JSON content-type forces a CORS preflight, which a cross-site form submit cannot satisfy.
- **CSP**: `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'`. The two `'unsafe-inline'` allowances are required by inline `onclick=` event handlers in the embedded SPA.
- **Privilege model**: role 0 = client (sees only their own peers, cannot edit IPs/AllowedIPs/DNS/MTU/AWG params/server-endpoint of any client), role 1 = admin.
- **Command execution**: every shell-out for `awg`/`awg-quick`/`nft` uses argv-style `Command::new(...).args(...)`. No `bash -c` with user-tainted arguments. nftables transactions are piped to `nft -f -` via stdin (still argv-only) so peer names containing quotes / backticks / shell metas can never escape into command interpretation. Interface names are validated against `[A-Za-z0-9_-]{1,15}` before any command call.
- **Metrics**: SHA-256 of the configured `metricsPassword` is stored, never the cleartext. Endpoints use constant-time comparison.

If you find a security issue, please open an issue marked `security`.

---

## Operational notes

- **Backups**: copy `/etc/coffeeblack/conf/coffeeblack.db` while the container is stopped (or use `sqlite3 .backup`). The `.conf` and live kernel state regenerate from it on next start.
- **Health check**: the Dockerfile health check runs `awg show` to verify the kernel interface is up. Add an HTTP probe on `/health` if you want the proxy / orchestrator to also check the web UI.
- **Sessions**: stored in-memory only, so a restart logs everyone out. Persist to disk if needed by trading off restart time vs. the slim attack surface of in-memory sessions.

---

## Comparison with upstream `awg-easy` (Node.js)

| | Upstream Node.js | coffeeblack-vpn |
|---|---|---|
| Container size | ~150 MB (Node + deps) | ~50 MB (Alpine + Rust binary with bundled Xray + telemt + MasterDnsVPN + AmneziaWG tools; +~20 MB if the DNS bundle is curated) |
| Cold start | seconds (Nuxt warm-up) | ~50 ms |
| RAM (idle) | 80-120 MB | 8-15 MB (each idle subprocess adds ~5 MB; budget for AWG only, AWG+Xray, AWG+Xray+telemt+mdnsvpn, etc.) |
| Distribution | docker image only | musl-static binary, runs unchanged on glibc / musl / any other libc x86_64 host |
| AmneziaWG params | Jc/Jmin/Jmax, S1-S4, H1-H4, I1-I5 | Same + per-peer AdvancedSecurity (kernel parity) + per-peer & UserConfig `additional_config` escape hatch |
| Xray VLESS+Reality+Vision | **no** | **yes** (bundled v26.3.27, supervised subprocess, per-peer UUIDs + shortIds, TLS dest probe) |
| Telegram MTProxy | **no** | **yes** (bundled telemt 3.5.5 — Fake-TLS / SNI fronting, per-user secrets, runtime HTTP control plane) |
| MasterDnsVPN DNS-tunnel | **no** | **yes** (bundled v2026.06.13 — encrypted TCP over DNS, NS-delegated subdomain, SOCKS5 / fixed-TCP forwarding) |
| Bundled DNS stack | **no** | **yes** (optional dnscrypt-proxy + tor + lyrebird/snowflake/webtunnel; off by default; tor opt-in independently) |
| DNS-leak prevention | client-side `DNS = …` only | nftables `dns-prerouting` DNAT + optional residual-drop chain — server-enforced regardless of client config |
| TOTP secret | server-generated | server-generated |
| CSP | `'unsafe-inline'` | `'unsafe-inline'` (inline event handlers) |
| Schema | Drizzle migrations | hand-rolled `CREATE TABLE IF NOT EXISTS` + idempotent `ALTER TABLE` |
| Plain WireGuard fallback | yes (`EXPERIMENTAL_AWG`/`OVERRIDE_AUTO_AWG`) | **no** — pure AmneziaWG (Gaming) + Xray Reality (Browsing) + telemt (Telegram) + MasterDnsVPN (DNS-tunnel) only |
| Reproducible build | n/a | vendored binaries are CI artifacts produced from `vendor/*_VERSION` pins; `scripts/build.sh` does the same locally |
| Tests | vitest unit suite | 400+ unit + integration tests across DB, API, security, AmneziaWG params, Xray config & supervisor, MTProxy + MasterDnsVPN config + envelope parsing, plus `--ignored` e2e tests that spawn real subprocesses |

If you need plain-WireGuard support, stay on upstream `awg-easy`. If you want any combination of AmneziaWG + Xray Reality + Telegram MTProxy + MasterDnsVPN DNS-tunnel in one self-supervising binary — with optional bundled DNS-leak prevention — this is the only option.

---

## License

[MIT](LICENSE)
