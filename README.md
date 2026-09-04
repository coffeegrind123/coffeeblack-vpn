# CoffeeBlack VPN

[![Build and Release](https://github.com/coffeegrind123/coffeeblack-vpn/actions/workflows/build-release.yml/badge.svg)](https://github.com/coffeegrind123/coffeeblack-vpn/actions/workflows/build-release.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform: x86_64 Linux](https://img.shields.io/badge/platform-x86__64%20linux-lightgrey.svg)](#requirements)
[![Rust 1.98](https://img.shields.io/badge/rust-1.98-orange.svg)](rust-toolchain.toml)

A self-hosted VPN and censorship-resistant proxy manager that ships as **one static
binary** with a built-in web UI. Five transports, one admin panel, one SQLite database.

Written in Rust, with no Node.js, npm, or JavaScript toolchain anywhere in the build or
the container. It is a from-scratch reimplementation of [wg-easy] /
[awg-easy], not a fork.

[wg-easy]: https://github.com/wg-easy/wg-easy
[awg-easy]: https://github.com/coffeegrind123/awg-easy

---

## Contents

- [Why](#why)
- [Transports](#transports)
- [Quick start](#quick-start)
- [Requirements](#requirements)
- [Documentation](#documentation)
- [Architecture](#architecture)
- [Security](#security)
- [Relationship to wg-easy and awg-easy](#relationship-to-wg-easy-and-awg-easy)
- [License](#license)

---

## Why

Most VPN panels manage one protocol. When that protocol gets blocked, you are done.

CoffeeBlack runs five transports side by side behind a single admin UI, user roster and
auth layer, so you can hand a user a different way in without redeploying anything. They
degrade independently: a misconfigured Xray inbound does not stop WireGuard, and every
transport can be turned off.

Three properties fall out of the single-binary design:

- **Runs anywhere x86_64 Linux runs.** Statically linked against musl — no glibc/musl
  mismatch, no runtime package dependencies beyond `nft` and, for Gaming mode, the
  AmneziaWG tools. The fully bundled release binary is ~57 MB, most of it the embedded
  Xray, telemt, MasterDnsVPN and DNS-stack ELFs; each release publishes its exact size
  and SHA-256.
- **Can run entirely in RAM.** `IN_MEMORY=true` (the Docker default) opens SQLite as
  `:memory:` and `exec`s every bundled subprocess from a sealed anonymous `memfd`.
  Nothing on the request path or the `exec` path touches a block device.
- **Keeps almost nothing it does not need.** Peer private keys are issued once and never
  stored. Connection history lives in process memory with no code path to a file. Every
  remaining credential is AES-256-GCM encrypted at rest.

---

## Transports

| Mode | Protocol | Default port | Reach for it when |
|---|---|---|---|
| **Gaming** | [AmneziaWG] — obfuscated WireGuard | UDP 51820 | Default choice. Lowest latency, full tunnel. |
| **Browsing** | [Xray] VLESS + Reality + Vision | TCP 443 | UDP is blocked or throttled. Looks like ordinary TLS to a real CDN host. |
| **Telegram** | [telemt] MTProxy, Fake-TLS | TCP 8080 | Telegram specifically — not a general tunnel. |
| **DNS tunnel** | [MasterDnsVPN] | UDP 53 | Only DNS escapes. Carries TCP/SOCKS5. Needs an `NS` delegation. |
| **UDP over DNS** | QQ-DNS ([QQ-Tunnel] port, in-process) | UDP 53 | Only DNS escapes and you want the Gaming config itself. |

[AmneziaWG]: https://docs.amnezia.org/documentation/amnezia-wg/
[Xray]: https://github.com/XTLS/Xray-core
[telemt]: https://github.com/telemt/telemt
[MasterDnsVPN]: https://github.com/masterking32/MasterDnsVPN
[QQ-Tunnel]: https://github.com/patterniha/QQ-Tunnel

Two optional add-ons layer on top rather than replacing a transport:

| Add-on | What it does |
|---|---|
| **DNS bundle** | Bundled `dnscrypt-proxy`, optionally over `tor` with obfs4/snowflake/webtunnel, plus an nftables DNAT chain that catches peer DNS leaks before they reach the WAN. |
| **DPI-imitation proxy** | Fronts the AmneziaWG port and rewrites each packet's padding so the datagrams read as QUIC / DNS / STUN / SIP, answering active probes convincingly. Client configs are unchanged. **Off by default — read the [trade-off](docs/TRANSPORTS.md#detection-trade-off) before enabling it; against some adversaries it makes you *more* identifiable, not less.** |

Every transport is off by default except Gaming. Setup for each is in
**[docs/TRANSPORTS.md](docs/TRANSPORTS.md)**.

---

## Quick start

### Docker

```bash
docker compose up -d
```

Then open `https://YOUR_HOST:51821/`. Put a reverse proxy in front of it — the binary
does not terminate TLS. See [TLS](docs/CONFIGURATION.md#tls).

### Prebuilt binary

Every push to `main` publishes a tagged release with a fully static ELF, its SHA-256, and
the pinned version of every bundled component.

```bash
curl -fsSL -o /usr/local/bin/coffeeblack-vpn \
  https://github.com/coffeegrind123/coffeeblack-vpn/releases/latest/download/coffeeblack-vpn
chmod +x /usr/local/bin/coffeeblack-vpn
sudo /usr/local/bin/coffeeblack-vpn
```

### Bare metal, as a systemd service

`scripts/install.sh` provisions the AmneziaWG kernel module via DKMS, installs the
binary, and registers the service.

```bash
curl -O https://raw.githubusercontent.com/coffeegrind123/coffeeblack-vpn/main/scripts/install.sh
chmod +x install.sh
sudo ./install.sh                      # guided
sudo AUTO_INSTALL=y ./install.sh       # unattended
```

Subcommands: `install`, `upgrade`, `uninstall`, `status`. Full reference in
**[docs/INSTALL.md](docs/INSTALL.md)**.

### First run

The setup wizard asks for an admin user, the public endpoint, and AmneziaWG parameters
(generated for you). For unattended deployments, pre-seed it instead:

```yaml
environment:
  - INIT_ENABLED=true
  - INIT_USERNAME=admin
  - INIT_PASSWORD=use-a-real-password-please
  - INIT_HOST=vpn.example.com
  - INIT_PORT=51820
```

These apply only when no admin user exists yet, so restarting with the same environment
is idempotent.

---

## Requirements

- **x86_64 Linux.** arm64 was dropped deliberately — see [`vendor/README.md`](vendor/README.md).
- **`nft`** for the firewall stage.
- **Gaming mode only:** `awg`, `awg-quick`, and the AmneziaWG kernel module on the host.
  The Docker image ships these. The other four transports are self-contained — their
  binaries are embedded and extracted on first start.
- **A reverse proxy** for TLS.

---

## Documentation

| Document | Covers |
|---|---|
| [docs/INSTALL.md](docs/INSTALL.md) | Bare-metal install, systemd unit, upgrade and uninstall, the `awg-quick` config bridge |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Every environment variable, runtime tunables, run-in-RAM mode, TLS, backups |
| [docs/TRANSPORTS.md](docs/TRANSPORTS.md) | Enabling and operating each transport, AmneziaWG 3 knobs, the DPI proxy trade-off |
| [docs/SECURITY.md](docs/SECURITY.md) | Threat model, peer key handling, encryption at rest, privilege separation, activity-history privacy |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Component diagram, source layout, dependency policy and in-house replacements |
| [docs/BUILDING.md](docs/BUILDING.md) | Building from source, vendored blobs, bumping pinned versions, CI |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│ Single static binary (musl, x86_64)                          │
│                                                              │
│  src/http/ ─── in-house HTTP/1.1 server + router             │
│  rusqlite ──── SQLite (WAL, foreign keys on)                 │
│  argon2 ────── password hashing                              │
│  hmac+sha1 ─── in-house RFC 6238 TOTP                        │
│  src/qr.rs ─── in-house SVG QR encoder                       │
│  tokio-rustls ─ TLS 1.3 dest probe for Reality               │
│                                                              │
│  UI: index.html + app.js, embedded via include_str!          │
│  Bundled ELFs, embedded via include_bytes! and SHA-verified: │
│    xray-core, telemt, MasterDnsVPN, dnscrypt-proxy, tor,     │
│    lyrebird, snowflake, webtunnel                            │
└─┬─────────┬──────────────┬─────────────┬──────────┬──────────┘
  │ Gaming  │ Browsing     │ Telegram    │ DNS      │ DNS
  │ argv    │ tokio Child  │ tokio Child │ tunnel   │ bundle
  ▼         ▼              ▼             ▼          ▼
awg /     xray            telemt      MasterDnsVPN  dnscrypt-proxy
awg-quick (SIGHUP         (notify     (rewrite +    (+ optional tor
/ nft     reload)         hot-reload) restart)      with a PT plugin)
  │         │               │            │            │
  ▼         ▼               ▼            ▼            ▼
AmneziaWG VLESS+Reality   MTProto     DNS-tunnel   DoH / DNSCrypt
kernel    +Vision         listener    listener     egress, optionally
module    on TCP/443      TCP/8080    UDP/53       via tor SOCKS :9053
                          (Fake-TLS)  (NS-delegated)

  Firewall: one `inet coffeeblack` nftables table.
  Chains: forward, nat-postrouting, filter-input, wg-clients
  (per-peer rules), dns-prerouting (leak DNAT), dns-lockdown.
  Torn down atomically as a single table delete.
```

Every subprocess is supervised by a Tokio task with backoff on crash, and each one is
independently disable-able. Details and the full source layout are in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Security

The full threat model is in **[docs/SECURITY.md](docs/SECURITY.md)**. The load-bearing
points:

- **Peer private keys are issued once and never stored** (default). The server only needs
  a peer's public key after the config is rendered, so the private half is returned in the
  create response and discarded. Peers may also bring their own key, in which case the
  server never sees a private half at all.
- **Every remaining stored credential is AES-256-GCM encrypted** when
  `COFFEEBLACK_SECRET_KEY` is set. The full list is a single auditable registry
  (`db::ENCRYPTED_COLUMNS`), not something you assemble by grepping.
- **Connection history never reaches disk.** It lives in a process-memory store with no
  code path to a file in any mode, and peer source addresses are never recorded at all.
  A test asserts this against the live schema so it cannot be quietly reintroduced.
- **Privilege separation is available.** `--privileged-helper` runs a root helper exposing
  a fixed six-operation allowlist over a Unix socket, so the web process needs no
  `CAP_NET_ADMIN` and an RCE in the HTTP layer no longer means root.
- **No shell interpolation anywhere.** Every call to `awg`, `awg-quick` and `nft` is an
  argument vector; nftables rulesets are piped to `nft -f -` over stdin.

Two things stated plainly rather than buried: the **HTTP server is hand-written** and is
the most exposed code in the project — keep a reverse proxy in front of it. And the
**DPI-imitation proxy is mimicry, not cryptography**; against an adversary fingerprinting
this specific tool it can increase detectability. Both are covered in the docs.

Found a security issue? Open an issue tagged `security`.

---

## Relationship to wg-easy and awg-easy

CoffeeBlack is a standalone project, **not** a drop-in replacement. It uses its own
database and its own configuration; there is no migration path from either upstream.

|  | upstream `awg-easy` (Node.js) | CoffeeBlack VPN |
|---|---|---|
| Distribution | Docker image | musl-static binary, or Docker |
| Cold start | seconds (Nuxt warm-up) | ~50 ms |
| Idle RAM | 80–120 MB | 8–15 MB, plus ~5 MB per enabled subprocess |
| Transports | AmneziaWG | AmneziaWG, Xray Reality, MTProxy, DNS-tunnel, UDP-over-DNS |
| Plain WireGuard | yes | **no** — AmneziaWG only |
| DNS-leak prevention | client-side `DNS =` line only | server-enforced nftables DNAT + residual-drop chain |
| Peer private keys | stored, re-displayable | issued once, not stored (default) |
| Secrets at rest | plaintext columns | AES-256-GCM |
| Tests | vitest unit suite | 1,092 unit + integration, plus `--ignored` end-to-end suites |

**If you need plain-WireGuard support, stay on upstream `awg-easy`.** If you want several
obfuscated transports under one panel in a single self-supervising binary, that is what
this is for.

---

## License

[MIT](LICENSE).

Bundled third-party binaries keep their own licenses, preserved verbatim in
[`vendor/LICENSES/`](vendor/LICENSES). Provenance and the curation procedure for each are
documented in [`vendor/README.md`](vendor/README.md).
