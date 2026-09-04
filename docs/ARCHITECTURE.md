# Architecture

- [Runtime shape](#runtime-shape)
- [Source layout](#source-layout)
- [Dependency policy](#dependency-policy)

---

## Runtime shape

One process. The web layer, the database, and every transport supervisor live in it; the
bundled third-party transports run as Tokio-supervised children, and two transports
(QQ-DNS and the DPI-imitation proxy) are in-process Rust with no subprocess at all.

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
  PostUp creates forward / nat-postrouting / filter-input.
  firewall.rs owns wg-clients (per-peer rules),
  dns-prerouting (DNS-leak DNAT) and dns-lockdown (residual drop).
  PostDown deletes the whole table atomically.
```

**Supervision.** Each child gets a Tokio supervisor with capped exponential backoff on
crash. Xray reloads on SIGHUP and shuts down on SIGTERM with a 10 s grace period; telemt
hot-reloads via `notify`; MasterDnsVPN has no upstream reload signal, so its supervisor
rewrites the config and restarts. Every supervisor's failures surface in its own admin tab
and none of them can block another — a misconfigured Browsing inbound does not stop
AmneziaWG.

**Firewall.** All rules live in a single `inet coffeeblack` nftables table applied through
one `nft -f -` transaction, so a rebuild is atomic and teardown is a single table delete.
A transparent compat shim covers hosts still on `iptables-legacy`: it is detected at
startup, three FORWARD/INPUT accept rules are mirrored into the legacy backend, and they
are removed on graceful shutdown.

---

## Source layout

```
src/
  main.rs          # entrypoint, env→config, INIT_ENABLED auto-setup,
                   # supervisor startup for every transport
  config.rs        # env-var Config (LazyLock)
  db.rs            # rusqlite + schema + idempotent migrations
  crypto.rs        # AES-256-GCM (ring) for secrets at rest; key from
                   # systemd-creds or env, never from the database
  secretfile.rs    # atomic 0600 writes for rendered configs carrying
                   # credentials
  privhelper.rs    # optional root helper: fixed allowlist over a Unix
                   # socket, so the web process needs no CAP_NET_ADMIN
  activity.rs      # RAM-only activity store + 30 s poller. Never
                   # touches SQLite — see the module doc
  auth.rs          # Argon2id wrappers, SHA-256, session-token gen
  datetime.rs      # RFC 3339 / expiry helpers + UTC day keys
  rng.rs           # OS CSPRNG + unbiased int ranges over getrandom
  qr.rs            # SVG QR codes
  memexec.rs       # sealed anonymous memfd exec for bundled ELFs
  inflate.rs       # in-house gzip/DEFLATE decoder
  log.rs           # in-house level filter, formatter, RUST_LOG parsing
  firewall.rs      # native nftables; owns the inet coffeeblack table

  http/            # in-house HTTP/1.1 server, router, extractors,
                   # responses, cookies, query deserializer

  wg/              # — Gaming (AmneziaWG) —
    cli.rs         # argv-only awg / awg-quick wrappers
    params.rs      # parameter generation + CPS tag validator
    config_gen.rs  # server and client .conf generation
    cb3.rs         # AmneziaWG 3 device knobs + proxy-conflict rules
    kernel.rs      # kernel-parity helpers
    mod.rs         # startup, save_config, cron

  xray/            # — Browsing (Xray VLESS+Reality+Vision) —
    runtime.rs     # embedded gzipped ELF → decompress → verify
    keys.rs        # x25519 wrapper + UUID / short-id generators
    config_gen.rs  # server.json (multi-client, per-peer sid)
    share.rs       # vless:// builder + Amnezia JSON template
    probe.rs       # TLS 1.3 dest probe (rustls + in-house DER SAN parse)
    supervisor.rs  # tokio Child + SIGHUP/SIGTERM lifecycle

  mtproxy/         # — Telegram (telemt) —
    runtime.rs     # embedded gzipped ELF
    config.rs      # config.toml (no [access.users] — users go via API)
    client.rs      # minimal HTTP/1.1 client for 127.0.0.1:9091/v1/*
    supervisor.rs  # spawn + reconcile users on every start

  mdnsvpn/         # — DNS tunnel (MasterDnsVPN) —
    runtime.rs     # embedded gzipped ELF
    keys.rs        # 16-byte hex shared-key generator + validator
    config.rs      # server_config.toml (singleton inbound)
    share.rs       # client_config.toml + resolvers.txt + JSON + b64 blob
    bundle.rs      # downloadable client bundle assembly
    logscrub.rs    # strips the tunnel key out of child log output
    supervisor.rs  # tokio Child; rewrite-and-restart on config change

  qqdns/           # — UDP over DNS (in-process, no subprocess) —
    codec.rs       # base32 label packing
    dns.rs         # query/response framing
    reassembly.rs  # fragmentation + retry
    engine.rs      # symmetric duplex engine
    share.rs       # client config emission
    supervisor.rs  # tokio task

  proxy/           # — DPI-imitation proxy (in-process) —
    transform.rs   # S1–S4 padding rewrite per protocol mode
    responder.rs   # active-probe responders (QUIC/DNS/STUN/SIP)
    quic_handshake.rs # QUIC v1 packet layer + TLS 1.3 server flight
    x509.rs        # self-signed per-SNI certificates
    session.rs     # per-peer session state
    shardmap.rs    # sharded concurrent map
    supervisor.rs  # tokio task; refuses AWG3-incompatible interfaces

  dns/             # — Bundled DNS stack —
    runtime.rs     # extract 5 optional ELFs
    dnscrypt.rs    # dnscrypt-proxy.toml generator
    tor.rs         # torrc + BridgeDB scraping for PT support
    supervisor.rs  # tokio Children for dnscrypt-proxy + tor

  api/
    mod.rs         # router, AppState, require_auth
    session.rs     # /api/session, /api/me, TOTP, rate limiter
    clients.rs     # /api/client/* CRUD, IDOR enforcement
    activity.rs    # /api/activity/heatmap, DELETE /api/activity
    admin.rs       # /api/admin/* (admin role required)
    xray.rs        # /api/admin/xray/* + /api/xray/clients/*
    mtproxy.rs     # /api/admin/mtproxy/*
    mdnsvpn.rs     # /api/admin/mdnsvpn/* + /api/mdnsvpn/clients/*
    qqdns.rs       # /api/admin/qqdns/*
    proxy.rs       # /api/admin/proxy/*
    dns.rs         # /api/admin/dns/*
    setup.rs       # /api/setup/* wizard
    routes.rs      # /api/information, /metrics/*, /cnf/:token

static/
  index.html       # SPA shell + inline CSS
  app.js           # SPA logic
  *.png *.svg      # branding

vendor/
  *_VERSION        # pinned versions + uncompressed-ELF SHA-256
  LICENSES/        # upstream LICENSE files, preserved verbatim
  update.sh        # curation tool: download or build, verify, gzip, pin
  README.md        # provenance + curation procedure
  *.gz             # CI artifacts, gitignored, never committed

build.rs           # validates pin SHAs, embeds blobs, tolerates
                   # missing ones (warns + disables the cfg)
```

---

## Dependency policy

The release build is **69 dependency crates, with no crate present at two versions**.

That is deliberate. Most of what a project like this would normally pull in is a
general-purpose library used through one narrow corner. Where that corner is small and
testable against the crate it replaces, it lives here instead — and in every case the
replaced crate is retained as a **dev-dependency** acting as the test oracle, so the
in-house version is pinned to the original's behaviour rather than merely believed to
match it.

| In-house | Replaces | Why |
|---|---|---|
| `src/http/` — HTTP/1.1 server, router, extractors, responses, cookies, query deserializer | `axum`, `hyper`, `tower`, `axum-extra` (~32 crates) | The panel speaks plaintext HTTP/1.1 behind a reverse proxy with in-memory bodies of a few kilobytes. The parser is deliberately strict where request smuggling lives — no obs-fold, no `Content-Length` with `Transfer-Encoding`, no conflicting lengths, explicit limits and timeouts — and `tests/http_server.rs` drives those cases as raw bytes over TCP. `http` itself is kept: it is the ecosystem's shared `Request`/`Response`/`HeaderMap` and costs one crate. |
| `src/proxy/quic_handshake.rs`, `src/proxy/x509.rs` — QUIC v1 packet layer and self-signed certificates | `quinn-proto`, `rcgen` (14 crates) | The DPI responder emits one server flight and forgets the peer; it never needs congestion control, loss recovery or streams. rustls's `quic` module supplies the Initial key schedule, header protection and the TLS state machine. `quinn-proto` stays a dev-dependency and a real QUIC client must accept our flight for the tests to pass. |
| `src/qr.rs` — QR encoder (byte mode, level M, ISO/IEC 18004) | `qrcode` | `tests/qr_parity.rs` asserts our symbol is module-for-module identical to the crate's, and the rendered SVG byte-for-byte identical. |
| `src/inflate.rs` — gzip/DEFLATE decoder | `flate2`, `miniz_oxide`, `adler2`, `crc32fast`, `simd-adler32` | The only runtime use was expanding the vendored ELFs; nothing compresses outside tests. `tests/vendor_blobs.rs` decompresses every real `vendor/*.gz` and checks the SHA-256 against its pin file. |
| `src/log.rs` — level filter, formatter, `RUST_LOG` parsing, event macros | `tracing`, `tracing-subscriber` (~11 crates, including a regex engine for `EnvFilter`) | The codebase never opens a span; every call site is a flat event. |
| `src/proxy/shardmap.rs` — sharded concurrent map | `dashmap`, `crossbeam-utils` | Built on `parking_lot`, which tokio already compiles in. |
| `src/cidr.rs`, `src/encoding.rs`, `src/rng.rs::uuid_v4`, hand-written error impls | `ipnet`, `hex`, `base64`, `uuid`, `thiserror` | Each was a few dozen lines used through a handful of calls. Base64 now comes from `base64ct`, which argon2 already compiles in. |

Earlier passes did the same for 2FA (hand-rolled HMAC-SHA1 TOTP rather than a TOTP crate
dragging in the `url`/ICU stack), the Reality dest probe's certificate SAN extraction (a
small DER walk instead of a full X.509 parser), date handling (`time` rather than a second
`chrono` tree), and randomness (the OS CSPRNG via `getrandom` instead of the `rand`
userspace generator).

### Two consequences worth stating plainly

- **QR codes for payloads with long digit runs may be one version larger.** The `qrcode`
  crate ran a segment optimiser that could encode a run of digits in numeric mode; ours is
  byte-mode only. The AmneziaWG config, `vless://` and `mdnsvpn://` payloads are
  unaffected — they are mixed-case throughout, so the optimiser chose byte mode too. A
  `tg://proxy` link with a 70-hex-digit secret renders at 49 modules instead of 45. Both
  scan.
- **The HTTP server is ours now.** It is the most exposed code in the project. It is strict
  by construction, covered by wire-level tests, and unchanged in behaviour for every route
  the panel serves — but it is a hand-written parser on an internet-facing port and should
  be read as such. Keep the reverse proxy in front of it.

The gate that keeps this honest is in [BUILDING.md](BUILDING.md#dependency-gate):
`Cargo.lock` is committed, every build path passes `--locked`, and `cargo-deny` fails CI on
an advisory, a yanked crate, an unexpected duplicate version, a license outside the
allowlist, or a non-crates.io source.
