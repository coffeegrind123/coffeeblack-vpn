# Configuration

All static configuration is supplied through environment variables. Anything an operator
changes day to day lives in SQLite and is edited in the admin UI.

- [Server](#server)
- [Run entirely in memory](#run-entirely-in-memory)
- [First-run auto-setup](#first-run-auto-setup)
- [Runtime tunables](#runtime-tunables)
- [Metrics](#metrics)
- [TLS](#tls)
- [Upgrades](#upgrades)
- [Operational notes](#operational-notes)

---

## Server

| Variable | Default | Description |
|---|---|---|
| `PORT` | `51821` | Web UI listen port. |
| `HOST` | `0.0.0.0` | Web UI bind address. |
| `INSECURE` | `false` | Drops the `Secure` flag from the session cookie. **Only for a trusted local network without TLS.** Leave it `false` and terminate TLS upstream in production. |
| `DISABLE_IPV6` | `false` | Skip IPv6 in generated configs and firewall rules. |
| `COFFEEBLACK_DB_PATH` | `/etc/coffeeblack/conf/coffeeblack.db` | SQLite database path. |
| `COFFEEBLACK_CONF_DIR` | `/etc/coffeeblack/conf` | Runtime root. The generated `cb0.conf` is written here. |
| `COFFEEBLACK_HELPER_SOCKET` | — | Path to the privileged helper's Unix socket. When set, every `awg` / `nft` call and the interface config write are routed through the helper and this process needs no capabilities. Unset means execute directly. See [Privilege separation](SECURITY.md#privilege-separation). |
| `COFFEEBLACK_HELPER_INTERFACE` | `cb0` | Helper only. The single interface it will act on; never read from a request. |
| `COFFEEBLACK_HELPER_GID` | — | Helper only. The gid allowed to connect. Sets the socket to `0660` and chowns it to that group; unset leaves it `0600`, root only. |
| `COFFEEBLACK_SECRET_KEY_PATH` | — | Path to a file holding the base64 AES-256 key used to encrypt secrets at rest. Intended for `LoadCredentialEncrypted=` under systemd. Takes precedence over `COFFEEBLACK_SECRET_KEY`. |
| `COFFEEBLACK_SECRET_KEY` | — | The base64 AES-256 key itself, 32 bytes: `openssl rand -base64 32`. For Docker and development. Unset means secrets are stored in plaintext, with a startup warning. |
| `COFFEEBLACK_XRAY_DIR` | `<CONF_DIR>/xray` | Where the bundled Xray ELF is extracted and `server.json` is written. |
| `XRAY_BIN_PATH` | — | Use this `xray` binary instead of extracting the bundled one. For operators tracking upstream Xray independently. |
| `COFFEEBLACK_MTPROXY_DIR` | `<CONF_DIR>/mtproxy` | Where the bundled `telemt` ELF is extracted, plus its `config.toml`, PID file, and the `tlsfront` cache of real TLS records fetched from the masking domain. |
| `COFFEEBLACK_MDNSVPN_DIR` | `<CONF_DIR>/mdnsvpn` | Where the bundled MasterDnsVPN ELF is extracted, plus `server_config.toml` and the singleton `encrypt_key.txt`. |
| `COFFEEBLACK_DNS_DIR` | `<CONF_DIR>/dns` | Where the bundled DNS-stack ELFs are extracted, plus their generated configs and tor's data directory. |

Persist the four subsystem directories on a volume to avoid re-extracting binaries on
every restart. The `dns` directory is worth persisting for a second reason: it holds
tor's consensus and onion descriptors.

---

## Run entirely in memory

| Variable | Default | Description |
|---|---|---|
| `IN_MEMORY` | `true` | Run with the data plane fully RAM-resident. Set `IN_MEMORY=false` for a classic durable on-disk database at `COFFEEBLACK_DB_PATH`. |
| `COFFEEBLACK_PERSIST_DB` | — (`/data/coffeeblack.db` in the image) | Durable snapshot file for the RAM database. Read only at boot; re-written by a background task and on graceful shutdown. Unset means pure RAM and state is lost on restart. Only consulted when `IN_MEMORY=true`. |
| `COFFEEBLACK_PERSIST_INTERVAL` | `30` | Seconds between RAM→disk snapshots. `0` disables periodic snapshots; shutdown still snapshots. |

When `IN_MEMORY=true`:

**Database.** SQLite is opened `:memory:`, so no query ever blocks on disk. If
`COFFEEBLACK_PERSIST_DB` is set, the full roster — clients, Reality keys, MTProxy
secrets, the MasterDnsVPN key, accounts, 2FA — is restored from that file at boot and
snapshotted back out of band through SQLite's online-backup API. Every snapshot is
best-effort and off the request path: a degraded or read-only disk demotes you to "no
fresh snapshot", it never stalls or crashes the data plane. That is the property the mode
exists for — the service comes up and stays up from RAM regardless of disk health.

**Subprocess binaries.** Each is decompressed, SHA-256-verified, and sealed with
`F_SEAL_WRITE` inside an anonymous `memfd`, then exec'd via `/proc/self/fd/N`. The binary
has no name in any filesystem and is immutable. The memfd is cached for the process
lifetime, so a crash-looping child re-`exec`s the same in-RAM image with no re-extraction.
`XRAY_BIN_PATH` still overrides Xray with a real on-disk binary if you want that.

**Config files, the `.conf`, tor's data dir, PT plugins.** These still need real paths —
tor `exec`s its lyrebird/snowflake/webtunnel plugins by the path written into `torrc`, and
`awg-quick` reads `<CONF_DIR>/cb0.conf`. Mount the runtime root as a **tmpfs** so they
live in RAM too. The shipped `docker-compose.yml` does exactly that, with a durable volume
only at `/data`. The server logs a warning at startup if `IN_MEMORY=true` but the runtime
root is not tmpfs.

No extra Linux capabilities are needed for any of this: `memfd` requires none and the
tmpfs comes from the container runtime, so the capability set stays `NET_ADMIN` alone. The
shipped compose file does `cap_drop: ALL` and re-adds only that. `SYS_MODULE` was dropped
deliberately — it let the container load kernel modules into the *host* kernel, and
`amneziawg-go` is userspace, so it was never needed.

---

## First-run auto-setup

These take effect only when no admin user exists, which makes `INIT_ENABLED=true`
deployments idempotent — restarting with the same environment does not recreate the user.

| Variable | Default | Description |
|---|---|---|
| `INIT_ENABLED` | `false` | Master switch. |
| `INIT_USERNAME` | — | Initial admin username. Required when enabled. |
| `INIT_PASSWORD` | — | Initial admin password, minimum 12 characters. Required when enabled. A shorter value is rejected and the server refuses to start rather than leaving the setup wizard open to the internet. |
| `INIT_HOST` | — | WireGuard endpoint hostname or IP. |
| `INIT_PORT` | `51820` | WireGuard listen port. |
| `INIT_DNS` | — | Comma-separated DNS servers pushed to clients. |
| `INIT_IPV4_CIDR` | `10.8.0.0/24` | IPv4 pool for clients. |
| `INIT_IPV6_CIDR` | `fdcc:ad94:bacf:61a4::cafe:0/112` | IPv6 pool for clients. |
| `INIT_ALLOWED_IPS` | — | Comma-separated default `AllowedIPs` for clients. |

---

## Runtime tunables

Stored in SQLite and edited in the admin panel, not through the environment:

- `metricsPrometheus`, `metricsJson`, `metricsPassword` (stored hashed)
- `sessionTimeout`, in seconds
- `privateKeyRetention` — `never` (default) or `plaintext`. See
  [Peer private keys](SECURITY.md#peer-private-keys).
- `activityRetentionDays` — 0–365, default 30. `0` disables collection *and* purges. See
  [Activity history](SECURITY.md#activity-history-and-privacy).
- AmneziaWG 2.x parameters: `Jc`/`Jmin`/`Jmax`, `S1`–`S4`, `H1`–`H4`, `I1`–`I5`
- AmneziaWG 3 device knobs — see [AmneziaWG 3](TRANSPORTS.md#amneziawg-3)
- Per-client `AdvancedSecurity`: on, off, or auto-detect
- Per-client firewall rules
- Free-form `additional_config` append for the AmneziaWG `[Interface]`, server and per-peer
- DNS lockdown: master switch, redirect target IP, drop-residual toggle
- Xray Reality inbound and per-peer expiry
- MTProxy inbound and per-user secret, ad-tag override, enabled state
- DNS bundle: master switch, listen port, upstream resolvers, DNSSEC / no-log / no-filter
  requirements, optional Tor routing with exit-country and pluggable-transport selectors

---

## Metrics

Two endpoints, both disabled until you enable them in Admin → General:

| Endpoint | Format |
|---|---|
| `/metrics/prometheus` | Prometheus text exposition |
| `/metrics/json` | JSON |

When `metricsPassword` is set, both require a `Bearer` token. Only the SHA-256 of that
password is stored, never the cleartext, and it is compared in constant time.

Exported per peer:

| Series | Meaning |
|---|---|
| rx / tx bytes | Raw kernel counters. **These reset to zero on every interface restart.** |
| `wireguard_peer_total_rx_bytes` / `_total_tx_bytes` | Monotonic lifetime totals accumulated by the poller, unaffected by those resets. Use these for anything cumulative. |
| `wireguard_peer_last_seen` | Last handshake timestamp. |
| online state | Derived from the last handshake age. |

The monotonic counters come from the same 30 s poller that backs the connection heatmap —
see [Activity history](SECURITY.md#activity-history-and-privacy) for what it does and does
not retain.

---

## TLS

The binary ships **without** TLS termination. Put a reverse proxy in front of it.

Caddy:

```caddy
vpn.example.com {
    reverse_proxy coffeeblack-vpn:51821
}
```

nginx:

```nginx
server {
    listen 443 ssl http2;
    server_name vpn.example.com;
    ssl_certificate     /etc/letsencrypt/live/vpn.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/vpn.example.com/privkey.pem;
    location / {
        proxy_pass http://127.0.0.1:51821;
        proxy_set_header Host            $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Real-IP       $remote_addr;
    }
}
```

Set those forwarded-address headers: the login rate limiter reads `X-Forwarded-For` /
`X-Real-IP` for its per-source-IP buckets, and without them every request looks like it
came from the proxy.

If you genuinely must run without a proxy on a trusted network, set `INSECURE=true`. **Do
not leave that on for an internet-facing deployment** — the session cookie then travels
over plain HTTP and any on-path observer can steal the session.

---

## Upgrades

CoffeeBlack is a standalone project and is not a drop-in for upstream `awg-easy` or
`wg-easy`. It runs against its own database at `COFFEEBLACK_DB_PATH`.

Between CoffeeBlack versions, idempotent `ALTER TABLE` migrations apply on first boot. No
manual DDL is ever required.

---

## Operational notes

- **Backups.** Copy the database while the service is stopped, or use `sqlite3 .backup`.
  The `.conf` files and live kernel state regenerate from it on the next start. Back up
  your `COFFEEBLACK_SECRET_KEY` separately and out of band — the database is useless
  without it.
- **Health checks.** `/health` always returns 200 once the web layer is up. The Docker
  health check separately runs `awg show` to verify the kernel interface. Use both if you
  want the orchestrator to distinguish "web up" from "tunnel up".
- **Sessions** are in-memory only, so a restart logs everyone out.
- **Expiry** is enforced by a background job every 60 s, which retires expired clients and
  one-time download links.
- **Failure isolation.** If `awg-quick up cb0` fails, the binary still starts and serves
  the web UI so you can fix the host config and hit *Restart Interface*. Per-supervisor
  failures surface in their own admin tabs. All five transports degrade independently.
