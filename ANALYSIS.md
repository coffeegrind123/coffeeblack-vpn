# awg-easy Comprehensive Analysis for Rust Rewrite

## Overview
awg-easy is an AmneziaWG VPN + Web UI management tool. It's a fork of wg-easy.
Runs as a single Docker container. Manages an AmneziaWG (or WireGuard) interface
with a web-based admin UI.

**Tech stack:** Nuxt 3 + Nitro server, Vue 3, SQLite (libsql), Drizzle ORM, Pinia, Radix Vue, Tailwind CSS

## Architecture

```
Docker Container
├── Node.js Nitro Server (port 51821)
│   ├── API routes (file-based, Nitro)
│   ├── Database: SQLite at /etc/coffeeblack/conf/coffeeblack.db
│   ├── WireGuard config at /etc/coffeeblack/conf/wg0.conf
│   └── Frontend: Vue 3 SPA (server-rendered)
├── awg/wg CLI tools (amneziawg-tools)
├── amneziawg-go (userspace WireGuard for Amnezia)
└── iptables/ip6tables for NAT + firewall
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| PORT | 51821 | Web UI port |
| HOST | 0.0.0.0 | Web UI bind address |
| INSECURE | false | HTTP mode (no HTTPS) |
| DISABLE_IPV6 | false | Disable IPv6 |
| DEBUG | Server,WireGuard,Database,CMD | Debug namespaces |
| EXPERIMENTAL_AWG | false | Enable AmneziaWG detection (auto-detect via `modinfo amneziawg`) |
| OVERRIDE_AUTO_AWG | - | Force `wg` or `awg` |
| INIT_ENABLED | false | Auto-setup on first run |
| INIT_USERNAME | - | Initial admin username |
| INIT_PASSWORD | - | Initial admin password |
| INIT_HOST | - | Server endpoint hostname |
| INIT_PORT | 51820 | WireGuard listen port |
| INIT_DNS | - | Comma-separated DNS servers |
| INIT_IPV4_CIDR | - | IPv4 CIDR for VPN |
| INIT_IPV6_CIDR | - | IPv6 CIDR for VPN |
| INIT_ALLOWED_IPS | - | Comma-separated allowed IPs |

## Database Schema (SQLite)

File: `/etc/coffeeblack/conf/coffeeblack.db`

### interfaces_table
| Column | Type | Notes |
|---|---|---|
| name | TEXT PK | e.g. "wg0" |
| device | TEXT | e.g. "eth0" |
| port | INTEGER UNIQUE | WireGuard port (51820) |
| private_key | TEXT | Server private key |
| public_key | TEXT | Server public key |
| ipv4_cidr | TEXT | e.g. "10.8.0.0/24" |
| ipv6_cidr | TEXT | e.g. "fdcc:ad94:bacf:61a4::cafe:0/112" |
| mtu | INTEGER | Default 1420 |
| j_c | INTEGER | Junk count, default 7 |
| j_min | INTEGER | Junk min size, default 10 |
| j_max | INTEGER | Junk max size, default 1000 |
| s1 | INTEGER | Init junk size, default 128 |
| s2 | INTEGER | Response junk size, default 56 |
| s3 | INTEGER | nullable |
| s4 | INTEGER | nullable |
| h1 | TEXT | Magic header 1 |
| h2 | TEXT | Magic header 2 |
| h3 | TEXT | Magic header 3 |
| h4 | TEXT | Magic header 4 |
| i1 | TEXT | Init junk 1 (giant hex blob default) |
| i2 | TEXT | Init junk 2 |
| i3 | TEXT | Init junk 3 |
| i4 | TEXT | Init junk 4 |
| i5 | TEXT | Init junk 5 |
| firewall_enabled | INTEGER | Default false |
| enabled | INTEGER | Always 1 |
| created_at | TEXT | CURRENT_TIMESTAMP |
| updated_at | TEXT | CURRENT_TIMESTAMP |

### clients_table
| Column | Type | Notes |
|---|---|---|
| id | INTEGER PK AUTOINCREMENT | |
| user_id | INTEGER FK→users_table | |
| interface_id | TEXT FK→interfaces_table | |
| name | TEXT | Client name |
| ipv4_address | TEXT UNIQUE | e.g. "10.8.0.2" |
| ipv6_address | TEXT UNIQUE | |
| private_key | TEXT | |
| public_key | TEXT | |
| pre_shared_key | TEXT | |
| pre_up | TEXT | |
| post_up | TEXT | |
| pre_down | TEXT | |
| post_down | TEXT | |
| expires_at | TEXT | nullable |
| allowed_ips | TEXT (JSON array) | nullable, e.g. ["0.0.0.0/0"] |
| server_allowed_ips | TEXT (JSON array) | Server-side AllowedIPs |
| firewall_ips | TEXT (JSON array) | nullable, per-client firewall rules |
| persistent_keepalive | INTEGER | |
| mtu | INTEGER | |
| j_c | INTEGER | nullable |
| j_min | INTEGER | nullable |
| j_max | INTEGER | nullable |
| i1-i5 | TEXT | nullable |
| dns | TEXT (JSON array) | nullable |
| server_endpoint | TEXT | nullable |
| enabled | INTEGER (boolean) | |
| created_at | TEXT | CURRENT_TIMESTAMP |
| updated_at | TEXT | CURRENT_TIMESTAMP |

### users_table
| Column | Type | Notes |
|---|---|---|
| id | INTEGER PK AUTOINCREMENT | |
| username | TEXT UNIQUE | |
| password | TEXT | argon2 hash |
| email | TEXT | nullable |
| name | TEXT | |
| role | INTEGER | Admin/Clients |
| totp_key | TEXT | nullable, TOTP secret |
| totp_verified | INTEGER (boolean) | |
| enabled | INTEGER (boolean) | |
| created_at | TEXT | |
| updated_at | TEXT | |

### user_configs_table
| Column | Type | Notes |
|---|---|---|
| id | TEXT PK FK→interfaces | "wg0" |
| default_mtu | INTEGER | 1420 |
| default_persistent_keepalive | INTEGER | 0 |
| default_dns | TEXT (JSON) | ["1.1.1.1","2606:4700:4700::1111"] |
| default_allowed_ips | TEXT (JSON) | ["0.0.0.0/0","::/0"] |
| default_j_c-j_max | INTEGER | AWG defaults |
| default_i1-i5 | TEXT | AWG init junk defaults |
| host | TEXT | Server endpoint |
| port | INTEGER | WireGuard port |

### hooks_table
| Column | Type | Notes |
|---|---|---|
| id | TEXT PK FK→interfaces | "wg0" |
| pre_up | TEXT | iptables template |
| post_up | TEXT | NAT + forwarding rules |
| pre_down | TEXT | |
| post_down | TEXT | cleanup rules |

### general_table
| Column | Type | Notes |
|---|---|---|
| id | INTEGER PK | Always 1 |
| setup_step | INTEGER | 0=done, 1=pending |
| session_password | TEXT | Random 256-byte hex, SHA-256 hashed |
| session_timeout | INTEGER | Seconds (3600) |
| metrics_prometheus | INTEGER (bool) | |
| metrics_json | INTEGER (bool) | |
| metrics_password | TEXT | nullable |
| created_at | TEXT | |
| updated_at | TEXT | |

### one_time_links_table
| Column | Type | Notes |
|---|---|---|
| id | INTEGER PK FK→clients | Client ID |
| one_time_link | TEXT UNIQUE | Random token |
| expires_at | TEXT | |
| created_at | TEXT | |
| updated_at | TEXT | |

## WireGuard/AmneziaWG Config Generation

### Server Config (`/etc/coffeeblack/conf/wg0.conf`)
```
[Interface]
PrivateKey = <server_private_key>
Address = <ipv4_addr>/<cidr>, <ipv6_addr>/<cidr>
ListenPort = <port>
MTU = <mtu>
Jc = <j_c>           # only if awg
Jmin = <j_min>
Jmax = <j_max>
S1 = <s1>
S2 = <s2>
S3 = <s3>            # if non-zero
S4 = <s4>            # if non-zero
H1 = <h1>
H2 = <h2>
H3 = <h3>
H4 = <h4>
I1 = <i1>            # if non-empty
I2 = <i2>
I3 = <i3>
I4 = <i4>
I5 = <i5>
PreUp = <template with {{device}} {{port}} {{ipv4Cidr}} {{ipv6Cidr}}>
PostUp = iptables -t nat -A POSTROUTING -s <cidr> -o <device> -j MASQUERADE; ...
PreDown = ...
PostDown = ...

# For each enabled client:
[Peer]
PublicKey = <client_public_key>
PresharedKey = <pre_shared_key>
AllowedIPs = <ipv4>/32, <ipv6>/128, <server_allowed_ips>
Endpoint = <server_endpoint>  # if set
```

### Client Config
```
[Interface]
PrivateKey = <client_private_key>
Address = <ipv4>/32, <ipv6>/128
MTU = <mtu>
DNS = <dns_servers>
Jc = <j_c>           # AmneziaWG params
Jmin = <j_min>
Jmax = <j_max>
S1-S4, H1-H4, I1-I5, J1-J3, Itime

[Peer]
PublicKey = <server_public_key>
PresharedKey = <pre_shared_key>
AllowedIPs = <allowed_ips>
PersistentKeepalive = <keepalive>
Endpoint = <host>:<port>
```

## wg/awg CLI Commands Used

| Command | Purpose |
|---|---|
| `awg genkey` | Generate private key |
| `echo <key> \| awg pubkey` | Derive public key |
| `awg genpsk` | Generate pre-shared key |
| `awg-quick up wg0` | Bring up interface |
| `awg-quick down wg0` | Take down interface |
| `awg syncconf wg0 <(awg-quick strip wg0)` | Sync config without restart |
| `awg show wg0 dump` | Get peer status (handshake, transfer, endpoint) |

## iptables/Firewall Rules

### Default NAT (from hooks_table PostUp):
```bash
iptables -t nat -A POSTROUTING -s <ipv4Cidr> -o <device> -j MASQUERADE
iptables -A INPUT -p udp -m udp --dport <port> -j ACCEPT
iptables -A FORWARD -i wg0 -j ACCEPT
iptables -A FORWARD -o wg0 -j ACCEPT
# IPv6 equivalents with ip6tables
```

### Per-Client Firewall (iptables):
When `firewall_enabled = true`:
- Creates custom chain `WG_CLIENTS`
- Jumps from FORWARD chain: `iptables -I FORWARD 1 -i wg0 -j WG_CLIENTS`
- Per-client ACCEPT rules for allowed IPs/ports
- Final DROP: `iptables -A WG_CLIENTS -j DROP`

### sysctls (from docker-compose):
```
net.ipv4.ip_forward=1
net.ipv4.conf.all.src_valid_mark=1
net.ipv6.conf.all.disable_ipv6=0
net.ipv6.conf.all.forwarding=1
net.ipv6.conf.default.forwarding=1
```

### Docker capabilities:
- NET_ADMIN (for iptables + interface management)
- SYS_MODULE (for kernel module loading)

## AmneziaWG Obfuscation Parameters

Generated randomly on first run (unique per installation):

| Param | Range | Purpose |
|---|---|---|
| Jc | 4-12 | Junk packet count |
| Jmin | 8-80 | Junk packet minimum size |
| Jmax | 80-1280 | Junk packet maximum size |
| S1 | 15-150 | Init header junk size (≤1132) |
| S2 | 15-150 | Response header junk size (≤1188) |
| H1-H4 | 5-2147483647 | Magic headers (must be distinct, >4) |

## Auth & Session Flow

1. Session password stored in `general_table.session_password` (SHA-256 of random 256-byte blob)
2. Login: POST to session endpoint with password → sets HTTP-only cookie with signed token
3. 2FA: TOTP support via `users_table.totp_key`
4. Permissions: role-based (admin, clients), per-endpoint permission checks
5. Setup flow: redirects to /setup if `general_table.setup_step != 0`

## Setup Wizard (4 Steps)

1. Step 2 (POST): Set admin password + email, generate keys, create interface
2. Step 4 (GET/POST): Configure server endpoint (host:port), DNS, MTU, CIDR
3. Migration: POST migrate for v14→v15 migration

## API Endpoints (Complete)

### Public
| Method | Path | Auth | Description |
|---|---|---|---|
| GET | /api/information | None | App version, release info |
| GET | /api/interface | None | Interface public info (hidden private key) |
| GET | /api/session | Session | Check session validity |
| POST | /api/session | None | Login (password in body) |
| DELETE | /api/session | Session | Logout |

### Setup
| Method | Path | Auth | Description |
|---|---|---|---|
| POST | /api/setup/2 | None | Setup step 2 (admin password + keys) |
| GET | /api/setup/4 | Setup | Get setup step 4 config |
| POST | /api/setup/4 | Setup | Save setup step 4 config |
| POST | /api/setup/migrate | Session | v14→v15 migration |

### Admin Interface
| Method | Path | Auth | Description |
|---|---|---|---|
| GET | /api/admin/interface | Admin | Get full interface config |
| POST | /api/admin/interface | Admin | Update interface config |
| POST | /api/admin/interface/restart | Admin | Restart wg interface |
| POST | /api/admin/interface/cidr | Admin | Change CIDR (reassigns client IPs) |

### Admin General
| Method | Path | Auth | Description |
|---|---|---|---|
| GET | /api/admin/general | Admin | Get general settings |
| POST | /api/admin/general | Admin | Update general settings |
| GET | /api/admin/hooks | Admin | Get hooks |
| POST | /api/admin/hooks | Admin | Update hooks |
| GET | /api/admin/ip-info | Admin | Get public IP info |
| GET | /api/admin/userconfig | Admin | Get user config defaults |
| POST | /api/admin/userconfig | Admin | Update user config defaults |

### Clients
| Method | Path | Description |
|---|---|---|
| GET | /api/client | List clients (w/ wg dump data) |
| POST | /api/client | Create client |
| GET | /api/client/:id | Get client details |
| POST | /api/client/:id | Update client |
| DELETE | /api/client/:id | Delete client |
| GET | /api/client/:id/configuration | Download client config |
| GET | /api/client/:id/qrcode.svg | QR code SVG |
| POST | /api/client/:id/enable | Enable client |
| POST | /api/client/:id/disable | Disable client |
| POST | /api/client/:id/generateOneTimeLink | Generate OTL |

### Routes (special)
| Method | Path | Description |
|---|---|---|
| GET | /cnf/:oneTimeLink | Download config via one-time link |
| GET | /metrics/json | JSON metrics |
| GET | /metrics/prometheus | Prometheus metrics |

## Cron Job (every 60 seconds)
1. Check for expired clients (disable them)
2. Check for expired one-time links (delete them)
3. Save/sync config if client state changed

## Docker Build Process (Multi-stage)

1. **Build stage (node:krypton-alpine):**
   - Install pnpm
   - pnpm install + pnpm build (Nuxt build)
   - Build amneziawg-go from source
   - Build amneziawg-tools from source

2. **Kernel module builder (alpine:3.22):**
   - Build amneziawg-linux-kernel-module against linux-lts

3. **Final stage (node:krypton-alpine):**
   - Copy .output (Nitro build)
   - Copy migrations
   - Install libsql
   - Copy CLI script
   - Copy amneziawg-go + awg + awg-quick binaries
   - Copy pre-built kernel module
   - Install iptables, nftables, kmod, wireguard-tools
   - Use iptables-legacy
   - Run: `node server/index.mjs`

## Key Dependencies (relevant to Rust rewrite)

| npm package | Purpose |
|---|---|
| @libsql/client | SQLite client |
| drizzle-orm | ORM |
| argon2 | Password hashing |
| cidr-tools | CIDR parsing |
| ip-bigint | IP arithmetic |
| zod | Schema validation |
| qr | QR code generation |
| otpauth | TOTP 2FA |
| consola | Logging |

## What the Rust Binary Must Do

1. **HTTP Server** (replace Nitro): Serve API + static HTML/CSS/JS
2. **SQLite** (replace libsql + Drizzle): Same schema, same DB file
3. **WireGuard/AmneziaWG Management**: Execute awg/wg CLI, generate configs, parse dump
4. **Config Generation**: Server config, client configs (identical format)
5. **iptables Management**: NAT rules, per-client firewall
6. **Auth**: Session management, password hashing, TOTP 2FA
7. **QR Code**: Generate SVG QR codes from config text
8. **Cron**: Background task to expire clients/links
9. **Frontend**: Serve HTML/CSS/JS that replicates existing Vue UI
10. **i18n**: Support 22 languages (static JSON files served to client)
11. **Setup Wizard**: First-run configuration flow
12. **Metrics**: Prometheus + JSON metrics endpoints
