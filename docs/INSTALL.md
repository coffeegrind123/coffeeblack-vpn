# Bare-metal installation

This guide covers installing **coffeeblack-vpn** directly on a host (no Docker), as a
systemd service. For the container path see the top-level `README.md` and
`docker-compose.yml`.

coffeeblack-vpn is a single static-musl binary. On a bare-metal host the installer's
job is small and specific:

1. Install the **AmneziaWG kernel module + `amneziawg-tools`** so `awg` /
   `awg-quick` exist and the fast in-kernel data path is available.
2. Install the **coffeeblack-vpn binary** as a systemd service.
3. Enable host **IPv4/IPv6 forwarding** (sysctl).
4. Seed the **first-run admin** (the `INIT_*` env vars) into an EnvironmentFile.

> coffeeblack-vpn **owns the AmneziaWG interface lifecycle itself**: on startup it
> runs `awg-quick up cb0` (writing `/etc/coffeeblack/conf/cb0.conf`) and tears it down
> on shutdown. There is therefore **no `awg-quick@cb0` service** to enable — the
> coffeeblack-vpn service is the only unit you manage.

---

## Quick start

```bash
# From a repository checkout (or after downloading the scripts):
sudo ./scripts/install.sh
```

Interactive install: it detects your distro, installs the kernel module + tools,
downloads the latest release binary, and prompts for the web port, the admin
user/password, and the WireGuard endpoint/pool. When it finishes, open:

```
https://<server-ip>:51821/
```

Put a TLS-terminating reverse proxy in front for anything Internet-facing (see
[TLS](#tls)), or pass `--insecure` for a trusted LAN without TLS.

### One-shot non-interactive install

```bash
sudo AUTO_INSTALL=y ./scripts/install.sh install \
  --admin-user admin \
  --admin-password 'use-a-real-password' \
  --endpoint vpn.example.com \
  --wg-port 51820
```

Everything the prompts would ask can be supplied via flags or same-named
environment variables (`INIT_PASSWORD`, `INIT_HOST`, `PORT`, `HOST`, …).

---

## Prerequisites

- A **systemd** Linux host on one of the supported distros:
  - Debian ≥ 11, Ubuntu ≥ 22.04, Linux Mint ≥ 21 — **fully supported**
    (apt `ppa:amnezia/ppa` + DKMS; Debian uses a manually verified keyring).
  - Fedora ≥ 39, CentOS/AlmaLinux/Rocky ≥ 9 — the dnf COPR
    (`amneziavpn/amneziawg`) + `amneziawg-dkms` path is present but
    **temporarily disabled** upstream because verified AmneziaWG 2.0 RPMs are not
    yet published. Management/uninstall on an existing install still work.
- **Root** (`sudo`).
- Not inside **OpenVZ** or **LXC** (the kernel module must load on the host; the
  installer refuses these).
- Outbound network access to the distro repos and, unless you build or supply
  the binary yourself, to GitHub releases.

The installer pulls in kernel headers and DKMS so the `amneziawg` module builds
for your running kernel. On some VPS providers IPv6 resolves but is unreachable;
the installer transparently forces IPv4 for package operations while it runs and
reverts that afterwards.

---

## Binary source

`install` and `upgrade` obtain the binary one of three ways (pick at most one):

| Mode | Flag | Notes |
|------|------|-------|
| Download release (default) | *(none)* | `https://github.com/coffeegrind123/coffeeblack-vpn/releases/latest/download/coffeeblack-vpn`. A repo-local `target/x86_64-unknown-linux-musl/release/coffeeblack-vpn` is used if present. |
| Pre-built binary | `--binary-src PATH` | Install a binary you already have (CI artifact, air-gapped copy). |
| Build from source | `--build-from-source` | Runs `cargo build --release --target x86_64-unknown-linux-musl` in the repo. Add `--install-rust` to bootstrap rustup if `cargo` is missing. |

---

## Subcommands

```
sudo ./scripts/install.sh [install|upgrade|uninstall|status] [options]
```

`install` is the default when no subcommand is given.

### install

Full provisioning (module + tools, binary, sysctl, service, EnvironmentFile).

```bash
# Interactive
sudo ./scripts/install.sh

# Build from source and install, no prompts
sudo AUTO_INSTALL=y ./scripts/install.sh install \
  --build-from-source --install-rust \
  --admin-user admin --admin-password 's3cret!' --endpoint 203.0.113.10

# Assume the module is already present; just install the service
sudo ./scripts/install.sh install --skip-module
```

### upgrade

Replace the installed binary (download / rebuild / `--binary-src`), refresh the
service unit, and restart. **Config and the database are left untouched.**

```bash
sudo ./scripts/install.sh upgrade                     # latest release
sudo ./scripts/install.sh upgrade --build-from-source # rebuild locally
sudo ./scripts/install.sh upgrade --binary-src ./coffeeblack-vpn
```

### uninstall

Stop/disable the service, bring `cb0` down, and remove the binary, unit, and
sysctl drop-in. Config and data are **kept** unless you ask otherwise.

```bash
sudo ./scripts/install.sh uninstall                 # keep config + data
sudo ./scripts/install.sh uninstall --purge-config  # also remove /etc/coffeeblack
sudo ./scripts/install.sh uninstall --purge-data    # also remove /etc/coffeeblack/conf (DB, cb0.conf)
sudo ./scripts/install.sh uninstall --force         # no confirmation
```

The `amneziawg` kernel module and `amneziawg-tools` are intentionally **left
installed** (other tooling may rely on them); remove them by hand if you want
(`sudo apt remove -y amneziawg amneziawg-tools`).

### status

Report install/service/module health at a glance.

```bash
sudo ./scripts/install.sh status
```

---

## All options

```
--non-interactive        Never prompt; fail if a required value is missing.
                         (AUTO_INSTALL=y in the environment does the same.)
--binary-src PATH        Install a pre-built binary.
--build-from-source      cargo build --release --target x86_64-unknown-linux-musl
--install-rust           Bootstrap rustup if cargo is missing (with --build-from-source).
--port PORT              Web UI port (default 51821).
--host HOST              Web UI bind address (default 0.0.0.0).
--listen HOST:PORT       Shorthand for --host + --port.
--insecure               Drop the Secure cookie flag (trusted LAN without TLS).
--disable-ipv6           Skip IPv6 in generated configs / firewall / sysctl.
--skip-module            Do not install the kernel module / tools.
--no-enable              Do not enable the service at boot.
--no-start               Do not start the service immediately.
--force                  Overwrite managed files / skip confirmations.

First-run admin (install):
--admin-user NAME        Admin username (default admin).
--admin-password PW      Admin password (>=6 chars). Prompted interactively.
--no-init                Do not seed an admin; use the web setup wizard instead.
--endpoint HOST          Public WireGuard endpoint advertised to clients (INIT_HOST).
--wg-port PORT           AmneziaWG UDP listen port (default 51820).
--dns SERVERS            Comma-separated client DNS (default 1.1.1.1,1.0.0.1).
--ipv4-cidr CIDR         Client IPv4 pool (default 10.8.0.0/24).
--ipv6-cidr CIDR         Client IPv6 pool.
--allowed-ips LIST       Default client AllowedIPs (default 0.0.0.0/0,::/0).

uninstall:
--purge-config           Also delete /etc/coffeeblack.
--purge-data             Also delete /etc/coffeeblack/conf (DB, cb0.conf, subprocess state).
```

---

## Installed files

| Path | Purpose |
|------|---------|
| `/usr/local/bin/coffeeblack-vpn` | The binary. |
| `/etc/systemd/system/coffeeblack-vpn.service` | systemd unit. |
| `/etc/coffeeblack/coffeeblack.env` | EnvironmentFile (mode 0600, root-only). |
| `/etc/coffeeblack/conf/` | Runtime root: `cb0.conf`, `coffeeblack.db`, and the extracted subprocess working dirs (`xray/`, `mtproxy/`, `dns/`, `mdnsvpn/`). |
| `/etc/amnezia/amneziawg` | Symlink to `/etc/coffeeblack/conf`. See [Config bridge](#config-bridge). |
| `/etc/sysctl.d/99-coffeeblack.conf` | IPv4/IPv6 forwarding. |
| `/etc/modules-load.d/amneziawg.conf` | Autoload the module at boot. |

### Config bridge

`awg-quick` does **not** consult `COFFEEBLACK_CONF_DIR`. amneziawg-tools'
`wg-quick/linux.bash` hardcodes the lookup when it is handed a bare interface
name — which is what coffeeblack-vpn passes:

```bash
[[ $CONFIG_FILE =~ ^[a-zA-Z0-9_=+.-]{1,15}$ ]] && \
    CONFIG_FILE="/etc/amnezia/amneziawg/$CONFIG_FILE.conf"
```

So `awg-quick up cb0` reads `/etc/amnezia/amneziawg/cb0.conf`, while
coffeeblack-vpn writes `$COFFEEBLACK_CONF_DIR/cb0.conf`. The installer bridges
the two with a symlink (the Docker image does the same thing at build time).
If you set a custom `COFFEEBLACK_CONF_DIR`, repoint the symlink to match:

```bash
sudo ln -sfn "$COFFEEBLACK_CONF_DIR" /etc/amnezia/amneziawg
```

Symptom when it is missing or stale: `awg-quick` exits with
`` `/etc/amnezia/amneziawg/cb0.conf' does not exist `` and Gaming mode never
comes up, while the web UI still serves normally.

---

## Environment variables

The service reads its configuration from `/etc/coffeeblack/coffeeblack.env`. The
installer seeds it; edit it and `sudo systemctl restart coffeeblack-vpn` to change
anything. The full list lives in the top-level `README.md`; the ones the
installer writes:

| Variable | Installer default | Meaning |
|----------|-------------------|---------|
| `PORT` | `51821` | Web UI listen port. |
| `HOST` | `0.0.0.0` | Web UI bind address. |
| `INSECURE` | `false` | Drop the `Secure` cookie flag (no-TLS LAN only). |
| `DISABLE_IPV6` | `false` | Skip IPv6 in generated configs / firewall. |
| `IN_MEMORY` | `false` | **Bare-metal is durable/on-disk.** The Docker image defaults to `true`. |
| `COFFEEBLACK_CONF_DIR` | `/etc/coffeeblack/conf` | Runtime root. |
| `COFFEEBLACK_DB_PATH` | `/etc/coffeeblack/conf/coffeeblack.db` | SQLite database. |
| `INIT_ENABLED` | `true` | Seed the first admin. Effective only while no admin exists (idempotent). |
| `INIT_USERNAME` / `INIT_PASSWORD` | *(prompted)* | First admin credentials. The password must be ≥12 characters; a shorter one aborts startup. |
| `INIT_HOST` | *(prompted / auto)* | Public WireGuard endpoint for client configs. |
| `INIT_PORT` | `51820` | AmneziaWG UDP listen port. |
| `INIT_DNS` | `1.1.1.1,1.0.0.1` | DNS pushed to clients. |
| `INIT_IPV4_CIDR` | `10.8.0.0/24` | Client IPv4 pool. |
| `INIT_IPV6_CIDR` | `fdcc:ad94:bacf:61a4::cafe:0/112` | Client IPv6 pool. |
| `INIT_ALLOWED_IPS` | `0.0.0.0/0,::/0` | Default client AllowedIPs. |

> On bare metal keep `IN_MEMORY=false` (the installer default). The RAM-resident
> mode is for the container image and expects a tmpfs runtime root.

---

## Service management

```bash
sudo systemctl status coffeeblack-vpn        # state
sudo journalctl -u coffeeblack-vpn -f         # follow logs
sudo systemctl restart coffeeblack-vpn        # apply env changes
```

The unit runs the binary as **root** with the `CAP_NET_ADMIN` and
`CAP_SYS_MODULE` ambient capabilities it needs to create the `cb0` interface,
program the nftables/iptables firewall, and load the kernel module. It
`ExecStartPre=-/sbin/modprobe amneziawg` best-effort (the `-` means a failure
there is non-fatal — the binary retries and, failing that, still serves the web
UI so you can recover). Restart is `on-failure`; teardown gets 30 s.

---

## TLS

The session cookie is `Secure` by default, so a plain-HTTP deployment can't log
in. For anything reachable from the Internet, terminate TLS at a reverse proxy:

**nginx**

```nginx
server {
    listen 443 ssl;
    server_name vpn.example.com;
    ssl_certificate     /etc/letsencrypt/live/vpn.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/vpn.example.com/privkey.pem;
    location / {
        proxy_pass http://127.0.0.1:51821;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

**Caddy**

```
vpn.example.com {
    reverse_proxy 127.0.0.1:51821
}
```

If you set `HOST=127.0.0.1` in the env file the UI listens on localhost only,
which pairs well with a same-host proxy. Only use `INSECURE=true` on a trusted
LAN with no path exposure — the session cookie then travels in the clear.

Remember to open the **WireGuard UDP port** (`INIT_PORT`, default `51820/udp`)
and any transport ports (Xray Reality `443/tcp`, MTProxy, DNS-tunnel `53/udp`)
on your firewall / cloud security group.

---

## Migrating a pre-2.0 server config

AmneziaWG 2.0 added the `S3`/`S4` parameters and turned the scalar `H1`–`H4`
header magics into `min-max` ranges. If you are moving an **existing pre-2.0
AmneziaWG server** onto coffeeblack-vpn, migrate its `.conf` in place first:

```bash
# Auto-discover under /etc/coffeeblack/conf and /etc/amnezia/amneziawg
sudo ./scripts/migrate-pre2.sh

# Or target one file
sudo ./scripts/migrate-pre2.sh --config /etc/coffeeblack/conf/cb0.conf

# See what would change without touching anything
sudo ./scripts/migrate-pre2.sh --config /etc/coffeeblack/conf/cb0.conf --dry-run

# No prompt (also honoured via AUTO_INSTALL=y)
sudo ./scripts/migrate-pre2.sh --force
```

The migrator:

- generates `S3`/`S4` in `[15,150]` satisfying `S3+56 != S4` and `S4+56 != S3`;
- converts each scalar `H1`–`H4` to a range and, if any pair overlaps or a value
  is missing/invalid, regenerates all four as non-overlapping ranges;
- backs up to `<conf>.bak`, writes atomically (temp file + rename), preserves the
  original mode (`600`/`400`), and **rolls back from the backup on any failure**.

> After migration, **existing client configs are incompatible** and must be
> regenerated so their `S3`/`S4`/`H1`–`H4` match the server. Do that from the
> coffeeblack-vpn admin UI once the service is running.

---

## Troubleshooting

**Service is up but the VPN interface isn't.**
coffeeblack-vpn still serves the web UI even if `awg-quick up cb0` fails, so you can
fix the host and use *Restart Interface* in the admin panel. Check:

```bash
sudo systemctl status coffeeblack-vpn
sudo journalctl -u coffeeblack-vpn -e
lsmod | grep amneziawg          # module loaded?
ip link show cb0               # interface present?
```

**`amneziawg` module missing after a kernel upgrade.**
DKMS may have built the module only for the old kernel. `install` and `upgrade`
run a self-repair pass (install matching headers → `dkms autoinstall` →
`depmod -a` → `modprobe`). Re-run it, or do it manually:

```bash
sudo apt install -y "linux-headers-$(uname -r)"      # Debian/Ubuntu
sudo dkms autoinstall -k "$(uname -r)" && sudo depmod -a
sudo modprobe amneziawg
sudo systemctl restart coffeeblack-vpn
```

**Package installs hang on a VPS.**
Broken outbound IPv6 is the usual cause. The installer already forces IPv4 for
apt/dnf while it runs; if you hit it outside the installer, prefer IPv4 (`curl -4`,
`Acquire::ForceIPv4 "true";`).

**Can't log in over HTTP.**
The `Secure` cookie needs HTTPS. Put a TLS proxy in front, or set `INSECURE=true`
(trusted LAN only) and restart.

**Fedora / RHEL family refuses to install the module.**
That path is intentionally gated off upstream until verified AmneziaWG 2.0 RPMs
ship. Use a Debian/Ubuntu host, or `--skip-module` if you have a working module
from another source.
