#!/usr/bin/env bash
#
# install.sh — bare-metal host installer for awg-easy-rs
#
# awg-easy-rs is a single static-musl Rust binary that manages an AmneziaWG VPN
# (plus Xray / MTProxy / DNS-tunnel transports) behind one web UI. The binary
# OWNS the AmneziaWG interface lifecycle itself (it runs `awg-quick up awg0` on
# startup and tears it down on shutdown), so the host does NOT need an
# `awg-quick@` systemd service. This installer's job is only to:
#
#   1. Install the AmneziaWG kernel module + amneziawg-tools (so `awg` /
#      `awg-quick` exist and the fast kernel data path is available).
#   2. Install the awg-easy-rs binary as a systemd service.
#   3. Configure host sysctl (IPv4 + IPv6 forwarding).
#   4. Seed the first-run admin config (INIT_* env vars) into an EnvironmentFile.
#
# Kernel-module provisioning is ported from the upstream amneziawg-install.sh
# reference (distro/version detection, apt PPA + DKMS, Debian manual keyring
# fetch-verify-import, dnf COPR path, the IPv4-forcing trick, post-kernel-upgrade
# self-repair). The service-install structure mirrors amneziawg-web-install.sh.
#
# Usage:
#   sudo ./install.sh                 # interactive install (default subcommand)
#   sudo ./install.sh install [opts]  # explicit install
#   sudo ./install.sh upgrade [opts]  # replace the binary, keep config
#   sudo ./install.sh uninstall [opts]
#   sudo ./install.sh status
#   ./install.sh --help
#
# https://github.com/coffeegrind123/awg-easy-rs

set -euo pipefail

# Ensure sbin dirs are on PATH for depmod/modprobe/sysctl/useradd on minimal
# root shells. Only when executed directly (not sourced).
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
	if [[ -n "${PATH:-}" ]]; then
		export PATH="/sbin:/usr/sbin:${PATH}"
	else
		export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	fi
fi

# ── Constants ─────────────────────────────────────────────────────────────────

readonly SERVICE_NAME="awg-easy-rs"
readonly BINARY_NAME="awg-easy-rs"
readonly INSTALL_DIR="/usr/local/bin"
readonly BINARY_DEST="${INSTALL_DIR}/${BINARY_NAME}"
readonly ENV_DIR="/etc/awg-easy-rs"
readonly ENV_FILE="${ENV_DIR}/awg-easy-rs.env"
readonly SYSTEMD_UNIT_DEST="/etc/systemd/system/${SERVICE_NAME}.service"
readonly WG_CONF_DIR="/etc/wireguard"
readonly SYSCTL_CONF="/etc/sysctl.d/99-awg-easy-rs.conf"
readonly MODULES_LOAD_CONF="/etc/modules-load.d/amneziawg.conf"

readonly RELEASE_URL="https://github.com/coffeegrind123/awg-easy-rs/releases/latest/download/awg-easy-rs"
readonly SHA256SUMS_URL="https://github.com/coffeegrind123/awg-easy-rs/releases/latest/download/SHA256SUMS"
readonly MUSL_TARGET="x86_64-unknown-linux-musl"
# Full 40-char fingerprint of the AmneziaWG APT signing key. Short IDs are
# collision-prone; always fetch and verify by full fingerprint.
readonly AMNEZIAWG_APT_FPR="75C9DD72C799870E310542E24166F2C257290828"

readonly MANAGED_SENTINEL="# Managed by awg-easy-rs install.sh - safe to remove"

# IPv4-forcing (broken-IPv6-VPS workaround) — ported verbatim in behaviour.
readonly APT_FORCE_IPV4_CONF="/etc/apt/apt.conf.d/99awg-easy-rs-force-ipv4"
readonly APT_FORCE_IPV4_SENTINEL="# Managed by awg-easy-rs - safe to remove"
readonly GAI_CONF="/etc/gai.conf"
readonly GAI_CONF_SENTINEL="# Added by awg-easy-rs - safe to remove"
readonly GAI_CONF_IPV4_RULE="precedence ::ffff:0:0/96 100"
readonly GAI_CONF_IPV4_RULE_REGEX='^[[:space:]]*precedence[[:space:]]+::ffff:0:0/96[[:space:]]+100([[:space:]]*(#.*)?)?$'

# Repo layout: this script lives in <repo>/scripts/.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly REPO_ROOT

# ── Colours / logging ─────────────────────────────────────────────────────────

if [[ -t 1 ]]; then
	RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
	CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
else
	RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; NC=''
fi

info()  { printf "${GREEN}[+]${NC} %s\n" "$*"; }
warn()  { printf "${YELLOW}[!]${NC} %s\n" "$*"; }
error() { printf "${RED}[x]${NC} %s\n" "$*" >&2; }
die()   { error "$*"; exit 1; }
step()  { printf "\n${BOLD}${CYAN}==> %s${NC}\n" "$*"; }

# ── Configuration (populated by parse_args / interactive_setup) ───────────────

SUBCOMMAND="install"

NON_INTERACTIVE=false
BINARY_SRC=""
BUILD_FROM_SOURCE=false
INSTALL_RUST=false
FORCE=false
ENABLE_SERVICE=true
START_SERVICE=true
SKIP_MODULE=false

# Web UI — honour same-named environment variables as defaults so the
# automation path (AUTO_INSTALL=y with exported vars) works. CLI flags parsed
# later override these.
WEB_PORT="${PORT:-51821}"
WEB_HOST="${HOST:-0.0.0.0}"
INSECURE="${INSECURE:-false}"
DISABLE_IPV6="${DISABLE_IPV6:-false}"

# First-run admin (INIT_*) — same environment-as-default treatment.
INIT_ENABLED="${INIT_ENABLED:-true}"
INIT_USERNAME="${INIT_USERNAME:-admin}"
INIT_PASSWORD="${INIT_PASSWORD:-}"
INIT_HOST="${INIT_HOST:-}"
INIT_PORT="${INIT_PORT:-51820}"
INIT_DNS="${INIT_DNS:-1.1.1.1,1.0.0.1}"
INIT_IPV4_CIDR="${INIT_IPV4_CIDR:-10.8.0.0/24}"
INIT_IPV6_CIDR="${INIT_IPV6_CIDR:-fdcc:ad94:bacf:61a4::cafe:0/112}"
INIT_ALLOWED_IPS="${INIT_ALLOWED_IPS:-0.0.0.0/0,::/0}"

# uninstall flags
PURGE_CONFIG=false
PURGE_DATA=false

# Detected by checkOS
OS=""
OS_VERSION_ID=""

# ── Usage ─────────────────────────────────────────────────────────────────────

usage() {
	cat <<EOF
awg-easy-rs bare-metal installer

Usage:
  sudo $0 [SUBCOMMAND] [OPTIONS]

Subcommands:
  install    (default)  Provision the AmneziaWG kernel module + tools, install
                        the awg-easy-rs binary as a systemd service, configure
                        sysctl, and seed the first-run admin.
  upgrade               Replace the installed binary (download or rebuild) and
                        restart the service. Leaves config/DB untouched.
  uninstall             Remove the service and binary. Add --purge-config to
                        also remove ${ENV_DIR}, --purge-data to remove the DB
                        and ${WG_CONF_DIR} state.
  status                Show install / service / module health.

Binary source (install / upgrade; choose at most one):
  --binary-src PATH     Install a pre-built awg-easy-rs binary from PATH.
  --build-from-source   Build with: cargo build --release --target ${MUSL_TARGET}
  --install-rust        Install the Rust toolchain via rustup if cargo is
                        missing (only meaningful with --build-from-source).
  (default)             Download the latest release binary from GitHub:
                        ${RELEASE_URL}

Options:
  -h, --help            Show this help and exit.
  --non-interactive     Never prompt. Fail if a required value is missing.
                        (Also enabled when AUTO_INSTALL=y in the environment.)
  --port PORT           Web UI listen port (default: ${WEB_PORT}).
  --host HOST           Web UI bind address (default: ${WEB_HOST}).
  --listen HOST:PORT    Shorthand for --host + --port.
  --insecure            Drop the Secure flag from the session cookie
                        (trusted LAN without TLS only).
  --disable-ipv6        Skip IPv6 in generated configs / firewall rules.
  --skip-module         Do NOT install the kernel module / tools (assume the
                        host already has a working amneziawg module).
  --no-enable           Do not enable the service at boot.
  --no-start            Do not start the service immediately.
  --force               Overwrite existing managed files without prompting.

First-run admin (install; used to seed INIT_* in the EnvironmentFile):
  --admin-user NAME     Admin username (default: ${INIT_USERNAME}).
  --admin-password PW   Admin password (>=6 chars). Prompted if omitted
                        interactively; required in --non-interactive mode
                        unless INIT_ENABLED is turned off.
  --no-init             Do not seed a first-run admin (use the web wizard).
  --endpoint HOST       Public WireGuard endpoint (DNS name or IP) advertised
                        to clients (INIT_HOST). Auto-detected if omitted.
  --wg-port PORT        AmneziaWG UDP listen port (default: ${INIT_PORT}).
  --dns SERVERS         Comma-separated DNS pushed to clients (default: ${INIT_DNS}).
  --ipv4-cidr CIDR      Client IPv4 pool (default: ${INIT_IPV4_CIDR}).
  --ipv6-cidr CIDR      Client IPv6 pool (default: ${INIT_IPV6_CIDR}).
  --allowed-ips LIST    Default client AllowedIPs (default: ${INIT_ALLOWED_IPS}).

uninstall options:
  --purge-config        Also delete ${ENV_DIR}.
  --purge-data          Also delete ${WG_CONF_DIR} (DB, awg0.conf, subprocess state).

Environment overrides (non-interactive automation):
  AUTO_INSTALL=y        Same as --non-interactive; auto-confirms prompts.
  INIT_PASSWORD, INIT_HOST, INIT_USERNAME, INIT_PORT, INIT_DNS,
  INIT_IPV4_CIDR, INIT_IPV6_CIDR, INIT_ALLOWED_IPS, PORT, HOST, INSECURE,
  DISABLE_IPV6 — seed the corresponding values.

Examples:
  # Interactive install, download the release binary
  sudo $0

  # Non-interactive install from a pre-built binary
  sudo AUTO_INSTALL=y $0 install \\
    --binary-src ./target/${MUSL_TARGET}/release/awg-easy-rs \\
    --admin-user admin --admin-password 's3cret!' --endpoint vpn.example.com

  # Build from source and install
  sudo $0 install --build-from-source --install-rust

  # Upgrade to the latest release
  sudo $0 upgrade

  # Uninstall but keep the client roster
  sudo $0 uninstall
EOF
}

# ── Argument parsing ───────────────────────────────────────────────────────────

parse_args() {
	# First positional token may be a subcommand.
	if [[ $# -gt 0 ]]; then
		case "$1" in
			install|upgrade|uninstall|status)
				SUBCOMMAND="$1"; shift ;;
		esac
	fi

	while [[ $# -gt 0 ]]; do
		case "$1" in
			-h|--help)          usage; exit 0 ;;
			--non-interactive)  NON_INTERACTIVE=true; shift ;;
			--binary-src)       BINARY_SRC="${2:?--binary-src requires a path}"; shift 2 ;;
			--build-from-source) BUILD_FROM_SOURCE=true; shift ;;
			--install-rust)     INSTALL_RUST=true; shift ;;
			--port)             WEB_PORT="${2:?--port requires a value}"; shift 2 ;;
			--host)             WEB_HOST="${2:?--host requires a value}"; shift 2 ;;
			--listen)
				local hp="${2:?--listen requires HOST:PORT}"
				WEB_HOST="${hp%:*}"; WEB_PORT="${hp##*:}"; shift 2 ;;
			--insecure)         INSECURE="true"; shift ;;
			--disable-ipv6)     DISABLE_IPV6="true"; shift ;;
			--skip-module)      SKIP_MODULE=true; shift ;;
			--no-enable)        ENABLE_SERVICE=false; shift ;;
			--no-start)         START_SERVICE=false; shift ;;
			--force)            FORCE=true; shift ;;
			--admin-user)       INIT_USERNAME="${2:?--admin-user requires a value}"; shift 2 ;;
			--admin-password)   INIT_PASSWORD="${2:?--admin-password requires a value}"; shift 2 ;;
			--no-init)          INIT_ENABLED="false"; shift ;;
			--endpoint)         INIT_HOST="${2:?--endpoint requires a value}"; shift 2 ;;
			--wg-port)          INIT_PORT="${2:?--wg-port requires a value}"; shift 2 ;;
			--dns)              INIT_DNS="${2:?--dns requires a value}"; shift 2 ;;
			--ipv4-cidr)        INIT_IPV4_CIDR="${2:?--ipv4-cidr requires a value}"; shift 2 ;;
			--ipv6-cidr)        INIT_IPV6_CIDR="${2:?--ipv6-cidr requires a value}"; shift 2 ;;
			--allowed-ips)      INIT_ALLOWED_IPS="${2:?--allowed-ips requires a value}"; shift 2 ;;
			--purge-config)     PURGE_CONFIG=true; shift ;;
			--purge-data)       PURGE_DATA=true; shift ;;
			*) error "Unknown option: $1"; usage; exit 1 ;;
		esac
	done

	# AUTO_INSTALL=y implies non-interactive.
	if [[ "${AUTO_INSTALL:-}" =~ ^[Yy]$ ]]; then
		NON_INTERACTIVE=true
	fi

	if [[ "${BUILD_FROM_SOURCE}" == "true" ]] && [[ -n "${BINARY_SRC}" ]]; then
		die "--build-from-source and --binary-src are mutually exclusive."
	fi
}

# ── IPv4 forcing (broken-IPv6-VPS workaround) ─────────────────────────────────

gai_conf_has_active_ipv4_rule() {
	grep -Eq "${GAI_CONF_IPV4_RULE_REGEX}" "${GAI_CONF}" 2>/dev/null
}

enable_apt_ipv4() {
	if command -v apt-get >/dev/null 2>&1 || command -v apt >/dev/null 2>&1 || [[ -d /etc/apt ]]; then
		mkdir -p /etc/apt/apt.conf.d
		printf '%s\n%s\n' "${APT_FORCE_IPV4_SENTINEL}" 'Acquire::ForceIPv4 "true";' \
			> "${APT_FORCE_IPV4_CONF}"
	fi
	if ! gai_conf_has_active_ipv4_rule; then
		local existed=0
		[[ -f "${GAI_CONF}" ]] && existed=1
		printf '\n%s\n%s\n' "${GAI_CONF_SENTINEL}" "${GAI_CONF_IPV4_RULE}" >> "${GAI_CONF}"
		[[ "${existed}" -eq 0 ]] && chmod 0644 "${GAI_CONF}"
	fi
}

disable_apt_ipv4() {
	if [[ -f "${APT_FORCE_IPV4_CONF}" ]] && grep -qFm1 "${APT_FORCE_IPV4_SENTINEL}" "${APT_FORCE_IPV4_CONF}"; then
		rm -f "${APT_FORCE_IPV4_CONF}"
	fi
	if [[ -f "${GAI_CONF}" ]] && grep -qF "${GAI_CONF_SENTINEL}" "${GAI_CONF}"; then
		local tmp
		tmp="$(mktemp "${GAI_CONF}.XXXXXX")" || return 0
		awk -v sent="${GAI_CONF_SENTINEL}" -v regex="${GAI_CONF_IPV4_RULE_REGEX}" '
			$0 == sent { prev_sent=1; next }
			prev_sent == 1 && $0 ~ regex { prev_sent=0; next }
			{ prev_sent=0; print }
		' "${GAI_CONF}" > "${tmp}"
		if chmod --reference="${GAI_CONF}" "${tmp}" 2>/dev/null && \
		   chown --reference="${GAI_CONF}" "${tmp}" 2>/dev/null; then
			mv "${tmp}" "${GAI_CONF}"
		else
			rm -f "${tmp}"
		fi
	fi
}

# ── Preflight ──────────────────────────────────────────────────────────────────

check_root() {
	[[ "${EUID}" -eq 0 ]] || die "This installer must be run as root (use sudo)."
}

check_systemd() {
	command -v systemctl >/dev/null 2>&1 || \
		die "systemd is required but 'systemctl' was not found. Only systemd distributions are supported."
}

check_virt() {
	command -v systemd-detect-virt >/dev/null 2>&1 || return 0
	local virt
	virt="$(systemd-detect-virt 2>/dev/null || echo none)"
	case "${virt}" in
		openvz) die "OpenVZ is not supported (no kernel module support)." ;;
		lxc)    die "LXC is not supported: the amneziawg kernel module must be installed on the host, not in the container." ;;
	esac
}

# Distro/version detection — ported from amneziawg-install.sh checkOS().
# Sets OS to one of: debian, ubuntu, fedora, centos, almalinux, rocky.
checkOS() {
	[[ -f /etc/os-release && -r /etc/os-release ]] || \
		die "Cannot detect OS: /etc/os-release is missing or not readable."
	# shellcheck source=/dev/null
	source /etc/os-release
	OS="${ID:-}"
	OS_VERSION_ID="${VERSION_ID:-}"
	[[ -n "${OS}" ]] || die "Cannot detect OS: /etc/os-release has no ID field."

	local major
	case "${OS}" in
		debian|raspbian)
			[[ -n "${OS_VERSION_ID}" ]] || die "Cannot detect Debian version (VERSION_ID missing)."
			major="$(echo "${OS_VERSION_ID}" | cut -d'.' -f1)"
			{ [[ "${major}" =~ ^[0-9]+$ ]] && (( major >= 11 )); } || \
				die "Debian ${OS_VERSION_ID} is not supported. Use Debian 11 (Bullseye) or later."
			OS=debian ;;
		ubuntu)
			[[ -n "${OS_VERSION_ID}" ]] || die "Cannot detect Ubuntu version (VERSION_ID missing)."
			major="$(echo "${OS_VERSION_ID}" | cut -d'.' -f1)"
			{ [[ "${major}" =~ ^[0-9]+$ ]] && (( major >= 22 )); } || \
				die "Ubuntu ${OS_VERSION_ID} is not supported. Use Ubuntu 22.04 or later."
			;;
		linuxmint)
			[[ -n "${OS_VERSION_ID}" ]] || die "Cannot detect Linux Mint version (VERSION_ID missing)."
			major="$(echo "${OS_VERSION_ID}" | cut -d'.' -f1)"
			{ [[ "${major}" =~ ^[0-9]+$ ]] && (( major >= 21 )); } || \
				die "Linux Mint ${OS_VERSION_ID} is not supported. Use Linux Mint 21 or later."
			OS=ubuntu ;;
		fedora)
			[[ -n "${OS_VERSION_ID}" ]] || die "Cannot detect Fedora version (VERSION_ID missing)."
			major="$(echo "${OS_VERSION_ID}" | cut -d'.' -f1)"
			{ [[ "${major}" =~ ^[0-9]+$ ]] && (( major >= 39 )); } || \
				die "Fedora ${OS_VERSION_ID} is not supported. Use Fedora 39 or later."
			;;
		centos|almalinux|rocky)
			[[ -n "${OS_VERSION_ID}" ]] || die "Cannot detect CentOS/AlmaLinux/Rocky version (VERSION_ID missing)."
			if [[ "${OS_VERSION_ID}" == 7* || "${OS_VERSION_ID}" == 8* ]]; then
				die "${OS} ${OS_VERSION_ID} is not supported. Use version 9 or later."
			fi
			;;
		*)
			die "Unsupported system '${OS}'. Supported: Debian, Ubuntu, Linux Mint, Fedora, CentOS/AlmaLinux/Rocky." ;;
	esac
}

getTemporarilyDisabledRPMFamilyMessage() {
	echo "Fedora, AlmaLinux, and Rocky Linux support is temporarily disabled because verified AmneziaWG 2.0 packages are not currently available for these RPM-based distributions. Please watch the upstream repository's releases and README for support status updates."
}

# Gate RPM-family module installs "temporarily disabled" exactly as upstream
# does, while leaving OS detection intact so management/uninstall still work.
ensureSupportedInstallDistro() {
	if [[ "${OS}" == 'fedora' || "${OS}" == 'almalinux' || "${OS}" == 'rocky' ]]; then
		die "$(getTemporarilyDisabledRPMFamilyMessage)"
	fi
}

# ── Kernel module + tools ─────────────────────────────────────────────────────

sanitizeAwgDkmsConf() {
	local conf
	for conf in /var/lib/dkms/amneziawg/*/source/dkms.conf; do
		[[ -f "${conf}" ]] && sed -i '/^REMAKE_INITRD=/d' "${conf}"
	done
}

# Install kernel headers for the running kernel so DKMS can build the module.
installKernelHeaders() {
	local kver="${1:-$(uname -r)}"
	if [[ "${OS}" == 'ubuntu' || "${OS}" == 'debian' ]]; then
		local installed=0 pkg
		local -a candidates=("linux-headers-${kver}" "raspberrypi-kernel-headers")
		local arch
		if arch="$(dpkg --print-architecture 2>/dev/null)"; then
			candidates+=("linux-headers-${arch}")
		fi
		[[ "${OS}" == 'ubuntu' ]] && candidates+=("linux-headers-generic")
		for pkg in "${candidates[@]}"; do
			if apt-get install -y "${pkg}"; then installed=1; break; fi
			warn "Failed to install kernel headers '${pkg}'. Trying next candidate..."
		done
		[[ "${installed}" -eq 1 ]] || \
			warn "Could not install any kernel headers package. DKMS build may fail until headers are present."
	elif [[ "${OS}" == 'fedora' || "${OS}" == 'centos' || "${OS}" == 'almalinux' || "${OS}" == 'rocky' ]]; then
		if ! dnf install -y "kernel-devel-${kver}"; then
			warn "Failed to install kernel-devel-${kver}; trying latest kernel-devel."
			dnf install -y kernel-devel || warn "Could not install kernel-devel. DKMS builds may fail."
		fi
	fi
}

# Ensure the amneziawg module is built + loaded for the running kernel. This is
# the post-kernel-upgrade self-repair helper (analog of upstream's
# ensureAmneziawgKernelModule). Idempotent: returns immediately if already loaded.
ensureAmneziawgKernelModule() {
	local kver
	kver="$(uname -r)"

	if lsmod 2>/dev/null | grep -q '^amneziawg '; then
		info "amneziawg kernel module already loaded."
		return 0
	fi

	if [[ -n "$(find "/lib/modules/${kver}" -name 'amneziawg.ko*' -print -quit 2>/dev/null)" ]]; then
		if modprobe amneziawg 2>/dev/null && lsmod 2>/dev/null | grep -q '^amneziawg '; then
			info "amneziawg kernel module loaded."
			return 0
		fi
	fi

	warn "amneziawg kernel module is not built or loaded for kernel ${kver}. Attempting automatic repair..."

	if [[ "${OS}" == 'ubuntu' || "${OS}" == 'debian' ]]; then
		local hdr="linux-headers-${kver}"
		if ! dpkg-query -W -f='${Status}' "${hdr}" 2>/dev/null | grep -q 'install ok installed'; then
			warn "Kernel headers (${hdr}) are not installed. Installing..."
			enable_apt_ipv4; installKernelHeaders "${kver}"; disable_apt_ipv4
		fi
	elif [[ "${OS}" == 'fedora' || "${OS}" == 'centos' || "${OS}" == 'almalinux' || "${OS}" == 'rocky' ]]; then
		local hdr="kernel-devel-${kver}"
		if ! rpm -q "${hdr}" &>/dev/null; then
			warn "Kernel headers (${hdr}) are not installed. Installing..."
			installKernelHeaders "${kver}"
		fi
	fi

	sanitizeAwgDkmsConf

	if command -v dkms >/dev/null 2>&1; then
		warn "Running: dkms autoinstall -k ${kver}"
		if ! dkms autoinstall -k "${kver}"; then
			warn "dkms autoinstall failed for kernel ${kver}."
			local log
			log="$(find /var/lib/dkms/amneziawg -name 'make.log' -path "*${kver}*" 2>/dev/null | head -n 1)"
			if [[ -n "${log}" ]]; then
				warn "Last 20 lines of DKMS build log (${log}):"
				tail -20 "${log}" || true
			fi
		fi
	else
		warn "dkms is not installed; cannot rebuild the kernel module."
	fi

	if command -v depmod >/dev/null 2>&1; then depmod -a || true; fi

	if ! modprobe amneziawg; then
		error "amneziawg kernel module could not be loaded for kernel ${kver}."
		warn  "Manual recovery:"
		if [[ "${OS}" == 'ubuntu' || "${OS}" == 'debian' ]]; then
			warn "  1. apt install -y \"linux-headers-${kver}\""
		else
			warn "  1. dnf install -y \"kernel-devel-${kver}\""
		fi
		warn "  2. dkms autoinstall -k \"${kver}\" && depmod -a"
		warn "  3. modprobe amneziawg"
		warn "awg-easy-rs will still start and serve the web UI; the kernel data path"
		warn "stays unavailable until the module loads. This is non-fatal — continuing."
		return 1
	fi

	info "amneziawg module loaded successfully for kernel ${kver}."
	return 0
}

# Add the Debian AmneziaWG APT signing key by full-fingerprint fetch-verify-import.
setupDebianKeyring() {
	if ! command -v gpg >/dev/null 2>&1; then
		apt-get update
		apt-get install -y gnupg || die "Failed to install gnupg (required for key import)."
	fi
	if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
		apt-get update
		apt-get install -y curl || die "Failed to install curl (required for key download)."
	fi
	mkdir -p /etc/apt/keyrings
	chmod 755 /etc/apt/keyrings

	local key_url="https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x${AMNEZIAWG_APT_FPR}"
	local tmp_asc
	tmp_asc="$(mktemp /tmp/awg-apt-key.XXXXXX)" || die "Failed to create temp file for APT key."

	local fetched=0
	if command -v curl >/dev/null 2>&1; then
		curl -4 -fsSL "${key_url}" -o "${tmp_asc}" && fetched=1
	elif command -v wget >/dev/null 2>&1; then
		wget -4 -qO "${tmp_asc}" "${key_url}" && fetched=1
	fi
	if [[ "${fetched}" -ne 1 || ! -s "${tmp_asc}" ]]; then
		rm -f "${tmp_asc}"
		die "Failed to download the AmneziaWG APT signing key. Check connectivity / that curl or wget and gnupg are installed."
	fi

	local got_fpr
	got_fpr="$(gpg --show-keys --with-colons "${tmp_asc}" 2>/dev/null | awk -F: '/^fpr:/ { print $10; exit }')"
	if [[ -z "${got_fpr}" ]]; then
		rm -f "${tmp_asc}"; die "Unable to read fingerprint from downloaded AmneziaWG APT key."
	fi
	if [[ "${got_fpr^^}" != "${AMNEZIAWG_APT_FPR^^}" ]]; then
		rm -f "${tmp_asc}"
		die "Downloaded key fingerprint (${got_fpr}) does not match expected (${AMNEZIAWG_APT_FPR}). Aborting."
	fi

	local tmp_keyring
	tmp_keyring="$(mktemp /etc/apt/keyrings/amneziawg.gpg.tmp.XXXXXX)" || {
		rm -f "${tmp_asc}"; die "Failed to create temp keyring file."; }
	if ! gpg --dearmor < "${tmp_asc}" > "${tmp_keyring}" 2>/dev/null; then
		rm -f "${tmp_asc}" "${tmp_keyring}"; die "Failed to import AmneziaWG APT signing key."
	fi
	rm -f "${tmp_asc}"
	[[ -s "${tmp_keyring}" ]] || { rm -f "${tmp_keyring}"; die "AmneziaWG APT keyring empty after import."; }
	chmod 644 "${tmp_keyring}"
	mv "${tmp_keyring}" /etc/apt/keyrings/amneziawg.gpg

	local list=/etc/apt/sources.list.d/amneziawg.sources.list
	if [[ ! -f "${list}" ]]; then
		echo "# Managed by amneziawg-install" > "${list}"
		chmod 644 "${list}"
	fi
	if ! grep -q 'ppa.launchpadcontent.net/amnezia/ppa' "${list}"; then
		echo "deb [signed-by=/etc/apt/keyrings/amneziawg.gpg] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main" >> "${list}"
		echo "deb-src [signed-by=/etc/apt/keyrings/amneziawg.gpg] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main" >> "${list}"
	fi
}

# Install the AmneziaWG kernel module + tools for the detected distro.
installAmneziaWGModule() {
	step "Installing AmneziaWG kernel module + tools"

	if [[ "${SKIP_MODULE}" == "true" ]]; then
		warn "--skip-module set; skipping kernel module / tools installation."
		return 0
	fi

	if command -v awg >/dev/null 2>&1 && command -v awg-quick >/dev/null 2>&1 \
		&& lsmod 2>/dev/null | grep -q '^amneziawg '; then
		info "amneziawg tools + module already present; running self-repair check only."
		ensureAmneziawgKernelModule || true
		return 0
	fi

	# RPM family is gated disabled (matches upstream). The code path below stays
	# for when packages become available, but ensureSupportedInstallDistro exits.
	ensureSupportedInstallDistro

	enable_apt_ipv4
	if [[ "${OS}" == 'ubuntu' ]]; then
		apt-get update || { disable_apt_ipv4; die "Failed to refresh APT package index."; }
		apt-get install -y software-properties-common || { disable_apt_ipv4; die "Failed to install software-properties-common."; }
		add-apt-repository -y ppa:amnezia/ppa || { disable_apt_ipv4; die "Failed to add the Amnezia PPA."; }
		apt-get update || { disable_apt_ipv4; die "Failed to update APT index after adding the Amnezia PPA."; }
		installKernelHeaders "$(uname -r)"
		apt-get install -y dkms iptables nftables amneziawg amneziawg-tools qrencode \
			|| { disable_apt_ipv4; die "Package installation failed. Check connectivity and retry."; }
	elif [[ "${OS}" == 'debian' ]]; then
		setupDebianKeyring
		apt-get update || { disable_apt_ipv4; die "Failed to update package index."; }
		installKernelHeaders "$(uname -r)"
		apt-get install -y dkms amneziawg amneziawg-tools qrencode iptables nftables \
			|| { disable_apt_ipv4; die "Package installation failed. Check connectivity and retry."; }
	elif [[ "${OS}" == 'fedora' || "${OS}" == 'centos' ]]; then
		# Reachable only if ensureSupportedInstallDistro is later relaxed.
		dnf config-manager --set-enabled crb || true
		dnf install -y epel-release || true
		dnf copr enable -y amneziavpn/amneziawg || { disable_apt_ipv4; die "Failed to enable the AmneziaWG COPR."; }
		installKernelHeaders "$(uname -r)"
		dnf install -y dkms amneziawg-dkms amneziawg-tools qrencode iptables nftables \
			|| { disable_apt_ipv4; die "Package installation failed. Check connectivity and retry."; }
	fi
	disable_apt_ipv4

	sanitizeAwgDkmsConf

	if command -v dkms >/dev/null 2>&1; then
		dkms autoinstall -k "$(uname -r)" || \
			warn "dkms autoinstall failed for kernel $(uname -r). The module may not be available until headers are installed and it is rebuilt."
	fi
	if command -v depmod >/dev/null 2>&1; then
		depmod -a || warn "depmod -a failed; the module may not load until reboot."
	fi

	if [[ -z "$(find "/lib/modules/$(uname -r)" -name 'amneziawg.ko*' -print -quit 2>/dev/null)" ]]; then
		warn "amneziawg kernel module was NOT built for kernel $(uname -r). Kernel headers may be missing or the DKMS build failed."
	fi

	# Autoload at boot.
	mkdir -p /etc/modules-load.d
	if ! grep -qx "amneziawg" "${MODULES_LOAD_CONF}" 2>/dev/null; then
		echo "amneziawg" >> "${MODULES_LOAD_CONF}"
	fi
	chmod 644 "${MODULES_LOAD_CONF}"

	# Build + load for the running kernel now (best-effort; non-fatal).
	ensureAmneziawgKernelModule || true
}

# ── Host sysctl ────────────────────────────────────────────────────────────────

setupSysctl() {
	step "Configuring host forwarding (sysctl)"
	mkdir -p /etc/sysctl.d
	{
		echo "${MANAGED_SENTINEL}"
		echo "net.ipv4.ip_forward = 1"
		if [[ "${DISABLE_IPV6}" != "true" ]]; then
			echo "net.ipv6.conf.all.forwarding = 1"
		fi
	} > "${SYSCTL_CONF}"
	chmod 644 "${SYSCTL_CONF}"
	local scope="IPv4"
	[[ "${DISABLE_IPV6}" != "true" ]] && scope="IPv4 + IPv6"
	if sysctl -p "${SYSCTL_CONF}" >/dev/null 2>&1; then
		info "Enabled ${scope} forwarding via ${SYSCTL_CONF}."
	else
		warn "sysctl -p ${SYSCTL_CONF} reported an error; forwarding will apply on next boot."
	fi
}

# ── Binary acquisition / install ──────────────────────────────────────────────

ensure_rust_toolchain() {
	if command -v cargo >/dev/null 2>&1; then
		info "Rust toolchain: $(cargo --version 2>/dev/null || echo unknown)"
		return 0
	fi
	if [[ -x "${HOME}/.cargo/bin/cargo" ]]; then
		export PATH="${HOME}/.cargo/bin:${PATH}"
		info "Rust toolchain: $(cargo --version 2>/dev/null || echo unknown)"
		return 0
	fi
	if [[ "${INSTALL_RUST}" != "true" ]]; then
		die "cargo not found. Install Rust (curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh) or re-run with --install-rust."
	fi
	info "Installing Rust toolchain via rustup..."
	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable \
		|| die "Failed to install Rust toolchain via rustup."
	# shellcheck source=/dev/null
	[[ -f "${HOME}/.cargo/env" ]] && . "${HOME}/.cargo/env"
	export PATH="${HOME}/.cargo/bin:${PATH}"
	command -v cargo >/dev/null 2>&1 || die "cargo still not in PATH after rustup install."
}

build_from_source() {
	step "Building awg-easy-rs from source"
	[[ -f "${REPO_ROOT}/Cargo.toml" ]] || \
		die "No Cargo.toml at ${REPO_ROOT}; run from a repository checkout to build from source."
	ensure_rust_toolchain
	if ! rustup target list --installed 2>/dev/null | grep -qx "${MUSL_TARGET}"; then
		info "Adding Rust target ${MUSL_TARGET}..."
		rustup target add "${MUSL_TARGET}" || warn "rustup target add ${MUSL_TARGET} failed; the build may still succeed if the target is already available."
	fi
	info "Running: cargo build --release --target ${MUSL_TARGET}"
	( cd "${REPO_ROOT}" && cargo build --release --locked --target "${MUSL_TARGET}" ) \
		|| die "Build failed. Ensure build dependencies are installed."
	local built="${REPO_ROOT}/target/${MUSL_TARGET}/release/${BINARY_NAME}"
	[[ -f "${built}" ]] || die "Build completed but binary not found at ${built}."
	BINARY_SRC="${built}"
	info "Built binary: ${BINARY_SRC}"
}

download_release() {
	step "Downloading the latest awg-easy-rs release"
	local tmp
	tmp="$(mktemp /tmp/awg-easy-rs.XXXXXX)" || die "Failed to create temp file for the binary download."
	local ok=0
	if command -v curl >/dev/null 2>&1; then
		curl -4 -fL --retry 3 -o "${tmp}" "${RELEASE_URL}" && ok=1
	elif command -v wget >/dev/null 2>&1; then
		wget -4 -O "${tmp}" "${RELEASE_URL}" && ok=1
	else
		rm -f "${tmp}"; die "Neither curl nor wget is available to download the release binary."
	fi
	if [[ "${ok}" -ne 1 || ! -s "${tmp}" ]]; then
		rm -f "${tmp}"; die "Failed to download the release binary from ${RELEASE_URL}."
	fi
	# Sanity check: must be an ELF executable.
	if ! head -c 4 "${tmp}" | grep -q $'\x7fELF'; then
		rm -f "${tmp}"; die "Downloaded file is not an ELF binary; the release URL may be unavailable."
	fi

	# Verify the published SHA-256 before this ever runs as root. The four-byte
	# ELF check above says only "this is a binary", not "this is *our* binary";
	# HTTPS protects the transport but not the artifact, and `curl -fL` follows
	# redirects to wherever they point. The release publishes SHA256SUMS
	# precisely so this check can exist.
	local sums
	sums="$(mktemp /tmp/awg-easy-rs-sums.XXXXXX)" || die "Failed to create temp file for the checksum download."
	local got=0
	if command -v curl >/dev/null 2>&1; then
		curl -4 -fL --retry 3 -o "${sums}" "${SHA256SUMS_URL}" && got=1
	elif command -v wget >/dev/null 2>&1; then
		wget -4 -O "${sums}" "${SHA256SUMS_URL}" && got=1
	fi
	if [[ "${got}" -ne 1 || ! -s "${sums}" ]]; then
		rm -f "${tmp}" "${sums}"
		die "Could not download ${SHA256SUMS_URL} to verify the release binary. Refusing to install an unverified binary that will run as root. Use --binary-src <path> or --build if you are installing deliberately from another source."
	fi
	local want
	want="$(awk '$2 ~ /(^|\/)awg-easy-rs$/ { print $1; exit }' "${sums}")"
	if [[ -z "${want}" ]]; then
		rm -f "${tmp}" "${sums}"
		die "SHA256SUMS did not list awg-easy-rs; refusing to install an unverified binary."
	fi
	local have
	have="$(sha256sum "${tmp}" | cut -d' ' -f1)"
	if [[ "${want}" != "${have}" ]]; then
		rm -f "${tmp}" "${sums}"
		die "Checksum mismatch for the downloaded binary. Expected ${want}, got ${have}. Refusing to install."
	fi
	rm -f "${sums}"
	info "Verified release binary against published SHA-256 (${have})."

	chmod +x "${tmp}"
	BINARY_SRC="${tmp}"
	info "Downloaded binary to ${BINARY_SRC}."
}

# Resolve BINARY_SRC per the selected source (binary-src / build / download).
acquire_binary() {
	if [[ -n "${BINARY_SRC}" ]]; then
		[[ -f "${BINARY_SRC}" ]] || die "Binary source not found: ${BINARY_SRC}"
		[[ -x "${BINARY_SRC}" ]] || chmod +x "${BINARY_SRC}"
		info "Using pre-built binary: ${BINARY_SRC}"
		return 0
	fi
	if [[ "${BUILD_FROM_SOURCE}" == "true" ]]; then
		build_from_source
		return 0
	fi
	# Default: prefer a repo-local build if present, else download.
	local repo_build="${REPO_ROOT}/target/${MUSL_TARGET}/release/${BINARY_NAME}"
	if [[ -f "${repo_build}" ]]; then
		BINARY_SRC="${repo_build}"
		[[ -x "${BINARY_SRC}" ]] || chmod +x "${BINARY_SRC}"
		info "Using repository build: ${BINARY_SRC}"
		return 0
	fi
	download_release
}

install_binary() {
	step "Installing binary"
	install -m 0755 "${BINARY_SRC}" "${BINARY_DEST}"
	info "Installed binary: ${BINARY_DEST}"
}

# ── Prompts ────────────────────────────────────────────────────────────────────

prompt_default() {
	local var="$1" text="$2" def="$3" input
	if [[ -n "${def}" ]]; then printf "%s [%s]: " "${text}" "${def}"; else printf "%s: " "${text}"; fi
	read -r input
	if [[ -z "${input}" ]]; then printf -v "${var}" '%s' "${def}"; else printf -v "${var}" '%s' "${input}"; fi
}

prompt_yesno() {
	local var="$1" text="$2" def="$3" hint input
	[[ "${def}" == true ]] && hint="Y/n" || hint="y/N"
	printf "%s [%s]: " "${text}" "${hint}"
	read -r input; input="${input,,}"
	if [[ -z "${input}" ]]; then printf -v "${var}" '%s' "${def}"
	elif [[ "${input}" == y || "${input}" == yes ]]; then printf -v "${var}" '%s' "true"
	else printf -v "${var}" '%s' "false"; fi
}

prompt_password_init() {
	local p1 p2
	while true; do
		printf "Admin password (min 6 chars): "; read -rs p1; printf "\n"
		if [[ "${#p1}" -lt 6 ]]; then warn "Password must be at least 6 characters."; continue; fi
		printf "Confirm password: "; read -rs p2; printf "\n"
		[[ "${p1}" == "${p2}" ]] || { warn "Passwords do not match. Try again."; continue; }
		INIT_PASSWORD="${p1}"; break
	done
}

# Best-effort public endpoint auto-detection for INIT_HOST.
detect_public_endpoint() {
	local ip=""
	if command -v curl >/dev/null 2>&1; then
		ip="$(curl -4 -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)"
		[[ -z "${ip}" ]] && ip="$(curl -4 -fsS --max-time 5 https://ifconfig.me 2>/dev/null || true)"
	fi
	if [[ -z "${ip}" ]] && command -v ip >/dev/null 2>&1; then
		ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
	fi
	echo "${ip}"
}

interactive_setup() {
	step "Interactive configuration"
	cat <<EOF

Configure awg-easy-rs. Press Enter to accept the default shown in brackets.

EOF
	prompt_default WEB_HOST "Web UI bind address"  "${WEB_HOST}"
	prompt_default WEB_PORT "Web UI listen port"   "${WEB_PORT}"

	local ins_bool
	[[ "${INSECURE}" == "true" ]] && ins_bool=true || ins_bool=false
	prompt_yesno ins_bool "Run without TLS (INSECURE cookie — trusted LAN only)?" "${ins_bool}"
	INSECURE="${ins_bool}"

	local seed_bool
	[[ "${INIT_ENABLED}" == "true" ]] && seed_bool=true || seed_bool=false
	prompt_yesno seed_bool "Seed the first-run admin user now (else use the web wizard)?" "${seed_bool}"
	INIT_ENABLED="${seed_bool}"

	if [[ "${INIT_ENABLED}" == "true" ]]; then
		prompt_default INIT_USERNAME "Admin username" "${INIT_USERNAME}"
		if [[ -z "${INIT_PASSWORD}" ]]; then
			prompt_password_init
		fi
		if [[ -z "${INIT_HOST}" ]]; then
			local guessed; guessed="$(detect_public_endpoint)"
			prompt_default INIT_HOST "Public WireGuard endpoint (DNS or IP)" "${guessed}"
		fi
		prompt_default INIT_PORT        "AmneziaWG UDP listen port" "${INIT_PORT}"
		prompt_default INIT_DNS         "DNS servers pushed to clients" "${INIT_DNS}"
		prompt_default INIT_IPV4_CIDR   "Client IPv4 pool" "${INIT_IPV4_CIDR}"
		if [[ "${DISABLE_IPV6}" != "true" ]]; then
			prompt_default INIT_IPV6_CIDR "Client IPv6 pool" "${INIT_IPV6_CIDR}"
		fi
		prompt_default INIT_ALLOWED_IPS "Default client AllowedIPs" "${INIT_ALLOWED_IPS}"
	fi

	local src_desc="download latest release"
	if [[ -n "${BINARY_SRC}" ]]; then
		src_desc="${BINARY_SRC}"
	elif [[ "${BUILD_FROM_SOURCE}" == true ]]; then
		src_desc="build from source"
	fi
	printf "\n%bConfiguration summary:%b\n" "${BOLD}" "${NC}"
	printf "  Binary source:    %s\n" "${src_desc}"
	printf "  Web UI:           %s:%s (INSECURE=%s)\n" "${WEB_HOST}" "${WEB_PORT}" "${INSECURE}"
	printf "  Seed admin:       %s\n" "${INIT_ENABLED}"
	if [[ "${INIT_ENABLED}" == "true" ]]; then
		printf "  Admin user:       %s\n" "${INIT_USERNAME}"
		printf "  Endpoint:         %s:%s\n" "${INIT_HOST}" "${INIT_PORT}"
		printf "  Client IPv4 pool: %s\n" "${INIT_IPV4_CIDR}"
	fi
	printf "\n"

	local proceed
	prompt_yesno proceed "Proceed with installation?" "true"
	[[ "${proceed}" == "true" ]] || { info "Installation cancelled."; exit 0; }
}

non_interactive_validate() {
	if [[ "${INIT_ENABLED}" == "true" ]]; then
		[[ -n "${INIT_PASSWORD}" ]] || \
			die "Non-interactive mode with admin seeding requires --admin-password (or INIT_PASSWORD), or pass --no-init."
		[[ "${#INIT_PASSWORD}" -ge 6 ]] || die "INIT_PASSWORD must be at least 6 characters."
		if [[ -z "${INIT_HOST}" ]]; then
			INIT_HOST="$(detect_public_endpoint)"
			[[ -n "${INIT_HOST}" ]] || warn "Could not auto-detect a public endpoint; INIT_HOST left blank. Set it in ${ENV_FILE} or the web UI."
		fi
	fi
}

# ── EnvironmentFile ────────────────────────────────────────────────────────────

write_env_file() {
	step "Writing environment file"

	mkdir -p "${ENV_DIR}"
	chown root:root "${ENV_DIR}"
	chmod 0700 "${ENV_DIR}"

	if [[ -f "${ENV_FILE}" ]] && [[ "${FORCE}" != "true" ]]; then
		if [[ "${NON_INTERACTIVE}" == "true" ]]; then
			warn "Env file exists: ${ENV_FILE}. Use --force to overwrite. Keeping existing file."
			return 0
		fi
		local overwrite
		prompt_yesno overwrite "Env file exists: ${ENV_FILE}. Overwrite?" "false"
		[[ "${overwrite}" == "true" ]] || { warn "Keeping existing env file."; return 0; }
	fi

	local old_umask; old_umask="$(umask)"; umask 077

	{
		echo "# awg-easy-rs environment configuration"
		echo "# Generated by install.sh. Manage with: sudo systemctl restart ${SERVICE_NAME}"
		echo "# All values are environment variables read by the awg-easy-rs binary."
		echo ""
		echo "# ── Web server ──────────────────────────────────────────────────────────────"
		echo "PORT=${WEB_PORT}"
		echo "HOST=${WEB_HOST}"
		echo "INSECURE=${INSECURE}"
		echo "DISABLE_IPV6=${DISABLE_IPV6}"
		echo ""
		echo "# ── Storage (bare-metal durable install: on-disk, not RAM) ──────────────────"
		echo "IN_MEMORY=false"
		echo "WG_EASY_CONF_DIR=${WG_CONF_DIR}"
		echo "WG_EASY_DB_PATH=${WG_CONF_DIR}/wg-easy.db"
		echo ""
		echo "# ── Logging ─────────────────────────────────────────────────────────────────"
		echo "RUST_LOG=info"
		echo ""
		echo "# ── First-run admin seed (INIT_*) ───────────────────────────────────────────"
		echo "# These take effect only when no admin user exists yet, so restarting the"
		echo "# service with the same values is idempotent."
		echo "INIT_ENABLED=${INIT_ENABLED}"
	} > "${ENV_FILE}"

	if [[ "${INIT_ENABLED}" == "true" ]]; then
		{
			echo "INIT_USERNAME=${INIT_USERNAME}"
			echo "INIT_PASSWORD=${INIT_PASSWORD}"
			echo "INIT_HOST=${INIT_HOST}"
			echo "INIT_PORT=${INIT_PORT}"
			echo "INIT_DNS=${INIT_DNS}"
			echo "INIT_IPV4_CIDR=${INIT_IPV4_CIDR}"
			[[ "${DISABLE_IPV6}" != "true" ]] && echo "INIT_IPV6_CIDR=${INIT_IPV6_CIDR}"
			echo "INIT_ALLOWED_IPS=${INIT_ALLOWED_IPS}"
		} >> "${ENV_FILE}"
	fi

	umask "${old_umask}"
	chown root:root "${ENV_FILE}"
	chmod 0600 "${ENV_FILE}"
	info "Wrote env file: ${ENV_FILE}"

	if [[ "${WEB_HOST}" != "127.0.0.1" && "${WEB_HOST}" != "localhost" && "${INSECURE}" != "true" ]]; then
		warn "Web UI is bound to ${WEB_HOST}. Terminate TLS upstream (reverse proxy) before exposing it to the Internet."
	fi
}

# ── systemd service ────────────────────────────────────────────────────────────

install_service_unit() {
	step "Installing systemd service"

	local unit_src="${REPO_ROOT}/packaging/${SERVICE_NAME}.service"
	if [[ -f "${unit_src}" ]]; then
		if [[ -f "${SYSTEMD_UNIT_DEST}" ]] && [[ "${FORCE}" != "true" ]] && [[ "${SUBCOMMAND}" != "upgrade" ]]; then
			warn "Service unit exists: ${SYSTEMD_UNIT_DEST}. Use --force to overwrite. Keeping existing unit."
		else
			install -m 0644 "${unit_src}" "${SYSTEMD_UNIT_DEST}"
			info "Installed service unit from ${unit_src}."
		fi
	else
		warn "packaging/${SERVICE_NAME}.service not found; writing an inline unit."
		cat > "${SYSTEMD_UNIT_DEST}" <<UNITEOF
[Unit]
Description=awg-easy-rs — AmneziaWG VPN + proxy manager with web UI
Documentation=https://github.com/coffeegrind123/awg-easy-rs
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Restart=on-failure
RestartSec=5s
User=root
Group=root
AmbientCapabilities=CAP_NET_ADMIN CAP_SYS_MODULE
ExecStart=${BINARY_DEST}
EnvironmentFile=-${ENV_FILE}
ExecStartPre=-/sbin/modprobe amneziawg
TimeoutStopSec=30s
KillMode=mixed
ProtectSystem=full
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=${WG_CONF_DIR}
ReadWritePaths=-${ENV_DIR}

[Install]
WantedBy=multi-user.target
UNITEOF
		chmod 0644 "${SYSTEMD_UNIT_DEST}"
		info "Wrote inline service unit: ${SYSTEMD_UNIT_DEST}"
	fi

	systemctl daemon-reload
	info "systemd daemon reloaded."

	if [[ "${ENABLE_SERVICE}" == "true" ]]; then
		if systemctl enable "${SERVICE_NAME}" >/dev/null 2>&1; then
			info "Service enabled at boot."
		else
			warn "Failed to enable ${SERVICE_NAME} at boot."
		fi
	fi
	if [[ "${START_SERVICE}" == "true" ]]; then
		if systemctl restart "${SERVICE_NAME}"; then
			info "Service started."
		else
			warn "Service failed to start. Inspect: journalctl -u ${SERVICE_NAME} -e"
		fi
	fi
}

# ── Runtime dirs ───────────────────────────────────────────────────────────────

setup_runtime_dirs() {
	step "Preparing runtime directories"
	mkdir -p "${WG_CONF_DIR}"
	chmod 700 "${WG_CONF_DIR}"
	info "Runtime root: ${WG_CONF_DIR} (awg0.conf, wg-easy.db, subprocess state)."
}

# ── Summary ────────────────────────────────────────────────────────────────────

print_summary() {
	local url_host="${WEB_HOST}"
	[[ "${url_host}" == "0.0.0.0" ]] && url_host="<server-ip>"
	local scheme="https"; [[ "${INSECURE}" == "true" ]] && scheme="http"

	printf "\n%b%b=======================================================%b\n" "${BOLD}" "${GREEN}" "${NC}"
	printf "%b%b  awg-easy-rs installation complete%b\n" "${BOLD}" "${GREEN}" "${NC}"
	printf "%b%b=======================================================%b\n\n" "${BOLD}" "${GREEN}" "${NC}"
	printf "%bWeb UI:%b\n" "${BOLD}" "${NC}"
	printf "  URL:            %s://%s:%s/\n" "${scheme}" "${url_host}" "${WEB_PORT}"
	[[ "${INIT_ENABLED}" == "true" ]] && printf "  Admin user:     %s\n" "${INIT_USERNAME}"
	printf "\n%bFiles:%b\n" "${BOLD}" "${NC}"
	printf "  Binary:         %s\n" "${BINARY_DEST}"
	printf "  Env file:       %s\n" "${ENV_FILE}"
	printf "  Service unit:   %s\n" "${SYSTEMD_UNIT_DEST}"
	printf "  Runtime root:   %s\n" "${WG_CONF_DIR}"
	printf "\n%bManage:%b\n" "${BOLD}" "${NC}"
	printf "  Status:         sudo systemctl status %s\n" "${SERVICE_NAME}"
	printf "  Logs:           sudo journalctl -u %s -f\n" "${SERVICE_NAME}"
	printf "  Restart:        sudo systemctl restart %s\n" "${SERVICE_NAME}"
	printf "\n"
	if [[ "${INSECURE}" != "true" && "${WEB_HOST}" != "127.0.0.1" && "${WEB_HOST}" != "localhost" ]]; then
		printf "%b%bTLS:%b put a reverse proxy (nginx/Caddy) in front and terminate TLS,\n" "${BOLD}" "${YELLOW}" "${NC}"
		printf "     or set INSECURE=true in %s for a trusted LAN only.\n\n" "${ENV_FILE}"
	fi
	printf "%bOpen the WireGuard UDP port (%s/udp) and the web port on your firewall / cloud SG.%b\n\n" "${BOLD}" "${INIT_PORT}" "${NC}"
}

# ── Subcommands ────────────────────────────────────────────────────────────────

cmd_install() {
	step "Preflight checks"
	check_root
	check_systemd
	check_virt
	checkOS
	info "Detected distro: ${OS} ${OS_VERSION_ID}"

	# Resolve binary before prompting so the summary is accurate; but for the
	# download path defer until after confirmation to avoid a wasted download if
	# the user cancels. We acquire post-confirmation.
	if [[ "${NON_INTERACTIVE}" == "true" ]]; then
		non_interactive_validate
	else
		interactive_setup
	fi

	installAmneziaWGModule
	setupSysctl
	setup_runtime_dirs
	acquire_binary
	install_binary
	write_env_file
	install_service_unit
	print_summary
}

cmd_upgrade() {
	step "Upgrading awg-easy-rs"
	check_root
	check_systemd
	checkOS

	[[ -x "${BINARY_DEST}" ]] || warn "No existing binary at ${BINARY_DEST}; installing fresh."

	acquire_binary

	# Show current vs new version if the binary supports --version.
	local was_active=false
	systemctl is-active --quiet "${SERVICE_NAME}" && was_active=true

	install_binary

	# Refresh the unit if the packaged template changed.
	install_service_unit

	if [[ "${was_active}" == true || "${START_SERVICE}" == true ]]; then
		if systemctl restart "${SERVICE_NAME}"; then
			info "Service restarted on the new binary."
		else
			warn "Service failed to restart. Inspect: journalctl -u ${SERVICE_NAME} -e"
		fi
	fi
	# Best-effort self-repair of the module after a possible kernel change.
	[[ "${SKIP_MODULE}" == "true" ]] || ensureAmneziawgKernelModule || true
	info "Upgrade complete. Config and database were left untouched."
}

cmd_uninstall() {
	step "Uninstalling awg-easy-rs"
	check_root
	check_systemd

	if [[ "${NON_INTERACTIVE}" != "true" && "${FORCE}" != "true" ]]; then
		local confirm
		prompt_yesno confirm "Remove the awg-easy-rs service and binary?" "false"
		[[ "${confirm}" == "true" ]] || { info "Uninstall aborted."; exit 0; }
	fi

	if systemctl list-unit-files 2>/dev/null | grep -q "^${SERVICE_NAME}.service"; then
		systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
		systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
		info "Stopped and disabled ${SERVICE_NAME}."
	fi

	# Best-effort: bring the interface down if awg-quick exists and it is up.
	if command -v awg-quick >/dev/null 2>&1 && ip link show awg0 >/dev/null 2>&1; then
		awg-quick down awg0 2>/dev/null || true
		info "Brought awg0 down."
	fi

	rm -f "${SYSTEMD_UNIT_DEST}"
	systemctl daemon-reload 2>/dev/null || true
	rm -f "${BINARY_DEST}"
	rm -f "${SYSCTL_CONF}"
	info "Removed binary, service unit, and sysctl drop-in."
	warn "Left net.*.forward sysctls as-is at runtime (other services may rely on them); they revert to defaults on reboot."

	if [[ "${PURGE_CONFIG}" == "true" ]]; then
		rm -rf "${ENV_DIR}"
		info "Purged config: ${ENV_DIR}"
	else
		info "Kept config directory ${ENV_DIR} (use --purge-config to remove)."
	fi

	if [[ "${PURGE_DATA}" == "true" ]]; then
		rm -rf "${WG_CONF_DIR}"
		info "Purged data: ${WG_CONF_DIR}"
	else
		info "Kept data directory ${WG_CONF_DIR} (DB + awg0.conf; use --purge-data to remove)."
	fi

	warn "The amneziawg kernel module and amneziawg-tools were left installed."
	warn "Remove them manually if desired (e.g. apt remove -y amneziawg amneziawg-tools)."
	info "Uninstall complete."
}

cmd_status() {
	check_systemd
	step "awg-easy-rs status"

	if [[ -x "${BINARY_DEST}" ]]; then
		local ver
		ver="$("${BINARY_DEST}" --version 2>/dev/null || echo 'unknown')"
		info "Binary:  ${BINARY_DEST} (${ver})"
	else
		warn "Binary:  not installed at ${BINARY_DEST}"
	fi

	if [[ -f "${ENV_FILE}" ]]; then info "Env:     ${ENV_FILE} present"; else warn "Env:     ${ENV_FILE} missing"; fi
	if [[ -f "${SYSTEMD_UNIT_DEST}" ]]; then info "Unit:    ${SYSTEMD_UNIT_DEST} present"; else warn "Unit:    ${SYSTEMD_UNIT_DEST} missing"; fi

	local active enabled
	active="$(systemctl is-active "${SERVICE_NAME}" 2>/dev/null || echo unknown)"
	enabled="$(systemctl is-enabled "${SERVICE_NAME}" 2>/dev/null || echo unknown)"
	info "Service: active=${active} enabled=${enabled}"

	if command -v awg >/dev/null 2>&1; then
		info "Tools:   awg $(awg --version 2>/dev/null | head -n1 || echo present)"
	else
		warn "Tools:   awg not found (kernel data path unavailable)"
	fi
	if lsmod 2>/dev/null | grep -q '^amneziawg '; then
		info "Module:  amneziawg loaded"
	else
		warn "Module:  amneziawg NOT loaded"
	fi
	if ip link show awg0 >/dev/null 2>&1; then
		info "Iface:   awg0 present"
	else
		warn "Iface:   awg0 not up (awg-easy-rs brings it up on start)"
	fi

	printf "\nRecent logs (sudo journalctl -u %s -e):\n" "${SERVICE_NAME}"
	systemctl status "${SERVICE_NAME}" --no-pager 2>/dev/null | head -n 8 || true
}

# ── Main ──────────────────────────────────────────────────────────────────────

main() {
	parse_args "$@"
	case "${SUBCOMMAND}" in
		install)   cmd_install ;;
		upgrade)   cmd_upgrade ;;
		uninstall) cmd_uninstall ;;
		status)    cmd_status ;;
		*)         usage; exit 1 ;;
	esac
}

main "$@"
