#!/usr/bin/env bash
#
# scripts/build.sh — Reproduce the CI build locally.
#
# What this does:
#
#   1. Reads each pinned binary version from vendor/<NAME>_VERSION.
#   2. Materialises the matching `vendor/<binary>-linux-amd64.gz` by
#      delegating to vendor/update.sh — which downloads or builds
#      from source, SHA-verifies, and gzip-9's into vendor/.
#      Skips binaries whose .gz is already on disk and round-trips
#      to the pinned SHA, so a re-run after a partial failure picks
#      up where the previous run left off (this matters: the tor
#      build alone takes ~10 minutes).
#   3. Builds awg-easy-rs as a fully static x86_64-linux-musl ELF
#      that runs unchanged on glibc, musl, or any other libc — see
#      Dockerfile for the same RUSTFLAGS triple.
#
# This is the script the GitHub `Build and Release` workflow runs.
# It's published as a separate file (rather than inlined in the .yml)
# so the build can be reproduced offline / in a fork / on a developer
# machine without leaning on Actions infrastructure.
#
# Requirements:
#
#   - bash, curl, gzip, sha256sum, file, tar, awk
#   - rustup with the x86_64-unknown-linux-musl target installed:
#       rustup target add x86_64-unknown-linux-musl
#   - a musl-capable linker. On glibc hosts that means musl-tools:
#       apt-get install -y musl-tools
#     On Alpine the system cc already targets musl — nothing to install.
#   - docker, for the tor + Go pluggable-transport builds
#     (xray + dnscrypt-proxy + telemt are pre-built downloads).
#
# Usage:
#
#   scripts/build.sh                    # full build (vendor + cargo)
#   scripts/build.sh --vendor-only      # materialise vendor/*.gz only
#   scripts/build.sh --cargo-only       # cargo build only (assumes blobs)
#   scripts/build.sh --check            # cargo build but stop short of strip
#   scripts/build.sh --skip <bin>...    # skip one or more binaries
#                                       #   (handy when iterating —
#                                       #    e.g. `--skip tor` to avoid
#                                       #    the 10-min Alpine rebuild)
#
# Output (on full success):
#
#   target/x86_64-unknown-linux-musl/release/awg-easy-rs
#       — statically linked, stripped, ready to ship
#
# Exit codes:
#
#   0  — success
#   1  — anything went wrong (the script `set -e`'s)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENDOR_DIR="$REPO_ROOT/vendor"
UPDATE_SH="$VENDOR_DIR/update.sh"

# Colour, but only on a TTY.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_RESET=$'\033[0m'; C_GREEN=$'\033[32m'; C_BLUE=$'\033[34m'
    C_YELLOW=$'\033[33m'; C_RED=$'\033[31m'; C_BOLD=$'\033[1m'
else
    C_RESET=""; C_GREEN=""; C_BLUE=""; C_YELLOW=""; C_RED=""; C_BOLD=""
fi
log()  { printf '%s[build.sh]%s %s\n' "$C_BLUE" "$C_RESET" "$*" >&2; }
ok()   { printf '%s[ ok ]%s %s\n' "$C_GREEN" "$C_RESET" "$*" >&2; }
warn() { printf '%s[warn]%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
die()  { printf '%s[fail]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Pinned-binary registry. Each entry is:
#   <update.sh-action> <pin-file> <version-key> <blob-name> <expected-sha-key>
#
# The script reads <version-key> and <expected-sha-key> from <pin-file>
# (parsed with parse_kv awk inline below), then calls
# `vendor/update.sh <action> <version>` if the on-disk blob doesn't
# already match the expected SHA.
#
# Add a new bundled binary by appending one row here + dropping a
# matching update_<binary> function in vendor/update.sh + adding a
# pin file (or a key in an existing pin file).
# ---------------------------------------------------------------------------
BINARIES=(
    "xray            vendor/XRAY_VERSION         XRAY_VERSION              xray            XRAY_AMD64_SHA256"
    "dnscrypt-proxy  vendor/DNS_BUNDLE_VERSION   DNSCRYPT_PROXY_VERSION    dnscrypt-proxy  DNSCRYPT_PROXY_AMD64_SHA256"
    "tor             vendor/DNS_BUNDLE_VERSION   TOR_VERSION               tor             TOR_AMD64_SHA256"
    "lyrebird        vendor/DNS_BUNDLE_VERSION   LYREBIRD_VERSION          lyrebird        LYREBIRD_AMD64_SHA256"
    "snowflake       vendor/DNS_BUNDLE_VERSION   SNOWFLAKE_VERSION         snowflake       SNOWFLAKE_AMD64_SHA256"
    "webtunnel       vendor/DNS_BUNDLE_VERSION   WEBTUNNEL_VERSION         webtunnel       WEBTUNNEL_AMD64_SHA256"
    "telemt          vendor/TELEMT_VERSION       TELEMT_VERSION            telemt          TELEMT_AMD64_SHA256"
    "mdnsvpn         vendor/MDNSVPN_VERSION      MDNSVPN_VERSION           mdnsvpn         MDNSVPN_AMD64_SHA256"
)

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
MODE="full"        # full | vendor-only | cargo-only | check
SKIP=()

while [ $# -gt 0 ]; do
    case "$1" in
        --vendor-only) MODE="vendor-only"; shift ;;
        --cargo-only)  MODE="cargo-only"; shift ;;
        --check)       MODE="check"; shift ;;
        --skip)        shift; SKIP+=("$1"); shift ;;
        --skip=*)      SKIP+=("${1#--skip=}"); shift ;;
        --help|-h)
            sed -n '3,46p' "$0" | sed 's/^# *//; s/^#$//'
            exit 0
            ;;
        *)
            die "unknown flag $1 (try --help)"
            ;;
    esac
done

is_skipped() {
    local name="$1"
    for s in "${SKIP[@]+"${SKIP[@]}"}"; do
        [ "$s" = "$name" ] && return 0
    done
    return 1
}

# ---------------------------------------------------------------------------
# Pin-file parser. Tolerates `KEY=VALUE` and `KEY = VALUE` (the two
# styles used across XRAY_VERSION / TELEMT_VERSION / DNS_BUNDLE_VERSION).
# Reads the first match for KEY and stops. Returns empty if not found.
# ---------------------------------------------------------------------------
read_pin_value() {
    local pin_file="$1" key="$2"
    awk -v k="$key" '
        BEGIN { pat = "^[[:space:]]*" k "[[:space:]]*=[[:space:]]*" }
        $0 ~ pat {
            sub(pat, "", $0)
            sub(/[[:space:]]*#.*$/, "", $0)
            sub(/^[[:space:]]+/, "", $0)
            sub(/[[:space:]]+$/, "", $0)
            print
            exit
        }
    ' "$pin_file"
}

# Compute the SHA-256 of the *uncompressed* ELF inside vendor/<name>.gz.
# Used to short-circuit re-builds when the on-disk blob already matches
# the pinned SHA. Empty output if the file is missing.
elf_sha_from_blob() {
    local blob="$1"
    [ -f "$blob" ] || { echo ""; return; }
    gunzip -c "$blob" 2>/dev/null | sha256sum | awk '{print $1}'
}

# ---------------------------------------------------------------------------
# Vendor stage — materialise each .gz from its pinned version.
# ---------------------------------------------------------------------------
fetch_vendor_blobs() {
    [ -x "$UPDATE_SH" ] || die "vendor/update.sh missing or not executable"

    local entry action pin_path version_key blob_name sha_key
    local pin_file version expected_sha actual_sha blob_path

    for entry in "${BINARIES[@]}"; do
        # shellcheck disable=SC2086
        set -- $entry
        action="$1"; pin_path="$2"; version_key="$3"
        blob_name="$4"; sha_key="$5"

        if is_skipped "$action"; then
            warn "$action: skipped (--skip)"
            continue
        fi

        pin_file="$REPO_ROOT/$pin_path"
        if [ ! -f "$pin_file" ]; then
            die "pin file $pin_file missing — bumping vendor.sh registry without updating pin files?"
        fi

        version="$(read_pin_value "$pin_file" "$version_key")"
        expected_sha="$(read_pin_value "$pin_file" "$sha_key")"
        blob_path="$VENDOR_DIR/${blob_name}-linux-amd64.gz"

        if [ -z "$version" ] || [ -z "$expected_sha" ]; then
            warn "$action: $version_key/$sha_key not pinned — leaving blob un-built"
            continue
        fi

        # Idempotency check — skip the (possibly very expensive) build
        # when the on-disk blob already round-trips to the pinned SHA.
        actual_sha="$(elf_sha_from_blob "$blob_path")"
        if [ "$actual_sha" = "$expected_sha" ]; then
            ok "$action $version: blob already current ($expected_sha)"
            continue
        fi

        log "$action $version: rebuilding (have=${actual_sha:-<none>} want=$expected_sha)"
        bash "$UPDATE_SH" "$action" "$version"

        # Re-verify after the rebuild. update.sh is authoritative —
        # it writes BOTH the blob and the matching pin atomically, so
        # the post-update.sh state of the pin file is what we should
        # compare against, not the pre-update.sh value we read above.
        # This matters for from-source builds (tor, the Go PTs) where
        # the resulting ELF SHA is environment-dependent (different
        # Alpine versions / apk package vintages produce different
        # bytes — tor's build isn't bit-reproducible cross-machine
        # without SOURCE_DATE_EPOCH and pinned-libc gymnastics).
        local post_pin_sha
        post_pin_sha="$(read_pin_value "$pin_file" "$sha_key")"
        actual_sha="$(elf_sha_from_blob "$blob_path")"
        if [ "$actual_sha" != "$post_pin_sha" ]; then
            die "$action: post-build pin/blob mismatch \
                (blob=$actual_sha pin=$post_pin_sha) — \
                update.sh failed to atomically write both"
        fi
        ok "$action $version: built and verified ($post_pin_sha)"
    done
}

# ---------------------------------------------------------------------------
# Cargo stage — fully-static musl-x86_64 build.
# ---------------------------------------------------------------------------
build_release_binary() {
    local target="x86_64-unknown-linux-musl"
    local out_path="$REPO_ROOT/target/$target/release/awg-easy-rs"

    # Same RUSTFLAGS the Dockerfile uses. Documented there in detail —
    # short version: +crt-static + static relocations → truly static, no
    # PT_INTERP, runs on any libc x86_64 host.
    local rustflags="-C target-feature=+crt-static -C relocation-model=static"

    if ! command -v cargo >/dev/null 2>&1; then
        die "cargo not on PATH — install rustup, then \`rustup target add $target\`"
    fi
    if ! rustup target list --installed 2>/dev/null | grep -q "^${target}$"; then
        warn "$target not installed; running rustup add"
        rustup target add "$target" || die "failed to install $target target"
    fi
    # Linker selection. On a glibc host (Debian/Ubuntu/Fedora) the system
    # cc cannot produce a musl binary, so musl-tools' `musl-gcc` wrapper is
    # required and must be named explicitly. On Alpine the system cc IS the
    # musl compiler and there is no `musl-gcc` at all — `apk add musl-dev`
    # does not create one — so asking for it fails the link outright. Pick
    # by what the host actually has rather than by package name.
    if command -v musl-gcc >/dev/null 2>&1; then
        rustflags="$rustflags -C linker=musl-gcc"
    elif cc -dumpmachine 2>/dev/null | grep -q musl; then
        log "musl-gcc absent; using the system cc ($(cc -dumpmachine)), which already targets musl"
    else
        die "no musl-capable linker — install \`musl-tools\` (Debian/Ubuntu/Fedora). \
On Alpine the system cc already targets musl and no extra package is needed."
    fi

    log "cargo build --release --target $target"
    RUSTFLAGS="$rustflags" cargo build --release --target "$target"

    if [ "$MODE" != "check" ]; then
        log "stripping $out_path"
        strip "$out_path"
    fi

    ok "binary: $out_path"
    if command -v file >/dev/null 2>&1; then
        log "  $(file "$out_path")"
    fi
    if command -v sha256sum >/dev/null 2>&1; then
        log "  sha256: $(sha256sum "$out_path" | awk '{print $1}')"
    fi
}

# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
printf '%s======== awg-easy-rs build ========%s\n' "$C_BOLD" "$C_RESET" >&2

case "$MODE" in
    full|vendor-only)
        log "Stage 1/2: materialising vendor/*.gz from pinned versions"
        fetch_vendor_blobs
        ;;
esac

case "$MODE" in
    full|cargo-only|check)
        log "Stage 2/2: cargo build (release, x86_64-unknown-linux-musl)"
        build_release_binary
        ;;
esac

ok "build complete"
