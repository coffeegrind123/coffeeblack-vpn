#!/usr/bin/env bash
#
# vendor/update.sh — Bump a vendored binary to a new version.
#
# Each of the six bundled binaries (Xray + the five DNS bundle binaries)
# has its own curation pipeline: download or build, verify, SHA, gzip,
# write back to vendor/, update the matching pin file. This script is
# the canonical implementation of the procedure documented prose-style
# in vendor/README.md.
#
# Usage:
#   vendor/update.sh <binary> <version>
#   vendor/update.sh --help
#
# Examples:
#   vendor/update.sh xray            v26.3.28
#   vendor/update.sh dnscrypt-proxy  2.1.16
#   vendor/update.sh tor             0.4.9.9
#   vendor/update.sh lyrebird        0.8.2
#   vendor/update.sh snowflake       v2.13.2
#   vendor/update.sh webtunnel       v0.0.5
#   vendor/update.sh telemt          3.4.12
#
# After a successful run:
#   - vendor/<name>-linux-amd64.gz is replaced with the new (truly static)
#     ELF, gzipped at level 9.
#   - vendor/{XRAY,DNS_BUNDLE}_VERSION has the matching VERSION + SHA256
#     lines updated atomically.
#   - The script verifies the on-disk SHA matches what it just wrote to
#     the pin file, then prints a `git diff --stat`-style summary.
#
# Build prerequisites:
#   - bash, curl, gzip, sha256sum, file (always)
#   - docker — used for tor (Alpine static-musl build) and the three Go
#     PT binaries (consistent toolchain via golang:<ver>-alpine images).
#     Falls back gracefully with a clear error if docker is missing.
#   - gpg (optional) — used for the Tor Project's .sha256sum.asc and
#     similar where signatures are available.

set -euo pipefail

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------

VENDOR_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$VENDOR_DIR/.." && pwd)"
XRAY_PIN="$VENDOR_DIR/XRAY_VERSION"
DNS_PIN="$VENDOR_DIR/DNS_BUNDLE_VERSION"
TELEMT_PIN="$VENDOR_DIR/TELEMT_VERSION"
MDNSVPN_PIN="$VENDOR_DIR/MDNSVPN_VERSION"

# Working directory for downloads + builds. Cleared on exit.
WORK_DIR=""
DOCKER_CONTAINERS=()  # tracked for cleanup

cleanup() {
    local rc=$?
    if [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ]; then
        rm -rf "$WORK_DIR"
    fi
    for c in "${DOCKER_CONTAINERS[@]+"${DOCKER_CONTAINERS[@]}"}"; do
        docker rm -f "$c" >/dev/null 2>&1 || true
    done
    return $rc
}
trap cleanup EXIT

# Colour output, but only to a TTY — keeps CI logs clean.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_RESET=$'\033[0m'; C_RED=$'\033[31m'; C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'; C_BLUE=$'\033[34m'; C_BOLD=$'\033[1m'
else
    C_RESET=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_BOLD=""
fi

log()  { printf '%s[update.sh]%s %s\n' "$C_BLUE" "$C_RESET" "$*" >&2; }
ok()   { printf '%s[ ok ]%s %s\n' "$C_GREEN" "$C_RESET" "$*" >&2; }
warn() { printf '%s[warn]%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
die()  { printf '%s[fail]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# CLI dispatch
# ---------------------------------------------------------------------------

usage() {
    cat <<'EOF'
Usage: vendor/update.sh <binary> <version>

Binaries:
  xray            Pre-built upstream release (GitHub, signed .dgst)
  dnscrypt-proxy  Pre-built upstream release (GitHub, HTTPS only — minisign
                  pubkey is stale; flag bumps for manual review)
  tor             Built from source in Alpine Docker, static-PIE
  lyrebird        Built from Go source (CGO_ENABLED=0, fully static)
  snowflake       Built from Go source (CGO_ENABLED=0, fully static)
  webtunnel       Built from Go source (CGO_ENABLED=0, fully static)
  telemt          Pre-built upstream release (GitHub, x86_64-linux-musl,
                  .sha256 companion verified)
  mdnsvpn         Pre-built upstream release (GitHub, Linux_AMD64.tar.gz,
                  SHA256SUMS.txt verified; stripped before gzip)

Examples:
  vendor/update.sh xray            v26.3.28
  vendor/update.sh dnscrypt-proxy  2.1.16
  vendor/update.sh tor             0.4.9.9
  vendor/update.sh lyrebird        0.8.2
  vendor/update.sh snowflake       v2.13.2
  vendor/update.sh webtunnel       v0.0.5
  vendor/update.sh telemt          3.4.12
  vendor/update.sh mdnsvpn         v2026.05.10.180256-27c7e11

Environment:
  NO_COLOR=1   Disable ANSI colour output (auto-disabled when stdout is
               not a TTY).
EOF
}

main() {
    if [ $# -lt 1 ] || [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
        usage
        exit 0
    fi

    local binary="$1"
    local version="${2:-}"
    if [ -z "$version" ]; then
        die "version is required (e.g. \`vendor/update.sh $binary <version>\`)"
    fi

    require_cmd curl gzip sha256sum file tar

    WORK_DIR="$(mktemp -d -t awg-easy-rs-vendor-XXXXXX)"
    log "work dir: $WORK_DIR"

    case "$binary" in
        xray)            update_xray "$version" ;;
        dnscrypt-proxy)  update_dnscrypt_proxy "$version" ;;
        tor)             update_tor "$version" ;;
        lyrebird)        update_lyrebird "$version" ;;
        snowflake)       update_snowflake "$version" ;;
        webtunnel)       update_webtunnel "$version" ;;
        telemt)          update_telemt "$version" ;;
        mdnsvpn)         update_mdnsvpn "$version" ;;
        *)               die "unknown binary $binary — see --help" ;;
    esac

    show_summary "$binary"
}

# ---------------------------------------------------------------------------
# Common helpers
# ---------------------------------------------------------------------------

require_cmd() {
    local missing=()
    for cmd; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    if [ ${#missing[@]} -gt 0 ]; then
        die "missing required command(s): ${missing[*]}"
    fi
}

require_docker() {
    require_cmd docker
    docker info >/dev/null 2>&1 || die "docker daemon not reachable"
}

# Verify the ELF is ACTUALLY a static ELF executable. Catches:
#   - dynamic linking ("we built with musl-gcc but forgot crt-static")
#   - dynamic interpreter declared ("would break on hosts without that
#     loader path")
#   - the configure/make produced something that isn't an ELF at all
#     ("data", a libtool wrapper script, an empty file). This last
#     case happened in CI when an Alpine package vintage broke tor's
#     static-link path; the build "succeeded" but produced garbage,
#     was SHA-pinned, and shipped to no end.
verify_static() {
    local path="$1" name="$2"
    local file_out
    file_out="$(file "$path")"
    log "  file: $file_out"
    if ! echo "$file_out" | grep -q "ELF "; then
        die "$name: $path is not an ELF binary (file says: $file_out) — \
build produced garbage or a wrapper script"
    fi
    if echo "$file_out" | grep -q "dynamically linked"; then
        die "$name: ELF is dynamically linked — would break on non-musl hosts"
    fi
    if echo "$file_out" | grep -qi "interpreter"; then
        die "$name: ELF declares an interpreter — would break on hosts \
without that loader path"
    fi
    if ! echo "$file_out" | grep -qE "statically linked|static-pie"; then
        die "$name: file output didn't include 'statically linked' or \
'static-pie' — refusing to ship a maybe-static binary (got: $file_out)"
    fi
}

# Compute the uncompressed ELF SHA-256 (used by the runtime extractor),
# gzip -9 into the vendor slot, and report the new SHA. Doesn't touch
# the pin file — caller does that next so a failure here doesn't leave
# the pin file pointing at a missing/old blob.
package_blob() {
    local elf_path="$1" blob_name="$2"
    local sha
    sha="$(sha256sum "$elf_path" | awk '{print $1}')"
    local dest="$VENDOR_DIR/${blob_name}-linux-amd64.gz"
    log "gzipping → $dest"
    gzip -9 -c "$elf_path" > "$dest.partial"
    mv "$dest.partial" "$dest"
    printf '%s' "$sha"
}

# Atomically rewrite a single `KEY = VALUE` line in a pin file. The
# match is anchored to the start-of-line and tolerates surrounding
# whitespace around `=`, matching the formats both pin files use.
# Errors out if the key isn't found — silent no-ops would be a footgun
# (a misspelled key would leave the old SHA in place undetected).
pin_update() {
    local pin_file="$1" key="$2" value="$3"
    if [ ! -f "$pin_file" ]; then
        die "pin file $pin_file does not exist"
    fi
    if ! grep -qE "^[[:space:]]*${key}[[:space:]]*=" "$pin_file"; then
        die "key $key not found in $pin_file — refusing to add silently. \
Add the key by hand if this is a new binary."
    fi
    local tmp="${pin_file}.tmp.$$"
    awk -v k="$key" -v v="$value" '
        BEGIN { pat = "^[[:space:]]*" k "[[:space:]]*=" }
        $0 ~ pat { printf "%s = %s\n", k, v; next }
        { print }
    ' "$pin_file" > "$tmp"
    mv "$tmp" "$pin_file"
    log "  pin: $key = $value"
}

# Cross-check: re-hash the on-disk gzipped blob's content against what
# we just wrote to the pin file. Catches "wrote the wrong SHA into the
# pin" or "the pin file format wasn't what awk expected".
verify_pin_matches_blob() {
    local blob_name="$1" expected_sha="$2"
    local blob="$VENDOR_DIR/${blob_name}-linux-amd64.gz"
    local actual
    actual="$(gunzip -c "$blob" | sha256sum | awk '{print $1}')"
    if [ "$actual" != "$expected_sha" ]; then
        die "POST-WRITE CHECK FAILED for $blob_name:
        pin file says SHA=$expected_sha
        on-disk gzipped blob unpacks to SHA=$actual
        Either the pin file write was wrong, or the blob got mangled."
    fi
}

show_summary() {
    local binary="$1"
    printf '\n%s%s──────────────────────────────────────────%s\n' \
        "$C_BOLD" "$C_GREEN" "$C_RESET" >&2
    ok "$binary updated"
    if command -v git >/dev/null 2>&1 && [ -d "$REPO_ROOT/.git" ]; then
        log "git status:"
        git -C "$REPO_ROOT" status --short -- vendor/ >&2 || true
    fi
    printf '%s%s──────────────────────────────────────────%s\n\n' \
        "$C_BOLD" "$C_GREEN" "$C_RESET" >&2
}

# Run a long-lived Alpine container detached, run the build inside, then
# `docker cp` the result out. We use `cp` rather than a `-v` bind mount
# because rootless / WSL2 / Lima setups don't always preserve binary
# permissions through volumes. This is slightly slower but works on
# every Docker variant.
docker_build_to_file() {
    local image="$1" container_name="$2" build_script="$3"
    local container_path="$4" host_path="$5"

    log "starting build container ($image)"
    docker pull "$image" >/dev/null 2>&1 || true
    # The build script itself appends `exec sleep infinity` at its
    # very end (callers responsibility — see update_tor /
    # update_go_pt). That keeps the container alive after a
    # successful build for the docker-cp step. On failure, set -e
    # aborts before the exec runs, so the shell exits non-zero
    # and the container terminates — that's what the polling
    # loop's "container exited before producing X" path detects.
    #
    # We previously tried `sh -c "$build_script && sleep infinity"`
    # for this. Doesn't work: $build_script ends with a newline,
    # so the result is a script with `&&` at the start of a new
    # line, which busybox sh rejects with "unexpected &&".
    docker run -d --name "$container_name" "$image" \
        sh -c "$build_script" >/dev/null
    DOCKER_CONTAINERS+=("$container_name")

    # Poll until the build artifact appears (and is non-empty) or the
    # container exits. `test -s` instead of `test -f` because tor's
    # Makefile creates `src/app/tor` as a 0-byte placeholder before
    # the actual final link runs; with -f we'd race that placeholder
    # and copy out an empty file, which then fails verify_static
    # downstream with a confusing "file says: empty" error.
    log "waiting for build to complete (this can take 10+ minutes for tor)"
    local elapsed=0
    while ! docker exec "$container_name" test -s "$container_path" 2>/dev/null; do
        if ! docker inspect -f '{{.State.Running}}' "$container_name" 2>/dev/null \
                | grep -q true; then
            warn "container exited before producing $container_path"
            # Dump the FULL container log on failure. Earlier we used
            # --tail 40, but autoconf's "configure: error: …" message
            # often comes mid-log followed by a hundred lines of make
            # noise — by the time the container exits, the actionable
            # error has scrolled off. Full logs go to stderr; CI keeps
            # the whole job log anyway, so size isn't a concern.
            log "build container logs (full):"
            docker logs "$container_name" >&2 || true
            die "build failed inside $image"
        fi
        sleep 5
        elapsed=$((elapsed + 5))
        if [ $((elapsed % 60)) -eq 0 ]; then
            log "  …${elapsed}s elapsed"
        fi
    done

    log "extracting build output → $host_path"
    docker cp "${container_name}:${container_path}" "$host_path"
    docker rm -f "$container_name" >/dev/null
    # Drop from the cleanup list since we just removed it.
    DOCKER_CONTAINERS=("${DOCKER_CONTAINERS[@]/$container_name}")
}

# ---------------------------------------------------------------------------
# Per-binary update functions
# ---------------------------------------------------------------------------

update_xray() {
    local version="$1"
    # Upstream tags like v26.3.27. Strip leading `v` for some URLs but
    # keep it in the pin file (matches the historical convention).
    local v="${version#v}"
    log "fetching Xray-core $version"
    local zip="$WORK_DIR/Xray-linux-64.zip"
    local dgst="$WORK_DIR/Xray-linux-64.zip.dgst"
    curl -sSL --fail-with-body -o "$zip" \
        "https://github.com/XTLS/Xray-core/releases/download/${version}/Xray-linux-64.zip"
    curl -sSL --fail-with-body -o "$dgst" \
        "https://github.com/XTLS/Xray-core/releases/download/${version}/Xray-linux-64.zip.dgst" || \
        { [ "${ALLOW_UNVERIFIED_VENDOR:-0}" = "1" ] \
            && warn "no .dgst for $version; ALLOW_UNVERIFIED_VENDOR=1 — proceeding" \
            || die "no .dgst published for Xray $version — cannot verify the download. \
Re-run with ALLOW_UNVERIFIED_VENDOR=1 to accept HTTPS alone."; }

    if [ -s "$dgst" ]; then
        local expected actual
        expected="$(awk '/SHA2-256/{print $2; exit}' "$dgst")"
        actual="$(sha256sum "$zip" | awk '{print $1}')"
        if [ "$expected" != "$actual" ]; then
            die "Xray zip SHA-256 mismatch:
                expected $expected (from upstream .dgst)
                got      $actual"
        fi
        ok "zip SHA-256 verified against upstream .dgst"
    fi

    log "extracting xray ELF"
    (cd "$WORK_DIR" && unzip -o "$zip" xray >/dev/null) \
        || die "unzip failed (is the 'unzip' command installed?)"
    local elf="$WORK_DIR/xray"
    [ -f "$elf" ] || die "xray binary not present in zip"
    chmod +x "$elf"

    log "smoke-test"
    "$elf" version >/dev/null 2>&1 || warn "xray --version returned non-zero (may be normal if libc is incompatible)"

    local sha
    sha="$(package_blob "$elf" "xray")"
    pin_update "$XRAY_PIN" "XRAY_VERSION" "$version"
    pin_update "$XRAY_PIN" "XRAY_AMD64_SHA256" "$sha"
    verify_pin_matches_blob "xray" "$sha"
}

update_dnscrypt_proxy() {
    local version="$1"
    # Upstream uses unprefixed versions like 2.1.15.
    local v="${version#v}"
    log "fetching dnscrypt-proxy $v"
    local tgz="$WORK_DIR/dnscrypt-proxy.tar.gz"
    curl -sSL --fail-with-body -o "$tgz" \
        "https://github.com/DNSCrypt/dnscrypt-proxy/releases/download/${v}/dnscrypt-proxy-linux_x86_64-${v}.tar.gz"

    # Try minisign verification — but the dnscrypt-proxy maintainers
    # have rotated keys without updating their public docs in the past,
    # so we treat a sig failure as a warning rather than a hard stop.
    # Operators bumping to a new version should manually verify the key
    # against a trusted out-of-band source.
    local sig="$WORK_DIR/dnscrypt-proxy.tar.gz.minisig"
    curl -sSL --fail-with-body -o "$sig" \
        "https://github.com/DNSCrypt/dnscrypt-proxy/releases/download/${v}/dnscrypt-proxy-linux_x86_64-${v}.tar.gz.minisig" 2>/dev/null || true

    # Fail closed. This artifact is unpacked and then *executed* on the build
    # host a few lines below, and its SHA is written into the pin file that the
    # runtime check trusts — so accepting an unverified download here defeats
    # every later integrity check rather than merely weakening this one.
    #
    # The maintainers have rotated the signing key without updating their docs
    # before, which is why this used to warn. That is a reason to make the
    # override explicit and auditable, not to accept any artifact silently: set
    # ALLOW_UNVERIFIED_VENDOR=1 to proceed after checking the key out of band.
    if [ -s "$sig" ] && command -v minisign >/dev/null 2>&1; then
        # Documented public key from the dnscrypt-proxy README.
        if minisign -V -P RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3 \
                -m "$tgz" 2>&1 | grep -q "Signature and comment signature verified"; then
            ok "minisign signature verified"
        elif [ "${ALLOW_UNVERIFIED_VENDOR:-0}" = "1" ]; then
            warn "minisign verification FAILED but ALLOW_UNVERIFIED_VENDOR=1 — proceeding"
        else
            die "minisign signature verification FAILED for dnscrypt-proxy $v. \
The signing key may have rotated: verify it out of band, then re-run with \
ALLOW_UNVERIFIED_VENDOR=1 if you accept the artifact."
        fi
    elif [ "${ALLOW_UNVERIFIED_VENDOR:-0}" = "1" ]; then
        warn "no minisig or minisign unavailable; ALLOW_UNVERIFIED_VENDOR=1 — proceeding"
    else
        die "cannot verify dnscrypt-proxy $v: \
$( [ -s "$sig" ] || echo 'no .minisig published' )$( command -v minisign >/dev/null 2>&1 || echo 'minisign not installed' ). \
Install minisign, or re-run with ALLOW_UNVERIFIED_VENDOR=1 to accept HTTPS alone."
    fi

    log "extracting dnscrypt-proxy ELF"
    (cd "$WORK_DIR" && tar xzf "$tgz")
    local elf="$WORK_DIR/linux-x86_64/dnscrypt-proxy"
    [ -f "$elf" ] || die "dnscrypt-proxy binary not present at expected path"

    verify_static "$elf" "dnscrypt-proxy"

    # Smoke-test runs the downloaded binary on the build host, so it must come
    # after verification, never before.
    log "smoke-test"
    "$elf" -version >/dev/null 2>&1 || warn "dnscrypt-proxy -version returned non-zero"

    local sha
    sha="$(package_blob "$elf" "dnscrypt-proxy")"
    pin_update "$DNS_PIN" "DNSCRYPT_PROXY_VERSION" "$v"
    pin_update "$DNS_PIN" "DNSCRYPT_PROXY_AMD64_SHA256" "$sha"
    verify_pin_matches_blob "dnscrypt-proxy" "$sha"
}

update_tor() {
    local version="$1"
    require_docker
    log "building tor $version from source in Alpine Docker (~10 min)"

    # Pin Alpine to 3.20 (current LTS as of 2026-05). The previous
    # `alpine` (= alpine:latest) tag broke under us when a newer
    # openssl-libs-static version stopped composing with tor's
    # `--enable-static-openssl` config — produced an output file
    # `file` reported as `data` (not ELF) that we then SHA-pinned
    # and shipped. Pinning the Alpine version makes apk pick up a
    # known-good toolchain across machines + CI runs. Bump
    # explicitly when revisiting.
    #
    # Same fully-static-PIE build via apk static-variant packages.
    # If --version fails or `file` says we didn't produce a valid
    # static ELF, the surrounding script aborts (verify_static is
    # strict about that since the CI failure on 2026-05-10).
    # NOTE on diagnostics: configure + make output goes straight to the
    # container's stdout/stderr (no redirection). When something breaks
    # we get the actual compiler error in `docker logs`, which the
    # docker_build_to_file failure path already prints. Without this,
    # alpine package drift between local and CI runners (e.g. openssl 3
    # API changes that tor's autoconf can't accommodate) shows up as
    # "container exited" with no clue why.
    local script="
set -e
echo '=== apk packages ==='
apk add --no-cache build-base wget openssl-dev openssl-libs-static \
    libevent-dev libevent-static zlib-dev zlib-static linux-headers \
    pkgconfig file
apk info -v openssl-libs-static libevent-static zlib-static build-base
echo '=== static archives on disk ==='
# tor's --enable-static-{zlib,libevent,openssl} require a matching
# --with-{zlib,libevent,openssl}-dir=DIR pointing at the directory
# containing lib<x>.a. Alpine versions move static archives around
# (the original /usr/lib worked locally but breaks on alpine:3.20),
# so derive the directory from apk's own file list rather than
# hardcoding it. Falls back to /usr/lib if the package query fails.
ZLIB_A=\$(apk info -L zlib-static    | grep -m1 '^.*libz\\.a\$'    | sed 's:^:/:;s:/libz\\.a\$::')
EVENT_A=\$(apk info -L libevent-static | grep -m1 '^.*libevent\\.a\$' | sed 's:^:/:;s:/libevent\\.a\$::')
SSL_A=\$(apk info -L openssl-libs-static | grep -m1 '^.*libssl\\.a\$'  | sed 's:^:/:;s:/libssl\\.a\$::')
ZLIB_DIR=\${ZLIB_A:-/usr/lib}
EVENT_DIR=\${EVENT_A:-/usr/lib}
SSL_DIR=\${SSL_A:-/usr/lib}
echo \"  libz.a    in \$ZLIB_DIR\"
echo \"  libevent.a in \$EVENT_DIR\"
echo \"  libssl.a   in \$SSL_DIR\"
ls -la \"\$ZLIB_DIR/libz.a\" \"\$EVENT_DIR/libevent.a\" \"\$SSL_DIR/libssl.a\" \"\$SSL_DIR/libcrypto.a\"
cd /tmp
echo '=== fetching tor ${version} ==='
wget -q https://dist.torproject.org/tor-${version}.tar.gz
wget -q https://dist.torproject.org/tor-${version}.tar.gz.sha256sum
sha256sum -c tor-${version}.tar.gz.sha256sum
tar xzf tor-${version}.tar.gz
cd tor-${version}
echo '=== ./configure ==='
./configure --enable-static-tor \
    --enable-static-openssl --with-openssl-dir=\$SSL_DIR \
    --enable-static-libevent --with-libevent-dir=\$EVENT_DIR \
    --enable-static-zlib --with-zlib-dir=\$ZLIB_DIR \
    --disable-asciidoc --disable-html-manual --disable-manpage \
    --disable-systemd --disable-lzma --disable-zstd
echo '=== make ==='
make -j\$(nproc)
echo '=== verify ==='
# Refuse to ship if the linker silently produced a non-ELF — make
# may exit 0 on a partial/odd link path.
file src/app/tor | grep -q 'ELF .* executable' || {
    echo 'tor build did not produce an ELF executable:'
    file src/app/tor
    exit 1
}
src/app/tor --version >/dev/null || {
    echo 'tor --version failed inside the build container'
    exit 1
}
strip src/app/tor
# Keep the container alive for docker-cp. set -e above means any
# prior failure already exited; reaching this line is the success
# path. exec replaces sh so the container's PID 1 becomes sleep —
# clean shutdown on docker rm -f.
exec sleep infinity
"
    docker_build_to_file alpine:3.20 "awg-tor-build-$$" "$script" \
        "/tmp/tor-${version}/src/app/tor" "$WORK_DIR/tor"

    verify_static "$WORK_DIR/tor" "tor"

    log "smoke-test"
    "$WORK_DIR/tor" --version >/dev/null 2>&1 \
        || die "tor --version returned non-zero — refusing to ship a non-functional binary"

    local sha
    sha="$(package_blob "$WORK_DIR/tor" "tor")"
    pin_update "$DNS_PIN" "TOR_VERSION" "$version"
    pin_update "$DNS_PIN" "TOR_AMD64_SHA256" "$sha"
    verify_pin_matches_blob "tor" "$sha"
}

# Shared logic for the three Go-built pluggable transports. Each PT has
# a different upstream URL, build path, and binary name — passed as args.
update_go_pt() {
    local pin_key_prefix="$1" git_url="$2" git_tag="$3"
    local build_subpath="$4" out_binary="$5" blob_name="$6"
    # The string written to <PREFIX>_VERSION. Defaults to the git tag,
    # which is right for snowflake/webtunnel (tags are `vX.Y.Z`), but
    # lyrebird tags are `lyrebird-X.Y.Z` while the pin holds the bare
    # version — without this the pin flip-flopped between the two forms
    # every time build.sh had to rebuild the blob.
    local pin_version="${7:-$git_tag}"
    require_docker

    log "building $blob_name $git_tag from source (Go, static, CGO_ENABLED=0)"
    # /src and /out aren't standard paths in golang:*-alpine — create
    # them before cd'ing in. Also pull in `file`, which the slim
    # alpine base doesn't ship: needed for the post-build ELF check.
    # (Both latent until CI actually exercised this path on 2026-05-10.)
    local script="
set -e
# golang:*-alpine is slim. We pull in three packages: git (for the
# clone step), file (for the post-build ELF gate), and binutils
# (which provides strip + ar + ld for any Go cgo fallback path).
# (Backticks elided from this comment on purpose — the script is
#  inside a bash double-quoted heredoc-style string, so a backtick
#  would trigger command substitution at variable-assign time.
#  Got bitten by exactly that on 2026-05-10: 'binutils' in
#  backticks ran as a shell command on the host before docker
#  even started.)
apk add --no-cache git file binutils >/dev/null 2>&1
mkdir -p /src /out
cd /src
git clone --depth 1 --branch '${git_tag}' '${git_url}' src 2>&1 | tail -3
cd src
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags='-s -w -extldflags=-static' \
    -o /out/${out_binary} ${build_subpath}
file /out/${out_binary} | grep -q 'ELF .* executable' || {
    echo '${blob_name} build did not produce an ELF executable:'
    file /out/${out_binary} 2>&1 || ls -la /out/${out_binary}
    exit 1
}
strip /out/${out_binary}
# Keep alive for docker-cp; see update_tor for the rationale.
exec sleep infinity
"
    docker_build_to_file golang:1.24-alpine "awg-go-build-$$" "$script" \
        "/out/${out_binary}" "$WORK_DIR/${out_binary}"

    verify_static "$WORK_DIR/${out_binary}" "$blob_name"

    local sha
    sha="$(package_blob "$WORK_DIR/${out_binary}" "$blob_name")"
    pin_update "$DNS_PIN" "${pin_key_prefix}_VERSION" "$pin_version"
    pin_update "$DNS_PIN" "${pin_key_prefix}_AMD64_SHA256" "$sha"
    verify_pin_matches_blob "$blob_name" "$sha"
}

update_lyrebird() {
    local version="$1"
    update_go_pt LYREBIRD \
        "https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird.git" \
        "lyrebird-${version#lyrebird-}" \
        "./cmd/lyrebird" \
        "lyrebird" \
        "lyrebird" \
        "${version#lyrebird-}"
}

update_snowflake() {
    local version="$1"
    # snowflake tags are prefixed `v` — pass through whatever the user gave.
    local tag="$version"
    [[ "$tag" == v* ]] || tag="v$tag"
    update_go_pt SNOWFLAKE \
        "https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake.git" \
        "$tag" \
        "./client" \
        "snowflake-client" \
        "snowflake"
}

update_webtunnel() {
    local version="$1"
    local tag="$version"
    [[ "$tag" == v* ]] || tag="v$tag"
    update_go_pt WEBTUNNEL \
        "https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/webtunnel.git" \
        "$tag" \
        "./main/client" \
        "webtunnel-client" \
        "webtunnel"
}

update_telemt() {
    local version="$1"
    # Upstream tags are unprefixed (e.g. 3.4.11). The release publishes
    # both glibc and musl variants for x86_64; we want the static-musl
    # one so the bundled binary runs on any libc host.
    local v="${version#v}"
    log "fetching telemt $v (x86_64-linux-musl)"
    local tgz="$WORK_DIR/telemt-x86_64-linux-musl.tar.gz"
    local sha_file="$WORK_DIR/telemt-x86_64-linux-musl.tar.gz.sha256"
    curl -sSL --fail-with-body -o "$tgz" \
        "https://github.com/telemt/telemt/releases/download/${v}/telemt-x86_64-linux-musl.tar.gz"
    curl -sSL --fail-with-body -o "$sha_file" \
        "https://github.com/telemt/telemt/releases/download/${v}/telemt-x86_64-linux-musl.tar.gz.sha256"

    local expected actual
    expected="$(awk '{print $1; exit}' "$sha_file")"
    actual="$(sha256sum "$tgz" | awk '{print $1}')"
    if [ "$expected" != "$actual" ]; then
        die "telemt tarball SHA-256 mismatch:
            expected $expected (from upstream .sha256)
            got      $actual"
    fi
    ok "tarball SHA-256 verified against upstream .sha256"

    log "extracting telemt ELF"
    (cd "$WORK_DIR" && tar xzf "$tgz")
    local elf="$WORK_DIR/telemt"
    [ -f "$elf" ] || die "telemt binary not present at expected path in tarball"
    chmod +x "$elf"

    verify_static "$elf" "telemt"

    log "smoke-test"
    "$elf" --help >/dev/null 2>&1 \
        || warn "telemt --help returned non-zero (may be normal — the binary uses positional args)"

    local sha
    sha="$(package_blob "$elf" "telemt")"
    pin_update "$TELEMT_PIN" "TELEMT_VERSION" "$v"
    pin_update "$TELEMT_PIN" "TELEMT_AMD64_SHA256" "$sha"
    verify_pin_matches_blob "telemt" "$sha"

    # Refresh the bundled LICENSE — operators bumping versions need the
    # right license file alongside the binary so the TPL3 attribution
    # condition stays satisfied.
    log "refreshing vendor/LICENSES/TELEMT-LICENSE.md"
    mkdir -p "$VENDOR_DIR/LICENSES"
    if curl -sSL --fail-with-body -o "$VENDOR_DIR/LICENSES/TELEMT-LICENSE.md" \
            "https://raw.githubusercontent.com/telemt/telemt/${v}/LICENSE"; then
        ok "license file refreshed"
    else
        warn "could not fetch upstream LICENSE for ${v} — the existing \
vendor/LICENSES/TELEMT-LICENSE.md was left in place; verify it still matches the new release"
    fi
}

# ---------------------------------------------------------------------------
# MasterDnsVPN (DNS-tunnel VPN server)
# ---------------------------------------------------------------------------
#
# Upstream releases ship a Go ELF inside `MasterDnsVPN_Server_Linux_AMD64.tar.gz`
# with debug_info still present (~6.6 MB). We strip it before gzipping so the
# bundled blob is ~1.9 MB instead of ~2.6 MB. The tarball is integrity-checked
# against the matching line in upstream `SHA256SUMS.txt`.
update_mdnsvpn() {
    local version="$1"
    # Upstream tags look like `v2026.05.10.180256-27c7e11`. We pass the
    # tag verbatim into the URL — no `v` prefix stripping. The asset
    # filename does not embed the version (just `_Linux_AMD64.tar.gz`).
    log "fetching MasterDnsVPN server $version (Linux_AMD64.tar.gz)"
    local asset="MasterDnsVPN_Server_Linux_AMD64.tar.gz"
    local tgz="$WORK_DIR/$asset"
    local sums_file="$WORK_DIR/SHA256SUMS.txt"
    curl -sSL --fail-with-body -o "$tgz" \
        "https://github.com/masterking32/MasterDnsVPN/releases/download/${version}/${asset}"
    curl -sSL --fail-with-body -o "$sums_file" \
        "https://github.com/masterking32/MasterDnsVPN/releases/download/${version}/SHA256SUMS.txt"

    # Pluck the line for our asset from the global SHA256SUMS.txt. The
    # file paths in there are prefixed with `release_assets/...` so we
    # match on the basename.
    local expected actual
    expected="$(awk -v want="$asset" '
        {
            n = split($2, parts, "/")
            if (parts[n] == want) { print $1; exit }
        }' "$sums_file")"
    if [ -z "$expected" ]; then
        die "mdnsvpn: $asset not found in upstream SHA256SUMS.txt"
    fi
    actual="$(sha256sum "$tgz" | awk '{print $1}')"
    if [ "$expected" != "$actual" ]; then
        die "mdnsvpn tarball SHA-256 mismatch:
            expected $expected (from upstream SHA256SUMS.txt)
            got      $actual"
    fi
    ok "tarball SHA-256 verified against upstream SHA256SUMS.txt"

    log "extracting mdnsvpn server ELF"
    (cd "$WORK_DIR" && tar xzf "$tgz")
    # The tarball contains:
    #   MasterDnsVPN_Server_Linux_AMD64_<version>      (Go ELF, ~6.6 MB)
    #   server_config.toml                              (sample config)
    # The ELF basename embeds the version; resolve by glob to avoid hard-
    # coding the version string twice.
    local elf
    elf="$(find "$WORK_DIR" -maxdepth 1 -name 'MasterDnsVPN_Server_Linux_AMD64_*' -type f | head -1)"
    [ -n "$elf" ] && [ -f "$elf" ] \
        || die "mdnsvpn server ELF not present at expected path in tarball"
    chmod +x "$elf"

    verify_static "$elf" "mdnsvpn"

    log "smoke-test"
    "$elf" -version >/dev/null 2>&1 \
        || warn "mdnsvpn -version returned non-zero (continuing anyway)"

    # Strip debug info to shrink the bundled blob. The runtime extractor
    # SHA-verifies the stripped ELF, so the pin SHA is computed AFTER
    # strip. Catches "strip changed bytes between commits" (different
    # strip versions can produce different bytes).
    log "stripping debug info"
    strip "$elf" \
        || warn "strip failed — falling back to unstripped ELF"
    log "  post-strip: $(file "$elf")"

    local sha
    sha="$(package_blob "$elf" "mdnsvpn")"
    pin_update "$MDNSVPN_PIN" "MDNSVPN_VERSION" "$version"
    pin_update "$MDNSVPN_PIN" "MDNSVPN_AMD64_SHA256" "$sha"
    verify_pin_matches_blob "mdnsvpn" "$sha"

    # Refresh the bundled LICENSE — MasterDnsVPN is MIT, the attribution
    # requirement means we keep an in-tree copy alongside the binary.
    log "refreshing vendor/LICENSES/MDNSVPN-LICENSE.md"
    mkdir -p "$VENDOR_DIR/LICENSES"
    if curl -sSL --fail-with-body -o "$VENDOR_DIR/LICENSES/MDNSVPN-LICENSE.md" \
            "https://raw.githubusercontent.com/masterking32/MasterDnsVPN/main/LICENSE"; then
        ok "license file refreshed"
    else
        warn "could not fetch upstream LICENSE — the existing \
vendor/LICENSES/MDNSVPN-LICENSE.md was left in place; verify it still matches the new release"
    fi
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

main "$@"
