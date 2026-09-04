# Stage 1: Build the Rust binary
#
# Base images are pinned by digest for reproducible, tamper-evident builds — a
# floating `:alpine` tag can silently change the toolchain (or be repointed by
# a registry compromise) between builds. Refresh the digests deliberately when
# bumping the toolchain (`docker buildx imagetools inspect rust:1-alpine`).
FROM rust:1-alpine@sha256:a10e64dd139b7387337c7fbe8aca31b959b57b2fd4c8ae20a02cf1d6ea424dce AS builder
WORKDIR /build

# Install build dependencies
RUN apk add --no-cache musl-dev pkgconfig

# Copy source
COPY Cargo.toml Cargo.lock* ./
COPY build.rs ./build.rs
COPY src/ ./src/
COPY static/ ./static/
# vendor/ holds the pinned Xray-core ELF (amd64 only, gzipped) and,
# when curated, the DNS-stack ELFs (dnscrypt-proxy, tor + PTs).
# build.rs embeds them into the binary via include_bytes!. The
# runtime extractor decompresses on first start. x86_64 only.
COPY vendor/ ./vendor/

# Build release binary as a fully static (interpreter-free) musl ELF.
#
# The two RUSTFLAGS below collaborate:
#   +crt-static          — link the C runtime into the binary so no
#                          .so files are needed at exec time.
#   relocation-model=static
#                        — disable PIE so the kernel doesn't look for
#                          a PT_INTERP entry. Without this the binary
#                          still declares /lib/ld-musl-x86_64.so.1 as
#                          its interpreter and won't run on glibc-only
#                          hosts (Debian / Ubuntu / RHEL).
#
# Result: `file` reports "statically linked" (no interpreter line) and
# the binary runs unchanged on glibc, musl, or any other libc x86_64
# Linux distro — verified by docker cp into debian:stable-slim.
#
# No `-C linker=musl-gcc` here, deliberately. `musl-gcc` is the Debian
# musl-tools wrapper around a glibc gcc; on Alpine the system compiler
# already targets musl and is installed as `/usr/bin/cc` — there is no
# `musl-gcc` in rust:*-alpine with or without `apk add musl-dev`
# (checked against both the previous and current base digests). Asking
# for it failed the builder stage outright with `linker \`musl-gcc\`
# not found`; rustc's default `cc` is the right linker in this image.
# The CI/bare-metal path is the one that needs musl-tools, because
# there the host gcc is glibc-targeting.
ENV RUSTFLAGS="-C target-feature=+crt-static -C relocation-model=static"
# `--locked` freezes the build to the committed Cargo.lock: if anything would
# change the lock (a yanked crate, a would-be minor bump), the build fails
# instead of silently resolving to different versions than were tested. Matches
# `scripts/install.sh`, which already builds with `--locked`.
RUN cargo build --release --locked --target x86_64-unknown-linux-musl && \
    strip target/x86_64-unknown-linux-musl/release/coffeeblack-vpn && \
    cp target/x86_64-unknown-linux-musl/release/coffeeblack-vpn /build/coffeeblack-vpn

# Stage 2: Build amneziawg-go (needs Go >= 1.24)
FROM golang:1-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS awg-go-builder
WORKDIR /build
RUN apk add --no-cache git make
# Pin to a release tag AND assert the resolved commit SHA. `--branch <tag>`
# alone is not enough — a tag is mutable and could be repointed upstream; the
# SHA assertion is the actual supply-chain integrity check. Bump both together.
# AWG 3.x: adds opt-in header protection, content padding and configurable
# timings on top of the 2.x junk/magic-header set. Every key we generate
# (Jc/Jmin/Jmax, S1-S4, H1-H4, I1-I5) is still accepted unchanged, and the
# new knobs default to off when unset, so existing peer configs keep working.
ARG AWG_GO_TAG=v3.1.20260828
ARG AWG_GO_SHA=b5928efb6ca19f0153958460c3d141f04abc5c2e
RUN git clone --depth 1 --branch "$AWG_GO_TAG" https://github.com/amnezia-vpn/amneziawg-go.git && \
    cd amneziawg-go && \
    got="$(git rev-parse HEAD)" && \
    [ "$got" = "$AWG_GO_SHA" ] || { echo "amneziawg-go SHA mismatch: got $got, want $AWG_GO_SHA" >&2; exit 1; } && \
    make

# Stage 3: Build amneziawg-tools
FROM alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d AS awg-builder
WORKDIR /build

RUN apk add --no-cache git build-base linux-headers

# Build amneziawg-tools (awg and awg-quick). Pinned to a release tag + asserted
# commit SHA (see the amneziawg-go stage for the rationale).
# Kept in lockstep with the amneziawg-go tag above — tools 3.x is what
# parses the AWG 3 keys and prints them in `awg show`. The `dump` peer
# lines (which src/wg/cli.rs parses) are unchanged; only the interface
# line grew columns, and that line is skipped.
ARG AWG_TOOLS_TAG=v3.1.20260812
ARG AWG_TOOLS_SHA=ee0f0a9aa34ff0a0da4b3433b9512781cfe02843
RUN git clone --depth 1 --branch "$AWG_TOOLS_TAG" https://github.com/amnezia-vpn/amneziawg-tools.git && \
    cd amneziawg-tools && \
    got="$(git rev-parse HEAD)" && \
    [ "$got" = "$AWG_TOOLS_SHA" ] || { echo "amneziawg-tools SHA mismatch: got $got, want $AWG_TOOLS_SHA" >&2; exit 1; } && \
    cd src && make

# Stage 4: Minimal runtime
FROM alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d
WORKDIR /app

# Install runtime dependencies. We use nftables natively now —
# `iptables` is no longer installed since we don't shell out to it.
# nftables comes from the `nftables` package and provides the `nft` CLI.
RUN apk add --no-cache \
    bash \
    nftables \
    kmod \
    wireguard-tools \
    curl \
    && rm -rf /var/cache/apk/*

# Copy amneziawg binaries
COPY --from=awg-go-builder /build/amneziawg-go/amneziawg-go /usr/bin/amneziawg-go
COPY --from=awg-builder /build/amneziawg-tools/src/wg /usr/bin/awg
COPY --from=awg-builder /build/amneziawg-tools/src/wg-quick/linux.bash /usr/bin/awg-quick
RUN chmod +x /usr/bin/awg /usr/bin/awg-quick /usr/bin/amneziawg-go

# Symlink amnezia config dir to wireguard
RUN mkdir -p /etc/amnezia && ln -s /etc/coffeeblack/conf /etc/amnezia/amneziawg

# Copy the Rust binary (truly static, runs on any x86_64 libc).
COPY --from=builder /build/coffeeblack-vpn /usr/local/bin/coffeeblack-vpn

# Health check — verifies the web UI binary is responding. We deliberately
# don't probe `awg show` here because a misconfigured WireGuard interface
# should surface in the UI / metrics rather than make the container
# unhealthy and start a restart loop.
HEALTHCHECK --interval=1m --timeout=5s --retries=3 \
    CMD /usr/bin/curl -fsS http://127.0.0.1:${PORT:-51821}/health || exit 1

ENV PORT=51821
ENV HOST=0.0.0.0
ENV INSECURE=false
ENV DISABLE_IPV6=false

# Run entirely in RAM by default (the operator asked for the WireGuard-style
# "data plane never depends on a healthy disk" property):
#  - IN_MEMORY=true        → SQLite opens :memory:; bundled subprocess ELFs
#                            (Xray/telemt/MasterDnsVPN/dnscrypt-proxy/tor) are
#                            exec'd from anonymous memfds, never written to a
#                            filesystem.
#  - COFFEEBLACK_PERSIST_DB    → the only durable touch point: the RAM database is
#                            snapshotted here (and restored on boot) so a
#                            planned restart keeps the full client roster. Put
#                            it on a small persistent volume (see compose).
#  - /etc/coffeeblack/conf is a tmpfs (see compose) so the generated configs, the
#    AmneziaWG .conf, and tor's data dir live in RAM too.
ENV IN_MEMORY=true
ENV COFFEEBLACK_PERSIST_DB=/data/coffeeblack.db
ENV COFFEEBLACK_PERSIST_INTERVAL=30

# Durable snapshot target (a volume is mounted here by compose). Created so
# the snapshot rename has a directory to land in even before the volume mount.
RUN mkdir -p /data

EXPOSE 51821/tcp
EXPOSE 51820/udp

CMD ["/usr/local/bin/coffeeblack-vpn"]
