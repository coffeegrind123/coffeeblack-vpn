# Vendored third-party binaries

## Repository layout

The pinned **versions + SHA-256 hashes** are committed:

- `XRAY_VERSION`        — Xray-core
- `TELEMT_VERSION`      — telemt (Telegram MTProxy)
- `MDNSVPN_VERSION`     — MasterDnsVPN (DNS-tunnel VPN server)
- `DNS_BUNDLE_VERSION`  — dnscrypt-proxy + tor + lyrebird + snowflake + webtunnel
- `LICENSES/`           — preserved upstream LICENSE files (legal attribution)
- `update.sh`           — curation tool: download/build, SHA-verify, gzip into place

The actual **binary blobs (`*-linux-amd64.gz`) are not committed.** They
are CI artifacts, produced from the pinned source list at build time
by [`scripts/build.sh`](../scripts/build.sh) (or the
[`Build and Release`](../.github/workflows/build-release.yml) workflow).
This keeps the repo small and forces every release to be reproducible
from the audited pin files.

`build.rs` is tolerant of missing blobs — when one is absent it emits a
`cargo:warning` and disables the matching `cfg(*_bundled)` gate, so
`cargo check` / `cargo test` work on a fresh clone without first
running the vendor stage. To get a fully-bundled binary, run
`scripts/build.sh` (or any of its `--vendor-only` / `--skip <bin>`
sub-modes for partial work).

## Supported architectures

**x86_64-linux only.** arm64 / aarch64 was dropped intentionally — the
DNS bundle's pluggable transports have no upstream pre-built static
arm64 ELFs and no viable cross-build path that's worth maintaining.
`build.rs` only emits `xray_bundled`, `dns_bundled`, and `telemt_bundled`
cfgs for `("linux", "x86_64")`; other targets compile cleanly but
without the bundled binaries.

## `xray-linux-amd64.gz`

Pinned [XTLS/Xray-core](https://github.com/XTLS/Xray-core) v26.3.27 ELF,
gzip-compressed (level 9). The Rust binary embeds it via
`include_bytes!` and extracts to disk on first run — this is what makes
the "Xray runs in the same binary" UX possible without writing a Rust
port of VLESS/Reality/Vision.

### Provenance

Downloaded from the upstream release page on 2026-05-09:

- `Xray-linux-64.zip` — SHA256 `23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae` (verified against the upstream `Xray-linux-64.zip.dgst`)

The `xray` ELF was extracted from the zip and re-compressed with
`gzip -9`. The decompressed-ELF SHA-256 hash (used by the runtime
extractor to detect cache-staleness) is recorded in `XRAY_VERSION`.

### Licensing

Xray-core is distributed under the
[Mozilla Public License 2.0](https://github.com/XTLS/Xray-core/blob/main/LICENSE).
Redistribution of the binary as part of awg-easy-rs is permitted under
MPL-2.0 §3.3 — the upstream source remains available at
<https://github.com/XTLS/Xray-core/tree/v26.3.27>.

### Updating

Bumping Xray is a three-step process:

1. Pick a new tag and download `Xray-linux-64.zip`.
2. Verify the zip SHA-256 against the upstream `.dgst` file.
3. Extract `xray`, run `gzip -9 -c xray > vendor/xray-linux-amd64.gz`, and update both `XRAY_VERSION` (version + uncompressed-ELF SHA) and the SHA above.

The build will refuse to start if `XRAY_VERSION` and the vendored blob disagree.

---

## DNS bundle (`dns_bundled` cfg)

Five binaries shipped together, each in `vendor/<name>-linux-amd64.gz`,
embedded the same way as Xray. `vendor/DNS_BUNDLE_VERSION` pins versions
and uncompressed-ELF SHA-256 sums. `build.rs` enables `cfg(dns_bundled)`
only when **all five** binaries have non-blank SHAs in the version file —
partial bundles are intentionally rejected so runtime supervisor code
can rely on every component being present.

### Components

| Binary | Upstream | How we sourced it |
|---|---|---|
| `dnscrypt-proxy` | <https://github.com/DNSCrypt/dnscrypt-proxy/releases> | Pre-built static-Go release asset (`dnscrypt-proxy-linux_x86_64-<ver>.tar.gz`). |
| `tor` | <https://www.torproject.org/download/tor/> | Built from source as a fully static-PIE binary in an Alpine Docker container, against musl-static `openssl-libs-static` + `libevent-static` + `zlib-static`. Distro-agnostic — runs on glibc, musl, or any other libc with no shared-library deps. |
| `lyrebird` | <https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird> | Built from source (`./cmd/lyrebird`) with `CGO_ENABLED=0 -ldflags='-s -w -extldflags=-static'` — truly distro-agnostic static binary. |
| `snowflake` | <https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake> | Built from source (`./client`) with `CGO_ENABLED=0 -ldflags='-s -w -extldflags=-static'` — truly distro-agnostic static binary. |
| `webtunnel` | <https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/webtunnel> | Built from source (`./main/client`) with `CGO_ENABLED=0 -ldflags='-s -w -extldflags=-static'` — truly distro-agnostic static binary. |

Total compressed bundle: ~20 MB. Adds the same again to the shipped
binary (~18 MB → ~35–40 MB stripped).

### Curation procedure

The whole pipeline is automated by `vendor/update.sh`. To bump any of
the six binaries to a new upstream version:

```bash
vendor/update.sh xray            v26.3.28
vendor/update.sh dnscrypt-proxy  2.1.16
vendor/update.sh tor             0.4.9.9
vendor/update.sh lyrebird        0.8.2
vendor/update.sh snowflake       v2.13.2
vendor/update.sh webtunnel       v0.0.5
```

For each binary the script:

1. Downloads or builds (Docker for tor + the Go PTs; HTTPS-pulled
   release tarball for xray + dnscrypt-proxy).
2. Verifies signatures where stable upstream keys exist
   (`Xray-linux-64.zip.dgst` SHA, `tor-<ver>.tar.gz.sha256sum`).
   For dnscrypt-proxy the maintainer's minisign key has rotated
   without updating their public docs in the past, so a sig failure
   is a warning rather than a hard stop — bumps require manual
   out-of-band verification.
3. Confirms the resulting ELF is fully static (`file` reports
   `statically linked` or `static-pie`, no dynamic interpreter).
   Aborts if anything is dynamically linked — `awg-easy-rs` is
   distro-agnostic and a non-static dependency would regress that.
4. SHA-256-hashes the uncompressed ELF, gzips at level 9 into
   `vendor/<name>-linux-amd64.gz`.
5. Atomically rewrites the matching `<NAME>_VERSION` and
   `<NAME>_AMD64_SHA256` lines in the pin file (`XRAY_VERSION` or
   `DNS_BUNDLE_VERSION`).
6. Cross-verifies: re-hashes the on-disk gzipped blob and confirms
   the unpacked content matches the SHA the pin file now holds.
   Catches "wrote the wrong SHA into the wrong field" bugs.

After the script finishes, `cargo build --release` will pick up the
new blob and SHA automatically — `build.rs` re-reads the pin file and
fails the build if the vendored blob and the pinned SHA disagree.

### Manual fallback

If you'd rather curate by hand (or the script's Docker-based build
isn't an option), the underlying steps are:

1. Download the upstream archive.
2. Verify the upstream signature when available.
3. Extract the ELF, sanity-check: `file <path>` must report
   `ELF 64-bit LSB executable`; `<path> --version` should run.
4. `sha256sum <elf>` — record in the appropriate pin file.
5. `gzip -9 -c <elf> > vendor/<name>-linux-amd64.gz`.
6. Bump `<NAME>_VERSION` in the pin file.

The runtime extractor (`src/dns/runtime.rs`) verifies the SHA on every
extract, so a tampered or corrupt blob fails fast at startup rather than
silently launching a wrong binary.

### Provenance (current pinned versions)

`vendor/DNS_BUNDLE_VERSION` is the authoritative record of what is pinned
(version string + SHA-256 of the *uncompressed* ELF, both checked by
`build.rs` at compile time and by `src/dns/runtime.rs` on every extract).
This section records the part the pin file cannot: **how each blob is
obtained and what the trust model is**. `vendor/update.sh <binary>
<version>` is the executable form of every recipe below — prefer it over
doing any of this by hand.

Versions below were current as of the 2026-09-03 curation pass
(dnscrypt-proxy and webtunnel bumped then; tor, lyrebird and snowflake
re-checked and already at their newest upstream release).

- **`dnscrypt-proxy` 2.1.18** — `dnscrypt-proxy-linux_x86_64-2.1.18.tar.gz`
  downloaded over HTTPS from
  <https://github.com/DNSCrypt/dnscrypt-proxy/releases/download/2.1.18/dnscrypt-proxy-linux_x86_64-2.1.18.tar.gz>
  (tarball SHA-256 `c8c8acb35b0f6619bfe8e4eed0c192672f8fd1964f467a42881905814e261c3e`).
  Minisign verification is still **not** part of the chain: the public key
  published in the project README remains stale relative to the release
  signing key, and `update.sh` prints a warning rather than pretending
  otherwise. Trust model: HTTPS chain-of-trust to
  `objects.githubusercontent.com`. **For future bumps, locate the current
  minisign public key from the dnscrypt-proxy maintainers and verify
  before vendoring.**

- **`tor` 0.4.9.11** — built from source inside an `alpine:3.20` Docker
  container (`apk add openssl-libs-static libevent-static zlib-static`),
  from `https://dist.torproject.org/tor-<ver>.tar.gz` with its published
  `.sha256sum` verified in-container, then
  `./configure --enable-static-tor --enable-static-openssl
  --enable-static-libevent --enable-static-zlib --disable-asciidoc
  --disable-html-manual --disable-manpage --disable-systemd
  --disable-lzma --disable-zstd && make && strip src/app/tor`.
  The result is checked with `file(1)` (must be static / static-PIE, no
  interpreter) and smoke-tested with `--version` before it is packaged —
  a partial static link that still exits 0 has shipped garbage before.

- **`lyrebird` 0.8.1**, **`snowflake` v2.14.1**, **`webtunnel` v0.0.6** —
  built from source in a `golang:1.24-alpine` container at the upstream
  git tag (`lyrebird-0.8.1`, `v2.14.1`, `v0.0.6`) from
  `gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/<name>`,
  via `CGO_ENABLED=0 go build -trimpath -ldflags='-s -w -extldflags=-static'`
  against `./cmd/lyrebird`, `./client` and `./main/client` respectively.
  Same static + smoke checks as tor. Trust model: HTTPS to
  `gitlab.torproject.org` plus the tag name — these projects publish no
  detached signatures for source tags, so pinning the built ELF's SHA-256
  in `DNS_BUNDLE_VERSION` is what makes a rebuild auditable.

  > **A Go PT's SHA is only reproducible against a fixed Go toolchain.**
  > `-trimpath` removes path noise, but a different Go minor version emits
  > a different binary. lyrebird's pin was carried over from a Go 1.23.4
  > build and did **not** reproduce under the `golang:1.24-alpine` image
  > `update.sh` now uses — the 2026-09-03 rebuild produced
  > `468ea0c7…` where the file recorded `0776d105…`, at the same upstream
  > tag. The pin now holds the value this repo's own pipeline reproduces.
  > When bumping the container's Go version, expect all three PT SHAs to
  > move even if no PT was upgraded, and re-materialise them in one pass
  > (`scripts/build.sh --vendor-only`) so the pin file stays truthful.

### Default posture

The bundle is opt-in at runtime. Even with `cfg(dns_bundled)` set:

- **dnscrypt-proxy** is started only when the operator enables it via the
  admin UI / env var.
- **tor + the three pluggable transports** are NEVER started by default.
  Tor adds latency, exit-node trust assumptions, and bridge-fetching
  network calls — all unwelcome in the default install. Operators who
  want the censorship-circumvention features flip an explicit toggle.

### Licensing

| Binary | License |
|---|---|
| `dnscrypt-proxy` | ISC |
| `tor` | BSD-3-Clause |
| `lyrebird` | BSD-2-Clause |
| `snowflake` | BSD-3-Clause |
| `webtunnel` | BSD-3-Clause |

All five are permissive licenses that allow redistribution of the
unmodified binary as part of awg-easy-rs.

---

## `telemt-linux-amd64.gz` (`telemt_bundled` cfg)

Pinned [telemt/telemt](https://github.com/telemt/telemt) **v3.5.5** ELF,
gzip-compressed (level 9). telemt is a Rust + Tokio implementation of
Telegram's MTProto proxy with full Fake-TLS / SNI fronting (the
`ee`-prefix link variant), per-user secrets, replay protection, and
optional masking. Embedded the same way as Xray — `include_bytes!` at
build time, runtime extraction with SHA verification.

### Provenance

Downloaded from the [3.5.5 release](https://github.com/telemt/telemt/releases/tag/3.5.5)
on 2026-09-03:

- `telemt-x86_64-linux-musl.tar.gz` — SHA256 `6be65484bb1b319798919b746e72d611d32e92aa07347c390fffc5127ff6615f` (verified against the upstream `telemt-x86_64-linux-musl.tar.gz.sha256`)

The single `telemt` ELF inside is `static-pie linked` (per `file(1)`), so
it runs unchanged on glibc, musl, or any other libc x86_64 host. It was
extracted from the tarball and re-compressed with `gzip -9`.
Decompressed-ELF SHA-256 (used by the runtime extractor to detect
cache-staleness): `a284ffe3df5d2fd23f96ba52aebc4e08529dda92add9fecedffd58cf8c85731e` — recorded in `TELEMT_VERSION`.

The 3.4 → 3.5 bump was checked against the control plane awg-easy-rs
actually drives, not just the changelog: the generated `config.toml` was
loaded by the 3.5.5 binary and every endpoint in `src/mtproxy/client.rs`
(`/v1/health`, user create/read/patch/delete, `rotate-secret`,
`reset-quota`, `/v1/stats/*`) exercised against it. Contract unchanged.
That run is also what caught the long-standing `ad_tag` vs `user_ad_tag`
request-field bug — telemt answers 2xx and drops keys it does not know,
so the mismatch had been silent since the module was written.

### Licensing

telemt is distributed under the **Telemt Public License 3** (TPL 3), an
Apache-License-2.0–derived permissive license. The full text is mirrored
at [`vendor/LICENSES/TELEMT-LICENSE.md`](LICENSES/TELEMT-LICENSE.md);
upstream copy at <https://github.com/telemt/telemt/blob/main/LICENSE>.

Redistribution of the unmodified binary as part of awg-easy-rs is
permitted under the TPL 3, provided that all copyright notices, license
terms, and conditions in the License are preserved — `vendor/LICENSES/`
is exactly that preservation.

### Updating

Bumping telemt is a three-step process — `vendor/update.sh telemt
<version>` automates it:

1. Download the new `telemt-x86_64-linux-musl.tar.gz` and verify the
   `.sha256` companion against upstream.
2. Extract the `telemt` ELF; re-gzip with `gzip -9`.
3. Update `TELEMT_VERSION` (version + uncompressed-ELF SHA-256) and the
   tarball SHA recorded above.

The build will refuse to start if `TELEMT_VERSION` and the vendored blob
disagree.

---

## `mdnsvpn-linux-amd64.gz` (`mdnsvpn_bundled` cfg)

Pinned [masterking32/MasterDnsVPN](https://github.com/masterking32/MasterDnsVPN)
release `v2026.06.13.234407-7de2476` server ELF, gzip-compressed (level 9).
MasterDnsVPN is a Go DNS-tunnel VPN: clients fragment + encrypt TCP/SOCKS5
traffic into DNS queries through public resolvers, the server listens on UDP/53
for tunnel envelopes (via NS-delegated subdomain) and re-emits the inner TCP
through a real socks5/forwarder. Embedded the same way as Xray + telemt —
`include_bytes!` at build time, runtime extraction with SHA verification.

### Provenance

Downloaded from the [v2026.06.13.234407-7de2476 release](https://github.com/masterking32/MasterDnsVPN/releases/tag/v2026.06.13.234407-7de2476)
(latest upstream release as of the 2026-09-03 pass):

- `MasterDnsVPN_Server_Linux_AMD64.tar.gz` — SHA256 `597bdc510b896a3b4ac89865ee7cefa73191025c64093f5e0f85c76a70430de9` (verified against the upstream `SHA256SUMS.txt`)

The Go ELF inside is `statically linked` (per `file(1)`), so it runs unchanged
on any libc x86_64 host. After extraction it was `strip`-ed (debug info shaves
~2.1 MB off the upstream 6.6 MB build) and re-compressed with `gzip -9`.
Decompressed-ELF SHA-256 (used by the runtime extractor to detect cache
staleness): `aebb7eb879c742135327b147f66e267e1587c47c9043de9a41811fe3eec8c126` —
recorded in `MDNSVPN_VERSION`.

### Default posture

The DNS-tunnel listener is **off by default**. Even with `cfg(mdnsvpn_bundled)`
set, the supervisor refuses to spawn until the operator:

1. Owns a domain and creates an `NS` delegation pointing the tunnel
   subdomain at this server's public IP (the upstream README walks
   through this — there is no way to skip it).
2. Sets `domain`, `port` (UDP/53 is the default), and an encryption key
   in the admin UI.
3. Flips `enabled = true`.

This matches the Xray, telemt, and DNS-bundle defaults — censorship
circumvention is opt-in, never on out of the box.

### Licensing

MasterDnsVPN is distributed under the **MIT License**. The full text is
mirrored at [`vendor/LICENSES/MDNSVPN-LICENSE.md`](LICENSES/MDNSVPN-LICENSE.md);
upstream copy at <https://github.com/masterking32/MasterDnsVPN/blob/main/LICENSE>.
Redistribution of the unmodified (modulo strip) binary as part of awg-easy-rs is
permitted under the MIT terms, provided the copyright notice and license remain
preserved — `vendor/LICENSES/MDNSVPN-LICENSE.md` is exactly that preservation.

### Updating

`vendor/update.sh mdnsvpn <version>` automates the bump:

1. Downloads the new `MasterDnsVPN_Server_Linux_AMD64.tar.gz` and verifies
   the matching line from upstream `SHA256SUMS.txt`.
2. Extracts the server ELF; runs `strip`; re-gzips with `gzip -9`.
3. Updates `MDNSVPN_VERSION` (version + uncompressed-ELF SHA-256) and
   the tarball SHA recorded above.

The build will refuse to start if `MDNSVPN_VERSION` and the vendored blob
disagree.
