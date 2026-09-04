# Building from source

- [Toolchain](#toolchain)
- [Dependency gate](#dependency-gate)
- [Full build](#full-build)
- [Fast iteration](#fast-iteration)
- [Updating bundled component versions](#updating-bundled-component-versions)
- [Running without Docker](#running-without-docker)
- [CI](#ci)

---

## Toolchain

The toolchain is pinned by [`rust-toolchain.toml`](../rust-toolchain.toml), currently
**1.98.1**. rustup installs that exact stable automatically when you build in the repo, so
CI, development machines and the Docker builder all compile with the same `rustc`. The code
itself needs 1.80+ for `LazyLock`, `OnceLock` and edition 2021.

---

## Dependency gate

Builds are reproducible down to the crate. [`Cargo.lock`](../Cargo.lock) is committed and
every build path — `Dockerfile`, `scripts/install.sh`, CI — passes `--locked`, so a build
**fails** rather than silently resolving to versions that were never tested.

[`deny.toml`](../deny.toml), enforced by [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny)
in CI, is the known-good-versions gate. It fails on any RUSTSEC advisory, a yanked crate, a
license outside an explicit allowlist, an unexpected duplicate crate version, or a
non-crates.io source.

```bash
cargo deny check
```

The rationale for the deliberately lean tree, and the list of in-house replacements, is in
[ARCHITECTURE.md](ARCHITECTURE.md#dependency-policy).

---

## Full build

The bundled binary blobs (`vendor/*.gz`) are **not** committed. They are CI artifacts
produced from the audited pin files in `vendor/*_VERSION`. To get a fully bundled release
binary:

```bash
scripts/build.sh
```

That script:

1. Reads each pinned version from `vendor/*_VERSION`.
2. Materialises `vendor/<name>-linux-amd64.gz` for each entry by delegating to
   `vendor/update.sh` — downloading pre-built artifacts where upstream publishes them, and
   building from source in Alpine Docker for `tor` and the Go pluggable transports. Any
   binary whose existing `.gz` already round-trips to the pinned SHA is skipped.
3. Builds a fully static **x86_64-unknown-linux-musl** ELF at
   `target/x86_64-unknown-linux-musl/release/coffeeblack-vpn`, which runs unchanged on
   glibc, musl, or any other libc. With every component bundled it is ~57 MB; a build
   with no vendor blobs present is a fraction of that, since each missing blob compiles
   its subsystem out via `cfg(*_bundled)`.

`build.rs` refuses to build if a pin's SHA does not match the actual blob, and runtime
extraction refuses to install a binary whose SHA does not match the embedded constant.

---

## Fast iteration

`build.rs` is tolerant of missing blobs — it warns and disables the matching
`cfg(*_bundled)` — so a plain `cargo build` works without fetching anything. Cached `.gz`
blobs also persist between runs:

```bash
scripts/build.sh --cargo-only              # use cached vendor blobs
scripts/build.sh --skip tor --skip xray    # skip specific binaries
cargo build                                # plain debug build
cargo test                                 # full suite, ~4 minutes
cargo clippy --all-targets -- -D warnings  # what CI enforces
```

The suite is 1,092 unit and integration tests, plus `--ignored` end-to-end tests that spawn
real subprocesses and need the vendored blobs present.

Note that the tests in `tests/config.rs` mutate the process-wide environment and are
serialised behind a mutex for that reason. If you add one there, take `env_guard()` as the
first statement of the test body.

---

## Updating bundled component versions

Versions and SHA-256 hashes are pinned in:

| Pin file | Covers |
|---|---|
| `vendor/XRAY_VERSION` | Xray-core |
| `vendor/TELEMT_VERSION` | telemt MTProxy |
| `vendor/MDNSVPN_VERSION` | MasterDnsVPN DNS-tunnel server |
| `vendor/DNS_BUNDLE_VERSION` | dnscrypt-proxy, tor, lyrebird, snowflake, webtunnel |

To bump one, run `vendor/update.sh <binary> <version>`. The script downloads or builds,
verifies the SHA, and rewrites the matching pin file:

```bash
vendor/update.sh xray            v26.3.28
vendor/update.sh telemt          3.4.12
vendor/update.sh mdnsvpn         v2026.06.01.000000-abcdef0
vendor/update.sh dnscrypt-proxy  2.1.16
vendor/update.sh tor             0.4.9.9     # Alpine Docker build, ~10 min
vendor/update.sh lyrebird        0.8.2       # Go static, ~2 min
vendor/update.sh snowflake       v2.13.2
vendor/update.sh webtunnel       v0.0.5
```

Then commit the updated pin file. The `.gz` itself stays out of git.

Provenance and the curation procedure for each binary are documented in
[`vendor/README.md`](../vendor/README.md), and upstream licenses are preserved verbatim in
`vendor/LICENSES/`.

---

## Running without Docker

Gaming mode requires `awg`, `awg-quick` and the AmneziaWG kernel module on the host. The
other four transports are self-contained: their ELFs are embedded and extracted to their
configured directories on first start. Only the firewall stage additionally needs `nft`.

```bash
sudo ./target/x86_64-unknown-linux-musl/release/coffeeblack-vpn
```

`COFFEEBLACK_CONF_DIR` must be writable by the user the binary runs as.

If `awg-quick up cb0` fails, the binary still starts and serves the web UI — fix the host
config and click *Restart Interface* in the admin panel. Per-supervisor failures surface in
their own admin tabs, and all five transports are independently disable-able and degrade
gracefully.

For a managed systemd install rather than running the binary by hand, see
[INSTALL.md](INSTALL.md) — in particular the
[config bridge](INSTALL.md#config-bridge), which `awg-quick` requires and which a
hand-rolled install will not have.

---

## CI

[`.github/workflows/build-release.yml`](../.github/workflows/build-release.yml) runs the
same flow on every push to `main`, and can be dispatched manually:

`cargo-deny` gate → clippy with `-D warnings` → test suite → musl release build → tag →
GitHub release with the binary, its SHA-256, and a table of every bundled component's
pinned version.
