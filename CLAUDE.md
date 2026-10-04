# coffeeblack-vpn — agent notes

Single static-musl Rust binary managing AmneziaWG plus Xray / MTProxy / DNS-tunnel
transports behind one web UI. Ships as a Docker image and as a bare-metal install
(`scripts/install.sh`). Read `README.md` and `docs/` first.

## Never compile on this box

Builds and every test run that compiles (cargo, docker build, `vendor/update.sh`,
`scripts/build.sh`, DKMS) happen in GitHub CI, never locally — see the global
CLAUDE.md. Locally: edit, read upstream sources, and non-compiling checks
(`bash -n`, shellcheck via `koalaman/shellcheck`, `node --check static/app.js`,
`cargo update --dry-run`, `scripts/vendor-proxy.sh verify`).

## CI

`.github/workflows/build-release.yml` runs on every push to `main` and on
`workflow_dispatch`: cargo-deny (`check advisories bans licenses sources`),
vendor blob materialisation, `cargo clippy --all-targets -- -D warnings`,
`cargo test --all-targets`, release build, **and a GitHub release**. Every push to
`main` ships a release, so batch related commits into one push.

Watch a run: `gh run watch <id> --exit-status`; failures: `gh run view <id> --log-failed`
(or `gh api repos/coffeegrind123/coffeeblack-vpn/actions/jobs/<job>/logs` when a
step fails before producing a test log). No `cargo fmt` gate — the code is
hand-aligned on purpose.

## Upstream upgrade protocol

Run when asked to bring the repo up to date with its upstreams. Previous passes:
`c28c7b5`, `27e2494` — their commit messages are the model for this one.

### 1. Inventory: measure before bumping

Read-only, nothing compiled. Record pinned vs latest for every row:

| Upstream | Pinned in | Latest from |
|---|---|---|
| Xray-core | `vendor/XRAY_VERSION` | `gh api repos/XTLS/Xray-core/releases` — **stable only**; its newer tags are usually pre-releases |
| dnscrypt-proxy, tor, lyrebird, snowflake, webtunnel | `vendor/DNS_BUNDLE_VERSION` | GitHub releases / `dist.torproject.org` / gitlab.torproject.org tags API |
| telemt | `vendor/TELEMT_VERSION` | `gh api repos/telemt/telemt/releases` (skip pre-releases) |
| MasterDnsVPN | `vendor/MDNSVPN_VERSION` | `gh api repos/masterking32/MasterDnsVPN/releases/latest` |
| amneziawg-go, amneziawg-tools (image) | `Dockerfile` `AWG_GO_TAG/SHA`, `AWG_TOOLS_TAG/SHA` | `gh api repos/amnezia-vpn/<repo>/tags` |
| amneziawg kernel module + tools (bare metal) | `scripts/install.sh` `AWG_KMOD_TAG/SHA`, `AWG_TOOLS_TAG/SHA` | same; tools pin must equal the Dockerfile's (`tests/install_pins.rs`) |
| DPI proxy (amneziawg-proxy) | `src/proxy/VENDOR.lock` | `scripts/vendor-proxy.sh diff` |
| Rust toolchain | `rust-toolchain.toml` | `static.rust-lang.org/dist/channel-rust-stable.toml` |
| crates | `Cargo.lock` | `cargo update --dry-run` (resolves only, does not compile) |
| base images | `Dockerfile` `FROM …@sha256:` | registry digests; Alpine minor from `dl-cdn.alpinelinux.org/alpine/` |
| GitHub Actions + cargo-deny binary | `.github/workflows/build-release.yml` | each action's releases |

### 2. Bump, one upstream per commit

- **Vendored binaries**: pins carry a version **and** a SHA-256 of the binary
  `vendor/update.sh` produces, so they can only be derived by building. Run the
  `vendor-update` workflow (`gh workflow run vendor-update.yml -f binary=<name> -f
  version=<v>`), download its artifact, review, and commit the pin file. Never run
  `update.sh` locally: it compiles tor and the Go transports, and a local rebuild
  does not reproduce the pinned SHA anyway.
- **AmneziaWG**: bump tag and SHA together (`git ls-remote` the tag to get the SHA).
  Diff the UAPI/config key set between old and new tags (`device/uapi.go`,
  `src/config.c`, `src/uapi/wireguard.h`) and confirm every key we generate is still
  accepted. Check whether `kmodCompatPatch()` in `install.sh` is still needed
  (upstream amneziawg-linux-kernel-module#173); `git apply` fails the install if it
  no longer applies.
- **DPI proxy**: `scripts/vendor-proxy.sh sync --ref <tag>`; local divergences live in
  `src/proxy/patches/` so they survive syncs. `verify` must pass.
- **Rust**: toolchain bump and `cargo update` are separate commits; `deny.toml`
  stays at `ignore = []` — fix advisories by upgrading, not by ignoring.
- **Base images and Actions**: refresh digests/versions; one commit.

### 3. Verify against behaviour, not changelogs

A bump is done when its behaviour has been checked against upstream's actual source
or a live instance — e.g. the telemt 3.5 bump caught `user_ad_tag` vs `ad_tag` only
because the control-plane endpoints `src/mtproxy/client.rs` uses were exercised. For
each bump, read upstream's diff for the surfaces this repo touches (CLI flags, config
keys, API fields, output formats it parses) and say in the commit message what was
checked.

### 4. Couplings to check every pass

- **pmnezia-client** (`coffeegrind123/pmnezia-client`, local `~/amnezia-client`) must
  parse every AmneziaWG key this server emits, and its amneziawg-go pin should not
  lag the image's `AWG_GO_TAG`. When AWG changes here, run that repo's protocol too.
- `README.md`, `vendor/README.md`, `docs/INSTALL.md` quote versions; bring them in
  line with the pins.

### 5. Ship

Commit each bump separately (Conventional Commits, `type(scope): summary`), push
`main` once, and watch the run to green. A pass is not finished while CI is red.
