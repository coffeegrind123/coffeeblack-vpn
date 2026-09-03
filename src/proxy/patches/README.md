# Local patches for the vendored proxy

These patches are applied by `scripts/vendor-proxy.sh` **after** the upstream
mirror is fetched and the `crate:: → crate::proxy::` transform is run — so the
vendored `.rs` files under `src/proxy/` stay a byte-diffable mirror of upstream,
while our hardening (and the couple of build-shape divergences below) survives
every `sync`/upgrade instead of being silently reverted.

Format: unified diff with `p0` paths (bare filename, e.g. `--- transform.rs`),
applied with `patch -p0` inside the staging dir.

## Series

- **`0001-deconstant-dns-sip-fingerprints.patch`** — removes two fixed
  cross-deployment DPI signatures the audit flagged (`transform.rs`):
  - the DNS EDNS cover **option-code** is drawn per-packet from the
    payload-seeded transaction ID within the IANA local-use range
    `[65001,65534]`, instead of a single hardcoded `0xFDE9` (which was a
    perfect one-rule signature for every deployment);
  - the SIP `Via`/`From`/`To`/`Call-ID` **host** is a per-packet
    seed-generated plausible hostname (`<label><n>.<tld>`) instead of the
    fixed RFC-2606 `*.example.*` literals.

  Both are cover bytes in the rewritten `[0..S]` prefix only — they never
  touch the encrypted region, and the tunnel is unaffected.

- **`0002-cfg-test-gate-toml-config-loader.patch`** — puts `#[cfg(test)]`
  on `config.rs`'s `load_config` / `parse_config` / `validate`. Upstream
  is a standalone daemon that reads a TOML file; here the `ProxyConfig`
  is assembled from SQLite by `proxy/supervisor.rs` and the file path is
  never taken, so gating the trio keeps the ported config tests
  compiling while dropping `toml` and its ~8-crate tree
  (toml/toml_edit/toml_datetime/serde_spanned/winnow/indexmap/hashbrown)
  out of the release binary — `toml` is a dev-dependency only. Not a
  security fix, but the same reasoning applies: as a patch it survives
  every `sync`, whereas a hand-edit would be reverted on the next
  upgrade and silently re-inflate the binary.

## Adding / refreshing a patch

1. Snapshot the current pristine (post-transform) file, edit the vendored file
   in place, then:
   `diff -u --label <f>.rs --label <f>.rs <pristine> src/proxy/<f>.rs > patches/NNNN-name.patch`
2. Round-trip check: apply the patch to a fresh pristine copy and confirm it
   reproduces the edited file.
3. `./scripts/vendor-proxy.sh sync` (re-applies + regenerates `VENDOR.lock`),
   then `cargo test`.

If a future upstream `sync` fails because a patched region moved, the script
stops and names the patch — refresh it against the new upstream rather than
dropping the fix.
