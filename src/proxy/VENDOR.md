# `src/proxy/` — vendored DPI-imitation proxy

Most of this directory is a **vendored mirror** of the `src/` tree of the
[`amneziawg-proxy`](https://github.com/wiresock/amneziawg-install/tree/main/amneziawg-proxy)
crate (part of `wiresock/amneziawg-install`), brought in-process so
coffeeblack-vpn ships a single static binary with no subprocess and no blob.

The only mechanical change applied to upstream is rehoming the crate paths:

```
sed 's/crate::/crate::proxy::/g'
```

## Which files are which

| File | Origin | Edit? |
|------|--------|-------|
| `backend.rs`, `config.rs`, `errors.rs`, `metrics.rs`, `proxy.rs`, `quic_handshake.rs`, `responder.rs`, `session.rs`, `transform.rs` | **Vendored** from upstream (post-`sed`) | ❌ never edit by hand — edits are overwritten on the next sync and will fail `verify` |
| `mod.rs` | **Ours** — module declarations, doc, and the vendored-lint `#![allow(...)]` scope | ✅ |
| `supervisor.rs` | **Ours** — the coffeeblack-vpn glue: builds `ProxyConfig`/`CbParams` from the DB, drives the proxy as a Tokio task, orchestrates the AmneziaWG loopback rebind + firewall lockdown | ✅ |
| `patches/*.patch` | **Ours** — local security patches re-applied on top of the upstream mirror on every sync (see [`patches/README.md`](./patches/README.md)) | ✅ |
| `VENDOR.lock` | Auto-generated pin + per-file & per-patch `sha256` | ❌ generated |
| `VENDOR.md` | This file | ✅ |

The vendored `.rs` files under `src/proxy/` are the upstream mirror **with the
`patches/` series already applied** (that's what compiles). Keeping the fixes as
a patch series rather than hand-edits means `vendor-proxy.sh sync` re-applies
them automatically on every upgrade — a patched region that moves upstream makes
the sync stop and name the patch to refresh, instead of silently dropping the
hardening.

The current pin (upstream commit + `amneziawg-proxy` version) lives in
[`VENDOR.lock`](./VENDOR.lock).

## Upgrading to a newer upstream

Everything is driven by [`scripts/vendor-proxy.sh`](../../scripts/vendor-proxy.sh):

```bash
# See what a new upstream would change, without writing anything:
./scripts/vendor-proxy.sh diff --ref main

# Apply the upgrade (re-fetches, re-transforms, rewrites the 9 files + lock):
./scripts/vendor-proxy.sh sync --ref <commit|tag|branch>

# Re-apply the currently-pinned ref (e.g. after an accidental local edit):
./scripts/vendor-proxy.sh sync

# CI / pre-commit integrity gate (offline, sha256 only):
./scripts/vendor-proxy.sh verify
```

After a `sync`:

1. `git diff -- src/proxy/` — review the upstream delta.
2. Reconcile any dependency change the script prints against the root
   `Cargo.toml` (the script can't safely rewrite it).
3. If upstream added a **new module**, the script warns; add it to the
   `VENDORED=()` list in the script *and* declare it in `mod.rs`.
4. `cargo test && cargo clippy --all-targets`.
5. Commit `src/proxy/*.rs` and `VENDOR.lock` together.

## Why a lock + `verify`

`VENDOR.lock` records the exact upstream commit and the `sha256` of every
vendored file as written. `verify` recomputes those hashes and fails on any
mismatch. That gives two guarantees:

- **No silent local edits.** Vendored files are supposed to be a faithful
  mirror; a hand-edit (which would be lost on the next sync) is caught in CI.
- **Reproducible supply chain.** The tree can always be re-derived from the
  pinned upstream commit, and drift from it is detectable.

## Auditing against AmneziaWG

The proxy's model of the AmneziaWG wire format (packet classification and the
S1–S4 padding transform) was audited against the real `amneziawg-go` and
`amneziawg-linux-kernel-module` sources. The load-bearing invariants
(`[S-junk][LE u32 H-header][WG body]`, `H1→init … H4→transport`, `S4` on every
data packet, overwrite-only-`[0..S]`) match. Two coffeeblack-vpn-side mitigations
came out of that audit and live in `supervisor.rs` / `wg/mod.rs`, not in the
vendored code (so they survive a sync):

- **F1** — native AmneziaWG junk (`Jc`, `I1–I5`) is dropped from the effective
  config while the proxy is active (those separate datagrams would otherwise
  cross the wire un-imitated). See `supervisor::suppress_native_junk`.
- **F3** — hex `H` values are normalised to decimal before the (decimal-only)
  upstream parser sees them, so a hex `H` can't silently disable the
  transform. See `supervisor::norm_h`.
