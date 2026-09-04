//! Bundled DNS stack — dnscrypt-proxy + (optional) tor + pluggable
//! transports + (in-process) hickory-dns recursive resolver.
//!
//! Layered the way Wiregate's compose stack is, just collapsed into one
//! binary:
//!
//! ```text
//!   peer (WG)
//!     │  :53 / :853
//!     ▼
//!   dns-prerouting (firewall.rs DNAT) ──► hickory-dns (in-process)
//!                                          │
//!                  ┌───────────────────────┴────────────────────────┐
//!                  │                                                │
//!                  ▼ (default)                                      ▼ (opt-in)
//!             dnscrypt-proxy                                  tor SOCKS :9053
//!             (DoH / DNSCrypt egress)                         + dnscrypt-proxy
//!                                                             ─────► public DoH
//! ```
//!
//! ## Module split
//!
//! - `runtime` — extract the bundled ELFs onto disk, SHA-verify, chmod
//!   755. Mirror of `src/xray/runtime.rs`. Always compiled (even when
//!   the bundle is absent) so callers can ask for the bundled-version
//!   strings via `embedded_versions()`.
//! - `supervisor` (TODO) — tokio-supervised dnscrypt-proxy + tor child
//!   processes with SIGHUP reload, SIGTERM grace shutdown, and capped
//!   exponential backoff on crash. Compiled only with `cfg(dns_bundled)`.
//! - `tor` (TODO) — torrc generator, BridgeDB scrape, PT plugin selection.
//! - `dnscrypt` (TODO) — `dnscrypt-proxy.toml` generator.
//!
//! ## Default posture
//!
//! Even with `cfg(dns_bundled)` set, **nothing starts by default**. The
//! operator opts in via DB toggles (admin UI) or `INIT_*` env vars. Tor
//! in particular is opt-in independent of dnscrypt-proxy because Tor
//! adds latency, exit-node trust assumptions, and BridgeDB network
//! calls — all unwelcome in a default install.

pub mod dnscrypt;
pub mod runtime;
#[cfg(dns_bundled)]
pub mod supervisor;
pub mod tor;

/// Per-binary version + SHA-256 surfaced from `vendor/DNS_BUNDLE_VERSION`.
/// Always populated (blank strings when the binary isn't bundled for the
/// current target). Exposed via `/about` so operators can confirm what
/// shipped without unpacking the binary.
pub fn embedded_versions() -> [(&'static str, &'static str, &'static str); 5] {
    [
        ("dnscrypt-proxy", env!("COFFEEBLACK_DNS_DNSCRYPT_PROXY_VERSION"), env!("COFFEEBLACK_DNS_DNSCRYPT_PROXY_SHA256")),
        ("tor",            env!("COFFEEBLACK_DNS_TOR_VERSION"),            env!("COFFEEBLACK_DNS_TOR_SHA256")),
        ("lyrebird",       env!("COFFEEBLACK_DNS_LYREBIRD_VERSION"),       env!("COFFEEBLACK_DNS_LYREBIRD_SHA256")),
        ("snowflake",      env!("COFFEEBLACK_DNS_SNOWFLAKE_VERSION"),      env!("COFFEEBLACK_DNS_SNOWFLAKE_SHA256")),
        ("webtunnel",      env!("COFFEEBLACK_DNS_WEBTUNNEL_VERSION"),      env!("COFFEEBLACK_DNS_WEBTUNNEL_SHA256")),
    ]
}

/// True when the build embedded all five DNS-bundle binaries for the
/// current architecture. False on partial bundles or unsupported arches.
/// Cheap enough to call from a request handler — it's a `const`-eval
/// path that the optimiser folds.
#[inline]
pub const fn is_bundled() -> bool {
    cfg!(dns_bundled)
}

/// Why the DNS bundle is absent, as build.rs saw it — e.g.
/// `"LYREBIRD (vendor blob …/lyrebird-linux-amd64.gz missing)"`. Empty
/// exactly when [`is_bundled`] is true.
///
/// The pins in `vendor/DNS_BUNDLE_VERSION` are only half the gate: the
/// `.gz` blobs are CI artifacts and aren't in git, so a fully-pinned
/// tree still builds unbundled until `scripts/build.sh` materialises
/// them. Without this, "bundle off" and "pin file broken" look
/// identical from inside the binary.
#[inline]
pub const fn bundle_incomplete_reason() -> &'static str {
    env!("COFFEEBLACK_DNS_BUNDLE_INCOMPLETE")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_versions_exposes_all_five_binaries() {
        // Stable contract for /about and admin-UI rendering: always five
        // entries, in a stable order, regardless of bundle state. When
        // the bundle is absent the version + sha strings are blank.
        let versions = embedded_versions();
        assert_eq!(versions.len(), 5);
        let names: Vec<&str> = versions.iter().map(|(n, _, _)| *n).collect();
        assert_eq!(
            names,
            ["dnscrypt-proxy", "tor", "lyrebird", "snowflake", "webtunnel"]
        );
    }

    #[test]
    fn version_and_sha_consistency_per_binary() {
        // Either both blank (bundle absent for this binary) or both
        // populated (bundle present). A version with no SHA — or vice
        // versa — would mean build.rs let through a partial pin, which
        // should be impossible given the all-or-nothing dns_bundled gate.
        for (name, version, sha) in embedded_versions() {
            assert_eq!(
                version.is_empty(),
                sha.is_empty(),
                "{name}: version and sha must be both blank or both populated \
                 (version={version:?}, sha={sha:?})"
            );
            if !sha.is_empty() {
                assert_eq!(sha.len(), 64, "{name} sha must be 64 hex chars");
                assert!(
                    sha.chars().all(|c| c.is_ascii_hexdigit()),
                    "{name} sha must be lowercase hex"
                );
            }
        }
    }

    #[test]
    fn is_bundled_matches_per_binary_pin_state() {
        // `dns_bundled` needs both halves: every binary pinned *and* its
        // blob on disk. The blobs are CI artifacts (vendor/*.gz is
        // untracked, materialised by scripts/build.sh), so a pinned-but
        // -blobless tree — the normal state of a fresh clone — must come
        // out unbundled. build.rs reports which half is missing.
        let any_blank = embedded_versions().iter().any(|(_, v, _)| v.is_empty());
        let incomplete = bundle_incomplete_reason();
        if any_blank || !incomplete.is_empty() {
            assert!(
                !is_bundled(),
                "is_bundled() true though the build reported: {incomplete}"
            );
        } else {
            assert!(is_bundled(), "is_bundled() false despite a complete bundle");
        }
    }

    #[test]
    fn incomplete_reason_is_blank_exactly_when_bundled() {
        assert_eq!(
            bundle_incomplete_reason().is_empty(),
            is_bundled(),
            "the reason string and the cfg must not disagree"
        );
    }
}
