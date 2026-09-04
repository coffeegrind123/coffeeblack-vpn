//! MasterDnsVPN (DNS-tunnel VPN) support — bundled
//! [masterking32/MasterDnsVPN](https://github.com/masterking32/MasterDnsVPN)
//! Go server, supervised as a tokio child process.
//!
//! MasterDnsVPN is a Go DNS-tunnel VPN: clients fragment + encrypt TCP /
//! SOCKS5 traffic into DNS queries that traverse public resolvers, and the
//! server listens on a UDP port (default 53) for tunnel envelopes whose
//! QNAMEs match one of the configured tunnel domains. The server then
//! decrypts, reassembles, and forwards the inner TCP either directly (acting
//! as a SOCKS5 proxy) or to a fixed upstream (`PROTOCOL_TYPE = TCP`).
//!
//! coffeeblack-vpn ships a pinned static ELF (vendored at build time, see
//! `vendor/`) and supervises it the same way Xray and telemt are
//! supervised — Rust never speaks the DNS-tunnel wire protocol itself.
//!
//! ## Module split
//!
//! * `runtime`    — extract the bundled ELF onto disk on first use.
//!   Mirror of `src/xray/runtime.rs` / `src/mtproxy/runtime.rs`.
//! * `config`     — assemble `server_config.toml` from the singleton DB row.
//! * `share`      — generate per-client `client_config.toml`, resolver
//!   list, JSON, and base64 share blobs.
//! * `bundle`     — pack those artifacts into a `bundle.zip` a peer can run.
//!   Exists because a peer needs *two* files: mdnsvpn reads the resolver list
//!   only from `client_resolvers.txt`, and a missing one is fatal.
//! * `keys`       — generate / validate the shared encryption key.
//! * `logscrub`   — strip the shared secret out of the child's log stream
//!   before it reaches `tracing` (the pinned upstream binary prints the raw
//!   key at INFO on every start).
//! * `supervisor` — own the mdnsvpn child process. No HTTP control plane
//!   to reconcile (mdnsvpn has no live API for users — every client
//!   shares the singleton encryption key, so changing the user roster
//!   is purely coffeeblack-vpn DB bookkeeping).
//!
//! ## Default posture
//!
//! Even with `cfg(mdnsvpn_bundled)` set, mdnsvpn does **not** start
//! automatically. The operator opts in via the admin UI after:
//!
//!   1. Owning a real domain and creating an `NS` delegation that points
//!      the tunnel subdomain at this server's public IP.
//!   2. Generating an encryption key (the **Generate** button calls
//!      `regenerate-key` on the inbound).
//!   3. Setting `domains = […]`, `port`, and any other site-specific
//!      knobs.
//!   4. Flipping `enabled = true`.
//!
//! This matches the Xray, telemt, and DNS-bundle defaults — every
//! censorship-circumvention transport is opt-in, never on by default.
//!
//! ## User store of record
//!
//! `mdnsvpn_clients_table` is the durable source of truth for the
//! client list — but unlike telemt, coffeeblack-vpn has no API to
//! reconcile this into the mdnsvpn process. mdnsvpn doesn't track
//! per-user secrets; the singleton `encryption_key` authenticates every
//! tunnel. Per-client rows are pure UX state (share-link slot, expiry,
//! enabled toggle).

pub mod bundle;
pub mod config;
pub mod keys;
pub mod logscrub;
pub mod share;

#[cfg(mdnsvpn_bundled)]
pub mod runtime;
#[cfg(mdnsvpn_bundled)]
pub mod supervisor;

/// Embedded MasterDnsVPN release tag, surfaced via `vendor/MDNSVPN_VERSION`.
/// Always populated (even on un-bundled builds) so `/about` and the admin
/// UI can show what would have shipped.
pub const MDNSVPN_VERSION: &str = env!("COFFEEBLACK_MDNSVPN_VERSION");

/// SHA-256 of the *uncompressed* MasterDnsVPN ELF, surfaced via
/// `vendor/MDNSVPN_VERSION`. Blank on un-bundled targets.
pub const MDNSVPN_SHA256: &str = env!("COFFEEBLACK_MDNSVPN_SHA256");

/// True when the build embedded the mdnsvpn ELF for the current
/// architecture. False on unsupported targets — the admin UI uses this
/// to grey out the DNS-tunnel panel.
#[inline]
pub const fn is_bundled() -> bool {
    cfg!(mdnsvpn_bundled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_and_sha_consistency() {
        // Either both blank (bundle absent) or both populated. A version
        // with no SHA — or vice versa — would mean build.rs let a partial
        // pin through.
        assert_eq!(
            MDNSVPN_VERSION.is_empty(),
            MDNSVPN_SHA256.is_empty(),
            "MDNSVPN_VERSION ({MDNSVPN_VERSION:?}) and MDNSVPN_SHA256 ({MDNSVPN_SHA256:?}) \
             must be both blank or both populated"
        );
        if !MDNSVPN_SHA256.is_empty() {
            assert_eq!(
                MDNSVPN_SHA256.len(),
                64,
                "mdnsvpn SHA must be 64 hex chars"
            );
            assert!(
                MDNSVPN_SHA256.chars().all(|c| c.is_ascii_hexdigit()),
                "mdnsvpn SHA must be lowercase hex"
            );
        }
    }

    #[test]
    fn is_bundled_matches_pin_state() {
        if MDNSVPN_SHA256.is_empty() {
            assert!(!is_bundled(), "is_bundled() true but no SHA pinned");
        } else {
            assert!(
                is_bundled(),
                "is_bundled() false despite a SHA being pinned"
            );
        }
    }
}
