//! TrustTunnel support — the bundled
//! [TrustTunnel/TrustTunnel](https://github.com/TrustTunnel/TrustTunnel)
//! endpoint (AdGuard, Apache-2.0), supervised as a tokio child process.
//!
//! TrustTunnel tunnels a device's TCP, UDP and ICMP through HTTP/2 or HTTP/3
//! (QUIC) `CONNECT` streams over TLS. To a passive observer the session is
//! HTTPS to `hostname`; to an active prober without credentials it is a web
//! server answering 407 (or 404/403, configurable), optionally fronting a
//! real cover site. It is an L4 proxy, not a TUN VPN: the endpoint opens
//! ordinary outbound sockets, so there is no NAT, no TUN device and no
//! firewall rule to manage — only the listen port, on TCP *and* UDP.
//!
//! coffeeblack-vpn ships the pinned upstream static-musl ELF (see `vendor/`)
//! and never speaks the protocol itself.
//!
//! ## Module split
//!
//! * `runtime`    — extract the bundled ELF (memfd when `IN_MEMORY`).
//! * `config`     — render `vpn.toml` / `hosts.toml` / `credentials.toml` /
//!   `rules.toml` from the DB rows.
//! * `cert`       — self-signed issuance, PEM, operator-cert validation.
//! * `deeplink`   — the `tt://` link encoder.
//! * `share`      — per-user link and client-config TOML.
//! * `keys`       — password / username / client-random-prefix generation.
//! * `stats`      — RAM-only per-user traffic from the endpoint's metrics.
//! * `supervisor` — own the child; every roster change is a restart because
//!   the endpoint reads credentials only at startup.
//!
//! ## Default posture
//!
//! Off until the operator enables it. Even then the supervisor waits for a
//! TLS hostname (the General tab host when it is a DNS name, else an explicit
//! one) and at least one active user, because upstream refuses to listen on
//! a public address with an empty credentials list.

pub mod cert;
pub mod config;
pub mod deeplink;
pub mod keys;
pub mod share;
pub mod stats;

#[cfg(trusttunnel_bundled)]
pub mod runtime;
#[cfg(trusttunnel_bundled)]
pub mod supervisor;

/// Embedded TrustTunnel release tag, from `vendor/TRUSTTUNNEL_VERSION`.
/// Always populated (even on un-bundled builds) so the admin UI can show
/// what would have shipped.
pub const TRUSTTUNNEL_VERSION: &str = env!("COFFEEBLACK_TRUSTTUNNEL_VERSION");

/// SHA-256 of the *uncompressed* endpoint ELF. Blank on un-bundled targets.
pub const TRUSTTUNNEL_SHA256: &str = env!("COFFEEBLACK_TRUSTTUNNEL_SHA256");

/// True when the build embedded the endpoint ELF for this architecture.
#[inline]
pub const fn is_bundled() -> bool {
    cfg!(trusttunnel_bundled)
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
            TRUSTTUNNEL_VERSION.is_empty(),
            TRUSTTUNNEL_SHA256.is_empty(),
            "TRUSTTUNNEL_VERSION ({TRUSTTUNNEL_VERSION:?}) and TRUSTTUNNEL_SHA256 ({TRUSTTUNNEL_SHA256:?}) \
             must be both blank or both populated"
        );
        if !TRUSTTUNNEL_SHA256.is_empty() {
            assert_eq!(
                TRUSTTUNNEL_SHA256.len(),
                64,
                "trusttunnel SHA must be 64 hex chars"
            );
            assert!(
                TRUSTTUNNEL_SHA256.chars().all(|c| c.is_ascii_hexdigit()),
                "trusttunnel SHA must be lowercase hex"
            );
        }
    }

    #[test]
    fn is_bundled_matches_pin_state() {
        if TRUSTTUNNEL_SHA256.is_empty() {
            assert!(!is_bundled(), "is_bundled() true but no SHA pinned");
        } else {
            assert!(
                is_bundled(),
                "is_bundled() false despite a SHA being pinned"
            );
        }
    }
}
