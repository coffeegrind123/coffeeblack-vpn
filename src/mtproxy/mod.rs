//! Telegram MTProxy support — bundled `telemt` (Rust + Tokio MTProto
//! proxy) supervised as a tokio child process.
//!
//! Telemt is upstream's Rust implementation of Telegram's MTProxy
//! protocol with full Fake-TLS / SNI fronting (the `secret=ee<…>` link
//! variant), per-user 32-hex secrets, replay protection, and traffic
//! masking. Coffeeblack-vpn ships a pinned static-musl ELF (vendored at
//! build time, see `vendor/`) and supervises it the same way Xray is
//! supervised — Rust never speaks the MTProto wire protocol itself.
//!
//! ## Module split
//!
//! * `runtime`    — extract the bundled ELF onto disk on first use.
//!   Mirror of `src/xray/runtime.rs`.
//! * `config`     — assemble `config.toml` from the singleton DB row.
//! * `client`     — minimal HTTP/1.1 client targeting telemt's
//!   `127.0.0.1:9091` control plane (`/v1/users`, `/v1/health`,
//!   `/v1/stats/*`). User CRUD goes through this rather than through
//!   `[access.users]` so the supervisor doesn't have to rewrite
//!   `config.toml` on every roster change.
//! * `supervisor` — own the telemt child process, reconcile users from
//!   `mtproxy_users_table` into the live process on every successful
//!   spawn.
//!
//! ## Default posture
//!
//! Even with `cfg(telemt_bundled)` set, telemt does **not** start
//! automatically. The operator opts in via the admin UI (sets a
//! `tls_domain`, picks a port, flips `enabled = true`). This matches
//! the Xray and DNS-bundle defaults.
//!
//! ## User store of record
//!
//! `mtproxy_users_table` is the durable source of truth for the user
//! roster. The supervisor reconciles the table into telemt via
//! `POST /v1/users` after every spawn — this means a telemt state-file
//! wipe doesn't lose the operator's users, and the admin UI doesn't
//! have to care whether telemt has its own persistence or not.

pub mod client;
pub mod config;
#[cfg(telemt_bundled)]
pub mod runtime;
#[cfg(telemt_bundled)]
pub mod supervisor;

/// Embedded telemt release tag, surfaced via `vendor/TELEMT_VERSION`.
/// Always populated (even on un-bundled builds) so `/about` /
/// `/api/admin/mtproxy/inbound` can show what would have shipped.
pub const TELEMT_VERSION: &str = env!("COFFEEBLACK_TELEMT_VERSION");

/// SHA-256 of the *uncompressed* telemt ELF, surfaced via
/// `vendor/TELEMT_VERSION`. Blank on un-bundled targets.
pub const TELEMT_SHA256: &str = env!("COFFEEBLACK_TELEMT_SHA256");

/// True when the build embedded the telemt ELF for the current
/// architecture. False on unsupported targets — the admin UI uses this
/// to grey out the panel.
#[inline]
pub const fn is_bundled() -> bool {
    cfg!(telemt_bundled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_and_sha_consistency() {
        // Either both blank (bundle absent) or both populated. A
        // version with no SHA — or vice versa — would mean build.rs let
        // a partial pin through.
        assert_eq!(
            TELEMT_VERSION.is_empty(),
            TELEMT_SHA256.is_empty(),
            "TELEMT_VERSION ({TELEMT_VERSION:?}) and TELEMT_SHA256 ({TELEMT_SHA256:?}) \
             must be both blank or both populated"
        );
        if !TELEMT_SHA256.is_empty() {
            assert_eq!(TELEMT_SHA256.len(), 64, "telemt SHA must be 64 hex chars");
            assert!(
                TELEMT_SHA256.chars().all(|c| c.is_ascii_hexdigit()),
                "telemt SHA must be lowercase hex"
            );
        }
    }

    #[test]
    fn is_bundled_matches_pin_state() {
        if TELEMT_SHA256.is_empty() {
            assert!(!is_bundled(), "is_bundled() true but no SHA pinned");
        } else {
            assert!(is_bundled(), "is_bundled() false despite a SHA being pinned");
        }
    }
}
