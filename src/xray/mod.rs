//! Browsing-mode (Xray VLESS+Reality+Vision) support.
//!
//! coffeeblack-vpn ships a pinned Xray-core ELF (vendored at build time, see
//! `vendor/`) and supervises it as a tokio child process. The Rust process
//! never speaks the Reality/Vision wire protocol itself — this module is a
//! thin orchestration layer:
//!
//! * `runtime`   — extract the bundled ELF to disk on first use.
//! * `keys`      — call the extracted `xray` binary for `uuid` / `x25519`.
//! * `config_gen`— assemble `server.json` from the DB.
//! * `share`     — build `vless://` URLs and the amnezia-client JSON template.
//! * `supervisor`— own the Xray child process, reload on config changes.

#[cfg(xray_bundled)]
pub mod runtime;

pub mod config_gen;
pub mod keys;
pub mod probe;
pub mod share;

#[cfg(xray_bundled)]
pub mod supervisor;
