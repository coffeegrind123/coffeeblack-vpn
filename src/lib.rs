//! coffeeblack-vpn — Standalone AmneziaWG VPN manager with Web UI.
//!
//! This library crate exposes all modules for both the binary and integration
//! tests.

// `serde_json::json!` expands one macro level per key, so the client
// serialisation in `api::clients` (~40 keys, and it grows with every peer
// attribute the UI learns to show) overruns the default 128-deep limit. This
// is the fix rustc itself suggests for the case; it bounds nothing at
// runtime and costs only compile-time recursion headroom.
#![recursion_limit = "256"]

pub mod activity;
pub mod api;
pub mod auth;
pub mod cidr;
pub mod config;
pub mod crypto;
pub mod datetime;
pub mod db;
pub mod dns;
pub mod encoding;
pub mod firewall;
pub mod http;
pub mod inflate;
pub mod init_setup;
pub mod log;
pub mod memexec;
pub mod mdnsvpn;
pub mod mtproxy;
pub mod privhelper;
pub mod proc;
pub mod proxy;
pub mod qqdns;
pub mod qr;
pub mod rng;
pub mod secretfile;
pub mod wg;
pub mod xray;
