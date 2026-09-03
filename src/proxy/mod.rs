//! In-process DPI-imitation proxy for the AmneziaWG UDP port.
//!
//! Ported in-process from [`wiresock/amneziawg-proxy`]. An async UDP proxy
//! that binds the interface's public port, forwards decrypted-looking
//! datagrams to AmneziaWG on a loopback backend port, and rewrites each
//! outbound packet's AmneziaWG S1–S4 padding prefix so the datagram looks
//! like a real **QUIC / DNS / STUN / SIP** service to Deep Packet
//! Inspection — while also answering active protocol probes with valid
//! responses (QUIC Version Negotiation / a full TLS 1.3 handshake, DNS
//! SERVFAIL or a forwarded answer, STUN Binding Success, a stateful SIP
//! dialog).
//!
//! Unlike Xray / MTProxy / MasterDnsVPN (which are *separate transports*
//! on their own ports), this proxy keeps clients on the native AmneziaWG
//! datapath and hardens *that* port against DPI. It runs as a supervised
//! Tokio task — no subprocess, no vendored blob — reading its S/H
//! obfuscation parameters straight from the `interfaces_table` row and its
//! settings from `proxy_settings_table`.
//!
//! The port modules below are near-verbatim from the upstream crate (only
//! the `crate::` paths were rehomed under `crate::proxy::`); the
//! awg-easy-rs-specific glue lives in [`supervisor`].
//!
//! The ported files are kept a faithful mirror of upstream so they can be
//! re-synced, so the handful of stylistic clippy lints they trip (all of
//! which upstream's own config tolerated) are allowed here at the module
//! root rather than by rewriting vendored code. These cascade to every
//! `src/proxy/*.rs` submodule. `supervisor` (our own code) sits under the
//! same allow but trips none of them.
#![allow(clippy::module_inception)] // proxy::proxy — the upstream module name
#![allow(clippy::too_many_arguments)] // Proxy::bind-time plumbing
#![allow(clippy::doc_lazy_continuation)] // upstream rustdoc list formatting
#![allow(clippy::unnecessary_map_or)] // predates Option::is_none_or MSRV bump
#![allow(clippy::manual_is_multiple_of)] // predates u32::is_multiple_of
#![allow(clippy::manual_repeat_n)] // upstream test helpers predate iter::repeat_n
#![allow(clippy::needless_range_loop)] // upstream test packet builders index by offset

pub mod backend;
pub mod config;
pub mod errors;
pub mod metrics;
pub mod proxy;
pub mod quic_handshake;
pub mod responder;
pub mod session;
pub mod supervisor;
pub mod transform;
