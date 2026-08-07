//! QQ-Tunnel UDP-over-DNS transport — server side, in-process.
//!
//! A faithful Rust port of [patterniha/QQ-Tunnel](https://github.com/patterniha/QQ-Tunnel):
//! a transport-agnostic forwarder that carries a raw UDP datapath (here, the
//! AmneziaWG datapath itself) inside the QNAMEs of DNS queries, so the tunnel
//! survives an egress blackout where only port 53 escapes.
//!
//! Unlike MasterDnsVPN (which tunnels TCP/SOCKS5), this carries **UDP**, so it
//! can wrap the native low-latency AmneziaWG port — "AmneziaWG-over-DNS",
//! positioned strictly as a blackout-survival fallback, not a low-latency
//! path (base32 + fragmentation + retries multiply overhead).
//!
//! The engine is fully symmetric: both ends run the same duplex loop and both
//! act as an authoritative DNS server for their NS-delegated subdomain. This
//! module hosts the **server** role in-process (mirroring `src/proxy/`'s
//! in-process-Tokio-task model, not the vendored-blob model of
//! `src/mdnsvpn/`). The matching client is a standalone crate; the wire codec
//! ([`codec`], [`dns`], [`reassembly`]) is shared verbatim so the two
//! interoperate on the wire.

pub mod codec;
pub mod config;
pub mod dns;
pub mod engine;
pub mod reassembly;
pub mod share;
pub mod supervisor;
