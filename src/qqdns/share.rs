//! Generate the matching **client** `config.json` from the server's settings.
//!
//! The tunnel is symmetric with the domains swapped: the client sends to the
//! server's `recv_domains` and receives on the server's `send_domains`. The
//! produced document uses the upstream QQ-Tunnel `config.json` field names, so
//! it drives both the standalone `amnezia-client` and the reference Python
//! client unchanged. Client-only fields the server can't know (the client's
//! own resolvers, bind IPs, and local WireGuard endpoint) are emitted as
//! sensible placeholders for the operator to fill in.

use serde_json::{json, Value};

use crate::db::QqdnsSettings;

fn parse_list(s: &str) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(s).unwrap_or_default()
}

/// Build the client `config.json` (as a `serde_json::Value`).
///
/// `client_wg_endpoint` is where the client-side WireGuard/Amnezia app will
/// point its `Endpoint` (the address the client engine binds as `h_in`);
/// defaults to `127.0.0.1:51820` when `None`.
pub fn client_config(settings: &QqdnsSettings, client_wg_endpoint: Option<&str>) -> Value {
    let h_in = client_wg_endpoint.unwrap_or("127.0.0.1:51820");
    json!({
        // Client fills these with resolvers reachable from its own vantage
        // point (they differ from the server's list).
        "dns_ips": [],
        // Client's own bind IPs — usually its public/NAT IP. Left blank so the
        // operator sets them; the engine treats "" as 0.0.0.0.
        "send_interface_ip": "",
        "receive_interface_ip": "",
        "receive_port": 53,
        // Domain swap: send where the server receives, receive where it sends.
        "send_domains": parse_list(&settings.recv_domains),
        "recv_domains": parse_list(&settings.send_domains),
        // Local WireGuard endpoint the client app targets. Client role, so
        // h_out_address is empty (learned from the first sender).
        "h_in_address": h_in,
        "h_out_address": "",
        // Wire-shape params must match the server exactly.
        "max_domain_len": settings.max_domain_len,
        "max_sub_len": settings.max_sub_len,
        "retries": settings.retries,
        "send_query_type_int": settings.send_query_type,
        "packets_send_interval": (settings.packets_send_interval_ms as f64) / 1000.0,
        "packets_wait_time_limit": (settings.packets_wait_time_limit_ms as f64) / 1000.0,
        "send_sock_numbers": settings.send_sock_numbers,
    })
}

/// Human-readable setup guidance: the DNS records the operator must create
/// and the coupling constraints, rendered from the current settings.
pub fn setup_notes(settings: &QqdnsSettings) -> Vec<String> {
    let recv = parse_list(&settings.recv_domains);
    let send = parse_list(&settings.send_domains);
    let mut notes = Vec::new();
    notes.push(
        "This transport is a symmetric server↔client-relay DNS tunnel. Both ends must be \
         authoritative for their own delegated subdomain (an NS delegation to a public IP)."
            .to_string(),
    );
    if let Some(d) = recv.first() {
        notes.push(format!(
            "Server side: delegate '{d}' to THIS server's public IP \
             (A record for the delegated host + an NS record pointing the tunnel subdomain at it)."
        ));
    }
    if let Some(d) = send.first() {
        notes.push(format!(
            "Client side: '{d}' must be delegated to the CLIENT relay's public IP."
        ));
    }
    notes.push(format!(
        "max_domain_len={} must be the lowest value ALL listed resolvers tolerate; \
         both ends must agree on it and on max_sub_len={}.",
        settings.max_domain_len, settings.max_sub_len
    ));
    notes.push(
        "One instance carries ONE client endpoint (the wire format has no client id). \
         For multiple clients, run multiple instances with distinct domains + h_in ports."
            .to_string(),
    );
    if settings.receive_port != 53 {
        notes.push(format!(
            "receive_port is {} — add a PREROUTING redirect from udp/53 so resolvers reach it, e.g. \
             `iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port {}`.",
            settings.receive_port, settings.receive_port
        ));
    }
    notes
}
