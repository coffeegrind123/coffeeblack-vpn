//! REST endpoints for the in-process DPI-imitation proxy.
//!
//! | Method | Path                          | Auth  | Purpose                                   |
//! |--------|-------------------------------|-------|-------------------------------------------|
//! | GET    | /api/admin/proxy/settings     | admin | Read singleton proxy_settings row + info  |
//! | POST   | /api/admin/proxy/settings     | admin | Update settings + rebind AWG + reconcile  |
//! | GET    | /api/admin/proxy/status       | admin | Supervisor status snapshot                |
//! | POST   | /api/admin/proxy/restart      | admin | Force teardown + rebind + re-bind proxy   |
//!
//! Every POST writes the DB first, then calls
//! `proxy::supervisor::apply_and_reconcile`, which re-renders the
//! AmneziaWG config onto the correct ListenPort (loopback backend when the
//! proxy is on, public when off), restarts the interface, reapplies the
//! backend firewall lockdown, and (re)binds the proxy task.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use serde_json::{json, Value};

use super::admin::require_admin;
use super::{map_err, ok_success, value_to_string, AppState};
use crate::db;

const VALID_PROTOCOLS: &[&str] = &["quic", "dns", "stun", "sip", "auto"];

// ---------------------------------------------------------------------------
// GET /api/admin/proxy/settings
// ---------------------------------------------------------------------------

pub async fn get_settings(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    let s = db::get_proxy_settings().map_err(map_err)?;
    // Resolve the effective backend port so the UI can show what AmneziaWG
    // will actually listen on ("auto → 51821"), not just the stored `0`.
    let effective_backend = db::get_interface()
        .map(|i| crate::proxy::supervisor::effective_backend_port(&s, i.port))
        .ok();
    let public_port = db::get_interface().map(|i| i.port).ok();
    Ok(Json(json!({
        "id": s.id,
        "enabled": s.enabled,
        "protocol": s.protocol,
        "backendPort": s.backend_port,
        "effectiveBackendPort": effective_backend,
        "publicPort": public_port,
        "quicHandshake": s.quic_handshake,
        "quicCertDomain": s.quic_cert_domain,
        "dnsForward": s.dns_forward,
        "dnsUpstream": s.dns_upstream,
        "additionalConfig": s.additional_config,
        "maxSessions": s.max_sessions,
        "sessionTtl": s.session_ttl,
        "protocols": VALID_PROTOCOLS,
    })))
}

// ---------------------------------------------------------------------------
// POST /api/admin/proxy/settings
// ---------------------------------------------------------------------------

pub async fn update_settings(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;

    let mut fields = db::UpdateMap::new();
    if let Value::Object(map) = &body {
        let scalars: &[(&str, &str)] = &[
            ("enabled", "enabled"),
            ("protocol", "protocol"),
            ("backendPort", "backend_port"),
            ("quicHandshake", "quic_handshake"),
            ("quicCertDomain", "quic_cert_domain"),
            ("dnsForward", "dns_forward"),
            ("dnsUpstream", "dns_upstream"),
            ("additionalConfig", "additional_config"),
            ("maxSessions", "max_sessions"),
            ("sessionTtl", "session_ttl"),
        ];
        for (json_key, db_key) in scalars {
            if let Some(val) = map.get(*json_key) {
                if let Some(s) = value_to_string(val) {
                    fields.insert(db_key.to_string(), s);
                }
            }
        }

        // Server-side validation so the operator gets a clean 4xx instead
        // of a Status::Crashed bubble later.
        if let Some(proto) = fields.get("protocol") {
            if !VALID_PROTOCOLS.contains(&proto.as_str()) {
                return Err(bad_request(format!(
                    "protocol must be one of {}, got {proto:?}",
                    VALID_PROTOCOLS.join("|")
                )));
            }
        }
        if let Some(bp) = fields.get("backend_port") {
            if let Ok(n) = bp.parse::<i64>() {
                if n != 0 && !(1..=65535).contains(&n) {
                    return Err(bad_request(format!(
                        "backendPort must be 0 (auto) or 1..=65535, got {n}"
                    )));
                }
                // Reject a backend that collides with the public port up
                // front (the supervisor would refuse to start otherwise).
                if n != 0 {
                    if let Ok(iface) = db::get_interface() {
                        if n == iface.port {
                            return Err(bad_request(format!(
                                "backendPort {n} collides with the public port {}",
                                iface.port
                            )));
                        }
                    }
                }
            } else {
                return Err(bad_request("backendPort must be an integer".into()));
            }
        }
        // Session caps — bound the spoofed-source fd/exhaustion blast radius.
        if let Some(v) = fields.get("max_sessions") {
            match v.parse::<i64>() {
                Ok(n) if (16..=65536).contains(&n) => {}
                _ => return Err(bad_request("maxSessions must be 16..=65536".into())),
            }
        }
        if let Some(v) = fields.get("session_ttl") {
            match v.parse::<i64>() {
                Ok(n) if (15..=3600).contains(&n) => {}
                _ => return Err(bad_request("sessionTtl must be 15..=3600 seconds".into())),
            }
        }
        // dns_upstream must be host:port when set.
        if let Some(up) = fields.get("dns_upstream") {
            let up = up.trim();
            if !up.is_empty() && up.parse::<std::net::SocketAddr>().is_err() {
                return Err(bad_request(format!(
                    "dnsUpstream must be host:port (e.g. 1.1.1.1:53), got {up:?}"
                )));
            }
            // Unauthenticated internet users drive traffic to whatever this
            // points at, so an internal address would make the proxy a relay
            // into the private network. Mirrors the vetting the Xray dest
            // probe already applies in `xray::probe::resolve_vetted_addr`.
            if let Ok(addr) = up.parse::<std::net::SocketAddr>() {
                if is_forbidden_upstream_ip(&addr.ip()) {
                    return Err(bad_request(format!(
                        "dnsUpstream must be a public resolver; loopback, private, \
                         link-local, multicast and unspecified addresses are refused, got {up:?}"
                    )));
                }
            }
        }
        // A QUIC cert domain is required whenever the handshake responder
        // is on with quic/auto — validate the effective combination.
        let effective = |key: &str, fallback: bool| -> bool {
            fields
                .get(key)
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(fallback)
        };
        if let Some(domain) = fields.get("quic_cert_domain") {
            let dom = domain.trim();
            if !dom.is_empty()
                && (dom.contains(' ') || dom.contains('\t') || dom.starts_with('.') || dom.ends_with('.'))
            {
                return Err(bad_request(format!(
                    "quicCertDomain {dom:?} doesn't look like a hostname"
                )));
            }
        }
        // Only enforce the "cert domain required" rule when the incoming
        // change would leave handshake on + quic/auto + empty domain.
        {
            let cur = db::get_proxy_settings().ok();
            let handshake_on = effective(
                "quic_handshake",
                cur.as_ref().map(|c| c.quic_handshake).unwrap_or(true),
            );
            let proto = fields
                .get("protocol")
                .cloned()
                .or_else(|| cur.as_ref().map(|c| c.protocol.clone()))
                .unwrap_or_default();
            let domain = fields
                .get("quic_cert_domain")
                .cloned()
                .or_else(|| cur.as_ref().map(|c| c.quic_cert_domain.clone()))
                .unwrap_or_default();
            if handshake_on
                && matches!(proto.as_str(), "quic" | "auto")
                && domain.trim().is_empty()
            {
                return Err(bad_request(
                    "quicCertDomain is required when the QUIC handshake responder is enabled".into(),
                ));
            }
        }
    }

    if !fields.is_empty() {
        db::update_proxy_settings(&fields).map_err(map_err)?;
    }

    // Rebind AmneziaWG + firewall + proxy task to the new desired state.
    // Non-fatal — the admin gets a 200 and the status endpoint surfaces
    // any reason the proxy declined to come up.
    if let Err(e) = crate::proxy::supervisor::apply_and_reconcile().await {
        tracing::warn!(error = ?e, "proxy reconcile failed after admin update");
    }

    Ok(ok_success())
}

// ---------------------------------------------------------------------------
// GET /api/admin/proxy/status
// ---------------------------------------------------------------------------

pub async fn supervisor_status(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    let s = crate::proxy::supervisor::status().await;
    Ok(Json(
        serde_json::to_value(s).unwrap_or_else(|_| json!({"state": "unknown"})),
    ))
}

// ---------------------------------------------------------------------------
// POST /api/admin/proxy/restart
// ---------------------------------------------------------------------------

pub async fn restart(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    if let Err(e) = crate::proxy::supervisor::apply_and_reconcile().await {
        return Err(map_err(e));
    }
    Ok(ok_success())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn bad_request(msg: String) -> (StatusCode, Json<Value>) {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": msg })))
}

/// True when `ip` is one the DNS forwarder must never be pointed at.
///
/// The forwarder relays datagrams from unauthenticated internet clients, so a
/// non-public upstream turns the proxy into a path into the private network.
fn is_forbidden_upstream_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_unspecified()
                || v4.octets()[0] == 0
                // 100.64.0.0/10 carrier-grade NAT
                || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]))
        }
        std::net::IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_forbidden_upstream_ip(&std::net::IpAddr::V4(mapped));
            }
            v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unspecified()
                // fc00::/7 unique-local, fe80::/10 link-local
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

#[cfg(test)]
mod upstream_vetting_tests {
    use super::is_forbidden_upstream_ip;
    use std::net::IpAddr;

    #[test]
    fn refuses_internal_destinations() {
        for bad in [
            "127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1",
            "169.254.169.254", "0.0.0.0", "224.0.0.1", "100.64.0.1",
            "::1", "fe80::1", "fd00::1", "::", "::ffff:127.0.0.1",
        ] {
            let ip: IpAddr = bad.parse().unwrap();
            assert!(is_forbidden_upstream_ip(&ip), "should refuse {bad}");
        }
    }

    #[test]
    fn allows_real_public_resolvers() {
        for ok in ["1.1.1.1", "8.8.8.8", "9.9.9.9", "2606:4700:4700::1111"] {
            let ip: IpAddr = ok.parse().unwrap();
            assert!(!is_forbidden_upstream_ip(&ip), "should allow {ok}");
        }
    }
}
