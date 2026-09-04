//! Miscellaneous routes (one-time links, metrics, info).
//!
//! | Method | Route                | Description               |
//! |--------|----------------------|---------------------------|
//! | GET    | /cnf/:oneTimeLink     | Client config via token   |
//! | GET    | /metrics/json         | JSON traffic metrics      |
//! | GET    | /metrics/prometheus   | Prometheus text metrics   |
//! | GET    | /api/information      | Version/release info      |
//! | GET    | /api/interface        | Interface public info     |

use crate::http::Path;
use crate::http::{header, HeaderMap, StatusCode};
use crate::http::IntoResponse;
use crate::http::Json;
use serde_json::{json, Value};

use super::{api_err, map_err, no_store_headers};
use crate::{auth, db, wg};

/// Escape a string for use inside a Prometheus label value (`name="…"`).
/// Per the exposition format the backslash, double-quote, and newline are the
/// only characters requiring escaping — and getting this wrong is a metric
/// **injection**: the client `name` is attacker-set (any authenticated user
/// can create a client), so an un-escaped `\n` or `"` would let a crafted name
/// forge additional metric lines on the (optionally public) `/metrics` output.
fn escape_prometheus_label(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

/// Constant-time string equality for short tokens.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Validate the incoming Authorization header against the stored metrics
/// password. The password is stored hashed (sha-256 hex) — see `update_general`.
fn check_metrics_password(headers: &HeaderMap, stored_hash: &str) -> bool {
    // Fail closed. This used to return `true` for an empty stored hash, so a
    // deployment whose metrics password was cleared served the full peer
    // roster — names, transfer counters, last handshake, and in the JSON
    // variant each peer's current remote endpoint IP — to anyone who asked.
    // Correctness relied on an unrelated handler never writing that state.
    if stored_hash.is_empty() {
        return false;
    }
    let auth = match headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        Some(s) => s,
        None => return false,
    };
    let token = if let Some(rest) = auth.strip_prefix("Bearer ") {
        rest.trim().to_string()
    } else {
        return false;
    };
    let supplied_hash = auth::sha256(&token);
    constant_time_eq(supplied_hash.as_bytes(), stored_hash.as_bytes())
}

// ---------------------------------------------------------------------------
// GET /api/information
// ---------------------------------------------------------------------------

pub async fn information() -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let version = env!("CARGO_PKG_VERSION");
    let iface = db::get_interface().map_err(map_err)?;
    let setup_step = db::get_setup_step().unwrap_or(0);
    let user_count = db::get_user_count().unwrap_or(0);

    Ok(Json(json!({
        "currentRelease": version,
        "defaultConfig": iface.ipv4_cidr,
        "latestRelease": null,
        "setupNeeded": setup_step != 0 || user_count == 0,
        "isAwg": true,
        "firewallEnabled": iface.firewall_enabled,
    })))
}

// ---------------------------------------------------------------------------
// GET /api/interface
// ---------------------------------------------------------------------------

pub async fn interface_info() -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let iface = db::get_interface().map_err(map_err)?;

    Ok(Json(json!({
        "isAwg": true,
        "firewallEnabled": iface.firewall_enabled,
    })))
}

// ---------------------------------------------------------------------------
// GET /cnf/:oneTimeLink — one-time client config download
// ---------------------------------------------------------------------------

pub async fn one_time_link(
    Path(token): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    // Claim the token atomically. Looking it up and deleting it afterwards let
    // two concurrent requests both pass the lookup and both receive the config
    // (which embeds the peer's private key), defeating the single-use property
    // this endpoint exists to enforce.
    let link = db::claim_one_time_link(&token).map_err(|_| {
        api_err(StatusCode::NOT_FOUND, "Invalid or expired one-time link")
    })?;

    // Check expiry. The row is already gone — claiming it is what deleted it —
    // so an expired link needs no further cleanup here.
    if let Some(ref expires) = link.expires_at {
        if let Some(exp) = crate::datetime::parse_expiry(expires) {
            if crate::datetime::now_utc() > exp {
                return Err(api_err(StatusCode::GONE, "One-time link has expired"));
            }
        }
    }

    // Generate client config
    let config = wg::get_client_config(link.id).map_err(|_| {
        api_err(StatusCode::NOT_FOUND, "Client not found")
    })?;

    let client = db::get_client(link.id).map_err(|_| {
        api_err(StatusCode::NOT_FOUND, "Client not found")
    })?;

    let filename = format!("{}.conf", sanitize_filename(&client.name));

    let mut headers = crate::http::HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/x-wireguard-config"),
    );
    headers.insert(header::CONTENT_DISPOSITION, super::attachment_disposition(&filename));
    // One-time link: the body embeds the peer's WireGuard private key, and the
    // link is already burnt above. A cached copy would outlive the single use
    // this endpoint exists to enforce.
    no_store_headers(&mut headers);

    Ok((StatusCode::OK, headers, config))
}

// ---------------------------------------------------------------------------
// GET /metrics/json
// ---------------------------------------------------------------------------

pub async fn metrics_json(
    peer: Option<crate::http::ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let general = db::get_general().map_err(map_err)?;

    if !general.metrics_json {
        return Err(api_err(StatusCode::FORBIDDEN, "JSON metrics disabled"));
    }

    // Bound guessing of the bearer token. This gate stands in front of the
    // whole peer roster, including each peer's current remote endpoint, and
    // had no attempt limiting at all while /api/session next door has had one
    // since the beginning.
    crate::api::session::check_ip_attempt_limit(
        "metrics",
        crate::api::session::client_ip_for_limit(
            &headers,
            peer.map(|crate::http::ConnectInfo(a)| a),
        )
        .as_deref(),
        30,
    )?;

    // `None` and empty are the same state — metrics enabled with no credential
    // — and both must be refused rather than skipping the check.
    if !check_metrics_password(&headers, general.metrics_password.as_deref().unwrap_or("")) {
        return Err(api_err(StatusCode::UNAUTHORIZED, "Bearer token required"));
    }

    let iface = db::get_interface().map_err(map_err)?;
    let clients = db::get_all_clients().map_err(map_err)?;
    let peers = wg::dump_peers_async(iface.name.clone()).await.unwrap_or_default();

    // One lock acquisition for the whole response rather than one per row.
    let ids: Vec<i64> = clients.iter().map(|c| c.id).collect();
    let recorded = crate::activity::client_activity_map(&ids);

    let metrics: Vec<Value> = clients
        .iter()
        .map(|client| {
            let peer = peers.iter().find(|p| p.public_key == client.public_key);
            let act = recorded.get(&client.id).cloned().unwrap_or_default();
            json!({
                "id": client.id,
                "name": client.name,
                "enabled": client.enabled,
                "transferRx": peer.map(|p| p.transfer_rx).unwrap_or(0),
                "transferTx": peer.map(|p| p.transfer_tx).unwrap_or(0),
                // Accumulated by the activity poller — monotonic across
                // interface restarts, unlike the two above.
                "totalRx": act.total_rx_bytes,
                "totalTx": act.total_tx_bytes,
                "lastSeenAt": act.last_seen_at,
                "latestHandshakeAt": peer.and_then(|p| p.latest_handshake.map(crate::datetime::to_rfc3339)),
                "endpoint": peer.and_then(|p| p.endpoint.clone()),
                "online": peer.map(|p| p.latest_handshake.is_some()).unwrap_or(false),
            })
        })
        .collect();

    Ok(Json(json!({
        "interface": {
            "name": iface.name,
            "port": iface.port,
        },
        "clients": metrics,
        "totalClients": clients.len(),
        "onlineClients": peers.iter().filter(|p| p.latest_handshake.is_some()).count(),
    })))
}

// ---------------------------------------------------------------------------
// GET /metrics/prometheus
// ---------------------------------------------------------------------------

pub async fn metrics_prometheus(
    peer: Option<crate::http::ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    let general = db::get_general().map_err(map_err)?;

    if !general.metrics_prometheus {
        return Err(api_err(
            StatusCode::FORBIDDEN,
            "Prometheus metrics disabled",
        ));
    }

    // Bound guessing of the bearer token. This gate stands in front of the
    // whole peer roster, including each peer's current remote endpoint, and
    // had no attempt limiting at all while /api/session next door has had one
    // since the beginning.
    crate::api::session::check_ip_attempt_limit(
        "metrics",
        crate::api::session::client_ip_for_limit(
            &headers,
            peer.map(|crate::http::ConnectInfo(a)| a),
        )
        .as_deref(),
        30,
    )?;

    // `None` and empty are the same state — metrics enabled with no credential
    // — and both must be refused rather than skipping the check.
    if !check_metrics_password(&headers, general.metrics_password.as_deref().unwrap_or("")) {
        return Err(api_err(StatusCode::UNAUTHORIZED, "Bearer token required"));
    }

    let iface = db::get_interface().map_err(map_err)?;
    let clients = db::get_all_clients().map_err(map_err)?;
    let peers = wg::dump_peers_async(iface.name.clone()).await.unwrap_or_default();

    let mut output = String::new();

    // Interface metrics
    output.push_str("# HELP wireguard_info Interface information\n");
    output.push_str("# TYPE wireguard_info gauge\n");
    output.push_str(&format!(
        "wireguard_info{{interface=\"{}\",port=\"{}\"}} 1\n",
        iface.name, iface.port
    ));

    // Client metrics
    output.push_str("# HELP wireguard_peer_rx_bytes Bytes received per peer\n");
    output.push_str("# TYPE wireguard_peer_rx_bytes counter\n");

    output.push_str("# HELP wireguard_peer_tx_bytes Bytes transmitted per peer\n");
    output.push_str("# TYPE wireguard_peer_tx_bytes counter\n");

    // The two above are read straight from `awg show dump` and therefore
    // restart at 0 with the interface — which is exactly the pattern
    // Prometheus's `rate()` reads as a counter reset. These two are the
    // poller's accumulated equivalents: genuinely monotonic across restarts,
    // so `increase()` over a window that contains one is still correct.
    output.push_str("# HELP wireguard_peer_total_rx_bytes Bytes received per peer, accumulated across interface restarts\n");
    output.push_str("# TYPE wireguard_peer_total_rx_bytes counter\n");

    output.push_str("# HELP wireguard_peer_total_tx_bytes Bytes transmitted per peer, accumulated across interface restarts\n");
    output.push_str("# TYPE wireguard_peer_total_tx_bytes counter\n");

    output.push_str("# HELP wireguard_peer_last_seen Unix timestamp the poller last observed a handshake for this peer\n");
    output.push_str("# TYPE wireguard_peer_last_seen gauge\n");

    output.push_str("# HELP wireguard_peer_latest_handshake Latest handshake timestamp\n");
    output.push_str("# TYPE wireguard_peer_latest_handshake gauge\n");

    output.push_str("# HELP wireguard_peer_online Whether the peer is online (1 = yes)\n");
    output.push_str("# TYPE wireguard_peer_online gauge\n");

    let safe_iface = escape_prometheus_label(&iface.name);
    let ids: Vec<i64> = clients.iter().map(|c| c.id).collect();
    let recorded = crate::activity::client_activity_map(&ids);
    for client in &clients {
        let peer = peers.iter().find(|p| p.public_key == client.public_key);
        let act = recorded.get(&client.id).cloned().unwrap_or_default();
        let safe_name = escape_prometheus_label(&client.name);

        let rx = peer.map(|p| p.transfer_rx).unwrap_or(0);
        let tx = peer.map(|p| p.transfer_tx).unwrap_or(0);
        let hs = peer
            .and_then(|p| p.latest_handshake)
            .map(|d| d.unix_timestamp())
            .unwrap_or(0);
        let online = if peer.map(|p| p.latest_handshake.is_some()).unwrap_or(false) { 1 } else { 0 };

        output.push_str(&format!(
            "wireguard_peer_rx_bytes{{interface=\"{}\",name=\"{}\",id=\"{}\"}} {}\n",
            safe_iface, safe_name, client.id, rx
        ));
        output.push_str(&format!(
            "wireguard_peer_tx_bytes{{interface=\"{}\",name=\"{}\",id=\"{}\"}} {}\n",
            safe_iface, safe_name, client.id, tx
        ));
        output.push_str(&format!(
            "wireguard_peer_total_rx_bytes{{interface=\"{}\",name=\"{}\",id=\"{}\"}} {}\n",
            safe_iface, safe_name, client.id, act.total_rx_bytes
        ));
        output.push_str(&format!(
            "wireguard_peer_total_tx_bytes{{interface=\"{}\",name=\"{}\",id=\"{}\"}} {}\n",
            safe_iface, safe_name, client.id, act.total_tx_bytes
        ));
        output.push_str(&format!(
            "wireguard_peer_last_seen{{interface=\"{}\",name=\"{}\",id=\"{}\"}} {}\n",
            safe_iface,
            safe_name,
            client.id,
            act.last_seen_at
                .as_deref()
                .and_then(crate::datetime::parse_expiry)
                .map(|d| d.unix_timestamp())
                .unwrap_or(0)
        ));
        output.push_str(&format!(
            "wireguard_peer_latest_handshake{{interface=\"{}\",name=\"{}\",id=\"{}\"}} {}\n",
            safe_iface, safe_name, client.id, hs
        ));
        output.push_str(&format!(
            "wireguard_peer_online{{interface=\"{}\",name=\"{}\",id=\"{}\"}} {}\n",
            safe_iface, safe_name, client.id, online
        ));
    }

    // Total counts
    output.push_str("# HELP wireguard_peers_total Total number of peers\n");
    output.push_str("# TYPE wireguard_peers_total gauge\n");
    output.push_str(&format!("wireguard_peers_total {}\n", clients.len()));

    let online_count = peers.iter().filter(|p| p.latest_handshake.is_some()).count();
    output.push_str("# HELP wireguard_peers_online Number of online peers\n");
    output.push_str("# TYPE wireguard_peers_online gauge\n");
    output.push_str(&format!("wireguard_peers_online {}\n", online_count));

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        output,
    ))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sanitize_filename(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let s = s.trim_start_matches('.').to_string();
    if s.is_empty() {
        "client".to_string()
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prometheus_label_escapes_injection_chars() {
        // A client named to break out of the label and forge a metric line.
        let hostile = "x\"} 1\nwireguard_peer_online{name=\"y";
        let escaped = escape_prometheus_label(hostile);
        // No RAW (unescaped) newline survives — the value stays one line.
        assert!(!escaped.contains('\n'), "raw newline must be escaped");
        // Every double-quote in the output is backslash-escaped: splitting on
        // the escaped form and rejoining must leave no stray quote.
        assert!(
            !escaped.replace("\\\"", "").contains('"'),
            "every quote must be escaped: {escaped}"
        );
        // Exact expected escaping (quote→\", newline→\n literal).
        assert_eq!(escaped, "x\\\"} 1\\nwireguard_peer_online{name=\\\"y");
        // Backslash is doubled.
        assert_eq!(escape_prometheus_label("a\\b"), "a\\\\b");
        // Ordinary names pass through unchanged.
        assert_eq!(escape_prometheus_label("Alice"), "Alice");
    }
}
