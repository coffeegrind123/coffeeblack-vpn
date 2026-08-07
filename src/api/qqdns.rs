//! REST endpoints for the in-process QQ-Tunnel UDP-over-DNS transport.
//!
//! | Method | Path                           | Auth  | Purpose                                    |
//! |--------|--------------------------------|-------|--------------------------------------------|
//! | GET    | /api/admin/qqdns/settings      | admin | Read singleton settings + effective info   |
//! | POST   | /api/admin/qqdns/settings      | admin | Update settings + reconcile the engine     |
//! | GET    | /api/admin/qqdns/status        | admin | Supervisor status snapshot                 |
//! | POST   | /api/admin/qqdns/restart       | admin | Force teardown + rebind the engine         |
//! | GET    | /api/admin/qqdns/client-config | admin | Generate the matching client config.json   |
//!
//! Every POST writes the DB first, then calls
//! `qqdns::supervisor::apply_and_reconcile`, which binds/rebinds the engine to
//! the new desired state (no AmneziaWG rebind — this is a side-channel).

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use serde_json::{json, Value};

use super::admin::require_admin;
use super::{map_err, ok_success, value_to_string, AppState};
use crate::db;
use crate::qqdns::{config as qconfig, share};

// ---------------------------------------------------------------------------
// GET /api/admin/qqdns/settings
// ---------------------------------------------------------------------------

pub async fn get_settings(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    let s = db::get_qqdns_settings().map_err(map_err)?;
    let iface = db::get_interface().ok();
    let effective_target = iface
        .as_ref()
        .map(|i| qconfig::effective_awg_target(&s, i.port));
    let disabled_reason = iface
        .as_ref()
        .and_then(|i| qconfig::should_remain_disabled(&s, i));

    Ok(Json(json!({
        "id": s.id,
        "enabled": s.enabled,
        "dnsIps": json_list(&s.dns_ips),
        "sendDomains": json_list(&s.send_domains),
        "recvDomains": json_list(&s.recv_domains),
        "sendInterfaceIp": s.send_interface_ip,
        "receiveInterfaceIp": s.receive_interface_ip,
        "receivePort": s.receive_port,
        "hInAddress": s.h_in_address,
        "awgTargetPort": s.awg_target_port,
        "effectiveAwgTargetPort": effective_target,
        "publicPort": iface.as_ref().map(|i| i.port),
        "maxDomainLen": s.max_domain_len,
        "maxSubLen": s.max_sub_len,
        "retries": s.retries,
        "sendQueryType": s.send_query_type,
        "packetsSendIntervalMs": s.packets_send_interval_ms,
        "packetsWaitTimeLimitMs": s.packets_wait_time_limit_ms,
        "sendSockNumbers": s.send_sock_numbers,
        "disabledReason": disabled_reason,
        "setupNotes": share::setup_notes(&s),
    })))
}

// ---------------------------------------------------------------------------
// POST /api/admin/qqdns/settings
// ---------------------------------------------------------------------------

pub async fn update_settings(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;

    let mut fields = db::UpdateMap::new();
    if let Value::Object(map) = &body {
        // JSON-array columns: accept an array and store it re-encoded.
        for (json_key, db_key) in [
            ("dnsIps", "dns_ips"),
            ("sendDomains", "send_domains"),
            ("recvDomains", "recv_domains"),
        ] {
            if let Some(val) = map.get(json_key) {
                let list = coerce_string_list(val)
                    .ok_or_else(|| bad_request(format!("{json_key} must be an array of strings")))?;
                fields.insert(db_key.to_string(), serde_json::to_string(&list).unwrap());
            }
        }

        let scalars: &[(&str, &str)] = &[
            ("enabled", "enabled"),
            ("sendInterfaceIp", "send_interface_ip"),
            ("receiveInterfaceIp", "receive_interface_ip"),
            ("receivePort", "receive_port"),
            ("hInAddress", "h_in_address"),
            ("awgTargetPort", "awg_target_port"),
            ("maxDomainLen", "max_domain_len"),
            ("maxSubLen", "max_sub_len"),
            ("retries", "retries"),
            ("sendQueryType", "send_query_type"),
            ("packetsSendIntervalMs", "packets_send_interval_ms"),
            ("packetsWaitTimeLimitMs", "packets_wait_time_limit_ms"),
            ("sendSockNumbers", "send_sock_numbers"),
        ];
        for (json_key, db_key) in scalars {
            if let Some(val) = map.get(*json_key) {
                if let Some(s) = value_to_string(val) {
                    fields.insert(db_key.to_string(), s);
                }
            }
        }

        // ---- validation (clean 4xx instead of a Crashed bubble later) ----
        if let Some(v) = fields.get("receive_port") {
            reject_unless_range(v, 1, 65535, "receivePort")?;
        }
        if let Some(v) = fields.get("awg_target_port") {
            // 0 = auto (interface port); otherwise a real port.
            if v != "0" {
                reject_unless_range(v, 1, 65535, "awgTargetPort")?;
            }
        }
        if let Some(v) = fields.get("max_domain_len") {
            reject_unless_range(v, 20, 253, "maxDomainLen")?;
        }
        if let Some(v) = fields.get("max_sub_len") {
            reject_unless_range(v, 1, 63, "maxSubLen")?;
        }
        if let Some(v) = fields.get("retries") {
            reject_unless_range(v, 0, 10, "retries")?;
        }
        if let Some(v) = fields.get("send_query_type") {
            // A=1, NS=2, CNAME=5, TXT=16, AAAA=28 — accept any 1..=65535.
            reject_unless_range(v, 1, 65535, "sendQueryType")?;
        }
        if let Some(v) = fields.get("send_sock_numbers") {
            reject_unless_range(v, 1, 65536, "sendSockNumbers")?;
        }
        if let Some(v) = fields.get("packets_send_interval_ms") {
            reject_unless_range(v, 0, 60000, "packetsSendIntervalMs")?;
        }
        if let Some(v) = fields.get("packets_wait_time_limit_ms") {
            reject_unless_range(v, 1, 60000, "packetsWaitTimeLimitMs")?;
        }
        if let Some(v) = fields.get("h_in_address") {
            if crate::qqdns::dns::split_host_port(v).is_none() {
                return Err(bad_request(format!(
                    "hInAddress must be host:port (e.g. 127.0.0.1:10443), got {v:?}"
                )));
            }
        }
    }

    if !fields.is_empty() {
        db::update_qqdns_settings(&fields).map_err(map_err)?;
    }

    // Rebind the engine to the new desired state. Non-fatal — the status
    // endpoint surfaces any reason it declined to come up.
    if let Err(e) = crate::qqdns::supervisor::apply_and_reconcile().await {
        tracing::warn!(error = ?e, "qqdns reconcile failed after admin update");
    }

    Ok(ok_success())
}

// ---------------------------------------------------------------------------
// GET /api/admin/qqdns/status
// ---------------------------------------------------------------------------

pub async fn supervisor_status(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    let s = crate::qqdns::supervisor::status().await;
    Ok(Json(
        serde_json::to_value(s).unwrap_or_else(|_| json!({"state": "unknown"})),
    ))
}

// ---------------------------------------------------------------------------
// POST /api/admin/qqdns/restart
// ---------------------------------------------------------------------------

pub async fn restart(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    if let Err(e) = crate::qqdns::supervisor::apply_and_reconcile().await {
        return Err(map_err(e));
    }
    Ok(ok_success())
}

// ---------------------------------------------------------------------------
// GET /api/admin/qqdns/client-config?endpoint=127.0.0.1:51820
// ---------------------------------------------------------------------------

pub async fn client_config(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    let s = db::get_qqdns_settings().map_err(map_err)?;
    let endpoint = params.get("endpoint").map(|s| s.as_str());
    Ok(Json(json!({
        "config": share::client_config(&s, endpoint),
        "notes": share::setup_notes(&s),
    })))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn json_list(s: &str) -> Vec<String> {
    serde_json::from_str(s).unwrap_or_default()
}

/// Accept a JSON array of strings, or a single string (comma/newline-split),
/// into a clean `Vec<String>`.
fn coerce_string_list(val: &Value) -> Option<Vec<String>> {
    match val {
        Value::Array(items) => {
            let mut out = Vec::new();
            for it in items {
                let s = it.as_str()?.trim().to_string();
                if !s.is_empty() {
                    out.push(s);
                }
            }
            Some(out)
        }
        Value::String(s) => Some(
            s.split([',', '\n', ' '])
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect(),
        ),
        _ => None,
    }
}

fn reject_unless_range(
    v: &str,
    lo: i64,
    hi: i64,
    name: &str,
) -> Result<(), (StatusCode, Json<Value>)> {
    match v.parse::<i64>() {
        Ok(n) if (lo..=hi).contains(&n) => Ok(()),
        Ok(n) => Err(bad_request(format!("{name} must be {lo}..={hi}, got {n}"))),
        Err(_) => Err(bad_request(format!("{name} must be an integer"))),
    }
}

fn bad_request(msg: String) -> (StatusCode, Json<Value>) {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": msg })))
}
