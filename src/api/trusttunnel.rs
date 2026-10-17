//! REST endpoints for TrustTunnel (HTTP/2 + HTTP/3 VPN endpoint).
//!
//! | Method | Path                                                | Auth  | Purpose                          |
//! |--------|-----------------------------------------------------|-------|----------------------------------|
//! | GET    | /api/admin/trusttunnel/inbound                      | admin | Read endpoint settings           |
//! | POST   | /api/admin/trusttunnel/inbound                      | admin | Update endpoint settings         |
//! | POST   | /api/admin/trusttunnel/inbound/certificate          | admin | Upload a PEM chain + key         |
//! | POST   | /api/admin/trusttunnel/inbound/regenerate-certificate | admin | New self-signed certificate    |
//! | GET    | /api/admin/trusttunnel/status                       | admin | Supervisor status                |
//! | POST   | /api/admin/trusttunnel/restart                      | admin | Force re-spawn                   |
//! | GET    | /api/trusttunnel/users                              | auth  | List users (own or all) + traffic|
//! | POST   | /api/trusttunnel/users                              | admin | Create user (generated password) |
//! | GET    | /api/trusttunnel/users/:id                          | auth  | Read one user                    |
//! | POST   | /api/trusttunnel/users/:id                          | admin | Update user                      |
//! | DELETE | /api/trusttunnel/users/:id                          | admin | Delete user                      |
//! | POST   | /api/trusttunnel/users/:id/rotate-password          | admin | New password                     |
//! | GET    | /api/trusttunnel/users/:id/share                    | auth  | `tt://` deep link                |
//! | GET    | /api/trusttunnel/users/:id/qrcode.svg               | auth  | QR of the deep link              |
//! | GET    | /api/trusttunnel/users/:id/client.toml              | auth  | Client endpoint config (TOML)    |
//!
//! Non-admins see and share only users linked to their own login, the same
//! rule as Xray. Passwords are never in list/read responses; they leave the
//! server only inside share artefacts, which carry `no-store`.

use crate::http::CookieJar;
use crate::http::IntoResponse;
use crate::http::Json;
use crate::http::{header, HeaderMap, StatusCode};
use crate::http::{Path, State};
use serde::Deserialize;
use serde_json::{json, Value};

use super::admin::require_admin;
use super::{
    api_err, attachment_disposition, map_err, no_store_headers, ok_success, require_auth,
    value_to_string, AppState,
};
use crate::db;
use crate::trusttunnel::{self, cert, config as ttcfg, keys, share, stats};

// ---------------------------------------------------------------------------
// Inbound
// ---------------------------------------------------------------------------

fn inbound_to_json(ib: &db::TrustTunnelInbound) -> Value {
    let list = |s: &str| json!(ttcfg::json_list(s));
    let host = db::get_user_config().map(|c| c.host).unwrap_or_default();
    let effective = ttcfg::effective_hostname(ib, &host);
    json!({
        "id": ib.id,
        "port": ib.port,
        "listenHttp1": ib.listen_http1,
        "listenHttp2": ib.listen_http2,
        "listenQuic": ib.listen_quic,
        "hostname": ib.hostname,
        "effectiveHostname": effective.as_ref().ok(),
        "hostnameError": effective.as_ref().err().map(|e| e.to_string()),
        "allowedSni": list(&ib.allowed_sni),
        "customSni": ib.custom_sni,
        "upstreamProtocol": ib.upstream_protocol,
        "antiDpi": ib.anti_dpi,
        "ipv6Available": ib.ipv6_available,
        "allowPrivateNetwork": ib.allow_private_network,
        "authFailureStatusCode": ib.auth_failure_status_code,
        "reverseProxyAddress": ib.reverse_proxy_address,
        "reverseProxyPathMask": ib.reverse_proxy_path_mask,
        "requireClientRandomPrefix": ib.require_client_random_prefix,
        "icmpEnabled": ib.icmp_enabled,
        "icmpInterface": ib.icmp_interface,
        "dnsUpstreams": list(&ib.dns_upstreams),
        "maxHttp2Conns": ib.max_http2_conns,
        "maxHttp3Conns": ib.max_http3_conns,
        "metricsPort": ib.metrics_port,
        "tlsMode": ib.tls_mode,
        // The chain is public (every client sees it); the key never leaves.
        "tlsChainPem": ib.tls_chain_pem,
        "hasTlsKey": !ib.tls_key_pem.is_empty(),
        "tlsCertHostname": ib.tls_cert_hostname,
        "tlsCaTrusted": effective
            .as_ref()
            .ok()
            .map(|h| !ib.tls_chain_pem.is_empty() && cert::ca_trusted(&ib.tls_chain_pem, h)),
        "additionalConfig": ib.additional_config,
        "enabled": ib.enabled,
        "isBundled": trusttunnel::is_bundled(),
        "trusttunnelVersion": trusttunnel::TRUSTTUNNEL_VERSION,
        "trusttunnelSha256": trusttunnel::TRUSTTUNNEL_SHA256,
    })
}

pub async fn get_inbound(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    let ib = db::get_trusttunnel_inbound().map_err(map_err)?;
    Ok(Json(inbound_to_json(&ib)))
}

/// `(jsonKey, db column)` for plain scalars.
const INBOUND_SCALARS: &[(&str, &str)] = &[
    ("port", "port"),
    ("listenHttp1", "listen_http1"),
    ("listenHttp2", "listen_http2"),
    ("listenQuic", "listen_quic"),
    ("hostname", "hostname"),
    ("customSni", "custom_sni"),
    ("upstreamProtocol", "upstream_protocol"),
    ("antiDpi", "anti_dpi"),
    ("ipv6Available", "ipv6_available"),
    ("allowPrivateNetwork", "allow_private_network"),
    ("authFailureStatusCode", "auth_failure_status_code"),
    ("reverseProxyAddress", "reverse_proxy_address"),
    ("reverseProxyPathMask", "reverse_proxy_path_mask"),
    ("requireClientRandomPrefix", "require_client_random_prefix"),
    ("icmpEnabled", "icmp_enabled"),
    ("icmpInterface", "icmp_interface"),
    ("maxHttp2Conns", "max_http2_conns"),
    ("maxHttp3Conns", "max_http3_conns"),
    ("metricsPort", "metrics_port"),
    ("tlsMode", "tls_mode"),
    ("additionalConfig", "additional_config"),
    ("enabled", "enabled"),
];

/// Columns stored as integers; their inputs must parse as one.
const INTEGER_COLUMNS: &[&str] = &[
    "port", "auth_failure_status_code", "max_http2_conns", "max_http3_conns", "metrics_port",
];

/// Apply `fields` to `ib` in memory so validation sees the row as it would
/// be after the write.
fn apply(ib: &mut db::TrustTunnelInbound, fields: &db::UpdateMap) -> Result<(), String> {
    let b = |v: &str| v == "1" || v.eq_ignore_ascii_case("true");
    let i = |k: &str, v: &str| v.trim().parse::<i64>().map_err(|_| format!("{k} must be an integer"));
    for (k, v) in fields {
        match k.as_str() {
            "port" => ib.port = i(k, v)?,
            "listen_http1" => ib.listen_http1 = b(v),
            "listen_http2" => ib.listen_http2 = b(v),
            "listen_quic" => ib.listen_quic = b(v),
            "hostname" => ib.hostname = v.clone(),
            "allowed_sni" => ib.allowed_sni = v.clone(),
            "custom_sni" => ib.custom_sni = v.clone(),
            "upstream_protocol" => ib.upstream_protocol = v.clone(),
            "anti_dpi" => ib.anti_dpi = b(v),
            "ipv6_available" => ib.ipv6_available = b(v),
            "allow_private_network" => ib.allow_private_network = b(v),
            "auth_failure_status_code" => ib.auth_failure_status_code = i(k, v)?,
            "reverse_proxy_address" => ib.reverse_proxy_address = v.clone(),
            "reverse_proxy_path_mask" => ib.reverse_proxy_path_mask = v.clone(),
            "require_client_random_prefix" => ib.require_client_random_prefix = b(v),
            "icmp_enabled" => ib.icmp_enabled = b(v),
            "icmp_interface" => ib.icmp_interface = v.clone(),
            "dns_upstreams" => ib.dns_upstreams = v.clone(),
            "max_http2_conns" => ib.max_http2_conns = i(k, v)?,
            "max_http3_conns" => ib.max_http3_conns = i(k, v)?,
            "metrics_port" => ib.metrics_port = i(k, v)?,
            "tls_mode" => ib.tls_mode = v.clone(),
            "additional_config" => ib.additional_config = v.clone(),
            "enabled" => ib.enabled = b(v),
            _ => {}
        }
    }
    Ok(())
}

/// Ports another enabled listener on this host already holds. TrustTunnel
/// binds its port on TCP *and* UDP, so a clash on either protocol counts.
fn port_conflicts(port: i64, metrics_port: i64) -> Vec<String> {
    let mut out = Vec::new();
    if port == i64::from(crate::config::CONFIG.port) || metrics_port == i64::from(crate::config::CONFIG.port) {
        out.push(format!("the admin web UI (TCP {})", crate::config::CONFIG.port));
    }
    if let Ok(iface) = db::get_interface() {
        if iface.port == port {
            out.push(format!("AmneziaWG (UDP {})", iface.port));
        }
    }
    if let Ok(x) = db::get_xray_inbound() {
        if x.enabled && x.port == port {
            out.push(format!("Xray Reality (TCP {})", x.port));
        }
    }
    if let Ok(m) = db::get_mtproxy_inbound() {
        if m.enabled && m.port == port {
            out.push(format!("MTProxy (TCP {})", m.port));
        }
    }
    if let Ok(d) = db::get_mdnsvpn_inbound() {
        if d.enabled && d.port == port {
            out.push(format!("MasterDnsVPN (UDP {})", d.port));
        }
    }
    if let Ok(q) = db::get_qqdns_settings() {
        if q.enabled && q.receive_port == port {
            out.push(format!("QQ-DNS (UDP {})", q.receive_port));
        }
    }
    if port == metrics_port {
        out.push("its own metrics listener".to_string());
    }
    out
}

pub async fn update_inbound(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    let Value::Object(map) = &body else {
        return Err(api_err(StatusCode::BAD_REQUEST, "body must be a JSON object"));
    };

    let mut fields = db::UpdateMap::new();
    for (json_key, col) in INBOUND_SCALARS {
        if let Some(s) = map.get(*json_key).and_then(value_to_string) {
            let s = if *col == "additional_config" { s } else { s.trim().to_string() };
            fields.insert(col.to_string(), s);
        }
    }
    for (json_key, col) in [("allowedSni", "allowed_sni"), ("dnsUpstreams", "dns_upstreams")] {
        if let Some(v) = map.get(json_key) {
            let list: Vec<String> = serde_json::from_value(v.clone()).map_err(|_| {
                api_err(StatusCode::BAD_REQUEST, &format!("{json_key} must be an array of strings"))
            })?;
            let list: Vec<String> = list.into_iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
            fields.insert(col.to_string(), serde_json::to_string(&list).unwrap_or_else(|_| "[]".into()));
        }
    }
    if fields.is_empty() {
        return Err(api_err(StatusCode::BAD_REQUEST, "No fields to update"));
    }
    for col in INTEGER_COLUMNS {
        if let Some(v) = fields.get(*col) {
            if v.parse::<i64>().is_err() {
                return Err(api_err(StatusCode::BAD_REQUEST, &format!("{col} must be an integer")));
            }
        }
    }

    let current = db::get_trusttunnel_inbound().map_err(map_err)?;
    let mut next = current.clone();
    apply(&mut next, &fields).map_err(|e| api_err(StatusCode::BAD_REQUEST, &e))?;
    ttcfg::validate(&next).map_err(|e| api_err(StatusCode::BAD_REQUEST, &e.to_string()))?;
    if !next.hostname.trim().is_empty() {
        ttcfg::validate_hostname(next.hostname.trim())
            .map_err(|e| api_err(StatusCode::BAD_REQUEST, &e.to_string()))?;
    }
    let conflicts = port_conflicts(next.port, next.metrics_port);
    if !conflicts.is_empty() {
        return Err(api_err(
            StatusCode::CONFLICT,
            &format!("port {} is already used by {}", next.port, conflicts.join(", ")),
        ));
    }
    let users = db::list_trusttunnel_users().map_err(map_err)?;
    if next.enabled {
        ttcfg::validate_roster(&next, &users, crate::datetime::now_utc())
            .map_err(|e| api_err(StatusCode::BAD_REQUEST, &e.to_string()))?;
    }

    // Leaving custom mode must not keep serving the uploaded certificate
    // under the self-signed label: clear it so a fresh one is issued.
    if current.tls_mode == "custom" && next.tls_mode == "self_signed" {
        fields.insert("tls_chain_pem".into(), String::new());
        fields.insert("tls_key_pem".into(), String::new());
        fields.insert("tls_cert_hostname".into(), String::new());
    }

    db::update_trusttunnel_inbound(&fields).map_err(map_err)?;
    let warning = reconcile_now().await;
    let ib = db::get_trusttunnel_inbound().map_err(map_err)?;
    let mut out = inbound_to_json(&ib);
    out["warning"] = json!(warning);
    Ok(Json(out))
}

#[derive(Deserialize)]
pub struct CertificateUpload {
    #[serde(rename = "chainPem")]
    pub chain_pem: String,
    #[serde(rename = "keyPem")]
    pub key_pem: String,
}

pub async fn upload_certificate(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<CertificateUpload>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    let ib = db::get_trusttunnel_inbound().map_err(map_err)?;
    let host = db::get_user_config().map(|c| c.host).unwrap_or_default();
    let hostname = ttcfg::effective_hostname(&ib, &host)
        .map_err(|e| api_err(StatusCode::PRECONDITION_FAILED, &e.to_string()))?;
    let material = cert::Material {
        chain_pem: body.chain_pem.trim().to_string() + "\n",
        key_pem: body.key_pem.trim().to_string() + "\n",
    };
    cert::validate(&material, &hostname)
        .map_err(|e| api_err(StatusCode::BAD_REQUEST, &format!("{e:#}")))?;

    let mut fields = db::UpdateMap::new();
    fields.insert("tls_mode".into(), "custom".into());
    fields.insert("tls_chain_pem".into(), material.chain_pem);
    fields.insert("tls_key_pem".into(), material.key_pem);
    fields.insert("tls_cert_hostname".into(), hostname);
    db::update_trusttunnel_inbound(&fields).map_err(map_err)?;
    let warning = reconcile_now().await;
    let ib = db::get_trusttunnel_inbound().map_err(map_err)?;
    let mut out = inbound_to_json(&ib);
    out["warning"] = json!(warning);
    Ok(Json(out))
}

pub async fn regenerate_certificate(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    let ib = db::get_trusttunnel_inbound().map_err(map_err)?;
    let host = db::get_user_config().map(|c| c.host).unwrap_or_default();
    let hostname = ttcfg::effective_hostname(&ib, &host)
        .map_err(|e| api_err(StatusCode::PRECONDITION_FAILED, &e.to_string()))?;
    let m = cert::self_signed(&hostname).map_err(map_err)?;
    let mut fields = db::UpdateMap::new();
    fields.insert("tls_mode".into(), "self_signed".into());
    fields.insert("tls_chain_pem".into(), m.chain_pem);
    fields.insert("tls_key_pem".into(), m.key_pem);
    fields.insert("tls_cert_hostname".into(), hostname);
    db::update_trusttunnel_inbound(&fields).map_err(map_err)?;
    let warning = reconcile_now().await;
    let ib = db::get_trusttunnel_inbound().map_err(map_err)?;
    let mut out = inbound_to_json(&ib);
    out["warning"] = json!(warning);
    Ok(Json(out))
}

// ---------------------------------------------------------------------------
// Supervisor
// ---------------------------------------------------------------------------

#[cfg(trusttunnel_bundled)]
pub async fn supervisor_status(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    let status = trusttunnel::supervisor::status().await;
    Ok(Json(serde_json::to_value(&status).unwrap_or(Value::Null)))
}

#[cfg(not(trusttunnel_bundled))]
pub async fn supervisor_status(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    Ok(Json(json!({
        "state": "disabled",
        "reason": "TrustTunnel support not bundled in this build",
    })))
}

#[cfg(trusttunnel_bundled)]
pub async fn restart(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    trusttunnel::supervisor::restart()
        .await
        .map_err(|e| api_err(StatusCode::BAD_REQUEST, &format!("{e:#}")))?;
    Ok(ok_success())
}

#[cfg(not(trusttunnel_bundled))]
pub async fn restart(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    Err(api_err(StatusCode::NOT_IMPLEMENTED, "TrustTunnel support not bundled in this build"))
}

/// Reconcile after an inbound change and return the error, if any, as a
/// warning: the row is saved either way, and the UI shows why the endpoint
/// is not (or no longer) running.
#[cfg(trusttunnel_bundled)]
async fn reconcile_now() -> Option<String> {
    match trusttunnel::supervisor::ensure_running().await {
        Ok(()) => None,
        Err(e) => {
            crate::warn!(error = ?e, "TrustTunnel supervisor reconcile failed");
            Some(format!("{e:#}"))
        }
    }
}

#[cfg(not(trusttunnel_bundled))]
async fn reconcile_now() -> Option<String> {
    None
}

#[cfg(trusttunnel_bundled)]
fn reconcile_later() {
    trusttunnel::supervisor::request_reconcile();
}

#[cfg(not(trusttunnel_bundled))]
fn reconcile_later() {}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

fn user_to_json(u: &db::TrustTunnelUser) -> Value {
    let now = crate::datetime::now_utc();
    json!({
        "id": u.id,
        "userId": u.user_id,
        "name": u.name,
        "username": u.username,
        "clientRandomPrefix": u.client_random_prefix,
        "expiresAt": u.expires_at,
        "enabled": u.enabled,
        "active": ttcfg::is_active(u, now),
        "traffic": stats::get(&u.username),
        "createdAt": u.created_at,
        "updatedAt": u.updated_at,
    })
}

fn load_user(
    state: &AppState,
    jar: &CookieJar,
    id: i64,
) -> Result<db::TrustTunnelUser, (StatusCode, Json<Value>)> {
    let viewer = require_auth(jar, state)?;
    let user = db::get_trusttunnel_user(id)
        .map_err(|_| api_err(StatusCode::NOT_FOUND, "TrustTunnel user not found"))?;
    if viewer.role < 1 && user.user_id != Some(viewer.id) {
        return Err(api_err(StatusCode::FORBIDDEN, "Access denied"));
    }
    Ok(user)
}

pub async fn list_users(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let viewer = require_auth(&jar, &state)?;
    let mut users = db::list_trusttunnel_users().map_err(map_err)?;
    if viewer.role < 1 {
        users.retain(|u| u.user_id == Some(viewer.id));
    }
    Ok(Json(json!(users.iter().map(user_to_json).collect::<Vec<_>>())))
}

pub async fn get_user(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<i64>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let user = load_user(&state, &jar, id)?;
    Ok(Json(user_to_json(&user)))
}

#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub name: String,
    #[serde(default, rename = "userId")]
    pub user_id: Option<i64>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default, rename = "expiresAt")]
    pub expires_at: Option<String>,
    #[serde(default, rename = "clientRandomPrefix")]
    pub client_random_prefix: Option<String>,
    /// Generate a prefix server-side (ignored when one is supplied).
    #[serde(default, rename = "generatePrefix")]
    pub generate_prefix: bool,
}

fn validate_expiry(v: &Option<String>) -> Result<(), (StatusCode, Json<Value>)> {
    match v.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) if !crate::datetime::is_valid_expiry(s) => Err(api_err(
            StatusCode::BAD_REQUEST,
            "expiresAt must be RFC 3339 or YYYY-MM-DDTHH:MM[:SS]",
        )),
        _ => Ok(()),
    }
}

fn validate_owner(user_id: Option<i64>) -> Result<(), (StatusCode, Json<Value>)> {
    if let Some(id) = user_id {
        db::get_user(id).map_err(|_| api_err(StatusCode::BAD_REQUEST, "userId does not exist"))?;
    }
    Ok(())
}

/// A free username: the requested/derived one, else `-2`, `-3`, ….
fn unique_username(base: &str, existing: &[db::TrustTunnelUser]) -> String {
    let taken = |n: &str| existing.iter().any(|u| u.username == n);
    if !taken(base) {
        return base.to_string();
    }
    (2..)
        .map(|i| format!("{base}-{i}"))
        .find(|n| !taken(n))
        .expect("an unbounded range always yields a free name")
}

pub async fn create_user(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<CreateUserRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    let name = body.name.trim();
    if name.is_empty() {
        return Err(api_err(StatusCode::BAD_REQUEST, "name is required"));
    }
    validate_expiry(&body.expires_at)?;
    validate_owner(body.user_id)?;

    let existing = db::list_trusttunnel_users().map_err(map_err)?;
    let username = match body.username.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(requested) => {
            ttcfg::validate_username(requested).map_err(|e| api_err(StatusCode::BAD_REQUEST, &e.to_string()))?;
            if existing.iter().any(|u| u.username == requested) {
                return Err(api_err(StatusCode::CONFLICT, "username is already taken"));
            }
            requested.to_string()
        }
        None => unique_username(&keys::username_from_name(name), &existing),
    };
    let prefix = match body.client_random_prefix.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(p) => {
            ttcfg::validate_client_random_prefix(p).map_err(|e| api_err(StatusCode::BAD_REQUEST, &e.to_string()))?;
            p.to_ascii_lowercase()
        }
        None if body.generate_prefix => keys::generate_client_random_prefix(),
        None => String::new(),
    };
    let inbound = db::get_trusttunnel_inbound().map_err(map_err)?;
    if inbound.require_client_random_prefix && prefix.is_empty() {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "this endpoint requires a client-random prefix for every user — supply one or set generatePrefix",
        ));
    }

    let id = db::create_trusttunnel_user(&db::CreateTrustTunnelUserParams {
        user_id: body.user_id,
        name: name.to_string(),
        username,
        password: keys::generate_password(),
        client_random_prefix: prefix,
        expires_at: body.expires_at.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
        enabled: true,
    })
    .map_err(map_err)?;
    reconcile_later();
    let created = db::get_trusttunnel_user(id).map_err(map_err)?;
    Ok(Json(user_to_json(&created)))
}

#[derive(Deserialize)]
pub struct UpdateUserRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default, rename = "expiresAt", deserialize_with = "present")]
    pub expires_at: Option<Option<String>>,
    #[serde(default, rename = "clientRandomPrefix")]
    pub client_random_prefix: Option<String>,
    #[serde(default, rename = "userId", deserialize_with = "present")]
    pub user_id: Option<Option<i64>>,
}

/// Distinguish an absent key (`None`, via `default`) from an explicit
/// `null` (`Some(None)`). Plain `Option<Option<T>>` folds both into `None`,
/// which would make "unlink the owner" / "clear the expiry" impossible.
fn present<'de, D, T>(d: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    Option::<T>::deserialize(d).map(Some)
}

pub async fn update_user(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<i64>,
    Json(body): Json<UpdateUserRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    let mut user = db::get_trusttunnel_user(id)
        .map_err(|_| api_err(StatusCode::NOT_FOUND, "TrustTunnel user not found"))?;
    let mut fields = db::UpdateMap::new();
    if let Some(ref v) = body.name {
        if v.trim().is_empty() {
            return Err(api_err(StatusCode::BAD_REQUEST, "name must not be empty"));
        }
        fields.insert("name".into(), v.trim().to_string());
    }
    if let Some(v) = body.enabled {
        fields.insert("enabled".into(), if v { "1".into() } else { "0".into() });
        user.enabled = v;
    }
    if let Some(ref v) = body.expires_at {
        validate_expiry(v)?;
        let v = v.as_deref().map(str::trim).unwrap_or_default().to_string();
        user.expires_at = (!v.is_empty()).then(|| v.clone());
        fields.insert("expires_at".into(), v);
    }
    if let Some(ref v) = body.client_random_prefix {
        let v = v.trim().to_ascii_lowercase();
        ttcfg::validate_client_random_prefix(&v).map_err(|e| api_err(StatusCode::BAD_REQUEST, &e.to_string()))?;
        user.client_random_prefix = v.clone();
        fields.insert("client_random_prefix".into(), v);
    }
    if let Some(owner) = body.user_id {
        // A NULL cannot go through the string-typed update map, so owner
        // changes use their own statement.
        validate_owner(owner)?;
        db::set_trusttunnel_user_owner(id, owner).map_err(map_err)?;
    }
    if fields.is_empty() && body.user_id.is_none() {
        return Err(api_err(StatusCode::BAD_REQUEST, "No fields to update"));
    }

    let inbound = db::get_trusttunnel_inbound().map_err(map_err)?;
    if inbound.enabled {
        let mut users = db::list_trusttunnel_users().map_err(map_err)?;
        if let Some(slot) = users.iter_mut().find(|u| u.id == id) {
            *slot = user.clone();
        }
        ttcfg::validate_roster(&inbound, &users, crate::datetime::now_utc())
            .map_err(|e| api_err(StatusCode::BAD_REQUEST, &e.to_string()))?;
    }
    if !fields.is_empty() {
        db::update_trusttunnel_user(id, &fields).map_err(map_err)?;
    }
    reconcile_later();
    let updated = db::get_trusttunnel_user(id).map_err(map_err)?;
    Ok(Json(user_to_json(&updated)))
}

pub async fn delete_user(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<i64>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    let user = db::get_trusttunnel_user(id)
        .map_err(|_| api_err(StatusCode::NOT_FOUND, "TrustTunnel user not found"))?;
    db::delete_trusttunnel_user(id).map_err(map_err)?;
    stats::forget(&user.username);
    reconcile_later();
    Ok(ok_success())
}

pub async fn rotate_password(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<i64>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    db::get_trusttunnel_user(id).map_err(|_| api_err(StatusCode::NOT_FOUND, "TrustTunnel user not found"))?;
    let mut fields = db::UpdateMap::new();
    fields.insert("password".into(), keys::generate_password());
    db::update_trusttunnel_user(id, &fields).map_err(map_err)?;
    reconcile_later();
    Ok(ok_success())
}

// ---------------------------------------------------------------------------
// Share artefacts
// ---------------------------------------------------------------------------

/// Public IPs `host` resolves to, IPv4 first. Empty when `host` is an IP.
/// Private and reserved answers (split-horizon DNS on the server) are
/// dropped — a remote client cannot reach them.
async fn resolve_public_ips(host: &str) -> Vec<std::net::IpAddr> {
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() || host.parse::<std::net::IpAddr>().is_ok() {
        return Vec::new();
    }
    let Ok(resolved) = tokio::net::lookup_host((host, 0)).await else {
        crate::warn!(host, "trusttunnel share: host did not resolve; link carries the name only");
        return Vec::new();
    };
    let mut ips: Vec<std::net::IpAddr> = Vec::new();
    for ip in resolved.map(|a| a.ip()) {
        if !crate::xray::probe::is_forbidden_ip(ip) && !ips.contains(&ip) {
            ips.push(ip);
        }
    }
    ips.sort_by_key(|ip| ip.is_ipv6());
    ips
}

async fn share_inputs(
    state: &AppState,
    jar: &CookieJar,
    id: i64,
) -> Result<(db::TrustTunnelInbound, db::TrustTunnelUser, String, Vec<std::net::IpAddr>), (StatusCode, Json<Value>)> {
    let user = load_user(state, jar, id)?;
    let inbound = db::get_trusttunnel_inbound().map_err(map_err)?;
    let host = db::get_user_config().map_err(map_err)?.host;
    if host.trim().is_empty() {
        return Err(api_err(
            StatusCode::PRECONDITION_FAILED,
            "host is not configured — set it on the General admin tab first",
        ));
    }
    let resolved = resolve_public_ips(&host).await;
    Ok((inbound, user, host, resolved))
}

/// Builder errors here are operator-fixable preconditions (no certificate
/// yet, no hostname), not server faults.
fn share_err(e: anyhow::Error) -> (StatusCode, Json<Value>) {
    api_err(StatusCode::PRECONDITION_FAILED, &format!("{e:#}"))
}

pub async fn user_share(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<i64>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    let (inbound, user, host, ips) = share_inputs(&state, &jar, id).await?;
    let ctx = share::Context { host: &host, resolved: &ips };
    let link = share::build_link(&inbound, &user, &ctx).map_err(share_err)?;
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "text/plain; charset=utf-8".parse().unwrap());
    // The link carries the user's password.
    no_store_headers(&mut headers);
    Ok((StatusCode::OK, headers, link))
}

pub async fn user_qrcode(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<i64>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    let (inbound, user, host, ips) = share_inputs(&state, &jar, id).await?;
    let ctx = share::Context { host: &host, resolved: &ips };
    let link = share::build_link(&inbound, &user, &ctx).map_err(share_err)?;
    let svg = crate::qr::generate_qr_svg(&link).map_err(|e| {
        // A self-signed chain makes the link ~1 KB; a long CA chain can
        // exceed what one QR code holds.
        api_err(StatusCode::UNPROCESSABLE_ENTITY, &format!("link too large for a QR code ({} bytes): {e}", link.len()))
    })?;
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "image/svg+xml".parse().unwrap());
    no_store_headers(&mut headers);
    Ok((StatusCode::OK, headers, svg))
}

pub async fn user_client_toml(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<i64>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    let (inbound, user, host, ips) = share_inputs(&state, &jar, id).await?;
    let ctx = share::Context { host: &host, resolved: &ips };
    let body = share::build_client_toml(&inbound, &user, &ctx).map_err(share_err)?;
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "application/toml; charset=utf-8".parse().unwrap());
    headers.insert(
        header::CONTENT_DISPOSITION,
        attachment_disposition(&format!("trusttunnel-{}.toml", user.username)),
    );
    no_store_headers(&mut headers);
    Ok((StatusCode::OK, headers, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(name: &str) -> db::TrustTunnelUser {
        db::TrustTunnelUser {
            id: 0,
            user_id: None,
            name: name.into(),
            username: name.into(),
            password: String::new(),
            client_random_prefix: String::new(),
            expires_at: None,
            enabled: true,
            created_at: String::new(),
            updated_at: String::new(),
        }
    }

    #[test]
    fn update_request_tells_null_from_absent() {
        let r: UpdateUserRequest = serde_json::from_str(r#"{"userId":null}"#).unwrap();
        assert_eq!(r.user_id, Some(None));
        assert!(r.expires_at.is_none());
        let r: UpdateUserRequest = serde_json::from_str(r#"{"userId":3,"expiresAt":null}"#).unwrap();
        assert_eq!(r.user_id, Some(Some(3)));
        assert_eq!(r.expires_at, Some(None));
    }

    #[test]
    fn usernames_get_numeric_suffixes() {
        let existing = vec![u("alice"), u("alice-2")];
        assert_eq!(unique_username("bob", &existing), "bob");
        assert_eq!(unique_username("alice", &existing), "alice-3");
    }
}
