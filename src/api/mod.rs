//! API route layer for awg-easy-rs.
//!
//! All HTTP handlers are organised into sub-modules:
//! - `session`  — authentication and session management
//! - `clients`  — AmneziaWG client CRUD
//! - `activity` — per-client activity history (heatmap matrix, purge)
//! - `admin`    — administrative endpoints (general, hooks, interface, etc.)
//! - `setup`    — first-run setup wizard
//! - `routes`   — miscellaneous routes (one-time links, metrics)

pub mod activity;
pub mod admin;
pub mod clients;
pub mod routes;
pub mod session;
pub mod setup;
pub mod dns;
pub mod mdnsvpn;
pub mod mtproxy;
pub mod proxy;
pub mod qqdns;
pub mod xray;

use crate::http::Router;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Session state
// ---------------------------------------------------------------------------

/// Per-session data stored in-memory.
#[derive(Clone, Debug)]
pub struct SessionData {
    pub user_id: i64,
    pub username: String,
    pub role: i64,
    pub created_at: u64, // unix timestamp seconds
}

impl SessionData {
    pub fn is_expired(&self, timeout_secs: i64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now.saturating_sub(self.created_at) > timeout_secs as u64
    }
}

/// Application state shared with every handler.
#[derive(Clone)]
pub struct AppState {
    pub sessions: Arc<Mutex<HashMap<String, SessionData>>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
    pub fn new() -> Self {
        AppState {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

/// Drop every session whose age exceeds `timeout_secs` from the in-memory
/// store. Expiry is enforced lazily on each request, but without a sweep the
/// map would retain entries for users who never return — this keeps it bounded.
/// Called from the background cron.
pub fn prune_expired_sessions(state: &AppState, timeout_secs: i64) {
    if let Ok(mut sessions) = state.sessions.lock() {
        sessions.retain(|_, s| !s.is_expired(timeout_secs));
    }
}

// ---------------------------------------------------------------------------
// Error helpers
// ---------------------------------------------------------------------------

use crate::http::{header, HeaderMap, HeaderValue, StatusCode};
use crate::http::Json;
use serde_json::{json, Value};

/// Convenience: build a JSON error response.
pub fn api_err(status: StatusCode, msg: &str) -> (StatusCode, Json<Value>) {
    (status, Json(json!({ "error": msg })))
}

/// Build a `Content-Disposition: attachment` header value for a download.
/// `filename` is expected to be pre-sanitized; this still falls back to a bare
/// `attachment` rather than panicking if the value can't form a valid header
/// (replaces the previous `format!(...).parse().unwrap()` at every call site).
pub fn attachment_disposition(filename: &str) -> HeaderValue {
    HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
        .unwrap_or_else(|_| HeaderValue::from_static("attachment"))
}

/// Headers for a response body that carries secrets (keys, peer configs,
/// share URLs, QR codes).
///
/// `no-store` is the operative directive: it forbids any cache — browser disk
/// cache, a corporate proxy, a CDN in front of the panel — from writing the
/// body to storage. Without it a downloaded tunnel config (which embeds the
/// shared encryption key) can outlive the session that fetched it, on disks we
/// do not control. `Pragma` is the HTTP/1.0 belt-and-braces for old
/// intermediaries that ignore `Cache-Control`.
pub fn no_store_headers(headers: &mut HeaderMap) {
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate, private"),
    );
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
}

/// Convert an `anyhow::Error` into a 500 response. The detailed error
/// (with chain) is logged server-side; clients only see a generic message
/// so we don't leak internal paths, SQL state, or filesystem layout.
pub fn map_err(e: anyhow::Error) -> (StatusCode, Json<Value>) {
    crate::error!("internal error: {:#}", e);
    api_err(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Internal server error",
    )
}

/// Shorthand: 200 OK with `{ "success": true }`.
pub fn ok_success() -> Json<Value> {
    Json(json!({ "success": true }))
}

/// Build the complete application router (API + static files).
pub fn build_router(state: AppState) -> Router {
    let api = Router::new()
        // Information & interface
        .route("/information", crate::http::routing::get(routes::information))
        .route("/interface", crate::http::routing::get(routes::interface_info))
        // Activity history
        .route(
            "/activity/heatmap",
            crate::http::routing::get(activity::heatmap),
        )
        .route("/activity", crate::http::routing::delete(activity::purge))
        // Session
        .route(
            "/session",
            crate::http::routing::get(session::get_session)
                .post(session::create_session)
                .delete(session::delete_session),
        )
        // Setup
        .route("/setup/2", crate::http::routing::post(setup::setup_step2))
        .route(
            "/setup/4",
            crate::http::routing::get(setup::setup_step4_get)
                .post(setup::setup_step4_post),
        )
        // Clients
        .route(
            "/client",
            crate::http::routing::get(clients::list_clients)
                .post(clients::create_client),
        )
        .route(
            "/client/:id",
            crate::http::routing::get(clients::get_client)
                .post(clients::update_client)
                .delete(clients::delete_client),
        )
        .route(
            "/client/:id/configuration",
            crate::http::routing::get(clients::client_configuration),
        )
        .route(
            "/client/:id/qrcode.svg",
            crate::http::routing::get(clients::client_qrcode),
        )
        .route(
            "/client/:id/enable",
            crate::http::routing::post(clients::enable_client),
        )
        .route(
            "/client/:id/disable",
            crate::http::routing::post(clients::disable_client),
        )
        .route(
            "/client/:id/rotateKey",
            crate::http::routing::post(clients::rotate_client_key),
        )
        .route(
            "/client/:id/generateOneTimeLink",
            crate::http::routing::post(clients::generate_one_time_link),
        )
        // Admin
        .route(
            "/admin/general",
            crate::http::routing::get(admin::get_general)
                .post(admin::update_general),
        )
        .route(
            "/admin/hooks",
            crate::http::routing::get(admin::get_hooks).post(admin::update_hooks),
        )
        .route("/admin/ip-info", crate::http::routing::get(admin::get_ip_info))
        .route(
            "/admin/userconfig",
            crate::http::routing::get(admin::get_userconfig)
                .post(admin::update_userconfig),
        )
        .route(
            "/admin/interface",
            crate::http::routing::get(admin::get_interface)
                .post(admin::update_interface),
        )
        .route(
            "/admin/interface/cidr",
            crate::http::routing::post(admin::change_cidr),
        )
        .route(
            "/admin/interface/restart",
            crate::http::routing::post(admin::restart_interface),
        )
        // Xray (Browsing mode) — admin
        .route(
            "/admin/xray/inbound",
            crate::http::routing::get(xray::get_inbound).post(xray::update_inbound),
        )
        .route(
            "/admin/xray/inbound/regenerate-keys",
            crate::http::routing::post(xray::regenerate_keys),
        )
        .route(
            "/admin/xray/inbound/regenerate-xhttp-path",
            crate::http::routing::post(xray::regenerate_xhttp_path),
        )
        .route(
            "/admin/xray/inbound/probe-dest",
            crate::http::routing::post(xray::probe_dest),
        )
        .route(
            "/admin/xray/inbound/dest-candidates",
            crate::http::routing::get(xray::dest_candidates),
        )
        .route(
            "/admin/xray/status",
            crate::http::routing::get(xray::supervisor_status),
        )
        .route(
            "/admin/xray/restart",
            crate::http::routing::post(xray::restart),
        )
        // Bundled DNS stack (dnscrypt-proxy + tor + PTs) — admin
        .route(
            "/admin/dns/bundle",
            crate::http::routing::get(dns::get_bundle).post(dns::update_bundle),
        )
        .route(
            "/admin/dns/status",
            crate::http::routing::get(dns::supervisor_status),
        )
        .route(
            "/admin/dns/restart",
            crate::http::routing::post(dns::restart),
        )
        // Telegram MTProxy (telemt) — admin inbound + supervisor
        .route(
            "/admin/mtproxy/inbound",
            crate::http::routing::get(mtproxy::get_inbound).post(mtproxy::update_inbound),
        )
        .route(
            "/admin/mtproxy/status",
            crate::http::routing::get(mtproxy::supervisor_status),
        )
        .route(
            "/admin/mtproxy/stats",
            crate::http::routing::get(mtproxy::stats),
        )
        .route(
            "/admin/mtproxy/restart",
            crate::http::routing::post(mtproxy::restart),
        )
        // Telegram MTProxy — admin user CRUD
        .route(
            "/admin/mtproxy/users",
            crate::http::routing::get(mtproxy::list_users).post(mtproxy::create_user),
        )
        .route(
            "/admin/mtproxy/users/:username",
            crate::http::routing::get(mtproxy::get_user)
                .post(mtproxy::update_user)
                .delete(mtproxy::delete_user),
        )
        .route(
            "/admin/mtproxy/users/:username/rotate-secret",
            crate::http::routing::post(mtproxy::rotate_secret),
        )
        .route(
            "/admin/mtproxy/users/:username/qrcode.svg",
            crate::http::routing::get(mtproxy::user_qrcode),
        )
        // DPI-imitation proxy (in-process, fronts the AmneziaWG UDP port)
        .route(
            "/admin/proxy/settings",
            crate::http::routing::get(proxy::get_settings).post(proxy::update_settings),
        )
        .route(
            "/admin/proxy/status",
            crate::http::routing::get(proxy::supervisor_status),
        )
        .route(
            "/admin/proxy/restart",
            crate::http::routing::post(proxy::restart),
        )
        // QQ-Tunnel UDP-over-DNS transport (in-process, side-channel to AWG)
        .route(
            "/admin/qqdns/settings",
            crate::http::routing::get(qqdns::get_settings).post(qqdns::update_settings),
        )
        .route(
            "/admin/qqdns/status",
            crate::http::routing::get(qqdns::supervisor_status),
        )
        .route("/admin/qqdns/restart", crate::http::routing::post(qqdns::restart))
        .route(
            "/admin/qqdns/client-config",
            crate::http::routing::get(qqdns::client_config),
        )
        // MasterDnsVPN (DNS-tunnel mode) — admin inbound + supervisor
        .route(
            "/admin/mdnsvpn/inbound",
            crate::http::routing::get(mdnsvpn::get_inbound).post(mdnsvpn::update_inbound),
        )
        .route(
            "/admin/mdnsvpn/inbound/regenerate-key",
            crate::http::routing::post(mdnsvpn::regenerate_key),
        )
        .route(
            "/admin/mdnsvpn/status",
            crate::http::routing::get(mdnsvpn::supervisor_status),
        )
        .route(
            "/admin/mdnsvpn/restart",
            crate::http::routing::post(mdnsvpn::restart),
        )
        // MasterDnsVPN clients
        .route(
            "/mdnsvpn/clients",
            crate::http::routing::get(mdnsvpn::list_clients).post(mdnsvpn::create_client),
        )
        .route(
            "/mdnsvpn/clients/:id",
            crate::http::routing::get(mdnsvpn::get_client)
                .post(mdnsvpn::update_client)
                .delete(mdnsvpn::delete_client),
        )
        .route(
            "/mdnsvpn/clients/:id/config.toml",
            crate::http::routing::get(mdnsvpn::client_config_toml),
        )
        .route(
            "/mdnsvpn/clients/:id/resolvers.txt",
            crate::http::routing::get(mdnsvpn::client_resolvers_txt),
        )
        .route(
            "/mdnsvpn/clients/:id/config.json",
            crate::http::routing::get(mdnsvpn::client_config_json),
        )
        .route(
            "/mdnsvpn/clients/:id/share",
            crate::http::routing::get(mdnsvpn::client_share_url),
        )
        .route(
            "/mdnsvpn/clients/:id/bundle.zip",
            crate::http::routing::get(mdnsvpn::client_bundle_zip),
        )
        .route(
            "/mdnsvpn/clients/:id/qrcode.svg",
            crate::http::routing::get(mdnsvpn::client_qrcode),
        )
        // Xray clients
        .route(
            "/xray/clients",
            crate::http::routing::get(xray::list_clients).post(xray::create_client),
        )
        .route(
            "/xray/clients/:id",
            crate::http::routing::get(xray::get_client)
                .post(xray::update_client)
                .delete(xray::delete_client),
        )
        .route(
            "/xray/clients/:id/share",
            crate::http::routing::get(xray::client_share_url),
        )
        .route(
            "/xray/clients/:id/qrcode.svg",
            crate::http::routing::get(xray::client_qrcode),
        )
        .route(
            "/xray/clients/:id/json",
            crate::http::routing::get(xray::client_amnezia_json),
        )
        // Me (current user)
        .route("/me", crate::http::routing::post(session::update_me))
        .route("/me/password", crate::http::routing::post(session::change_password))
        .route("/me/totp", crate::http::routing::post(session::toggle_totp));

    let api = api.with_state(state.clone());

    let root = Router::new()
        .route("/cnf/:oneTimeLink", crate::http::routing::get(routes::one_time_link))
        .route("/metrics/json", crate::http::routing::get(routes::metrics_json))
        .route(
            "/metrics/prometheus",
            crate::http::routing::get(routes::metrics_prometheus),
        )
        .route("/health", crate::http::routing::get(|| async { "OK" }))
        .nest("/api", api);
    // Note: no CorsLayer is attached. The single-origin admin UI is served
    // from the same listener as the API, so cross-origin requests must not
    // succeed. Adding `CorsLayer::permissive()` here would expose every
    // unauthenticated endpoint (e.g. /api/information) to any web origin.
    root
}

// ---------------------------------------------------------------------------
// Session helpers used across sub-modules
// ---------------------------------------------------------------------------

/// Extract a session user from the request cookie jar.  Returns 401 when
/// there is no valid session.
pub fn require_auth(
    jar: &crate::http::CookieJar,
    state: &AppState,
) -> Result<crate::db::User, (StatusCode, Json<Value>)> {
    let token = jar
        .get("awg_session")
        .map(|c| c.value().to_string())
        .ok_or_else(|| api_err(StatusCode::UNAUTHORIZED, "Not authenticated"))?;

    let sessions = state.sessions.lock().map_err(|e| {
        api_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Session lock: {e}"),
        )
    })?;

    let session = sessions
        .get(&token)
        .ok_or_else(|| api_err(StatusCode::UNAUTHORIZED, "Session expired"))?;

    // Check expiry against config
    let general = crate::db::get_general().map_err(map_err)?;
    if session.is_expired(general.session_timeout) {
        return Err(api_err(StatusCode::UNAUTHORIZED, "Session expired"));
    }

    crate::db::get_user(session.user_id).map_err(map_err)
}

/// Drop every session belonging to `user_id`, optionally sparing one token.
///
/// Called when a credential changes. Changing a password (or disabling 2FA) is
/// the standard response to a suspected compromise, so leaving previously
/// issued sessions valid would mean the action does not actually evict an
/// attacker holding a stolen cookie. The caller's own session is spared so the
/// user is not logged out of the tab they just used.
pub fn revoke_user_sessions(state: &AppState, user_id: i64, keep_token: Option<&str>) {
    if let Ok(mut sessions) = state.sessions.lock() {
        sessions.retain(|token, s| {
            s.user_id != user_id || keep_token.is_some_and(|k| k == token)
        });
    }
}

/// The caller's raw session token, when the request carried one.
pub fn session_token(jar: &crate::http::CookieJar) -> Option<String> {
    jar.get("awg_session").map(|c| c.value().to_string())
}

/// Convert a camelCase JSON key to snake_case database column name.
pub fn to_snake_case(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 4);
    for (i, c) in s.chars().enumerate() {
        if c.is_uppercase() {
            if i > 0 {
                result.push('_');
            }
            for ch in c.to_lowercase() {
                result.push(ch);
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// Convert a JSON value to its string representation for `db::UpdateMap`.
/// Returns `None` for null values (which means "skip this field").
pub fn value_to_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(if *b { "1".into() } else { "0".into() }),
        Value::Array(arr) => {
            // Serialize arrays as JSON – used for allowedIps, dns, etc.
            Some(serde_json::to_string(arr).unwrap_or_default())
        }
        Value::Null => None,
        Value::Object(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn session(age_secs: u64) -> SessionData {
        SessionData {
            user_id: 1,
            username: "u".into(),
            role: 0,
            created_at: now().saturating_sub(age_secs),
        }
    }

    #[test]
    fn session_is_expired_past_timeout() {
        let s = session(100);
        assert!(s.is_expired(50), "100s-old session exceeds a 50s timeout");
        assert!(!s.is_expired(200), "100s-old session is within a 200s timeout");
    }

    #[test]
    fn prune_removes_only_expired_sessions() {
        let state = AppState::new();
        {
            let mut m = state.sessions.lock().unwrap();
            m.insert("fresh".into(), session(1));
            m.insert("stale".into(), session(10_000));
        }
        prune_expired_sessions(&state, 3600);
        let m = state.sessions.lock().unwrap();
        assert!(m.contains_key("fresh"));
        assert!(!m.contains_key("stale"));
    }
}
