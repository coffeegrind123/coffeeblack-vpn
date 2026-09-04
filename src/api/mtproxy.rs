//! REST endpoints for "Telegram MTProxy" — bundled telemt server.
//!
//! | Method | Path                                       | Auth   | Purpose                                |
//! |--------|--------------------------------------------|--------|----------------------------------------|
//! | GET    | /api/admin/mtproxy/inbound                 | admin  | Read singleton mtproxy_inbound row     |
//! | POST   | /api/admin/mtproxy/inbound                 | admin  | Update inbound + reconcile supervisor  |
//! | GET    | /api/admin/mtproxy/status                  | admin  | Supervisor status snapshot             |
//! | GET    | /api/admin/mtproxy/stats                   | admin  | Live stats from telemt /v1/stats/*     |
//! | POST   | /api/admin/mtproxy/restart                 | admin  | Force re-spawn                         |
//! | GET    | /api/admin/mtproxy/users                   | admin  | List MTProxy users (with rendered links) |
//! | POST   | /api/admin/mtproxy/users                   | admin  | Create user (auto-gen 32-hex secret)   |
//! | GET    | /api/admin/mtproxy/users/:username         | admin  | Read one user                          |
//! | POST   | /api/admin/mtproxy/users/:username         | admin  | Update user (ad_tag, enabled)          |
//! | DELETE | /api/admin/mtproxy/users/:username         | admin  | Delete user                            |
//! | POST   | /api/admin/mtproxy/users/:username/rotate-secret | admin | Rotate a user's secret           |
//!
//! Operator authentication is enforced at our edge — telemt's own API
//! stays bound to `127.0.0.1:9091` with whitelist `127.0.0.1/32 ::1/128`
//! per the generated config.toml.
//!
//! Awg-easy-rs is the durable source of truth for the user roster.
//! Every CRUD here writes the DB first, then drives the live telemt
//! through `mtproxy::client`. On startup or config change, the
//! supervisor's user-reconciler converges live state to DB state.

use crate::http::{Path, Query, State};
use crate::http::{header, HeaderMap, StatusCode};
use crate::http::IntoResponse;
use crate::http::Json;
use crate::http::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};

use super::admin::require_admin;
use super::{api_err, map_err, no_store_headers, ok_success, value_to_string, AppState};
use crate::db;
use crate::mtproxy;

// ---------------------------------------------------------------------------
// GET /api/admin/mtproxy/inbound
// ---------------------------------------------------------------------------

pub async fn get_inbound(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    let i = db::get_mtproxy_inbound().map_err(map_err)?;
    Ok(Json(json!({
        "id": i.id,
        "port": i.port,
        "publicHost": i.public_host,
        "publicPort": i.public_port,
        "tlsDomain": i.tls_domain,
        "maskEnabled": i.mask_enabled,
        "modesClassic": i.modes_classic,
        "modesSecure": i.modes_secure,
        "modesTls": i.modes_tls,
        "useMiddleProxy": i.use_middle_proxy,
        "adTag": i.ad_tag,
        "additionalConfig": i.additional_config,
        "enabled": i.enabled,
        "isBundled": mtproxy::is_bundled(),
        "telemtVersion": mtproxy::TELEMT_VERSION,
        "telemtSha256": mtproxy::TELEMT_SHA256,
    })))
}

// ---------------------------------------------------------------------------
// POST /api/admin/mtproxy/inbound
// ---------------------------------------------------------------------------

pub async fn update_inbound(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;

    let mut fields = db::UpdateMap::new();
    if let Value::Object(map) = &body {
        // camelCase JSON → snake_case DB columns. Mirrors the dns/xray
        // pattern. Booleans get value_to_string'd into "0"/"1" by the
        // shared helper.
        let scalars: &[(&str, &str)] = &[
            ("port", "port"),
            ("publicHost", "public_host"),
            ("publicPort", "public_port"),
            ("tlsDomain", "tls_domain"),
            ("maskEnabled", "mask_enabled"),
            ("modesClassic", "modes_classic"),
            ("modesSecure", "modes_secure"),
            ("modesTls", "modes_tls"),
            ("useMiddleProxy", "use_middle_proxy"),
            ("adTag", "ad_tag"),
            ("additionalConfig", "additional_config"),
            ("enabled", "enabled"),
        ];
        for (json_key, db_key) in scalars {
            if let Some(val) = map.get(*json_key) {
                if let Some(s) = value_to_string(val) {
                    fields.insert(db_key.to_string(), s);
                }
            }
        }

        // Cheap server-side validation for the values most likely to
        // get the supervisor stuck. Telemt itself revalidates; doing it
        // here means the operator sees a clean 4xx on the admin POST
        // instead of a "telemt crashed" status bubble later.
        if let Some(port) = fields.get("port") {
            if let Ok(n) = port.parse::<i64>() {
                if !(1..=65535).contains(&n) {
                    return Err(bad_request(format!(
                        "port must be in 1..=65535, got {n}"
                    )));
                }
            }
        }
        if let Some(public_port) = fields.get("public_port") {
            if let Ok(n) = public_port.parse::<i64>() {
                if n != 0 && !(1..=65535).contains(&n) {
                    return Err(bad_request(format!(
                        "publicPort must be 0 (= use port) or 1..=65535, got {n}"
                    )));
                }
            }
        }
        if let Some(ad_tag) = fields.get("ad_tag") {
            if !ad_tag.trim().is_empty() {
                if let Err(e) = mtproxy::config::validate_hex32("adTag", ad_tag) {
                    return Err(bad_request(e.to_string()));
                }
            }
        }
        if let Some(domain) = fields.get("tls_domain") {
            let dom = domain.trim();
            if !dom.is_empty()
                && (dom.contains(' ')
                    || dom.contains('\t')
                    || dom.starts_with('.')
                    || dom.ends_with('.'))
            {
                return Err(bad_request(format!(
                    "tlsDomain {dom:?} doesn't look like a hostname"
                )));
            }
        }
    }

    if !fields.is_empty() {
        db::update_mtproxy_inbound(&fields).map_err(map_err)?;
    }

    // Reconcile supervisor with new DB state. Non-fatal — admin still
    // gets a 200 even if telemt fails to spawn (the status endpoint
    // will surface the reason).
    #[cfg(telemt_bundled)]
    if let Err(e) = crate::mtproxy::supervisor::ensure_running().await {
        crate::warn!(error = ?e, "MTProxy supervisor reconcile failed after admin update");
    }

    Ok(ok_success())
}

// ---------------------------------------------------------------------------
// GET /api/admin/mtproxy/status
// ---------------------------------------------------------------------------

pub async fn supervisor_status(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    Ok(Json(status_payload().await))
}

#[cfg(telemt_bundled)]
async fn status_payload() -> Value {
    let s = crate::mtproxy::supervisor::status().await;
    serde_json::to_value(s).unwrap_or_else(|_| json!({"state": "unknown"}))
}

#[cfg(not(telemt_bundled))]
async fn status_payload() -> Value {
    json!({
        "state": "disabled",
        "reason": "telemt was not compiled into this build (cfg(telemt_bundled) is off)",
    })
}

// ---------------------------------------------------------------------------
// GET /api/admin/mtproxy/stats
// ---------------------------------------------------------------------------

pub async fn stats(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    // Both calls go to the same loopback API; we issue them
    // sequentially because telemt's hyper server's localhost RTT is
    // sub-millisecond — concurrency would buy nothing and complicate
    // error handling. If telemt isn't running the calls error out and
    // we report "unavailable" rather than 500.
    let summary = crate::mtproxy::client::stats_summary().await.ok();
    let users = crate::mtproxy::client::stats_users().await.ok();
    let system = crate::mtproxy::client::system_info().await.ok();
    Ok(Json(json!({
        "summary": summary,
        "users": users,
        "system": system,
        "available": summary.is_some(),
    })))
}

// ---------------------------------------------------------------------------
// POST /api/admin/mtproxy/restart
// ---------------------------------------------------------------------------

pub async fn restart(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;

    #[cfg(telemt_bundled)]
    {
        if let Err(e) = crate::mtproxy::supervisor::restart().await {
            return Err(map_err(e));
        }
    }
    #[cfg(not(telemt_bundled))]
    {
        return Err((
            StatusCode::PRECONDITION_FAILED,
            Json(json!({
                "error": "telemt was not compiled into this build",
            })),
        ));
    }

    #[allow(unreachable_code)]
    Ok(ok_success())
}

// ---------------------------------------------------------------------------
// GET /api/admin/mtproxy/users
// ---------------------------------------------------------------------------

pub async fn list_users(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;

    let db_rows = db::list_mtproxy_users().map_err(map_err)?;
    // Telemt computes the tg:// links itself (per its src/api/users.rs
    // `build_user_links`). We try to fetch them so the admin UI can
    // display them; on failure we fall through to a links-less response
    // — the operator can copy the secret manually and build the link.
    let live_users = crate::mtproxy::client::list_users().await.ok();
    let live_map = live_users
        .as_ref()
        .map(extract_user_map)
        .unwrap_or_default();

    let entries: Vec<Value> = db_rows
        .iter()
        .map(|u| {
            let live = live_map.get(&u.username);
            json!({
                "id": u.id,
                "userId": u.user_id,
                "username": u.username,
                "secret": u.secret_hex,
                "adTag": u.ad_tag,
                "enabled": u.enabled,
                "createdAt": u.created_at,
                "updatedAt": u.updated_at,
                // Pre-rendered links from telemt — null when telemt is
                // down or the user isn't in its store yet (the
                // reconciler hasn't run for fresh DB rows). UI handles
                // the null case by falling back to a client-side
                // link-builder.
                "links": live.and_then(|v| v.get("links").cloned()),
            })
        })
        .collect();

    Ok(Json(json!({
        "users": entries,
        "telemtAvailable": live_users.is_some(),
    })))
}

// ---------------------------------------------------------------------------
// POST /api/admin/mtproxy/users
// ---------------------------------------------------------------------------

pub async fn create_user(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;

    let map = body
        .as_object()
        .ok_or_else(|| bad_request("body must be a JSON object".to_string()))?;
    let username = map
        .get("username")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| bad_request("username is required".to_string()))?;
    validate_username(&username)?;

    // Operator can supply their own 32-hex secret (e.g. when migrating
    // a user from another proxy); otherwise we generate a fresh one.
    let secret_hex = match map.get("secret").and_then(|v| v.as_str()) {
        Some(s) if !s.trim().is_empty() => {
            mtproxy::config::validate_hex32("secret", s).map_err(|e| bad_request(e.to_string()))?;
            s.trim().to_lowercase()
        }
        _ => generate_secret_hex(),
    };

    let ad_tag = map
        .get("adTag")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    if let Some(tag) = &ad_tag {
        mtproxy::config::validate_hex32("adTag", tag).map_err(|e| bad_request(e.to_string()))?;
    }

    let user_id = map.get("userId").and_then(|v| v.as_i64());
    let enabled = map.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);

    let id = db::create_mtproxy_user(&db::CreateMtproxyUserParams {
        user_id,
        inbound_id: "mtproxy0".into(),
        username: username.clone(),
        secret_hex: secret_hex.clone(),
        ad_tag: ad_tag.clone(),
        enabled,
    })
    .map_err(map_err)?;

    // Push to live telemt. Best-effort — if telemt is down the
    // reconciler will pick this up next time it runs. The DB write
    // already succeeded so the user is durably recorded.
    #[cfg(telemt_bundled)]
    {
        let req = crate::mtproxy::client::CreateUser {
            username: &username,
            secret: &secret_hex,
            ad_tag: ad_tag.as_deref(),
        };
        match crate::mtproxy::client::create_user(&req).await {
            Ok(_) => {}
            Err(e) => crate::warn!(
                username = %username,
                error = ?e,
                "MTProxy create_user: live push failed; reconciler will retry"
            ),
        }
    }

    Ok(Json(json!({
        "id": id,
        "username": username,
        "secret": secret_hex,
        "adTag": ad_tag,
        "enabled": enabled,
    })))
}

// ---------------------------------------------------------------------------
// GET /api/admin/mtproxy/users/:username
// ---------------------------------------------------------------------------

pub async fn get_user(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(username): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    let u = db::get_mtproxy_user_by_username(&username).map_err(map_err)?;
    let live = crate::mtproxy::client::get_user(&username).await.ok().flatten();
    Ok(Json(json!({
        "id": u.id,
        "userId": u.user_id,
        "username": u.username,
        "secret": u.secret_hex,
        "adTag": u.ad_tag,
        "enabled": u.enabled,
        "createdAt": u.created_at,
        "updatedAt": u.updated_at,
        "links": live.as_ref().and_then(|v| v.get("links").cloned()),
        "stats": live.as_ref().and_then(|v| v.get("stats").cloned()),
    })))
}

// ---------------------------------------------------------------------------
// POST /api/admin/mtproxy/users/:username
// ---------------------------------------------------------------------------

pub async fn update_user(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(username): Path<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;

    let mut fields = db::UpdateMap::new();
    // new_ad_tag / new_enabled feed the live telemt PATCH below; both the
    // bindings and their assignments only exist when that branch is compiled.
    #[cfg(telemt_bundled)]
    let mut new_ad_tag: Option<Option<String>> = None;
    #[cfg(telemt_bundled)]
    let mut new_enabled: Option<bool> = None;

    if let Value::Object(map) = &body {
        if let Some(v) = map.get("adTag") {
            // adTag is nullable — null clears the override.
            let parsed: Option<String> = match v {
                Value::Null => None,
                Value::String(s) if s.trim().is_empty() => None,
                Value::String(s) => Some(s.trim().to_string()),
                _ => {
                    return Err(bad_request("adTag must be a string or null".into()));
                }
            };
            if let Some(tag) = &parsed {
                mtproxy::config::validate_hex32("adTag", tag)
                    .map_err(|e| bad_request(e.to_string()))?;
            }
            fields.insert(
                "ad_tag".into(),
                parsed.clone().unwrap_or_default(), // empty string maps to NULL via UpdateMap? actually maps to "" — telemt treats "" as no-tag
            );
            #[cfg(telemt_bundled)]
            {
                new_ad_tag = Some(parsed);
            }
        }
        if let Some(v) = map.get("enabled").and_then(|v| v.as_bool()) {
            fields.insert("enabled".into(), if v { "1".into() } else { "0".into() });
            #[cfg(telemt_bundled)]
            {
                new_enabled = Some(v);
            }
        }
        if let Some(v) = map.get("userId") {
            if let Some(s) = value_to_string(v) {
                fields.insert("user_id".into(), s);
            }
        }
    }

    if !fields.is_empty() {
        db::update_mtproxy_user(&username, &fields).map_err(map_err)?;
    }

    // Mirror the change into telemt. We only PATCH the things we
    // actually changed — see comment in supervisor.reconcile_users on
    // why we avoid no-op patches.
    #[cfg(telemt_bundled)]
    {
        let patch = crate::mtproxy::client::PatchUser {
            secret: None,
            ad_tag: new_ad_tag.as_ref().map(|o| o.as_deref().unwrap_or("")),
            enabled: new_enabled,
        };
        // Only call PATCH if something is set.
        if patch.ad_tag.is_some() || patch.enabled.is_some() {
            if let Err(e) = crate::mtproxy::client::patch_user(&username, &patch).await {
                crate::warn!(
                    username = %username,
                    error = ?e,
                    "MTProxy update_user: live PATCH failed; reconciler will retry"
                );
            }
        }
    }

    Ok(ok_success())
}

// ---------------------------------------------------------------------------
// DELETE /api/admin/mtproxy/users/:username
// ---------------------------------------------------------------------------

pub async fn delete_user(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(username): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    db::delete_mtproxy_user(&username).map_err(map_err)?;

    #[cfg(telemt_bundled)]
    {
        if let Err(e) = crate::mtproxy::client::delete_user(&username).await {
            crate::warn!(
                username = %username,
                error = ?e,
                "MTProxy delete_user: live DELETE failed; reconciler will retry"
            );
        }
    }

    Ok(ok_success())
}

// ---------------------------------------------------------------------------
// POST /api/admin/mtproxy/users/:username/rotate-secret
// ---------------------------------------------------------------------------

pub async fn rotate_secret(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(username): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    // Verify the user exists durably before issuing a rotate. A bare
    // 404 from telemt is harder to debug than "user not in DB".
    let _ = db::get_mtproxy_user_by_username(&username).map_err(map_err)?;
    let new_secret = generate_secret_hex();

    let mut fields = db::UpdateMap::new();
    fields.insert("secret_hex".into(), new_secret.clone());
    db::update_mtproxy_user(&username, &fields).map_err(map_err)?;

    #[cfg(telemt_bundled)]
    {
        let patch = crate::mtproxy::client::PatchUser {
            secret: Some(&new_secret),
            ad_tag: None,
            enabled: None,
        };
        if let Err(e) = crate::mtproxy::client::patch_user(&username, &patch).await {
            crate::warn!(
                username = %username,
                error = ?e,
                "MTProxy rotate_secret: live PATCH failed; reconciler will retry"
            );
        }
    }

    Ok(Json(json!({
        "username": username,
        "secret": new_secret,
    })))
}

// ---------------------------------------------------------------------------
// GET /api/admin/mtproxy/users/:username/qrcode.svg?mode=tls|secure|classic
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct QrQuery {
    /// `tls` (Fake-TLS) | `secure` (`dd`-prefix) | `classic`. Defaults to
    /// the most DPI-resistant one available on the user.
    #[serde(default)]
    pub mode: Option<String>,
}

pub async fn user_qrcode(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(username): Path<String>,
    Query(q): Query<QrQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    // Verify the user exists durably before hitting telemt.
    let _ = db::get_mtproxy_user_by_username(&username).map_err(map_err)?;

    // Fetch the live link from telemt — telemt's link builder bakes
    // public_host / public_port / tls_domain into the URL, so we don't
    // have to reimplement it here.
    let live = crate::mtproxy::client::get_user(&username)
        .await
        .map_err(|e| {
            api_err(
                StatusCode::SERVICE_UNAVAILABLE,
                &format!("telemt API unavailable: {e}"),
            )
        })?
        .ok_or_else(|| {
            api_err(
                StatusCode::NOT_FOUND,
                "user not found in telemt — supervisor reconciler hasn't pushed it yet",
            )
        })?;

    let url = pick_link(&live, q.mode.as_deref()).ok_or_else(|| {
        api_err(
            StatusCode::PRECONDITION_FAILED,
            "no share link available — enable at least one MTProxy mode (TLS / Secure / Classic)",
        )
    })?;

    let svg = crate::qr::generate_qr_svg(&url)
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("qr: {e}")))?;
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "image/svg+xml".parse().unwrap());
    // The QR encodes the tg:// proxy link, i.e. the user's MTProxy secret.
    no_store_headers(&mut headers);
    Ok((StatusCode::OK, headers, svg))
}

/// Pick the preferred share link from telemt's `links` block.
/// Resolution order: explicit `mode` query param → fake-TLS → secure → classic.
fn pick_link(live: &Value, mode_hint: Option<&str>) -> Option<String> {
    let links = live.get("links")?;
    let take_first = |key: &str| -> Option<String> {
        links
            .get(key)
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    };
    if let Some(mode) = mode_hint {
        let key = match mode {
            "tls" | "fake-tls" | "ee" => "tls",
            "secure" | "dd" => "secure",
            "classic" => "classic",
            _ => return None,
        };
        return take_first(key);
    }
    take_first("tls")
        .or_else(|| take_first("secure"))
        .or_else(|| take_first("classic"))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn bad_request(msg: String) -> (StatusCode, Json<Value>) {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": msg })))
}

/// Validate an MTProxy username. Telemt itself accepts a wider charset
/// than we want exposed via the admin UI — we restrict to a safe
/// subset (alphanumeric, dash, underscore, dot) to keep URLs sane and
/// avoid shell-injection-style fun if the username ever ends up in a
/// log message that gets re-parsed.
fn validate_username(name: &str) -> Result<(), (StatusCode, Json<Value>)> {
    if name.is_empty() || name.len() > 64 {
        return Err(bad_request(format!(
            "username must be 1..=64 chars (got {})",
            name.len()
        )));
    }
    let ok = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if !ok {
        return Err(bad_request(
            "username may contain only ASCII letters, digits, '-', '_', '.'".into(),
        ));
    }
    Ok(())
}

/// 32-char lowercase-hex MTProxy secret (16 random bytes). Standard
/// MTProto secret format — same length and encoding @MTProxybot uses.
fn generate_secret_hex() -> String {
    let mut bytes = [0u8; 16];
    crate::rng::fill(&mut bytes);
    crate::encoding::hex_encode(bytes)
}

/// Pull `name → entry` out of telemt's `/v1/users` response. v3.4.11
/// wraps the array in `{ok, data, revision}`; older / future versions
/// might use a bare array or `{users: [...]}`. Tolerate all three.
fn extract_user_map(value: &Value) -> std::collections::HashMap<String, Value> {
    let mut map = std::collections::HashMap::new();
    let array_opt: Option<&Vec<Value>> = if let Value::Array(arr) = value {
        Some(arr)
    } else if let Value::Object(obj) = value {
        obj.get("data")
            .and_then(|v| v.as_array())
            .or_else(|| obj.get("users").and_then(|v| v.as_array()))
    } else {
        None
    };
    if let Some(arr) = array_opt {
        for entry in arr {
            if let Some(name) = entry.get("username").and_then(|v| v.as_str()) {
                map.insert(name.to_string(), entry.clone());
            }
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_username_accepts_safe_chars() {
        validate_username("alice").unwrap();
        validate_username("alice.bob").unwrap();
        validate_username("user_42").unwrap();
        validate_username("a-b-c").unwrap();
    }

    #[test]
    fn validate_username_rejects_unsafe_chars() {
        assert!(validate_username("alice bob").is_err());
        assert!(validate_username("alice/bob").is_err());
        assert!(validate_username("alice;rm-rf").is_err());
        assert!(validate_username("").is_err());
        assert!(validate_username(&"a".repeat(65)).is_err());
    }

    #[test]
    fn generate_secret_hex_format() {
        let s = generate_secret_hex();
        assert_eq!(s.len(), 32);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(s.chars().all(|c| !c.is_ascii_uppercase()));
        // Two successive calls should differ overwhelmingly often.
        let t = generate_secret_hex();
        assert_ne!(s, t);
    }
}
