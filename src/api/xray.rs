//! REST endpoints for "Browsing mode" — Xray VLESS+Reality.
//!
//! Two transports — `transport: "tcp"` (classic Vision) and `"xhttp"`
//! (amnezia-client/#2339; HTTP framing over a secret path). The path is
//! generated server-side and persisted on the inbound row.
//!
//! | Method | Path                                       | Auth   | Purpose                       |
//! |--------|--------------------------------------------|--------|-------------------------------|
//! | GET    | /api/admin/xray/inbound                    | admin  | Read singleton inbound config |
//! | POST   | /api/admin/xray/inbound                    | admin  | Update inbound (port/dest/…)  |
//! | POST   | /api/admin/xray/inbound/regenerate-keys    | admin  | New x25519 keypair            |
//! | POST   | /api/admin/xray/inbound/regenerate-xhttp-path | admin | New random xhttp routing path |
//! | POST   | /api/admin/xray/inbound/probe-dest         | admin  | TLS probe a candidate dest    |
//! | GET    | /api/admin/xray/inbound/dest-candidates    | admin  | Curated dest list             |
//! | GET    | /api/admin/xray/status                     | admin  | Supervisor status snapshot    |
//! | POST   | /api/admin/xray/restart                    | admin  | Force re-spawn                |
//! | GET    | /api/xray/clients                          | auth   | List peers (own or all)       |
//! | POST   | /api/xray/clients                          | admin  | Create peer (auto-gen UUID)   |
//! | GET    | /api/xray/clients/:id                      | auth   | Read one peer                 |
//! | POST   | /api/xray/clients/:id                      | admin  | Update peer                   |
//! | DELETE | /api/xray/clients/:id                      | admin  | Delete peer                   |
//! | GET    | /api/xray/clients/:id/share                | auth   | vless:// URL                  |
//! | GET    | /api/xray/clients/:id/qrcode.svg           | auth   | QR of vless:// URL            |
//! | GET    | /api/xray/clients/:id/json                 | auth   | Amnezia-format JSON config    |

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};

use super::admin::require_admin;
use super::{
    api_err, map_err, no_store_headers, ok_success, require_auth, value_to_string, AppState,
};
use crate::db;
use crate::xray;

// ---------------------------------------------------------------------------
// GET /api/admin/xray/inbound
// ---------------------------------------------------------------------------

pub async fn get_inbound(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    let inbound = db::get_xray_inbound().map_err(map_err)?;
    let server_names: Value =
        serde_json::from_str(&inbound.server_names).unwrap_or_else(|_| json!([]));
    Ok(Json(json!({
        "id": inbound.id,
        "port": inbound.port,
        "dest": inbound.dest,
        "serverNames": server_names,
        // Don't ship the private key to the browser — only the public
        // half is needed for the share-link builder. Operators who need
        // the private key can pull it out of the DB directly.
        "publicKey": inbound.public_key,
        "hasPrivateKey": !inbound.private_key.is_empty(),
        "fingerprintDefault": inbound.fingerprint_default,
        "transport": inbound.transport,
        // The path itself is not a long-term secret in the same sense as
        // the private key (a network-active attacker who can sniff the
        // first request to the inbound learns it), but we still surface
        // it only via an explicit field so the admin UI can choose to
        // hide it from non-share contexts.
        "xhttpPath": inbound.xhttp_path,
        "additionalConfig": inbound.additional_config,
        "enabled": inbound.enabled,
        "xrayVersion": xray_version_string(),
    })))
}

#[cfg(xray_bundled)]
fn xray_version_string() -> &'static str {
    xray::runtime::XRAY_VERSION
}

#[cfg(not(xray_bundled))]
fn xray_version_string() -> &'static str {
    "not-bundled"
}

// ---------------------------------------------------------------------------
// POST /api/admin/xray/inbound
// ---------------------------------------------------------------------------

pub async fn update_inbound(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;

    let mut fields = db::UpdateMap::new();
    if let Value::Object(map) = &body {
        // Plain scalar fields — port/dest/fingerprintDefault/additionalConfig/enabled.
        let scalar = [
            ("port", "port"),
            ("dest", "dest"),
            ("fingerprintDefault", "fingerprint_default"),
            ("transport", "transport"),
            ("additionalConfig", "additional_config"),
            ("enabled", "enabled"),
        ];
        for (json_key, db_key) in &scalar {
            if let Some(v) = map.get(*json_key) {
                if let Some(s) = value_to_string(v) {
                    fields.insert(db_key.to_string(), s);
                }
            }
        }
        // serverNames is a JSON array stored as a JSON-encoded string.
        if let Some(v) = map.get("serverNames") {
            let s = serde_json::to_string(v).unwrap_or_default();
            fields.insert("server_names".into(), s);
        }
    }

    // Auto-generate the xhttp routing path the first time the operator
    // flips transport to xhttp. We do this in the same UpdateMap as the
    // transport switch itself so the row never lands in an inconsistent
    // state (transport='xhttp' with xhttp_path=''), which would cause
    // both the supervisor and the share-link builder to refuse work.
    if let Some(transport) = fields.get("transport") {
        if transport == "xhttp" {
            let current = db::get_xray_inbound().map_err(map_err)?;
            if current.xhttp_path.trim().is_empty() {
                fields.insert("xhttp_path".into(), xray::keys::generate_xhttp_path());
            }
        } else if transport == "tcp" {
            // Don't drop the persisted xhttp_path on transport='tcp' —
            // operators flipping back and forth (e.g. while debugging
            // client compat) get the same path on return without losing
            // the share links handed out earlier.
        }
    }

    if !fields.is_empty() {
        // Cheap server-side validation before commit.
        validate_inbound_update(&fields)?;
        db::update_xray_inbound(&fields).map_err(map_err)?;
    }

    // Reconcile after every mutation — toggling `enabled`, changing
    // `port`, etc. should take effect immediately.
    reconcile_supervisor().await;
    Ok(ok_success())
}

fn validate_inbound_update(fields: &db::UpdateMap) -> Result<(), (StatusCode, Json<Value>)> {
    if let Some(port) = fields.get("port") {
        let n: u32 = port
            .parse()
            .map_err(|_| api_err(StatusCode::BAD_REQUEST, "port must be an integer"))?;
        if !(1..=65535).contains(&n) {
            return Err(api_err(StatusCode::BAD_REQUEST, "port must be 1-65535"));
        }
    }
    if let Some(dest) = fields.get("dest") {
        if dest.trim().is_empty() {
            return Err(api_err(StatusCode::BAD_REQUEST, "dest must not be empty"));
        }
    }
    if let Some(server_names) = fields.get("server_names") {
        let parsed: Result<Vec<String>, _> = serde_json::from_str(server_names);
        match parsed {
            Ok(arr) if arr.is_empty() => {
                return Err(api_err(
                    StatusCode::BAD_REQUEST,
                    "serverNames must contain at least one entry",
                ));
            }
            Err(_) => {
                return Err(api_err(
                    StatusCode::BAD_REQUEST,
                    "serverNames must be a JSON array of strings",
                ));
            }
            _ => {}
        }
    }
    if let Some(transport) = fields.get("transport") {
        if transport != "tcp" && transport != "xhttp" {
            return Err(api_err(
                StatusCode::BAD_REQUEST,
                "transport must be 'tcp' or 'xhttp'",
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// POST /api/admin/xray/inbound/regenerate-keys
// ---------------------------------------------------------------------------

#[cfg(xray_bundled)]
pub async fn regenerate_keys(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    let kp = xray::keys::generate_x25519().await.map_err(map_err)?;
    db::update_xray_keypair(&kp.private_key, &kp.public_key).map_err(map_err)?;
    reconcile_supervisor().await;
    Ok(Json(json!({
        "publicKey": kp.public_key,
        // Private key intentionally omitted — it's now in the DB and
        // doesn't need to round-trip through the browser.
        "privateKeyStored": true,
    })))
}

#[cfg(not(xray_bundled))]
pub async fn regenerate_keys(
    State(_state): State<AppState>,
    _jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    Err(api_err(
        StatusCode::NOT_IMPLEMENTED,
        "Xray support not bundled in this build",
    ))
}

// ---------------------------------------------------------------------------
// POST /api/admin/xray/inbound/regenerate-xhttp-path
// ---------------------------------------------------------------------------
//
// Rotate the xhttp routing path. Any existing share links pointing at
// the old path stop working immediately — operators rotate when they
// suspect a path leak or as part of a periodic credential refresh. The
// generator doesn't depend on the bundled Xray binary, so this endpoint
// is available regardless of the `xray_bundled` cfg.

pub async fn regenerate_xhttp_path(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    let new_path = xray::keys::generate_xhttp_path();
    let mut fields = db::UpdateMap::new();
    fields.insert("xhttp_path".into(), new_path.clone());
    db::update_xray_inbound(&fields).map_err(map_err)?;
    reconcile_supervisor().await;
    Ok(Json(json!({ "xhttpPath": new_path })))
}

// ---------------------------------------------------------------------------
// POST /api/admin/xray/inbound/probe-dest
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ProbeRequest {
    pub dest: String,
    pub sni: String,
}

pub async fn probe_dest(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<ProbeRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    match xray::probe::probe_dest(&body.dest, &body.sni).await {
        Ok(report) => Ok(Json(serde_json::to_value(&report).unwrap_or(Value::Null))),
        Err(e) => Err(api_err(StatusCode::BAD_GATEWAY, &format!("probe failed: {e}"))),
    }
}

// ---------------------------------------------------------------------------
// GET /api/admin/xray/inbound/dest-candidates
// ---------------------------------------------------------------------------

pub async fn dest_candidates(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    Ok(Json(json!(xray::probe::curated_candidates())))
}

// ---------------------------------------------------------------------------
// GET /api/admin/xray/status
// ---------------------------------------------------------------------------

#[cfg(xray_bundled)]
pub async fn supervisor_status(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    let status = xray::supervisor::status().await;
    Ok(Json(serde_json::to_value(&status).unwrap_or(Value::Null)))
}

#[cfg(not(xray_bundled))]
pub async fn supervisor_status(
    State(_state): State<AppState>,
    _jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    Ok(Json(json!({
        "state": "disabled",
        "reason": "Xray support not bundled in this build",
    })))
}

// ---------------------------------------------------------------------------
// POST /api/admin/xray/restart
// ---------------------------------------------------------------------------

#[cfg(xray_bundled)]
pub async fn restart(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    xray::supervisor::stop().await.map_err(map_err)?;
    xray::supervisor::ensure_running().await.map_err(map_err)?;
    Ok(ok_success())
}

#[cfg(not(xray_bundled))]
pub async fn restart(
    State(_state): State<AppState>,
    _jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    Err(api_err(
        StatusCode::NOT_IMPLEMENTED,
        "Xray support not bundled in this build",
    ))
}

// ---------------------------------------------------------------------------
// Client CRUD
// ---------------------------------------------------------------------------

fn client_to_json(client: &db::XrayClient) -> Value {
    json!({
        "id": client.id,
        "userId": client.user_id,
        "inboundId": client.inbound_id,
        "name": client.name,
        "uuid": client.uuid,
        "shortId": client.short_id,
        "expiresAt": client.expires_at,
        "additionalConfig": client.additional_config,
        "enabled": client.enabled,
        "createdAt": client.created_at,
        "updatedAt": client.updated_at,
    })
}

pub async fn list_clients(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let user = require_auth(&jar, &state)?;
    let mut clients = db::list_xray_clients().map_err(map_err)?;
    if user.role < 1 {
        // Non-admins only see their own peers — same rule as AWG.
        clients.retain(|c| c.user_id == Some(user.id));
    }
    let out: Vec<Value> = clients.iter().map(client_to_json).collect();
    Ok(Json(json!(out)))
}

#[derive(Deserialize)]
pub struct CreateClientRequest {
    pub name: String,
    #[serde(default)]
    pub user_id: Option<i64>,
    #[serde(default)]
    pub expires_at: Option<String>,
}

pub async fn create_client(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<CreateClientRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    if body.name.trim().is_empty() {
        return Err(api_err(StatusCode::BAD_REQUEST, "name is required"));
    }

    // Generate per-peer UUID + short-id locally. The UUID is a v4 random
    // and the short-id is 16 hex chars (8 bytes of OsRng) — well above
    // the 0xevn / wulabing reference implementations' entropy floor.
    let uuid = xray::keys::generate_uuid();
    let short_id = xray::keys::generate_short_id();

    let id = db::create_xray_client(&db::CreateXrayClientParams {
        user_id: body.user_id,
        inbound_id: "xray0".into(),
        name: body.name.trim().to_string(),
        uuid,
        short_id,
        expires_at: body.expires_at,
        additional_config: None,
        enabled: true,
    })
    .map_err(map_err)?;

    reconcile_supervisor().await;

    let created = db::get_xray_client(id).map_err(map_err)?;
    Ok(Json(client_to_json(&created)))
}

pub async fn get_client(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<i64>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let user = require_auth(&jar, &state)?;
    let client = db::get_xray_client(id)
        .map_err(|_| api_err(StatusCode::NOT_FOUND, "Xray client not found"))?;
    if user.role < 1 && client.user_id != Some(user.id) {
        return Err(api_err(StatusCode::FORBIDDEN, "Access denied"));
    }
    Ok(Json(client_to_json(&client)))
}

#[derive(Deserialize)]
pub struct UpdateClientRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub expires_at: Option<Option<String>>,
    #[serde(default, rename = "additionalConfig")]
    pub additional_config: Option<String>,
}

pub async fn update_client(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<i64>,
    Json(body): Json<UpdateClientRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    let mut fields = db::UpdateMap::new();
    if let Some(ref v) = body.name {
        if v.trim().is_empty() {
            return Err(api_err(StatusCode::BAD_REQUEST, "name must not be empty"));
        }
        fields.insert("name".into(), v.clone());
    }
    if let Some(v) = body.enabled {
        fields.insert("enabled".into(), if v { "1".into() } else { "0".into() });
    }
    if let Some(ref v) = body.expires_at {
        match v {
            Some(s) => fields.insert("expires_at".into(), s.clone()),
            None => fields.insert("expires_at".into(), String::new()),
        };
    }
    if let Some(ref v) = body.additional_config {
        fields.insert("additional_config".into(), v.clone());
    }

    if fields.is_empty() {
        return Err(api_err(StatusCode::BAD_REQUEST, "No fields to update"));
    }
    db::update_xray_client(id, &fields).map_err(map_err)?;
    reconcile_supervisor().await;
    Ok(ok_success())
}

pub async fn delete_client(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<i64>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    db::delete_xray_client(id).map_err(map_err)?;
    reconcile_supervisor().await;
    Ok(ok_success())
}

// ---------------------------------------------------------------------------
// Share endpoints (URL / QR / Amnezia JSON)
// ---------------------------------------------------------------------------

async fn load_for_share(
    state: &AppState,
    jar: &CookieJar,
    id: i64,
) -> Result<(db::XrayInbound, db::XrayClient, String), (StatusCode, Json<Value>)> {
    let user = require_auth(jar, state)?;
    let client = db::get_xray_client(id)
        .map_err(|_| api_err(StatusCode::NOT_FOUND, "Xray client not found"))?;
    if user.role < 1 && client.user_id != Some(user.id) {
        return Err(api_err(StatusCode::FORBIDDEN, "Access denied"));
    }
    let inbound = db::get_xray_inbound().map_err(map_err)?;
    let user_config = db::get_user_config().map_err(map_err)?;
    if user_config.host.trim().is_empty() {
        return Err(api_err(
            StatusCode::PRECONDITION_FAILED,
            "host is not configured — set it on the General admin tab first",
        ));
    }
    Ok((inbound, client, user_config.host))
}

pub async fn client_share_url(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<i64>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    let (inbound, client, host) = load_for_share(&state, &jar, id).await?;
    let url = xray::share::build_vless_url(&inbound, &client, &host).map_err(map_err)?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "text/plain; charset=utf-8".parse().unwrap(),
    );
    // The vless:// URL carries the client UUID and transport secrets.
    no_store_headers(&mut headers);
    Ok((StatusCode::OK, headers, url))
}

pub async fn client_qrcode(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<i64>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    let (inbound, client, host) = load_for_share(&state, &jar, id).await?;
    let url = xray::share::build_vless_url(&inbound, &client, &host).map_err(map_err)?;
    let svg = crate::qr::generate_qr_svg(&url)
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("qr: {e}")))?;
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "image/svg+xml".parse().unwrap());
    // The QR encodes the vless:// URL, i.e. the client's credentials.
    no_store_headers(&mut headers);
    Ok((StatusCode::OK, headers, svg))
}

pub async fn client_amnezia_json(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<i64>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    let (inbound, client, host) = load_for_share(&state, &jar, id).await?;
    let body = xray::share::build_amnezia_json(&inbound, &client, &host).map_err(map_err)?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "application/json; charset=utf-8".parse().unwrap(),
    );
    // AmneziaVPN import payload — same credentials as the vless:// URL.
    no_store_headers(&mut headers);
    Ok((StatusCode::OK, headers, body))
}

// ---------------------------------------------------------------------------
// Supervisor reconciliation hook
// ---------------------------------------------------------------------------

#[cfg(xray_bundled)]
async fn reconcile_supervisor() {
    if let Err(e) = xray::supervisor::ensure_running().await {
        // Non-fatal — the admin UI shows the failure via /status.
        tracing::warn!(error = ?e, "xray supervisor reconcile failed");
    }
}

#[cfg(not(xray_bundled))]
async fn reconcile_supervisor() {}
