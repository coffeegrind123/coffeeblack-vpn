//! REST endpoints for the bundled DNS stack (dnscrypt-proxy + tor + PTs).
//!
//! | Method | Path                          | Auth   | Purpose                            |
//! |--------|-------------------------------|--------|------------------------------------|
//! | GET    | /api/admin/dns/bundle         | admin  | Read singleton dns_bundle row      |
//! | POST   | /api/admin/dns/bundle         | admin  | Update bundle config + reconcile   |
//! | GET    | /api/admin/dns/status         | admin  | Supervisor status snapshot         |
//! | POST   | /api/admin/dns/restart        | admin  | Force re-spawn (admin override)    |
//!
//! `bundle` carries every field of `db::DnsBundle` in camelCase JSON.
//! Tor toggles are exposed but the supervisor still refuses to spawn
//! tor unless `torEnabled` is explicitly true (matches feedback memory).
//! The status endpoint is `Disabled` until the v1 of the supervisor
//! actually runs the dnscrypt-proxy child — the shape is forward-
//! compatible with a future `tor` field.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use serde_json::{json, Value};

use super::admin::require_admin;
use super::{map_err, ok_success, value_to_string, AppState};
use crate::db;

// ---------------------------------------------------------------------------
// GET /api/admin/dns/bundle
// ---------------------------------------------------------------------------

pub async fn get_bundle(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    let b = db::get_dns_bundle().map_err(map_err)?;
    let upstream_resolvers: Value =
        serde_json::from_str(&b.upstream_resolvers).unwrap_or_else(|_| json!([]));

    Ok(Json(json!({
        "id": b.id,
        "enabled": b.enabled,
        "listenPort": b.listen_port,
        "upstreamResolvers": upstream_resolvers,
        "requireDnssec": b.require_dnssec,
        "requireNolog": b.require_nolog,
        "requireNofilter": b.require_nofilter,
        // Tor block — admin UI shows these grouped under "Optional: Tor".
        // Even when torEnabled=true the user has explicitly opted in;
        // the supervisor enforces the feedback-memory rule.
        "torEnabled": b.tor_enabled,
        "torSocksPort": b.tor_socks_port,
        "torExitNodes": b.tor_exit_nodes,
        "torDnsExitNodes": b.tor_dns_exit_nodes,
        "torUseBridges": b.tor_use_bridges,
        "torPlugin": b.tor_plugin,
        "additionalConfig": b.additional_config,
        "isBundled": crate::dns::is_bundled(),
        // When isBundled is false this says which half is missing —
        // an unpinned binary vs a vendor blob that was never
        // materialised. Empty string when the bundle is present.
        "bundleIncompleteReason": crate::dns::bundle_incomplete_reason(),
        "embeddedVersions": versions_payload(),
    })))
}

/// Per-binary `(name, version, sha256)` triples surfaced from `dns::mod`.
/// Empty version + sha mean the binary isn't bundled in this build.
fn versions_payload() -> Value {
    let v = crate::dns::embedded_versions();
    Value::Array(
        v.iter()
            .map(|(name, version, sha)| {
                json!({
                    "name": name,
                    "version": version,
                    "sha256": sha,
                })
            })
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// POST /api/admin/dns/bundle
// ---------------------------------------------------------------------------

pub async fn update_bundle(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;

    let mut fields = db::UpdateMap::new();
    if let Value::Object(map) = &body {
        // Scalar fields — straight camelCase → snake_case mapping.
        let scalars: &[(&str, &str)] = &[
            ("enabled", "enabled"),
            ("listenPort", "listen_port"),
            ("requireDnssec", "require_dnssec"),
            ("requireNolog", "require_nolog"),
            ("requireNofilter", "require_nofilter"),
            ("torEnabled", "tor_enabled"),
            ("torSocksPort", "tor_socks_port"),
            ("torExitNodes", "tor_exit_nodes"),
            ("torDnsExitNodes", "tor_dns_exit_nodes"),
            ("torUseBridges", "tor_use_bridges"),
            ("torPlugin", "tor_plugin"),
            ("additionalConfig", "additional_config"),
        ];
        for (json_key, db_key) in scalars {
            if let Some(val) = map.get(*json_key) {
                if let Some(s) = value_to_string(val) {
                    fields.insert(db_key.to_string(), s);
                }
            }
        }
        // upstream_resolvers comes in as a JSON array; we round-trip it
        // through serde so the on-disk form is normalised regardless of
        // how the client serialised it.
        if let Some(val) = map.get("upstreamResolvers") {
            let s = serde_json::to_string(val).unwrap_or_else(|_| "[]".to_string());
            fields.insert("upstream_resolvers".into(), s);
        }

        // Validate tor_plugin upfront — only the three PT names we
        // actually ship binaries for, plus empty (no PT). Catching this
        // here gives the operator a clean 400 instead of a tor spawn
        // failure later when the torrc references a non-existent plugin.
        if let Some(plugin) = map.get("torPlugin").and_then(|v| v.as_str()) {
            let normalised = plugin.trim();
            const ALLOWED: &[&str] = &["", "obfs4", "snowflake", "webtunnel"];
            if !ALLOWED.contains(&normalised) {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": format!(
                            "torPlugin must be one of {ALLOWED:?} (got {plugin:?})"
                        ),
                    })),
                ));
            }
        }
    }

    if !fields.is_empty() {
        db::update_dns_bundle(&fields).map_err(map_err)?;
    }

    // Reconcile supervisor with new DB state. Non-fatal — admin still
    // gets a 200 even if dnscrypt-proxy fails to spawn (the status
    // endpoint will surface the reason). Mirrors how xray::update_inbound
    // handles supervisor errors.
    #[cfg(dns_bundled)]
    if let Err(e) = crate::dns::supervisor::ensure_running().await {
        tracing::warn!(error = ?e, "DNS supervisor reconcile failed after admin update");
    }

    Ok(ok_success())
}

// ---------------------------------------------------------------------------
// GET /api/admin/dns/status
// ---------------------------------------------------------------------------

pub async fn supervisor_status(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    Ok(Json(status_payload().await))
}

#[cfg(dns_bundled)]
async fn status_payload() -> Value {
    let s = crate::dns::supervisor::status().await;
    serde_json::to_value(s).unwrap_or_else(|_| json!({"state": "unknown"}))
}

#[cfg(not(dns_bundled))]
async fn status_payload() -> Value {
    json!({
        "state": "disabled",
        "reason": "DNS bundle was not compiled into this build (cfg(dns_bundled) is off)",
    })
}

// ---------------------------------------------------------------------------
// POST /api/admin/dns/restart
// ---------------------------------------------------------------------------

pub async fn restart(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;

    #[cfg(dns_bundled)]
    {
        // stop + ensure_running rather than a single "respawn" call so
        // any new config rendered between calls actually lands. Same
        // pattern as xray::restart.
        let _ = crate::dns::supervisor::stop().await;
        if let Err(e) = crate::dns::supervisor::ensure_running().await {
            return Err(map_err(e));
        }
    }
    #[cfg(not(dns_bundled))]
    {
        return Err((
            StatusCode::PRECONDITION_FAILED,
            Json(json!({
                "error": "DNS bundle was not compiled into this build",
            })),
        ));
    }

    #[allow(unreachable_code)]
    Ok(ok_success())
}
