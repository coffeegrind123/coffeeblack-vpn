//! Admin endpoint handlers.
//!
//! | Method | Route                           | Description               |
//! |--------|---------------------------------|---------------------------|
//! | GET    | /api/admin/general              | Get general settings      |
//! | POST   | /api/admin/general              | Update general settings   |
//! | GET    | /api/admin/hooks                | Get hooks                 |
//! | POST   | /api/admin/hooks                | Update hooks              |
//! | GET    | /api/admin/ip-info              | Get IP information        |
//! | GET    | /api/admin/userconfig           | Get user config defaults  |
//! | POST   | /api/admin/userconfig           | Update user config        |
//! | GET    | /api/admin/interface            | Get interface (no key)    |
//! | POST   | /api/admin/interface            | Update interface          |
//! | POST   | /api/admin/interface/cidr       | Change CIDR + reassign IPs|
//! | POST   | /api/admin/interface/restart    | Restart AmneziaWG         |

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{api_err, map_err, ok_success, require_auth, value_to_string, AppState};
use crate::{db, wg};

fn get_i64(map: &serde_json::Map<String, Value>, key: &str) -> Option<i64> {
    map.get(key).and_then(|v| v.as_i64())
}

/// String elements of a JSON value that is expected to be an array of
/// strings. Non-array values and non-string elements are ignored, so callers
/// get a clean `Vec<String>` to validate before the value is JSON-re-encoded
/// into a DB TEXT column.
fn json_str_elements(v: &Value) -> Vec<String> {
    match v {
        Value::Array(items) => items
            .iter()
            .filter_map(|i| i.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

/// A magic header is `digits` or `digits-digits` — nothing else. Both halves
/// must be non-empty and each must fit in an `i64`.
fn is_valid_magic_header(s: &str) -> bool {
    let parse_part = |p: &str| -> bool { !p.is_empty() && p.parse::<i64>().is_ok() };
    match s.split_once('-') {
        Some((lo, hi)) => parse_part(lo) && parse_part(hi),
        None => parse_part(s),
    }
}

fn validate_awg_params(map: &serde_json::Map<String, Value>) -> Result<(), (StatusCode, Json<Value>)> {
    let jc = get_i64(map, "jC").or_else(|| get_i64(map, "jc"));
    let jmin = get_i64(map, "jMin").or_else(|| get_i64(map, "jmin"));
    let jmax = get_i64(map, "jMax").or_else(|| get_i64(map, "jmax"));
    let s1 = get_i64(map, "s1");
    let s2 = get_i64(map, "s2");
    let s3 = get_i64(map, "s3");
    let s4 = get_i64(map, "s4");

    if let Some(jc) = jc {
        // Kernel permits jc == 0 ("junk packets disabled"); upstream
        // awg-easy required >= 1. We follow the kernel and accept 0.
        if !(0..=128).contains(&jc) {
            return Err(api_err(StatusCode::BAD_REQUEST, "Jc must be 0-128"));
        }
    }
    if let (Some(jmin), Some(jmax)) = (jmin, jmax) {
        // Kernel device.c rejects only when jmax > 0 AND jmax < jmin. The
        // jmax == jmin case is handled separately below (kernel auto-bumps,
        // we reject when jc != 0 so the user can fix it explicitly).
        if jmax > 0 && jmax < jmin {
            return Err(api_err(StatusCode::BAD_REQUEST, "Jmax must be >= Jmin"));
        }
    }
    if let Some(jmin) = jmin {
        if !(0..=1279).contains(&jmin) {
            return Err(api_err(StatusCode::BAD_REQUEST, "Jmin must be 0-1279"));
        }
    }
    if let Some(jmax) = jmax {
        // Spec: Jmax < 1280 (strict)
        if !(1..=1279).contains(&jmax) {
            return Err(api_err(StatusCode::BAD_REQUEST, "Jmax must be 1-1279"));
        }
    }
    // Mirror kernel device.c post-config check: when Jc != 0 the kernel
    // requires Jmax > Jmin (otherwise it auto-increments). We reject the
    // equal case at API time so the user notices.
    if let (Some(jc), Some(jmin), Some(jmax)) = (jc, jmin, jmax) {
        if jc != 0 && jmin == jmax {
            return Err(api_err(
                StatusCode::BAD_REQUEST,
                "When Jc != 0, Jmax must be strictly greater than Jmin",
            ));
        }
    }
    if let Some(s1) = s1 {
        if !(0..=1132).contains(&s1) {
            return Err(api_err(StatusCode::BAD_REQUEST, "S1 must be 0-1132"));
        }
    }
    if let Some(s2) = s2 {
        if !(0..=1188).contains(&s2) {
            return Err(api_err(StatusCode::BAD_REQUEST, "S2 must be 0-1188"));
        }
    }
    if let Some(s3) = s3 {
        // Per gl-inet AmneziaWG-2.0 parameter table.
        if !(0..=1216).contains(&s3) {
            return Err(api_err(StatusCode::BAD_REQUEST, "S3 must be 0-1216"));
        }
    }
    if let Some(s4) = s4 {
        // Per AmneziaWG-2.0 transport-message padding limit.
        if !(0..=32).contains(&s4) {
            return Err(api_err(StatusCode::BAD_REQUEST, "S4 must be 0-32"));
        }
    }
    if let (Some(s1), Some(s2)) = (s1, s2) {
        if s1 > 0 && s2 > 0 && s1 + 56 == s2 {
            return Err(api_err(StatusCode::BAD_REQUEST, "S1 + 56 must not equal S2"));
        }
    }

    // Validate I1-I5 CPS tag grammar
    for key in ["i1", "i2", "i3", "i4", "i5"] {
        if let Some(val) = map.get(key).and_then(|v| v.as_str()) {
            if let Err(msg) = crate::wg::params::validate_init_spec(val) {
                return Err(api_err(
                    StatusCode::BAD_REQUEST,
                    &format!("Invalid {}: {msg}", key.to_uppercase()),
                ));
            }
        }
    }

    // Validate H1-H4. Each magic header is a single integer or an
    // `int-int` range. Enforce that grammar strictly (digits and at most one
    // dash) — these values are written verbatim into the generated
    // `[Interface]` block, so a newline or stray token would inject arbitrary
    // config directives (e.g. a `PostUp` line) into awg-quick's input.
    let h_keys = ["h1", "h2", "h3", "h4"];
    for k in h_keys {
        if let Some(s) = map.get(k).and_then(|v| v.as_str()) {
            if !s.is_empty() && !is_valid_magic_header(s) {
                return Err(api_err(
                    StatusCode::BAD_REQUEST,
                    &format!(
                        "{} must be a single integer or an int-int range (digits and one dash only)",
                        k.to_uppercase()
                    ),
                ));
            }
        }
    }
    let ranges: Vec<Option<(i64, i64)>> = h_keys.iter().map(|k| {
        map.get(*k).and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(|s| {
            let parts: Vec<&str> = s.splitn(2, '-').collect();
            let start: i64 = parts[0].parse().unwrap_or(0);
            let end: i64 = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(start);
            (start, end)
        })
    }).collect();

    for i in 0..4 {
        for j in (i+1)..4 {
            if let (Some(a), Some(b)) = (ranges[i], ranges[j]) {
                if !(a.1 < b.0 || b.1 < a.0) {
                    return Err(api_err(StatusCode::BAD_REQUEST,
                        &format!("Magic headers H{} and H{} overlap. They must not overlap.", i+1, j+1)));
                }
            }
        }
    }
    Ok(())
}


/// Why the two shape-changing AmneziaWG 3 knobs are unavailable right now,
/// or `None` when they are free to use.
///
/// Reads the *stored* proxy switch rather than whether the proxy task
/// happens to be running, so the answer doesn't flicker while the
/// supervisor is starting or backing off after a crash.
fn awg3_proxy_lock_reason() -> Option<String> {
    let settings = db::get_proxy_settings().ok()?;
    if !settings.enabled {
        return None;
    }
    Some(
        "the DPI-imitation proxy is enabled: header protection and random \
         trailers change the datagram shape it parses, so they cannot be \
         used together with it"
            .to_string(),
    )
}

/// Validate the AmneziaWG 3 half of an interface update.
///
/// Split from [`validate_awg_params`] because it needs the *merged* view —
/// several rules span fields the request may not have sent (header
/// protection depends on S1–S4, the proxy interlock on a different table),
/// so it reads the stored row for anything absent from the body.
fn validate_awg3_params(
    map: &serde_json::Map<String, Value>,
) -> Result<(), (StatusCode, Json<Value>)> {
    use crate::wg::awg3;

    let touches_awg3 = [
        "headerProtection",
        "headerProtectionKey",
        "contentPaddingAddition",
        "rekeyAfterTime",
        "rekeyTimeout",
        "rejectAfterTime",
        "keepaliveTimeout",
        "maxHandshakeAttempts",
        "randomTrailers",
        "disableCookies",
    ]
    .iter()
    .any(|k| map.contains_key(*k));
    if !touches_awg3 {
        return Ok(());
    }

    for (json_key, config_key) in [
        ("contentPaddingAddition", "ContentPaddingAddition"),
        ("rekeyAfterTime", "RekeyAfterTime"),
        ("rekeyTimeout", "RekeyTimeout"),
        ("rejectAfterTime", "RejectAfterTime"),
        ("keepaliveTimeout", "KeepaliveTimeout"),
        ("maxHandshakeAttempts", "MaxHandshakeAttempts"),
    ] {
        if let Some(v) = map.get(json_key).and_then(value_to_string) {
            if let Err(e) = awg3::validate_range(config_key, &v) {
                return Err(api_err(StatusCode::BAD_REQUEST, &format!("{e}")));
            }
        }
    }
    if let Some(v) = map.get("headerProtectionKey").and_then(|v| v.as_str()) {
        if let Err(e) = awg3::validate_header_protection_key(v) {
            return Err(api_err(StatusCode::BAD_REQUEST, &format!("{e}")));
        }
    }

    // Everything below needs the merged (request over stored) view.
    let stored = db::get_interface().map_err(map_err)?;
    let want_header_protection = match map.get("headerProtectionKey").and_then(|v| v.as_str()) {
        Some(k) => !k.trim().is_empty(),
        None => match map.get("headerProtection").and_then(json_bool) {
            Some(b) => b,
            None => !stored.header_protection_key.is_empty(),
        },
    };
    let want_random_trailers = map
        .get("randomTrailers")
        .and_then(json_bool)
        .unwrap_or(stored.random_trailers);

    if want_header_protection {
        let s1 = get_i64(map, "s1").unwrap_or(stored.s1);
        let s2 = get_i64(map, "s2").unwrap_or(stored.s2);
        let s3 = get_i64(map, "s3").or(stored.s3);
        let s4 = get_i64(map, "s4").or(stored.s4);
        if let Err(e) = awg3::check_header_protection_paddings(s1, s2, s3, s4) {
            return Err(api_err(StatusCode::BAD_REQUEST, &format!("{e}")));
        }
    }

    // The interlock, checked from this side too: the proxy's own supervisor
    // refuses to start against a conflicting interface, but an operator who
    // sets the knob here would otherwise only find out when the proxy went
    // quiet.
    if (want_header_protection || want_random_trailers) && awg3_proxy_lock_reason().is_some() {
        let conflict = awg3::proxy_conflict(
            if want_header_protection { "set" } else { "" },
            want_random_trailers,
        )
        .unwrap_or("incompatible with the DPI-imitation proxy");
        return Err(api_err(
            StatusCode::CONFLICT,
            &format!("{conflict}. Turn the proxy off first, or leave this unset."),
        ));
    }

    Ok(())
}

/// Coerce a JSON value the UI might send for a checkbox into a bool.
/// Accepts a real bool, `"true"`/`"false"`, and 0/1 — the admin form posts
/// all three shapes depending on the control.
fn json_bool(v: &Value) -> Option<bool> {
    match v {
        Value::Bool(b) => Some(*b),
        Value::Number(n) => n.as_i64().map(|i| i != 0),
        Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "on" | "yes" => Some(true),
            "false" | "0" | "off" | "no" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Enforce admin role (role >= 1)
// ---------------------------------------------------------------------------

pub(crate) fn require_admin(
    jar: &CookieJar,
    state: &AppState,
) -> Result<db::User, (StatusCode, Json<Value>)> {
    let user = require_auth(jar, state)?;
    if user.role < 1 {
        return Err(api_err(StatusCode::FORBIDDEN, "Admin access required"));
    }
    Ok(user)
}

// ---------------------------------------------------------------------------
// GET /api/admin/general
// ---------------------------------------------------------------------------

pub async fn get_general(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    let general = db::get_general().map_err(map_err)?;

    // Never return the metrics password (it's a hash anyway, but treat the
    // hash as a credential). We surface only a boolean so the UI can display
    // "set / not set" without the value.
    let metrics_password_set = general
        .metrics_password
        .as_ref()
        .map(|s| !s.is_empty())
        .unwrap_or(false);

    Ok(Json(json!({
        "setupStep": general.setup_step,
        "sessionTimeout": general.session_timeout,
        "metricsPrometheus": general.metrics_prometheus,
        "metricsJson": general.metrics_json,
        "metricsPasswordSet": metrics_password_set,
        "activityRetentionDays": general.activity_retention_days,
        "privateKeyRetention": general.private_key_retention,
        // Lets the admin UI show how many peers would actually be affected by
        // a switch to `never`, instead of asking the operator to confirm a
        // purge whose scope they cannot see.
        "clientsWithStoredKeys": db::get_all_clients()
            .map(|cs| cs.iter().filter(|c| c.has_private_key()).count())
            .unwrap_or(0),
        "activityMaxRetentionDays": db::MAX_ACTIVITY_RETENTION_DAYS,
        "activityPollIntervalSeconds": crate::activity::POLL_INTERVAL_SECS,
    })))
}

// ---------------------------------------------------------------------------
// POST /api/admin/general
// ---------------------------------------------------------------------------

pub async fn update_general(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;

    let mut fields = db::UpdateMap::new();
    if let Value::Object(map) = &body {
        // Strict whitelist — never accept arbitrary keys here. The generic
        // pass-through that previously existed could be abused (with admin
        // credentials) to reset `setupStep` and re-trigger the setup wizard.
        let mappings: &[(&str, &str)] = &[
            ("sessionTimeout", "session_timeout"),
            ("metricsPrometheus", "metrics_prometheus"),
            ("metricsJson", "metrics_json"),
        ];
        // Bound the session timeout: it is later cast `as u64` in
        // `is_expired`, so a negative value would wrap to a ~584-billion-year
        // timeout and effectively disable session expiry. Require a sane
        // positive range (60s … 30d).
        if let Some(val) = map.get("sessionTimeout") {
            let secs = val.as_i64().or_else(|| value_to_string(val).and_then(|s| s.parse().ok()));
            match secs {
                Some(n) if (60..=2_592_000).contains(&n) => {
                    fields.insert("session_timeout".into(), n.to_string());
                }
                _ => {
                    return Err(api_err(
                        StatusCode::BAD_REQUEST,
                        "sessionTimeout must be an integer between 60 and 2592000 seconds",
                    ));
                }
            }
        }
        // Retention window: bounded for the same class of reason as the
        // session timeout above — an unchecked value here either turns the
        // bounded daily rollup back into an unbounded table, or (if negative)
        // reads as "disabled" through one code path and "keep forever"
        // through another.
        if let Some(val) = map.get("activityRetentionDays") {
            let days = val
                .as_i64()
                .or_else(|| value_to_string(val).and_then(|s| s.parse().ok()))
                .ok_or_else(|| {
                    api_err(
                        StatusCode::BAD_REQUEST,
                        "activityRetentionDays must be an integer",
                    )
                })?;
            let days = super::activity::validate_retention_days(days)?;
            fields.insert("activity_retention_days".into(), days.to_string());
        }
        // Private-key retention. Switching to `never` must also destroy the
        // keys already stored, or the setting would describe an intention
        // rather than a fact: every peer created before the switch would keep
        // its key on disk indefinitely while the UI claimed otherwise.
        if let Some(val) = map.get("privateKeyRetention") {
            let mode = value_to_string(val).unwrap_or_default();
            if !db::PRIVATE_KEY_RETENTION_MODES.contains(&mode.as_str()) {
                return Err(api_err(
                    StatusCode::BAD_REQUEST,
                    &format!(
                        "privateKeyRetention must be one of: {}",
                        db::PRIVATE_KEY_RETENTION_MODES.join(", ")
                    ),
                ));
            }
            if mode == db::RETENTION_NEVER {
                let purged = db::purge_client_private_keys().map_err(map_err)?;
                if purged > 0 {
                    tracing::info!(
                        "private-key retention set to 'never' — purged stored keys for \
                         {purged} peer(s); their configs can no longer be re-displayed"
                    );
                }
            }
            fields.insert("private_key_retention".into(), mode);
        }
        for (json_key, db_key) in mappings {
            if *json_key == "sessionTimeout" {
                continue; // handled above with range validation
            }
            if let Some(val) = map.get(*json_key) {
                if let Some(s) = value_to_string(val) {
                    fields.insert((*db_key).into(), s);
                }
            }
        }
        // Metrics password: never store cleartext. We hash with SHA-256 hex
        // and the metrics endpoints constant-time-compare against the hash.
        // Empty / null clears the value.
        if let Some(val) = map.get("metricsPassword") {
            match val {
                Value::Null => {
                    fields.insert("metrics_password".into(), String::new());
                }
                Value::String(s) if s.is_empty() => {
                    fields.insert("metrics_password".into(), String::new());
                }
                Value::String(s) => {
                    fields.insert("metrics_password".into(), crate::auth::sha256(s));
                }
                _ => {}
            }
        }

        // Refuse to enable metrics without a password. An unauthenticated
        // /metrics/{json,prometheus} endpoint discloses the entire client
        // roster — names, public keys, peer endpoint IPs, and transfer stats.
        // Compute the POST-update state (request value if present, else stored)
        // and reject the transition that would leave metrics on but open.
        let current = db::get_general().map_err(map_err)?;
        // Accept bool, "true"/"1", or a non-zero number — mirrors how the
        // value is later coerced for storage, so the guard can't be dodged by
        // sending the flag in a different encoding.
        let truthy = |v: &Value| -> Option<bool> {
            match v {
                Value::Bool(b) => Some(*b),
                Value::Number(n) => Some(n.as_i64().unwrap_or(0) != 0),
                Value::String(s) => Some(matches!(s.as_str(), "true" | "1")),
                _ => None,
            }
        };
        let json_on = map
            .get("metricsJson")
            .and_then(truthy)
            .unwrap_or(current.metrics_json);
        let prom_on = map
            .get("metricsPrometheus")
            .and_then(truthy)
            .unwrap_or(current.metrics_prometheus);
        let password_after = match map.get("metricsPassword") {
            Some(Value::String(s)) => !s.is_empty(),
            Some(Value::Null) => false,
            _ => current
                .metrics_password
                .as_deref()
                .map(|s| !s.is_empty())
                .unwrap_or(false),
        };
        if (json_on || prom_on) && !password_after {
            return Err(api_err(
                StatusCode::BAD_REQUEST,
                "Set a metricsPassword before enabling metrics — the endpoint \
                 exposes the client roster (names, public keys, peer IPs) to \
                 anyone who can reach it",
            ));
        }
    }

    if !fields.is_empty() {
        db::update_general(&fields).map_err(map_err)?;
    }

    Ok(ok_success())
}

// ---------------------------------------------------------------------------
// GET /api/admin/hooks
// ---------------------------------------------------------------------------

pub async fn get_hooks(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    let hooks = db::get_hooks().map_err(map_err)?;

    Ok(Json(json!({
        "preUp": hooks.pre_up,
        "postUp": hooks.post_up,
        "preDown": hooks.pre_down,
        "postDown": hooks.post_down,
    })))
}

// ---------------------------------------------------------------------------
// POST /api/admin/hooks
// ---------------------------------------------------------------------------

pub async fn update_hooks(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;

    let mut fields = db::UpdateMap::new();
    if let Value::Object(map) = &body {
        let mappings = [
            ("preUp", "pre_up"),
            ("postUp", "post_up"),
            ("preDown", "pre_down"),
            ("postDown", "post_down"),
        ];
        for (json_key, db_key) in &mappings {
            if let Some(val) = map.get(*json_key) {
                if let Some(s) = value_to_string(val) {
                    fields.insert(db_key.to_string(), s);
                }
            }
        }
    }

    if !fields.is_empty() {
        db::update_hooks(&fields).map_err(map_err)?;
        // Re-save config to apply new hooks
        wg::save_config_async().await.map_err(map_err)?;
    }

    Ok(ok_success())
}

// ---------------------------------------------------------------------------
// GET /api/admin/ip-info
// ---------------------------------------------------------------------------

pub async fn get_ip_info(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;

    let public_ip = get_public_ip();
    let private_ips = get_private_ips();

    Ok(Json(json!({
        "publicIp": public_ip,
        "privateIps": private_ips,
    })))
}

// ---------------------------------------------------------------------------
// GET /api/admin/userconfig
// ---------------------------------------------------------------------------

pub async fn get_userconfig(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    let uc = db::get_user_config().map_err(map_err)?;

    // Parse JSON arrays
    let default_dns: Value =
        serde_json::from_str(&uc.default_dns).unwrap_or(json!([]));
    let default_allowed_ips: Value =
        serde_json::from_str(&uc.default_allowed_ips).unwrap_or(json!([]));

    Ok(Json(json!({
        // Match the frontend / Node.js naming exactly: defaultMtu / defaultDns
        // (lowercase initialism). The previous all-caps form silently failed
        // to round-trip through the Vue UI.
        "defaultMtu": uc.default_mtu,
        "defaultPersistentKeepalive": uc.default_persistent_keepalive,
        "defaultDns": default_dns,
        "defaultAllowedIps": default_allowed_ips,
        "defaultJC": uc.default_j_c,
        "defaultJMin": uc.default_j_min,
        "defaultJMax": uc.default_j_max,
        "defaultI1": uc.default_i1,
        "defaultI2": uc.default_i2,
        "defaultI3": uc.default_i3,
        "defaultI4": uc.default_i4,
        "defaultI5": uc.default_i5,
        "defaultAdditionalConfig": uc.default_additional_config,
        "host": uc.host,
        "port": uc.port,
    })))
}

// ---------------------------------------------------------------------------
// POST /api/admin/userconfig
// ---------------------------------------------------------------------------

pub async fn update_userconfig(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;

    let mut fields = db::UpdateMap::new();
    if let Value::Object(map) = &body {
        // Accept BOTH the all-caps initialism (legacy clients) and the
        // camelCase form used by the modern UI/Nuxt server.
        let mappings: &[(&[&str], &str)] = &[
            (&["defaultMtu", "defaultMTU"], "default_mtu"),
            (&["defaultPersistentKeepalive"], "default_persistent_keepalive"),
            (&["defaultJC"], "default_j_c"),
            (&["defaultJMin"], "default_j_min"),
            (&["defaultJMax"], "default_j_max"),
            (&["defaultI1"], "default_i1"),
            (&["defaultI2"], "default_i2"),
            (&["defaultI3"], "default_i3"),
            (&["defaultI4"], "default_i4"),
            (&["defaultI5"], "default_i5"),
            (&["defaultAdditionalConfig"], "default_additional_config"),
            (&["host"], "host"),
            (&["port"], "port"),
        ];
        for (json_keys, db_key) in mappings {
            for k in *json_keys {
                if let Some(val) = map.get(*k) {
                    if let Some(s) = value_to_string(val) {
                        fields.insert((*db_key).into(), s);
                        break;
                    }
                }
            }
        }
        // DNS array -> JSON string (accept both spellings). Every element
        // must be a bare IP literal: these values are string-interpolated
        // into the generated WireGuard `DNS = …` line, so a newline / stray
        // token would inject config directives. (Mirrors the per-client `dns`
        // validation in `api::clients`.)
        if let Some(val) = map.get("defaultDns").or_else(|| map.get("defaultDNS")) {
            for e in json_str_elements(val) {
                if e.trim().parse::<std::net::IpAddr>().is_err() {
                    return Err(api_err(
                        StatusCode::BAD_REQUEST,
                        &format!("Invalid defaultDns entry '{e}': must be a valid IP address"),
                    ));
                }
            }
            let s = serde_json::to_string(val).unwrap_or_default();
            fields.insert("default_dns".into(), s);
        }
        // AllowedIPs array -> JSON string. Every element must be an IP or CIDR
        // literal: these flow into the per-client nftables transaction
        // (`firewall::gen_rules`, fed to `nft -f -`) and the client config.
        // `firewall::parse_target` now also rejects non-IP tokens in-module,
        // but we reject here too for a clear 400 instead of a silent skip.
        if let Some(val) = map.get("defaultAllowedIps") {
            for e in json_str_elements(val) {
                super::clients::validate_routing_entry(&e).map_err(|m| {
                    api_err(
                        StatusCode::BAD_REQUEST,
                        &format!("Invalid defaultAllowedIps entry: {m}"),
                    )
                })?;
            }
            let s = serde_json::to_string(val).unwrap_or_default();
            fields.insert("default_allowed_ips".into(), s);
        }
    }

    if !fields.is_empty() {
        db::update_user_config(&fields).map_err(map_err)?;
    }

    Ok(ok_success())
}

// ---------------------------------------------------------------------------
// GET /api/admin/interface — get interface (hide private_key)
// ---------------------------------------------------------------------------

pub async fn get_interface(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    let iface = db::get_interface().map_err(map_err)?;

    Ok(Json(json!({
        "name": iface.name,
        "device": iface.device,
        "port": iface.port,
        "publicKey": iface.public_key,
        "ipv4Cidr": iface.ipv4_cidr,
        "ipv6Cidr": iface.ipv6_cidr,
        "mtu": iface.mtu,
        "jC": iface.j_c,
        "jMin": iface.j_min,
        "jMax": iface.j_max,
        "s1": iface.s1,
        "s2": iface.s2,
        "s3": iface.s3,
        "s4": iface.s4,
        "h1": iface.h1,
        "h2": iface.h2,
        "h3": iface.h3,
        "h4": iface.h4,
        "i1": iface.i1,
        "i2": iface.i2,
        "i3": iface.i3,
        "i4": iface.i4,
        "i5": iface.i5,
        "additionalConfig": iface.additional_config,
        // AmneziaWG 3 device knobs. The header-protection *key* is never
        // returned: it is a symmetric secret with the same standing as the
        // device private key (which this endpoint also withholds), and the
        // UI only needs to know whether it is set. Peers get their copy in
        // the generated config, so nothing needs it back out of here.
        "headerProtection": !iface.header_protection_key.is_empty(),
        "contentPaddingAddition": iface.content_padding_addition,
        "rekeyAfterTime": iface.rekey_after_time,
        "rekeyTimeout": iface.rekey_timeout,
        "rejectAfterTime": iface.reject_after_time,
        "keepaliveTimeout": iface.keepalive_timeout,
        "maxHandshakeAttempts": iface.max_handshake_attempts,
        "randomTrailers": iface.random_trailers,
        "disableCookies": iface.disable_cookies,
        // Whether the installed `awg` speaks AWG 3 at all. `null` means the
        // probe couldn't tell (no awg on PATH, unrecognised banner) — the
        // UI shows the section without a confirmation rather than hiding a
        // feature that may well work.
        "awg3Supported": crate::wg::awg3::tools_support_awg3(),
        // Set when the DPI-imitation proxy is on, naming the AWG 3 knobs it
        // cannot carry, so the UI can disable those two controls with the
        // reason instead of letting the operator discover it via a 400.
        "awg3ProxyLock": awg3_proxy_lock_reason(),
        "firewallEnabled": iface.firewall_enabled,
        // DNS-leak prevention. Three independent fields so the UI can
        // expose the master switch separately from the redirect target
        // (operator might want to set the target ahead of time and flip
        // the switch later) and from the residual-leak drop policy.
        "dnsLockdown": iface.dns_lockdown,
        "dnsLockdownTarget": iface.dns_lockdown_target,
        "dnsBlockExternal": iface.dns_block_external,
        // Which AmneziaWG implementation will service handshakes for
        // this interface — the in-kernel module (full feature set,
        // including per-peer AdvancedSecurity = on|off) or the
        // amneziawg-go userspace fallback (chokes on explicit
        // AdvancedSecurity peer lines). The UI uses this to gate the
        // per-peer advancedSecurity tri-state and surface a status
        // badge so operators don't ship a broken peer config.
        "gamingMode": crate::wg::kernel::detect(),
        "enabled": iface.enabled,
    })))
}

// ---------------------------------------------------------------------------
// POST /api/admin/interface — update interface
// ---------------------------------------------------------------------------

pub async fn update_interface(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;

    // Validate AWG params
    if let Value::Object(ref map) = body {
        validate_awg_params(map)?;
        validate_awg3_params(map)?;
    }

    let mut fields = db::UpdateMap::new();
    if let Value::Object(map) = &body {
        let mappings = [
            ("port", "port"),
            ("ipv4Cidr", "ipv4_cidr"),
            ("ipv6Cidr", "ipv6_cidr"),
            ("mtu", "mtu"),
            ("jC", "j_c"),
            ("jMin", "j_min"),
            ("jMax", "j_max"),
            ("s1", "s1"),
            ("s2", "s2"),
            ("s3", "s3"),
            ("s4", "s4"),
            ("h1", "h1"),
            ("h2", "h2"),
            ("h3", "h3"),
            ("h4", "h4"),
            ("i1", "i1"),
            ("i2", "i2"),
            ("i3", "i3"),
            ("i4", "i4"),
            ("i5", "i5"),
            ("additionalConfig", "additional_config"),
            ("device", "device"),
            // AWG 3 range-valued knobs; validated above, stored verbatim.
            ("contentPaddingAddition", "content_padding_addition"),
            ("rekeyAfterTime", "rekey_after_time"),
            ("rekeyTimeout", "rekey_timeout"),
            ("rejectAfterTime", "reject_after_time"),
            ("keepaliveTimeout", "keepalive_timeout"),
            ("maxHandshakeAttempts", "max_handshake_attempts"),
        ];
        for (json_key, db_key) in &mappings {
            if let Some(val) = map.get(*json_key) {
                if let Some(s) = value_to_string(val) {
                    fields.insert(db_key.to_string(), s);
                }
            }
        }
        // AWG 3 booleans. Normalised to 0/1 through json_bool so a
        // checkbox posting "on" can't land in the DB as the string "on"
        // and read back as false.
        for (json_key, db_key) in [
            ("randomTrailers", "random_trailers"),
            ("disableCookies", "disable_cookies"),
        ] {
            if let Some(b) = map.get(json_key).and_then(json_bool) {
                fields.insert(db_key.to_string(), i64::from(b).to_string());
            }
        }
        // Header-protection key. Two ways in, because they answer different
        // questions: `headerProtectionKey` sets an exact value (matching an
        // existing deployment, or rotating to one you generated elsewhere),
        // while the `headerProtection` toggle asks the server to mint a
        // fresh key — or clear it. An explicit key wins if both are sent.
        //
        // Generating server-side rather than in the browser keeps the key
        // out of the request log and off the operator's clipboard; peers
        // receive it in their generated config either way.
        if let Some(explicit) = map.get("headerProtectionKey").and_then(|v| v.as_str()) {
            fields.insert("header_protection_key".into(), explicit.trim().to_string());
        } else if let Some(enable) = map.get("headerProtection").and_then(json_bool) {
            let stored = db::get_interface().map_err(map_err)?;
            let already_set = !stored.header_protection_key.is_empty();
            if enable && !already_set {
                fields.insert(
                    "header_protection_key".into(),
                    crate::wg::awg3::generate_header_protection_key(),
                );
            } else if !enable && already_set {
                fields.insert("header_protection_key".into(), String::new());
            }
        }
        // Special: firewall_enabled boolean
        if let Some(val) = map.get("firewallEnabled") {
            if let Some(s) = value_to_string(val) {
                fields.insert("firewall_enabled".into(), s);
            }
        }
        // DNS lockdown — three independent fields. Validate the target
        // here (instead of just at firewall-apply time) so a bad value
        // bounces back to the UI as a 4xx instead of getting silently
        // accepted into the DB and then failing on the next nft apply.
        if let Some(val) = map.get("dnsLockdownTarget") {
            if let Some(s) = value_to_string(val) {
                let trimmed = s.trim();
                if !trimmed.is_empty()
                    && trimmed.parse::<std::net::IpAddr>().is_err() {
                        return Err((
                            StatusCode::BAD_REQUEST,
                            Json(json!({
                                "error":
                                    "dnsLockdownTarget must be a valid IPv4 or IPv6 literal \
                                     (hostnames are not accepted)"
                            })),
                        ));
                    }
                fields.insert("dns_lockdown_target".into(), trimmed.to_string());
            }
        }
        if let Some(val) = map.get("dnsLockdown") {
            if let Some(s) = value_to_string(val) {
                fields.insert("dns_lockdown".into(), s);
            }
        }
        if let Some(val) = map.get("dnsBlockExternal") {
            if let Some(s) = value_to_string(val) {
                fields.insert("dns_block_external".into(), s);
            }
        }
    }

    if !fields.is_empty() {
        db::update_interface(&fields).map_err(map_err)?;
        wg::save_config_async().await.map_err(map_err)?;

        // Apply firewall changes if firewall_enabled or any DNS
        // lockdown field was touched. We re-read the interface row
        // rather than acting on `body` directly so the apply uses
        // exactly what the DB now holds — no risk of acting on a
        // partial update if a future caller batches multiple writes.
        if let Value::Object(ref map) = body {
            let firewall_touched = map.contains_key("firewallEnabled");
            let dns_touched = map.contains_key("dnsLockdown")
                || map.contains_key("dnsLockdownTarget")
                || map.contains_key("dnsBlockExternal");

            if firewall_touched || dns_touched {
                let iface = db::get_interface().map_err(map_err)?;
                // rebuild_rules handles both per-peer filtering and DNS
                // lockdown atomically, with the right "off" semantics
                // for each independently. Cheaper than two calls.
                crate::firewall::rebuild_rules_async().await.map_err(map_err).ok();

                // If per-peer firewall was specifically turned off and
                // DNS lockdown is also off, rebuild_rules() already
                // called remove_filtering. Nothing more to do.
                let _ = iface;
            }

            // The DPI proxy's start/stop decision now reads AmneziaWG 3
            // fields (see proxy::supervisor::should_remain_disabled), and
            // its packet transform reads S1-S4/H1-H4. Re-reconcile when any
            // of those moved so the running proxy matches the row that was
            // just written instead of the one it started with.
            let proxy_relevant = [
                "headerProtection",
                "headerProtectionKey",
                "randomTrailers",
                "s1",
                "s2",
                "s3",
                "s4",
                "h1",
                "h2",
                "h3",
                "h4",
            ]
            .iter()
            .any(|k| map.contains_key(*k));
            if proxy_relevant {
                if let Err(e) = crate::proxy::supervisor::ensure_running().await {
                    tracing::warn!("proxy reconcile after interface update failed: {e:#}");
                }
            }
        }
    }

    Ok(ok_success())
}

// ---------------------------------------------------------------------------
// POST /api/admin/interface/cidr — change CIDR + reassign client IPs
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ChangeCidrRequest {
    #[serde(rename = "ipv4Cidr")]
    pub ipv4_cidr: String,
    #[serde(rename = "ipv6Cidr")]
    pub ipv6_cidr: String,
}

pub async fn change_cidr(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<ChangeCidrRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;

    // Update CIDR in interface
    db::update_cidr(&body.ipv4_cidr, &body.ipv6_cidr).map_err(map_err)?;

    // Reassign all client IPs
    let clients = db::get_all_clients().map_err(map_err)?;
    let mut used_v4: Vec<String> = Vec::new();
    let mut used_v6: Vec<String> = Vec::new();

    for client in &clients {
        let new_v4 = db::next_ipv4(&body.ipv4_cidr, &used_v4).map_err(map_err)?;
        used_v4.push(new_v4.clone());

        let new_v6 = if !body.ipv6_cidr.is_empty() {
            let v6 = db::next_ipv6(&body.ipv6_cidr, &used_v6).map_err(map_err)?;
            used_v6.push(v6.clone());
            Some(v6)
        } else {
            None
        };

        let mut fields = db::UpdateMap::new();
        fields.insert("ipv4_address".into(), new_v4);
        if let Some(ref v6) = new_v6 {
            fields.insert("ipv6_address".into(), v6.clone());
        }
        db::update_client(client.id, &fields).map_err(map_err)?;
    }

    wg::save_config_async().await.map_err(map_err)?;

    Ok(ok_success())
}

// ---------------------------------------------------------------------------
// POST /api/admin/interface/restart — restart AmneziaWG
// ---------------------------------------------------------------------------

pub async fn restart_interface(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;

    wg::restart_async().await.map_err(map_err)?;

    // Re-apply firewall if enabled
    let iface = db::get_interface().map_err(map_err)?;
    if iface.firewall_enabled {
        crate::firewall::rebuild_rules_async().await.map_err(map_err).ok();
    }

    Ok(ok_success())
}

// ---------------------------------------------------------------------------
// IP detection helpers
// ---------------------------------------------------------------------------

/// Run a command with explicit argv; never invokes a shell.
fn run_argv(prog: &str, args: &[&str]) -> String {
    std::process::Command::new(prog)
        .args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

fn get_public_ip() -> String {
    // URLs are constants — no user input ever reaches the command line.
    for url in &["https://api.ipify.org", "https://ifconfig.me/ip"] {
        let out = run_argv("curl", &["-s", "--max-time", "5", url]);
        if !out.is_empty() && out.len() < 50 {
            return out;
        }
    }
    String::new()
}

fn get_private_ips() -> Vec<String> {
    // hostname -I prints all assigned IPv4 addresses on stdout.
    let out = run_argv("hostname", &["-I"]);
    if !out.is_empty() {
        return out.split_whitespace().map(|s| s.to_string()).collect();
    }
    // Fallback: parse `ip -4 addr show` output. Still no shell parsing.
    let out = run_argv("ip", &["-4", "addr", "show"]);
    let mut ips = Vec::new();
    for line in out.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("inet ") {
            if let Some(ip) = rest.split('/').next() {
                if ip != "127.0.0.1" {
                    ips.push(ip.to_string());
                }
            }
        }
    }
    ips
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_header_accepts_int_and_range() {
        for ok in ["5", "5-2147483647", "100-200", "0", "1-2"] {
            assert!(is_valid_magic_header(ok), "should accept {ok}");
        }
    }

    #[test]
    fn magic_header_rejects_injection_and_junk() {
        for bad in ["5\nPostUp = id", "5 6", "abc", "5-", "-5", "", "5-x", "1-2-3"] {
            assert!(!is_valid_magic_header(bad), "should reject {bad:?}");
        }
    }
}
