//! Session and user-profile handlers.
//!
//! | Method | Route            | Description          |
//! |--------|------------------|----------------------|
//! | POST   | /api/session     | Login                |
//! | GET    | /api/session     | Current user         |
//! | DELETE | /api/session     | Logout               |
//! | POST   | /api/me          | Update profile       |
//! | POST   | /api/me/password | Change password      |
//! | POST   | /api/me/totp     | Enable/disable TOTP  |

use crate::http::{ConnectInfo, State};
use crate::http::{HeaderMap, StatusCode};
use crate::http::Json;
use crate::http::{Cookie, CookieJar};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{api_err, map_err, ok_success, require_auth, AppState};
use crate::{auth, db};

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Per-key login attempt timestamps (seconds since epoch).
type AttemptStore = HashMap<String, Vec<u64>>;

static LOGIN_ATTEMPTS: OnceLock<Mutex<AttemptStore>> = OnceLock::new();

/// Hard cap on the number of distinct rate-limit keys (usernames + IPs) we
/// track at once. An attacker who cycles through unbounded distinct usernames
/// (or, behind a trusted proxy, spoofed `X-Forwarded-For` values) would
/// otherwise grow the map without bound — a memory-exhaustion DoS, since each
/// distinct value left a permanent entry. When the map exceeds this after a
/// live-window sweep we fail closed (429) rather than keep allocating.
const MAX_RATE_LIMIT_KEYS: usize = 16_384;

/// Longest subject string folded into a rate-limit key. Bounds per-key memory
/// regardless of how long a submitted username is.
const RATE_LIMIT_SUBJECT_MAX: usize = 64;

/// Build a length-bounded rate-limit key. The subject (username or IP) is
/// truncated on a char boundary so an attacker can't blow up key size with a
/// megabyte-long username.
fn rate_limit_key(prefix: &str, subject: &str) -> String {
    let bounded: String = subject.chars().take(RATE_LIMIT_SUBJECT_MAX).collect();
    format!("{prefix}:{bounded}")
}

fn login_attempts() -> &'static Mutex<AttemptStore> {
    LOGIN_ATTEMPTS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Per-source-IP attempt limiter for a non-login credential check.
///
/// The metrics endpoints gate the entire peer roster — names, transfer
/// counters, last handshake, and each peer's current remote endpoint IP —
/// behind a single static bearer token, and did so with no attempt limiting at
/// all, while `/api/session` next door has had one all along. Reuses the same
/// store and 60-second horizon so both paths age out together.
pub(crate) fn check_ip_attempt_limit(
    prefix: &str,
    ip: Option<&str>,
    limit: usize,
) -> Result<(), (StatusCode, Json<Value>)> {
    let Some(ip) = ip else { return Ok(()) };
    let mut attempts = login_attempts().lock().map_err(|e| {
        crate::error!("Rate limit lock poisoned: {e}");
        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if attempts.len() > MAX_RATE_LIMIT_KEYS {
        attempts.retain(|_, window| {
            window.retain(|t| now.saturating_sub(*t) < 60);
            !window.is_empty()
        });
        if attempts.len() > MAX_RATE_LIMIT_KEYS {
            return Err(api_err(
                StatusCode::TOO_MANY_REQUESTS,
                "Server is rate limiting. Try again later.",
            ));
        }
    }
    let key = rate_limit_key(prefix, ip);
    let window = attempts.entry(key).or_default();
    window.retain(|t| now.saturating_sub(*t) < 60);
    if window.len() >= limit {
        return Err(api_err(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many attempts from this address. Try again later.",
        ));
    }
    window.push(now);
    Ok(())
}

/// Resolve the client IP for a limiter key, honouring TRUST_PROXY.
pub(crate) fn client_ip_for_limit(
    headers: &crate::http::HeaderMap,
    peer: Option<std::net::SocketAddr>,
) -> Option<String> {
    resolve_client_ip(headers, peer)
}

/// Reset the rate limiter state (for tests).
pub fn reset_login_attempts() {
    if let Some(m) = LOGIN_ATTEMPTS.get() {
        if let Ok(mut g) = m.lock() {
            g.clear();
        }
    }
}

/// Resolve a client identifier for rate limiting. `X-Forwarded-For` /
/// `X-Real-IP` are honoured ONLY when `TRUST_PROXY=true` — those headers are
/// trivially forged by a direct client, so trusting them unconditionally let
/// an attacker rotate the header to evade the per-IP bucket (and mint
/// unlimited distinct keys). When not trusting the proxy, or when no header is
/// present, we fall back to the real peer socket address. Used for rate
/// limiting only — never for authentication decisions.
fn resolve_client_ip(headers: &HeaderMap, peer: Option<SocketAddr>) -> Option<String> {
    if crate::config::CONFIG.trust_proxy {
        if let Some(v) = headers.get("x-forwarded-for").and_then(|h| h.to_str().ok()) {
            // Take the RIGHTMOST entry, not the leftmost. The standard reverse-
            // proxy idiom (nginx `$proxy_add_x_forwarded_for`, Apache
            // mod_proxy) *appends* the real peer to whatever the client sent,
            // so the header reads `<client-forged…>, <real-peer>`. The leftmost
            // token is therefore fully attacker-controlled — trusting it let a
            // client mint a fresh rate-limit bucket per request and evade the
            // per-IP limiter. The rightmost entry is the address our own
            // trusted proxy vouched for.
            if let Some(last) = v.split(',').next_back() {
                let s = last.trim();
                if !s.is_empty() {
                    return Some(s.to_string());
                }
            }
        }
        if let Some(v) = headers.get("x-real-ip").and_then(|h| h.to_str().ok()) {
            let s = v.trim();
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    peer.map(|a| a.ip().to_string())
}

/// Pre-computed Argon2id hash of a constant string. Used to make username
/// enumeration via timing impossible — when a user is missing we still spend
/// ~the same wall-clock time as a real verify before returning 401.
fn dummy_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| {
        crate::auth::hash_password("___dummy___never___match___")
            .expect("dummy hash")
    })
}

// ---------------------------------------------------------------------------
// Login body
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub remember: bool,
    // Accept both `totpCode` (legacy / Node.js upstream) and `totp` (the
    // shorter form the redesigned UI sends). Ignoring this field meant
    // every TOTP-protected account was unauthable from the browser.
    #[serde(rename = "totpCode", alias = "totp", default)]
    pub totp_code: Option<String>,
}

// ---------------------------------------------------------------------------
// POST /api/session — login
// ---------------------------------------------------------------------------

pub async fn create_session(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    // Optional so the extractor never fails: present in production (the router
    // is served with connect-info), absent in `oneshot` unit tests.
    peer: Option<ConnectInfo<SocketAddr>>,
    Json(body): Json<LoginRequest>,
) -> Result<(CookieJar, Json<Value>), (StatusCode, Json<Value>)> {
    // Rate limiting: per-username (10/min) AND per-source-IP (50/min). The
    // IP bucket prevents an attacker from spreading attempts across many
    // usernames; the username bucket prevents distributed credential-stuffing
    // against a single account.
    let client_ip = resolve_client_ip(&headers, peer.map(|ConnectInfo(a)| a));
    {
        let mut attempts = login_attempts().lock().map_err(|e| {
            crate::error!("Rate limit lock poisoned: {e}");
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Bound the key space. When the map has grown large, sweep out every
        // window whose timestamps have all aged out of the 60s horizon — that
        // alone reclaims the keys left by a username/IP-cycling attacker. If
        // we're still over the cap afterwards we're under a genuine flood, so
        // fail closed for new subjects rather than keep allocating.
        if attempts.len() > MAX_RATE_LIMIT_KEYS {
            attempts.retain(|_, window| {
                window.retain(|t| now.saturating_sub(*t) < 60);
                !window.is_empty()
            });
            if attempts.len() > MAX_RATE_LIMIT_KEYS {
                return Err(api_err(
                    StatusCode::TOO_MANY_REQUESTS,
                    "Server is rate limiting. Try again later.",
                ));
            }
        }

        // Per-username bucket. Empty windows are evicted so a one-shot attempt
        // against a never-seen username doesn't leave a permanent key.
        let user_key = rate_limit_key("user", &body.username);
        let user_window = attempts.entry(user_key.clone()).or_default();
        user_window.retain(|t| now.saturating_sub(*t) < 60);
        if user_window.len() >= 10 {
            return Err(api_err(
                StatusCode::TOO_MANY_REQUESTS,
                "Too many login attempts. Try again later.",
            ));
        }
        user_window.push(now);

        // Per-source-IP bucket
        if let Some(ip) = client_ip.as_deref() {
            let ip_key = rate_limit_key("ip", ip);
            let ip_window = attempts.entry(ip_key).or_default();
            ip_window.retain(|t| now.saturating_sub(*t) < 60);
            if ip_window.len() >= 50 {
                // This username's attempt was already recorded above; drop its
                // window if it would otherwise linger as a stale single entry.
                if attempts.get(&user_key).is_some_and(|w| w.is_empty()) {
                    attempts.remove(&user_key);
                }
                return Err(api_err(
                    StatusCode::TOO_MANY_REQUESTS,
                    "Too many login attempts from this address. Try again later.",
                ));
            }
            ip_window.push(now);
        }
    }

    // Look up user — but ALWAYS run argon2 verification against either the
    // real hash or a constant dummy hash so the response time does not leak
    // whether a username exists. The dummy hash is generated once at startup.
    let lookup = db::get_user_by_username(&body.username);
    let (user_opt, hash_to_check) = match lookup {
        Ok(u) => {
            let hash = u.password.clone();
            (Some(u), hash)
        }
        Err(_) => (None, dummy_hash().to_string()),
    };

    let valid = auth::verify_password(&body.password, &hash_to_check)
        .map_err(map_err)?;
    let user = match user_opt {
        Some(u) if valid && u.enabled => u,
        _ => {
            return Err(api_err(
                StatusCode::UNAUTHORIZED,
                "Invalid username or password",
            ));
        }
    };

    // TOTP check — only enforced once the secret is verified.
    if let Some(ref totp_key) = user.totp_key {
        if user.totp_verified && !totp_key.is_empty() {
            match body.totp_code {
                Some(ref code) => {
                    // Burn one TOTP attempt against this user's bucket so a
                    // password+TOTP brute-force is bounded independently of
                    // the password rate limiter.
                    check_totp_rate_limit(user.id)?;
                    match verify_totp_code_step(totp_key, code)? {
                        Some(step) => {
                            // Single-use: reject any code whose timestep was
                            // already consumed, so a captured/observed code
                            // can't be replayed within its validity window.
                            let last = db::get_totp_last_step(user.id).map_err(map_err)?;
                            if (step as i64) <= last {
                                return Err(api_err(
                                    StatusCode::UNAUTHORIZED,
                                    "TOTP code already used — wait for the next one",
                                ));
                            }
                            db::set_totp_last_step(user.id, step as i64).map_err(map_err)?;
                        }
                        None => {
                            return Err(api_err(StatusCode::UNAUTHORIZED, "Invalid TOTP code"));
                        }
                    }
                }
                None => {
                    return Ok((jar, Json(json!({ "status": "TOTP_REQUIRED" }))));
                }
            }
        }
    }

    // Generate session token and store
    let token = auth::generate_session_token();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let session_data = super::SessionData {
        user_id: user.id,
        username: user.username.clone(),
        role: user.role,
        created_at: now,
    };

    {
        let mut sessions = state.sessions.lock().map_err(|e| {
            api_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Session lock error: {e}"),
            )
        })?;
        sessions.insert(token.clone(), session_data);
    }

    // Build cookie
    let secure = !crate::config::CONFIG.insecure;
    let cookie = Cookie::build(("awg_session", token))
        .path("/")
        .http_only(true)
        .secure(secure)
        .same_site(crate::http::SameSite::Strict);

    let cookie = if body.remember {
        cookie.max_age(time::Duration::days(30))
            .build()
    } else {
        cookie.build()
    };

    let jar = jar.add(cookie);

    let resp = json!({
        "status": "success",
        "user": {
            "id": user.id,
            "username": user.username,
            "name": user.name,
            "role": user.role,
            "email": user.email,
            "totpVerified": user.totp_verified,
        }
    });

    Ok((jar, Json(resp)))
}

// ---------------------------------------------------------------------------
// GET /api/session — current user
// ---------------------------------------------------------------------------

pub async fn get_session(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let user = require_auth(&jar, &state)?;

    Ok(Json(json!({
        "user": {
            "id": user.id,
            "username": user.username,
            "name": user.name,
            "role": user.role,
            "email": user.email,
            "totpVerified": user.totp_verified,
        }
    })))
}

// ---------------------------------------------------------------------------
// DELETE /api/session — logout
// ---------------------------------------------------------------------------

pub async fn delete_session(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, Json<Value>), (StatusCode, Json<Value>)> {
    // Remove session from store if cookie present
    if let Some(cookie) = jar.get("awg_session") {
        let token = cookie.value().to_string();
        if let Ok(mut sessions) = state.sessions.lock() {
            sessions.remove(&token);
        }
    }

    // Clear the cookie
    let jar = jar.remove(Cookie::from("awg_session"));

    Ok((jar, Json(json!({ "success": true }))))
}

// ---------------------------------------------------------------------------
// POST /api/me — update current user profile
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct UpdateMeRequest {
    #[serde(rename = "currentPassword")]
    pub current_password: Option<String>,
    pub email: Option<String>,
    pub name: Option<String>,
}

pub async fn update_me(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<UpdateMeRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let user = require_auth(&jar, &state)?;

    // Verify current password if changing password-sensitive fields
    if let Some(ref pw) = body.current_password {
        let valid = auth::verify_password(pw, &user.password).map_err(map_err)?;
        if !valid {
            return Err(api_err(StatusCode::UNAUTHORIZED, "Invalid current password"));
        }
    }

    let mut fields = db::UpdateMap::new();
    if let Some(ref email) = body.email {
        fields.insert("email".into(), email.clone());
    }
    if let Some(ref name) = body.name {
        fields.insert("name".into(), name.clone());
    }

    if !fields.is_empty() {
        db::update_user(user.id, &fields).map_err(map_err)?;
    }

    Ok(ok_success())
}

// ---------------------------------------------------------------------------
// POST /api/me/password — change password
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    #[serde(rename = "currentPassword")]
    pub current_password: String,
    #[serde(rename = "newPassword")]
    pub new_password: String,
    /// Optional client-side double-check. When provided, must equal
    /// `newPassword`; setup flow already validates this and the change-password
    /// flow should be consistent.
    #[serde(rename = "confirmPassword", default)]
    pub confirm_password: Option<String>,
}

pub async fn change_password(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<ChangePasswordRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let user = require_auth(&jar, &state)?;

    // Verify current password
    let valid = auth::verify_password(&body.current_password, &user.password)
        .map_err(map_err)?;
    if !valid {
        return Err(api_err(StatusCode::UNAUTHORIZED, "Invalid current password"));
    }

    // If the caller sent confirmPassword, it must match. Defense in depth
    // against a UI that forgets to validate before submit.
    if let Some(ref confirm) = body.confirm_password {
        if confirm != &body.new_password {
            return Err(api_err(
                StatusCode::BAD_REQUEST,
                "New password and confirmation do not match",
            ));
        }
    }

    if body.new_password.chars().count() < 12 {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "Password must be at least 12 characters",
        ));
    }

    // Hash and store new password
    let hash = auth::hash_password(&body.new_password).map_err(map_err)?;
    db::update_password(user.id, &hash).map_err(map_err)?;

    // Evict every other session for this user. A password change is what
    // someone does after suspecting their session was stolen; without this it
    // would not actually remove the attacker's access.
    let current = super::session_token(&jar);
    super::revoke_user_sessions(&state, user.id, current.as_deref());

    Ok(ok_success())
}

// ---------------------------------------------------------------------------
// POST /api/me/totp — set up / verify / delete TOTP
// ---------------------------------------------------------------------------
//
// Mirrors the original Node.js contract:
//
//   { type: "setup" }
//       → server generates a fresh secret, stores it as unverified, and
//         returns { type: "setup", key: <base32>, uri: <otpauth://...> }.
//   { type: "create", code: "123456" }
//       → verifies the code against the stored secret, marks totp_verified=1.
//   { type: "delete", currentPassword: "..." }
//       → requires the current password and clears the secret.
//
// The secret is generated server-side; it never travels from the browser to
// the server, eliminating an entire class of MITM/CSRF attack surface.

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum TotpRequest {
    Setup {
        // Required only when a verified TOTP secret already exists — rotating
        // an active second factor must re-prove the password so a hijacked
        // session can't silently replace the victim's 2FA. Optional/ignored on
        // first-time enrolment (no verified secret yet).
        #[serde(rename = "currentPassword", default)]
        current_password: Option<String>,
    },
    Create {
        code: String,
    },
    Delete {
        #[serde(rename = "currentPassword")]
        current_password: String,
    },
}

pub async fn toggle_totp(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<TotpRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let user = require_auth(&jar, &state)?;

    match body {
        TotpRequest::Setup { current_password } => {
            // If a verified 2FA secret is already active, require the current
            // password before overwriting it — otherwise anyone holding a live
            // session cookie could rotate the victim's second factor to one
            // they control (a 2FA takeover / lockout). First-time enrolment
            // (no verified secret) needs no password.
            if user.totp_verified {
                let ok = current_password
                    .as_deref()
                    .map(|pw| auth::verify_password(pw, &user.password))
                    .transpose()
                    .map_err(map_err)?
                    .unwrap_or(false);
                if !ok {
                    return Err(api_err(
                        StatusCode::UNAUTHORIZED,
                        "Current password is required to change an active TOTP secret",
                    ));
                }
            }
            // Generate a fresh 20-byte secret per RFC 6238 recommendations.
            let mut secret = [0u8; 20];
            crate::rng::fill(&mut secret);
            let key_b32 = base32_encode(&secret);

            // Build the otpauth:// URI for QR code consumption.
            let issuer = "wg-easy";
            let label = url_encode(&format!("{}:{}", issuer, user.username));
            let uri = format!(
                "otpauth://totp/{label}?secret={key}&issuer={issuer}&algorithm=SHA1&digits=6&period=30",
                label = label,
                key = key_b32,
                issuer = issuer,
            );

            // Persist as unverified.
            let mut fields = db::UpdateMap::new();
            fields.insert("totp_key".into(), key_b32.clone());
            fields.insert("totp_verified".into(), "0".into());
            db::update_user(user.id, &fields).map_err(map_err)?;

            Ok(Json(json!({
                "success": true,
                "type": "setup",
                "key": key_b32,
                "uri": uri,
            })))
        }
        TotpRequest::Create { code } => {
            let key = user.totp_key.ok_or_else(|| {
                api_err(
                    StatusCode::BAD_REQUEST,
                    "No TOTP setup in progress — call type=setup first",
                )
            })?;
            // Burn one TOTP attempt against this user's bucket.
            check_totp_rate_limit(user.id)?;
            let secret = base32_decode(&key).ok_or_else(|| {
                api_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Stored TOTP key is not valid base32",
                )
            })?;
            let step = match verify_totp_secret_step(&secret, &code)? {
                Some(s) => s,
                None => return Err(api_err(StatusCode::BAD_REQUEST, "Invalid TOTP code")),
            };
            let mut fields = db::UpdateMap::new();
            fields.insert("totp_verified".into(), "1".into());
            db::update_user(user.id, &fields).map_err(map_err)?;
            // Consume the enrolment code's timestep so it can't be immediately
            // replayed at the login prompt.
            db::set_totp_last_step(user.id, step as i64).map_err(map_err)?;
            Ok(Json(json!({
                "success": true,
                "type": "created",
            })))
        }
        TotpRequest::Delete { current_password } => {
            let valid = auth::verify_password(&current_password, &user.password)
                .map_err(map_err)?;
            if !valid {
                return Err(api_err(StatusCode::UNAUTHORIZED, "Invalid current password"));
            }
            let mut fields = db::UpdateMap::new();
            fields.insert("totp_key".into(), String::new());
            fields.insert("totp_verified".into(), "0".into());
            db::update_user(user.id, &fields).map_err(map_err)?;
            // Removing the second factor is a credential change: evict the
            // user's other sessions so a stolen one cannot outlive it.
            let current = super::session_token(&jar);
            super::revoke_user_sessions(&state, user.id, current.as_deref());
            Ok(Json(json!({
                "success": true,
                "type": "deleted",
            })))
        }
    }
}

// ---------------------------------------------------------------------------
// TOTP attempt rate limiter — independent of the password rate limiter so a
// successful login can't be coupled with a brute-force on the 6-digit code.
// ---------------------------------------------------------------------------

static TOTP_ATTEMPTS: OnceLock<Mutex<HashMap<i64, Vec<u64>>>> = OnceLock::new();

fn totp_attempts() -> &'static Mutex<HashMap<i64, Vec<u64>>> {
    TOTP_ATTEMPTS.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn reset_totp_attempts() {
    if let Some(m) = TOTP_ATTEMPTS.get() {
        if let Ok(mut g) = m.lock() {
            g.clear();
        }
    }
}

/// Allow at most 5 TOTP-code attempts per 5-minute window per user.
fn check_totp_rate_limit(user_id: i64) -> Result<(), (StatusCode, Json<Value>)> {
    let mut attempts = totp_attempts().lock().map_err(|e| {
        api_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("TOTP rate limit error: {e}"),
        )
    })?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let window = attempts.entry(user_id).or_default();
    window.retain(|t| now.saturating_sub(*t) < 300);
    if window.len() >= 5 {
        return Err(api_err(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many TOTP attempts. Try again later.",
        ));
    }
    window.push(now);
    Ok(())
}

// ---------------------------------------------------------------------------
// base32 encode / decode (RFC 4648, no padding) — used for TOTP secrets.
// We avoid pulling in another crate for ~30 lines of code.
// ---------------------------------------------------------------------------

fn base32_encode(bytes: &[u8]) -> String {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity(bytes.len() * 8 / 5 + 1);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &b in bytes {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buf >> bits) & 0x1F) as usize;
            out.push(ALPHA[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buf << (5 - bits)) & 0x1F) as usize;
        out.push(ALPHA[idx] as char);
    }
    out
}

fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for c in s.chars() {
        if c == '=' || c.is_whitespace() {
            continue;
        }
        let v: u32 = match c {
            'A'..='Z' => (c as u8 - b'A') as u32,
            'a'..='z' => (c as u8 - b'a') as u32,
            '2'..='7' => 26 + (c as u8 - b'2') as u32,
            _ => return None,
        };
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    Some(out)
}

/// URL-encode a path segment for the otpauth URI (RFC 3986 unreserved + `%`).
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// TOTP helper
// ---------------------------------------------------------------------------

/// Verify a TOTP code against the **stored base32 secret**. Used at login
/// after the secret has been stored on the user row. Tries the current
/// 30-second window. Constant-time on the result; the totp-rs library does
/// not expose a const-time comparison so we collapse failures into a single
/// boolean.
/// Verify a TOTP code and return the matched 30-second timestep on success
/// (so the caller can enforce single-use / replay protection).
fn verify_totp_code_step(
    key_b32: &str,
    code: &str,
) -> Result<Option<u64>, (StatusCode, Json<Value>)> {
    let secret = base32_decode(key_b32).ok_or_else(|| {
        api_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Stored TOTP key is not valid base32",
        )
    })?;
    verify_totp_secret_step(&secret, code)
}

/// Verify a TOTP code and return the matched timestep (`time / 30`) so the
/// caller can reject reuse. Replicates the library's skew-1 window (previous,
/// current, next step) explicitly — `check_current` only yields a bool, which
/// isn't enough to identify *which* code was consumed. The per-candidate
/// compare is constant-time so the matched step doesn't leak via timing.
fn verify_totp_secret_step(
    secret: &[u8],
    code: &str,
) -> Result<Option<u64>, (StatusCode, Json<Value>)> {
    if !code.chars().all(|c| c.is_ascii_digit()) || code.len() != 6 {
        return Ok(None);
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // TOTP step number: floor(unix_time / period), period = 30s (RFC 6238).
    let current = now / 30;
    // Accept ±1 step (±30s) to tolerate client/server clock drift. The matched
    // step is returned so the caller can reject replay of an already-used code.
    for step in [current.saturating_sub(1), current, current + 1] {
        let expected = hotp_sha1(secret, step);
        if ct_eq(expected.as_bytes(), code.as_bytes()) {
            return Ok(Some(step));
        }
    }
    Ok(None)
}

/// RFC 4226 HOTP with SHA-1, 6 digits — the primitive behind our RFC 6238
/// TOTP. `counter` is the moving factor (for TOTP, `unix_time / period`).
/// Replaces the `totp-rs` dependency, whose only use here was this exact
/// computation; hand-rolling it drops totp-rs's entire url/idna/ICU subtree.
fn hotp_sha1(secret: &[u8], counter: u64) -> String {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;

    // HMAC accepts a key of any length, so this never errors.
    let mut mac = <Hmac<Sha1>>::new_from_slice(secret).expect("HMAC key length is unrestricted");
    mac.update(&counter.to_be_bytes());
    let hs = mac.finalize().into_bytes();

    // Dynamic truncation (RFC 4226 §5.3): the low nibble of the last byte
    // selects a 4-byte window; mask the top bit to stay positive.
    let offset = (hs[19] & 0x0f) as usize;
    let bin = (u32::from(hs[offset] & 0x7f) << 24)
        | (u32::from(hs[offset + 1]) << 16)
        | (u32::from(hs[offset + 2]) << 8)
        | u32::from(hs[offset + 3]);
    format!("{:06}", bin % 1_000_000)
}

/// Constant-time byte-slice equality (length-independent short-circuit only on
/// length, which is fixed at 6 here anyway).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    /// RFC 4226 Appendix D reference vectors: secret is the ASCII string
    /// "12345678901234567890" (20 bytes), 6 digits, counters 0..=9. Locks our
    /// hand-rolled HOTP to the standard so it stays interoperable with every
    /// authenticator app (Google Authenticator, Aegis, 1Password, …).
    #[test]
    fn hotp_sha1_matches_rfc4226_vectors() {
        let secret = b"12345678901234567890";
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, want) in expected.iter().enumerate() {
            assert_eq!(&hotp_sha1(secret, counter as u64), want, "counter {counter}");
        }
    }

    /// RFC 6238 uses HOTP with counter = unix_time / period. Cross-check the
    /// SHA-1 TOTP vector from RFC 6238 Appendix B (secret "12345678901234567890",
    /// T = 59s → step 1 → code 94287082, truncated to 6 digits = 287082).
    #[test]
    fn totp_step_matches_rfc6238_sha1_vector() {
        let secret = b"12345678901234567890";
        // 59s / 30 = step 1.
        assert_eq!(hotp_sha1(secret, 59 / 30), "287082");
        // 1111111109s / 30 = step 37037036 → RFC vector 07081804 → 081804.
        assert_eq!(hotp_sha1(secret, 1111111109 / 30), "081804");
    }

    #[test]
    fn rate_limit_key_truncates_long_subjects() {
        // A megabyte-long username must not produce a megabyte-long key.
        let long = "a".repeat(5000);
        let key = rate_limit_key("user", &long);
        assert!(key.starts_with("user:"));
        assert_eq!(key.len(), "user:".len() + RATE_LIMIT_SUBJECT_MAX);
    }

    #[test]
    fn rate_limit_key_truncates_on_char_boundary() {
        // Multi-byte chars: take() counts chars, never splitting a code point.
        let s = "é".repeat(200);
        let key = rate_limit_key("ip", &s);
        assert!(key.starts_with("ip:"));
        // 64 two-byte chars → 128 bytes of subject.
        assert_eq!(key.len(), "ip:".len() + RATE_LIMIT_SUBJECT_MAX * 2);
    }

    #[test]
    fn resolve_client_ip_uses_peer_when_proxy_untrusted() {
        // Default config has trust_proxy = false, so a forged X-Forwarded-For
        // is ignored and the real peer address is used.
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "1.2.3.4".parse().unwrap());
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 5555);
        assert_eq!(
            resolve_client_ip(&h, Some(peer)).as_deref(),
            Some("9.9.9.9")
        );
    }

    #[test]
    fn resolve_client_ip_none_without_peer() {
        assert_eq!(resolve_client_ip(&HeaderMap::new(), None), None);
    }
}
