//! Setup wizard handlers (first-run configuration).
//!
//! | Method | Route              | Description                    |
//! |--------|--------------------|--------------------------------|
//! | POST   | /api/setup/2       | Create admin user              |
//! | GET    | /api/setup/4       | Get IP info for host selection |
//! | POST   | /api/setup/4       | Set host and port              |

use crate::http::State;
use crate::http::StatusCode;
use crate::http::Json;
use crate::http::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{api_err, map_err, require_auth, AppState};
use crate::{auth, db};

// ---------------------------------------------------------------------------
// POST /api/setup/2 — create admin user
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SetupStep2Request {
    pub username: String,
    pub password: String,
    #[serde(rename = "confirmPassword")]
    pub confirm_password: String,
}

pub async fn setup_step2(
    State(_state): State<AppState>,
    _jar: CookieJar,
    Json(body): Json<SetupStep2Request>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Check passwords match
    if body.password != body.confirm_password {
        return Err(api_err(StatusCode::BAD_REQUEST, "Passwords do not match"));
    }

    if body.password.chars().count() < 12 {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "Password must be at least 12 characters",
        ));
    }

    if body.username.len() < 3 {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "Username must be at least 3 characters",
        ));
    }
    if body.username.len() > 64 {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "Username must be at most 64 characters",
        ));
    }

    // Check setup step (should be 1 or 2, or 0 if no users exist)
    let step = db::get_setup_step().map_err(map_err)?;
    if step != 1 && step != 2 {
        // Allow step 0 (setup marked complete) only when no users exist
        if step == 0 {
            let user_count = db::get_user_count().unwrap_or(0);
            if user_count > 0 {
                return Err(api_err(
                    StatusCode::BAD_REQUEST,
                    "Setup already completed (admin user already exists)",
                ));
            }
            // step == 0 with no users: allow proceeding (recovering from bad state)
        } else {
            return Err(api_err(
                StatusCode::BAD_REQUEST,
                "Setup already completed or in invalid state",
            ));
        }
    }

    // Hash password and create admin user
    let hash = auth::hash_password(&body.password).map_err(map_err)?;
    let params = db::CreateUserParams {
        username: body.username,
        password: hash,
        email: None,
        name: "Admin".into(),
        role: 1, // admin
        totp_key: None,
        totp_verified: false,
        enabled: true,
    };

    db::create_user(&params).map_err(map_err)?;

    // Advance setup step
    db::set_setup_step(3).map_err(map_err)?;

    Ok(Json(json!({ "success": true, "step": 3 })))
}

// ---------------------------------------------------------------------------
// GET /api/setup/4 — get IP info for host selection
// ---------------------------------------------------------------------------

pub async fn setup_step4_get(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // After initial setup is finished, this endpoint becomes admin-only —
    // it shells out to curl/ip to gather network info and must not be
    // exposed unauthenticated on a running deployment.
    let setup_step = db::get_setup_step().unwrap_or(0);
    if setup_step == 0 {
        let user = require_auth(&jar, &state)?;
        if user.role < 1 {
            return Err(api_err(StatusCode::FORBIDDEN, "Admin access required"));
        }
    }

    let public_ip = detect_public_ip();
    let private_ips = detect_private_ips();

    Ok(Json(json!({
        "publicIp": public_ip,
        "privateIps": private_ips,
    })))
}

// ---------------------------------------------------------------------------
// POST /api/setup/4 — set host and port
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SetupStep4Request {
    pub host: String,
    pub port: Option<u16>,
}

pub async fn setup_step4_post(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<SetupStep4Request>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Check setup step (should be 3 — ready for host/port config)
    let step = db::get_setup_step().map_err(map_err)?;
    if step != 3 {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "Setup not ready for this step. Complete step 2 first.",
        ));
    }

    // Once an admin exists, this stops being first-run setup and becomes an
    // ordinary configuration write: `host` is interpolated into the Endpoint
    // line of every generated peer config, so an unauthenticated caller could
    // otherwise point every future client at an address of their choosing.
    if db::get_user_count().unwrap_or(0) > 0 {
        let _admin = crate::api::admin::require_admin(&jar, &state)?;
    }

    // Reject anything that is not a hostname or IP literal before it reaches
    // a config file.
    if !is_valid_endpoint_host(&body.host) {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "host must be a hostname or IP address",
        ));
    }

    // Update host and port in user_config
    let port = body.port.unwrap_or(51820);
    db::update_host_port(&body.host, port as i64).map_err(map_err)?;

    // Also update the interface port
    let mut iface_fields = db::UpdateMap::new();
    iface_fields.insert("port".into(), port.to_string());
    db::update_interface(&iface_fields).map_err(map_err)?;

    // Mark setup as complete
    db::set_setup_step(0).map_err(map_err)?;

    Ok(Json(json!({ "success": true, "step": 0 })))
}

// ---------------------------------------------------------------------------
// IP detection helpers (shared with admin module logic)
// ---------------------------------------------------------------------------

fn run_argv(prog: &str, args: &[&str]) -> String {
    std::process::Command::new(prog)
        .args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

fn detect_public_ip() -> String {
    for url in &["https://api.ipify.org", "https://ifconfig.me/ip"] {
        let out = run_argv("curl", &["-s", "--max-time", "5", url]);
        if !out.is_empty() && out.len() < 50 {
            return out;
        }
    }
    String::new()
}

fn detect_private_ips() -> Vec<String> {
    let out = run_argv("hostname", &["-I"]);
    if !out.is_empty() {
        return out.split_whitespace().map(|s| s.to_string()).collect();
    }
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

/// Accept only a hostname or IP literal for the peer `Endpoint` host.
///
/// This value is interpolated verbatim into every generated client config, so
/// it must not be able to carry a newline (which would inject a further config
/// directive) or the surrounding punctuation of an `Endpoint = host:port`
/// line. Deliberately permissive about the shape of a *name* — internationalised
/// and single-label hostnames are legitimate — and strict about the character
/// set.
fn is_valid_endpoint_host(host: &str) -> bool {
    // Deliberately does NOT trim: the caller stores exactly what it validated,
    // so accepting surrounding whitespace here would let a trailing `\r` or
    // space through into the config file.
    let h = host;
    if h.is_empty() || h.len() > 253 {
        return false;
    }
    // An IPv6 literal is written bare here; the config generator adds the
    // brackets. Accept it via the standard parser rather than by character set.
    if h.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    // Hostname: letters, digits, dot and hyphen only. No label may be empty,
    // which also rejects a leading/trailing dot and a doubled dot.
    h.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

#[cfg(test)]
mod host_validation_tests {
    use super::is_valid_endpoint_host;

    #[test]
    fn accepts_real_endpoint_hosts() {
        for ok in [
            "vpn.example.com",
            "example.com",
            "localhost",
            "203.0.113.7",
            "2001:db8::1",
            "a-b.c-d.example",
        ] {
            assert!(is_valid_endpoint_host(ok), "should accept {ok:?}");
        }
    }

    #[test]
    fn rejects_values_that_could_inject_a_config_directive() {
        for bad in [
            "",
            "   ",
            "vpn.example.com\nPostUp = id",
            "vpn.example.com:51820",
            "vpn.example.com/../x",
            "vpn example.com",
            "vpn.example.com\r",
            ".example.com",
            "example..com",
            "example.com.",
            "vpn.example.com#comment",
        ] {
            assert!(!is_valid_endpoint_host(bad), "should reject {bad:?}");
        }
    }
}
