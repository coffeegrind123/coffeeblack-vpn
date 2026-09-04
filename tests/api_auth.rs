//! Track 3: API auth tests — login, logout, session, rate limiter, TOTP,
//! Secure cookie, setup wizard.
//!
//! Uses `awg_easy_rs::http::Body` and `Router::oneshot` to send HTTP requests
//! against the full router with a test database.

mod common;

use awg_easy_rs::{api, auth, db};
use awg_easy_rs::http::Body;
use awg_easy_rs::http::{header, Request, StatusCode};
use serde_json::{json, Value};
use serial_test::serial;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn seed() {
    common::seed();
}

fn router() -> awg_easy_rs::http::Router {
    api::build_router(api::AppState::new())
}

fn create_admin() -> i64 {
    let hash = auth::hash_password("admin123").unwrap();
    db::create_user(&db::CreateUserParams {
        username: "admin".into(),
        password: hash,
        email: Some("admin@example.com".into()),
        name: "Admin".into(),
        role: 1,
        totp_key: None,
        totp_verified: false,
        enabled: true,
    })
    .unwrap()
}

async fn login(app: &awg_easy_rs::http::Router, username: &str, password: &str, totp_code: Option<&str>) -> (StatusCode, Value, Option<String>) {
    let mut body = json!({ "username": username, "password": password });
    if let Some(code) = totp_code {
        body["totpCode"] = json!(code);
    }
    let req = Request::builder()
        .method("POST")
        .uri("/api/session")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let cookies: Vec<String> = resp
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect();
    let session_cookie = cookies
        .into_iter()
        .find(|c| c.starts_with("awg_session="));
    let body_bytes = awg_easy_rs::http::to_bytes(resp.into_body(), 1024 * 1024).unwrap();
    let body: Value = serde_json::from_slice(&body_bytes).unwrap_or(json!({}));
    (status, body, session_cookie)
}

async fn get(app: &awg_easy_rs::http::Router, path: &str, cookie: Option<&str>) -> (StatusCode, Value) {
    let mut builder = Request::builder().method("GET").uri(path);
    if let Some(c) = cookie {
        builder = builder.header(header::COOKIE, c);
    }
    let req = builder.body(Body::empty()).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body_bytes = awg_easy_rs::http::to_bytes(resp.into_body(), 1024 * 1024).unwrap();
    let body: Value = serde_json::from_slice(&body_bytes).unwrap_or(json!({}));
    (status, body)
}

// ---------------------------------------------------------------------------
// Login / Logout / Session
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(db)]
async fn login_success() {
    seed();
    create_admin();
    let app = router();
    let (status, body, cookie) = login(&app, "admin", "admin123", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "success");
    assert!(cookie.is_some());
}

#[tokio::test]
#[serial(db)]
async fn login_invalid_username() {
    seed();
    create_admin();
    let app = router();
    let (status, body, cookie) = login(&app, "nonexistent", "admin123", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "Invalid username or password");
    assert!(cookie.is_none());
}

#[tokio::test]
#[serial(db)]
async fn login_invalid_password() {
    seed();
    create_admin();
    let app = router();
    let (status, body, cookie) = login(&app, "admin", "wrongpass", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "Invalid username or password");
    assert!(cookie.is_none());
}

#[tokio::test]
#[serial(db)]
async fn login_disabled_user() {
    seed();
    let hash = auth::hash_password("pass").unwrap();
    db::create_user(&db::CreateUserParams {
        username: "disabled".into(),
        password: hash,
        email: None,
        name: "Disabled".into(),
        role: 0,
        totp_key: None,
        totp_verified: false,
        enabled: false,
    })
    .unwrap();
    let app = router();
    let (status, body, _) = login(&app, "disabled", "pass", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Disabled users return the same generic message as wrong-password to
    // avoid leaking account state. Just assert that the request was denied.
    assert_eq!(body["error"], "Invalid username or password");
}

#[tokio::test]
#[serial(db)]
async fn login_empty_username() {
    seed();
    let app = router();
    let (status, _, _) = login(&app, "", "pass", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[serial(db)]
async fn session_check_authenticated() {
    seed();
    create_admin();
    let app = router();
    let (_, _, cookie) = login(&app, "admin", "admin123", None).await;
    let cookie = cookie.unwrap();
    let session_val = cookie
        .strip_prefix("awg_session=")
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let (status, body) = get(&app, "/api/session", Some(&format!("awg_session={session_val}"))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["user"]["username"], "admin");
}

#[tokio::test]
#[serial(db)]
async fn session_check_unauthenticated() {
    seed();
    let app = router();
    let (status, body) = get(&app, "/api/session", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "Not authenticated");
}

#[tokio::test]
#[serial(db)]
async fn logout() {
    seed();
    create_admin();
    let app = router();
    let (_, _, cookie) = login(&app, "admin", "admin123", None).await;
    let cookie = cookie.unwrap();
    let session_val = cookie
        .strip_prefix("awg_session=")
        .unwrap()
        .split(';')
        .next()
        .unwrap();

    let req = Request::builder()
        .method("DELETE")
        .uri("/api/session")
        .header(header::COOKIE, format!("awg_session={session_val}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // After logout, session check should fail
    let (status2, _) = get(&app, "/api/session", Some(&format!("awg_session={session_val}"))).await;
    assert_eq!(status2, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[serial(db)]
async fn login_remember_me_sets_max_age() {
    seed();
    create_admin();
    let app = router();
    let body = json!({ "username": "admin", "password": "admin123", "remember": true });
    let req = Request::builder()
        .method("POST")
        .uri("/api/session")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let cookies: Vec<String> = resp
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect();
    let session_cookie = cookies
        .into_iter()
        .find(|c| c.starts_with("awg_session="))
        .unwrap();
    assert!(session_cookie.contains("Max-Age=2592000")); // 30 days
}

#[tokio::test]
#[serial(db)]
async fn session_cookie_httponly() {
    seed();
    create_admin();
    let app = router();
    let body = json!({ "username": "admin", "password": "admin123" });
    let req = Request::builder()
        .method("POST")
        .uri("/api/session")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let cookies: Vec<String> = resp
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect();
    let cookie = cookies
        .into_iter()
        .find(|c| c.starts_with("awg_session="))
        .unwrap();
    assert!(cookie.to_lowercase().contains("httponly"));
}

// ---------------------------------------------------------------------------
// Rate Limiter
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(db)]
async fn rate_limiter_blocks_after_10_attempts() {
    seed();
    create_admin();
    let app = router();

    // 10 attempts with wrong password
    for i in 0..10 {
        let (status, _, _) = login(&app, "admin", "wrong", None).await;
        if i < 10 {
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
    }

    // 11th attempt should be rate limited
    let (status, body, _) = login(&app, "admin", "admin123", None).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(body["error"].as_str().unwrap().contains("Too many login attempts"));
}

#[tokio::test]
#[serial(db)]
async fn rate_limiter_per_username_independent() {
    seed();
    create_admin();
    let hash = auth::hash_password("pass").unwrap();
    db::create_user(&db::CreateUserParams {
        username: "other".into(), password: hash, email: None,
        name: "Other".into(), role: 0, totp_key: None,
        totp_verified: false, enabled: true,
    }).unwrap();
    let app = router();

    // Exhaust attempts for "admin"
    for _ in 0..10 {
        login(&app, "admin", "wrong", None).await;
    }

    // "other" should still work
    let (status, _, _) = login(&app, "other", "pass", None).await;
    assert_eq!(status, StatusCode::OK);
}

// ---------------------------------------------------------------------------
// TOTP 2FA
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(db)]
async fn login_with_totp_returns_totp_required() {
    seed();
    let hash = auth::hash_password("pass").unwrap();
    db::create_user(&db::CreateUserParams {
        username: "totpuser".into(),
        password: hash,
        email: None,
        name: "TOTP".into(),
        role: 0,
        totp_key: Some("JBSWY3DPEHPK3PXP".into()), // fake key
        totp_verified: true,
        enabled: true,
    })
    .unwrap();
    let app = router();
    let (status, body, _) = login(&app, "totpuser", "pass", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "TOTP_REQUIRED");
}

#[tokio::test]
#[serial(db)]
async fn login_with_invalid_totp_code() {
    seed();
    let hash = auth::hash_password("pass").unwrap();
    db::create_user(&db::CreateUserParams {
        username: "totpuser".into(),
        password: hash,
        // 32-char base32 = 20 bytes = SHA-1 RFC 6238 minimum.
        email: None,
        name: "TOTP".into(),
        role: 0,
        totp_key: Some("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".into()),
        totp_verified: true,
        enabled: true,
    })
    .unwrap();
    let app = router();
    let (status, body, _) = login(&app, "totpuser", "pass", Some("000000")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // check_current should return false for 000000
    assert!(body["error"].as_str().is_some_and(|e| e.contains("TOTP")));
}

// ---------------------------------------------------------------------------
// Setup Wizard
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(db)]
async fn setup_step2_creates_admin() {
    seed();
    let app = router();
    let body = json!({
        "username": "newadmin",
        "password": "securepass-12",
        "confirmPassword": "securepass-12"
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/setup/2")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify user was created
    let user = db::get_user_by_username("newadmin").unwrap();
    assert_eq!(user.name, "Admin");
    assert_eq!(user.role, 1);
    assert!(auth::verify_password("securepass-12", &user.password).unwrap());

    // Setup should advance to step 3
    assert_eq!(db::get_setup_step().unwrap(), 3);
}

#[tokio::test]
#[serial(db)]
async fn setup_step2_password_mismatch() {
    seed();
    let app = router();
    let body = json!({
        "username": "admin",
        "password": "pass1",
        "confirmPassword": "pass2"
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/setup/2")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial(db)]
async fn setup_step2_short_password() {
    seed();
    let app = router();
    let body = json!({
        "username": "admin",
        "password": "12345",
        "confirmPassword": "12345"
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/setup/2")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body_bytes = awg_easy_rs::http::to_bytes(resp.into_body(), 1024 * 1024).unwrap();
    let body: Value = serde_json::from_slice(&body_bytes).unwrap();
    assert!(body["error"].as_str().unwrap().contains("at least 12"));
}

#[tokio::test]
#[serial(db)]
async fn setup_step2_short_username() {
    seed();
    let app = router();
    let body = json!({
        "username": "ab",
        "password": "password1234",
        "confirmPassword": "password1234"
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/setup/2")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial(db)]
async fn setup_step2_long_username() {
    seed();
    let app = router();
    let long_name = "a".repeat(65);
    let body = json!({
        "username": long_name,
        "password": "password1234",
        "confirmPassword": "password1234"
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/setup/2")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial(db)]
async fn setup_step4_requires_correct_step() {
    seed();
    let app = router();
    let body = json!({ "host": "vpn.example.com", "port": 51820 });
    let req = Request::builder()
        .method("POST")
        .uri("/api/setup/4")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    // step is 1, not 3 — should fail
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// Change Password
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(db)]
async fn change_password_success() {
    seed();
    create_admin();
    let app = router();
    let (_, _, cookie) = login(&app, "admin", "admin123", None).await;
    let cookie = cookie.unwrap();
    let session_val = cookie
        .strip_prefix("awg_session=")
        .unwrap()
        .split(';')
        .next()
        .unwrap();

    let body = json!({
        "currentPassword": "admin123",
        "newPassword": "newpassword456"
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/me/password")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, format!("awg_session={session_val}"))
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify new password works, old doesn't
    let (s1, _, _) = login(&app, "admin", "newpassword456", None).await;
    assert_eq!(s1, StatusCode::OK);
    let (s2, _, _) = login(&app, "admin", "admin123", None).await;
    assert_eq!(s2, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[serial(db)]
async fn change_password_wrong_current() {
    seed();
    create_admin();
    let app = router();
    let (_, _, cookie) = login(&app, "admin", "admin123", None).await;
    let cookie = cookie.unwrap();
    let session_val = cookie
        .strip_prefix("awg_session=")
        .unwrap()
        .split(';')
        .next()
        .unwrap();

    let body = json!({
        "currentPassword": "wrongcurrent",
        "newPassword": "newpassword456"
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/me/password")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, format!("awg_session={session_val}"))
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[serial(db)]
async fn change_password_too_short() {
    seed();
    create_admin();
    let app = router();
    let (_, _, cookie) = login(&app, "admin", "admin123", None).await;
    let cookie = cookie.unwrap();
    let session_val = cookie
        .strip_prefix("awg_session=")
        .unwrap()
        .split(';')
        .next()
        .unwrap();

    let body = json!({
        "currentPassword": "admin123",
        "newPassword": "12345"
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/me/password")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, format!("awg_session={session_val}"))
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
