//! Integration tests for the Xray (Browsing mode) REST endpoints.
//!
//! These cover the happy paths an admin walks through to bootstrap
//! Xray: read inbound → update inbound → regenerate keys → create
//! peer → read share URL → delete peer. Tests that would actually
//! spawn the Xray subprocess are kept in the supervisor module's
//! `--ignored` set; here we exercise just the API surface.

mod common;

use coffeeblack_vpn::{api, auth, db};
use coffeeblack_vpn::http::Body;
use coffeeblack_vpn::http::{header, Request, StatusCode};
use serde_json::{json, Value};
use serial_test::serial;

fn seed() {
    common::seed();
}

fn router() -> coffeeblack_vpn::http::Router {
    api::build_router(api::AppState::new())
}

fn create_admin() -> (i64, String) {
    let hash = auth::hash_password("adminpass").unwrap();
    let id = db::create_user(&db::CreateUserParams {
        username: "admin".into(),
        password: hash,
        email: None,
        name: "Admin".into(),
        role: 1,
        totp_key: None,
        totp_verified: false,
        enabled: true,
    })
    .unwrap();
    (id, "adminpass".into())
}

async fn login(app: &coffeeblack_vpn::http::Router, username: &str, password: &str) -> String {
    let body = json!({ "username": username, "password": password });
    let req = Request::builder()
        .method("POST")
        .uri("/api/session")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let cookies: Vec<_> = resp
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect();
    cookies
        .into_iter()
        .find(|c| c.starts_with("coffeeblack_session="))
        .unwrap()
        .strip_prefix("coffeeblack_session=")
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

async fn json_get(app: &coffeeblack_vpn::http::Router, path: &str, cookie: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri(path)
        .header(header::COOKIE, format!("coffeeblack_session={cookie}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = coffeeblack_vpn::http::to_bytes(resp.into_body(), 1024 * 64).unwrap();
    let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    (status, v)
}

async fn json_post(
    app: &coffeeblack_vpn::http::Router,
    path: &str,
    cookie: &str,
    body: Value,
) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, format!("coffeeblack_session={cookie}"))
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = coffeeblack_vpn::http::to_bytes(resp.into_body(), 1024 * 64).unwrap();
    let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    (status, v)
}

async fn raw_get(app: &coffeeblack_vpn::http::Router, path: &str, cookie: &str) -> (StatusCode, String) {
    let req = Request::builder()
        .method("GET")
        .uri(path)
        .header(header::COOKIE, format!("coffeeblack_session={cookie}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = coffeeblack_vpn::http::to_bytes(resp.into_body(), 1024 * 64).unwrap();
    let s = String::from_utf8(body.to_vec()).unwrap_or_default();
    (status, s)
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(db)]
async fn xray_inbound_requires_auth() {
    seed();
    let app = router();
    let req = Request::builder()
        .method("GET")
        .uri("/api/admin/xray/inbound")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[serial(db)]
async fn xray_inbound_requires_admin() {
    seed();
    // Non-admin user (role=0).
    let hash = auth::hash_password("pw").unwrap();
    db::create_user(&db::CreateUserParams {
        username: "alice".into(),
        password: hash,
        email: None,
        name: "Alice".into(),
        role: 0,
        totp_key: None,
        totp_verified: false,
        enabled: true,
    })
    .unwrap();
    let app = router();
    let cookie = login(&app, "alice", "pw").await;
    let (status, _) = json_get(&app, "/api/admin/xray/inbound", &cookie).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ---------------------------------------------------------------------------
// Inbound CRUD
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(db)]
async fn get_inbound_returns_seeded_defaults() {
    seed();
    let _admin = create_admin();
    let app = router();
    let cookie = login(&app, "admin", "adminpass").await;

    let (status, body) = json_get(&app, "/api/admin/xray/inbound", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["id"], "xray0");
    assert_eq!(body["port"], 443);
    assert_eq!(body["dest"], "www.microsoft.com:443");
    assert_eq!(body["serverNames"], json!(["www.microsoft.com"]));
    assert_eq!(body["enabled"], false);
    assert_eq!(body["hasPrivateKey"], false);
    // Public key shouldn't be empty if we surface it; with no keys yet
    // it's ""
    assert_eq!(body["publicKey"], "");
}

#[tokio::test]
#[serial(db)]
async fn update_inbound_round_trip() {
    seed();
    let _admin = create_admin();
    let app = router();
    let cookie = login(&app, "admin", "adminpass").await;

    let (status, _) = json_post(
        &app,
        "/api/admin/xray/inbound",
        &cookie,
        json!({
            "port": 8443,
            "dest": "www.cloudflare.com:443",
            "serverNames": ["www.cloudflare.com"],
            "fingerprintDefault": "firefox",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (_, body) = json_get(&app, "/api/admin/xray/inbound", &cookie).await;
    assert_eq!(body["port"], 8443);
    assert_eq!(body["dest"], "www.cloudflare.com:443");
    assert_eq!(body["serverNames"], json!(["www.cloudflare.com"]));
    assert_eq!(body["fingerprintDefault"], "firefox");
}

#[tokio::test]
#[serial(db)]
async fn update_inbound_rejects_invalid_port() {
    seed();
    let _admin = create_admin();
    let app = router();
    let cookie = login(&app, "admin", "adminpass").await;

    let (status, body) =
        json_post(&app, "/api/admin/xray/inbound", &cookie, json!({"port": 70000})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap_or("").contains("port"));
}

#[tokio::test]
#[serial(db)]
async fn update_inbound_rejects_empty_server_names() {
    seed();
    let _admin = create_admin();
    let app = router();
    let cookie = login(&app, "admin", "adminpass").await;

    let (status, _) = json_post(
        &app,
        "/api/admin/xray/inbound",
        &cookie,
        json!({"serverNames": []}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// Transport switching — covers amnezia-client/#2339 (xhttp transport).
// The first switch from tcp -> xhttp must auto-generate a routing path
// in the same write so the row never lands with transport='xhttp' and
// an empty path (which would make supervisor and share both refuse).
#[tokio::test]
#[serial(db)]
async fn switching_to_xhttp_auto_generates_path() {
    seed();
    let _admin = create_admin();
    let app = router();
    let cookie = login(&app, "admin", "adminpass").await;

    // Sanity: defaults are tcp with no path.
    let (_, body) = json_get(&app, "/api/admin/xray/inbound", &cookie).await;
    assert_eq!(body["transport"], "tcp");
    assert_eq!(body["xhttpPath"], "");

    let (status, _) = json_post(
        &app,
        "/api/admin/xray/inbound",
        &cookie,
        json!({"transport": "xhttp"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (_, body) = json_get(&app, "/api/admin/xray/inbound", &cookie).await;
    assert_eq!(body["transport"], "xhttp");
    let path = body["xhttpPath"].as_str().unwrap();
    // /<32 hex> — 33 chars total.
    assert_eq!(path.len(), 33);
    assert!(path.starts_with('/'));
    assert!(path[1..].chars().all(|c| c.is_ascii_hexdigit()));
}

// Switching back to tcp must NOT erase the path. Operators flipping
// transports while debugging client compat keep the same path on return
// so previously-handed-out share links still work.
#[tokio::test]
#[serial(db)]
async fn switching_back_to_tcp_keeps_xhttp_path() {
    seed();
    let _admin = create_admin();
    let app = router();
    let cookie = login(&app, "admin", "adminpass").await;

    json_post(&app, "/api/admin/xray/inbound", &cookie, json!({"transport": "xhttp"})).await;
    let (_, body) = json_get(&app, "/api/admin/xray/inbound", &cookie).await;
    let path1 = body["xhttpPath"].as_str().unwrap().to_string();
    assert!(!path1.is_empty());

    json_post(&app, "/api/admin/xray/inbound", &cookie, json!({"transport": "tcp"})).await;
    let (_, body) = json_get(&app, "/api/admin/xray/inbound", &cookie).await;
    assert_eq!(body["transport"], "tcp");
    assert_eq!(body["xhttpPath"], path1);
}

#[tokio::test]
#[serial(db)]
async fn update_inbound_rejects_unknown_transport() {
    seed();
    let _admin = create_admin();
    let app = router();
    let cookie = login(&app, "admin", "adminpass").await;

    let (status, body) = json_post(
        &app,
        "/api/admin/xray/inbound",
        &cookie,
        json!({"transport": "websocket"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap_or("").contains("transport"));
}

#[tokio::test]
#[serial(db)]
async fn regenerate_xhttp_path_rotates_value() {
    seed();
    let _admin = create_admin();
    let app = router();
    let cookie = login(&app, "admin", "adminpass").await;

    // Switch to xhttp first so we have a path to rotate.
    json_post(&app, "/api/admin/xray/inbound", &cookie, json!({"transport": "xhttp"})).await;
    let (_, body) = json_get(&app, "/api/admin/xray/inbound", &cookie).await;
    let before = body["xhttpPath"].as_str().unwrap().to_string();

    let (status, resp) = json_post(
        &app,
        "/api/admin/xray/inbound/regenerate-xhttp-path",
        &cookie,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let after = resp["xhttpPath"].as_str().unwrap().to_string();
    assert_ne!(before, after);
    assert_eq!(after.len(), 33);

    // And the inbound read endpoint must reflect the rotation.
    let (_, body) = json_get(&app, "/api/admin/xray/inbound", &cookie).await;
    assert_eq!(body["xhttpPath"], after);
}

#[tokio::test]
#[serial(db)]
async fn share_url_for_xhttp_drops_flow_and_adds_path() {
    seed();
    let _admin = create_admin();
    let app = router();
    let cookie = login(&app, "admin", "adminpass").await;

    db::update_xray_keypair("PRIV", "PUB").unwrap();
    db::update_host_port("vpn.example.com", 51820).unwrap();
    json_post(&app, "/api/admin/xray/inbound", &cookie, json!({"transport": "xhttp"})).await;
    let (_, c) = json_post(&app, "/api/xray/clients", &cookie, json!({"name": "alice"})).await;
    let id = c["id"].as_i64().unwrap();

    let (status, body) = raw_get(&app, &format!("/api/xray/clients/{id}/share"), &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.starts_with("vless://"));
    assert!(body.contains("type=xhttp"));
    assert!(body.contains("path=%2F"), "expected percent-encoded path, got {body}");
    assert!(!body.contains("flow="), "xhttp share must not carry Vision flow, got {body}");
}

#[tokio::test]
#[serial(db)]
async fn dest_candidates_returns_curated_list() {
    seed();
    let _admin = create_admin();
    let app = router();
    let cookie = login(&app, "admin", "adminpass").await;

    let (status, body) =
        json_get(&app, "/api/admin/xray/inbound/dest-candidates", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    let arr = body.as_array().unwrap();
    assert!(arr.len() >= 4);
    // Sanity: must include something from the curated list and exclude
    // GitHub-related infra (per the operator note about IR blocks).
    let strings: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
    assert!(strings.iter().any(|s| s.contains("microsoft")));
    assert!(!strings.iter().any(|s| s.contains("github")));
}

// ---------------------------------------------------------------------------
// Client CRUD
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(db)]
async fn create_list_delete_client_round_trip() {
    seed();
    let _admin = create_admin();
    let app = router();
    let cookie = login(&app, "admin", "adminpass").await;

    // Create
    let (status, body) = json_post(
        &app,
        "/api/xray/clients",
        &cookie,
        json!({"name": "alice"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["name"], "alice");
    assert!(body["uuid"].as_str().unwrap().len() == 36);
    assert_eq!(body["shortId"].as_str().unwrap().len(), 16);
    let id = body["id"].as_i64().unwrap();

    // List
    let (_, list) = json_get(&app, "/api/xray/clients", &cookie).await;
    let arr = list.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["id"], id);

    // Delete
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/xray/clients/{id}"))
        .header(header::COOKIE, format!("coffeeblack_session={cookie}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let (_, list) = json_get(&app, "/api/xray/clients", &cookie).await;
    assert_eq!(list.as_array().unwrap().len(), 0);
}

#[tokio::test]
#[serial(db)]
async fn create_client_rejects_empty_name() {
    seed();
    let _admin = create_admin();
    let app = router();
    let cookie = login(&app, "admin", "adminpass").await;
    let (status, _) =
        json_post(&app, "/api/xray/clients", &cookie, json!({"name": "  "})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial(db)]
async fn share_url_requires_host_set() {
    seed();
    let _admin = create_admin();
    let app = router();
    let cookie = login(&app, "admin", "adminpass").await;

    // Create a client and seed a public key but DO NOT set host on
    // user_config — the share endpoint should refuse with 412.
    let (_, c) = json_post(&app, "/api/xray/clients", &cookie, json!({"name": "alice"})).await;
    let id = c["id"].as_i64().unwrap();
    db::update_xray_keypair("PRIV", "PUB").unwrap();

    let (status, _) =
        raw_get(&app, &format!("/api/xray/clients/{id}/share"), &cookie).await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
#[serial(db)]
async fn share_url_returns_vless_uri() {
    seed();
    let _admin = create_admin();
    let app = router();
    let cookie = login(&app, "admin", "adminpass").await;

    db::update_xray_keypair("PRIV", "PUB").unwrap();
    db::update_host_port("vpn.example.com", 51820).unwrap();
    let (_, c) = json_post(&app, "/api/xray/clients", &cookie, json!({"name": "alice"})).await;
    let id = c["id"].as_i64().unwrap();

    let (status, body) =
        raw_get(&app, &format!("/api/xray/clients/{id}/share"), &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.starts_with("vless://"));
    assert!(body.contains("@vpn.example.com:443"));
    assert!(body.contains("flow=xtls-rprx-vision"));
    assert!(body.contains("security=reality"));
    assert!(body.contains("pbk=PUB"));
}

#[tokio::test]
#[serial(db)]
async fn non_admin_cannot_create_client() {
    seed();
    let hash = auth::hash_password("pw").unwrap();
    db::create_user(&db::CreateUserParams {
        username: "bob".into(),
        password: hash,
        email: None,
        name: "Bob".into(),
        role: 0,
        totp_key: None,
        totp_verified: false,
        enabled: true,
    })
    .unwrap();
    let app = router();
    let cookie = login(&app, "bob", "pw").await;

    let (status, _) =
        json_post(&app, "/api/xray/clients", &cookie, json!({"name": "self"})).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
#[serial(db)]
async fn non_admin_only_sees_own_clients() {
    seed();
    let _admin = create_admin();
    let bob_hash = auth::hash_password("pw").unwrap();
    let bob_id = db::create_user(&db::CreateUserParams {
        username: "bob".into(),
        password: bob_hash,
        email: None,
        name: "Bob".into(),
        role: 0,
        totp_key: None,
        totp_verified: false,
        enabled: true,
    })
    .unwrap();

    let app = router();

    // Admin creates two clients — one tied to Bob, one unowned.
    let admin_cookie = login(&app, "admin", "adminpass").await;
    let _ = json_post(
        &app,
        "/api/xray/clients",
        &admin_cookie,
        json!({"name": "bobs-phone", "user_id": bob_id}),
    )
    .await;
    let _ = json_post(
        &app,
        "/api/xray/clients",
        &admin_cookie,
        json!({"name": "company-laptop"}),
    )
    .await;

    // Bob lists — must only see his own.
    let bob_cookie = login(&app, "bob", "pw").await;
    let (_, list) = json_get(&app, "/api/xray/clients", &bob_cookie).await;
    let arr = list.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["name"], "bobs-phone");
}

/// The vless:// URL, its QR, and the AmneziaVPN JSON all carry the client's
/// credentials. None of them may be cacheable.
#[tokio::test]
#[serial(db)]
async fn share_artifacts_forbid_caching() {
    seed();
    let _admin = create_admin();
    let app = router();
    let cookie = login(&app, "admin", "adminpass").await;

    db::update_xray_keypair("PRIV", "PUB").unwrap();
    db::update_host_port("vpn.example.com", 51820).unwrap();
    let (_, c) = json_post(&app, "/api/xray/clients", &cookie, json!({"name": "alice"})).await;
    let id = c["id"].as_i64().unwrap();

    for path in [
        format!("/api/xray/clients/{id}/share"),
        format!("/api/xray/clients/{id}/qrcode.svg"),
        format!("/api/xray/clients/{id}/json"),
    ] {
        let req = Request::builder()
            .method("GET")
            .uri(&path)
            .header(header::COOKIE, format!("coffeeblack_session={cookie}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{path}");
        let cc = resp
            .headers()
            .get(header::CACHE_CONTROL)
            .unwrap_or_else(|| panic!("{path}: no Cache-Control"))
            .to_str()
            .unwrap()
            .to_string();
        assert!(cc.contains("no-store"), "{path}: {cc:?}");
        assert_eq!(
            resp.headers().get(header::PRAGMA).map(|v| v.to_str().unwrap()),
            Some("no-cache"),
            "{path}: missing Pragma"
        );
    }
}
