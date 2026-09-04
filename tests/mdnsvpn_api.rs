//! Integration tests for the MasterDnsVPN REST endpoints.
//!
//! Covers the admin flow an operator walks through to bootstrap the
//! DNS-tunnel transport: read inbound → set domains → generate key →
//! create client → download per-client config bundle → delete client.
//! The actual mdnsvpn subprocess smoke test lives in
//! `tests/mdnsvpn_config_smoke.rs` (gated by `#[ignore]`).

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
    // QR-code SVGs encode every module as its own <rect/>, so they can
    // run into the hundreds of KB for share strings as long as
    // `mdnsvpn://b64?<base64>`. 1 MB cap is plenty.
    let body = coffeeblack_vpn::http::to_bytes(resp.into_body(), 1024 * 1024).unwrap();
    let s = String::from_utf8(body.to_vec()).unwrap_or_default();
    (status, s)
}

/// Like `raw_get`, but keeps the response headers so cache-policy can be
/// asserted on secret-bearing bodies.
async fn headers_get(
    app: &coffeeblack_vpn::http::Router,
    path: &str,
    cookie: &str,
) -> (StatusCode, coffeeblack_vpn::http::HeaderMap) {
    let req = Request::builder()
        .method("GET")
        .uri(path)
        .header(header::COOKIE, format!("coffeeblack_session={cookie}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    (resp.status(), resp.headers().clone())
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(db)]
async fn mdnsvpn_inbound_requires_auth() {
    seed();
    let app = router();
    let req = Request::builder()
        .method("GET")
        .uri("/api/admin/mdnsvpn/inbound")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[serial(db)]
async fn mdnsvpn_inbound_requires_admin() {
    seed();
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
    let (status, _) = json_get(&app, "/api/admin/mdnsvpn/inbound", &cookie).await;
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

    let (status, body) = json_get(&app, "/api/admin/mdnsvpn/inbound", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["id"], "mdnsvpn0");
    assert_eq!(body["port"], 53);
    assert_eq!(body["bind"], "0.0.0.0");
    // Fresh installs must default to authenticated encryption, NOT upstream's
    // method 1 (XOR against a repeating key — neither confidential nor
    // authenticated). Guards against the schema default regressing.
    assert_eq!(body["encryptionMethod"], 5);
    assert_eq!(body["encryptionMethodName"], "AES-256-GCM");
    assert_eq!(body["encryptionIsAuthenticated"], true);
    assert_eq!(body["recommendedEncryptionMethod"], 5);
    // No key set yet, so nothing to fingerprint and nothing to warn about.
    assert_eq!(body["encryptionKeyFingerprint"], "");
    assert_eq!(body["securityWarnings"], json!([]));
    assert_eq!(body["protocolType"], "SOCKS5");
    assert_eq!(body["enabled"], false);
    assert_eq!(body["hasEncryptionKey"], false);
    // Default upstream resolvers are seeded.
    assert_eq!(
        body["dnsUpstreamServers"],
        json!(["1.1.1.1:53", "1.0.0.1:53"])
    );
    // domains default to empty array
    assert_eq!(body["domains"], json!([]));
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
        "/api/admin/mdnsvpn/inbound",
        &cookie,
        json!({
            "domains": ["v.example.com", "tunnel.example.com"],
            "port": 5353,
            "encryptionMethod": 5,
            "protocolType": "SOCKS5",
            "dnsUpstreamServers": ["9.9.9.9:53"],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (_, body) = json_get(&app, "/api/admin/mdnsvpn/inbound", &cookie).await;
    assert_eq!(body["port"], 5353);
    assert_eq!(body["encryptionMethod"], 5);
    assert_eq!(body["domains"], json!(["v.example.com", "tunnel.example.com"]));
    assert_eq!(body["dnsUpstreamServers"], json!(["9.9.9.9:53"]));
}

#[tokio::test]
#[serial(db)]
async fn update_inbound_rejects_invalid_port() {
    seed();
    let _admin = create_admin();
    let app = router();
    let cookie = login(&app, "admin", "adminpass").await;

    let (status, body) = json_post(
        &app,
        "/api/admin/mdnsvpn/inbound",
        &cookie,
        json!({ "port": 0 }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap_or("").contains("port"));
}

#[tokio::test]
#[serial(db)]
async fn update_inbound_rejects_invalid_encryption_method() {
    seed();
    let _admin = create_admin();
    let app = router();
    let cookie = login(&app, "admin", "adminpass").await;

    let (status, body) = json_post(
        &app,
        "/api/admin/mdnsvpn/inbound",
        &cookie,
        json!({ "encryptionMethod": 99 }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap_or("").contains("ENCRYPTION_METHOD"));
}

#[tokio::test]
#[serial(db)]
async fn update_inbound_rejects_invalid_protocol_type() {
    seed();
    let _admin = create_admin();
    let app = router();
    let cookie = login(&app, "admin", "adminpass").await;

    let (status, _) = json_post(
        &app,
        "/api/admin/mdnsvpn/inbound",
        &cookie,
        json!({ "protocolType": "HTTP" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial(db)]
async fn update_inbound_rejects_empty_domains() {
    seed();
    let _admin = create_admin();
    let app = router();
    let cookie = login(&app, "admin", "adminpass").await;

    let (status, _) =
        json_post(&app, "/api/admin/mdnsvpn/inbound", &cookie, json!({ "domains": [] })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial(db)]
async fn regenerate_key_creates_key() {
    seed();
    let _admin = create_admin();
    let app = router();
    let cookie = login(&app, "admin", "adminpass").await;

    let (status, body) = json_post(
        &app,
        "/api/admin/mdnsvpn/inbound/regenerate-key",
        &cookie,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["encryptionKeySet"], true);
    assert_eq!(body["encryptionKeyLength"], 32);

    // hasEncryptionKey should now report true.
    let (_, inbound) = json_get(&app, "/api/admin/mdnsvpn/inbound", &cookie).await;
    assert_eq!(inbound["hasEncryptionKey"], true);
    assert_eq!(inbound["encryptionKeyLength"], 32);
}

#[tokio::test]
#[serial(db)]
async fn regenerate_key_accepts_supplied_value() {
    seed();
    let _admin = create_admin();
    let app = router();
    let cookie = login(&app, "admin", "adminpass").await;

    let supplied = "0123456789abcdef0123456789abcdef";
    let (status, _) = json_post(
        &app,
        "/api/admin/mdnsvpn/inbound/regenerate-key",
        &cookie,
        json!({ "key": supplied }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let stored = db::get_mdnsvpn_inbound().unwrap();
    assert_eq!(stored.encryption_key, supplied);
}

#[tokio::test]
#[serial(db)]
async fn regenerate_key_rejects_too_short_supplied_value() {
    seed();
    let _admin = create_admin();
    let app = router();
    let cookie = login(&app, "admin", "adminpass").await;

    let (status, _) = json_post(
        &app,
        "/api/admin/mdnsvpn/inbound/regenerate-key",
        &cookie,
        json!({ "key": "deadbeef" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
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

    let (status, body) = json_post(
        &app,
        "/api/mdnsvpn/clients",
        &cookie,
        json!({ "name": "alice" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["name"], "alice");
    assert_eq!(body["listenPort"], 18000);
    let id = body["id"].as_i64().unwrap();

    let (_, list) = json_get(&app, "/api/mdnsvpn/clients", &cookie).await;
    let arr = list.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["id"], id);

    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/mdnsvpn/clients/{id}"))
        .header(header::COOKIE, format!("coffeeblack_session={cookie}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let (_, list) = json_get(&app, "/api/mdnsvpn/clients", &cookie).await;
    assert_eq!(list.as_array().unwrap().len(), 0);
}

#[tokio::test]
#[serial(db)]
async fn create_client_requires_name() {
    seed();
    let _admin = create_admin();
    let app = router();
    let cookie = login(&app, "admin", "adminpass").await;

    let (status, _) = json_post(
        &app,
        "/api/mdnsvpn/clients",
        &cookie,
        json!({ "name": "  " }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial(db)]
async fn create_client_rejects_invalid_listen_port() {
    seed();
    let _admin = create_admin();
    let app = router();
    let cookie = login(&app, "admin", "adminpass").await;

    let (status, _) = json_post(
        &app,
        "/api/mdnsvpn/clients",
        &cookie,
        json!({ "name": "bob", "listen_port": 70000 }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial(db)]
async fn create_duplicate_name_is_rejected() {
    seed();
    let _admin = create_admin();
    let app = router();
    let cookie = login(&app, "admin", "adminpass").await;

    let (status, _) = json_post(
        &app,
        "/api/mdnsvpn/clients",
        &cookie,
        json!({ "name": "alice" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = json_post(
        &app,
        "/api/mdnsvpn/clients",
        &cookie,
        json!({ "name": "alice" }),
    )
    .await;
    // UNIQUE(name) on the DB trips — the API surfaces 400 with a
    // "create failed: …" message.
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// Share endpoints
// ---------------------------------------------------------------------------

async fn setup_for_share(app: &coffeeblack_vpn::http::Router, cookie: &str) -> i64 {
    // Inbound: set domains + key so the supervisor would-be-runnable.
    let (status, _) = json_post(
        app,
        "/api/admin/mdnsvpn/inbound",
        cookie,
        json!({ "domains": ["v.example.com"] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = json_post(
        app,
        "/api/admin/mdnsvpn/inbound/regenerate-key",
        cookie,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = json_post(
        app,
        "/api/mdnsvpn/clients",
        cookie,
        json!({ "name": "alice", "listen_port": 19000 }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    body["id"].as_i64().unwrap()
}

#[tokio::test]
#[serial(db)]
async fn share_config_toml_download_works() {
    seed();
    let _admin = create_admin();
    let app = router();
    let cookie = login(&app, "admin", "adminpass").await;

    let id = setup_for_share(&app, &cookie).await;

    let (status, body) =
        raw_get(&app, &format!("/api/mdnsvpn/clients/{id}/config.toml"), &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains(r#"DOMAINS = ["v.example.com"]"#));
    assert!(body.contains("LISTEN_PORT = 19000"));
    assert!(body.contains("ENCRYPTION_KEY ="));
    // `RESOLVERS = […]` is NOT a real mdnsvpn config key — it used to be
    // emitted here and was silently discarded by the client. It must stay gone.
    assert!(!body.contains("RESOLVERS ="), "{body}");
    // Instead the config states where the resolver file must live.
    assert!(body.contains("client_resolvers.txt"));
}

#[tokio::test]
#[serial(db)]
async fn share_resolvers_txt_download_works() {
    seed();
    let _admin = create_admin();
    let app = router();
    let cookie = login(&app, "admin", "adminpass").await;

    let id = setup_for_share(&app, &cookie).await;

    let (status, body) =
        raw_get(&app, &format!("/api/mdnsvpn/clients/{id}/resolvers.txt"), &cookie).await;
    assert_eq!(status, StatusCode::OK);
    // Should contain default resolvers
    assert!(body.contains("8.8.8.8"));
    assert!(body.contains("1.1.1.1"));
}

#[tokio::test]
#[serial(db)]
async fn share_config_json_download_works() {
    seed();
    let _admin = create_admin();
    let app = router();
    let cookie = login(&app, "admin", "adminpass").await;

    let id = setup_for_share(&app, &cookie).await;

    let (status, body) =
        raw_get(&app, &format!("/api/mdnsvpn/clients/{id}/config.json"), &cookie).await;
    assert_eq!(status, StatusCode::OK);
    let v: Value = serde_json::from_str(&body).expect("returned JSON parses");
    assert_eq!(v["DOMAINS"][0], "v.example.com");
    assert_eq!(v["LISTEN_PORT"], 19000);
}

#[tokio::test]
#[serial(db)]
async fn share_url_returns_mdnsvpn_scheme() {
    seed();
    let _admin = create_admin();
    let app = router();
    let cookie = login(&app, "admin", "adminpass").await;

    let id = setup_for_share(&app, &cookie).await;

    let (status, body) =
        raw_get(&app, &format!("/api/mdnsvpn/clients/{id}/share"), &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.starts_with("mdnsvpn://b64?"));
    assert!(body.len() > "mdnsvpn://b64?".len() + 20);
}

#[tokio::test]
#[serial(db)]
async fn share_fails_when_inbound_missing_key() {
    seed();
    let _admin = create_admin();
    let app = router();
    let cookie = login(&app, "admin", "adminpass").await;

    // Domains set, but no key generated yet.
    let (_, _) = json_post(
        &app,
        "/api/admin/mdnsvpn/inbound",
        &cookie,
        json!({ "domains": ["v.example.com"] }),
    )
    .await;
    let (_, created) = json_post(
        &app,
        "/api/mdnsvpn/clients",
        &cookie,
        json!({ "name": "alice" }),
    )
    .await;
    let id = created["id"].as_i64().unwrap();

    let (status, _) =
        raw_get(&app, &format!("/api/mdnsvpn/clients/{id}/config.toml"), &cookie).await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
#[serial(db)]
async fn share_qrcode_returns_svg() {
    seed();
    let _admin = create_admin();
    let app = router();
    let cookie = login(&app, "admin", "adminpass").await;

    let id = setup_for_share(&app, &cookie).await;

    let (status, body) =
        raw_get(&app, &format!("/api/mdnsvpn/clients/{id}/qrcode.svg"), &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("<svg"));
}

// ---------------------------------------------------------------------------
// Security posture
// ---------------------------------------------------------------------------

/// Every endpoint whose body carries (or decodes to) the shared encryption key
/// must forbid caching. Without `no-store`, a downloaded tunnel config can be
/// written to a browser disk cache or a proxy/CDN in front of the panel and
/// outlive the session that fetched it.
#[tokio::test]
#[serial(db)]
async fn secret_bearing_downloads_forbid_caching() {
    seed();
    let _admin = create_admin();
    let app = router();
    let cookie = login(&app, "admin", "adminpass").await;

    let id = setup_for_share(&app, &cookie).await;

    for path in [
        format!("/api/mdnsvpn/clients/{id}/config.toml"),
        format!("/api/mdnsvpn/clients/{id}/config.json"),
        format!("/api/mdnsvpn/clients/{id}/resolvers.txt"),
        format!("/api/mdnsvpn/clients/{id}/share"),
        format!("/api/mdnsvpn/clients/{id}/qrcode.svg"),
    ] {
        let (status, headers) = headers_get(&app, &path, &cookie).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        let cc = headers
            .get(header::CACHE_CONTROL)
            .unwrap_or_else(|| panic!("{path} has no Cache-Control"))
            .to_str()
            .unwrap();
        assert!(cc.contains("no-store"), "{path} Cache-Control = {cc:?}");
        assert_eq!(
            headers.get(header::PRAGMA).map(|v| v.to_str().unwrap()),
            Some("no-cache"),
            "{path} missing Pragma: no-cache"
        );
    }
}

/// Selecting a non-AEAD cipher must be visible in the admin surface rather
/// than silently accepted. Upstream's own default (1 = XOR) lands here.
#[tokio::test]
#[serial(db)]
async fn non_aead_cipher_is_flagged_in_the_admin_surface() {
    seed();
    let _admin = create_admin();
    let app = router();
    let cookie = login(&app, "admin", "adminpass").await;

    let (status, _) = json_post(
        &app,
        "/api/admin/mdnsvpn/inbound",
        &cookie,
        json!({ "domains": ["v.example.com"], "encryptionMethod": 1 }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = json_get(&app, "/api/admin/mdnsvpn/inbound", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["encryptionMethod"], 1);
    assert_eq!(body["encryptionMethodName"], "XOR");
    assert_eq!(body["encryptionIsAuthenticated"], false);

    let warnings = body["securityWarnings"].as_array().expect("array");
    assert!(
        warnings
            .iter()
            .any(|w| w.as_str().unwrap_or_default().contains("not authenticated")),
        "expected a non-AEAD warning, got {warnings:?}"
    );
}

/// An AEAD cipher with a full-length key must produce no advisories — so the
/// warning list stays meaningful instead of always being non-empty.
#[tokio::test]
#[serial(db)]
async fn aead_cipher_with_generated_key_raises_no_warnings() {
    seed();
    let _admin = create_admin();
    let app = router();
    let cookie = login(&app, "admin", "adminpass").await;

    setup_for_share(&app, &cookie).await;

    let (status, body) = json_get(&app, "/api/admin/mdnsvpn/inbound", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["encryptionIsAuthenticated"], true);
    assert_eq!(body["securityWarnings"], json!([]));
}

/// The admin surface exposes a key *fingerprint* so operators can match a
/// client config to the running server — and must never expose the key itself.
#[tokio::test]
#[serial(db)]
async fn inbound_exposes_a_fingerprint_never_the_key() {
    seed();
    let _admin = create_admin();
    let app = router();
    let cookie = login(&app, "admin", "adminpass").await;

    let id = setup_for_share(&app, &cookie).await;

    // Recover the real key from a peer config (the only place it is served).
    let (status, toml) =
        raw_get(&app, &format!("/api/mdnsvpn/clients/{id}/config.toml"), &cookie).await;
    assert_eq!(status, StatusCode::OK);
    let key = toml
        .lines()
        .find_map(|l| l.strip_prefix("ENCRYPTION_KEY = "))
        .expect("client config carries the key")
        .trim()
        .trim_matches('"')
        .to_string();
    assert!(!key.is_empty());

    let (status, body) = json_get(&app, "/api/admin/mdnsvpn/inbound", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    let fp = body["encryptionKeyFingerprint"].as_str().expect("fingerprint");
    assert_eq!(fp.len(), 8, "fingerprint = {fp:?}");
    assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(!key.contains(fp), "fingerprint is a substring of the key");

    // Belt and braces: the whole admin payload must not contain the key.
    let serialized = serde_json::to_string(&body).unwrap();
    assert!(
        !serialized.contains(&key),
        "admin inbound payload leaked the encryption key"
    );
}

// ---------------------------------------------------------------------------
// bundle.zip — the artifact that actually starts a client
// ---------------------------------------------------------------------------

/// A peer needs two files. Every single-file download leaves them one short,
/// because mdnsvpn reads its resolver list only from `client_resolvers.txt` and
/// aborts startup when it is absent. `bundle.zip` is the fix.
#[tokio::test]
#[serial(db)]
async fn bundle_zip_contains_config_and_resolver_file() {
    seed();
    let _admin = create_admin();
    let app = router();
    let cookie = login(&app, "admin", "adminpass").await;

    let id = setup_for_share(&app, &cookie).await;

    let (status, headers) =
        headers_get(&app, &format!("/api/mdnsvpn/clients/{id}/bundle.zip"), &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get(header::CONTENT_TYPE).unwrap(),
        "application/zip"
    );
    let disposition = headers
        .get(header::CONTENT_DISPOSITION)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(disposition.contains("mdnsvpn_alice.zip"), "{disposition}");
    // Archive embeds the shared key, so it must not be cacheable.
    assert!(headers
        .get(header::CACHE_CONTROL)
        .unwrap()
        .to_str()
        .unwrap()
        .contains("no-store"));

    // Fetch the bytes and check the archive shape + stored contents.
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/mdnsvpn/clients/{id}/bundle.zip"))
        .header(header::COOKIE, format!("coffeeblack_session={cookie}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let bytes = coffeeblack_vpn::http::to_bytes(resp.into_body(), 1024 * 1024).unwrap();

    assert!(bytes.starts_with(b"PK\x03\x04"), "not a zip");
    let blob = String::from_utf8_lossy(&bytes);
    // Stored (uncompressed) entries, so names and contents appear verbatim.
    assert!(blob.contains("client_config.toml"));
    assert!(blob.contains("client_resolvers.txt"));
    assert!(blob.contains("run.sh"));
    assert!(blob.contains("run.cmd"));
    assert!(blob.contains("README.txt"));
    assert!(blob.contains("LISTEN_PORT = 19000"));
    assert!(blob.contains("8.8.8.8"));
    // The launcher wires both files together.
    assert!(blob.contains("-config client_config.toml -resolvers client_resolvers.txt"));
}

#[tokio::test]
#[serial(db)]
async fn bundle_zip_requires_a_configured_inbound() {
    seed();
    let _admin = create_admin();
    let app = router();
    let cookie = login(&app, "admin", "adminpass").await;

    // Client exists but the inbound has no key/domains yet.
    let (status, _) = json_post(
        &app,
        "/api/admin/mdnsvpn/inbound",
        &cookie,
        json!({ "domains": ["v.example.com"] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = json_post(
        &app,
        "/api/mdnsvpn/clients",
        &cookie,
        json!({ "name": "bob", "listen_port": 19100 }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let id = body["id"].as_i64().unwrap();

    let (status, _) =
        raw_get(&app, &format!("/api/mdnsvpn/clients/{id}/bundle.zip"), &cookie).await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
}

/// The share string must stay pasteable into `-json_base64` *and* carry the
/// resolver list, so scanning the QR does not lose it.
#[tokio::test]
#[serial(db)]
async fn share_url_carries_resolvers_without_corrupting_the_blob() {
    seed();
    let _admin = create_admin();
    let app = router();
    let cookie = login(&app, "admin", "adminpass").await;

    let id = setup_for_share(&app, &cookie).await;

    let (status, url) =
        raw_get(&app, &format!("/api/mdnsvpn/clients/{id}/share"), &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(url.starts_with("mdnsvpn://b64?"));

    let query = url.strip_prefix("mdnsvpn://b64?").unwrap();
    let mut parts = query.split('&');
    let payload = parts.next().unwrap();
    // Must remain valid *standard* base64 with padding — upstream decodes with
    // base64.StdEncoding, which rejects the URL-safe alphabet.
    let decoded = coffeeblack_vpn::encoding::b64_decode(payload)
        .expect("share payload must be standard base64");
    let blob: Value = serde_json::from_slice(&decoded).unwrap();
    assert_eq!(blob["LISTEN_PORT"], 19000);
    // The dead key must not have crept back into the blob.
    assert!(blob.get("RESOLVERS").is_none());

    let resolvers = parts.next().expect("resolvers param present");
    assert!(resolvers.starts_with("resolvers="));
    assert!(resolvers.contains("8.8.8.8"));
}
