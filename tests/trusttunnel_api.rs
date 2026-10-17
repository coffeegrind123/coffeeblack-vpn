//! Integration tests for the TrustTunnel REST endpoints: inbound settings,
//! certificate upload / regeneration, user CRUD, ownership rules and the
//! share artefacts (`tt://` link, QR, client TOML). Nothing here enables the
//! endpoint — spawning the real binary is `tests/trusttunnel_e2e.rs`.

mod common;

use base64ct::{Base64UrlUnpadded, Encoding as _};
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

async fn delete(app: &coffeeblack_vpn::http::Router, path: &str, cookie: &str) -> StatusCode {
    let req = Request::builder()
        .method("DELETE")
        .uri(path)
        .header(header::COOKIE, format!("coffeeblack_session={cookie}"))
        .body(Body::empty())
        .unwrap();
    app.clone().oneshot(req).await.unwrap().status()
}

fn create_member(username: &str) -> i64 {
    let hash = auth::hash_password("pw").unwrap();
    db::create_user(&db::CreateUserParams {
        username: username.into(),
        password: hash,
        email: None,
        name: username.into(),
        role: 0,
        totp_key: None,
        totp_verified: false,
        enabled: true,
    })
    .unwrap()
}

fn set_host(host: &str) {
    let mut f = db::UpdateMap::new();
    f.insert("host".into(), host.into());
    db::update_user_config(&f).unwrap();
}

async fn admin_session() -> (coffeeblack_vpn::http::Router, String) {
    seed();
    let _ = create_admin();
    let app = router();
    let cookie = login(&app, "admin", "adminpass").await;
    (app, cookie)
}

#[tokio::test]
#[serial(db)]
async fn admin_routes_require_admin() {
    seed();
    create_member("bob");
    let app = router();
    let req = Request::builder()
        .method("GET")
        .uri("/api/admin/trusttunnel/inbound")
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);
    let cookie = login(&app, "bob", "pw").await;
    for path in ["/api/admin/trusttunnel/inbound", "/api/admin/trusttunnel/status"] {
        let (status, _) = json_get(&app, path, &cookie).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
    }
    let (status, _) = json_post(&app, "/api/trusttunnel/users", &cookie, json!({"name": "x"})).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
#[serial(db)]
async fn inbound_defaults_are_off_and_on_8443() {
    let (app, cookie) = admin_session().await;
    let (status, body) = json_get(&app, "/api/admin/trusttunnel/inbound", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["id"], "trusttunnel0");
    assert_eq!(body["port"], 8443);
    assert_eq!(body["enabled"], false);
    assert_eq!(body["listenHttp2"], true);
    assert_eq!(body["listenQuic"], true);
    assert_eq!(body["listenHttp1"], false);
    assert_eq!(body["tlsMode"], "self_signed");
    assert_eq!(body["authFailureStatusCode"], 407);
    assert_eq!(body["hasTlsKey"], false);
    assert!(body.get("tlsKeyPem").is_none(), "the private key never leaves the server");
}

#[tokio::test]
#[serial(db)]
async fn inbound_update_round_trips_and_validates() {
    let (app, cookie) = admin_session().await;
    let (status, body) = json_post(
        &app,
        "/api/admin/trusttunnel/inbound",
        &cookie,
        json!({
            "port": 9443,
            "hostname": "tt.example.net",
            "upstreamProtocol": "http3",
            "allowedSni": ["cdn.example.org", " "],
            "customSni": "cdn.example.org",
            "dnsUpstreams": ["1.1.1.1"],
            "authFailureStatusCode": 404,
            "antiDpi": true,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["port"], 9443);
    assert_eq!(body["effectiveHostname"], "tt.example.net");
    assert_eq!(body["allowedSni"], json!(["cdn.example.org"]), "blank entries dropped");
    assert_eq!(body["upstreamProtocol"], "http3");

    for (bad, why) in [
        (json!({"listenHttp2": false, "listenQuic": false}), "no listener"),
        (json!({"customSni": "other.example.org"}), "custom SNI not allowed"),
        (json!({"authFailureStatusCode": 500}), "status code"),
        (json!({"hostname": "1.2.3.4"}), "IP hostname"),
        (json!({"reverseProxyAddress": "127.0.0.1:80"}), "half a reverse proxy"),
        (json!({"port": "abc"}), "non-integer port"),
        (json!({"upstreamProtocol": "http3", "listenQuic": false}), "links need QUIC"),
    ] {
        let (status, _) = json_post(&app, "/api/admin/trusttunnel/inbound", &cookie, bad).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{why}");
    }
}

#[tokio::test]
#[serial(db)]
async fn port_clash_with_another_transport_is_refused() {
    let (app, cookie) = admin_session().await;
    let mut f = db::UpdateMap::new();
    f.insert("enabled".into(), "1".into());
    f.insert("port".into(), "8443".into());
    db::update_xray_inbound(&f).unwrap();
    let (status, body) = json_post(&app, "/api/admin/trusttunnel/inbound", &cookie, json!({"port": 8443})).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(body["error"].as_str().unwrap().contains("Xray"));
    let wg_port = db::get_interface().unwrap().port;
    let (status, _) = json_post(&app, "/api/admin/trusttunnel/inbound", &cookie, json!({"port": wg_port})).await;
    assert_eq!(status, StatusCode::CONFLICT, "UDP clash with AmneziaWG counts");
}

#[tokio::test]
#[serial(db)]
async fn certificate_upload_and_regeneration() {
    let (app, cookie) = admin_session().await;
    let (status, _) = json_post(&app, "/api/admin/trusttunnel/inbound/regenerate-certificate", &cookie, json!({})).await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED, "no hostname yet");

    json_post(&app, "/api/admin/trusttunnel/inbound", &cookie, json!({"hostname": "tt.example.net"})).await;
    let (status, body) = json_post(&app, "/api/admin/trusttunnel/inbound/regenerate-certificate", &cookie, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["tlsMode"], "self_signed");
    assert_eq!(body["hasTlsKey"], true);
    assert_eq!(body["tlsCertHostname"], "tt.example.net");
    assert_eq!(body["tlsCaTrusted"], false);
    assert!(body["tlsChainPem"].as_str().unwrap().contains("BEGIN CERTIFICATE"));

    // A valid chain + key for the hostname is accepted as `custom`.
    let m = coffeeblack_vpn::trusttunnel::cert::self_signed("tt.example.net").unwrap();
    let (status, body) = json_post(
        &app,
        "/api/admin/trusttunnel/inbound/certificate",
        &cookie,
        json!({"chainPem": m.chain_pem, "keyPem": m.key_pem}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["tlsMode"], "custom");

    // Wrong hostname or mismatched key: rejected, nothing stored.
    let other = coffeeblack_vpn::trusttunnel::cert::self_signed("other.example.net").unwrap();
    let (status, _) = json_post(
        &app,
        "/api/admin/trusttunnel/inbound/certificate",
        &cookie,
        json!({"chainPem": other.chain_pem, "keyPem": other.key_pem}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = json_post(
        &app,
        "/api/admin/trusttunnel/inbound/certificate",
        &cookie,
        json!({"chainPem": m.chain_pem, "keyPem": other.key_pem}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(db::get_trusttunnel_inbound().unwrap().tls_chain_pem.trim(), m.chain_pem.trim());

    // Switching back to self-signed drops the uploaded material.
    json_post(&app, "/api/admin/trusttunnel/inbound", &cookie, json!({"tlsMode": "self_signed"})).await;
    assert!(db::get_trusttunnel_inbound().unwrap().tls_chain_pem.is_empty());
}

#[tokio::test]
#[serial(db)]
async fn user_crud_never_returns_the_password() {
    let (app, cookie) = admin_session().await;
    let (status, created) = json_post(&app, "/api/trusttunnel/users", &cookie, json!({"name": "Alice's Phone"})).await;
    assert_eq!(status, StatusCode::OK, "{created}");
    assert_eq!(created["username"], "alice-s-phone");
    assert!(created.get("password").is_none());
    assert_eq!(created["active"], true);
    let id = created["id"].as_i64().unwrap();

    let (_, again) = json_post(&app, "/api/trusttunnel/users", &cookie, json!({"name": "Alice's Phone"})).await;
    assert_eq!(again["username"], "alice-s-phone-2", "derived usernames are made unique");
    let (status, _) = json_post(&app, "/api/trusttunnel/users", &cookie, json!({"name": "x", "username": "alice-s-phone"})).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = json_post(&app, "/api/trusttunnel/users", &cookie, json!({"name": "x", "username": "bad name"})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let before = db::get_trusttunnel_user(id).unwrap().password;
    let (status, _) = json_post(&app, &format!("/api/trusttunnel/users/{id}/rotate-password"), &cookie, json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(db::get_trusttunnel_user(id).unwrap().password, before);

    let (status, updated) = json_post(
        &app,
        &format!("/api/trusttunnel/users/{id}"),
        &cookie,
        json!({"enabled": false, "expiresAt": "2030-01-01T00:00", "clientRandomPrefix": "A0B0/F0F0"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{updated}");
    assert_eq!(updated["enabled"], false);
    assert_eq!(updated["clientRandomPrefix"], "a0b0/f0f0");
    let (status, _) = json_post(&app, &format!("/api/trusttunnel/users/{id}"), &cookie, json!({"clientRandomPrefix": "xyz"})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = json_post(&app, &format!("/api/trusttunnel/users/{id}"), &cookie, json!({"expiresAt": "tomorrow"})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (_, cleared) = json_post(&app, &format!("/api/trusttunnel/users/{id}"), &cookie, json!({"expiresAt": null})).await;
    assert!(cleared["expiresAt"].is_null() || cleared["expiresAt"] == "");

    assert_eq!(delete(&app, &format!("/api/trusttunnel/users/{id}"), &cookie).await, StatusCode::OK);
    let (status, _) = json_get(&app, &format!("/api/trusttunnel/users/{id}"), &cookie).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
#[serial(db)]
async fn prefix_requirement_is_enforced_on_users() {
    let (app, cookie) = admin_session().await;
    json_post(&app, "/api/admin/trusttunnel/inbound", &cookie, json!({"requireClientRandomPrefix": true})).await;
    let (status, _) = json_post(&app, "/api/trusttunnel/users", &cookie, json!({"name": "noprefix"})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, u) = json_post(&app, "/api/trusttunnel/users", &cookie, json!({"name": "gen", "generatePrefix": true})).await;
    assert_eq!(status, StatusCode::OK);
    assert!(u["clientRandomPrefix"].as_str().unwrap().contains('/'));
}

#[tokio::test]
#[serial(db)]
async fn members_see_and_share_only_their_own_users() {
    let (app, admin) = admin_session().await;
    set_host("203.0.113.10");
    json_post(&app, "/api/admin/trusttunnel/inbound", &admin, json!({"hostname": "tt.example.net"})).await;
    json_post(&app, "/api/admin/trusttunnel/inbound/regenerate-certificate", &admin, json!({})).await;

    let bob = create_member("bob");
    let (_, mine) = json_post(&app, "/api/trusttunnel/users", &admin, json!({"name": "bob-laptop", "userId": bob})).await;
    let (_, theirs) = json_post(&app, "/api/trusttunnel/users", &admin, json!({"name": "carol"})).await;
    let mine = mine["id"].as_i64().unwrap();
    let theirs = theirs["id"].as_i64().unwrap();

    let cookie = login(&app, "bob", "pw").await;
    let (status, list) = json_get(&app, "/api/trusttunnel/users", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    let ids: Vec<i64> = list.as_array().unwrap().iter().map(|u| u["id"].as_i64().unwrap()).collect();
    assert_eq!(ids, vec![mine]);

    let (status, link) = raw_get(&app, &format!("/api/trusttunnel/users/{mine}/share"), &cookie).await;
    assert_eq!(status, StatusCode::OK, "{link}");
    assert!(link.starts_with("tt://?AAEB"), "version-1 deep link: {link}");
    let payload = Base64UrlUnpadded::decode_vec(link.trim_start_matches("tt://?")).unwrap();
    let password = db::get_trusttunnel_user(mine).unwrap().password;
    assert!(payload.windows(password.len()).any(|w| w == password.as_bytes()));
    assert!(payload.windows(17).any(|w| w == b"203.0.113.10:8443"), "dial address");

    let (status, _) = raw_get(&app, &format!("/api/trusttunnel/users/{theirs}/share"), &cookie).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, svg) = raw_get(&app, &format!("/api/trusttunnel/users/{mine}/qrcode.svg"), &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(svg.contains("<svg"));
    let (status, toml) = raw_get(&app, &format!("/api/trusttunnel/users/{mine}/client.toml"), &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(toml.contains("hostname = \"tt.example.net\""));
    assert!(toml.contains("BEGIN CERTIFICATE"));

    // Unlinking the owner takes the user out of bob's view.
    let (status, _) = json_post(&app, &format!("/api/trusttunnel/users/{mine}"), &admin, json!({"userId": null})).await;
    assert_eq!(status, StatusCode::OK);
    let (_, list) = json_get(&app, "/api/trusttunnel/users", &cookie).await;
    assert!(list.as_array().unwrap().is_empty());
}

#[tokio::test]
#[serial(db)]
async fn share_needs_host_and_certificate() {
    let (app, cookie) = admin_session().await;
    let (_, u) = json_post(&app, "/api/trusttunnel/users", &cookie, json!({"name": "x"})).await;
    let id = u["id"].as_i64().unwrap();
    set_host("");
    let (status, _) = raw_get(&app, &format!("/api/trusttunnel/users/{id}/share"), &cookie).await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED, "no host");
    set_host("203.0.113.10");
    let (status, body) = raw_get(&app, &format!("/api/trusttunnel/users/{id}/share"), &cookie).await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED, "IP host and no hostname: {body}");
}
