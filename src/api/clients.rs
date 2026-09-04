//! AmneziaWG client CRUD handlers.
//!
//! | Method | Route                                  | Description           |
//! |--------|----------------------------------------|-----------------------|
//! | GET    | /api/client                            | List all clients      |
//! | POST   | /api/client                            | Create client         |
//! | GET    | /api/client/:id                        | Get single client     |
//! | POST   | /api/client/:id                        | Update client         |
//! | DELETE | /api/client/:id                        | Delete client         |
//! | GET    | /api/client/:id/configuration          | Download .conf        |
//! | GET    | /api/client/:id/qrcode.svg             | QR code SVG           |
//! | POST   | /api/client/:id/enable                 | Enable client         |
//! | POST   | /api/client/:id/disable                | Disable client        |
//! | POST   | /api/client/:id/generateOneTimeLink    | One-time config link  |

use crate::http::{Path, Query, State};
use crate::http::{header, StatusCode};
use crate::http::IntoResponse;
use crate::http::Json;
use crate::http::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{api_err, map_err, no_store_headers, ok_success, require_auth, AppState};
use crate::{db, wg};

/// Maximum AmneziaWG clients a non-admin user may create. Bounds the
/// per-account resource cost (IP allocation + config rewrite + nft rebuild) so
/// a low-privilege account can't exhaust the address pool or churn the config.
const MAX_CLIENTS_PER_USER: i64 = 50;

// ---------------------------------------------------------------------------
// Query params for list
// ---------------------------------------------------------------------------

#[derive(Deserialize, Default)]
pub struct ClientFilter {
    pub filter: Option<String>,
}

// ---------------------------------------------------------------------------
// Create request body
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CreateClientRequest {
    pub name: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: Option<String>,
    /// Optional caller-supplied peer public key ("bring your own key").
    ///
    /// The strongest mode available: the client generates its own keypair and
    /// sends only the public half, so the server never sees the private key
    /// at all and cannot leak what it never had. When omitted the server
    /// generates the pair and hands the private key back exactly once.
    #[serde(rename = "publicKey")]
    pub public_key: Option<String>,
}

/// Reject a re-display request for a peer whose private key was not retained.
///
/// Without this the caller gets a 500 from the config generator; the whole
/// point of `never` retention is that this is an expected, explainable state,
/// so it answers 409 with the action that actually resolves it.
fn require_retained_key(client: &db::Client) -> Result<(), (StatusCode, Json<Value>)> {
    if client.has_private_key() {
        return Ok(());
    }
    Err(api_err(
        StatusCode::CONFLICT,
        "This server does not hold this peer's private key — it was issued once when \
         the peer was created. Rotate the peer's key to issue a new configuration.",
    ))
}

/// Accept a caller-supplied WireGuard public key.
///
/// Curve25519 keys are exactly 32 bytes, which is 44 base64 characters ending
/// in `=`. Validating the shape here keeps a malformed value from reaching
/// the generated config, where it would silently produce a peer that can
/// never complete a handshake.
fn validate_public_key(key: &str) -> Result<String, (StatusCode, Json<Value>)> {
    let key = key.trim();
    let valid = key.len() == 44
        && key.ends_with('=')
        && key[..43]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/');
    if !valid {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "publicKey must be a base64-encoded 32-byte WireGuard key (44 characters ending in '=')",
        ));
    }
    Ok(key.to_string())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateClientRequest {
    name: Option<String>,
    #[serde(rename = "ipv4Address")]
    ipv4_address: Option<String>,
    #[serde(rename = "ipv6Address")]
    ipv6_address: Option<String>,
    enabled: Option<bool>,
    #[serde(rename = "expiresAt")]
    expires_at: Option<String>,
    dns: Option<Vec<String>>,
    #[serde(rename = "allowedIps")]
    allowed_ips: Option<Vec<String>>,
    #[serde(rename = "firewallIps")]
    firewall_ips: Option<Vec<String>>,
    mtu: Option<i64>,
    #[serde(rename = "persistentKeepalive")]
    persistent_keepalive: Option<i64>,
    #[serde(rename = "preUp")]
    pre_up: Option<String>,
    #[serde(rename = "postUp")]
    post_up: Option<String>,
    #[serde(rename = "preDown")]
    pre_down: Option<String>,
    #[serde(rename = "postDown")]
    post_down: Option<String>,
    #[serde(rename = "serverEndpoint")]
    server_endpoint: Option<String>,
    #[serde(rename = "jC")]
    j_c: Option<i64>,
    #[serde(rename = "jMin")]
    j_min: Option<i64>,
    #[serde(rename = "jMax")]
    j_max: Option<i64>,
    i1: Option<String>,
    i2: Option<String>,
    i3: Option<String>,
    i4: Option<String>,
    i5: Option<String>,
    /// Per-peer AmneziaWG opt-in. `null` clears any previous override and
    /// lets the kernel auto-detect; `true`/`false` write `AdvancedSecurity
    /// = on`/`off` to the [Peer] block. Outer `Option` distinguishes
    /// "field absent in the JSON" from "field explicitly null".
    #[serde(
        rename = "advancedSecurity",
        default,
        deserialize_with = "deserialize_tristate_bool"
    )]
    advanced_security: Option<Option<bool>>,
    /// Free-form `[Interface]` append on the generated client config.
    /// Empty string clears the per-peer override; a non-empty string
    /// replaces it. `None` (field absent) leaves the column untouched.
    #[serde(rename = "additionalConfig")]
    additional_config: Option<String>,
}

fn deserialize_tristate_bool<'de, D>(de: D) -> Result<Option<Option<bool>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    // Called only when the JSON field is present. `null` deserialises to
    // None (clear override), `true`/`false` to Some(value). The outer
    // Some(...) marks "field present in payload" and survives `#[serde(
    // default)]` providing None when the field is absent.
    Option::<bool>::deserialize(de).map(Some)
}

// ---------------------------------------------------------------------------
// Helper: build a JSON representation of a client augmented with wg dump data.
// ---------------------------------------------------------------------------

fn client_to_json(client: &db::Client, peers: &[wg::cli::PeerDump]) -> Value {
    let peer = peers.iter().find(|p| p.public_key == client.public_key);
    // Activity lives in process memory, not in the client row — see
    // `crate::activity`. Absent means never sampled, which is all-zero.
    let recorded = crate::activity::client_activity(client.id).unwrap_or_default();

    // dns / allowedIps / serverAllowedIps / firewallIps are stored as JSON-
    // encoded arrays in TEXT columns. Deserialize them on the way out so the
    // UI receives real arrays — calling .join() on a string was the previous
    // failure mode.
    let parse_arr = |s: &Option<String>| -> Value {
        s.as_deref()
            .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
            .unwrap_or_else(|| json!([]))
    };

    // Active one-time link, if any. Shape mirrors upstream awg-easy
    // (oneTimeLink.oneTimeLink + oneTimeLink.expiresAt) so the frontend
    // can render the inline OTL bar with its countdown.
    let one_time_link = db::get_active_one_time_link(client.id)
        .ok()
        .flatten()
        .map(|l| {
            json!({
                "oneTimeLink": l.one_time_link,
                "expiresAt": l.expires_at,
                "createdAt": l.created_at,
            })
        });

    json!({
        "id": client.id,
        "userId": client.user_id,
        "interfaceId": client.interface_id,
        "name": client.name,
        "ipv4Address": client.ipv4_address,
        "ipv6Address": client.ipv6_address,
        // Null rather than "" when the key was not retained, so the UI can
        // tell "no key on this server" apart from "key is the empty string".
        "privateKey": if client.has_private_key() { json!(client.private_key) } else { Value::Null },
        "keyRetained": client.has_private_key(),
        "publicKey": client.public_key,
        "preSharedKey": client.pre_shared_key,
        "preUp": client.pre_up,
        "postUp": client.post_up,
        "preDown": client.pre_down,
        "postDown": client.post_down,
        "expiresAt": client.expires_at,
        "allowedIps": parse_arr(&client.allowed_ips),
        "serverAllowedIps": parse_arr(&client.server_allowed_ips),
        "firewallIps": parse_arr(&client.firewall_ips),
        "persistentKeepalive": client.persistent_keepalive,
        "mtu": client.mtu,
        "jC": client.j_c,
        "jMin": client.j_min,
        "jMax": client.j_max,
        "i1": client.i1,
        "i2": client.i2,
        "i3": client.i3,
        "i4": client.i4,
        "i5": client.i5,
        "dns": parse_arr(&client.dns),
        "serverEndpoint": client.server_endpoint,
        "advancedSecurity": client.advanced_security,
        "additionalConfig": client.additional_config,
        "enabled": client.enabled,
        "createdAt": client.created_at,
        "updatedAt": client.updated_at,
        // Runtime data from wg dump — current since the interface last came
        // up, and back to zero after a restart.
        "transferRx": peer.map(|p| p.transfer_rx).unwrap_or(0),
        "transferTx": peer.map(|p| p.transfer_tx).unwrap_or(0),
        "latestHandshakeAt": peer.and_then(|p| p.latest_handshake.map(crate::datetime::to_rfc3339)),
        "endpoint": peer.and_then(|p| p.endpoint.clone()),
        // Counterparts accumulated by the activity poller from clamped
        // deltas — these survive an interface restart (though not a restart
        // of this process, by design), and are what the UI labels "lifetime".
        "totalRx": recorded.total_rx_bytes,
        "totalTx": recorded.total_tx_bytes,
        // Last tick the poller saw a handshake. Distinct from
        // `latestHandshakeAt`: that is the kernel's own timestamp and is
        // lost when the interface restarts, this one is not.
        "lastSeenAt": recorded.last_seen_at,
        "oneTimeLink": one_time_link,
    })
}

// ---------------------------------------------------------------------------
// GET /api/client — list clients
// ---------------------------------------------------------------------------

pub async fn list_clients(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(filter): Query<ClientFilter>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let user = require_auth(&jar, &state)?;

    let clients = db::get_all_clients().map_err(map_err)?;
    let iface = db::get_interface().map_err(map_err)?;
    let peers = wg::dump_peers_async(iface.name.clone()).await.unwrap_or_default();

    let list: Vec<Value> = clients
        .into_iter()
        .filter(|c| {
            // Non-admin users can only see their own clients
            if user.role == 0 && c.user_id != Some(user.id) {
                return false;
            }
            if let Some(ref term) = filter.filter {
                let term = term.to_lowercase();
                c.name.to_lowercase().contains(&term)
                    || c.ipv4_address
                        .as_ref()
                        .map(|ip| ip.to_lowercase().contains(&term))
                        .unwrap_or(false)
                    || c.public_key.to_lowercase().contains(&term)
            } else {
                true
            }
        })
        .map(|c| client_to_json(&c, &peers))
        .collect();

    Ok(Json(json!(list)))
}

// ---------------------------------------------------------------------------
// POST /api/client — create client
// ---------------------------------------------------------------------------

pub async fn create_client(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<CreateClientRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let user = require_auth(&jar, &state)?;

    validate_client_name(&body.name)
        .map_err(|m| api_err(StatusCode::BAD_REQUEST, &m))?;
    if let Some(ref expires) = body.expires_at {
        if !crate::datetime::is_valid_expiry(expires) {
            return Err(api_err(
                StatusCode::BAD_REQUEST,
                "Invalid date format for expiresAt. Use ISO 8601 format.",
            ));
        }
    }

    // Per-user quota for non-admins: each client allocates an IP, rewrites the
    // WireGuard config, and triggers an nftables rebuild, so an unbounded
    // create loop from a low-privilege account is a resource/IP-exhaustion DoS.
    // Admins (role >= 1) are exempt — they manage the whole roster.
    if user.role == 0 {
        let mine = db::count_clients_for_user(user.id).map_err(map_err)?;
        if mine >= MAX_CLIENTS_PER_USER {
            return Err(api_err(
                StatusCode::TOO_MANY_REQUESTS,
                &format!("Client limit reached ({MAX_CLIENTS_PER_USER} per user)"),
            ));
        }
    }

    let iface = db::get_interface().map_err(map_err)?;
    let user_config = db::get_user_config().map_err(map_err)?;

    // Key acquisition, in order of decreasing trust placed in this server:
    //   1. caller supplied a public key  → we never hold a private key at all
    //   2. we generate the pair          → private key is handed back once,
    //                                      and persisted only in `plaintext`
    //                                      retention mode
    let general = db::get_general().map_err(map_err)?;
    let retain = general.private_key_retention == db::RETENTION_PLAINTEXT;
    let (issued_private_key, public_key) = match body.public_key.as_deref() {
        Some(byo) => (None, validate_public_key(byo)?),
        None => {
            let (private_key, public_key) = wg::generate_keypair().map_err(map_err)?;
            (Some(private_key), public_key)
        }
    };
    // What actually goes into the row: the key itself only when the operator
    // has opted into retention, otherwise the empty "not retained" marker.
    let stored_private_key = match (&issued_private_key, retain) {
        (Some(pk), true) => pk.clone(),
        _ => String::new(),
    };
    let psk = wg::generate_psk().map_err(map_err)?;

    // Build CreateClientParams with sensible defaults from user_config. The
    // IPv4/IPv6 addresses are placeholders — `create_client_alloc_ip` picks the
    // real ones atomically (under a single DB lock) to avoid the check-then-
    // insert race two concurrent creates would otherwise hit.
    let mut params = db::CreateClientParams {
        user_id: Some(user.id),
        interface_id: Some(iface.name.clone()),
        name: body.name,
        ipv4_address: None,
        ipv6_address: None,
        private_key: stored_private_key,
        public_key,
        pre_shared_key: Some(psk),
        pre_up: None,
        post_up: None,
        pre_down: None,
        post_down: None,
        expires_at: body.expires_at,
        allowed_ips: Some(user_config.default_allowed_ips.clone()),
        server_allowed_ips: None,
        firewall_ips: None,
        persistent_keepalive: user_config.default_persistent_keepalive,
        mtu: user_config.default_mtu,
        j_c: None,
        j_min: None,
        j_max: None,
        i1: None,
        i2: None,
        i3: None,
        i4: None,
        i5: None,
        dns: Some(user_config.default_dns.clone()),
        server_endpoint: None,
        // Default to "auto" (None): the kernel module auto-detects from the
        // H1 magic header on the first incoming handshake, and the userspace
        // amneziawg-go fallback chokes on an explicit AdvancedSecurity peer
        // directive. Operators who want to force the value can flip it
        // per-peer in the edit page.
        advanced_security: None,
        enabled: true,
    };

    let client_id =
        db::create_client_alloc_ip(&mut params, &iface.ipv4_cidr, &iface.ipv6_cidr)
            .map_err(map_err)?;

    // Save config to apply changes
    wg::save_config_async().await.map_err(map_err)?;

    // Rebuild firewall if enabled
    if iface.firewall_enabled {
        crate::firewall::rebuild_rules_async().await.map_err(map_err).ok();
    }

    // The one-and-only delivery. Under `never` retention this response is the
    // sole moment the private key and the rendered config exist outside the
    // client's own device, so both are returned here rather than left for a
    // follow-up GET that would have nothing to serve.
    let config = issued_private_key
        .as_deref()
        .map(|pk| wg::build_client_config(client_id, Some(pk)))
        .transpose()
        .map_err(map_err)?;
    // The QR must ride along with the config rather than being fetched from
    // /qrcode.svg afterwards: under `never` retention that endpoint has no
    // key to render from, so this response is the only chance to produce one.
    let qr_svg = config
        .as_deref()
        .map(crate::qr::generate_qr_svg)
        .transpose()
        .map_err(map_err)?;

    Ok(Json(json!({
        "success": true,
        "clientId": client_id,
        // Present only when this server generated the pair. Null for a
        // caller-supplied public key — there was never a private half here.
        "privateKey": issued_private_key,
        "config": config,
        "qrSvg": qr_svg,
        // Tells the UI whether it may offer download/QR later, or must make
        // the operator save this response now.
        "keyRetained": retain && issued_private_key.is_some(),
        "retentionMode": general.private_key_retention,
    })))
}

// ---------------------------------------------------------------------------
// POST /api/client/:id/rotateKey — re-issue the peer's keypair
// ---------------------------------------------------------------------------

/// Issue a fresh keypair for an existing peer and return the new config once.
///
/// This is the counterpart that makes `never` retention usable: with no
/// re-display possible, a lost config is recovered by rotating rather than by
/// keeping a copy on the server forever. It doubles as revocation — the old
/// public key stops being accepted the moment the interface reloads.
pub async fn rotate_client_key(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(client_id): Path<i64>,
    body: Option<Json<Value>>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let user = require_auth(&jar, &state)?;

    let client = db::get_client(client_id)
        .map_err(|_| api_err(StatusCode::NOT_FOUND, "Client not found"))?;
    if user.role == 0 && client.user_id != Some(user.id) {
        return Err(api_err(StatusCode::FORBIDDEN, "Access denied"));
    }

    let general = db::get_general().map_err(map_err)?;
    let retain = general.private_key_retention == db::RETENTION_PLAINTEXT;

    let supplied = body
        .as_ref()
        .and_then(|Json(v)| v.get("publicKey"))
        .and_then(|v| v.as_str());
    let (issued_private_key, public_key) = match supplied {
        Some(byo) => (None, validate_public_key(byo)?),
        None => {
            let (private_key, public_key) = wg::generate_keypair().map_err(map_err)?;
            (Some(private_key), public_key)
        }
    };
    let stored_private_key = match (&issued_private_key, retain) {
        (Some(pk), true) => pk.clone(),
        _ => String::new(),
    };

    db::update_client_keypair(client_id, &stored_private_key, &public_key).map_err(map_err)?;

    // Any config still in flight for the old key is now worthless, and the
    // link that would serve it must not outlive it.
    let _ = db::delete_one_time_link(client_id);

    wg::save_config_async().await.map_err(map_err)?;
    let iface = db::get_interface().map_err(map_err)?;
    if iface.firewall_enabled {
        crate::firewall::rebuild_rules_async().await.map_err(map_err).ok();
    }

    let config = issued_private_key
        .as_deref()
        .map(|pk| wg::build_client_config(client_id, Some(pk)))
        .transpose()
        .map_err(map_err)?;
    let qr_svg = config
        .as_deref()
        .map(crate::qr::generate_qr_svg)
        .transpose()
        .map_err(map_err)?;

    crate::info!(
        "client {client_id} keypair rotated by user {} (retained: {retain})",
        user.username
    );

    Ok(Json(json!({
        "success": true,
        "clientId": client_id,
        "privateKey": issued_private_key,
        "config": config,
        "qrSvg": qr_svg,
        "keyRetained": retain && issued_private_key.is_some(),
    })))
}

// ---------------------------------------------------------------------------
// GET /api/client/:id — get single client
// ---------------------------------------------------------------------------

pub async fn get_client(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(client_id): Path<i64>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let user = require_auth(&jar, &state)?;

    let client = db::get_client(client_id).map_err(|_| {
        api_err(StatusCode::NOT_FOUND, "Client not found")
    })?;
    if user.role == 0 && client.user_id != Some(user.id) {
        return Err(api_err(StatusCode::FORBIDDEN, "Access denied"));
    }
    let iface = db::get_interface().map_err(map_err)?;
    let peers = wg::dump_peers_async(iface.name.clone()).await.unwrap_or_default();

    Ok(Json(client_to_json(&client, &peers)))
}

// ---------------------------------------------------------------------------
// POST /api/client/:id — update client
// ---------------------------------------------------------------------------

pub async fn update_client(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(client_id): Path<i64>,
    Json(body): Json<UpdateClientRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let user = require_auth(&jar, &state)?;

    // Validate numeric fields
    if let Some(mtu) = body.mtu {
        if !(68..=65535).contains(&mtu) {
            return Err(api_err(StatusCode::BAD_REQUEST, "MTU must be 68-65535"));
        }
    }
    if let Some(pk) = body.persistent_keepalive {
        if pk != 0 && !(15..=65535).contains(&pk) {
            return Err(api_err(StatusCode::BAD_REQUEST, "PersistentKeepalive must be 0 or 15-65535"));
        }
    }
    if let Some(jc) = body.j_c {
        if !(1..=128).contains(&jc) {
            return Err(api_err(StatusCode::BAD_REQUEST, "JC must be 1-128"));
        }
    }
    if let Some(jmin) = body.j_min {
        if !(0..=1279).contains(&jmin) {
            return Err(api_err(StatusCode::BAD_REQUEST, "JMin must be 0-1279"));
        }
    }
    if let Some(jmax) = body.j_max {
        if !(1..=1280).contains(&jmax) {
            return Err(api_err(StatusCode::BAD_REQUEST, "JMax must be 1-1280"));
        }
        if let Some(jmin) = body.j_min {
            if jmax <= jmin {
                return Err(api_err(StatusCode::BAD_REQUEST, "JMax must be > JMin"));
            }
        }
    }
    // j_c must be >= j_min when both are provided
    if let (Some(jc), Some(jmin)) = (body.j_c, body.j_min) {
        if jc < jmin {
            return Err(api_err(StatusCode::BAD_REQUEST, "Jc must be >= Jmin"));
        }
    }

    // Validate I1-I5 CPS tag grammar.
    for (label, val) in [
        ("i1", &body.i1),
        ("i2", &body.i2),
        ("i3", &body.i3),
        ("i4", &body.i4),
        ("i5", &body.i5),
    ] {
        if let Some(s) = val {
            if let Err(msg) = crate::wg::params::validate_init_spec(s) {
                return Err(api_err(
                    StatusCode::BAD_REQUEST,
                    &format!("Invalid {}: {msg}", label.to_uppercase()),
                ));
            }
        }
    }
    if let Some(ref expires) = body.expires_at {
        // RFC3339, or ISO 8601 datetime-local (with/without seconds).
        if !crate::datetime::is_valid_expiry(expires) {
            return Err(api_err(StatusCode::BAD_REQUEST, "Invalid date format for expiresAt. Use ISO 8601 format."));
        }
    }

    // Validate routing/firewall/DNS list entries before they're JSON-encoded
    // into TEXT columns and later string-interpolated into the WireGuard config
    // (`DNS =`, `AllowedIPs =`) or the per-client nftables transaction. Without
    // this, a value carrying a newline or nft statement separator could inject
    // extra config directives / firewall rule tokens.
    if let Some(ref entries) = body.allowed_ips {
        for e in entries {
            validate_routing_entry(e)
                .map_err(|m| api_err(StatusCode::BAD_REQUEST, &format!("Invalid allowedIps entry: {m}")))?;
        }
    }
    if let Some(ref entries) = body.firewall_ips {
        for e in entries {
            validate_firewall_target(e)
                .map_err(|m| api_err(StatusCode::BAD_REQUEST, &format!("Invalid firewallIps entry: {m}")))?;
        }
    }
    if let Some(ref entries) = body.dns {
        for e in entries {
            if e.trim().parse::<std::net::IpAddr>().is_err() {
                return Err(api_err(
                    StatusCode::BAD_REQUEST,
                    &format!("Invalid dns entry '{e}': must be a valid IP address"),
                ));
            }
        }
    }

    // Verify client exists and check ownership
    let client = db::get_client(client_id).map_err(|_| {
        api_err(StatusCode::NOT_FOUND, "Client not found")
    })?;
    let is_admin = user.role >= 1;
    if !is_admin && client.user_id != Some(user.id) {
        return Err(api_err(StatusCode::FORBIDDEN, "Access denied"));
    }

    // Bound the name length and reject control characters (see
    // `validate_client_name`).
    if let Some(ref n) = body.name {
        validate_client_name(n).map_err(|m| api_err(StatusCode::BAD_REQUEST, &m))?;
    }

    // Privilege escalation guard: only admins may change addressing,
    // routing, or interface-level fields. A non-admin must not be able to
    // self-assign an arbitrary IP, change AllowedIPs, override DNS, or
    // attach interface-level hooks to their downloaded config.
    if !is_admin {
        let admin_only = [
            (body.ipv4_address.is_some(), "ipv4Address"),
            (body.ipv6_address.is_some(), "ipv6Address"),
            (body.allowed_ips.is_some(), "allowedIps"),
            (body.firewall_ips.is_some(), "firewallIps"),
            (body.dns.is_some(), "dns"),
            (body.mtu.is_some(), "mtu"),
            (body.persistent_keepalive.is_some(), "persistentKeepalive"),
            (body.j_c.is_some(), "jC"),
            (body.j_min.is_some(), "jMin"),
            (body.j_max.is_some(), "jMax"),
            (body.i1.is_some(), "i1"),
            (body.i2.is_some(), "i2"),
            (body.i3.is_some(), "i3"),
            (body.i4.is_some(), "i4"),
            (body.i5.is_some(), "i5"),
            (body.pre_up.is_some(), "preUp"),
            (body.post_up.is_some(), "postUp"),
            (body.pre_down.is_some(), "preDown"),
            (body.post_down.is_some(), "postDown"),
            (body.server_endpoint.is_some(), "serverEndpoint"),
            (body.advanced_security.is_some(), "advancedSecurity"),
            (body.additional_config.is_some(), "additionalConfig"),
        ];
        if let Some((_, field)) = admin_only.iter().find(|(present, _)| *present) {
            return Err(api_err(
                StatusCode::FORBIDDEN,
                &format!("Field '{field}' may only be changed by an admin"),
            ));
        }
    }

    // Validate that any new IP address is a real address inside the
    // configured interface CIDR. This blocks privilege escalation via IP
    // self-assignment to gateways or out-of-range targets.
    let iface_for_validation = db::get_interface().map_err(map_err)?;
    if let Some(ref v) = body.ipv4_address {
        if v.parse::<std::net::Ipv4Addr>().is_err()
            || !db::ip_in_cidr(v, &iface_for_validation.ipv4_cidr)
        {
            return Err(api_err(
                StatusCode::BAD_REQUEST,
                "ipv4Address must be a valid IPv4 address inside the interface CIDR",
            ));
        }
    }
    if let Some(ref v) = body.ipv6_address {
        if !v.is_empty()
            && (v.parse::<std::net::Ipv6Addr>().is_err()
                || !db::ip_in_cidr(v, &iface_for_validation.ipv6_cidr))
        {
            return Err(api_err(
                StatusCode::BAD_REQUEST,
                "ipv6Address must be a valid IPv6 address inside the interface CIDR",
            ));
        }
    }

    let mut fields = db::UpdateMap::new();
    if let Some(ref v) = body.name { fields.insert("name".into(), v.clone()); }
    if let Some(ref v) = body.ipv4_address { fields.insert("ipv4_address".into(), v.clone()); }
    if let Some(ref v) = body.ipv6_address { fields.insert("ipv6_address".into(), v.clone()); }
    if let Some(v) = body.enabled { fields.insert("enabled".into(), if v { "1".into() } else { "0".into() }); }
    if let Some(ref v) = body.expires_at { fields.insert("expires_at".into(), v.clone()); }
    if let Some(ref v) = body.dns { fields.insert("dns".into(), serde_json::to_string(v).unwrap_or_default()); }
    if let Some(ref v) = body.allowed_ips { fields.insert("allowed_ips".into(), serde_json::to_string(v).unwrap_or_default()); }
    if let Some(ref v) = body.firewall_ips { fields.insert("firewall_ips".into(), serde_json::to_string(v).unwrap_or_default()); }
    if let Some(v) = body.mtu { fields.insert("mtu".into(), v.to_string()); }
    if let Some(v) = body.persistent_keepalive { fields.insert("persistent_keepalive".into(), v.to_string()); }
    if let Some(ref v) = body.pre_up { fields.insert("pre_up".into(), v.clone()); }
    if let Some(ref v) = body.post_up { fields.insert("post_up".into(), v.clone()); }
    if let Some(ref v) = body.pre_down { fields.insert("pre_down".into(), v.clone()); }
    if let Some(ref v) = body.post_down { fields.insert("post_down".into(), v.clone()); }
    if let Some(ref v) = body.server_endpoint {
        // Interpolated verbatim into the server `[Peer]` block's `Endpoint = …`
        // line (wg::config_gen). Admin-only, but validate for consistency with
        // the other routing fields: a newline would inject arbitrary config
        // directives into the generated .conf.
        validate_server_endpoint(v).map_err(|m| api_err(StatusCode::BAD_REQUEST, &m))?;
        fields.insert("server_endpoint".into(), v.clone());
    }
    if let Some(v) = body.j_c { fields.insert("j_c".into(), v.to_string()); }
    if let Some(v) = body.j_min { fields.insert("j_min".into(), v.to_string()); }
    if let Some(v) = body.j_max { fields.insert("j_max".into(), v.to_string()); }
    if let Some(ref v) = body.i1 { fields.insert("i1".into(), v.clone()); }
    if let Some(ref v) = body.i2 { fields.insert("i2".into(), v.clone()); }
    if let Some(ref v) = body.i3 { fields.insert("i3".into(), v.clone()); }
    if let Some(ref v) = body.i4 { fields.insert("i4".into(), v.clone()); }
    if let Some(ref v) = body.i5 { fields.insert("i5".into(), v.clone()); }
    if let Some(ref v) = body.additional_config { fields.insert("additional_config".into(), v.clone()); }
    // Tri-state mapping for AdvancedSecurity:
    //   Some(Some(v)) → write 1/0 via the generic UPDATE
    //   Some(None)    → write SQL NULL (clears override → kernel auto-detect)
    //   None          → leave the column untouched
    //
    // The generic UPDATE helper takes string values, so only the
    // Some(Some(_)) case routes through it. The null branch goes through a
    // dedicated helper that emits a NULL literal.
    //
    // Refuse the explicit on|off setting when the host isn't running
    // the kernel module — userspace amneziawg-go chokes on a peer
    // line containing `AdvancedSecurity = on|off` and the resulting
    // handshake silently fails. Operators see this as a clean 4xx
    // here instead of a peer-side "no handshake" debug session
    // hours later. Only `Some(Some(_))` triggers the gate; clearing
    // (Some(None)) and leaving-untouched (None) are always allowed.
    let null_advanced_security = matches!(body.advanced_security, Some(None));
    if let Some(Some(b)) = body.advanced_security {
        let mode = crate::wg::kernel::detect();
        if !mode.supports_advanced_security() {
            return Err(api_err(
                StatusCode::PRECONDITION_FAILED,
                "advancedSecurity = on|off requires the AmneziaWG kernel \
                 module; this host is running the userspace amneziawg-go \
                 fallback. Use 'auto' (null) or load the kernel module first.",
            ));
        }
        fields.insert("advanced_security".into(), if b { "1".into() } else { "0".into() });
    }

    if fields.is_empty() && !null_advanced_security {
        return Err(api_err(StatusCode::BAD_REQUEST, "No fields to update"));
    }

    if !fields.is_empty() {
        db::update_client(client_id, &fields).map_err(map_err)?;
    }
    if null_advanced_security {
        db::set_client_advanced_security(client_id, None).map_err(map_err)?;
    }
    wg::save_config_async().await.map_err(map_err)?;

    // Rebuild firewall if enabled
    let iface = db::get_interface().map_err(map_err)?;
    if iface.firewall_enabled {
        crate::firewall::rebuild_rules_async().await.map_err(map_err).ok();
    }

    Ok(ok_success())
}

// ---------------------------------------------------------------------------
// DELETE /api/client/:id — delete client
// ---------------------------------------------------------------------------

pub async fn delete_client(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(client_id): Path<i64>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let user = require_auth(&jar, &state)?;

    let client = db::get_client(client_id).map_err(|_| {
        api_err(StatusCode::NOT_FOUND, "Client not found")
    })?;
    if user.role == 0 && client.user_id != Some(user.id) {
        return Err(api_err(StatusCode::FORBIDDEN, "Access denied"));
    }

    db::delete_client(client_id).map_err(|e| {
        api_err(StatusCode::NOT_FOUND, &e.to_string())
    })?;
    wg::save_config_async().await.map_err(map_err)?;

    // Rebuild firewall if enabled
    let iface = db::get_interface().map_err(map_err)?;
    if iface.firewall_enabled {
        crate::firewall::rebuild_rules_async().await.map_err(map_err).ok();
    }

    Ok(ok_success())
}

// ---------------------------------------------------------------------------
// GET /api/client/:id/configuration — download .conf
// ---------------------------------------------------------------------------

pub async fn client_configuration(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(client_id): Path<i64>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    let user = require_auth(&jar, &state)?;

    let client = db::get_client(client_id).map_err(|_| {
        api_err(StatusCode::NOT_FOUND, "Client not found")
    })?;
    if user.role == 0 && client.user_id != Some(user.id) {
        return Err(api_err(StatusCode::FORBIDDEN, "Access denied"));
    }

    require_retained_key(&client)?;
    let config = wg::get_client_config(client_id).map_err(|_| {
        api_err(StatusCode::NOT_FOUND, "Client not found or config generation failed")
    })?;

    let filename = format!("{}.conf", sanitize_filename(&client.name));

    let mut headers = crate::http::HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/x-wireguard-config"),
    );
    headers.insert(header::CONTENT_DISPOSITION, super::attachment_disposition(&filename));
    // Body embeds the peer's WireGuard private key.
    no_store_headers(&mut headers);

    Ok((StatusCode::OK, headers, config))
}

// ---------------------------------------------------------------------------
// GET /api/client/:id/qrcode.svg — QR code SVG
// ---------------------------------------------------------------------------

pub async fn client_qrcode(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(client_id): Path<i64>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    let user = require_auth(&jar, &state)?;

    let client = db::get_client(client_id).map_err(|_| {
        api_err(StatusCode::NOT_FOUND, "Client not found")
    })?;
    if user.role == 0 && client.user_id != Some(user.id) {
        return Err(api_err(StatusCode::FORBIDDEN, "Access denied"));
    }

    require_retained_key(&client)?;
    let config = wg::get_client_config(client_id).map_err(|_| {
        api_err(StatusCode::NOT_FOUND, "Client not found or config generation failed")
    })?;

    let svg = crate::qr::generate_qr_svg(&config).map_err(map_err)?;

    let mut headers = crate::http::HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("image/svg+xml"),
    );
    // The QR encodes the full peer config, private key included.
    no_store_headers(&mut headers);

    Ok((StatusCode::OK, headers, svg))
}

// ---------------------------------------------------------------------------
// POST /api/client/:id/enable — enable client
// ---------------------------------------------------------------------------

pub async fn enable_client(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(client_id): Path<i64>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let user = require_auth(&jar, &state)?;

    let client = db::get_client(client_id).map_err(|_| {
        api_err(StatusCode::NOT_FOUND, "Client not found")
    })?;
    if user.role == 0 && client.user_id != Some(user.id) {
        return Err(api_err(StatusCode::FORBIDDEN, "Access denied"));
    }

    db::toggle_client(client_id, true).map_err(map_err)?;
    wg::save_config_async().await.map_err(map_err)?;

    // Rebuild firewall if enabled
    let iface = db::get_interface().map_err(map_err)?;
    if iface.firewall_enabled {
        crate::firewall::rebuild_rules_async().await.map_err(map_err).ok();
    }

    Ok(ok_success())
}

// ---------------------------------------------------------------------------
// POST /api/client/:id/disable — disable client
// ---------------------------------------------------------------------------

pub async fn disable_client(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(client_id): Path<i64>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let user = require_auth(&jar, &state)?;

    let client = db::get_client(client_id).map_err(|_| {
        api_err(StatusCode::NOT_FOUND, "Client not found")
    })?;
    if user.role == 0 && client.user_id != Some(user.id) {
        return Err(api_err(StatusCode::FORBIDDEN, "Access denied"));
    }

    db::toggle_client(client_id, false).map_err(map_err)?;
    wg::save_config_async().await.map_err(map_err)?;

    // Rebuild firewall if enabled
    let iface = db::get_interface().map_err(map_err)?;
    if iface.firewall_enabled {
        crate::firewall::rebuild_rules_async().await.map_err(map_err).ok();
    }

    Ok(ok_success())
}

// ---------------------------------------------------------------------------
// POST /api/client/:id/generateOneTimeLink — one-time config link
// ---------------------------------------------------------------------------

pub async fn generate_one_time_link(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(client_id): Path<i64>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let user = require_auth(&jar, &state)?;

    // Verify client exists and check ownership
    let client = db::get_client(client_id).map_err(|_| {
        api_err(StatusCode::NOT_FOUND, "Client not found")
    })?;
    if user.role == 0 && client.user_id != Some(user.id) {
        return Err(api_err(StatusCode::FORBIDDEN, "Access denied"));
    }

    require_retained_key(&client)?;
    // Generate CSPRNG-based token (validate config generation)
    let _config = wg::get_client_config(client_id).map_err(map_err)?;
    let mut bytes = [0u8; 32];
    crate::rng::fill(&mut bytes);
    let token = crate::encoding::hex_encode(bytes);

    // Expire in 5 minutes
    let expires =
        crate::datetime::to_rfc3339(crate::datetime::now_utc() + time::Duration::minutes(5));

    db::create_one_time_link(client_id, &token, &expires).map_err(map_err)?;

    Ok(Json(json!({
        "success": true,
        "token": token,
        "expiresAt": expires,
    })))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Validate a routing entry (`allowedIps` element): a bare IP literal or a
/// CIDR. Rejects anything else — in particular values carrying whitespace or
/// nft statement separators, which would otherwise be string-interpolated into
/// the per-client nftables transaction (`firewall::gen_rules`) and could inject
/// extra rule tokens.
/// Validate a client display name: 1–256 chars, no control characters.
/// The name is rendered into many sinks (WireGuard peer comment, Xray
/// `email`, share-link labels, the Prometheus `name="…"` label). Each sink
/// has its own escaping, but rejecting control characters (newlines, CR, NUL,
/// tabs, ANSI escapes) at the boundary is cheap defense-in-depth against any
/// sink whose escaping is imperfect — the Prometheus exposition path being the
/// concrete example.
fn validate_client_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.chars().count() > 256 {
        return Err("Name must be 1-256 characters".into());
    }
    if name.chars().any(|c| c.is_control()) {
        return Err("Name must not contain control characters".into());
    }
    Ok(())
}

/// Validate a per-client `serverEndpoint` override: `host:port` (or
/// `[v6]:port`), no control characters, host non-empty, port 1–65535. Rejects
/// the newline that would otherwise inject config lines into the generated
/// server `[Peer]` block. An empty value clears the override and is allowed.
fn validate_server_endpoint(ep: &str) -> Result<(), String> {
    let ep = ep.trim();
    if ep.is_empty() {
        return Ok(());
    }
    if ep.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("serverEndpoint must not contain whitespace or control characters".into());
    }
    // Split host:port from the right so IPv6 (with its internal colons) works;
    // bracketed IPv6 keeps its port after the closing ']'.
    let (host, port) = if let Some(rest) = ep.strip_prefix('[') {
        let (h, after) = rest
            .split_once(']')
            .ok_or_else(|| "serverEndpoint: unterminated '[' in IPv6 literal".to_string())?;
        let port = after
            .strip_prefix(':')
            .ok_or_else(|| "serverEndpoint: expected ':port' after IPv6 literal".to_string())?;
        (h.to_string(), port.to_string())
    } else {
        let (h, p) = ep
            .rsplit_once(':')
            .ok_or_else(|| "serverEndpoint must be host:port".to_string())?;
        (h.to_string(), p.to_string())
    };
    if host.is_empty() {
        return Err("serverEndpoint host is empty".into());
    }
    validate_port(&port).map_err(|m| format!("serverEndpoint: {m}"))?;
    Ok(())
}

pub(crate) fn validate_routing_entry(entry: &str) -> Result<(), String> {
    let e = entry.trim();
    if e.is_empty() {
        return Err("empty entry".into());
    }
    if e.parse::<std::net::IpAddr>().is_ok() || e.parse::<crate::cidr::IpNet>().is_ok() {
        Ok(())
    } else {
        Err(format!("'{e}' is not a valid IP address or CIDR"))
    }
}

/// Validate a firewall target (`firewallIps` element): `IP`, `IP/cidr`,
/// `IP:port`, `[v6]:port`, optionally suffixed with `/tcp` or `/udp`. The
/// address part must be a real IP literal and the port numeric in 1..=65535.
/// Mirrors `firewall::parse_target` so nothing reaches the nft transaction that
/// the rule generator can't safely render.
pub(crate) fn validate_firewall_target(entry: &str) -> Result<(), String> {
    let e = entry.trim();
    if e.is_empty() {
        return Err("empty entry".into());
    }
    let body = e
        .strip_suffix("/tcp")
        .or_else(|| e.strip_suffix("/udp"))
        .unwrap_or(e);

    // Bracketed IPv6 with optional :port — [2001:db8::1]:443
    if let Some(rest) = body.strip_prefix('[') {
        let (addr, after) = rest
            .split_once(']')
            .ok_or_else(|| format!("'{e}': unterminated '[' in IPv6 literal"))?;
        addr.parse::<std::net::Ipv6Addr>()
            .map_err(|_| format!("'{e}': invalid IPv6 literal"))?;
        if let Some(port) = after.strip_prefix(':') {
            validate_port(port).map_err(|m| format!("'{e}': {m}"))?;
        } else if !after.is_empty() {
            return Err(format!("'{e}': trailing junk after ']' "));
        }
        return Ok(());
    }

    // Bare IP / CIDR, or IPv4 with a single :port. A value with >1 colon and
    // no brackets is treated as a bare IPv6 literal (no port).
    if body.matches(':').count() == 1 {
        if let Some((addr, port)) = body.rsplit_once(':') {
            if port.chars().all(|c| c.is_ascii_digit()) {
                validate_routing_entry(addr).map_err(|m| format!("'{e}': {m}"))?;
                validate_port(port).map_err(|m| format!("'{e}': {m}"))?;
                return Ok(());
            }
        }
    }
    validate_routing_entry(body).map_err(|m| format!("'{e}': {m}"))
}

fn validate_port(port: &str) -> Result<(), String> {
    match port.parse::<u32>() {
        Ok(p) if (1..=65535).contains(&p) => Ok(()),
        _ => Err(format!("port '{port}' must be 1-65535")),
    }
}

fn sanitize_filename(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    // Strip any leading dots so we never produce names like `.` or `.htaccess`,
    // and fall back to a fixed value when the input collapses to empty.
    let s = s.trim_start_matches('.').to_string();
    if s.is_empty() {
        "client".to_string()
    } else {
        s
    }
}

#[cfg(test)]
mod validation_tests {
    use super::*;

    #[test]
    fn client_name_rejects_control_chars() {
        assert!(validate_client_name("Alice's laptop").is_ok());
        assert!(validate_client_name("").is_err());
        // Newline / CR / NUL / tab / ANSI-escape must all be rejected — they
        // feed the WG peer comment, Xray email, and the Prometheus label.
        for bad in ["a\nb", "a\rb", "a\tb", "a\0b", "a\x1b[31mb"] {
            assert!(validate_client_name(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn server_endpoint_rejects_injection() {
        assert!(validate_server_endpoint("vpn.example.com:51820").is_ok());
        assert!(validate_server_endpoint("[2001:db8::1]:51820").is_ok());
        assert!(validate_server_endpoint("").is_ok()); // clears the override
        for bad in [
            "host:51820\nPostUp = id",
            "host:99999",
            "host",
            "ho st:53",
        ] {
            assert!(validate_server_endpoint(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn routing_entry_accepts_ip_and_cidr() {
        for ok in ["10.0.0.1", "0.0.0.0/0", "::/0", "2001:db8::1", "10.8.0.0/24"] {
            assert!(validate_routing_entry(ok).is_ok(), "should accept {ok}");
        }
    }

    #[test]
    fn routing_entry_rejects_junk_and_injection() {
        for bad in [
            "",
            "not-an-ip",
            "1.2.3.4 accept; add rule",
            "1.2.3.4\naccept",
            "1.2.3.4; drop table",
        ] {
            assert!(validate_routing_entry(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn firewall_target_accepts_valid_shapes() {
        for ok in [
            "8.8.8.8",
            "8.8.8.8:53",
            "8.8.8.8:53/udp",
            "8.8.8.8:443/tcp",
            "[2001:db8::1]:443",
            "2001:db8::1",
            "10.0.0.0/24",
        ] {
            assert!(validate_firewall_target(ok).is_ok(), "should accept {ok}");
        }
    }

    #[test]
    fn firewall_target_rejects_bad_port_and_injection() {
        for bad in [
            "",
            "8.8.8.8:0",
            "8.8.8.8:99999",
            "8.8.8.8:53 accept;",
            "evil.example.com",
            "8.8.8.8\naccept",
        ] {
            assert!(validate_firewall_target(bad).is_err(), "should reject {bad:?}");
        }
    }
}
