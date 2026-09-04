//! Track 2: Database tests — CRUD, whitelist enforcement, IP allocation,
//! transactions.
//!
//! Each test resets the global DB to a fresh in-memory SQLite database.
//! All tests are `#[serial(db)]` to prevent races on the global handle.

use awg_easy_rs::db;
use serial_test::serial;

fn seed() {
    db::init_test_db();
}

// ---------------------------------------------------------------------------
// Interface CRUD
// ---------------------------------------------------------------------------

#[test]
#[serial(db)]
fn get_interface_seeded() {
    seed();
    let iface = db::get_interface().unwrap();
    assert_eq!(iface.name, "awg0");
    assert_eq!(iface.device, "eth0");
    assert_eq!(iface.port, 51820);
    assert_eq!(iface.ipv4_cidr, "10.8.0.0/24");
    assert_eq!(iface.mtu, 1420);
    assert!(iface.enabled);
}

#[test]
#[serial(db)]
fn update_interface_port() {
    seed();
    let mut fields = db::UpdateMap::new();
    fields.insert("port".into(), "1194".into());
    db::update_interface(&fields).unwrap();
    let iface = db::get_interface().unwrap();
    assert_eq!(iface.port, 1194);
}

#[test]
#[serial(db)]
fn update_interface_invalid_column() {
    seed();
    let mut fields = db::UpdateMap::new();
    fields.insert("nonexistent_column".into(), "value".into());
    let result = db::update_interface(&fields);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Invalid column"));
}

#[test]
#[serial(db)]
fn update_key_pair() {
    seed();
    db::update_key_pair("new-pub", "new-priv").unwrap();
    let iface = db::get_interface().unwrap();
    assert_eq!(iface.public_key, "new-pub");
    assert_eq!(iface.private_key, "new-priv");
}

#[test]
#[serial(db)]
fn update_cidr() {
    seed();
    db::update_cidr("172.16.0.0/16", "fd00::/64").unwrap();
    let iface = db::get_interface().unwrap();
    assert_eq!(iface.ipv4_cidr, "172.16.0.0/16");
    assert_eq!(iface.ipv6_cidr, "fd00::/64");
}

// ---------------------------------------------------------------------------
// User CRUD
// ---------------------------------------------------------------------------

#[test]
#[serial(db)]
fn create_and_get_user() {
    seed();
    let id = db::create_user(&db::CreateUserParams {
        username: "testuser".into(),
        password: "hash123".into(),
        email: Some("test@example.com".into()),
        name: "Test User".into(),
        role: 0,
        totp_key: None,
        totp_verified: false,
        enabled: true,
    })
    .unwrap();
    assert!(id > 0);
    let user = db::get_user(id).unwrap();
    assert_eq!(user.username, "testuser");
    assert_eq!(user.email.unwrap(), "test@example.com");
    assert_eq!(user.role, 0);
}

#[test]
#[serial(db)]
fn get_user_by_username() {
    seed();
    db::create_user(&db::CreateUserParams {
        username: "alice".into(),
        password: "pwhash".into(),
        email: None,
        name: "Alice".into(),
        role: 1,
        totp_key: None,
        totp_verified: false,
        enabled: true,
    })
    .unwrap();
    let user = db::get_user_by_username("alice").unwrap();
    assert_eq!(user.name, "Alice");
    assert_eq!(user.role, 1);
}

#[test]
#[serial(db)]
fn get_user_not_found() {
    seed();
    assert!(db::get_user(9999).is_err());
}

#[test]
#[serial(db)]
fn get_user_by_username_not_found() {
    seed();
    assert!(db::get_user_by_username("nonexistent").is_err());
}

#[test]
#[serial(db)]
fn get_user_count() {
    seed();
    assert_eq!(db::get_user_count().unwrap(), 0);
    db::create_user(&db::CreateUserParams {
        username: "u1".into(), password: "h1".into(), email: None,
        name: "U1".into(), role: 0, totp_key: None,
        totp_verified: false, enabled: true,
    }).unwrap();
    assert_eq!(db::get_user_count().unwrap(), 1);
}

#[test]
#[serial(db)]
fn update_user() {
    seed();
    let id = db::create_user(&db::CreateUserParams {
        username: "update-me".into(), password: "hash".into(), email: None,
        name: "Old".into(), role: 0, totp_key: None,
        totp_verified: false, enabled: true,
    }).unwrap();
    let mut fields = db::UpdateMap::new();
    fields.insert("email".into(), "new@new.com".into());
    fields.insert("name".into(), "New Name".into());
    db::update_user(id, &fields).unwrap();
    let user = db::get_user(id).unwrap();
    assert_eq!(user.email.unwrap(), "new@new.com");
    assert_eq!(user.name, "New Name");
}

#[test]
#[serial(db)]
fn update_password() {
    seed();
    let id = db::create_user(&db::CreateUserParams {
        username: "pw-user".into(), password: "old-hash".into(), email: None,
        name: "PW".into(), role: 0, totp_key: None,
        totp_verified: false, enabled: true,
    }).unwrap();
    db::update_password(id, "new-hash").unwrap();
    let user = db::get_user(id).unwrap();
    assert_eq!(user.password, "new-hash");
}

#[test]
#[serial(db)]
fn update_user_invalid_column() {
    seed();
    let mut fields = db::UpdateMap::new();
    fields.insert("hacked".into(), "yes".into());
    assert!(db::update_user(1, &fields).is_err());
}

#[test]
#[serial(db)]
fn user_enabled_field() {
    seed();
    let id = db::create_user(&db::CreateUserParams {
        username: "enabled-test".into(), password: "h".into(), email: None,
        name: "E".into(), role: 0, totp_key: None,
        totp_verified: false, enabled: true,
    }).unwrap();
    let user = db::get_user(id).unwrap();
    assert!(user.enabled);
}

#[test]
#[serial(db)]
fn user_disabled_field() {
    seed();
    let id = db::create_user(&db::CreateUserParams {
        username: "disabled-test".into(), password: "h".into(), email: None,
        name: "D".into(), role: 0, totp_key: None,
        totp_verified: false, enabled: false,
    }).unwrap();
    let user = db::get_user(id).unwrap();
    assert!(!user.enabled);
}

#[test]
#[serial(db)]
fn user_unique_username_constraint() {
    seed();
    let params = db::CreateUserParams {
        username: "dup".into(), password: "h".into(), email: None,
        name: "A".into(), role: 0, totp_key: None,
        totp_verified: false, enabled: true,
    };
    db::create_user(&params).unwrap();
    let result = db::create_user(&params);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Client CRUD
// ---------------------------------------------------------------------------

fn create_test_client(name: &str) -> i64 {
    create_test_client_with_ip(name, "10.8.0.10", "fdcc::10")
}

fn create_test_client_with_ip(name: &str, ipv4: &str, ipv6: &str) -> i64 {
    db::create_client(&db::CreateClientParams {
        user_id: None,
        interface_id: Some("awg0".into()),
        name: name.into(),
        ipv4_address: Some(ipv4.into()),
        ipv6_address: Some(ipv6.into()),
        private_key: format!("pk-{name}"),
        public_key: format!("pub-{name}"),
        pre_shared_key: Some(format!("psk-{name}")),
        pre_up: None, post_up: None, pre_down: None, post_down: None,
        expires_at: None,
        allowed_ips: Some(r#"["0.0.0.0/0"]"#.into()),
        server_allowed_ips: None, firewall_ips: None,
        persistent_keepalive: 25, mtu: 1420,
        j_c: None, j_min: None, j_max: None,
        i1: None, i2: None, i3: None, i4: None, i5: None,
        dns: Some(r#"["1.1.1.1"]"#.into()),
        server_endpoint: None,
        advanced_security: Some(true),
        enabled: true,
    }).unwrap()
}

#[test]
#[serial(db)]
fn create_and_get_client() {
    seed();
    let id = create_test_client("my-client");
    assert!(id > 0);
    let client = db::get_client(id).unwrap();
    assert_eq!(client.name, "my-client");
    assert_eq!(client.ipv4_address.unwrap(), "10.8.0.10");
    assert!(client.enabled);
}

#[test]
#[serial(db)]
fn get_client_not_found() {
    seed();
    assert!(db::get_client(9999).is_err());
}

#[test]
#[serial(db)]
fn get_all_clients() {
    seed();
    assert_eq!(db::get_all_clients().unwrap().len(), 0);
    create_test_client_with_ip("c1", "10.8.0.10", "fdcc::10");
    create_test_client_with_ip("c2", "10.8.0.11", "fdcc::11");
    assert_eq!(db::get_all_clients().unwrap().len(), 2);
}

#[test]
#[serial(db)]
fn update_client() {
    seed();
    let id = create_test_client("update-me");
    let mut fields = db::UpdateMap::new();
    fields.insert("name".into(), "updated-name".into());
    fields.insert("enabled".into(), "0".into());
    db::update_client(id, &fields).unwrap();
    let client = db::get_client(id).unwrap();
    assert_eq!(client.name, "updated-name");
    assert!(!client.enabled);
}

#[test]
#[serial(db)]
fn delete_client() {
    seed();
    let id = create_test_client("to-delete");
    db::delete_client(id).unwrap();
    assert!(db::get_client(id).is_err());
}

#[test]
#[serial(db)]
fn delete_client_not_found() {
    seed();
    assert!(db::delete_client(9999).is_err());
}

#[test]
#[serial(db)]
fn toggle_client() {
    seed();
    let id = create_test_client("toggle-me");
    db::toggle_client(id, false).unwrap();
    assert!(!db::get_client(id).unwrap().enabled);
    db::toggle_client(id, true).unwrap();
    assert!(db::get_client(id).unwrap().enabled);
}

#[test]
#[serial(db)]
fn update_client_invalid_column() {
    seed();
    let id = create_test_client("bad-update");
    let mut fields = db::UpdateMap::new();
    fields.insert("nope".into(), "v".into());
    assert!(db::update_client(id, &fields).is_err());
}

#[test]
#[serial(db)]
fn client_ipv4_unique_constraint() {
    seed();
    create_test_client("c1");
    // Creating another client with the same ipv4 should fail
    let result = db::create_client(&db::CreateClientParams {
        user_id: None,
        interface_id: Some("awg0".into()),
        name: "c2".into(),
        ipv4_address: Some("10.8.0.10".into()), // same as c1
        ipv6_address: Some("fdcc::99".into()),
        private_key: "pk2".into(),
        public_key: "pub2".into(),
        pre_shared_key: Some("psk2".into()),
        pre_up: None, post_up: None, pre_down: None, post_down: None,
        expires_at: None,
        allowed_ips: Some(r#"["0.0.0.0/0"]"#.into()),
        server_allowed_ips: None, firewall_ips: None,
        persistent_keepalive: 25, mtu: 1420,
        j_c: None, j_min: None, j_max: None,
        i1: None, i2: None, i3: None, i4: None, i5: None,
        dns: Some(r#"["1.1.1.1"]"#.into()),
        server_endpoint: None,
        advanced_security: Some(true),
        enabled: true,
    });
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// IP Allocation
// ---------------------------------------------------------------------------

#[test]
fn next_ipv4_first_available() {
    // 10.8.0.0/24 — server occupies .1 by convention, peers start at .2.
    let ip = db::next_ipv4("10.8.0.0/24", &[]).unwrap();
    assert_eq!(ip, "10.8.0.2");
}

#[test]
fn next_ipv4_skips_used() {
    // Used addresses include the server (.1) and peers .2-.5; next is .6.
    let used: Vec<String> = (2..=5)
        .map(|i| format!("10.8.0.{i}"))
        .collect();
    let ip = db::next_ipv4("10.8.0.0/24", &used).unwrap();
    assert_eq!(ip, "10.8.0.6");
}

#[test]
fn next_ipv4_exhausted_pool() {
    let used: Vec<String> = (2..=254)
        .map(|i| format!("10.8.0.{i}"))
        .collect();
    let result = db::next_ipv4("10.8.0.0/24", &used);
    assert!(result.is_err());
}

#[test]
fn next_ipv4_invalid_cidr() {
    assert!(db::next_ipv4("not-a-cidr", &[]).is_err());
}

#[test]
fn next_ipv6_first_available() {
    // cidr::Ipv6Net::hosts() for fdcc::/112 enumerates fdcc:: (network) and
    // fdcc::1 (server) before fdcc::2 (first peer). The allocator skips both
    // the network address and the server IP, so peer #1 lands on fdcc::2.
    let ip = db::next_ipv6("fdcc::/112", &[]).unwrap();
    assert_eq!(ip, "fdcc::2");
}

#[test]
fn next_ipv6_skips_used() {
    let used: Vec<String> = vec!["fdcc::2".into(), "fdcc::3".into()];
    let ip = db::next_ipv6("fdcc::/112", &used).unwrap();
    assert_eq!(ip, "fdcc::4");
}

#[test]
fn next_ipv6_invalid_cidr() {
    assert!(db::next_ipv6("not-a-cidr", &[]).is_err());
}

// ---------------------------------------------------------------------------
// One-time links
// ---------------------------------------------------------------------------

#[test]
#[serial(db)]
fn create_and_get_one_time_link() {
    seed();
    let client_id = create_test_client("otl-client");
    db::create_one_time_link(client_id, "my-token", "2099-01-01T00:00:00Z").unwrap();
    let link = db::get_one_time_link("my-token").unwrap();
    assert_eq!(link.id, client_id);
    assert_eq!(link.one_time_link, "my-token");
}

#[test]
#[serial(db)]
fn delete_one_time_link() {
    seed();
    let client_id = create_test_client("otl-del");
    db::create_one_time_link(client_id, "del-token", "2099-01-01T00:00:00Z").unwrap();
    db::delete_one_time_link(client_id).unwrap();
    assert!(db::get_one_time_link("del-token").is_err());
}

#[test]
#[serial(db)]
fn get_one_time_link_not_found() {
    seed();
    assert!(db::get_one_time_link("no-such-token").is_err());
}

// ---------------------------------------------------------------------------
// General settings
// ---------------------------------------------------------------------------

#[test]
#[serial(db)]
fn get_general_seeded() {
    seed();
    let general = db::get_general().unwrap();
    assert_eq!(general.setup_step, 1);
    assert_eq!(general.session_timeout, 3600);
    assert!(!general.session_password.is_empty());
}

#[test]
#[serial(db)]
fn update_general() {
    seed();
    let mut fields = db::UpdateMap::new();
    fields.insert("session_timeout".into(), "7200".into());
    db::update_general(&fields).unwrap();
    let general = db::get_general().unwrap();
    assert_eq!(general.session_timeout, 7200);
}

#[test]
#[serial(db)]
fn set_setup_step() {
    seed();
    db::set_setup_step(3).unwrap();
    assert_eq!(db::get_setup_step().unwrap(), 3);
}

// ---------------------------------------------------------------------------
// User config
// ---------------------------------------------------------------------------

#[test]
#[serial(db)]
fn get_user_config_seeded() {
    seed();
    let uc = db::get_user_config().unwrap();
    assert_eq!(uc.id, "awg0");
    assert_eq!(uc.default_mtu, 1420);
    assert_eq!(uc.default_persistent_keepalive, 0);
    assert_eq!(uc.port, 51820);
}

#[test]
#[serial(db)]
fn update_user_config() {
    seed();
    let mut fields = db::UpdateMap::new();
    fields.insert("default_mtu".into(), "1280".into());
    db::update_user_config(&fields).unwrap();
    assert_eq!(db::get_user_config().unwrap().default_mtu, 1280);
}

#[test]
#[serial(db)]
fn update_host_port() {
    seed();
    db::update_host_port("vpn.myhost.com", 1194).unwrap();
    let uc = db::get_user_config().unwrap();
    assert_eq!(uc.host, "vpn.myhost.com");
    assert_eq!(uc.port, 1194);
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

#[test]
#[serial(db)]
fn get_hooks_seeded() {
    seed();
    let hooks = db::get_hooks().unwrap();
    assert_eq!(hooks.id, "awg0");
    // Native nftables defaults: PostUp creates the awg-easy-rs table and
    // a masquerade rule; PostDown wipes the table atomically.
    assert!(hooks.post_up.contains("nft "), "post_up must use nft");
    assert!(hooks.post_up.contains("inet awg-easy-rs"));
    assert!(hooks.post_up.contains("masquerade"));
    assert!(hooks.post_down.contains("nft delete table inet awg-easy-rs"));
    assert!(
        !hooks.post_up.contains("iptables") && !hooks.post_down.contains("iptables"),
        "default hooks must not reference iptables anymore"
    );
}

#[test]
#[serial(db)]
fn update_hooks() {
    seed();
    let mut fields = db::UpdateMap::new();
    fields.insert("pre_up".into(), "echo hello".into());
    db::update_hooks(&fields).unwrap();
    assert_eq!(db::get_hooks().unwrap().pre_up, "echo hello");
}

// ---------------------------------------------------------------------------
// Xray inbound + clients
// ---------------------------------------------------------------------------

#[test]
#[serial(db)]
fn get_xray_inbound_seeded() {
    seed();
    let inbound = db::get_xray_inbound().unwrap();
    assert_eq!(inbound.id, "xray0");
    assert_eq!(inbound.port, 443);
    // Default dest must be reachable from most jurisdictions; if we ever
    // change it, update this assertion.
    assert_eq!(inbound.dest, "www.microsoft.com:443");
    assert!(inbound.server_names.contains("www.microsoft.com"));
    assert_eq!(inbound.fingerprint_default, "chrome");
    // Disabled until operator generates keys.
    assert!(!inbound.enabled);
    assert!(inbound.private_key.is_empty());
    assert!(inbound.public_key.is_empty());
}

#[test]
#[serial(db)]
fn update_xray_keypair_round_trip() {
    seed();
    db::update_xray_keypair("PRIV_KEY_BASE64", "PUB_KEY_BASE64").unwrap();
    let inbound = db::get_xray_inbound().unwrap();
    assert_eq!(inbound.private_key, "PRIV_KEY_BASE64");
    assert_eq!(inbound.public_key, "PUB_KEY_BASE64");
}

#[test]
#[serial(db)]
fn update_xray_inbound_invalid_column() {
    seed();
    let mut fields = db::UpdateMap::new();
    // Column not in VALID_XRAY_INBOUND_COLUMNS — must be rejected.
    fields.insert("password".into(), "hunter2".into());
    let res = db::update_xray_inbound(&fields);
    assert!(res.is_err(), "whitelist must reject unknown columns");
}

#[test]
#[serial(db)]
fn create_and_list_xray_clients() {
    seed();
    let id = db::create_xray_client(&db::CreateXrayClientParams {
        user_id: None,
        inbound_id: "xray0".into(),
        name: "alice".into(),
        uuid: "11111111-2222-3333-4444-555555555555".into(),
        short_id: "0123456789abcdef".into(),
        expires_at: None,
        additional_config: None,
        enabled: true,
    }).unwrap();
    assert!(id > 0);

    let clients = db::list_xray_clients().unwrap();
    assert_eq!(clients.len(), 1);
    assert_eq!(clients[0].name, "alice");
    assert_eq!(clients[0].uuid, "11111111-2222-3333-4444-555555555555");
    assert_eq!(clients[0].short_id, "0123456789abcdef");
    assert!(clients[0].enabled);
}

#[test]
#[serial(db)]
fn xray_client_uuid_unique() {
    seed();
    let p = db::CreateXrayClientParams {
        user_id: None,
        inbound_id: "xray0".into(),
        name: "alice".into(),
        uuid: "deadbeef-dead-beef-dead-beefdeadbeef".into(),
        short_id: "aaaaaaaaaaaaaaaa".into(),
        expires_at: None,
        additional_config: None,
        enabled: true,
    };
    db::create_xray_client(&p).unwrap();
    // Second insert with same UUID must fail the UNIQUE constraint.
    let res = db::create_xray_client(&p);
    assert!(res.is_err(), "UUID UNIQUE must be enforced");
}

#[test]
#[serial(db)]
fn xray_client_short_id_unique() {
    seed();
    db::create_xray_client(&db::CreateXrayClientParams {
        user_id: None,
        inbound_id: "xray0".into(),
        name: "alice".into(),
        uuid: "11111111-1111-1111-1111-111111111111".into(),
        short_id: "shared_short_id".into(),
        expires_at: None,
        additional_config: None,
        enabled: true,
    }).unwrap();
    // Different UUID, same shortId — must fail UNIQUE on short_id.
    let res = db::create_xray_client(&db::CreateXrayClientParams {
        user_id: None,
        inbound_id: "xray0".into(),
        name: "bob".into(),
        uuid: "22222222-2222-2222-2222-222222222222".into(),
        short_id: "shared_short_id".into(),
        expires_at: None,
        additional_config: None,
        enabled: true,
    });
    assert!(res.is_err(), "short_id UNIQUE must be enforced");
}

#[test]
#[serial(db)]
fn toggle_and_delete_xray_client() {
    seed();
    let id = db::create_xray_client(&db::CreateXrayClientParams {
        user_id: None,
        inbound_id: "xray0".into(),
        name: "carol".into(),
        uuid: "33333333-3333-3333-3333-333333333333".into(),
        short_id: "bbbbbbbbbbbbbbbb".into(),
        expires_at: None,
        additional_config: None,
        enabled: true,
    }).unwrap();
    db::toggle_xray_client(id, false).unwrap();
    assert!(!db::get_xray_client(id).unwrap().enabled);
    db::delete_xray_client(id).unwrap();
    assert!(db::get_xray_client(id).is_err());
}
