//! Secret-encryption tests.
//!
//! `crypto::KEY` is a process-wide `LazyLock` resolved on first use, so the
//! key has to be in the environment before anything touches the module. This
//! file therefore sets it at the very top of every test *and* keeps all of the
//! key-present assertions in one binary — a second test binary gets its own
//! process and its own resolution, which is exactly what the "no key
//! configured" coverage in `src/crypto.rs`'s unit tests relies on.

use awg_easy_rs::{crypto, db};
use serial_test::serial;

/// Set the key before the LazyLock can resolve. Idempotent; every test calls
/// it because test order within a binary is not guaranteed.
fn install_key() {
    // Deterministic 32 bytes, base64 — test material only.
    std::env::set_var(
        "WG_EASY_SECRET_KEY",
        "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
    );
}

fn seed() {
    install_key();
    db::init_test_db();
}

#[test]
#[serial(db)]
fn key_is_picked_up_from_the_environment() {
    install_key();
    assert!(
        crypto::is_configured(),
        "a 32-byte base64 key in WG_EASY_SECRET_KEY must be accepted"
    );
}

#[test]
#[serial(db)]
fn round_trips() {
    install_key();
    let secret = "JBSWY3DPEHPK3PXP";
    let enc = crypto::encrypt(secret).unwrap();
    assert!(crypto::is_encrypted(&enc));
    assert!(!enc.contains(secret), "ciphertext must not contain the plaintext");
    assert_eq!(crypto::decrypt(&enc).unwrap(), secret);
}

#[test]
#[serial(db)]
fn each_encryption_uses_a_fresh_nonce() {
    install_key();
    let a = crypto::encrypt("same-input").unwrap();
    let b = crypto::encrypt("same-input").unwrap();
    // Deterministic ciphertext would mean a reused nonce, which for GCM is
    // catastrophic rather than merely untidy — and it would also leak that two
    // users share a secret.
    assert_ne!(a, b);
    assert_eq!(crypto::decrypt(&a).unwrap(), "same-input");
    assert_eq!(crypto::decrypt(&b).unwrap(), "same-input");
}

#[test]
#[serial(db)]
fn tampering_is_detected() {
    install_key();
    let enc = crypto::encrypt("JBSWY3DPEHPK3PXP").unwrap();
    // Flip a character in the base64 body. GCM is authenticated, so this must
    // fail loudly rather than yield garbage that later fails as a bad code.
    let body = &enc[crypto::ENC_PREFIX.len()..];
    let mut chars: Vec<char> = body.chars().collect();
    let last = chars.len() - 2;
    chars[last] = if chars[last] == 'A' { 'B' } else { 'A' };
    let tampered = format!("{}{}", crypto::ENC_PREFIX, chars.into_iter().collect::<String>());
    assert!(crypto::decrypt(&tampered).is_err());
}

#[test]
#[serial(db)]
fn legacy_plaintext_is_passed_through() {
    install_key();
    // Values written before encryption was configured have no prefix and must
    // keep working — otherwise enabling the feature locks every existing user
    // out of their second factor.
    assert_eq!(crypto::decrypt("JBSWY3DPEHPK3PXP").unwrap(), "JBSWY3DPEHPK3PXP");
}

#[test]
#[serial(db)]
fn malformed_ciphertext_errors_without_panicking() {
    install_key();
    for bad in ["enc$", "enc$!!!!", "enc$AAAA", "enc$QUFBQQ=="] {
        assert!(crypto::decrypt(bad).is_err(), "{bad} should error");
    }
}

// ---------------------------------------------------------------------------
// Storage integration
// ---------------------------------------------------------------------------

fn make_user(username: &str, totp: Option<&str>) -> i64 {
    db::create_user(&db::CreateUserParams {
        username: username.into(),
        password: "hash".into(),
        email: None,
        name: username.into(),
        role: 1,
        totp_key: totp.map(|s| s.to_string()),
        totp_verified: totp.is_some(),
        enabled: true,
    })
    .unwrap()
}

/// Read the column without going through the row mapper, which decrypts.
fn raw_totp(user_id: i64) -> Option<String> {
    db::raw_totp_key(user_id).unwrap()
}

#[test]
#[serial(db)]
fn totp_secrets_are_encrypted_on_disk_and_plaintext_in_memory() {
    seed();
    let secret = "JBSWY3DPEHPK3PXP";
    let id = make_user("alice", Some(secret));

    // On disk: ciphertext, and the secret must not appear anywhere in it.
    let stored = raw_totp(id).unwrap();
    assert!(crypto::is_encrypted(&stored), "stored value must be encrypted");
    assert!(!stored.contains(secret));

    // In memory: the plaintext the verifier needs, with no call site aware
    // that encryption happened at all.
    assert_eq!(db::get_user(id).unwrap().totp_key.as_deref(), Some(secret));
}

#[test]
#[serial(db)]
fn updating_a_secret_encrypts_it_too() {
    seed();
    let id = make_user("bob", None);
    let mut f = db::UpdateMap::new();
    f.insert("totp_key".into(), "NEWSECRET1234567".into());
    db::update_user(id, &f).unwrap();

    assert!(crypto::is_encrypted(&raw_totp(id).unwrap()));
    assert_eq!(
        db::get_user(id).unwrap().totp_key.as_deref(),
        Some("NEWSECRET1234567")
    );
}

#[test]
#[serial(db)]
fn re_saving_an_encrypted_value_does_not_double_encrypt() {
    seed();
    let id = make_user("carol", Some("JBSWY3DPEHPK3PXP"));
    let already = raw_totp(id).unwrap();

    let mut f = db::UpdateMap::new();
    f.insert("totp_key".into(), already.clone());
    db::update_user(id, &f).unwrap();

    // Still exactly one layer: decrypting once yields the secret, not another
    // enc$ blob.
    assert_eq!(
        db::get_user(id).unwrap().totp_key.as_deref(),
        Some("JBSWY3DPEHPK3PXP")
    );
}

#[test]
#[serial(db)]
fn startup_migration_upgrades_legacy_plaintext_rows() {
    seed();
    let id = make_user("dave", Some("JBSWY3DPEHPK3PXP"));
    // Simulate a row written before encryption existed.
    db::force_raw_totp_key(id, "JBSWY3DPEHPK3PXP").unwrap();
    assert!(!crypto::is_encrypted(&raw_totp(id).unwrap()));

    let upgraded = db::encrypt_plaintext_totp_secrets().unwrap();
    assert_eq!(upgraded, 1);
    assert!(crypto::is_encrypted(&raw_totp(id).unwrap()));
    assert_eq!(
        db::get_user(id).unwrap().totp_key.as_deref(),
        Some("JBSWY3DPEHPK3PXP")
    );

    // Idempotent: a second pass has nothing left to do.
    assert_eq!(db::encrypt_plaintext_totp_secrets().unwrap(), 0);
}

#[test]
#[serial(db)]
fn migration_leaves_users_without_a_secret_alone() {
    seed();
    let id = make_user("erin", None);
    assert_eq!(db::encrypt_plaintext_totp_secrets().unwrap(), 0);
    assert!(db::get_user(id).unwrap().totp_key.is_none());
}

// ---------------------------------------------------------------------------
// The rest of the secret columns
// ---------------------------------------------------------------------------

/// Every column the registry claims to protect, checked against the raw bytes
/// on disk rather than through the row mappers (which decrypt and would make
/// an unencrypted column look identical to an encrypted one).
fn raw(table: &str, column: &str) -> Vec<String> {
    db::raw_column(table, column).unwrap()
}

#[test]
#[serial(db)]
fn wireguard_material_is_encrypted_at_rest() {
    seed();
    let secret = "cGVlci1wcml2YXRlLWtleS1oZXJlLTAwMDAwMDAwMDA=";
    let psk = "cHJlc2hhcmVkLWtleS1oZXJlLTAwMDAwMDAwMDAwMDA=";
    let id = db::create_client(&db::CreateClientParams {
        user_id: None,
        interface_id: Some("awg0".into()),
        name: "phone".into(),
        ipv4_address: Some("10.8.0.2".into()),
        ipv6_address: None,
        private_key: secret.into(),
        public_key: "pub".into(),
        pre_shared_key: Some(psk.into()),
        pre_up: None, post_up: None, pre_down: None, post_down: None,
        expires_at: None,
        allowed_ips: None, server_allowed_ips: None, firewall_ips: None,
        persistent_keepalive: 0, mtu: 1420,
        j_c: None, j_min: None, j_max: None,
        i1: None, i2: None, i3: None, i4: None, i5: None,
        dns: None, server_endpoint: None, advanced_security: None,
        enabled: true,
    })
    .unwrap();

    for stored in raw("clients_table", "private_key") {
        assert!(crypto::is_encrypted(&stored), "peer private key stored as {stored}");
        assert!(!stored.contains(secret));
    }
    for stored in raw("clients_table", "pre_shared_key") {
        assert!(crypto::is_encrypted(&stored), "PSK stored as {stored}");
        assert!(!stored.contains(psk));
    }
    // …and comes back usable, because the config generator needs the real value.
    let c = db::get_client(id).unwrap();
    assert_eq!(c.private_key, secret);
    assert_eq!(c.pre_shared_key.as_deref(), Some(psk));

    // The server's own key too.
    db::update_key_pair("srvpub", "srvpriv-secret-value").unwrap();
    for stored in raw("interfaces_table", "private_key") {
        assert!(crypto::is_encrypted(&stored), "server key stored as {stored}");
    }
    assert_eq!(db::get_interface().unwrap().private_key, "srvpriv-secret-value");
}

#[test]
#[serial(db)]
fn xray_and_mtproxy_credentials_are_encrypted_at_rest() {
    seed();
    let uuid = "11111111-2222-3333-4444-555555555555";
    let short = "a1b2c3d4";
    db::create_xray_client(&db::CreateXrayClientParams {
        user_id: None,
        inbound_id: "xray0".into(),
        name: "browser".into(),
        uuid: uuid.into(),
        short_id: short.into(),
        expires_at: None,
        additional_config: None,
        enabled: true,
    })
    .unwrap();
    for stored in raw("xray_clients_table", "uuid") {
        assert!(crypto::is_encrypted(&stored), "VLESS UUID stored as {stored}");
        assert!(!stored.contains(uuid));
    }
    for stored in raw("xray_clients_table", "short_id") {
        assert!(crypto::is_encrypted(&stored));
    }
    let listed = db::list_xray_clients().unwrap();
    assert_eq!(listed[0].uuid, uuid, "must come back usable for the Xray config");
    assert_eq!(listed[0].short_id, short);

    // Reality server key.
    db::update_xray_keypair("reality-private-secret", "reality-public").unwrap();
    for stored in raw("xray_inbound_table", "private_key") {
        assert!(crypto::is_encrypted(&stored), "Reality key stored as {stored}");
    }
    assert_eq!(db::get_xray_inbound().unwrap().private_key, "reality-private-secret");

    // MTProxy per-user secret.
    db::create_mtproxy_user(&db::CreateMtproxyUserParams {
        user_id: None,
        inbound_id: "mtproxy0".into(),
        username: "tg".into(),
        secret_hex: "00112233445566778899aabbccddeeff".into(),
        ad_tag: None,
        enabled: true,
    })
    .unwrap();
    for stored in raw("mtproxy_users_table", "secret_hex") {
        assert!(crypto::is_encrypted(&stored), "MTProxy secret stored as {stored}");
        assert!(!stored.contains("00112233445566778899aabbccddeeff"));
    }
    assert_eq!(
        db::get_mtproxy_user_by_username("tg").unwrap().secret_hex,
        "00112233445566778899aabbccddeeff"
    );
}

#[test]
#[serial(db)]
fn dns_tunnel_key_and_session_secret_are_encrypted_at_rest() {
    seed();
    db::update_mdnsvpn_encryption_key("tunnel-key-material").unwrap();
    for stored in raw("mdnsvpn_inbound_table", "encryption_key") {
        assert!(crypto::is_encrypted(&stored), "DNS-tunnel key stored as {stored}");
    }
    assert_eq!(
        db::get_mdnsvpn_inbound().unwrap().encryption_key,
        "tunnel-key-material"
    );

    // Seeded at first run, so it exercises the seed path rather than an update.
    for stored in raw("general_table", "session_password") {
        assert!(crypto::is_encrypted(&stored), "session secret stored as {stored}");
    }
}

#[test]
#[serial(db)]
fn one_time_link_tokens_are_stored_hashed() {
    seed();
    let id = db::create_client(&db::CreateClientParams {
        user_id: None, interface_id: Some("awg0".into()), name: "p".into(),
        ipv4_address: Some("10.8.0.9".into()), ipv6_address: None,
        private_key: "pk".into(), public_key: "pub".into(), pre_shared_key: None,
        pre_up: None, post_up: None, pre_down: None, post_down: None,
        expires_at: None, allowed_ips: None, server_allowed_ips: None,
        firewall_ips: None, persistent_keepalive: 0, mtu: 1420,
        j_c: None, j_min: None, j_max: None,
        i1: None, i2: None, i3: None, i4: None, i5: None,
        dns: None, server_endpoint: None, advanced_security: None, enabled: true,
    })
    .unwrap();

    let token = "0123456789abcdef0123456789abcdef";
    db::create_one_time_link(id, token, "2099-01-01T00:00:00Z").unwrap();

    // The lookup column must be a digest, not the bearer token.
    let stored = raw("one_time_links_table", "one_time_link");
    assert_eq!(stored.len(), 1);
    assert_ne!(stored[0], token, "the raw token must not be the stored value");
    assert_eq!(stored[0], awg_easy_rs::auth::sha256(token));

    // Lookup by the real token still works…
    assert_eq!(db::get_one_time_link(token).unwrap().id, id);
    // …and a wrong token does not.
    assert!(db::get_one_time_link("ffffffffffffffffffffffffffffffff").is_err());
    // …and the token is still recoverable for display, from the encrypted copy.
    assert_eq!(
        db::get_active_one_time_link(id).unwrap().unwrap().one_time_link,
        token
    );
}

#[test]
#[serial(db)]
fn migration_upgrades_every_registered_column() {
    seed();
    db::create_client(&db::CreateClientParams {
        user_id: None, interface_id: Some("awg0".into()), name: "p".into(),
        ipv4_address: Some("10.8.0.7".into()), ipv6_address: None,
        private_key: "legacy-private".into(), public_key: "pub".into(),
        pre_shared_key: Some("legacy-psk".into()),
        pre_up: None, post_up: None, pre_down: None, post_down: None,
        expires_at: None, allowed_ips: None, server_allowed_ips: None,
        firewall_ips: None, persistent_keepalive: 0, mtu: 1420,
        j_c: None, j_min: None, j_max: None,
        i1: None, i2: None, i3: None, i4: None, i5: None,
        dns: None, server_endpoint: None, advanced_security: None, enabled: true,
    })
    .unwrap();
    // Force the pre-encryption shape everywhere.
    db::force_raw_column("clients_table", "private_key", "legacy-private").unwrap();
    db::force_raw_column("clients_table", "pre_shared_key", "legacy-psk").unwrap();
    db::force_raw_column("interfaces_table", "private_key", "legacy-server-key").unwrap();

    let n = db::encrypt_plaintext_secrets().unwrap();
    assert!(n >= 3, "expected at least the three forced columns, got {n}");
    for (t, c) in [
        ("clients_table", "private_key"),
        ("clients_table", "pre_shared_key"),
        ("interfaces_table", "private_key"),
    ] {
        for stored in raw(t, c) {
            assert!(crypto::is_encrypted(&stored), "{t}.{c} left as {stored}");
        }
    }
    assert_eq!(db::get_interface().unwrap().private_key, "legacy-server-key");
    // Idempotent.
    assert_eq!(db::encrypt_plaintext_secrets().unwrap(), 0);
}
