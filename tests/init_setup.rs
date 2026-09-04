//! INIT_ENABLED auto-provisioning (end-to-end against the in-memory DB).

mod common;

use coffeeblack_vpn::{db, init_setup};
use serial_test::serial;

fn params<'a>(
    username: &'a str,
    password: &'a str,
    dns: &'a [String],
    allowed: &'a [String],
) -> init_setup::InitSetupParams<'a> {
    init_setup::InitSetupParams {
        username,
        password,
        host: Some("vpn.example.com"),
        port: Some(51820),
        ipv4_cidr: Some("10.9.0.1/24"),
        ipv6_cidr: None,
        dns: Some(dns),
        allowed_ips: Some(allowed),
    }
}

#[test]
#[serial(db)]
fn provisions_admin_and_completes_setup() {
    common::seed();
    assert_eq!(db::get_user_count().unwrap(), 0);

    let dns = vec!["1.1.1.1".to_string()];
    let allowed = vec!["0.0.0.0/0".to_string()];
    let p = params("root", "supersecret-pw", &dns, &allowed);

    assert!(init_setup::provision_initial_setup(&p).unwrap(), "provisioned");
    assert_eq!(db::get_user_count().unwrap(), 1);
    // Setup wizard marked complete.
    assert_eq!(db::get_general().unwrap().setup_step, 0);
    // The seeded defaults were overwritten.
    let uc = db::get_user_config().unwrap();
    assert!(uc.default_dns.contains("1.1.1.1"));

    // Idempotent: with a user present, a second call is a no-op.
    assert!(!init_setup::provision_initial_setup(&p).unwrap(), "skipped");
    assert_eq!(db::get_user_count().unwrap(), 1);
}

#[test]
#[serial(db)]
fn rejects_short_password_and_leaves_db_empty() {
    common::seed();
    let dns: Vec<String> = vec![];
    let allowed: Vec<String> = vec![];
    let p = params("root", "short", &dns, &allowed);
    assert!(init_setup::provision_initial_setup(&p).is_err());
    assert_eq!(db::get_user_count().unwrap(), 0);
}
