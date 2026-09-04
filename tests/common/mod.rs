//! Shared test fixtures — temp env, in-memory DB, rate limiter reset.

use std::sync::OnceLock;

static SETUP: OnceLock<()> = OnceLock::new();

pub fn seed() {
    SETUP.get_or_init(|| {
        // Write WireGuard configs to a temp directory instead of /etc/coffeeblack/conf
        let dir = std::env::temp_dir().join("coffeeblack-vpn-test");
        std::fs::create_dir_all(&dir).expect("create test conf dir");
        std::env::set_var("COFFEEBLACK_CONF_DIR", dir.to_str().unwrap());

        // Run the API suites with secret encryption ENABLED. This is what
        // makes the existing TOTP login tests meaningful proof that the
        // encrypted path works end to end — the secret is written encrypted
        // by the setup handler and has to come back decrypted for the login
        // handler to verify a code. Without a key here they would all pass
        // through the plaintext branch and prove nothing about encryption.
        //
        // The unconfigured branch is still covered: `tests/db.rs`,
        // `tests/auth.rs` and the unit tests in `src/crypto.rs` call
        // `db::init_test_db()` directly and never set this, so both shapes
        // are exercised across the suite. Must be set before anything touches
        // `crypto`, whose key is a process-wide `LazyLock`.
        std::env::set_var(
            "COFFEEBLACK_SECRET_KEY",
            "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
        );
    });

    coffeeblack_vpn::db::init_test_db();
    // The activity history is a process-global in-memory store, so it needs
    // resetting between tests exactly like the DB handle does — otherwise one
    // test's recorded peers leak into the next one's heatmap.
    coffeeblack_vpn::activity::reset_for_tests();
    coffeeblack_vpn::api::session::reset_login_attempts();
    coffeeblack_vpn::api::session::reset_totp_attempts();
}
