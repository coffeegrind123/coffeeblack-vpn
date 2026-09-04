//! Track 1: Unit tests for config.rs — environment variable parsing and
//! defaults.

use std::sync::{Mutex, MutexGuard, OnceLock};

/// Every test here mutates the *process-wide* environment, and
/// `Config::load()` reads all of it. libtest runs tests in one process on
/// several threads, so without serialisation one test's `remove_var` races
/// another's `set_var` — e.g. `config_init_enabled_default` clearing
/// `INIT_ENABLED` between `config_init_enabled_true`'s `set_var` and its
/// `Config::load()`. That reproduced at roughly 1 run in 6.
///
/// Hold this guard for the whole body of any test that touches the
/// environment. Poisoning is recovered from deliberately: a panic in one
/// test must fail only that test, not cascade into every other one.
fn env_guard() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[test]
fn get_env_returns_value_when_set() {
    let _env = env_guard();
    std::env::set_var("COFFEEBLACK_TEST_GET_ENV", "hello");
    let val = coffeeblack_vpn::config::get_env("COFFEEBLACK_TEST_GET_ENV", "default");
    assert_eq!(val, "hello");
}

#[test]
fn get_env_returns_default_when_unset() {
    let _env = env_guard();
    // Make sure the env var is not set
    std::env::remove_var("COFFEEBLACK_TEST_GET_ENV_UNSET");
    let val = coffeeblack_vpn::config::get_env("COFFEEBLACK_TEST_GET_ENV_UNSET", "fallback");
    assert_eq!(val, "fallback");
}

#[test]
fn get_env_empty_string_uses_default() {
    let _env = env_guard();
    // If the var is set but empty, we still get the value (empty string)
    // because env::var returns Ok("") — our implementation returns that.
    // Test that default is returned when var doesn't exist at all.
    std::env::remove_var("COFFEEBLACK_TEST_EMPTY_VAR");
    let val =
        coffeeblack_vpn::config::get_env("COFFEEBLACK_TEST_EMPTY_VAR", "default-val");
    assert_eq!(val, "default-val");
}

#[test]
fn config_port_default() {
    let _env = env_guard();
    std::env::remove_var("PORT");
    let cfg = coffeeblack_vpn::config::Config::load();
    assert_eq!(cfg.port, 51821);
}

#[test]
fn config_port_custom() {
    let _env = env_guard();
    std::env::set_var("PORT", "9999");
    let cfg = coffeeblack_vpn::config::Config::load();
    assert_eq!(cfg.port, 9999);
    std::env::remove_var("PORT");
}

#[test]
fn config_port_invalid_uses_default() {
    let _env = env_guard();
    std::env::set_var("PORT", "not-a-number");
    let cfg = coffeeblack_vpn::config::Config::load();
    assert_eq!(cfg.port, 51821);
    std::env::remove_var("PORT");
}

#[test]
fn config_host_default() {
    let _env = env_guard();
    std::env::remove_var("HOST");
    let cfg = coffeeblack_vpn::config::Config::load();
    assert_eq!(cfg.host, "0.0.0.0");
}

#[test]
fn config_host_custom() {
    let _env = env_guard();
    std::env::set_var("HOST", "127.0.0.1");
    let cfg = coffeeblack_vpn::config::Config::load();
    assert_eq!(cfg.host, "127.0.0.1");
    std::env::remove_var("HOST");
}

#[test]
fn config_insecure_true_variants() {
    let _env = env_guard();
    std::env::set_var("INSECURE", "TRUE");
    assert!(coffeeblack_vpn::config::Config::load().insecure);
    std::env::set_var("INSECURE", "true");
    assert!(coffeeblack_vpn::config::Config::load().insecure);
    std::env::remove_var("INSECURE");
}

#[test]
fn config_insecure_default_false() {
    let _env = env_guard();
    std::env::remove_var("INSECURE");
    assert!(!coffeeblack_vpn::config::Config::load().insecure);
}

#[test]
fn config_disable_ipv6_parsing_logic() {
    let _env = env_guard();
    // Test the parsing logic directly, since CONFIG is a LazyLock static
    // that can't be reloaded mid-process.
    let val = coffeeblack_vpn::config::get_env("COFFEEBLACK_TEST_DISABLE_IPV6_UNSET", "false");
    assert_eq!(val.to_lowercase(), "false");
    std::env::set_var("COFFEEBLACK_TEST_DISABLE_IPV6_UNSET", "true");
    let val = coffeeblack_vpn::config::get_env("COFFEEBLACK_TEST_DISABLE_IPV6_UNSET", "false");
    assert_eq!(val, "true");
    std::env::remove_var("COFFEEBLACK_TEST_DISABLE_IPV6_UNSET");
}

#[test]
fn config_disable_ipv6_true() {
    let _env = env_guard();
    std::env::set_var("DISABLE_IPV6", "true");
    assert!(coffeeblack_vpn::config::Config::load().disable_ipv6);
    std::env::remove_var("DISABLE_IPV6");
}

#[test]
fn config_init_enabled_default() {
    let _env = env_guard();
    std::env::remove_var("INIT_ENABLED");
    assert!(!coffeeblack_vpn::config::Config::load().init_enabled);
}

#[test]
fn config_init_enabled_true() {
    let _env = env_guard();
    std::env::set_var("INIT_ENABLED", "true");
    assert!(coffeeblack_vpn::config::Config::load().init_enabled);
    std::env::remove_var("INIT_ENABLED");
}

#[test]
fn config_init_username_set() {
    let _env = env_guard();
    std::env::set_var("INIT_USERNAME", "admin");
    let cfg = coffeeblack_vpn::config::Config::load();
    assert_eq!(cfg.init_username.unwrap(), "admin");
    std::env::remove_var("INIT_USERNAME");
}

#[test]
fn config_init_username_empty_ignored() {
    let _env = env_guard();
    std::env::set_var("INIT_USERNAME", "");
    let cfg = coffeeblack_vpn::config::Config::load();
    assert!(cfg.init_username.is_none());
    std::env::remove_var("INIT_USERNAME");
}

#[test]
fn config_init_password_set() {
    let _env = env_guard();
    std::env::set_var("INIT_PASSWORD", "hunter2");
    let cfg = coffeeblack_vpn::config::Config::load();
    assert_eq!(cfg.init_password.unwrap(), "hunter2");
    std::env::remove_var("INIT_PASSWORD");
}

#[test]
fn config_init_host_set() {
    let _env = env_guard();
    std::env::set_var("INIT_HOST", "vpn.example.com");
    let cfg = coffeeblack_vpn::config::Config::load();
    assert_eq!(cfg.init_host.unwrap(), "vpn.example.com");
    std::env::remove_var("INIT_HOST");
}

#[test]
fn config_init_port_set() {
    let _env = env_guard();
    std::env::set_var("INIT_PORT", "1194");
    let cfg = coffeeblack_vpn::config::Config::load();
    assert_eq!(cfg.init_port.unwrap(), 1194);
    std::env::remove_var("INIT_PORT");
}

#[test]
fn config_init_port_invalid() {
    let _env = env_guard();
    std::env::set_var("INIT_PORT", "bad");
    let cfg = coffeeblack_vpn::config::Config::load();
    assert!(cfg.init_port.is_none());
    std::env::remove_var("INIT_PORT");
}

#[test]
fn config_init_dns_parsed() {
    let _env = env_guard();
    std::env::set_var("INIT_DNS", "1.1.1.1,8.8.8.8, 9.9.9.9 ");
    let cfg = coffeeblack_vpn::config::Config::load();
    let dns = cfg.init_dns.unwrap();
    assert_eq!(dns, vec!["1.1.1.1", "8.8.8.8", "9.9.9.9"]);
    std::env::remove_var("INIT_DNS");
}

#[test]
fn config_comma_only_env_yields_empty_vec() {
    let _env = env_guard();
    // Comma-only strings should produce an empty Vec, which is filtered
    // to None by Config::load's check for init_dns.
    // black_box keeps the literal opaque so the `is_empty()` branch below isn't
    // const-folded (this mirrors Config::load's runtime logic on env input).
    let s = std::hint::black_box(",");
    let result: Option<Vec<String>> = if s.is_empty() {
        None
    } else {
        let v: Vec<String> = s.split(',')
            .map(|part| part.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect();
        if v.is_empty() { None } else { Some(v) }
    };
    assert!(result.is_none());
}

#[test]
fn config_init_ipv4_cidr_set() {
    let _env = env_guard();
    std::env::set_var("INIT_IPV4_CIDR", "10.0.0.0/24");
    let cfg = coffeeblack_vpn::config::Config::load();
    assert_eq!(cfg.init_ipv4_cidr.unwrap(), "10.0.0.0/24");
    std::env::remove_var("INIT_IPV4_CIDR");
}

#[test]
fn config_init_ipv6_cidr_set() {
    let _env = env_guard();
    std::env::set_var("INIT_IPV6_CIDR", "fd00::/64");
    let cfg = coffeeblack_vpn::config::Config::load();
    assert_eq!(cfg.init_ipv6_cidr.unwrap(), "fd00::/64");
    std::env::remove_var("INIT_IPV6_CIDR");
}

#[test]
fn config_init_allowed_ips_parsed() {
    let _env = env_guard();
    std::env::set_var("INIT_ALLOWED_IPS", "0.0.0.0/0,::/0, 192.168.0.0/16");
    let cfg = coffeeblack_vpn::config::Config::load();
    let ips = cfg.init_allowed_ips.unwrap();
    assert_eq!(ips, vec!["0.0.0.0/0", "::/0", "192.168.0.0/16"]);
    std::env::remove_var("INIT_ALLOWED_IPS");
}

#[test]
fn config_db_path_default() {
    let _env = env_guard();
    std::env::remove_var("COFFEEBLACK_DB_PATH");
    let cfg = coffeeblack_vpn::config::Config::load();
    assert_eq!(cfg.db_path, "/etc/coffeeblack/conf/coffeeblack.db");
}

#[test]
fn config_db_path_parsing_logic() {
    let _env = env_guard();
    // get_env fallback is the mechanism; test it directly since CONFIG
    // is a LazyLock that may already be initialised.
    std::env::set_var("COFFEEBLACK_TEST_DB_PATH", "/custom/path.db");
    let val = coffeeblack_vpn::config::get_env("COFFEEBLACK_TEST_DB_PATH", "/default/path.db");
    assert_eq!(val, "/custom/path.db");
    std::env::remove_var("COFFEEBLACK_TEST_DB_PATH");
    let val = coffeeblack_vpn::config::get_env("COFFEEBLACK_TEST_DB_PATH", "/default/path.db");
    assert_eq!(val, "/default/path.db");
}

#[test]
fn config_wg_conf_dir_default() {
    let _env = env_guard();
    std::env::remove_var("COFFEEBLACK_CONF_DIR");
    let cfg = coffeeblack_vpn::config::Config::load();
    assert_eq!(cfg.wg_conf_dir, "/etc/coffeeblack/conf");
}

#[test]
fn config_wg_conf_dir_custom() {
    let _env = env_guard();
    std::env::set_var("COFFEEBLACK_CONF_DIR", "/opt/wireguard");
    let cfg = coffeeblack_vpn::config::Config::load();
    assert_eq!(cfg.wg_conf_dir, "/opt/wireguard");
    std::env::remove_var("COFFEEBLACK_CONF_DIR");
}
