//! Translate the persisted [`db::QqdnsSettings`] singleton + the AmneziaWG
//! interface row into a runtime [`EngineConfig`], and decide whether the
//! transport should run at all.

use std::time::Duration;

use anyhow::{anyhow, Result};

use crate::db;
use crate::qqdns::engine::EngineConfig;

/// Parse a JSON string array column into `Vec<String>`, dropping blanks.
fn parse_json_list(s: &str) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(s)
        .unwrap_or_default()
        .into_iter()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .collect()
}

/// The AmneziaWG loopback target decoded traffic is delivered to. `0` in the
/// settings means "the interface's own ListenPort".
pub fn effective_awg_target(settings: &db::QqdnsSettings, iface_port: i64) -> i64 {
    if settings.awg_target_port != 0 {
        settings.awg_target_port
    } else {
        iface_port
    }
}

/// Reason we'd refuse to run — surfaced verbatim to the admin UI. `None`
/// means "good to go".
pub fn should_remain_disabled(
    settings: &db::QqdnsSettings,
    iface: &db::Interface,
) -> Option<String> {
    if !settings.enabled {
        return Some("QQ-DNS transport is disabled in admin settings".to_string());
    }
    if !iface.enabled {
        return Some("AmneziaWG interface is disabled".to_string());
    }
    if parse_json_list(&settings.dns_ips).is_empty() {
        return Some("no resolvers configured (dns_ips is empty)".to_string());
    }
    if parse_json_list(&settings.send_domains).is_empty() {
        return Some("no send_domains configured (the client's delegated domain)".to_string());
    }
    if parse_json_list(&settings.recv_domains).is_empty() {
        return Some("no recv_domains configured (this server's delegated domain)".to_string());
    }
    if crate::qqdns::dns::split_host_port(&settings.h_in_address).is_none() {
        return Some(format!(
            "h_in_address '{}' is not host:port",
            settings.h_in_address
        ));
    }
    if !(1..=65535).contains(&settings.receive_port) {
        return Some(format!("receive_port {} out of range", settings.receive_port));
    }
    let target = effective_awg_target(settings, iface.port);
    if !(1..=65535).contains(&target) {
        return Some(format!("awg_target_port {target} out of range"));
    }
    if settings.max_domain_len < 20 || settings.max_domain_len > 253 {
        return Some(format!(
            "max_domain_len {} out of range (20..=253)",
            settings.max_domain_len
        ));
    }
    if settings.max_sub_len < 1 || settings.max_sub_len > 63 {
        return Some(format!(
            "max_sub_len {} out of range (1..=63)",
            settings.max_sub_len
        ));
    }
    if settings.send_sock_numbers < 1 {
        return Some("send_sock_numbers must be >= 1".to_string());
    }
    None
}

/// Build the runtime [`EngineConfig`] from DB state. The server always runs
/// in the fixed-target role: decoded traffic is delivered to the AmneziaWG
/// loopback socket, and only replies from it are re-encoded.
pub fn build_engine_config(
    settings: &db::QqdnsSettings,
    iface: &db::Interface,
) -> Result<EngineConfig> {
    if let Some(reason) = should_remain_disabled(settings, iface) {
        return Err(anyhow!(reason));
    }
    let target = effective_awg_target(settings, iface.port);
    let send_interface_ip = if settings.send_interface_ip.trim().is_empty() {
        "0.0.0.0".to_string()
    } else {
        settings.send_interface_ip.trim().to_string()
    };

    Ok(EngineConfig {
        dns_ips: parse_json_list(&settings.dns_ips),
        send_interface_ip,
        receive_interface_ip: settings.receive_interface_ip.trim().to_string(),
        receive_port: settings.receive_port as u16,
        send_domains: parse_json_list(&settings.send_domains),
        recv_domains: parse_json_list(&settings.recv_domains),
        h_in_address: settings.h_in_address.trim().to_string(),
        // Server role: fixed AmneziaWG loopback target.
        h_out_address: Some(format!("127.0.0.1:{target}")),
        max_domain_len: settings.max_domain_len as usize,
        max_sub_len: settings.max_sub_len as usize,
        retries: settings.retries.max(0) as usize,
        send_query_type: settings.send_query_type as u16,
        packets_send_interval: Duration::from_millis(settings.packets_send_interval_ms.max(0) as u64),
        packets_wait_time_limit: Duration::from_millis(
            settings.packets_wait_time_limit_ms.max(1) as u64,
        ),
        send_sock_numbers: settings.send_sock_numbers as usize,
    })
}

/// A stable hash of the inputs that define a running engine — lets the
/// supervisor skip a teardown/rebind when nothing material changed.
pub fn config_signature(cfg: &EngineConfig) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    cfg.dns_ips.hash(&mut h);
    cfg.send_interface_ip.hash(&mut h);
    cfg.receive_interface_ip.hash(&mut h);
    cfg.receive_port.hash(&mut h);
    cfg.send_domains.hash(&mut h);
    cfg.recv_domains.hash(&mut h);
    cfg.h_in_address.hash(&mut h);
    cfg.h_out_address.hash(&mut h);
    cfg.max_domain_len.hash(&mut h);
    cfg.max_sub_len.hash(&mut h);
    cfg.retries.hash(&mut h);
    cfg.send_query_type.hash(&mut h);
    cfg.packets_send_interval.hash(&mut h);
    cfg.packets_wait_time_limit.hash(&mut h);
    cfg.send_sock_numbers.hash(&mut h);
    h.finish()
}
