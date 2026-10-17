//! Render the four files `trusttunnel_endpoint` reads.
//!
//! ```text
//! <trusttunnel_dir>/
//!   vpn.toml          listener, protocols, limits, metrics — positional arg 1
//!   hosts.toml        [[main_hosts]] hostname + cert paths — positional arg 2
//!   credentials.toml  one [[client]] per active user  (vpn.toml credentials_file)
//!   rules.toml        client-random-prefix allow rules (vpn.toml rules_file)
//!   tls/chain.pem     certificate chain               (hosts.toml)
//!   tls/key.pem       private key                     (hosts.toml)
//! ```
//!
//! Pure functions over the DB rows; the supervisor writes the results with
//! `secretfile::write_atomic`. Three upstream behaviours shape the output,
//! all read from `lib/src/settings.rs` at v1.1.0:
//!
//! * **Paths resolve against the process CWD** and must already exist, so
//!   every path written here is absolute.
//! * **`credentials.toml` values are not TOML-decoded.** Upstream reads them
//!   as `x["username"].to_string()` and strips every `"` — escapes, literal
//!   strings and inline comments all come through mangled. [`validate_username`]
//!   and [`validate_password`] restrict both to characters that survive that
//!   unchanged, so the credentials the endpoint checks are the ones we issue.
//! * **No `deny_unknown_fields`.** A misspelt key is silently ignored, so the
//!   key names below are pinned by tests against upstream's spelling.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Result};

use crate::db::{TrustTunnelInbound, TrustTunnelUser};

pub const VPN_FILE: &str = "vpn.toml";
pub const HOSTS_FILE: &str = "hosts.toml";
pub const CREDENTIALS_FILE: &str = "credentials.toml";
pub const RULES_FILE: &str = "rules.toml";
pub const TLS_DIR: &str = "tls";
pub const CHAIN_FILE: &str = "chain.pem";
pub const KEY_FILE: &str = "key.pem";

/// Status codes upstream accepts for `auth_failure_status_code`.
pub const AUTH_FAILURE_CODES: &[i64] = &[407, 405, 404, 403];

/// Username alphabet. Usernames also appear as Prometheus label values on
/// the metrics listener, which this alphabet needs no escaping for.
pub const USERNAME_MAX: usize = 64;
pub const PASSWORD_MIN: usize = 16;
pub const PASSWORD_MAX: usize = 128;

/// Absolute paths of every rendered file under one runtime dir.
#[derive(Debug, Clone)]
pub struct Paths {
    pub vpn: PathBuf,
    pub hosts: PathBuf,
    pub credentials: PathBuf,
    pub rules: PathBuf,
    pub tls_dir: PathBuf,
    pub chain: PathBuf,
    pub key: PathBuf,
}

impl Paths {
    pub fn new(dir: &Path) -> Self {
        let tls_dir = dir.join(TLS_DIR);
        Paths {
            vpn: dir.join(VPN_FILE),
            hosts: dir.join(HOSTS_FILE),
            credentials: dir.join(CREDENTIALS_FILE),
            rules: dir.join(RULES_FILE),
            chain: tls_dir.join(CHAIN_FILE),
            key: tls_dir.join(KEY_FILE),
            tls_dir,
        }
    }
}

/// Basic TOML string. Every value we emit is validated ASCII without
/// control characters, but escape anyway so a future caller cannot break
/// out of the string.
fn toml_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04X}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn path_string(p: &Path) -> Result<String> {
    let s = p
        .to_str()
        .ok_or_else(|| anyhow!("path {} is not valid UTF-8", p.display()))?;
    if !p.is_absolute() {
        bail!("path {s} must be absolute (the endpoint resolves relative paths against its CWD)");
    }
    Ok(toml_string(s))
}

pub fn validate_username(s: &str) -> Result<()> {
    if s.is_empty() || s.len() > USERNAME_MAX {
        bail!("username must be 1-{USERNAME_MAX} characters");
    }
    if !s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')) {
        bail!("username may only contain A-Z a-z 0-9 . _ -");
    }
    Ok(())
}

pub fn validate_password(s: &str) -> Result<()> {
    if s.len() < PASSWORD_MIN || s.len() > PASSWORD_MAX {
        bail!("password must be {PASSWORD_MIN}-{PASSWORD_MAX} characters");
    }
    // Printable ASCII minus space, `"`, `'`, `\` and `#`: the endpoint strips
    // quotes and does not decode escapes, and `#` / `'` change how its TOML
    // parser tokenises the line before the strip happens.
    if !s
        .bytes()
        .all(|b| b.is_ascii_graphic() && !matches!(b, b'"' | b'\'' | b'\\' | b'#'))
    {
        bail!("password may not contain spaces, quotes, backslashes or '#'");
    }
    Ok(())
}

/// `hex` or `hex/hexmask`, as `rules.toml` and the deep link carry it.
pub fn validate_client_random_prefix(s: &str) -> Result<()> {
    if s.is_empty() {
        return Ok(());
    }
    let (prefix, mask) = match s.split_once('/') {
        Some((p, m)) => (p, Some(m)),
        None => (s, None),
    };
    let is_hex = |h: &str| !h.is_empty() && h.len().is_multiple_of(2) && h.bytes().all(|b| b.is_ascii_hexdigit());
    if !is_hex(prefix) || prefix.len() > 64 {
        bail!("client random prefix must be an even-length hex string of at most 32 bytes");
    }
    if let Some(mask) = mask {
        if !is_hex(mask) || mask.len() != prefix.len() {
            bail!("client random mask must be hex of the same length as the prefix");
        }
    }
    Ok(())
}

/// A DNS name usable as `main_hosts` hostname / TLS SNI.
pub fn validate_hostname(s: &str) -> Result<()> {
    if s.is_empty() || s.len() > 253 {
        bail!("hostname must be 1-253 characters");
    }
    if s.parse::<std::net::IpAddr>().is_ok() {
        bail!("hostname must be a DNS name, not an IP address (TLS SNI cannot carry an IP)");
    }
    let label_ok = |l: &str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    };
    if !s.split('.').all(label_ok) || !s.contains('.') {
        bail!("'{s}' is not a valid DNS name");
    }
    Ok(())
}

/// The TLS hostname actually served: the inbound's own, else the General
/// tab host when that is a DNS name.
pub fn effective_hostname(inbound: &TrustTunnelInbound, host: &str) -> Result<String> {
    let own = inbound.hostname.trim();
    if !own.is_empty() {
        validate_hostname(own)?;
        return Ok(own.to_ascii_lowercase());
    }
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() || host.parse::<std::net::IpAddr>().is_ok() {
        bail!(
            "TrustTunnel needs a TLS hostname: the General tab host is {}, so set one on the \
             TrustTunnel tab (any DNS name works with the self-signed certificate)",
            if host.is_empty() { "unset" } else { "an IP address" }
        );
    }
    validate_hostname(host)?;
    Ok(host.to_ascii_lowercase())
}

/// Parse a JSON array-of-strings column; malformed or absent is empty.
pub fn json_list(s: &str) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(s)
        .unwrap_or_default()
        .into_iter()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .collect()
}

/// Enabled and not past `expires_at` (an unparsable expiry counts as none,
/// matching `wg::cron_job`).
pub fn is_active(user: &TrustTunnelUser, now: time::OffsetDateTime) -> bool {
    if !user.enabled {
        return false;
    }
    match user.expires_at.as_deref().filter(|e| !e.trim().is_empty()) {
        Some(exp) => crate::datetime::parse_expiry(exp).is_none_or(|t| now <= t),
        None => true,
    }
}

/// Inbound settings that would make the endpoint refuse to start or that
/// the API must reject.
pub fn validate(inbound: &TrustTunnelInbound) -> Result<()> {
    if !(1..=65535).contains(&inbound.port) {
        bail!("port must be 1-65535");
    }
    if !(inbound.listen_http1 || inbound.listen_http2 || inbound.listen_quic) {
        bail!("enable at least one of HTTP/1.1, HTTP/2 or HTTP/3 (QUIC)");
    }
    match inbound.upstream_protocol.as_str() {
        "http2" if !inbound.listen_http2 => {
            bail!("share links use HTTP/2 but the HTTP/2 listener is off")
        }
        "http3" if !inbound.listen_quic => {
            bail!("share links use HTTP/3 but the QUIC listener is off")
        }
        "http2" | "http3" => {}
        other => bail!("upstream protocol must be http2 or http3, not '{other}'"),
    }
    if !AUTH_FAILURE_CODES.contains(&inbound.auth_failure_status_code) {
        bail!("auth failure status code must be one of 407, 405, 404, 403");
    }
    for sni in json_list(&inbound.allowed_sni) {
        validate_hostname(&sni)?;
    }
    let custom = inbound.custom_sni.trim();
    if !custom.is_empty() {
        validate_hostname(custom)?;
        if !json_list(&inbound.allowed_sni).iter().any(|s| s.eq_ignore_ascii_case(custom)) {
            bail!("custom SNI '{custom}' must also be listed in allowed SNIs");
        }
    }
    let rp_addr = inbound.reverse_proxy_address.trim();
    let rp_mask = inbound.reverse_proxy_path_mask.trim();
    if rp_addr.is_empty() != rp_mask.is_empty() {
        bail!("the cover-site reverse proxy needs both an address and a path prefix");
    }
    if !rp_addr.is_empty() {
        rp_addr
            .parse::<std::net::SocketAddr>()
            .map_err(|_| anyhow!("reverse proxy address must be ip:port, not '{rp_addr}'"))?;
        if !rp_mask.starts_with('/') {
            bail!("reverse proxy path prefix must start with '/'");
        }
    }
    if !(1..=65535).contains(&inbound.metrics_port) {
        bail!("metrics port must be 1-65535");
    }
    if inbound.max_http2_conns < 0 || inbound.max_http3_conns < 0 {
        bail!("connection limits cannot be negative");
    }
    let iface = inbound.icmp_interface.trim();
    if !iface.is_empty()
        && (iface.len() > 15
            || !iface.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'@')))
    {
        bail!("ICMP interface '{iface}' is not a valid Linux interface name");
    }
    match inbound.tls_mode.as_str() {
        "self_signed" | "custom" => {}
        other => bail!("TLS mode must be self_signed or custom, not '{other}'"),
    }
    Ok(())
}

/// `vpn.toml`. `icmp_interface` is the resolved interface (the caller fills
/// in the default-route interface when the inbound leaves it blank).
pub fn generate_vpn(
    inbound: &TrustTunnelInbound,
    paths: &Paths,
    ipv6_listen: bool,
    icmp_interface: Option<&str>,
) -> Result<String> {
    validate(inbound)?;
    let mut b = String::new();
    writeln!(b, "# Generated by coffeeblack-vpn — do NOT edit by hand.")?;
    writeln!(b, "# Users live in trusttunnel_users_table; see credentials.toml.")?;
    b.push('\n');

    // `[::]` is dual-stack (upstream clears IPV6_V6ONLY); a host with IPv6
    // disabled cannot bind it at all, hence the switch.
    let listen = if ipv6_listen {
        format!("[::]:{}", inbound.port)
    } else {
        format!("0.0.0.0:{}", inbound.port)
    };
    writeln!(b, "listen_address = {}", toml_string(&listen))?;
    writeln!(b, "ipv6_available = {}", inbound.ipv6_available)?;
    writeln!(
        b,
        "allow_private_network_connections = {}",
        inbound.allow_private_network
    )?;
    writeln!(b, "credentials_file = {}", path_string(&paths.credentials)?)?;
    writeln!(b, "rules_file = {}", path_string(&paths.rules)?)?;
    writeln!(b, "auth_failure_status_code = {}", inbound.auth_failure_status_code)?;
    if inbound.max_http2_conns > 0 {
        writeln!(b, "default_max_http2_conns_per_client = {}", inbound.max_http2_conns)?;
    }
    if inbound.max_http3_conns > 0 {
        writeln!(b, "default_max_http3_conns_per_client = {}", inbound.max_http3_conns)?;
    }

    // Spliced before the first table header so operator top-level keys land
    // at the top level; any [section] it opens is closed by ours below.
    let extra = inbound.additional_config.trim();
    if !extra.is_empty() {
        b.push('\n');
        writeln!(b, "# --- additional_config (operator-supplied) ---")?;
        writeln!(b, "{extra}")?;
        writeln!(b, "# --- end additional_config ---")?;
    }

    // Empty sub-tables enable a protocol with upstream defaults.
    b.push('\n');
    writeln!(b, "[listen_protocols]")?;
    if inbound.listen_http1 {
        writeln!(b, "[listen_protocols.http1]")?;
    }
    if inbound.listen_http2 {
        writeln!(b, "[listen_protocols.http2]")?;
    }
    if inbound.listen_quic {
        writeln!(b, "[listen_protocols.quic]")?;
    }

    let rp_addr = inbound.reverse_proxy_address.trim();
    if !rp_addr.is_empty() {
        b.push('\n');
        writeln!(b, "[reverse_proxy]")?;
        writeln!(b, "server_address = {}", toml_string(rp_addr))?;
        writeln!(b, "path_mask = {}", toml_string(inbound.reverse_proxy_path_mask.trim()))?;
    }

    if inbound.icmp_enabled {
        let iface = icmp_interface
            .filter(|i| !i.is_empty())
            .ok_or_else(|| anyhow!("ICMP forwarding is on but no egress interface was found"))?;
        b.push('\n');
        writeln!(b, "[icmp]")?;
        writeln!(b, "interface_name = {}", toml_string(iface))?;
    }

    // Always on, loopback only: the supervisor polls /clients for per-user
    // traffic and /health-check for liveness.
    b.push('\n');
    writeln!(b, "[metrics]")?;
    writeln!(
        b,
        "address = {}",
        toml_string(&format!("127.0.0.1:{}", inbound.metrics_port))
    )?;
    writeln!(b, "per_client_metrics = true")?;
    Ok(b)
}

/// `hosts.toml` — one main host for `hostname`, with every allowed SNI.
pub fn generate_hosts(inbound: &TrustTunnelInbound, hostname: &str, paths: &Paths) -> Result<String> {
    validate_hostname(hostname)?;
    let mut b = String::new();
    writeln!(b, "# Generated by coffeeblack-vpn — do NOT edit by hand.")?;
    writeln!(b, "[[main_hosts]]")?;
    writeln!(b, "hostname = {}", toml_string(hostname))?;
    writeln!(b, "cert_chain_path = {}", path_string(&paths.chain)?)?;
    writeln!(b, "private_key_path = {}", path_string(&paths.key)?)?;
    let snis: Vec<String> = json_list(&inbound.allowed_sni)
        .into_iter()
        .map(|s| s.to_ascii_lowercase())
        .filter(|s| s != hostname)
        .collect();
    let list: Vec<String> = snis.iter().map(|s| toml_string(s)).collect();
    writeln!(b, "allowed_sni = [{}]", list.join(", "))?;
    Ok(b)
}

/// `credentials.toml` for every active user. Errors on a user the endpoint
/// would misread rather than writing a credential that silently differs.
pub fn generate_credentials(users: &[TrustTunnelUser], now: time::OffsetDateTime) -> Result<String> {
    let mut b = String::new();
    writeln!(b, "# Generated by coffeeblack-vpn — do NOT edit by hand.")?;
    for u in users.iter().filter(|u| is_active(u, now)) {
        validate_username(&u.username)
            .map_err(|e| anyhow!("TrustTunnel user #{}: {e}", u.id))?;
        validate_password(&u.password)
            .map_err(|e| anyhow!("TrustTunnel user '{}': {e}", u.username))?;
        b.push('\n');
        writeln!(b, "[[client]]")?;
        writeln!(b, "username = {}", toml_string(&u.username))?;
        writeln!(b, "password = {}", toml_string(&u.password))?;
    }
    Ok(b)
}

/// `rules.toml`. Upstream evaluates rules first-match-wins against the TLS
/// ClientHello and allows anything unmatched (`lib/src/rules.rs`), so each
/// user's client-random prefix becomes an allow rule and `require_prefix`
/// appends a match-everything deny after them. Upstream also denies a
/// ClientHello with no client random outright once any prefix rule exists.
pub fn generate_rules(
    users: &[TrustTunnelUser],
    now: time::OffsetDateTime,
    require_prefix: bool,
) -> Result<String> {
    let mut b = String::new();
    writeln!(b, "# Generated by coffeeblack-vpn — do NOT edit by hand.")?;
    for u in users.iter().filter(|u| is_active(u, now)) {
        let prefix = u.client_random_prefix.trim();
        if prefix.is_empty() {
            continue;
        }
        validate_client_random_prefix(prefix)?;
        b.push('\n');
        writeln!(b, "# {}", u.username)?;
        writeln!(b, "[[rule]]")?;
        writeln!(b, "client_random_prefix = {}", toml_string(prefix))?;
        writeln!(b, "action = \"allow\"")?;
    }
    if require_prefix {
        b.push('\n');
        writeln!(b, "# require_client_random_prefix: everything else is dropped")?;
        writeln!(b, "[[rule]]")?;
        writeln!(b, "action = \"deny\"")?;
    }
    Ok(b)
}

/// Inbound + roster combinations that would lock every user out.
pub fn validate_roster(inbound: &TrustTunnelInbound, users: &[TrustTunnelUser], now: time::OffsetDateTime) -> Result<()> {
    if inbound.require_client_random_prefix
        && users
            .iter()
            .filter(|u| is_active(u, now))
            .any(|u| u.client_random_prefix.trim().is_empty())
    {
        bail!(
            "\"require client-random prefix\" is on, but an active user has no prefix — \
             that user could never connect; give every user a prefix first"
        );
    }
    Ok(())
}

/// Interface carrying the IPv4 default route, from `/proc/net/route`
/// (`Iface Destination Gateway ...`, destination `00000000` = default).
pub fn default_route_interface() -> Option<String> {
    let text = std::fs::read_to_string("/proc/net/route").ok()?;
    parse_default_route(&text)
}

fn parse_default_route(text: &str) -> Option<String> {
    text.lines().skip(1).find_map(|line| {
        let mut cols = line.split_whitespace();
        let iface = cols.next()?;
        let dest = cols.next()?;
        (dest == "00000000").then(|| iface.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inbound() -> TrustTunnelInbound {
        TrustTunnelInbound {
            id: "trusttunnel0".into(),
            port: 8443,
            listen_http1: false,
            listen_http2: true,
            listen_quic: true,
            hostname: "tt.example.net".into(),
            allowed_sni: "[]".into(),
            custom_sni: String::new(),
            upstream_protocol: "http2".into(),
            anti_dpi: false,
            ipv6_available: true,
            allow_private_network: false,
            auth_failure_status_code: 407,
            reverse_proxy_address: String::new(),
            reverse_proxy_path_mask: String::new(),
            require_client_random_prefix: false,
            icmp_enabled: false,
            icmp_interface: String::new(),
            dns_upstreams: "[]".into(),
            max_http2_conns: 0,
            max_http3_conns: 0,
            metrics_port: 1987,
            tls_mode: "self_signed".into(),
            tls_chain_pem: String::new(),
            tls_key_pem: String::new(),
            tls_cert_hostname: String::new(),
            additional_config: String::new(),
            enabled: true,
            created_at: "n".into(),
            updated_at: "n".into(),
        }
    }

    fn user(name: &str, enabled: bool, expires: Option<&str>) -> TrustTunnelUser {
        TrustTunnelUser {
            id: 1,
            user_id: None,
            name: name.into(),
            username: name.into(),
            password: "abcdefghijklmnop1234".into(),
            client_random_prefix: String::new(),
            expires_at: expires.map(String::from),
            enabled,
            created_at: "n".into(),
            updated_at: "n".into(),
        }
    }

    fn paths() -> Paths {
        Paths::new(Path::new("/etc/coffeeblack/conf/trusttunnel"))
    }

    fn now() -> time::OffsetDateTime {
        crate::datetime::parse_expiry("2026-10-18T00:00:00Z").unwrap()
    }

    #[test]
    fn vpn_toml_parses_and_uses_upstream_key_names() {
        let body = generate_vpn(&inbound(), &paths(), true, None).unwrap();
        let v: toml::Value = toml::from_str(&body).expect("valid TOML");
        assert_eq!(v["listen_address"].as_str(), Some("[::]:8443"));
        assert_eq!(
            v["credentials_file"].as_str(),
            Some("/etc/coffeeblack/conf/trusttunnel/credentials.toml")
        );
        assert_eq!(v["rules_file"].as_str(), Some("/etc/coffeeblack/conf/trusttunnel/rules.toml"));
        assert_eq!(v["auth_failure_status_code"].as_integer(), Some(407));
        assert_eq!(v["allow_private_network_connections"].as_bool(), Some(false));
        let lp = v["listen_protocols"].as_table().unwrap();
        assert!(lp.contains_key("http2") && lp.contains_key("quic") && !lp.contains_key("http1"));
        assert_eq!(v["metrics"]["address"].as_str(), Some("127.0.0.1:1987"));
        assert_eq!(v["metrics"]["per_client_metrics"].as_bool(), Some(true));
        assert!(v.get("icmp").is_none() && v.get("reverse_proxy").is_none());
        assert!(v.get("default_max_http2_conns_per_client").is_none());
    }

    #[test]
    fn ipv4_only_listen_when_ipv6_is_off() {
        let body = generate_vpn(&inbound(), &paths(), false, None).unwrap();
        assert!(body.contains("listen_address = \"0.0.0.0:8443\""));
    }

    #[test]
    fn optional_sections_render_when_set() {
        let mut ib = inbound();
        ib.reverse_proxy_address = "127.0.0.1:8080".into();
        ib.reverse_proxy_path_mask = "/site".into();
        ib.icmp_enabled = true;
        ib.max_http2_conns = 16;
        let body = generate_vpn(&ib, &paths(), true, Some("ens3")).unwrap();
        let v: toml::Value = toml::from_str(&body).unwrap();
        assert_eq!(v["reverse_proxy"]["server_address"].as_str(), Some("127.0.0.1:8080"));
        assert_eq!(v["reverse_proxy"]["path_mask"].as_str(), Some("/site"));
        assert_eq!(v["icmp"]["interface_name"].as_str(), Some("ens3"));
        assert_eq!(v["default_max_http2_conns_per_client"].as_integer(), Some(16));
        assert!(generate_vpn(&ib, &paths(), true, None).is_err(), "ICMP with no interface");
    }

    #[test]
    fn additional_config_lands_at_top_level() {
        let mut ib = inbound();
        ib.additional_config = "speedtest_enable = true".into();
        let v: toml::Value = toml::from_str(&generate_vpn(&ib, &paths(), true, None).unwrap()).unwrap();
        assert_eq!(v["speedtest_enable"].as_bool(), Some(true));
        assert!(v["listen_protocols"].get("speedtest_enable").is_none());
    }

    #[test]
    fn hosts_toml_points_at_absolute_cert_paths() {
        let mut ib = inbound();
        ib.allowed_sni = r#"["cdn.example.org","TT.example.net"]"#.into();
        let body = generate_hosts(&ib, "tt.example.net", &paths()).unwrap();
        let v: toml::Value = toml::from_str(&body).unwrap();
        let host = &v["main_hosts"][0];
        assert_eq!(host["hostname"].as_str(), Some("tt.example.net"));
        assert_eq!(
            host["cert_chain_path"].as_str(),
            Some("/etc/coffeeblack/conf/trusttunnel/tls/chain.pem")
        );
        assert_eq!(host["private_key_path"].as_str(), Some("/etc/coffeeblack/conf/trusttunnel/tls/key.pem"));
        let snis: Vec<&str> = host["allowed_sni"].as_array().unwrap().iter().map(|s| s.as_str().unwrap()).collect();
        assert_eq!(snis, vec!["cdn.example.org"], "the main hostname is not repeated");
    }

    #[test]
    fn credentials_hold_only_active_users() {
        let users = vec![
            user("alice", true, None),
            user("bob", false, None),
            user("carol", true, Some("2026-01-01T00:00")),
            user("dave", true, Some("2027-01-01T00:00:00Z")),
        ];
        let body = generate_credentials(&users, now()).unwrap();
        let v: toml::Value = toml::from_str(&body).unwrap();
        let names: Vec<&str> = v["client"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["username"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["alice", "dave"]);
    }

    #[test]
    fn credentials_survive_upstreams_quote_stripping_parser() {
        // Upstream: demangle_toml_string(x["password"].to_string()) ==
        // to_string().replace('"', "").trim(). Model it and require a
        // round trip for a generated-shape password.
        let mut u = user("alice", true, None);
        u.password = "A-b_c.d~e!f@g$h%i^j&k*l(m)n+o=p".into();
        let body = generate_credentials(&[u.clone()], now()).unwrap();
        let v: toml::Value = toml::from_str(&body).unwrap();
        let raw = v["client"][0]["password"].to_string();
        assert_eq!(raw.replace('"', "").trim(), u.password);
    }

    #[test]
    fn mangling_credentials_are_refused() {
        for bad in ["has space in it!!!!", "quote\"inside1234567", "back\\slash123456789", "hash#comment12345678", "apos'trophe123456789"] {
            assert!(validate_password(bad).is_err(), "{bad}");
        }
        assert!(validate_password("short").is_err());
        assert!(validate_username("a b").is_err());
        assert!(validate_username("").is_err());
        assert!(validate_username("user.name-1_x").is_ok());
        let mut u = user("alice", true, None);
        u.password = "has space in it!!!!".into();
        assert!(generate_credentials(&[u], now()).is_err());
    }

    #[test]
    fn rules_carry_prefixes_of_active_users() {
        let mut a = user("alice", true, None);
        a.client_random_prefix = "a0b0/f0f0".into();
        let mut b = user("bob", false, None);
        b.client_random_prefix = "c0d0".into();
        let users = [a, b];
        let v: toml::Value = toml::from_str(&generate_rules(&users, now(), false).unwrap()).unwrap();
        let rules = v["rule"].as_array().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["client_random_prefix"].as_str(), Some("a0b0/f0f0"));
        assert_eq!(rules[0]["action"].as_str(), Some("allow"));
        let empty: toml::Value = toml::from_str(&generate_rules(&[], now(), false).unwrap()).unwrap();
        assert!(empty.get("rule").is_none());

        // The gate: allow rules first, then one bare deny that matches all.
        let v: toml::Value = toml::from_str(&generate_rules(&users, now(), true).unwrap()).unwrap();
        let rules = v["rule"].as_array().unwrap();
        assert_eq!(rules.len(), 2);
        let last = rules[1].as_table().unwrap();
        assert_eq!(last.get("action").and_then(|a| a.as_str()), Some("deny"));
        assert!(!last.contains_key("cidr") && !last.contains_key("client_random_prefix"));
    }

    #[test]
    fn prefix_gate_refuses_users_without_a_prefix() {
        let mut ib = inbound();
        ib.require_client_random_prefix = true;
        let mut with = user("alice", true, None);
        with.client_random_prefix = "a0b0".into();
        let without = user("bob", true, None);
        assert!(validate_roster(&ib, &[with.clone()], now()).is_ok());
        assert!(validate_roster(&ib, &[with, without.clone()], now()).is_err());
        ib.require_client_random_prefix = false;
        assert!(validate_roster(&ib, &[without], now()).is_ok());
    }

    #[test]
    fn prefix_validation() {
        assert!(validate_client_random_prefix("").is_ok());
        assert!(validate_client_random_prefix("a0b0").is_ok());
        assert!(validate_client_random_prefix("a0b0/f0f0").is_ok());
        assert!(validate_client_random_prefix("a0b").is_err());
        assert!(validate_client_random_prefix("a0b0/f0").is_err());
        assert!(validate_client_random_prefix("zz").is_err());
    }

    #[test]
    fn inbound_validation_catches_unstartable_configs() {
        let mut ib = inbound();
        ib.listen_http2 = false;
        assert!(validate(&ib).unwrap_err().to_string().contains("HTTP/2"));
        ib.listen_quic = false;
        assert!(validate(&ib).is_err());

        let mut ib = inbound();
        ib.custom_sni = "cdn.example.org".into();
        assert!(validate(&ib).is_err(), "custom SNI not in allowed list");
        ib.allowed_sni = r#"["cdn.example.org"]"#.into();
        assert!(validate(&ib).is_ok());

        let mut ib = inbound();
        ib.auth_failure_status_code = 500;
        assert!(validate(&ib).is_err());

        let mut ib = inbound();
        ib.reverse_proxy_address = "example.com:80".into();
        ib.reverse_proxy_path_mask = "/x".into();
        assert!(validate(&ib).is_err(), "upstream needs a SocketAddr");
        ib.reverse_proxy_address = "127.0.0.1:80".into();
        ib.reverse_proxy_path_mask = String::new();
        assert!(validate(&ib).is_err(), "address without path");
    }

    #[test]
    fn hostname_resolution() {
        let mut ib = inbound();
        assert_eq!(effective_hostname(&ib, "1.2.3.4").unwrap(), "tt.example.net");
        ib.hostname = String::new();
        assert_eq!(effective_hostname(&ib, "VPN.Example.com").unwrap(), "vpn.example.com");
        assert!(effective_hostname(&ib, "1.2.3.4").is_err());
        assert!(effective_hostname(&ib, "").is_err());
        assert!(validate_hostname("not_a_name.com").is_err());
        assert!(validate_hostname("localhost").is_err());
    }

    #[test]
    fn default_route_is_found_in_proc_net_route() {
        let table = "Iface\tDestination\tGateway\tFlags\n\
                     docker0\t000011AC\t00000000\t0001\n\
                     ens3\t00000000\t0101A8C0\t0003\n";
        assert_eq!(parse_default_route(table).as_deref(), Some("ens3"));
        assert_eq!(parse_default_route("Iface\tDestination\n"), None);
    }
}
