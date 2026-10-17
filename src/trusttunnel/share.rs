//! Per-user share artefacts: the `tt://` deep link (and its QR), and the
//! flat client-config TOML `trusttunnel_endpoint -c <user> --format toml`
//! prints, which `TrustTunnelClient`'s `setup_wizard --endpoint_config`
//! imports.
//!
//! ## Addresses
//!
//! A link carries a list of `host:port` addresses the client may dial, and
//! a separate `hostname` used for SNI and certificate checks. We list the
//! host's public IPs first, then the host name itself when it is one:
//!
//! * IPs first, because pmnezia-client's Android path runs the static
//!   `trusttunnel_client` binary with no `/etc/resolv.conf` to resolve with.
//! * The name last, so a client that can resolve still finds the server
//!   after its IP changes.

use std::fmt::Write as _;
use std::net::IpAddr;

use anyhow::{bail, Result};

use crate::db::{TrustTunnelInbound, TrustTunnelUser};
use crate::trusttunnel::config::{effective_hostname, json_list};
use crate::trusttunnel::deeplink::{self, UpstreamProtocol};
use crate::trusttunnel::cert;

/// Everything share builders need beyond the two DB rows.
#[derive(Debug, Clone)]
pub struct Context<'a> {
    /// The General tab's public host (name or IP).
    pub host: &'a str,
    /// Public IPs `host` resolves to (empty when it is an IP already).
    pub resolved: &'a [IpAddr],
}

/// `host:port`, bracketing IPv6.
fn join_host_port(host: &str, port: i64) -> String {
    let bare = host.trim().trim_start_matches('[').trim_end_matches(']');
    match bare.parse::<IpAddr>() {
        Ok(IpAddr::V6(v6)) => format!("[{v6}]:{port}"),
        Ok(IpAddr::V4(v4)) => format!("{v4}:{port}"),
        Err(_) => format!("{bare}:{port}"),
    }
}

/// Ordered, de-duplicated dial list. See the module docs.
pub fn addresses(inbound: &TrustTunnelInbound, ctx: &Context<'_>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |a: String| {
        if !out.contains(&a) {
            out.push(a);
        }
    };
    let host = ctx.host.trim();
    let host_is_ip = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .is_ok();
    if host_is_ip {
        push(join_host_port(host, inbound.port));
    }
    for ip in ctx.resolved {
        push(join_host_port(&ip.to_string(), inbound.port));
    }
    if !host_is_ip && !host.is_empty() {
        push(join_host_port(host, inbound.port));
    }
    out
}

/// DER chain for the link, or `None` when public roots already verify it.
fn link_certificate(inbound: &TrustTunnelInbound, hostname: &str) -> Result<Option<Vec<u8>>> {
    if inbound.tls_chain_pem.trim().is_empty() {
        bail!("the TrustTunnel endpoint has no TLS certificate yet — enable it or generate one");
    }
    if cert::ca_trusted(&inbound.tls_chain_pem, hostname) {
        return Ok(None);
    }
    Ok(Some(cert::chain_der(&inbound.tls_chain_pem)?))
}

fn upstream(inbound: &TrustTunnelInbound) -> UpstreamProtocol {
    UpstreamProtocol::parse(&inbound.upstream_protocol).unwrap_or(UpstreamProtocol::Http2)
}

/// The `tt://?…` link for one user.
pub fn build_link(
    inbound: &TrustTunnelInbound,
    user: &TrustTunnelUser,
    ctx: &Context<'_>,
) -> Result<String> {
    let hostname = effective_hostname(inbound, ctx.host)?;
    let addrs = addresses(inbound, ctx);
    let der = link_certificate(inbound, &hostname)?;
    let dns = json_list(&inbound.dns_upstreams);
    let custom_sni = inbound.custom_sni.trim();
    let prefix = user.client_random_prefix.trim();
    deeplink::encode(&deeplink::Endpoint {
        hostname: &hostname,
        addresses: &addrs,
        custom_sni: (!custom_sni.is_empty()).then_some(custom_sni),
        has_ipv6: inbound.ipv6_available,
        username: &user.username,
        password: &user.password,
        skip_verification: false,
        certificate_der: der.as_deref(),
        upstream_protocol: upstream(inbound),
        anti_dpi: inbound.anti_dpi,
        client_random_prefix: (!prefix.is_empty()).then_some(prefix),
        name: Some(user.name.as_str()),
        dns_upstreams: &dns,
    })
}

fn toml_string(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into())
}

fn toml_array(items: &[String]) -> String {
    let parts: Vec<String> = items.iter().map(|s| toml_string(s)).collect();
    format!("[{}]", parts.join(", "))
}

/// The flat client config, same keys and order as upstream's
/// `ClientConfig::compose_toml`. `certificate` is `""` when public roots
/// verify the chain, else the PEM chain.
pub fn build_client_toml(
    inbound: &TrustTunnelInbound,
    user: &TrustTunnelUser,
    ctx: &Context<'_>,
) -> Result<String> {
    let hostname = effective_hostname(inbound, ctx.host)?;
    let certificate = match link_certificate(inbound, &hostname)? {
        Some(_) => inbound.tls_chain_pem.trim_end().to_string() + "\n",
        None => String::new(),
    };
    let mut b = String::new();
    writeln!(b, "# TrustTunnel client endpoint config for '{}', generated by coffeeblack-vpn.", user.name)?;
    writeln!(b, "# Import with: setup_wizard --endpoint_config <this file>")?;
    writeln!(b)?;
    writeln!(b, "hostname = {}", toml_string(&hostname))?;
    writeln!(b, "addresses = {}", toml_array(&addresses(inbound, ctx)))?;
    writeln!(b, "custom_sni = {}", toml_string(inbound.custom_sni.trim()))?;
    writeln!(b, "has_ipv6 = {}", inbound.ipv6_available)?;
    writeln!(b, "username = {}", toml_string(&user.username))?;
    writeln!(b, "password = {}", toml_string(&user.password))?;
    writeln!(b, "client_random_prefix = {}", toml_string(user.client_random_prefix.trim()))?;
    writeln!(b, "skip_verification = false")?;
    writeln!(b, "certificate = {}", toml_string(&certificate))?;
    writeln!(b, "upstream_protocol = {}", toml_string(upstream(inbound).as_str()))?;
    writeln!(b, "anti_dpi = {}", inbound.anti_dpi)?;
    writeln!(b, "name = {}", toml_string(&user.name))?;
    let dns = json_list(&inbound.dns_upstreams);
    if !dns.is_empty() {
        writeln!(b, "dns_upstreams = {}", toml_array(&dns))?;
    }
    Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64ct::{Base64UrlUnpadded, Encoding as _};

    fn inbound(chain_pem: String) -> TrustTunnelInbound {
        TrustTunnelInbound {
            id: "trusttunnel0".into(),
            port: 8443,
            listen_http1: false,
            listen_http2: true,
            listen_quic: true,
            hostname: "tt.example.net".into(),
            allowed_sni: "[]".into(),
            custom_sni: String::new(),
            upstream_protocol: "http3".into(),
            anti_dpi: true,
            ipv6_available: false,
            allow_private_network: false,
            auth_failure_status_code: 407,
            reverse_proxy_address: String::new(),
            reverse_proxy_path_mask: String::new(),
            require_client_random_prefix: false,
            icmp_enabled: false,
            icmp_interface: String::new(),
            dns_upstreams: r#"["1.1.1.1"]"#.into(),
            max_http2_conns: 0,
            max_http3_conns: 0,
            metrics_port: 1987,
            tls_mode: "self_signed".into(),
            tls_chain_pem: chain_pem,
            tls_key_pem: String::new(),
            tls_cert_hostname: "tt.example.net".into(),
            additional_config: String::new(),
            enabled: true,
            created_at: "n".into(),
            updated_at: "n".into(),
        }
    }

    fn user() -> TrustTunnelUser {
        TrustTunnelUser {
            id: 7,
            user_id: None,
            name: "Alice phone".into(),
            username: "alice-phone".into(),
            password: "PASSWORDpassword0123456789abcdef".into(),
            client_random_prefix: "a0b0c0d0/f0f0f0f0".into(),
            expires_at: None,
            enabled: true,
            created_at: "n".into(),
            updated_at: "n".into(),
        }
    }

    #[test]
    fn addresses_put_ips_before_the_name() {
        let ib = inbound(String::new());
        let ips: Vec<IpAddr> = vec!["203.0.113.5".parse().unwrap(), "2001:db8::5".parse().unwrap()];
        let ctx = Context { host: "vpn.example.com", resolved: &ips };
        assert_eq!(
            addresses(&ib, &ctx),
            vec!["203.0.113.5:8443", "[2001:db8::5]:8443", "vpn.example.com:8443"]
        );
        let ctx = Context { host: "198.51.100.7", resolved: &[] };
        assert_eq!(addresses(&ib, &ctx), vec!["198.51.100.7:8443"]);
    }

    #[test]
    fn self_signed_link_embeds_the_chain_and_user_fields() {
        let m = cert::self_signed("tt.example.net").unwrap();
        let ib = inbound(m.chain_pem.clone());
        let ctx = Context { host: "198.51.100.7", resolved: &[] };
        let link = build_link(&ib, &user(), &ctx).unwrap();
        let payload = Base64UrlUnpadded::decode_vec(link.strip_prefix("tt://?").unwrap()).unwrap();
        assert_eq!(&payload[..3], &[0x00, 0x01, 0x01], "version 1");
        let der = cert::chain_der(&m.chain_pem).unwrap();
        assert!(payload.windows(der.len()).any(|w| w == der.as_slice()), "chain embedded");
        for needle in [&b"tt.example.net"[..], b"alice-phone", b"a0b0c0d0/f0f0f0f0", b"Alice phone"] {
            assert!(payload.windows(needle.len()).any(|w| w == needle));
        }
        // http3, anti-DPI and has_ipv6=false are all non-default, so present.
        assert!(payload.windows(3).any(|w| w == [0x09, 0x01, 0x02]));
        assert!(payload.windows(3).any(|w| w == [0x0a, 0x01, 0x01]));
        assert!(payload.windows(3).any(|w| w == [0x04, 0x01, 0x00]));
    }

    #[test]
    fn link_needs_a_certificate() {
        let ib = inbound(String::new());
        let ctx = Context { host: "198.51.100.7", resolved: &[] };
        assert!(build_link(&ib, &user(), &ctx).is_err());
    }

    #[test]
    fn client_toml_parses_with_upstream_keys() {
        let m = cert::self_signed("tt.example.net").unwrap();
        let ib = inbound(m.chain_pem.clone());
        let ctx = Context { host: "198.51.100.7", resolved: &[] };
        let body = build_client_toml(&ib, &user(), &ctx).unwrap();
        let v: toml::Value = toml::from_str(&body).unwrap();
        assert_eq!(v["hostname"].as_str(), Some("tt.example.net"));
        assert_eq!(v["addresses"][0].as_str(), Some("198.51.100.7:8443"));
        assert_eq!(v["upstream_protocol"].as_str(), Some("http3"));
        assert_eq!(v["has_ipv6"].as_bool(), Some(false));
        assert!(v["certificate"].as_str().unwrap().contains("BEGIN CERTIFICATE"));
        assert_eq!(v["dns_upstreams"][0].as_str(), Some("1.1.1.1"));
        for key in ["custom_sni", "username", "password", "client_random_prefix", "skip_verification", "anti_dpi", "name"] {
            assert!(v.get(key).is_some(), "{key}");
        }
    }
}
