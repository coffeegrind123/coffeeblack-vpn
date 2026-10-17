//! `tt://` deep-link encoder — the import format every TrustTunnel client
//! (the official Flutter apps, the C++ CLI's `setup_wizard --deeplink`,
//! Shadowrocket, pmnezia-client) accepts.
//!
//! Wire format, from upstream `deeplink/src/{encode,varint,types}.rs` at
//! v1.1.0 (the source, not `DEEP_LINK.md` — that document's worked example
//! predates the version TLV and its tag order is wrong):
//!
//! ```text
//! tt://?<base64url, no padding>(payload)
//!
//! payload = TLV*          TLV = varint(tag) ‖ varint(len) ‖ value
//! varint  = RFC 9000 §16: 1/2/4/8 bytes, top two bits = length class
//!
//!  tag  field               value
//!  0x00 version             varint (always 1 here — see below)
//!  0x01 hostname            utf-8; TLS SNI + certificate name
//!  0x02 address             utf-8 "host:port"; one TLV per address
//!  0x03 custom_sni          utf-8
//!  0x04 has_ipv6            1 byte bool — emitted only when false
//!  0x05 username            utf-8
//!  0x06 password            utf-8
//!  0x07 skip_verification   1 byte bool — emitted only when true
//!  0x08 certificate         concatenated DER of the chain
//!  0x09 upstream_protocol   1 byte: 0x01 http2, 0x02 http3 — emitted only for http3
//!  0x0A anti_dpi            1 byte bool — emitted only when true
//!  0x0B client_random_prefix utf-8 "hex[/hexmask]"
//!  0x0C name                utf-8 display name
//!  0x0D dns_upstreams       ‖(varint(len) ‖ utf-8) per entry
//! ```
//!
//! Emission order is upstream's, not tag order, so a link this module makes
//! is byte-identical to `trusttunnel_endpoint -c <user> --format deeplink`
//! for the same inputs. Decoders do not care about order, but identical
//! bytes make "does our link match theirs?" a string comparison.
//!
//! **Version 1, deliberately.** v1.3.0-beta moved to version 2 (adding
//! `subscription_url` / `client_random_auth_key`), and a v1-era decoder
//! rejects any link whose version exceeds its own. Every field this server
//! emits exists in v1, so v1 is readable by every client in the field.

use anyhow::{bail, Result};
use base64ct::{Base64UrlUnpadded, Encoding as _};

/// Deep-link format version this encoder emits.
pub const VERSION: u64 = 1;

/// URI prefix. Decoders also accept the legacy `tt://` without `?`; we
/// only ever produce the current form.
pub const SCHEME_PREFIX: &str = "tt://?";

mod tag {
    pub const VERSION: u64 = 0x00;
    pub const HOSTNAME: u64 = 0x01;
    pub const ADDRESS: u64 = 0x02;
    pub const CUSTOM_SNI: u64 = 0x03;
    pub const HAS_IPV6: u64 = 0x04;
    pub const USERNAME: u64 = 0x05;
    pub const PASSWORD: u64 = 0x06;
    pub const SKIP_VERIFICATION: u64 = 0x07;
    pub const CERTIFICATE: u64 = 0x08;
    pub const UPSTREAM_PROTOCOL: u64 = 0x09;
    pub const ANTI_DPI: u64 = 0x0A;
    pub const CLIENT_RANDOM_PREFIX: u64 = 0x0B;
    pub const NAME: u64 = 0x0C;
    pub const DNS_UPSTREAMS: u64 = 0x0D;
}

/// Transport the client opens to the endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamProtocol {
    Http2,
    Http3,
}

impl UpstreamProtocol {
    /// Name used in the endpoint's TOML client config and our DB column.
    pub fn as_str(self) -> &'static str {
        match self {
            UpstreamProtocol::Http2 => "http2",
            UpstreamProtocol::Http3 => "http3",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "http2" => Some(UpstreamProtocol::Http2),
            "http3" => Some(UpstreamProtocol::Http3),
            _ => None,
        }
    }

    fn wire(self) -> u8 {
        match self {
            UpstreamProtocol::Http2 => 0x01,
            UpstreamProtocol::Http3 => 0x02,
        }
    }
}

/// Everything a client needs to reach one endpoint as one user.
#[derive(Debug, Clone)]
pub struct Endpoint<'a> {
    pub hostname: &'a str,
    pub addresses: &'a [String],
    pub custom_sni: Option<&'a str>,
    pub has_ipv6: bool,
    pub username: &'a str,
    pub password: &'a str,
    pub skip_verification: bool,
    /// Concatenated DER of the chain. `None` when the chain verifies
    /// against public roots and clients should use their system store.
    pub certificate_der: Option<&'a [u8]>,
    pub upstream_protocol: UpstreamProtocol,
    pub anti_dpi: bool,
    pub client_random_prefix: Option<&'a str>,
    pub name: Option<&'a str>,
    pub dns_upstreams: &'a [String],
}

/// RFC 9000 §16 variable-length integer.
fn put_varint(v: u64, out: &mut Vec<u8>) -> Result<()> {
    if v <= 0x3f {
        out.push(v as u8);
    } else if v <= 0x3fff {
        out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes());
    } else if v <= 0x3fff_ffff {
        out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes());
    } else if v <= 0x3fff_ffff_ffff_ffff {
        out.extend_from_slice(&(v | 0xc000_0000_0000_0000).to_be_bytes());
    } else {
        bail!("value {v} does not fit an RFC 9000 varint");
    }
    Ok(())
}

fn put_tlv(tag: u64, value: &[u8], out: &mut Vec<u8>) -> Result<()> {
    put_varint(tag, out)?;
    put_varint(value.len() as u64, out)?;
    out.extend_from_slice(value);
    Ok(())
}

/// Serialise the TLV payload (no scheme, no base64).
pub fn payload(ep: &Endpoint<'_>) -> Result<Vec<u8>> {
    // Upstream's `validate()` — a decoder rejects a link missing any of
    // these, so refuse to mint one.
    if ep.hostname.is_empty() {
        bail!("deep link needs a hostname");
    }
    if ep.username.is_empty() || ep.password.is_empty() {
        bail!("deep link needs a username and password");
    }
    if ep.addresses.is_empty() {
        bail!("deep link needs at least one address");
    }

    let mut out = Vec::with_capacity(256);
    let mut version = Vec::with_capacity(1);
    put_varint(VERSION, &mut version)?;
    put_tlv(tag::VERSION, &version, &mut out)?;
    put_tlv(tag::HOSTNAME, ep.hostname.as_bytes(), &mut out)?;
    put_tlv(tag::USERNAME, ep.username.as_bytes(), &mut out)?;
    put_tlv(tag::PASSWORD, ep.password.as_bytes(), &mut out)?;
    for addr in ep.addresses {
        put_tlv(tag::ADDRESS, addr.as_bytes(), &mut out)?;
    }
    if let Some(prefix) = ep.client_random_prefix.filter(|p| !p.is_empty()) {
        put_tlv(tag::CLIENT_RANDOM_PREFIX, prefix.as_bytes(), &mut out)?;
    }
    if let Some(sni) = ep.custom_sni.filter(|s| !s.is_empty()) {
        put_tlv(tag::CUSTOM_SNI, sni.as_bytes(), &mut out)?;
    }
    // Booleans and the protocol byte are only written when they differ from
    // the decoder's default (has_ipv6 = true, the rest false, http2).
    if !ep.has_ipv6 {
        put_tlv(tag::HAS_IPV6, &[0], &mut out)?;
    }
    if ep.skip_verification {
        put_tlv(tag::SKIP_VERIFICATION, &[1], &mut out)?;
    }
    if ep.anti_dpi {
        put_tlv(tag::ANTI_DPI, &[1], &mut out)?;
    }
    if let Some(der) = ep.certificate_der.filter(|d| !d.is_empty()) {
        put_tlv(tag::CERTIFICATE, der, &mut out)?;
    }
    if ep.upstream_protocol == UpstreamProtocol::Http3 {
        put_tlv(tag::UPSTREAM_PROTOCOL, &[ep.upstream_protocol.wire()], &mut out)?;
    }
    if let Some(name) = ep.name.filter(|n| !n.is_empty()) {
        put_tlv(tag::NAME, name.as_bytes(), &mut out)?;
    }
    if !ep.dns_upstreams.is_empty() {
        let mut list = Vec::new();
        for dns in ep.dns_upstreams {
            put_varint(dns.len() as u64, &mut list)?;
            list.extend_from_slice(dns.as_bytes());
        }
        put_tlv(tag::DNS_UPSTREAMS, &list, &mut out)?;
    }
    Ok(out)
}

/// Build the full `tt://?…` link.
pub fn encode(ep: &Endpoint<'_>) -> Result<String> {
    let bytes = payload(ep)?;
    Ok(format!("{SCHEME_PREFIX}{}", Base64UrlUnpadded::encode_string(&bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basic<'a>(addresses: &'a [String], dns: &'a [String]) -> Endpoint<'a> {
        Endpoint {
            hostname: "vpn.example.com",
            addresses,
            custom_sni: None,
            has_ipv6: true,
            username: "alice",
            password: "secret123",
            skip_verification: false,
            certificate_der: None,
            upstream_protocol: UpstreamProtocol::Http2,
            anti_dpi: false,
            client_random_prefix: None,
            name: None,
            dns_upstreams: dns,
        }
    }

    // Both vectors were produced by upstream's own reference encoder,
    // `scripts/config_to_deeplink.py` at v1.1.0, which upstream's
    // `deeplink/tests/python_compat.rs` holds byte-identical to the Rust
    // crate.

    #[test]
    fn matches_upstream_vector_minimal() {
        let addrs = vec!["1.2.3.4:443".to_string()];
        let link = encode(&basic(&addrs, &[])).unwrap();
        assert_eq!(
            link,
            "tt://?AAEBAQ92cG4uZXhhbXBsZS5jb20FBWFsaWNlBglzZWNyZXQxMjMCCzEuMi4zLjQ6NDQz"
        );
    }

    #[test]
    fn matches_upstream_vector_full() {
        let addrs = vec!["192.168.1.1:8443".to_string(), "10.0.0.1:443".to_string()];
        let dns = vec!["1.1.1.1".to_string(), "tls://dns.example.com".to_string()];
        let ep = Endpoint {
            hostname: "secure.vpn.example.com",
            addresses: &addrs,
            custom_sni: Some("cdn.example.org"),
            has_ipv6: false,
            username: "premium_user",
            password: "very_secret_password",
            skip_verification: false,
            certificate_der: None,
            upstream_protocol: UpstreamProtocol::Http3,
            anti_dpi: true,
            client_random_prefix: None,
            name: Some("My VPN"),
            dns_upstreams: &dns,
        };
        assert_eq!(
            encode(&ep).unwrap(),
            "tt://?AAEBARZzZWN1cmUudnBuLmV4YW1wbGUuY29tBQxwcmVtaXVtX3VzZXIGFHZlcnlfc2VjcmV0X3Bh\
             c3N3b3JkAhAxOTIuMTY4LjEuMTo4NDQzAgwxMC4wLjAuMTo0NDMDD2Nkbi5leGFtcGxlLm9yZwQBAAoB\
             AQkBAgwGTXkgVlBODR4HMS4xLjEuMRV0bHM6Ly9kbnMuZXhhbXBsZS5jb20"
        );
    }

    #[test]
    fn varint_boundaries_follow_rfc9000() {
        let cases: &[(u64, &[u8])] = &[
            (0, &[0x00]),
            (63, &[0x3f]),
            (64, &[0x40, 0x40]),
            (16383, &[0x7f, 0xff]),
            (16384, &[0x80, 0x00, 0x40, 0x00]),
            (1_073_741_823, &[0xbf, 0xff, 0xff, 0xff]),
            (1_073_741_824, &[0xc0, 0, 0, 0, 0x40, 0, 0, 0]),
        ];
        for (v, want) in cases {
            let mut out = Vec::new();
            put_varint(*v, &mut out).unwrap();
            assert_eq!(&out, want, "varint({v})");
        }
        assert!(put_varint(u64::MAX, &mut Vec::new()).is_err());
    }

    #[test]
    fn certificate_uses_a_two_byte_length_when_large() {
        let addrs = vec!["1.2.3.4:443".to_string()];
        let der = vec![0xabu8; 600];
        let mut ep = basic(&addrs, &[]);
        ep.certificate_der = Some(&der);
        let bytes = payload(&ep).unwrap();
        let pos = bytes
            .windows(3)
            .position(|w| w == [0x08, 0x42, 0x58])
            .expect("tag 0x08 with varint(600) = 0x4258");
        assert_eq!(&bytes[pos + 3..pos + 3 + 600], der.as_slice());
    }

    #[test]
    fn prefix_is_emitted_after_addresses_and_before_sni() {
        let addrs = vec!["1.2.3.4:443".to_string()];
        let mut ep = basic(&addrs, &[]);
        ep.client_random_prefix = Some("a0b0/f0f0");
        ep.custom_sni = Some("cdn.example.org");
        let bytes = payload(&ep).unwrap();
        let addr = bytes.windows(2).position(|w| w == [0x02, 11]).unwrap();
        let prefix = bytes.windows(2).position(|w| w == [0x0b, 9]).unwrap();
        let sni = bytes.windows(2).position(|w| w == [0x03, 15]).unwrap();
        assert!(addr < prefix && prefix < sni);
    }

    #[test]
    fn refuses_links_a_decoder_would_reject() {
        let addrs = vec!["1.2.3.4:443".to_string()];
        let mut ep = basic(&addrs, &[]);
        ep.password = "";
        assert!(encode(&ep).is_err());
        let ep = basic(&[], &[]);
        assert!(encode(&ep).is_err());
    }
}
