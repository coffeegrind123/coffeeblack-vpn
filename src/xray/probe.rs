//! Probe a candidate Reality `dest` with a real TLS 1.3 handshake.
//!
//! Reality's camouflage is only as good as the dest. The dest must:
//!
//! 1. Accept inbound TLS on the configured port (typically 443).
//! 2. Negotiate TLS 1.3 — Reality's TLS-in-TLS splicing relies on it.
//! 3. Present a valid certificate whose SAN matches the SNI coffeeblack-vpn
//!    will tell clients to send (`serverNames[0]`).
//! 4. Ideally support HTTP/2 in ALPN — that's what real CDN traffic
//!    looks like to a DPI box, so it's the more convincing fall-through.
//!
//! This module checks all four. The operator's "Probe" button hits
//! `POST /api/admin/xray/probe-dest`, the backend opens a single
//! socket to the dest, and the result is rendered inline.
//!
//! We deliberately use the Mozilla root store (via `webpki-roots`) for
//! verification — if the cert doesn't chain to a public CA, the dest is
//! either a private/self-signed endpoint (terrible camouflage) or a
//! known-bad CA (also terrible). Either way, reject.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use serde::Serialize;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

const PROBE_TIMEOUT: Duration = Duration::from_secs(7);

/// What the probe reports back to the UI / API caller.
#[derive(Debug, Clone, Serialize)]
pub struct ProbeReport {
    /// Did all hard checks pass? (TCP up + TLS 1.3 + SAN match + chain valid)
    pub ok: bool,
    /// `host:port` the probe connected to.
    pub dest: String,
    /// SNI the probe sent (== `serverNames[0]`).
    pub sni: String,
    /// Negotiated TLS version: `"1.3"`, `"1.2"`, etc.
    pub tls_version: String,
    /// Negotiated ALPN protocol (e.g. `"h2"`) or empty if none.
    pub alpn: String,
    /// Subject Alternative Names extracted from the leaf certificate.
    pub cert_sans: Vec<String>,
    /// True if any SAN (literal or wildcard) matches `sni`.
    pub sni_matches_san: bool,
    /// TCP+TLS handshake RTT in milliseconds.
    pub rtt_ms: u128,
    /// Soft warnings (e.g. "TLS 1.2 negotiated, expected 1.3"). When
    /// `ok` is true the operator can ignore these; when false, they
    /// explain why the probe rejected the dest.
    pub warnings: Vec<String>,
}

/// Run the probe. `dest` is what goes into `realitySettings.dest` —
/// either `host:port` or just `host` (defaulted to port 443). `sni`
/// is what clients will send (`serverNames[0]`).
pub async fn probe_dest(dest: &str, sni: &str) -> Result<ProbeReport> {
    let (host, port) = split_host_port(dest)?;
    let mut warnings: Vec<String> = Vec::new();

    // SSRF guard: resolve the dest ourselves and refuse any address in a
    // private / loopback / link-local / carrier-NAT / ULA / metadata range.
    // Without this the probe is a blind port/TLS scanner for the internal
    // network (and the cloud metadata endpoint), reachable over the same web
    // origin. We then connect to the *vetted* address — not by name — so a
    // DNS-rebinding host can't return a public IP for the check and a private
    // one for the connect.
    let addr = resolve_vetted_addr(&host, port).await?;

    let started = Instant::now();
    let tcp = timeout(PROBE_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow!("TCP connect to {host}:{port} timed out after {:?}", PROBE_TIMEOUT))?
        .with_context(|| format!("TCP connect to {host}:{port}"))?;

    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    // Advertise both — h2 is what real CDN-fronted sites negotiate, and
    // a dest that returns h2 makes for the most convincing camouflage.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(config));

    let server_name = ServerName::try_from(sni.to_string())
        .map_err(|e| anyhow!("invalid SNI {sni:?}: {e}"))?;

    let stream = timeout(PROBE_TIMEOUT, connector.connect(server_name, tcp))
        .await
        .map_err(|_| anyhow!("TLS handshake with {sni} timed out after {:?}", PROBE_TIMEOUT))?
        .with_context(|| format!("TLS handshake with {sni}"))?;
    let rtt_ms = started.elapsed().as_millis();

    let (_io, tls_conn) = stream.get_ref();
    let proto_version = tls_conn.protocol_version();
    let tls_version = match proto_version {
        Some(rustls::ProtocolVersion::TLSv1_3) => "1.3".to_string(),
        Some(rustls::ProtocolVersion::TLSv1_2) => "1.2".to_string(),
        Some(v) => format!("{v:?}"),
        None => "unknown".to_string(),
    };
    if proto_version != Some(rustls::ProtocolVersion::TLSv1_3) {
        warnings.push(format!(
            "Reality requires TLS 1.3 but {host} negotiated {tls_version}; pick another dest"
        ));
    }

    let alpn = tls_conn
        .alpn_protocol()
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .unwrap_or_default();
    if alpn.is_empty() {
        warnings.push("dest didn't agree to an ALPN protocol — camouflage will be weaker".into());
    } else if alpn != "h2" {
        warnings.push(format!(
            "dest negotiated ALPN {alpn:?}; modern CDN traffic looks like h2"
        ));
    }

    let mut sans: Vec<String> = Vec::new();
    if let Some(certs) = tls_conn.peer_certificates() {
        if let Some(leaf) = certs.first() {
            sans = extract_sans(leaf.as_ref()).unwrap_or_default();
        }
    }
    let sni_matches_san = sans.iter().any(|s| san_matches(s, sni));
    if !sni_matches_san {
        warnings.push(format!(
            "leaf cert SAN {sans:?} doesn't cover SNI {sni:?} — clients will fail TLS verification"
        ));
    }

    // Cleanly tear down so we don't leak a socket on the dest. Reality
    // hugs the connection lifecycle so half-closing is fine.
    let mut stream = stream;
    let _ = stream.shutdown().await;

    let ok = proto_version == Some(rustls::ProtocolVersion::TLSv1_3) && sni_matches_san;

    Ok(ProbeReport {
        ok,
        dest: format!("{host}:{port}"),
        sni: sni.to_string(),
        tls_version,
        alpn,
        cert_sans: sans,
        sni_matches_san,
        rtt_ms,
        warnings,
    })
}

/// Minimal DER TLV reader — just enough to walk an X.509 certificate to its
/// SubjectAlternativeName extension. Not a general ASN.1 parser: it handles
/// definite-length short/long form and single-byte tags, which is everything a
/// DER-encoded certificate uses (BER indefinite length is illegal in DER).
/// Replaces the `x509-parser` crate — and its `asn1-rs`/`der-parser`/`nom`/
/// `oid-registry` subtree — for our single need: reading dNSName SANs.
///
/// Returns `(tag, value, rest)` where `rest` is the bytes following this whole
/// TLV, or `None` on truncated/malformed input.
fn read_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, after_tag) = input.split_first()?;
    let (&len_byte, after_len_byte) = after_tag.split_first()?;
    let (len, body) = if len_byte < 0x80 {
        // Short form: length is the byte itself.
        (len_byte as usize, after_len_byte)
    } else {
        // Long form: low 7 bits give the number of subsequent length bytes.
        // 0x80 (indefinite) is illegal in DER; cap at 4 bytes (>4 GiB is absurd
        // for a cert and would risk usize overflow on 32-bit).
        let num = (len_byte & 0x7f) as usize;
        if num == 0 || num > 4 || after_len_byte.len() < num {
            return None;
        }
        let (len_bytes, rest) = after_len_byte.split_at(num);
        let mut len = 0usize;
        for &b in len_bytes {
            len = (len << 8) | b as usize;
        }
        (len, rest)
    };
    if body.len() < len {
        return None;
    }
    let (value, rest) = body.split_at(len);
    Some((tag, value, rest))
}

/// Pull SANs out of a DER-encoded certificate. Returns dNSName entries
/// (the only kind Reality cares about); we silently drop other GeneralName
/// variants like rfc822Name or iPAddress.
///
/// Structure walked (RFC 5280):
///   Certificate ::= SEQUENCE { tbsCertificate, sigAlg, sigValue }
///   TBSCertificate ::= SEQUENCE { version[0], serial, ..., extensions[3] }
///   Extensions ::= SEQUENCE OF Extension
///   Extension ::= SEQUENCE { extnID OID, critical BOOLEAN?, extnValue OCTETSTRING }
///   SAN extnValue wraps GeneralNames ::= SEQUENCE OF GeneralName
///   dNSName is context tag [2] IMPLICIT IA5String → DER tag 0x82.
fn extract_sans(der: &[u8]) -> Result<Vec<String>> {
    // 2.5.29.17 encoded as OID content bytes (the 0x06/len header is stripped
    // by read_tlv): 2*40+5 = 0x55, 29 = 0x1d, 17 = 0x11.
    const SAN_OID: &[u8] = &[0x55, 0x1d, 0x11];

    let (cert_tag, cert_body, _) =
        read_tlv(der).ok_or_else(|| anyhow!("parse leaf cert: not a TLV"))?;
    if cert_tag != 0x30 {
        return Err(anyhow!("parse leaf cert: expected SEQUENCE"));
    }
    let (tbs_tag, tbs, _) =
        read_tlv(cert_body).ok_or_else(|| anyhow!("parse leaf cert: missing TBSCertificate"))?;
    if tbs_tag != 0x30 {
        return Err(anyhow!("parse leaf cert: TBSCertificate not a SEQUENCE"));
    }

    // Scan TBS children for the [3] EXPLICIT extensions wrapper (0xA3).
    let mut cur = tbs;
    let ext_wrapper = loop {
        let Some((t, v, rest)) = read_tlv(cur) else {
            return Ok(Vec::new()); // no extensions field at all
        };
        if t == 0xA3 {
            break v;
        }
        cur = rest;
    };
    // [3] wraps a single SEQUENCE OF Extension.
    let (seq_tag, extensions, _) =
        read_tlv(ext_wrapper).ok_or_else(|| anyhow!("parse leaf cert: bad extensions"))?;
    if seq_tag != 0x30 {
        return Err(anyhow!("parse leaf cert: extensions not a SEQUENCE"));
    }

    let mut cur = extensions;
    while let Some((ext_tag, ext, rest)) = read_tlv(cur) {
        cur = rest;
        if ext_tag != 0x30 {
            continue;
        }
        let Some((oid_tag, oid, after_oid)) = read_tlv(ext) else {
            continue;
        };
        if oid_tag != 0x06 || oid != SAN_OID {
            continue;
        }
        // Reach extnValue, skipping the optional critical BOOLEAN.
        let (mut vtag, mut val, mut vrest) =
            read_tlv(after_oid).ok_or_else(|| anyhow!("parse leaf cert: SAN missing extnValue"))?;
        if vtag == 0x01 {
            (vtag, val, vrest) = read_tlv(vrest)
                .ok_or_else(|| anyhow!("parse leaf cert: SAN extnValue after critical"))?;
        }
        let _ = vrest;
        if vtag != 0x04 {
            return Err(anyhow!("parse leaf cert: SAN extnValue not an OCTET STRING"));
        }
        // OCTET STRING wraps the GeneralNames SEQUENCE.
        let (gn_tag, general_names, _) =
            read_tlv(val).ok_or_else(|| anyhow!("parse leaf cert: bad GeneralNames"))?;
        if gn_tag != 0x30 {
            return Err(anyhow!("parse leaf cert: GeneralNames not a SEQUENCE"));
        }
        let mut out = Vec::new();
        let mut gcur = general_names;
        while let Some((name_tag, name, grest)) = read_tlv(gcur) {
            gcur = grest;
            // dNSName [2] IMPLICIT IA5String. IA5 is ASCII; from_utf8_lossy is
            // safe — a non-ASCII dNSName is malformed and we'd reject the SNI
            // match anyway.
            if name_tag == 0x82 {
                out.push(String::from_utf8_lossy(name).into_owned());
            }
        }
        return Ok(out);
    }
    Ok(Vec::new()) // no SAN extension present
}

/// SAN matches SNI by RFC 6125: literal equality OR a leading `*.`
/// wildcard whose suffix matches everything from the first dot onward.
fn san_matches(san: &str, sni: &str) -> bool {
    let san = san.to_ascii_lowercase();
    let sni = sni.to_ascii_lowercase();
    if san == sni {
        return true;
    }
    if let Some(wildcard_suffix) = san.strip_prefix("*.") {
        // *.example.com matches foo.example.com but NOT example.com or foo.bar.example.com.
        if let Some((_, rest)) = sni.split_once('.') {
            return rest == wildcard_suffix;
        }
    }
    false
}

fn split_host_port(dest: &str) -> Result<(String, u16)> {
    if let Some((h, p)) = dest.rsplit_once(':') {
        // Bracketed IPv6 literal like [::1]:443.
        let host = h.trim_start_matches('[').trim_end_matches(']');
        let port: u16 = p.parse().map_err(|_| anyhow!("invalid port {p:?} in dest"))?;
        Ok((host.to_string(), port))
    } else {
        Ok((dest.to_string(), 443))
    }
}

/// True if `ip` is in a range the probe must never connect to: it would turn
/// the admin "Probe" button into an internal-network / cloud-metadata scanner.
/// Covers loopback, private (RFC1918), link-local (incl. 169.254.169.254
/// metadata), carrier-grade NAT, unspecified/broadcast/documentation for v4;
/// loopback, unspecified, unique-local (fc00::/7), link-local (fe80::/10),
/// multicast, and IPv4-mapped (unwrapped and re-checked) for v6.
pub(crate) fn is_forbidden_ip(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                // Carrier-grade NAT 100.64.0.0/10 and 0.0.0.0/8.
                || matches!(v4.octets(), [100, b, ..] if (64..=127).contains(&b))
                || v4.octets()[0] == 0
        }
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_forbidden_ip(IpAddr::V4(mapped));
            }
            let seg = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // Unique-local fc00::/7.
                || (seg[0] & 0xfe00) == 0xfc00
                // Link-local fe80::/10.
                || (seg[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Resolve `host:port` and return a single address that passed the SSRF vet.
/// Rejects if resolution yields nothing, or if ANY resolved address is
/// forbidden (a host that resolves to both a public and a private address is
/// treated as hostile — the classic rebinding split).
async fn resolve_vetted_addr(host: &str, port: u16) -> Result<std::net::SocketAddr> {
    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("resolve {host}:{port}"))?
        .collect();
    if addrs.is_empty() {
        return Err(anyhow!("{host}:{port} did not resolve to any address"));
    }
    if let Some(bad) = addrs.iter().find(|a| is_forbidden_ip(a.ip())) {
        return Err(anyhow!(
            "refusing to probe {host}:{port}: resolves to a private/reserved \
             address ({}) — dest must be a public host",
            bad.ip()
        ));
    }
    Ok(addrs[0])
}

/// Curated list of dest candidates that are reachable from most
/// jurisdictions, terminate TLS 1.3, present long-lived public CA
/// chains, and look like organic CDN traffic. Surfaced in the admin
/// UI as a dropdown.
pub fn curated_candidates() -> &'static [&'static str] {
    &[
        "www.microsoft.com",
        "www.cloudflare.com",
        "www.bing.com",
        "www.cisco.com",
        "www.akamai.com",
        "www.apple.com",
        "learn.microsoft.com",
        "azure.microsoft.com",
        // Deliberately omit GitHub-related infra — intermittently
        // blocked from some jurisdictions per operator reports.
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn ssrf_guard_blocks_internal_ranges() {
        for bad in [
            "127.0.0.1",       // loopback
            "10.0.0.5",        // RFC1918
            "192.168.1.1",     // RFC1918
            "172.16.0.1",      // RFC1918
            "169.254.169.254", // link-local / cloud metadata
            "100.64.0.1",      // CGNAT
            "0.0.0.0",         // unspecified / 0.0.0.0/8
            "::1",             // v6 loopback
            "fe80::1",         // v6 link-local
            "fc00::1",         // v6 unique-local
            "::ffff:10.0.0.1", // v4-mapped private
        ] {
            let ip: IpAddr = bad.parse().unwrap();
            assert!(is_forbidden_ip(ip), "must block {bad}");
        }
    }

    #[test]
    fn ssrf_guard_allows_public() {
        for ok in ["1.1.1.1", "8.8.8.8", "93.184.216.34", "2606:4700:4700::1111"] {
            let ip: IpAddr = ok.parse().unwrap();
            assert!(!is_forbidden_ip(ip), "must allow {ok}");
        }
    }

    #[test]
    fn split_host_port_default() {
        assert_eq!(split_host_port("foo.com").unwrap(), ("foo.com".into(), 443));
    }

    #[test]
    fn split_host_port_explicit() {
        assert_eq!(
            split_host_port("foo.com:8443").unwrap(),
            ("foo.com".into(), 8443)
        );
    }

    #[test]
    fn split_host_port_ipv6_bracketed() {
        let (h, p) = split_host_port("[::1]:443").unwrap();
        assert_eq!(h, "::1");
        assert_eq!(p, 443);
    }

    #[test]
    fn san_matches_literal() {
        assert!(san_matches("www.microsoft.com", "www.microsoft.com"));
        assert!(san_matches("WWW.MICROSOFT.COM", "www.microsoft.com"));
        assert!(!san_matches("www.microsoft.com", "microsoft.com"));
    }

    #[test]
    fn extract_sans_reads_dns_names_from_real_cert() {
        // Generate a genuine DER cert with rcgen (already a dependency) so the
        // hand-rolled DER walk is tested against a real-world encoder, not a
        // hand-crafted fixture.
        let ck = rcgen::generate_simple_self_signed(vec![
            "example.com".to_string(),
            "*.example.com".to_string(),
            "learn.microsoft.com".to_string(),
        ])
        .unwrap();
        let der = ck.cert.der();
        let mut sans = extract_sans(der.as_ref()).unwrap();
        sans.sort();
        assert_eq!(
            sans,
            vec![
                "*.example.com".to_string(),
                "example.com".to_string(),
                "learn.microsoft.com".to_string(),
            ]
        );
    }

    #[test]
    fn extract_sans_empty_on_garbage() {
        // A non-SEQUENCE first byte must error, not panic.
        assert!(extract_sans(&[0x02, 0x01, 0x00]).is_err());
        // Truncated length must be handled gracefully.
        assert!(read_tlv(&[0x30, 0x82, 0x00]).is_none());
    }

    #[test]
    fn san_matches_wildcard() {
        assert!(san_matches("*.microsoft.com", "www.microsoft.com"));
        assert!(san_matches("*.microsoft.com", "learn.microsoft.com"));
        // Wildcard must not match the apex.
        assert!(!san_matches("*.microsoft.com", "microsoft.com"));
        // Wildcard is single-level only per RFC 6125.
        assert!(!san_matches("*.microsoft.com", "a.b.microsoft.com"));
    }

    /// Live network test against a known-good public dest. Marked
    /// `#[ignore]` so CI without internet access doesn't fail — run
    /// with `cargo test -- --ignored` for the e2e check.
    #[tokio::test]
    #[ignore = "requires network access to www.microsoft.com:443"]
    async fn probe_microsoft_succeeds() {
        let report = probe_dest("www.microsoft.com:443", "www.microsoft.com").await.unwrap();
        assert!(report.ok, "report not ok: {report:?}");
        assert_eq!(report.tls_version, "1.3");
        assert!(report.sni_matches_san);
        assert!(report.rtt_ms > 0 && report.rtt_ms < 5000);
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn probe_rejects_san_mismatch() {
        // Connect to microsoft.com but send a SNI it doesn't cover —
        // microsoft.com's leaf cert SANs are .microsoft-curated, not
        // example.invalid.
        let res = probe_dest("www.microsoft.com:443", "example.invalid").await;
        // Either the handshake fails (server rejects unknown SNI) or
        // the report comes back ok=false. Both are acceptable rejection
        // signals — the probe must not silently pass.
        // A handshake error is also a valid rejection signal; we only need to
        // ensure that a *successful* probe reports ok=false.
        if let Ok(r) = res {
            assert!(!r.ok);
        }
    }
}
