//! Byte-exact port of QQ-Tunnel's `utility/dns.py`.
//!
//! Minimal DNS message handling: build a query carrying a data-bearing
//! QNAME, parse an inbound query far enough to recover its labels, and
//! synthesise the NOERROR / empty-answer response the authoritative side
//! always returns (the tunnel never carries payload in DNS *answers* — data
//! flows one-way in the QNAME of queries in each direction).

use std::net::SocketAddr;

/// RFC 1035 caps a complete domain name at 255 octets including the length
/// bytes. Enforcing it bounds what one datagram can allocate here.
const MAX_QNAME_TOTAL_LEN: usize = 255;

/// Port of `label_domain`: split a domain into its non-empty labels
/// (lowercased, trailing/leading dots stripped).
pub fn label_domain(domain: &[u8]) -> Vec<Vec<u8>> {
    domain
        .split(|&b| b == b'.')
        .filter(|l| !l.is_empty())
        .map(|l| l.to_ascii_lowercase())
        .collect()
}

/// Port of `encode_qname`: wire-encode a domain as length-prefixed labels
/// terminated by a zero byte.
pub fn encode_qname(domain: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(domain.len() + 2);
    for label in domain.split(|&b| b == b'.') {
        if !label.is_empty() {
            out.push(label.len() as u8);
            out.extend_from_slice(label);
        }
    }
    out.push(0);
    out
}

/// Port of `insert_dots`: chunk `data` into ≤`max_sub` byte labels, each
/// length-prefixed — i.e. the DNS-label encoding of the data portion of a
/// QNAME (no terminating zero; the send-domain QNAME is appended after).
pub fn insert_dots(data: &[u8], max_sub: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / max_sub + 1);
    let mut i = 0;
    while i < data.len() {
        let end = (i + max_sub).min(data.len());
        let seg = &data[i..end];
        out.push(seg.len() as u8);
        out.extend_from_slice(seg);
        i = end;
    }
    out
}

/// Port of `build_dns_query`. `qname_encoded` must be wire-encoded and end
/// in a zero byte. Produces a standard recursion-desired A/AAAA/… query.
pub fn build_dns_query(qname_encoded: &[u8], q_id: u16, qtype: u16) -> Vec<u8> {
    debug_assert!(
        qname_encoded.last() == Some(&0),
        "qname_encoded must end with a null byte"
    );
    let mut msg = Vec::with_capacity(12 + qname_encoded.len() + 4);
    // Header: ID, flags(RD), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0.
    msg.extend_from_slice(&q_id.to_be_bytes());
    msg.extend_from_slice(&0x0100u16.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    // Question: QNAME + QTYPE + QCLASS(IN=1).
    msg.extend_from_slice(qname_encoded);
    msg.extend_from_slice(&qtype.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg
}

/// A parsed inbound DNS query — the fields QQ-Tunnel's receive path needs.
#[derive(Debug, Clone)]
pub struct ParsedQuery {
    pub qid: u16,
    pub qflags: u16,
    /// The question's labels, lowercased (raw label bytes, no length prefix).
    pub labels: Vec<Vec<u8>>,
    pub qtype: u16,
    /// Offset one past the question section — `data[12..next_question]` is the
    /// echoable question used to build the response.
    pub next_question: usize,
}

/// Port of `handle_question`: walk one uncompressed question, returning its
/// labels, qtype, and the offset just past QCLASS.
fn handle_question(data: &[u8], mut offset: usize) -> Result<(Vec<Vec<u8>>, u16, usize), DnsError> {
    let mut labels = Vec::new();
    let mut total_len = 0usize;
    let len_data = data.len();
    while offset < len_data {
        let label_len = data[offset] as usize;
        if label_len == 0 {
            if offset + 5 > len_data {
                return Err(DnsError::Malformed);
            }
            let qtype = u16::from_be_bytes([data[offset + 1], data[offset + 2]]);
            let qclass = u16::from_be_bytes([data[offset + 3], data[offset + 4]]);
            if qclass != 1 {
                return Err(DnsError::Malformed);
            }
            return Ok((labels, qtype, offset + 5));
        }
        if label_len > 63 {
            return Err(DnsError::Malformed);
        }
        let start = offset + 1;
        offset = start + label_len;
        if offset > len_data {
            return Err(DnsError::Malformed);
        }
        // Enforce the total-name limit, not just the per-label one. Without
        // it the accumulated name grows with the datagram rather than with the
        // protocol, so one maximal UDP datagram of 63-byte labels became a
        // correspondingly large allocation (and reassembly fragment) for an
        // unauthenticated sender.
        total_len += 1 + label_len;
        if total_len > MAX_QNAME_TOTAL_LEN {
            return Err(DnsError::Malformed);
        }
        labels.push(data[start..offset].to_ascii_lowercase());
    }
    Err(DnsError::Malformed)
}

/// Port of `handle_dns_request`: parse a single-question query message.
/// Rejects responses (QR set), multi-question messages, and truncated input.
pub fn handle_dns_request(data: &[u8]) -> Result<ParsedQuery, DnsError> {
    if data.len() < 17 {
        return Err(DnsError::Malformed);
    }
    let qid = u16::from_be_bytes([data[0], data[1]]);
    let qflags = u16::from_be_bytes([data[2], data[3]]);
    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    if qdcount != 1 {
        return Err(DnsError::Malformed);
    }
    if qflags & 0x8000 != 0 {
        return Err(DnsError::NotAQuery);
    }
    let (labels, qtype, next_question) = handle_question(data, 12)?;
    Ok(ParsedQuery {
        qid,
        qflags,
        labels,
        qtype,
        next_question,
    })
}

/// Port of `create_noerror_empty_response`. Echoes the question with QR=1,
/// AA=1, RCODE=0 (or 4 for a non-standard opcode), and no answer records —
/// exactly what the reference authoritative side replies to every tunnel
/// query so recursive resolvers stay happy.
pub fn create_noerror_empty_response(qid: u16, qflags: u16, question: &[u8]) -> Vec<u8> {
    let rflags: u16 = 0x8400 | (qflags & 0x7910) | (u16::from((qflags & 0x7800) != 0) << 2);
    let mut msg = Vec::with_capacity(12 + question.len());
    msg.extend_from_slice(&qid.to_be_bytes());
    msg.extend_from_slice(&rflags.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    msg.extend_from_slice(question);
    msg
}

/// If `labels` ends with one of `recv_domain_labels`, return the number of
/// suffix labels matched (so the caller can strip them and keep the data
/// labels). Mirrors the `all_recv_domains_labels` suffix scan in the
/// reference `wan_recv`.
pub fn match_recv_suffix(labels: &[Vec<u8>], recv_domains: &[Vec<Vec<u8>>]) -> Option<usize> {
    for rd in recv_domains {
        let n = rd.len();
        if n == 0 || labels.len() < n {
            continue;
        }
        if &labels[labels.len() - n..] == rd.as_slice() {
            return Some(n);
        }
    }
    None
}

/// Parse `host:port` (IPv4/hostname) into a `SocketAddr`-friendly pair — the
/// shape QQ-Tunnel's config uses for `h_in_address` / `h_out_address`.
pub fn split_host_port(s: &str) -> Option<(String, u16)> {
    let (host, port) = s.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    Some((host.to_string(), port))
}

/// Resolve a `host:port` string to a concrete `SocketAddr` (first match).
pub fn resolve_addr(s: &str) -> Option<SocketAddr> {
    use std::net::ToSocketAddrs;
    s.to_socket_addrs().ok()?.next()
}

/// DNS-level parse errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    Malformed,
    NotAQuery,
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsError::Malformed => write!(f, "malformed DNS query"),
            DnsError::NotAQuery => write!(f, "message is a response, not a query"),
        }
    }
}

impl std::error::Error for DnsError {}

#[cfg(test)]
mod qname_bounds_tests {
    use super::{handle_dns_request, MAX_QNAME_TOTAL_LEN};

    /// Build a query whose QNAME carries `label_count` maximal 63-byte labels.
    fn query_with_labels(label_count: usize) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&1u16.to_be_bytes()); // id
        m.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD
        m.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        m.extend_from_slice(&0u16.to_be_bytes());
        m.extend_from_slice(&0u16.to_be_bytes());
        m.extend_from_slice(&0u16.to_be_bytes());
        for _ in 0..label_count {
            m.push(63);
            m.extend_from_slice(&[b'a'; 63]);
        }
        m.push(0);
        m.extend_from_slice(&1u16.to_be_bytes()); // QTYPE
        m.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
        m
    }

    #[test]
    fn accepts_a_name_within_the_total_limit() {
        // 3 * 64 = 192 octets, comfortably inside the 255 limit.
        let q = query_with_labels(3);
        let parsed = handle_dns_request(&q).expect("a normal-length name parses");
        assert_eq!(parsed.labels.len(), 3);
    }

    #[test]
    fn rejects_a_name_past_the_total_limit() {
        // 5 * 64 = 320 octets. Each label is individually legal, so only the
        // total-length check can reject this.
        let q = query_with_labels(5);
        assert!(
            handle_dns_request(&q).is_err(),
            "a name over {MAX_QNAME_TOTAL_LEN} octets must be rejected"
        );
    }

    #[test]
    fn a_maximal_datagram_cannot_allocate_without_bound() {
        // The pre-fix behaviour: allocation grew with the datagram rather than
        // with the protocol limit.
        let q = query_with_labels(1000);
        assert!(handle_dns_request(&q).is_err());
    }
}
