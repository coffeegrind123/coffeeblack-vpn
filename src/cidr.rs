//! IPv4/IPv6 CIDR parsing, containment, and host enumeration.
//!
//! Replaces the `ipnet` crate, of which this project used exactly five things:
//! `FromStr`, `addr()`, `prefix_len()`, `contains()`, and `hosts()`. The
//! semantics below are deliberately identical to `ipnet` 2.x, including the
//! two that are easy to get subtly wrong:
//!
//! * [`Ipv4Net::addr`] returns the address **as written**, not the network
//!   base — `10.8.0.5/24` keeps its `.5`. `next_ipv4`/`server_ip` rely on this
//!   (they add 1 to `addr()` to derive the server address), so masking here
//!   would silently move every server IP.
//! * [`Ipv4Net::hosts`] excludes the network and broadcast addresses, but only
//!   for prefixes shorter than 31 — `/31` and `/32` yield the full range.
//!   [`Ipv6Net::hosts`] excludes neither: IPv6 has no broadcast address.
//!
//! Parsing matches `ipnet`'s hand-written parser: the address half goes
//! through `std`'s own `Ipv4Addr`/`Ipv6Addr` parser, and the prefix half must
//! be plain decimal digits — at most 2 for IPv4 and 3 for IPv6 — inside the
//! valid range. `10.0.0.0/024` is rejected there and here.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Returned when a string is not a valid CIDR network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddrParseError;

impl fmt::Display for AddrParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid IP network address syntax")
    }
}

impl std::error::Error for AddrParseError {}

/// Split `"<addr>/<prefix>"` and validate the prefix shape.
///
/// `max_digits` bounds the written length of the prefix (so a zero-padded
/// `/024` is rejected, as in `ipnet`), and `max_len` is the largest legal
/// prefix for the family.
fn split_prefix(s: &str, max_digits: usize, max_len: u8) -> Option<(&str, u8)> {
    let (addr, prefix) = s.split_once('/')?;
    if prefix.is_empty() || prefix.len() > max_digits {
        return None;
    }
    if !prefix.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let len: u8 = prefix.parse().ok()?;
    if len > max_len {
        return None;
    }
    Some((addr, len))
}

// ---------------------------------------------------------------------------
// IPv4
// ---------------------------------------------------------------------------

/// An IPv4 network: an address plus a prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Net {
    addr: Ipv4Addr,
    prefix_len: u8,
}

impl Ipv4Net {
    /// Build a network from an address and prefix length (`0..=32`).
    pub fn new(addr: Ipv4Addr, prefix_len: u8) -> Result<Self, AddrParseError> {
        if prefix_len > 32 {
            return Err(AddrParseError);
        }
        Ok(Self { addr, prefix_len })
    }

    /// The address as written — host bits included.
    pub fn addr(&self) -> Ipv4Addr {
        self.addr
    }

    /// The prefix length in bits.
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Mask with `prefix_len` leading ones. `/0` is all zeros; shifting by 32
    /// would be UB-adjacent (it panics in debug), hence the explicit case.
    fn mask(&self) -> u32 {
        if self.prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix_len)
        }
    }

    /// The network (base) address: `addr` with all host bits cleared.
    pub fn network(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.addr) & self.mask())
    }

    /// The broadcast address: `addr` with all host bits set.
    pub fn broadcast(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.addr) | !self.mask())
    }

    /// Whether `other` falls inside this network.
    pub fn contains(&self, other: &Ipv4Addr) -> bool {
        u32::from(*other) & self.mask() == u32::from(self.addr) & self.mask()
    }

    /// Assignable host addresses. Excludes the network and broadcast
    /// addresses for prefixes shorter than 31; `/31` and `/32` yield every
    /// address in the range.
    pub fn hosts(&self) -> Ipv4AddrRange {
        let mut start = u32::from(self.network());
        let mut end = u32::from(self.broadcast());
        if self.prefix_len < 31 {
            start = start.saturating_add(1);
            end = end.saturating_sub(1);
        }
        Ipv4AddrRange {
            next: start,
            end,
            done: false,
        }
    }
}

impl fmt::Display for Ipv4Net {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

impl FromStr for Ipv4Net {
    type Err = AddrParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, prefix_len) = split_prefix(s, 2, 32).ok_or(AddrParseError)?;
        let addr: Ipv4Addr = addr.parse().map_err(|_| AddrParseError)?;
        Ok(Self { addr, prefix_len })
    }
}

/// Inclusive iterator over an IPv4 address range.
///
/// Exhaustion is a flag rather than `next > end`, because the last address a
/// range can yield is `255.255.255.255`: incrementing past it would wrap to
/// `0.0.0.0` and iterate the whole space forever.
pub struct Ipv4AddrRange {
    next: u32,
    end: u32,
    done: bool,
}

impl Iterator for Ipv4AddrRange {
    type Item = Ipv4Addr;
    fn next(&mut self) -> Option<Ipv4Addr> {
        if self.done || self.next > self.end {
            return None;
        }
        let out = Ipv4Addr::from(self.next);
        if self.next == self.end {
            self.done = true;
        } else {
            self.next += 1;
        }
        Some(out)
    }
}

// ---------------------------------------------------------------------------
// IPv6
// ---------------------------------------------------------------------------

/// An IPv6 network: an address plus a prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Net {
    addr: Ipv6Addr,
    prefix_len: u8,
}

impl Ipv6Net {
    /// Build a network from an address and prefix length (`0..=128`).
    pub fn new(addr: Ipv6Addr, prefix_len: u8) -> Result<Self, AddrParseError> {
        if prefix_len > 128 {
            return Err(AddrParseError);
        }
        Ok(Self { addr, prefix_len })
    }

    /// The address as written — host bits included.
    pub fn addr(&self) -> Ipv6Addr {
        self.addr
    }

    /// The prefix length in bits.
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    fn mask(&self) -> u128 {
        if self.prefix_len == 0 {
            0
        } else {
            u128::MAX << (128 - self.prefix_len)
        }
    }

    /// The network (base) address.
    pub fn network(&self) -> Ipv6Addr {
        Ipv6Addr::from(u128::from(self.addr) & self.mask())
    }

    /// The last address in the network. IPv6 has no broadcast address; the
    /// name matches `ipnet`'s, and [`hosts`](Self::hosts) includes this value.
    pub fn broadcast(&self) -> Ipv6Addr {
        Ipv6Addr::from(u128::from(self.addr) | !self.mask())
    }

    /// Whether `other` falls inside this network.
    pub fn contains(&self, other: &Ipv6Addr) -> bool {
        u128::from(*other) & self.mask() == u128::from(self.addr) & self.mask()
    }

    /// Every address in the network, network address included.
    pub fn hosts(&self) -> Ipv6AddrRange {
        Ipv6AddrRange {
            next: u128::from(self.network()),
            end: u128::from(self.broadcast()),
            done: false,
        }
    }
}

impl fmt::Display for Ipv6Net {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

impl FromStr for Ipv6Net {
    type Err = AddrParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, prefix_len) = split_prefix(s, 3, 128).ok_or(AddrParseError)?;
        let addr: Ipv6Addr = addr.parse().map_err(|_| AddrParseError)?;
        Ok(Self { addr, prefix_len })
    }
}

/// Inclusive iterator over an IPv6 address range. Same wrap-safe exhaustion
/// flag as [`Ipv4AddrRange`].
pub struct Ipv6AddrRange {
    next: u128,
    end: u128,
    done: bool,
}

impl Iterator for Ipv6AddrRange {
    type Item = Ipv6Addr;
    fn next(&mut self) -> Option<Ipv6Addr> {
        if self.done || self.next > self.end {
            return None;
        }
        let out = Ipv6Addr::from(self.next);
        if self.next == self.end {
            self.done = true;
        } else {
            self.next += 1;
        }
        Some(out)
    }
}

// ---------------------------------------------------------------------------
// Family-agnostic
// ---------------------------------------------------------------------------

/// Either an IPv4 or an IPv6 network. Used where a string only has to be
/// *validated* as a CIDR, whichever family it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpNet {
    /// An IPv4 network.
    V4(Ipv4Net),
    /// An IPv6 network.
    V6(Ipv6Net),
}

impl IpNet {
    /// The address as written.
    pub fn addr(&self) -> IpAddr {
        match self {
            IpNet::V4(n) => IpAddr::V4(n.addr()),
            IpNet::V6(n) => IpAddr::V6(n.addr()),
        }
    }

    /// The prefix length in bits.
    pub fn prefix_len(&self) -> u8 {
        match self {
            IpNet::V4(n) => n.prefix_len(),
            IpNet::V6(n) => n.prefix_len(),
        }
    }

    /// Whether `other` falls inside this network. Mixed families never match.
    pub fn contains(&self, other: &IpAddr) -> bool {
        match (self, other) {
            (IpNet::V4(n), IpAddr::V4(a)) => n.contains(a),
            (IpNet::V6(n), IpAddr::V6(a)) => n.contains(a),
            _ => false,
        }
    }
}

impl fmt::Display for IpNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpNet::V4(n) => n.fmt(f),
            IpNet::V6(n) => n.fmt(f),
        }
    }
}

impl FromStr for IpNet {
    type Err = AddrParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(n) = s.parse::<Ipv4Net>() {
            return Ok(IpNet::V4(n));
        }
        s.parse::<Ipv6Net>().map(IpNet::V6)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_parses_and_keeps_host_bits() {
        let net: Ipv4Net = "10.8.0.5/24".parse().unwrap();
        assert_eq!(net.addr(), Ipv4Addr::new(10, 8, 0, 5));
        assert_eq!(net.prefix_len(), 24);
        assert_eq!(net.network(), Ipv4Addr::new(10, 8, 0, 0));
        assert_eq!(net.broadcast(), Ipv4Addr::new(10, 8, 0, 255));
        assert_eq!(net.to_string(), "10.8.0.5/24");
    }

    #[test]
    fn v4_rejects_malformed() {
        for bad in [
            "10.8.0.0",
            "10.8.0.0/",
            "10.8.0.0/33",
            "10.8.0.0/024",
            "10.8.0.0/-1",
            "10.8.0.0/ 24",
            "10.8.0.0/2 4",
            "999.0.0.0/8",
            "10.8.0.0/24/24",
            "",
        ] {
            assert!(bad.parse::<Ipv4Net>().is_err(), "{bad} must not parse");
        }
    }

    #[test]
    fn v4_hosts_skips_network_and_broadcast() {
        let net: Ipv4Net = "10.8.0.0/29".parse().unwrap();
        let hosts: Vec<String> = net.hosts().map(|h| h.to_string()).collect();
        assert_eq!(
            hosts,
            vec![
                "10.8.0.1", "10.8.0.2", "10.8.0.3", "10.8.0.4", "10.8.0.5", "10.8.0.6",
            ]
        );
    }

    #[test]
    fn v4_hosts_includes_everything_for_31_and_32() {
        let p31: Ipv4Net = "10.8.0.0/31".parse().unwrap();
        assert_eq!(p31.hosts().count(), 2);
        let p32: Ipv4Net = "10.8.0.7/32".parse().unwrap();
        let only: Vec<Ipv4Addr> = p32.hosts().collect();
        assert_eq!(only, vec![Ipv4Addr::new(10, 8, 0, 7)]);
    }

    #[test]
    fn v4_hosts_terminates_at_the_top_of_the_space() {
        // A /32 on the last address would wrap a naive `next += 1` iterator.
        let top: Ipv4Net = "255.255.255.255/32".parse().unwrap();
        assert_eq!(top.hosts().count(), 1);
        // /31 at the top: both addresses, then stop.
        let top31: Ipv4Net = "255.255.255.254/31".parse().unwrap();
        assert_eq!(top31.hosts().count(), 2);
    }

    #[test]
    fn v4_contains_matches_prefix() {
        let net: Ipv4Net = "10.8.0.0/24".parse().unwrap();
        assert!(net.contains(&"10.8.0.1".parse().unwrap()));
        assert!(net.contains(&"10.8.0.255".parse().unwrap()));
        assert!(!net.contains(&"10.8.1.0".parse().unwrap()));
        let all: Ipv4Net = "0.0.0.0/0".parse().unwrap();
        assert!(all.contains(&"203.0.113.9".parse().unwrap()));
        let one: Ipv4Net = "10.8.0.4/32".parse().unwrap();
        assert!(one.contains(&"10.8.0.4".parse().unwrap()));
        assert!(!one.contains(&"10.8.0.5".parse().unwrap()));
    }

    #[test]
    fn v6_parses_and_enumerates_from_the_network_address() {
        let net: Ipv6Net = "fdcc:ad94:bacf:61a3::/112".parse().unwrap();
        assert_eq!(net.prefix_len(), 112);
        let first: Vec<String> = net.hosts().take(3).map(|h| h.to_string()).collect();
        assert_eq!(
            first,
            vec![
                "fdcc:ad94:bacf:61a3::",
                "fdcc:ad94:bacf:61a3::1",
                "fdcc:ad94:bacf:61a3::2",
            ]
        );
    }

    #[test]
    fn v6_rejects_malformed() {
        for bad in [
            "fdcc::",
            "fdcc::/129",
            "fdcc::/0064",
            "fdcc::/",
            "not-an-address/64",
            "",
        ] {
            assert!(bad.parse::<Ipv6Net>().is_err(), "{bad} must not parse");
        }
    }

    #[test]
    fn v6_contains_and_edges() {
        let net: Ipv6Net = "fd00::/8".parse().unwrap();
        assert!(net.contains(&"fd00::1".parse().unwrap()));
        assert!(!net.contains(&"fe80::1".parse().unwrap()));
        let one: Ipv6Net = "::1/128".parse().unwrap();
        assert_eq!(one.hosts().count(), 1);
        let top: Ipv6Net = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128".parse().unwrap();
        assert_eq!(top.hosts().count(), 1, "must not wrap at the top");
    }

    #[test]
    fn ip_net_accepts_either_family_and_never_crosses_them() {
        let v4: IpNet = "10.8.0.0/24".parse().unwrap();
        let v6: IpNet = "fd00::/64".parse().unwrap();
        assert!(matches!(v4, IpNet::V4(_)));
        assert!(matches!(v6, IpNet::V6(_)));
        assert!(v4.contains(&"10.8.0.9".parse::<IpAddr>().unwrap()));
        assert!(!v4.contains(&"fd00::9".parse::<IpAddr>().unwrap()));
        assert!(!v6.contains(&"10.8.0.9".parse::<IpAddr>().unwrap()));
        assert_eq!(v4.prefix_len(), 24);
        assert_eq!(v6.addr().to_string(), "fd00::");
        assert!("192.168.0.1".parse::<IpNet>().is_err(), "bare address is not a CIDR");
    }
}
