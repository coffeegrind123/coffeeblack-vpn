//! Per-client firewall + DNS-leak prevention, native nftables.
//!
//! All our rules live inside one `inet awg-easy-rs` table — the same
//! table the AmneziaWG PostUp hook creates for masquerade / accept rules.
//! Sharing the table means we can rebuild *just* our chains atomically
//! without disturbing the operator's NAT / forwarding setup.
//!
//! Layout we expect:
//!
//! ```text
//! table inet awg-easy-rs {
//!   chain forward {                          # owned by hooks
//!     type filter hook forward priority filter; policy accept;
//!     iifname "awg0" jump dns-lockdown       # only when dns_lockdown=true
//!     iifname "awg0" jump wg-clients
//!     oifname "awg0" jump wg-clients
//!   }
//!   chain wg-clients {                       # owned by this module
//!     # per-client rules, then a final `drop` (when firewall_enabled)
//!     # or empty (when firewall_disabled — all traffic returns and is
//!     # accepted by the forward chain's policy)
//!   }
//!   chain dns-lockdown {                     # owned by this module
//!     # accept the redirect target, drop residual :53/:853 to anywhere
//!     # else. Only populated / jumped to when dns_lockdown=true.
//!   }
//!   chain dns-prerouting {                   # owned by this module
//!     type nat hook prerouting priority dstnat; policy accept;
//!     # DNAT every peer :53/:853 packet to dns_lockdown_target.
//!     # Empty (and chain absent) when dns_lockdown=false.
//!   }
//!   chain nat-postrouting { ... }            # owned by hooks
//!   chain filter-input    { ... }            # owned by hooks
//! }
//! ```
//!
//! Every chain we own is rebuilt via a single `nft -f -` transaction so
//! the rebuild is atomic — peers never see a half-applied ruleset.
//!
//! ## DNS lockdown rationale
//!
//! WireGuard / AmneziaWG `DNS = …` is honor-system: the client decides
//! which resolver to query. A misconfigured app, a malicious binary, or
//! a peer who edited their `.conf` can query 1.1.1.1 / 8.8.8.8 / their
//! ISP's resolver directly through the tunnel and bypass any in-VPN
//! filtering, logging, or DNSSEC posture. The dns-prerouting DNAT
//! rewrites the destination to `dns_lockdown_target` before the packet
//! leaves the box — the client doesn't get a choice. dns-lockdown's
//! drop catches v6 leaks (when the target is v4-only) and any future
//! address family the DNAT rule doesn't match.

use std::io::Write;
use std::process::{Command, Stdio};

use anyhow::{anyhow, Result};

/// Single source of truth for the table name. Hooks reference it from
/// the DB-stored PostUp/PostDown templates; everything in this module
/// references it from here.
pub const TABLE: &str = "awg-easy-rs";

/// Per-client filtering chain. Lives inside `TABLE`.
const CHAIN: &str = "wg-clients";

/// Filter chain that drops residual peer DNS traffic (`udp/tcp dport
/// 53|853`) headed anywhere other than `dns_lockdown_target`. Jumped to
/// from `forward` only when `dns_lockdown && dns_block_external`.
const DNS_FILTER_CHAIN: &str = "dns-lockdown";

/// NAT chain that DNAT-redirects every peer :53/:853 packet to
/// `dns_lockdown_target:53`. Lives at `prerouting/dstnat` priority so
/// the rewrite happens before any later forward / filter / postrouting
/// hook sees the packet. Created on demand (when `dns_lockdown=true`)
/// and torn down when the toggle goes off — we don't leave an empty
/// nat hook chain around because that costs a per-packet cycle even
/// when it has no rules.
const DNS_NAT_CHAIN: &str = "dns-prerouting";

/// Input-hook filter chain that confines AmneziaWG's loopback backend port
/// to the loopback interface while the DPI-imitation proxy fronts the
/// public port. Without it, AmneziaWG (which binds the backend port on all
/// addresses) would still answer raw handshakes on that port from the WAN,
/// letting a prober bypass the proxy's protocol imitation entirely.
/// Created when the proxy is active, torn down when it isn't.
const PROXY_LOCKDOWN_CHAIN: &str = "proxy-lockdown";

/// Run a single `nft` invocation with the given argv. argv-only — no
/// shell — so peer names containing quotes / backticks / shell metas
/// can never escape into command interpretation.
fn nft(args: &[&str]) -> Result<String> {
    if !cfg!(target_os = "linux") {
        return Ok(String::new());
    }
    // With the privileged helper enabled the only read this code needs is the
    // table listing, which the helper exposes as its own fixed operation —
    // arbitrary `nft` argument vectors are deliberately not forwardable.
    if crate::privhelper::is_enabled() {
        return crate::privhelper::call(&crate::privhelper::Request::NftList);
    }
    let out = Command::new("nft").args(args).output()?;
    if !out.status.success() {
        return Err(anyhow!(
            "nft {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Apply a multi-statement nftables transaction atomically by piping it
/// to `nft -f -`. The rule body is freshly assembled every call so a
/// caller can't end up with stale rules from a previous rebuild.
fn nft_apply(transaction: &str) -> Result<()> {
    if !cfg!(target_os = "linux") {
        return Ok(());
    }
    if crate::privhelper::is_enabled() {
        return crate::privhelper::call(&crate::privhelper::Request::NftApply {
            ruleset: transaction.to_string(),
        })
        .map(|_| ());
    }
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow!("nft child has no stdin"))?;
        stdin.write_all(transaction.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err(anyhow!(
            "nft transaction failed: {}\n--- transaction ---\n{}",
            String::from_utf8_lossy(&out.stderr).trim(),
            transaction
        ));
    }
    Ok(())
}

pub fn is_available() -> bool {
    Command::new("nft")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Make sure the table + per-client chain exist, and that the forward
/// chain has a jump into us. Idempotent — `add table`/`add chain` /
/// `add rule` are tolerant of pre-existing definitions, and we only
/// add the jump if it isn't already there.
pub fn init_chain(iface: &str) -> Result<()> {
    let iface = sanitize_iface(iface);
    let txn = format!(
        "add table inet {table}\n\
         add chain inet {table} {chain}\n\
         add chain inet {table} forward {{ type filter hook forward priority filter; policy accept; }}\n",
        table = TABLE,
        chain = CHAIN,
    );
    nft_apply(&txn)?;

    // The `add rule … jump wg-clients` form is NOT idempotent — it
    // appends a duplicate every time. We list the chain first and only
    // add the jump if the literal rule isn't already there.
    let listing = nft(&["list", "chain", "inet", TABLE, "forward"]).unwrap_or_default();
    let want_in = format!("iifname \"{iface}\" jump {CHAIN}");
    let want_out = format!("oifname \"{iface}\" jump {CHAIN}");
    let mut adds = String::new();
    if !listing.contains(&want_in) {
        adds.push_str(&format!(
            "add rule inet {TABLE} forward iifname \"{iface}\" jump {CHAIN}\n"
        ));
    }
    if !listing.contains(&want_out) {
        adds.push_str(&format!(
            "add rule inet {TABLE} forward oifname \"{iface}\" jump {CHAIN}\n"
        ));
    }
    if !adds.is_empty() {
        nft_apply(&adds)?;
    }
    Ok(())
}

/// Empty the per-client chain. Doesn't touch the forward chain or the
/// table itself — those are owned by the hooks.
pub fn flush_chain() -> Result<()> {
    nft_apply(&format!("flush chain inet {TABLE} {CHAIN}\n"))
}

/// Toggle off: flush the chain and remove the forward-chain jumps. We
/// leave the empty `wg-clients` chain in place so re-enabling is a
/// pure rebuild without having to recreate it.
pub fn remove_filtering(iface: &str) -> Result<()> {
    let iface = sanitize_iface(iface);
    flush_chain()?;

    // Locate and delete the jump rules by handle. `--handle --numeric`
    // gives us `… # handle N` suffix on each rule line.
    let listing = nft(&["--handle", "--numeric", "list", "chain", "inet", TABLE, "forward"])
        .unwrap_or_default();
    let mut deletions = String::new();
    for line in listing.lines() {
        let line = line.trim();
        if line.contains(&format!("iifname \"{iface}\" jump {CHAIN}"))
            || line.contains(&format!("oifname \"{iface}\" jump {CHAIN}"))
        {
            if let Some(handle) = parse_handle(line) {
                deletions.push_str(&format!(
                    "delete rule inet {TABLE} forward handle {handle}\n"
                ));
            }
        }
    }
    if !deletions.is_empty() {
        // Best-effort: a missing handle is not an error worth aborting
        // the whole shutdown for.
        let _ = nft_apply(&deletions);
    }
    Ok(())
}

/// Full rebuild from DB state. Single atomic `nft -f -` apply for the
/// per-client chain; DNS lockdown gets its own atomic apply because its
/// chains live in a different hook (prerouting vs. forward) and may
/// or may not exist at this point.
///
/// DNS lockdown is rebuilt **first** so that even when the per-peer
/// firewall is disabled (`firewall_enabled = false`) the lockdown still
/// applies — the two settings are independent.
/// `spawn_blocking` wrapper around [`rebuild_rules`]. `nft -f -` is a
/// subprocess invocation; offloading it keeps async handlers from parking a
/// tokio worker on the firewall rebuild.
pub async fn rebuild_rules_async() -> Result<()> {
    tokio::task::spawn_blocking(rebuild_rules)
        .await
        .map_err(|e| anyhow!("blocking task failed: {e}"))?
}

pub fn rebuild_rules() -> Result<()> {
    let iface = crate::db::get_interface()?;
    let enable_ipv6 = !crate::config::CONFIG.disable_ipv6;

    rebuild_dns_lockdown(&iface)?;

    if !iface.firewall_enabled {
        // DNS lockdown lives in its own chain — leave it alone here.
        return remove_filtering(&iface.name);
    }

    init_chain(&iface.name)?;

    let clients = crate::db::get_all_clients()?;
    let user_config = crate::db::get_user_config()?;
    let default_ips: Vec<String> =
        serde_json::from_str(&user_config.default_allowed_ips).unwrap_or_default();

    let mut txn = String::new();
    txn.push_str(&format!("flush chain inet {TABLE} {CHAIN}\n"));
    for client in &clients {
        if !client.enabled {
            continue;
        }
        append_client_rules(&mut txn, client, &default_ips, enable_ipv6)?;
    }
    // Final default-deny.
    txn.push_str(&format!("add rule inet {TABLE} {CHAIN} drop\n"));

    nft_apply(&txn)
}

// ---------------------------------------------------------------------------
// DNS lockdown
// ---------------------------------------------------------------------------

/// Address family of a parsed DNS-lockdown target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

/// Validate the operator-supplied target into a `(family, canonical-form)`
/// pair. nft DNAT targets must be IP literals — hostnames would let
/// runtime DNS state silently rewrite the redirect, which defeats the
/// point of the lockdown. v6 literals are returned bare (without the
/// `[]` wrappers) because nft writes them inline (`dnat ip6 to fd::1:53`).
fn parse_target_ip(target: &str) -> Result<(Family, String)> {
    let t = target.trim();
    if t.is_empty() {
        return Err(anyhow!("DNS lockdown target is empty"));
    }
    // Reject anything obviously not an IP — single-label hostnames slip
    // through Ipv4Addr::from_str rejection, so we additionally insist
    // the string contains '.' or ':'.
    if !(t.contains('.') || t.contains(':')) {
        return Err(anyhow!(
            "DNS lockdown target {t:?} is not an IP literal (hostnames disallowed)"
        ));
    }
    if let Ok(v4) = t.parse::<std::net::Ipv4Addr>() {
        return Ok((Family::V4, v4.to_string()));
    }
    // Strip surrounding brackets if the operator typed them.
    let stripped = t.strip_prefix('[').and_then(|s| s.strip_suffix(']')).unwrap_or(t);
    if let Ok(v6) = stripped.parse::<std::net::Ipv6Addr>() {
        return Ok((Family::V6, v6.to_string()));
    }
    Err(anyhow!("DNS lockdown target {t:?} is not a valid IPv4 or IPv6 literal"))
}

/// Build the `dns-prerouting` rule lines that DNAT every peer-originated
/// :53/:853 packet to `target:53`. Pure function — returns the rule body
/// (without the `add chain` header) so the caller assembles the full
/// transaction. Each rule emits a `meta nfproto` guard so we don't ask
/// nft to DNAT a v6 packet to a v4 target (or vice versa) — that would
/// be rejected at apply time.
fn dns_dnat_rules(iface: &str, family: Family, target: &str) -> Vec<String> {
    // `inet` family chains can carry both v4 and v6 rules; `dnat ip to`
    // is restricted to v4 packets, `dnat ip6 to` to v6 packets. The
    // `meta nfproto` guard makes that explicit and keeps the rule from
    // matching the wrong family.
    // nftables requires an IPv6 DNAT target carrying a port to be bracketed —
    // `dnat ip6 to [fd00::53]:53`. Without the brackets, `fd00::53:53` is
    // itself a valid IPv6 literal, so nft would either DNAT to the wrong
    // address with no port translation or reject the whole transaction
    // (silently disabling v6 DNS lockdown). v4 is written bare.
    let (nfproto, dnat_kw, dst) = match family {
        Family::V4 => ("ipv4", "dnat ip to", target.to_string()),
        Family::V6 => ("ipv6", "dnat ip6 to", format!("[{target}]")),
    };
    // Send everything to :53 on the target — DoT (:853) is also
    // rewritten to plain :53 so the lockdown resolver doesn't need a
    // separate listener. Operators who run DoT-only resolvers can change
    // this in a follow-up; today's wg-easy ecosystem assumes :53.
    vec![
        format!(
            "add rule inet {TABLE} {DNS_NAT_CHAIN} \
             iifname \"{iface}\" meta nfproto {nfproto} udp dport {{ 53, 853 }} {dnat_kw} {dst}:53"
        ),
        format!(
            "add rule inet {TABLE} {DNS_NAT_CHAIN} \
             iifname \"{iface}\" meta nfproto {nfproto} tcp dport {{ 53, 853 }} {dnat_kw} {dst}:53"
        ),
    ]
}

/// Build the `dns-lockdown` filter chain rules: accept legitimate
/// (DNATed) traffic that already hits the target, then drop the rest of
/// peer :53/:853 across both address families.
fn dns_filter_rules(family: Family, target: &str) -> Vec<String> {
    let (saddr_kw, dst) = match family {
        Family::V4 => ("ip daddr", target.to_string()),
        Family::V6 => ("ip6 daddr", target.to_string()),
    };
    vec![
        // Already-DNATed packets land here with daddr == target — let
        // them through ahead of the catch-all drop. Without this an
        // operator who flipped block_external on would null-route their
        // own redirect.
        format!(
            "add rule inet {TABLE} {DNS_FILTER_CHAIN} {saddr_kw} {dst} accept"
        ),
        // The actual leak guard. Drops anything still asking :53/:853
        // anywhere else, regardless of address family — covers v6
        // queries when the target is v4 (and vice versa).
        format!("add rule inet {TABLE} {DNS_FILTER_CHAIN} udp dport {{ 53, 853 }} drop"),
        format!("add rule inet {TABLE} {DNS_FILTER_CHAIN} tcp dport {{ 53, 853 }} drop"),
    ]
}

/// Cross-family leak guard, applied when `dns_lockdown` is on but
/// `dns_block_external` is off. The DNAT rules only redirect the target's own
/// address family (`meta nfproto` guard), so peer DNS in the *other* family
/// would pass straight through the tunnel. Drop exactly that family's
/// :53/:853 — the DNATed family still flows (its packets are rewritten in
/// prerouting and fall through this chain), and non-DNS traffic is untouched.
fn dns_leak_guard_rules(target_family: Family) -> Vec<String> {
    let other = match target_family {
        Family::V4 => "ipv6",
        Family::V6 => "ipv4",
    };
    vec![
        format!(
            "add rule inet {TABLE} {DNS_FILTER_CHAIN} meta nfproto {other} udp dport {{ 53, 853 }} drop"
        ),
        format!(
            "add rule inet {TABLE} {DNS_FILTER_CHAIN} meta nfproto {other} tcp dport {{ 53, 853 }} drop"
        ),
    ]
}

/// Idempotently create the dns-prerouting nat chain. We only call this
/// when DNS lockdown is enabled — the chain is removed when it goes
/// off. Creating an empty nat-prerouting chain costs nothing at packet
/// time, but leaving stale ones around clutters `nft list ruleset`.
fn ensure_dns_chains(iface: &str) -> Result<()> {
    let iface = sanitize_iface(iface);
    // The filter chain is now always created and jumped to whenever lockdown
    // is on: even with `dns_block_external = false` we populate it with the
    // cross-family leak guard (see `dns_leak_guard_rules`), so the previous
    // "only create it when block_external" branch would have left v6 (or v4)
    // DNS leaking. Creating the empty chain costs nothing at packet time.
    let txn = format!(
        "add table inet {TABLE}\n\
         add chain inet {TABLE} forward {{ type filter hook forward priority filter; policy accept; }}\n\
         add chain inet {TABLE} {DNS_NAT_CHAIN} {{ type nat hook prerouting priority dstnat; policy accept; }}\n\
         add chain inet {TABLE} {DNS_FILTER_CHAIN}\n",
    );
    nft_apply(&txn)?;

    // Add the forward jump for dns-lockdown if it isn't already there.
    // Same idempotency dance as init_chain — `add rule` would otherwise
    // append a duplicate every rebuild.
    let listing = nft(&["list", "chain", "inet", TABLE, "forward"]).unwrap_or_default();
    let want = format!("iifname \"{iface}\" jump {DNS_FILTER_CHAIN}");
    if !listing.contains(&want) {
        nft_apply(&format!(
            "add rule inet {TABLE} forward iifname \"{iface}\" jump {DNS_FILTER_CHAIN}\n"
        ))?;
    }
    Ok(())
}

/// Tear down both DNS chains and the forward-chain jump. Best-effort:
/// the jump-handle delete swallows errors so a missing rule (already
/// removed, never inserted) doesn't fail the call. Used both when DNS
/// lockdown is toggled off and when the whole feature is disabled.
fn remove_dns_lockdown(iface: &str) -> Result<()> {
    let iface = sanitize_iface(iface);
    delete_dns_filter_jump(&iface);
    // `delete chain` requires the chain to be empty; flush first. Both
    // commands tolerate the chain not existing (we use `add` semantics
    // implicitly via `delete chain` — an absent chain produces a
    // non-zero exit which we swallow).
    let _ = nft_apply(&format!(
        "flush chain inet {TABLE} {DNS_FILTER_CHAIN}\n\
         delete chain inet {TABLE} {DNS_FILTER_CHAIN}\n"
    ));
    let _ = nft_apply(&format!(
        "flush chain inet {TABLE} {DNS_NAT_CHAIN}\n\
         delete chain inet {TABLE} {DNS_NAT_CHAIN}\n"
    ));
    Ok(())
}

/// Confine (or release) the AmneziaWG loopback backend port for the DPI
/// proxy. Idempotent: when the proxy is active it (re)creates the
/// `proxy-lockdown` input chain with a single rule dropping any external
/// packet to the backend port (loopback traffic — the proxy→AWG hop — is
/// left alone); when the proxy is inactive it tears the chain down.
///
/// Whether the proxy is active, and which loopback port AmneziaWG moved
/// to, are both derived from the same source of truth the config
/// generator uses ([`crate::proxy::supervisor::effective_listen_port`]),
/// so the firewall and the `.conf` can never disagree about the backend
/// port. Best-effort and non-fatal at the call sites.
pub fn apply_proxy_lockdown(iface: &crate::db::Interface) -> Result<()> {
    let backend = crate::proxy::supervisor::effective_listen_port(iface);
    if backend == iface.port {
        // Proxy inactive — AmneziaWG owns the public port directly.
        return remove_proxy_lockdown();
    }
    // `add chain` is idempotent (no-op if present); `flush` then clears any
    // prior rule so a backend-port change doesn't leave a stale drop.
    let txn = format!(
        "add table inet {TABLE}\n\
         add chain inet {TABLE} {PROXY_LOCKDOWN_CHAIN} \
           {{ type filter hook input priority filter; policy accept; }}\n\
         flush chain inet {TABLE} {PROXY_LOCKDOWN_CHAIN}\n\
         add rule inet {TABLE} {PROXY_LOCKDOWN_CHAIN} \
           udp dport {backend} iifname != \"lo\" drop\n"
    );
    nft_apply(&txn)
}

/// Remove the proxy backend lockdown chain. Best-effort — an absent chain
/// is fine (delete of a missing chain returns non-zero, which we swallow).
fn remove_proxy_lockdown() -> Result<()> {
    let _ = nft_apply(&format!(
        "flush chain inet {TABLE} {PROXY_LOCKDOWN_CHAIN}\n\
         delete chain inet {TABLE} {PROXY_LOCKDOWN_CHAIN}\n"
    ));
    Ok(())
}

/// Locate and delete the `forward → dns-lockdown` jump rule by handle.
/// Mirrors the per-client jump cleanup in `remove_per_peer_filtering`.
fn delete_dns_filter_jump(iface: &str) {
    let listing = nft(&["--handle", "--numeric", "list", "chain", "inet", TABLE, "forward"])
        .unwrap_or_default();
    let mut deletions = String::new();
    for line in listing.lines() {
        let line = line.trim();
        if line.contains(&format!("iifname \"{iface}\" jump {DNS_FILTER_CHAIN}")) {
            if let Some(handle) = parse_handle(line) {
                deletions.push_str(&format!(
                    "delete rule inet {TABLE} forward handle {handle}\n"
                ));
            }
        }
    }
    if !deletions.is_empty() {
        let _ = nft_apply(&deletions);
    }
}

/// Apply DNS lockdown to the running ruleset based on the interface row.
/// When `dns_lockdown=false` or the target is empty, this is the same as
/// `remove_dns_lockdown` — we tolerate either form of "off".
pub fn rebuild_dns_lockdown(iface: &crate::db::Interface) -> Result<()> {
    if !iface.dns_lockdown || iface.dns_lockdown_target.trim().is_empty() {
        return remove_dns_lockdown(&iface.name);
    }
    let (family, target) = parse_target_ip(&iface.dns_lockdown_target)?;
    let enable_ipv6 = !crate::config::CONFIG.disable_ipv6;
    if family == Family::V6 && !enable_ipv6 {
        return Err(anyhow!(
            "DNS lockdown target is IPv6 but DISABLE_IPV6 is set; refusing to apply"
        ));
    }

    ensure_dns_chains(&iface.name)?;

    let iface_name = sanitize_iface(&iface.name);
    let mut txn = String::new();
    // Flush both chains before re-adding so a previous (different)
    // target doesn't leave orphan rules behind.
    txn.push_str(&format!("flush chain inet {TABLE} {DNS_NAT_CHAIN}\n"));
    txn.push_str(&format!("flush chain inet {TABLE} {DNS_FILTER_CHAIN}\n"));
    for r in dns_dnat_rules(&iface_name, family, &target) {
        txn.push_str(&r);
        txn.push('\n');
    }
    // The filter chain is always populated when lockdown is on:
    //  * block_external  → drop ALL residual peer :53/:853 (both families)
    //    except traffic already DNATed to the target.
    //  * otherwise       → drop only the address family we CANNOT DNAT (the
    //    DNAT rules carry a `meta nfproto` guard, so with a v4 target only v4
    //    is redirected; without this guard peer v6 DNS would leak straight
    //    out — the exact leak the module doc promised to prevent).
    let filter_rules = if iface.dns_block_external {
        dns_filter_rules(family, &target)
    } else {
        dns_leak_guard_rules(family)
    };
    for r in filter_rules {
        txn.push_str(&r);
        txn.push('\n');
    }
    nft_apply(&txn)?;
    tracing::info!(
        iface = %iface.name,
        target = %target,
        family = ?family,
        block_external = iface.dns_block_external,
        "DNS lockdown active: peer :53/:853 redirected"
    );
    Ok(())
}

fn append_client_rules(
    txn: &mut String,
    client: &crate::db::Client,
    default_ips: &[String],
    enable_ipv6: bool,
) -> Result<()> {
    let targets: Vec<String> = match client.firewall_ips.as_deref() {
        Some(s) if !s.is_empty() => serde_json::from_str(s).unwrap_or_default(),
        _ => match client.allowed_ips.as_deref() {
            Some(s) if !s.is_empty() => serde_json::from_str(s).unwrap_or_default(),
            _ => default_ips.to_vec(),
        },
    };

    let src4 = client.ipv4_address.as_deref().unwrap_or("0.0.0.0");
    let src6 = client.ipv6_address.as_deref().unwrap_or("::");

    // The peer's own addresses are spliced into the ruleset exactly like the
    // targets below, so they need the same validation. `parse_target` guards
    // the destination but nothing guarded the source, leaving a legacy or
    // hand-edited row able to carry nft syntax into the transaction. Same
    // disposition as an invalid target: skip this client rather than abort the
    // rebuild, since default-deny means a skipped client is closed, not open.
    if src4.parse::<std::net::Ipv4Addr>().is_err() {
        tracing::warn!(
            client = client.id, addr = %src4,
            "skipping per-client firewall rules: ipv4_address is not an IPv4 address"
        );
        return Ok(());
    }
    if src6.parse::<std::net::Ipv6Addr>().is_err() {
        tracing::warn!(
            client = client.id, addr = %src6,
            "skipping per-client firewall rules: ipv6_address is not an IPv6 address"
        );
        return Ok(());
    }

    let comment = sanitize_comment(&client.name, client.id);

    for t in &targets {
        // A single malformed/hostile target must not abort the whole ruleset
        // rebuild (which would leave every client's rules stale) nor reach the
        // nft transaction. Skip it — with default-deny in force, a dropped
        // target simply means that destination is not opened. Reachable only
        // for legacy rows written before the write-side validators existed;
        // fresh writes are already rejected at the API boundary.
        let (ip, port, proto) = match parse_target(t) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(target = %t, error = %e, "skipping invalid firewall target");
                continue;
            }
        };
        let is_v6 = ip.contains(':');
        if is_v6 && !enable_ipv6 {
            continue;
        }
        let src = if is_v6 { src6 } else { src4 };

        for rule in gen_rules(src, ip, port, proto, &comment, is_v6) {
            txn.push_str(&rule);
            txn.push('\n');
        }
    }
    Ok(())
}

/// Allow only chars nft is happy to put inside a `comment "…"` literal.
/// The transaction is fed via stdin so the shell can't interfere, but
/// nft itself rejects unescaped `"` inside the comment string.
fn sanitize_comment(name: &str, id: i64) -> String {
    let s: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '_' | '-' | '.'))
        .take(80) // nft caps comments at 128 — leave headroom for the prefix
        .collect();
    format!("client {id}: {s}")
}

/// Interface names already pass `[A-Za-z0-9_-]{1,15}` validation
/// upstream of every call site, but we redo it here so this module is
/// safe to call directly from tests.
fn sanitize_iface(iface: &str) -> String {
    iface
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
        .take(15)
        .collect()
}

/// Reject any address token that isn't a bare IP or CIDR literal. The
/// returned string is spliced verbatim into an `nft -f -` transaction, so a
/// value carrying whitespace, a newline, or an nft keyword must never
/// survive — otherwise a caller that stored an unvalidated target (e.g. the
/// admin-set `default_allowed_ips`, see the write-side guard in `api::admin`)
/// could inject arbitrary nft statements. This is the durable, in-module
/// guard: `firewall.rs` does not trust its callers for bytes it renders into
/// the ruleset — mirroring the canonicalisation `parse_target_ip` already
/// does for the DNS-lockdown target.
fn checked_ip(ip: &str) -> Result<&str> {
    if ip.parse::<std::net::IpAddr>().is_ok() || ip.parse::<ipnet::IpNet>().is_ok() {
        Ok(ip)
    } else {
        Err(anyhow!(
            "firewall target address {ip:?} is not a valid IP or CIDR literal"
        ))
    }
}

fn parse_target(entry: &str) -> Result<(&str, Option<u16>, Option<&str>)> {
    let (body, proto) = if let Some(rest) = entry.strip_suffix("/tcp") {
        (rest, Some("tcp"))
    } else if let Some(rest) = entry.strip_suffix("/udp") {
        (rest, Some("udp"))
    } else {
        (entry, None)
    };

    if body.starts_with('[') {
        if let Some(end) = body.find(']') {
            let ip = &body[1..end];
            let rest = &body[end + 1..];
            if let Some(port_str) = rest.strip_prefix(':') {
                return Ok((checked_ip(ip)?, Some(port_str.parse()?), proto));
            }
            return Ok((checked_ip(ip)?, None, proto));
        }
    }

    if body.matches(':').count() <= 1 {
        if let Some(col) = body.rfind(':') {
            let maybe_port = &body[col + 1..];
            if maybe_port.chars().all(|c| c.is_ascii_digit()) {
                return Ok((checked_ip(&body[..col])?, Some(maybe_port.parse()?), proto));
            }
        }
    }

    Ok((checked_ip(body)?, None, proto))
}

/// Build the nft `add rule …` lines for one (src, dst, [port], [proto]) triple.
/// `is_v6` switches the address-family qualifier to `ip6`. We use `inet`
/// table family which lets us mix both in the same chain.
fn gen_rules(
    src: &str,
    dst: &str,
    port: Option<u16>,
    proto: Option<&str>,
    comment: &str,
    is_v6: bool,
) -> Vec<String> {
    let fam = if is_v6 { "ip6" } else { "ip" };
    let prefix = format!(
        "add rule inet {TABLE} {CHAIN} {fam} saddr {src} {fam} daddr {dst}"
    );
    let mut out = Vec::new();

    let mk = |proto_clause: &str, port_clause: &str| {
        format!(
            "{prefix}{proto}{port} accept comment \"{comment}\"",
            proto = proto_clause,
            port = port_clause,
        )
    };

    if let Some(p) = port {
        let do_tcp = proto.is_none() || proto == Some("tcp");
        let do_udp = proto.is_none() || proto == Some("udp");
        if do_tcp {
            out.push(mk(" tcp", &format!(" dport {p}")));
        }
        if do_udp {
            out.push(mk(" udp", &format!(" dport {p}")));
        }
    } else {
        out.push(format!(
            "{prefix} accept comment \"{comment}\""
        ));
    }
    out
}

/// Pull `N` out of an nft `… # handle N` line. Returns None when the
/// listing didn't include the handle (e.g. `nft` without `--handle`).
fn parse_handle(line: &str) -> Option<u64> {
    let marker = line.find("# handle ")?;
    line[marker + "# handle ".len()..]
        .split_whitespace()
        .next()
        .and_then(|s| s.parse().ok())
}

// ---------------------------------------------------------------------------
// iptables-legacy compatibility
// ---------------------------------------------------------------------------
//
// Modern hosts run `iptables-nft`, which writes to the same `nf_tables`
// kernel backend our `nft` commands use. On those hosts our
// `inet awg-easy-rs forward accept` and the operator's `ip filter forward`
// rules (also nf_tables) compose cleanly: same backend, single hook chain
// per priority, verdicts merge predictably.
//
// Older hosts run `iptables-legacy`, which writes to the parallel
// `xt_tables` kernel backend. xt_tables and nf_tables are separate kernel
// modules with separate hook chains; the kernel runs both at each
// netfilter hook and the packet is forwarded only if BOTH chains accept.
// A FORWARD-DROP policy in xt_tables drops the packet even though our
// nf_tables chain said accept.
//
// On startup we detect whether xt_tables is loaded AND a legacy CLI is
// available, and if so we mirror the three "let AWG traffic through"
// rules into the legacy backend so they're seen by both subsystems.
// Removed on graceful shutdown via the SIGTERM handler in main.rs.
//
// Detection signal: `/proc/net/ip_tables_names` exists if and only if
// the `ip_tables` kernel module is loaded. iptables-nft hosts don't
// load `ip_tables` and don't create that file. (Same for ip6_tables.)

fn ip_tables_loaded() -> bool {
    std::path::Path::new("/proc/net/ip_tables_names").exists()
}

fn ip6_tables_loaded() -> bool {
    std::path::Path::new("/proc/net/ip6_tables_names").exists()
}

/// Resolve the binary that speaks the xt_tables backend. Returns the
/// argv-0 we should call. Tries `iptables-legacy` first (explicit name
/// on Debian/Ubuntu/Fedora when both backends are co-installed), then
/// falls back to plain `iptables` if its `--version` reports `(legacy)`.
fn legacy_iptables_bin() -> Option<&'static str> {
    if Command::new("iptables-legacy")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return Some("iptables-legacy");
    }
    let out = Command::new("iptables").arg("--version").output().ok()?;
    if out.status.success() && String::from_utf8_lossy(&out.stdout).contains("(legacy)") {
        return Some("iptables");
    }
    None
}

fn legacy_ip6tables_bin() -> Option<&'static str> {
    if Command::new("ip6tables-legacy")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return Some("ip6tables-legacy");
    }
    let out = Command::new("ip6tables").arg("--version").output().ok()?;
    if out.status.success() && String::from_utf8_lossy(&out.stdout).contains("(legacy)") {
        return Some("ip6tables");
    }
    None
}

/// Idempotent insert. `-C` first to test, `-I` only if missing, so
/// repeated calls don't pile up duplicates.
fn ensure_iptables_rule(bin: &str, args: &[&str]) -> Result<()> {
    let mut check: Vec<&str> = vec!["-C"];
    check.extend_from_slice(args);
    let exists = Command::new(bin)
        .args(&check)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if exists {
        return Ok(());
    }
    let mut insert: Vec<&str> = vec!["-I"];
    insert.extend_from_slice(args);
    let out = Command::new(bin).args(&insert).output()?;
    if !out.status.success() {
        return Err(anyhow!(
            "{bin} {:?}: {}",
            insert,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

fn delete_iptables_rule(bin: &str, args: &[&str]) {
    let mut delete: Vec<&str> = vec!["-D"];
    delete.extend_from_slice(args);
    // Best-effort: a missing rule (already removed, never inserted) is
    // not worth a noisy warning during shutdown.
    let _ = Command::new(bin).args(&delete).output();
}

/// The three rules we mirror into the legacy backend. Returned as
/// argv slices so the caller can pass them straight to `ensure_iptables_rule`
/// / `delete_iptables_rule` without rebuilding.
fn legacy_compat_rule_set<'a>(iface: &'a str, port: &'a str) -> [Vec<&'a str>; 3] {
    [
        vec!["FORWARD", "-i", iface, "-j", "ACCEPT"],
        vec!["FORWARD", "-o", iface, "-j", "ACCEPT"],
        vec!["INPUT", "-p", "udp", "--dport", port, "-j", "ACCEPT"],
    ]
}

/// Idempotently mirror our forward/input accept rules into iptables-legacy
/// so they're seen by both kernel subsystems. No-op when xt_tables isn't
/// loaded or no legacy CLI is available — that covers every iptables-nft
/// host (the default on every modern distro).
pub fn ensure_legacy_compat(iface: &str, port: i64, enable_ipv6: bool) -> Result<()> {
    if !cfg!(target_os = "linux") {
        return Ok(());
    }
    let port_str = port.to_string();
    let iface = sanitize_iface(iface);

    if ip_tables_loaded() {
        if let Some(bin) = legacy_iptables_bin() {
            for args in legacy_compat_rule_set(&iface, &port_str) {
                ensure_iptables_rule(bin, &args)?;
            }
            tracing::info!(
                bin,
                iface = %iface,
                port,
                "iptables-legacy compat: ensured FORWARD/INPUT accept rules"
            );
        }
    }
    if enable_ipv6 && ip6_tables_loaded() {
        if let Some(bin) = legacy_ip6tables_bin() {
            for args in legacy_compat_rule_set(&iface, &port_str) {
                ensure_iptables_rule(bin, &args)?;
            }
            tracing::info!(
                bin,
                iface = %iface,
                port,
                "ip6tables-legacy compat: ensured FORWARD/INPUT accept rules"
            );
        }
    }
    Ok(())
}

/// Best-effort cleanup. Called from the SIGTERM handler so a graceful
/// shutdown doesn't leave orphaned `-i awg0 -j ACCEPT` rules in
/// iptables-legacy after the interface is gone. Errors swallowed —
/// the process is on its way out anyway.
pub fn remove_legacy_compat(iface: &str, port: i64, enable_ipv6: bool) {
    if !cfg!(target_os = "linux") {
        return;
    }
    let port_str = port.to_string();
    let iface = sanitize_iface(iface);

    if ip_tables_loaded() {
        if let Some(bin) = legacy_iptables_bin() {
            for args in legacy_compat_rule_set(&iface, &port_str) {
                delete_iptables_rule(bin, &args);
            }
            tracing::info!(bin, "iptables-legacy compat: removed accept rules");
        }
    }
    if enable_ipv6 && ip6_tables_loaded() {
        if let Some(bin) = legacy_ip6tables_bin() {
            for args in legacy_compat_rule_set(&iface, &port_str) {
                delete_iptables_rule(bin, &args);
            }
            tracing::info!(bin, "ip6tables-legacy compat: removed accept rules");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_target_bare_ipv4() {
        let (ip, port, proto) = parse_target("8.8.8.8").unwrap();
        assert_eq!(ip, "8.8.8.8");
        assert_eq!(port, None);
        assert_eq!(proto, None);
    }

    #[test]
    fn parse_target_ipv4_with_port_and_proto() {
        let (ip, port, proto) = parse_target("8.8.8.8:53/udp").unwrap();
        assert_eq!(ip, "8.8.8.8");
        assert_eq!(port, Some(53));
        assert_eq!(proto, Some("udp"));
    }

    #[test]
    fn parse_target_ipv6_bracketed() {
        let (ip, port, proto) = parse_target("[2001:db8::1]:443/tcp").unwrap();
        assert_eq!(ip, "2001:db8::1");
        assert_eq!(port, Some(443));
        assert_eq!(proto, Some("tcp"));
    }

    #[test]
    fn parse_target_bare_ipv6() {
        let (ip, port, _) = parse_target("2001:db8::1").unwrap();
        assert_eq!(ip, "2001:db8::1");
        assert_eq!(port, None);
    }

    #[test]
    fn gen_rules_no_port_emits_one_rule() {
        let rules = gen_rules("10.8.0.2", "8.8.8.8", None, None, "client 1: alice", false);
        assert_eq!(rules.len(), 1);
        assert!(rules[0].contains("ip saddr 10.8.0.2 ip daddr 8.8.8.8"));
        assert!(rules[0].contains("accept comment \"client 1: alice\""));
        assert!(!rules[0].contains("dport"));
    }

    #[test]
    fn gen_rules_port_no_proto_emits_tcp_and_udp() {
        let rules = gen_rules("10.8.0.2", "8.8.8.8", Some(53), None, "alice", false);
        assert_eq!(rules.len(), 2);
        assert!(rules.iter().any(|r| r.contains("tcp dport 53")));
        assert!(rules.iter().any(|r| r.contains("udp dport 53")));
    }

    #[test]
    fn gen_rules_explicit_proto_emits_one() {
        let rules = gen_rules("10.8.0.2", "8.8.8.8", Some(53), Some("udp"), "alice", false);
        assert_eq!(rules.len(), 1);
        assert!(rules[0].contains("udp dport 53"));
    }

    #[test]
    fn gen_rules_v6_uses_ip6_qualifier() {
        let rules = gen_rules("fd::2", "2001:db8::1", Some(443), Some("tcp"), "alice", true);
        assert_eq!(rules.len(), 1);
        assert!(rules[0].contains("ip6 saddr fd::2 ip6 daddr 2001:db8::1"));
        assert!(!rules[0].contains("ip saddr"));
    }

    #[test]
    fn sanitize_comment_strips_shell_metas() {
        let c = sanitize_comment("alice'; DROP TABLE users; --", 7);
        assert_eq!(c, "client 7: alice DROP TABLE users --");
    }

    #[test]
    fn sanitize_iface_filters_special_chars() {
        assert_eq!(sanitize_iface("awg0"), "awg0");
        assert_eq!(sanitize_iface("awg0; rm -rf /"), "awg0rm-rf");
        // 16-char input gets clipped to 15.
        assert_eq!(sanitize_iface("0123456789abcdefg").len(), 15);
    }

    #[test]
    fn parse_handle_extracts_numeric_id() {
        assert_eq!(
            parse_handle("\tiifname \"awg0\" jump wg-clients # handle 42"),
            Some(42)
        );
        assert_eq!(parse_handle("no handle here"), None);
    }

    #[test]
    fn parse_target_ip_accepts_ipv4() {
        let (fam, s) = parse_target_ip("10.2.0.100").unwrap();
        assert_eq!(fam, Family::V4);
        assert_eq!(s, "10.2.0.100");
        // Whitespace tolerated.
        let (fam, s) = parse_target_ip("  1.1.1.1  ").unwrap();
        assert_eq!(fam, Family::V4);
        assert_eq!(s, "1.1.1.1");
    }

    #[test]
    fn parse_target_ip_accepts_ipv6_with_or_without_brackets() {
        let (fam, s) = parse_target_ip("fd00::53").unwrap();
        assert_eq!(fam, Family::V6);
        assert_eq!(s, "fd00::53");
        let (fam, s) = parse_target_ip("[2001:db8::1]").unwrap();
        assert_eq!(fam, Family::V6);
        assert_eq!(s, "2001:db8::1");
    }

    #[test]
    fn parse_target_ip_rejects_hostname_and_empty() {
        // Hostnames would let runtime DNS rewrite the redirect — defeats
        // the lockdown's whole point. Reject them at config time.
        assert!(parse_target_ip("dns.example.com").is_err());
        assert!(parse_target_ip("localhost").is_err());
        assert!(parse_target_ip("").is_err());
        assert!(parse_target_ip("   ").is_err());
        assert!(parse_target_ip("not-an-ip").is_err());
        // 999.999 is a hostname-shaped string that contains '.' but
        // isn't a valid v4 — must still be rejected.
        assert!(parse_target_ip("999.999.999.999").is_err());
    }

    #[test]
    fn dns_dnat_rules_v4_target_emits_v4_dnat_only() {
        let rules = dns_dnat_rules("awg0", Family::V4, "10.2.0.100");
        assert_eq!(rules.len(), 2);
        for r in &rules {
            assert!(r.contains("iifname \"awg0\""));
            assert!(r.contains("meta nfproto ipv4"));
            assert!(r.contains("dnat ip to 10.2.0.100:53"));
            // dport set covers both classic DNS and DoT — operators who
            // run a plain-text-only resolver still want :853 redirected
            // to :53 rather than letting it leak.
            assert!(r.contains("dport { 53, 853 }"));
        }
        // One UDP, one TCP — SQL injection of a third rule would be a
        // regression worth catching.
        assert!(rules.iter().any(|r| r.contains("udp dport")));
        assert!(rules.iter().any(|r| r.contains("tcp dport")));
    }

    #[test]
    fn dns_dnat_rules_v6_target_is_bracketed() {
        let rules = dns_dnat_rules("awg0", Family::V6, "fd00::53");
        for r in &rules {
            assert!(r.contains("meta nfproto ipv6"));
            // The v6 target MUST be bracketed so the `:53` port is
            // unambiguous — `fd00::53:53` (unbracketed) is a different,
            // valid IPv6 literal and would silently mis-DNAT.
            assert!(
                r.contains("dnat ip6 to [fd00::53]:53"),
                "v6 DNAT target must be bracketed, got: {r}"
            );
            assert!(!r.contains("dnat ip to"));
        }
    }

    #[test]
    fn dns_leak_guard_drops_other_family_only() {
        // v4 target → the un-DNAT-able family is v6, so the leak guard drops
        // ipv6 :53/:853 and leaves ipv4 (DNATed) alone.
        let v4 = dns_leak_guard_rules(Family::V4);
        assert_eq!(v4.len(), 2);
        for r in &v4 {
            assert!(r.contains("meta nfproto ipv6"));
            assert!(r.contains("dport { 53, 853 } drop"));
        }
        // v6 target → drops ipv4.
        let v6 = dns_leak_guard_rules(Family::V6);
        for r in &v6 {
            assert!(r.contains("meta nfproto ipv4"));
        }
    }

    #[test]
    fn dns_filter_rules_accept_target_then_drop_others() {
        let rules = dns_filter_rules(Family::V4, "10.2.0.100");
        // Order matters — accept must come before drop, otherwise the
        // catch-all drop fires first and the redirect target is null-
        // routed alongside everything else.
        assert!(rules[0].contains("ip daddr 10.2.0.100 accept"));
        assert!(rules[1].contains("udp dport { 53, 853 } drop"));
        assert!(rules[2].contains("tcp dport { 53, 853 } drop"));
    }

    #[test]
    fn dns_filter_rules_v6_uses_ip6_daddr() {
        let rules = dns_filter_rules(Family::V6, "fd00::53");
        assert!(rules[0].contains("ip6 daddr fd00::53 accept"));
    }

    #[test]
    fn parse_target_accepts_valid_shapes() {
        for ok in [
            "8.8.8.8",
            "8.8.8.8:53",
            "8.8.8.8:443/tcp",
            "10.0.0.0/24",
            "[2001:db8::1]:443",
            "2001:db8::1",
        ] {
            assert!(parse_target(ok).is_ok(), "should accept {ok:?}");
        }
    }

    #[test]
    fn parse_target_rejects_nft_injection() {
        // The address token is spliced verbatim into `nft -f -`; anything that
        // isn't a bare IP/CIDR (whitespace, newline, nft keywords) must be
        // rejected so a stored-but-unvalidated target can't inject statements.
        for bad in [
            "1.1.1.1\nadd rule inet awg-easy-rs wg-clients accept",
            "1.1.1.1 accept",
            "0.0.0.0/0 drop",
            "not-an-ip",
            "1.1.1.1; flush ruleset",
            "$(whoami)",
        ] {
            assert!(parse_target(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn legacy_compat_rule_set_covers_forward_and_input() {
        let rules = legacy_compat_rule_set("awg0", "51820");
        // Three rules: FORWARD-in, FORWARD-out, INPUT.
        assert_eq!(rules.len(), 3);
        assert_eq!(
            rules[0],
            vec!["FORWARD", "-i", "awg0", "-j", "ACCEPT"]
        );
        assert_eq!(
            rules[1],
            vec!["FORWARD", "-o", "awg0", "-j", "ACCEPT"]
        );
        assert_eq!(
            rules[2],
            vec!["INPUT", "-p", "udp", "--dport", "51820", "-j", "ACCEPT"]
        );
    }

    #[test]
    fn legacy_compat_no_op_when_modules_not_loaded() {
        // /proc/net/ip_tables_names doesn't exist on this dev box (we
        // sit behind an iptables-nft kernel). ensure_legacy_compat must
        // silently no-op without spawning any legacy CLI, otherwise it
        // would fail the build pipeline on systems lacking the binary.
        if ip_tables_loaded() || ip6_tables_loaded() {
            return; // skip on hosts where xt_tables IS loaded
        }
        // Should be Ok and a no-op.
        ensure_legacy_compat("awg0", 51820, true).unwrap();
        // remove is fire-and-forget but still must not panic.
        remove_legacy_compat("awg0", 51820, true);
    }

    /// End-to-end: feed a representative transaction through `nft -c -f -`
    /// (check-only mode) and assert it parses cleanly. Catches syntax
    /// regressions in `gen_rules` / `init_chain` that pure-string tests
    /// would miss. Marked `#[ignore]` because dev machines often don't
    /// have `nft`; CI runners and the docker container do.
    #[test]
    #[ignore = "requires the nft binary in PATH"]
    fn nft_validates_generated_transaction() {
        if !is_available() {
            // Belt-and-braces in case the runner skips the ignore filter.
            return;
        }

        // Build a transaction that exercises every shape gen_rules can
        // emit (no port, port-with-explicit-proto, port-no-proto, both
        // address families) plus the chain bootstrap from init_chain
        // AND the DNS-lockdown chains so a syntax regression in
        // dns_dnat_rules / dns_filter_rules surfaces here.
        let mut txn = String::new();
        txn.push_str("add table inet awg-easy-rs-syntaxtest\n");
        txn.push_str(
            "add chain inet awg-easy-rs-syntaxtest forward { type filter hook forward priority filter; policy accept; }\n",
        );
        txn.push_str("add chain inet awg-easy-rs-syntaxtest wg-clients\n");
        txn.push_str("add chain inet awg-easy-rs-syntaxtest dns-lockdown\n");
        txn.push_str(
            "add chain inet awg-easy-rs-syntaxtest dns-prerouting { type nat hook prerouting priority dstnat; policy accept; }\n",
        );
        // DNS lockdown rules — both families to catch v4/v6 syntax.
        for r in dns_dnat_rules("awg0", Family::V4, "10.2.0.100") {
            let r = r.replace("inet awg-easy-rs ", "inet awg-easy-rs-syntaxtest ");
            txn.push_str(&r);
            txn.push('\n');
        }
        for r in dns_dnat_rules("awg0", Family::V6, "fd00::53") {
            let r = r.replace("inet awg-easy-rs ", "inet awg-easy-rs-syntaxtest ");
            txn.push_str(&r);
            txn.push('\n');
        }
        for r in dns_filter_rules(Family::V4, "10.2.0.100") {
            let r = r.replace("inet awg-easy-rs ", "inet awg-easy-rs-syntaxtest ");
            txn.push_str(&r);
            txn.push('\n');
        }
        // Cross-family leak guard (block_external=false path) — validate the
        // `meta nfproto … drop` syntax for both target families.
        for r in dns_leak_guard_rules(Family::V4)
            .into_iter()
            .chain(dns_leak_guard_rules(Family::V6))
        {
            let r = r.replace("inet awg-easy-rs ", "inet awg-easy-rs-syntaxtest ");
            txn.push_str(&r);
            txn.push('\n');
        }
        // Rewrite TABLE to the test name so the rules land in the test table.
        let rules = vec![
            gen_rules("10.8.0.2", "8.8.8.8", None,           None,         "client 1: alice", false),
            gen_rules("10.8.0.2", "8.8.8.8", Some(53),       Some("udp"),  "client 1: alice", false),
            gen_rules("10.8.0.2", "8.8.8.8", Some(443),      None,         "client 1: alice", false),
            gen_rules("fd::2",    "2001:db8::1", Some(443),  Some("tcp"),  "client 2: bob",   true),
        ];
        for batch in rules {
            for r in batch {
                let r = r.replace("inet awg-easy-rs ", "inet awg-easy-rs-syntaxtest ");
                txn.push_str(&r);
                txn.push('\n');
            }
        }
        txn.push_str("add rule inet awg-easy-rs-syntaxtest wg-clients drop\n");

        // `nft -c` validates without applying. Doesn't need root.
        let mut child = std::process::Command::new("nft")
            .arg("-c")
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn nft -c");
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(txn.as_bytes())
            .unwrap();
        let out = child.wait_with_output().expect("wait nft -c");
        assert!(
            out.status.success(),
            "nft -c rejected our transaction:\nstderr:\n{}\n--- transaction ---\n{}",
            String::from_utf8_lossy(&out.stderr),
            txn,
        );
    }
}
