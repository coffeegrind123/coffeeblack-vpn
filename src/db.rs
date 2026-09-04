use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, OnceLock};

use anyhow::{anyhow, Context, Result};
use crate::cidr::{Ipv4Net, Ipv6Net};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::config::CONFIG;

// ---------------------------------------------------------------------------
// Global database handle – initialised once by init_db()
// ---------------------------------------------------------------------------
//
// The outer OnceLock is initialised on first use; the inner Mutex<Option<…>>
// allows the test harness to swap the connection between tests without UB.
static DB: OnceLock<Mutex<Option<Connection>>> = OnceLock::new();

fn db_slot() -> &'static Mutex<Option<Connection>> {
    DB.get_or_init(|| Mutex::new(None))
}

/// A guard that exposes the underlying SQLite connection while the global
/// mutex is held. Mirrors the previous `MutexGuard<Connection>` API.
pub struct ConnGuard {
    inner: MutexGuard<'static, Option<Connection>>,
}

impl std::ops::Deref for ConnGuard {
    type Target = Connection;
    fn deref(&self) -> &Self::Target {
        self.inner
            .as_ref()
            .expect("Database not initialised – call db::init_db() first")
    }
}

impl std::ops::DerefMut for ConnGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner
            .as_mut()
            .expect("Database not initialised – call db::init_db() first")
    }
}

fn conn() -> ConnGuard {
    // Recover from a poisoned mutex instead of cascading the panic. Poisoning
    // means some thread panicked *while holding the guard*; but every write in
    // this module is a self-contained statement/transaction (rusqlite rolls an
    // uncommitted transaction back on drop), so the Connection itself is not
    // left in a torn state. Propagating the poison (the old `.expect`) instead
    // turned a single stray panic into a permanent, whole-service DB outage —
    // strictly worse for availability. `into_inner()` takes the guard anyway.
    let inner = db_slot()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    ConnGuard { inner }
}

/// Generic field map used by update helpers.
pub type UpdateMap = HashMap<String, String>;

// ---------------------------------------------------------------------------
// Secrets encrypted at rest
// ---------------------------------------------------------------------------

/// `(table, column)` pairs holding credentials, encrypted transparently by
/// [`crate::crypto`] whenever a key is configured.
///
/// This is the whole list, in one place, so "what does a stolen database
/// yield?" has an auditable answer rather than one assembled by grepping.
///
/// **Not** included, deliberately:
/// - `users_table.password` is already an argon2id hash. Encrypting a strong
///   password hash protects nothing that the hash does not already protect.
///   (`general_table.metrics_password` used to be excluded for the same
///   reason, but it is a single unsalted SHA-256 rather than argon2id, so the
///   argument does not carry and it is now encrypted.)
/// - `one_time_links_table.one_time_link` is looked up *by value*, so it
///   cannot be randomly encrypted. It is stored as a SHA-256 digest instead —
///   strictly better, since the server never needs the token back.
///
/// Note the parallel exposure this does not touch: the same secrets are
/// rendered into the config files the bundled transports read, which must be
/// plaintext because those processes parse them. Those files are written 0600
/// by `crate::secretfile`; see that module.
const ENCRYPTED_COLUMNS: &[(&str, &str)] = &[
    ("interfaces_table", "private_key"),
    // AmneziaWG 3 header-protection key. Same standing as the device
    // private key: it is a symmetric key both ends hold, and anyone with
    // it can strip the header obfuscation off captured traffic.
    ("interfaces_table", "header_protection_key"),
    ("clients_table", "private_key"),
    ("clients_table", "pre_shared_key"),
    ("xray_inbound_table", "private_key"),
    ("xray_clients_table", "uuid"),
    ("xray_clients_table", "short_id"),
    ("mtproxy_users_table", "secret_hex"),
    ("mdnsvpn_inbound_table", "encryption_key"),
    ("general_table", "session_password"),
    ("users_table", "totp_key"),
    // The recoverable copy of a one-time-link token. The `one_time_link`
    // column holds only a SHA-256 digest (used for lookup); this column is
    // what lets the UI re-display an active link, so it is a live bearer
    // credential and belongs in the registry. It was already encrypted at its
    // insert site, but its absence here meant the startup back-fill never
    // upgraded rows written before a key was configured.
    ("one_time_links_table", "token_enc"),
    // SOCKS5 credentials for the MasterDnsVPN tunnel. Live authentication
    // secrets: rendered into the server config and into every per-client
    // share bundle. They sat beside `encryption_key` on the same rows, which
    // *is* encrypted, so a stolen database gave up these and nothing else.
    ("mdnsvpn_inbound_table", "socks5_pass"),
    ("mdnsvpn_clients_table", "socks5_pass"),
    // The metrics bearer token's digest. The exclusion note below used to
    // cover this on the grounds that a hash needs no encryption — true of the
    // argon2id account password, but this one is a single unsalted SHA-256
    // (`auth::sha256`), which is cheap to crack offline from a stolen DB.
    // Encrypting it costs nothing on the request path and removes that.
    ("general_table", "metrics_password"),
];

fn is_encrypted_column(table: &str, column: &str) -> bool {
    ENCRYPTED_COLUMNS
        .iter()
        .any(|(t, c)| *t == table && *c == column)
}

/// Encrypt a value destined for an encrypted column. Empty stays empty — an
/// absent secret should not become an opaque blob that looks like one.
fn enc(v: &str) -> Result<String> {
    if v.is_empty() || crate::crypto::is_encrypted(v) {
        return Ok(v.to_string());
    }
    crate::crypto::encrypt(v)
}

/// Decrypt a value read from an encrypted column.
///
/// Failure is an error, never a fallback to the raw bytes: handing ciphertext
/// to a config generator would produce a peer that silently cannot connect,
/// and (as the TOTP path once did) treating an unreadable secret as "absent"
/// turns a decryption failure into a disabled security control. Fail closed
/// and loudly.
fn dec(v: &str) -> rusqlite::Result<String> {
    crate::crypto::decrypt(v).map_err(|e| {
        crate::error!("could not decrypt a stored secret: {e:#}");
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::other(format!(
                "stored secret could not be decrypted: {e}"
            ))),
        )
    })
}

/// Decrypt an optional column.
fn dec_opt(v: Option<String>) -> rusqlite::Result<Option<String>> {
    match v {
        Some(v) if !v.is_empty() => dec(&v).map(Some),
        other => Ok(other),
    }
}

/// Default activity-history window, in days.
///
/// Deliberately short. The heatmap's operational value — spotting a peer that
/// has gone quiet, or one suddenly moving far more than usual — is served
/// well by a few weeks; the months beyond that add little but retroactive
/// exposure if the box is ever seized. Operators who want a longer window can
/// raise it, and `0` turns collection off entirely.
pub const DEFAULT_ACTIVITY_RETENTION_DAYS: i64 = 30;

/// Hard ceiling on the retention window, enforced at the API boundary so an
/// operator cannot set an unbounded value that quietly turns the rollup back
/// into an ever-growing table.
pub const MAX_ACTIVITY_RETENTION_DAYS: i64 = 365;

/// Peer private keys are handed over once at creation and never stored. The
/// config and QR cannot be re-displayed afterwards; recovery is rotation,
/// exactly like a lost API key.
pub const RETENTION_NEVER: &str = "never";
/// Peer private keys are stored, so the config and QR can be re-rendered on
/// demand. Convenient, and strictly weaker: anyone who reaches the database —
/// or a backup of it — can impersonate every peer.
pub const RETENTION_PLAINTEXT: &str = "plaintext";

/// The accepted values of `general_table.private_key_retention`.
///
/// Instance-wide rather than per-peer, deliberately: a per-peer toggle makes
/// the question "does this server hold key material?" unanswerable without
/// auditing every row, when it should have exactly one answer for the whole
/// box.
pub const PRIVATE_KEY_RETENTION_MODES: &[&str] = &[RETENTION_NEVER, RETENTION_PLAINTEXT];

// ---------------------------------------------------------------------------
// Entity structs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Interface {
    pub name: String,
    pub device: String,
    pub port: i64,
    pub private_key: String,
    pub public_key: String,
    pub ipv4_cidr: String,
    pub ipv6_cidr: String,
    pub mtu: i64,
    pub j_c: i64,
    pub j_min: i64,
    pub j_max: i64,
    pub s1: i64,
    pub s2: i64,
    pub s3: Option<i64>,
    pub s4: Option<i64>,
    pub h1: String,
    pub h2: String,
    pub h3: String,
    pub h4: String,
    pub i1: String,
    pub i2: String,
    pub i3: String,
    pub i4: String,
    pub i5: String,
    // ---- AmneziaWG 3 device knobs (all inert when empty / false) ----
    /// Base64 32-byte key enabling AWG 3 header protection: the message
    /// header is encrypted with the S1–S4 padding as the nonce. **Server-
    /// side** in upstream's taxonomy — both ends must carry the same value,
    /// so it is rendered into peer configs too. Empty disables it.
    ///
    /// Requires every one of S1–S4 to be at least 12 (the cipher's nonce
    /// size); amneziawg-go refuses the device otherwise.
    pub header_protection_key: String,
    /// Extra random padding added to *data* packets, as `n` or `lo-hi`
    /// (u16). Client-side, but upstream recommends setting it on both ends.
    pub content_padding_addition: String,
    /// WireGuard timer overrides, each `n` or `lo-hi` seconds (u16), except
    /// `max_handshake_attempts` which is a count. Empty leaves the protocol
    /// default in place.
    pub rekey_after_time: String,
    pub rekey_timeout: String,
    pub reject_after_time: String,
    pub keepalive_timeout: String,
    pub max_handshake_attempts: String,
    /// Append a random-length trailer to every packet.
    pub random_trailers: bool,
    /// Suppress cookie replies entirely (removes the S3/H3 message type
    /// from the wire).
    pub disable_cookies: bool,
    pub firewall_enabled: bool,
    /// DNS-leak-prevention master switch. When true, all UDP/TCP :53 and
    /// :853 traffic from peers is DNAT-redirected to `dns_lockdown_target`
    /// before it leaves the box, regardless of the peer's configured
    /// `DNS = …` line. Closes the honor-system hole where a misconfigured
    /// or malicious client queries any resolver it likes over the tunnel.
    pub dns_lockdown: bool,
    /// IP literal (v4 or v6) packets are redirected to when `dns_lockdown`
    /// is on. Empty string disables the lockdown even if the bool is set
    /// (defensive — prevents an unconfigured field from generating
    /// `dnat to :53` rules with no target).
    pub dns_lockdown_target: String,
    /// Belt-and-braces: when true AND `dns_lockdown` is on, drop any peer
    /// :53/:853 traffic that isn't headed to `dns_lockdown_target`. Catches
    /// edge cases the DNAT rule misses (e.g. v6 queries when target is v4,
    /// or a future address family the rule doesn't match).
    pub dns_block_external: bool,
    /// Free-form text appended verbatim to the server `[Interface]` block.
    /// Mirrors amnezia-client's `additionalServerConfig` — escape hatch for
    /// keys awg-quick understands but the UI doesn't model. Empty by default.
    pub additional_config: String,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    pub id: i64,
    pub user_id: Option<i64>,
    pub interface_id: Option<String>,
    pub name: String,
    pub ipv4_address: Option<String>,
    pub ipv6_address: Option<String>,
    pub private_key: String,
    pub public_key: String,
    pub pre_shared_key: Option<String>,
    pub pre_up: Option<String>,
    pub post_up: Option<String>,
    pub pre_down: Option<String>,
    pub post_down: Option<String>,
    pub expires_at: Option<String>,
    pub allowed_ips: Option<String>,
    pub server_allowed_ips: Option<String>,
    pub firewall_ips: Option<String>,
    pub persistent_keepalive: i64,
    pub mtu: i64,
    pub j_c: Option<i64>,
    pub j_min: Option<i64>,
    pub j_max: Option<i64>,
    pub i1: Option<String>,
    pub i2: Option<String>,
    pub i3: Option<String>,
    pub i4: Option<String>,
    pub i5: Option<String>,
    pub dns: Option<String>,
    pub server_endpoint: Option<String>,
    /// Tri-state per-peer AmneziaWG opt-in:
    /// - `Some(true)` → emit `AdvancedSecurity = on` in the [Peer] block
    /// - `Some(false)` → emit `AdvancedSecurity = off`
    /// - `None` → omit the key entirely; the kernel auto-detects on first
    ///   handshake by validating the H1 magic header.
    pub advanced_security: Option<bool>,
    /// Free-form text appended to this peer's generated client `[Interface]`
    /// block. When `None`, falls back to `UserConfig::default_additional_config`.
    pub additional_config: Option<String>,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub password: String,
    pub email: Option<String>,
    pub name: String,
    pub role: i64,
    pub totp_key: Option<String>,
    pub totp_verified: bool,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserConfig {
    pub id: String,
    pub default_mtu: i64,
    pub default_persistent_keepalive: i64,
    pub default_dns: String,
    pub default_allowed_ips: String,
    pub default_j_c: i64,
    pub default_j_min: i64,
    pub default_j_max: i64,
    pub default_i1: String,
    pub default_i2: String,
    pub default_i3: String,
    pub default_i4: String,
    pub default_i5: String,
    /// Default free-form `[Interface]` append used for new clients that don't
    /// override it on their own row. Empty string == no append.
    pub default_additional_config: String,
    pub host: String,
    pub port: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hooks {
    pub id: String,
    pub pre_up: String,
    pub post_up: String,
    pub pre_down: String,
    pub post_down: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct General {
    pub id: i64,
    pub setup_step: i64,
    pub session_password: String,
    pub session_timeout: i64,
    pub metrics_prometheus: bool,
    pub metrics_json: bool,
    pub metrics_password: Option<String>,
    /// Days of per-client activity history to retain. `0` disables the
    /// activity poller and purges any history already recorded.
    pub activity_retention_days: i64,
    /// `never` | `plaintext` — see [`PRIVATE_KEY_RETENTION_MODES`].
    pub private_key_retention: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Singleton "Browsing mode" inbound — one Xray VLESS+Reality+Vision listener
/// per server. Modelled as a single row keyed on `id = 'xray0'` to match
/// the singleton pattern already used by `interfaces_table`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XrayInbound {
    pub id: String,
    pub port: i64,
    /// Reality `dest` — the upstream `host:port` Xray fronts when DPI
    /// inspects the connection. Must be reachable from the server and
    /// must terminate TLS 1.3 with a SAN matching `server_names[0]`.
    pub dest: String,
    /// JSON array of SNI strings (Reality `serverNames`). The first
    /// entry is what clients put in `?sni=…`.
    pub server_names: String,
    /// Reality x25519 private key (server-side). Empty until first
    /// `regenerate_keys` call.
    pub private_key: String,
    /// Matching x25519 public key (handed to clients in `?pbk=…`).
    pub public_key: String,
    /// Default uTLS fingerprint baked into share links (`chrome`,
    /// `firefox`, `safari`, `randomized`, `random`).
    pub fingerprint_default: String,
    /// Stream transport multiplexed on top of Reality. `"tcp"` is the
    /// classic VLESS+Reality+Vision stack every reference impl ships.
    /// `"xhttp"` wraps the inner connection in HTTP framing with a
    /// secret path — adopted by amnezia-client/#2339 to evade probes
    /// that fingerprint raw TLS-on-443 flows. Vision flow is TCP-only
    /// and is dropped when transport is xhttp.
    pub transport: String,
    /// Secret routing path for the xhttp transport — `/<32 hex chars>`,
    /// generated on first switch to xhttp and kept stable until the
    /// operator regenerates it. Empty when `transport == "tcp"`.
    pub xhttp_path: String,
    /// Free-form text appended verbatim into the generated `server.json`'s
    /// inbound — escape hatch for sniffing/routing tweaks the UI doesn't
    /// model. Empty by default.
    pub additional_config: String,
    /// When false the supervisor will not start Xray. Safe default —
    /// requires the operator to set `dest`, generate keys, and explicitly
    /// flip the toggle.
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// Singleton row (`id = 'proxy0'`) holding the in-process DPI-imitation
/// proxy configuration. Read by `proxy::supervisor` at startup and after
/// every admin POST. The proxy fronts the AmneziaWG UDP port and makes the
/// datagrams look like QUIC / DNS / STUN / SIP to DPI.
///
/// Port model: the proxy always binds the interface's *public* port
/// (`interfaces_table.port`) so client `Endpoint` lines never change;
/// AmneziaWG itself is moved onto `backend_port` (loopback-restricted by
/// the firewall). Only `backend_port` is operator-tunable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxySettings {
    pub id: String,
    /// When false the supervisor tears the proxy down and AmneziaWG keeps
    /// the public port directly. Safe default — no obfuscation layer until
    /// the operator opts in.
    pub enabled: bool,
    /// Protocol the proxy imitates: `quic` | `dns` | `stun` | `sip` |
    /// `auto`. Maps to `ProxyConfig::imitate_protocol`.
    pub protocol: String,
    /// Loopback port AmneziaWG is rebound to while the proxy is enabled.
    /// `0` = auto (`interface.port ± 1`). The proxy forwards decrypted
    /// frontend datagrams to `127.0.0.1:<backend_port>`.
    pub backend_port: i64,
    /// Answer QUIC Initial probes with a real TLS 1.3 server flight
    /// (`ProxyConfig::quic_handshake_enabled`). Only consulted for
    /// `quic` / `auto`.
    pub quic_handshake: bool,
    /// Domain placed in the self-signed QUIC server certificate when
    /// `quic_handshake` is on. Must be non-empty then.
    pub quic_cert_domain: String,
    /// Forward DNS probes to a real upstream resolver instead of always
    /// synthesising SERVFAIL (`ProxyConfig::dns_forward_enabled`). Only
    /// consulted for `dns` / `auto`.
    pub dns_forward: bool,
    /// Upstream resolver `host:port` used when `dns_forward` is on.
    pub dns_upstream: String,
    /// Free-form escape hatch, reserved for future proxy tunables the UI
    /// doesn't model. Empty by default.
    pub additional_config: String,
    /// Cap on concurrent proxy sessions. Each session is one backend UDP
    /// socket (fd) + one relay task, so this bounds the blast radius of a
    /// spoofed-source flood pinning slots. Conservative default (2048).
    pub max_sessions: i64,
    /// Seconds an idle session is kept before reaping. Lower = spoofed
    /// junk sessions free their fd/slot sooner. Default 120.
    pub session_ttl: i64,
    pub created_at: String,
    pub updated_at: String,
}

/// Singleton row holding the QQ-Tunnel UDP-over-DNS transport configuration
/// (server side). Read by `qqdns::supervisor` at startup and after every
/// admin POST. Disabled by default — the operator must own a delegated
/// domain, list resolvers, and opt in. See `src/qqdns/` for the engine that
/// consumes these fields. JSON-array columns (`dns_ips`, `send_domains`,
/// `recv_domains`) hold `serde_json`-encoded `Vec<String>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QqdnsSettings {
    pub id: String,
    /// When false the supervisor keeps the engine torn down. AmneziaWG is
    /// unaffected either way — this transport is a side-channel, not a rebind.
    pub enabled: bool,
    /// Resolver IPs outbound queries are sent to (always port 53), JSON array.
    pub dns_ips: String,
    /// Domains delegated to the *client* relay — outbound data rides these
    /// QNAMEs. JSON array. (The `nb.<client-domain>` records.)
    pub send_domains: String,
    /// Our own delegated domains — inbound queries whose QNAME ends in one of
    /// these are accepted and decoded. JSON array. (The `nb.<server-domain>`.)
    pub recv_domains: String,
    /// Source address the outbound query sockets bind to. Empty = `0.0.0.0`.
    pub send_interface_ip: String,
    /// Address the authoritative :53 listener binds to.
    pub receive_interface_ip: String,
    /// Port the authoritative listener binds to (53, or 5353 behind a
    /// PREROUTING redirect when systemd-resolved owns 53).
    pub receive_port: i64,
    /// Local UDP endpoint the engine binds; AmneziaWG sees the tunnelled peer
    /// arriving from here. `host:port`.
    pub h_in_address: String,
    /// AmneziaWG UDP port decoded traffic is delivered to on loopback. `0` =
    /// auto (the interface's own `ListenPort`).
    pub cb_target_port: i64,
    /// Max final domain length without trailing dot (≤253). Set to the lowest
    /// value all listed resolvers tolerate.
    pub max_domain_len: i64,
    /// Max length of each subdomain label (≤63).
    pub max_sub_len: i64,
    /// Extra transmissions per datagram (0 = once). Multiplies bandwidth by
    /// `retries+1`; trades bandwidth for packet-loss resilience.
    pub retries: i64,
    /// Outbound DNS query type (1=A, 28=AAAA, 16=TXT, …).
    pub send_query_type: i64,
    /// Pacing between packets per resolver queue, milliseconds.
    pub packets_send_interval_ms: i64,
    /// Drop a queued datagram that waited longer than this, milliseconds.
    pub packets_wait_time_limit_ms: i64,
    /// Number of source sockets used to spread queries across ports
    /// (resolver rate-limit evasion). May need a raised `ulimit -n`.
    pub send_sock_numbers: i64,
    pub created_at: String,
    pub updated_at: String,
}

/// Singleton row holding the bundled-DNS-stack configuration. Read by
/// `dns::supervisor` at startup and after every admin POST. The
/// supervisor is the sole consumer — keep field-level docs in sync with
/// `src/dns/dnscrypt.rs` and `src/dns/tor.rs` since those translate
/// these fields into TOML/torrc directives.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsBundle {
    pub id: String,
    /// Master switch for the dnscrypt-proxy supervisor. When false the
    /// supervisor refuses to spawn — DNS lockdown then needs an
    /// external resolver target (the operator's pre-existing setup).
    pub enabled: bool,
    /// Port dnscrypt-proxy binds to (`listen_addresses` entry). Default
    /// 5353 to avoid colliding with anything already on :53; the DNS
    /// lockdown DNAT redirects peer :53/:853 to this port.
    pub listen_port: i64,
    /// JSON array of upstream resolver names (DNSCrypt or DoH). Empty
    /// = let dnscrypt-proxy auto-select from its public-resolvers source.
    pub upstream_resolvers: String,
    pub require_dnssec: bool,
    pub require_nolog: bool,
    pub require_nofilter: bool,
    /// Independently opt-in for tor SOCKS routing — even with
    /// `enabled=true`, tor stays off unless this is also true. Per
    /// feedback_dns_bundle.md: tor adds latency and trust assumptions
    /// the user explicitly doesn't want by default.
    pub tor_enabled: bool,
    pub tor_socks_port: i64,
    /// Comma-separated 2-letter country codes wrapped in braces, e.g.
    /// `"{us},{gb}"`. Empty = tor's default exit selection.
    pub tor_exit_nodes: String,
    /// Same format as `tor_exit_nodes` but for a separate tor instance
    /// dedicated to DNS egress (mirrors Wiregate's two-tor design so
    /// query traffic and content traffic exit through different
    /// circuits / countries).
    pub tor_dns_exit_nodes: String,
    pub tor_use_bridges: bool,
    /// Pluggable transport name: `obfs4` (lyrebird), `snowflake`, or
    /// `webtunnel`. Empty disables PT use.
    pub tor_plugin: String,
    /// Free-form TOML appended to the generated dnscrypt-proxy.toml.
    /// Mirrors `XrayInbound::additional_config` — escape hatch for keys
    /// the UI doesn't model.
    pub additional_config: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Singleton "Telegram MTProxy" inbound — one telemt listener per server.
/// Modelled as a single row keyed on `id = 'mtproxy0'` to match the
/// singleton pattern already used by `interfaces_table` / `xray_inbound`.
///
/// Operators don't write `[access.users]` from this row — telemt has its
/// own runtime user CRUD via `127.0.0.1:9091/v1/users` and per-user
/// records live in `mtproxy_users_table`. This struct only carries the
/// listener-level static settings (port, modes, TLS-front domain, mask,
/// fallback ad_tag).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtproxyInbound {
    pub id: String,
    /// TCP listening port telemt binds. Default 8080 — picked to avoid
    /// the 443 conflict with Xray Reality. Operators on a host with no
    /// Xray inbound can move it back to 443 explicitly.
    pub port: i64,
    /// Public host operators want baked into `tg://proxy?server=…` share
    /// links. Empty means "let telemt auto-detect from the listener IP" —
    /// works on hosts with one public IP, fails on multi-homed setups.
    pub public_host: String,
    /// Public port for the share links. `0` means "use `port`" — set
    /// only when the operator runs a port-forward / load balancer that
    /// exposes a different external port than the listener.
    pub public_port: i64,
    /// TLS-front masking domain. Used for the `secret=ee<32hex><hex(domain)>`
    /// suffix in TLS-mode share links AND as the SNI telemt mirrors when
    /// emulating real TLS records. Default `petrovich.ru` matches the
    /// telemt example config; operators should pick a real, popular,
    /// reachable domain.
    pub tls_domain: String,
    /// Master switch for telemt's `censorship.mask = …` traffic-masking
    /// feature: forward unrecognised connections to a real web server.
    /// Default on — when off, non-MTProto connections are dropped.
    pub mask_enabled: bool,
    /// Classic MTProto framing (no obfuscation prefix). Default off —
    /// trivial DPI detection.
    pub modes_classic: bool,
    /// Secure mode (`dd`-prefix obfuscation). Default off — older
    /// obfuscation, still works but easier to fingerprint than TLS.
    pub modes_secure: bool,
    /// Fake-TLS mode (`ee`-prefix + SNI fronting). Default ON — most
    /// DPI-resistant variant.
    pub modes_tls: bool,
    /// Whether to register with the Telegram middle-proxy network. When
    /// off, telemt acts as a direct relay — clients still work but
    /// official "ads" / sponsored channels won't render.
    pub use_middle_proxy: bool,
    /// Default 32-hex ad_tag from @MTProxybot, used as the global
    /// fallback when a per-user ad_tag isn't set. Empty disables ad-tag
    /// fallback entirely.
    pub ad_tag: String,
    /// Free-form TOML appended to the generated `config.toml`. Mirrors
    /// `XrayInbound::additional_config` — escape hatch for keys the UI
    /// doesn't model (e.g. `metrics_port`, custom listeners).
    pub additional_config: String,
    /// When false the supervisor refuses to spawn telemt. Disabled by
    /// default — operator opts in after picking a TLS domain and port.
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// One MTProxy user. `username` is the key telemt's HTTP API uses;
/// `secret_hex` is the 32-character lowercase-hex secret that becomes
/// the `ee<…>` link suffix. Coffeeblack-vpn is the durable source of truth;
/// the supervisor reconciles this table into telemt via `POST /v1/users`
/// on startup, so a telemt state-file wipe doesn't lose the operator's
/// roster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtproxyUser {
    pub id: i64,
    pub user_id: Option<i64>,
    pub inbound_id: String,
    pub username: String,
    pub secret_hex: String,
    /// Per-user ad_tag override (32 hex chars). When `None`, telemt
    /// falls back to the inbound's `ad_tag` default.
    pub ad_tag: Option<String>,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// Singleton "MasterDnsVPN" inbound — one mdnsvpn server per host.
/// Modelled as a single row keyed on `id = 'mdnsvpn0'`, mirroring the
/// `xray0` / `mtproxy0` pattern.
///
/// MasterDnsVPN is a DNS-tunnel VPN (the upstream Go binary): the server
/// listens on a UDP port (default :53) and parses incoming DNS queries
/// whose QNAME matches one of the configured tunnel domains. It then
/// extracts encrypted TCP fragments out of the labels, reassembles the
/// stream, and forwards via either an internal SOCKS5 dispatcher
/// (`PROTOCOL_TYPE = "SOCKS5"`) or a fixed `FORWARD_IP:FORWARD_PORT`
/// target (`PROTOCOL_TYPE = "TCP"`). Operator owns a real domain and an
/// `NS` delegation that points the tunnel subdomain at this server's
/// public IP — there is no way to short-cut that requirement.
///
/// All clients share the same pre-shared encryption key (stored here as
/// `encryption_key` in lowercase hex). Per-user records in
/// `mdnsvpn_clients_table` are bookkeeping for the share-link UX —
/// MasterDnsVPN itself doesn't have a per-user secret model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MdnsvpnInbound {
    pub id: String,
    /// JSON array of tunnel domains (matches MasterDnsVPN's `DOMAIN = […]`).
    /// Each entry must be the full FQDN that the operator NS-delegated to
    /// this server. e.g. `["v.example.com"]`.
    pub domains: String,
    /// UDP port the mdnsvpn server binds. Default 53. Operators behind a
    /// load balancer can move it but most clients pick public resolvers
    /// that talk to the authoritative on :53, so changing this is unusual.
    pub port: i64,
    /// Bind address — almost always `0.0.0.0`. Stored separately so an
    /// operator who wants to bind a specific interface can do it without
    /// editing `additional_config`.
    pub bind: String,
    /// MasterDnsVPN encryption method:
    ///   0 = None, 1 = XOR, 2 = ChaCha20,
    ///   3 = AES-128-GCM, 4 = AES-192-GCM, 5 = AES-256-GCM.
    /// Must match every client's `DATA_ENCRYPTION_METHOD`. Default 1
    /// (XOR) — matches the upstream sample. Operators handling sensitive
    /// traffic should bump to 5.
    pub encryption_method: i64,
    /// Pre-shared encryption key (lowercase hex). The same value is
    /// written into both `encrypt_key.txt` (read by mdnsvpn server) and
    /// every generated `client_config.toml`. Empty until first
    /// `regenerate-key` admin call.
    pub encryption_key: String,
    /// "SOCKS5" — clients pick the destination per-stream (acts as a
    /// generic egress proxy).
    /// "TCP"    — every client connection forwards to a fixed
    ///            `FORWARD_IP:FORWARD_PORT`. Used for chaining: terminate
    ///            mdnsvpn on this host, hand off to a Shadowsocks /
    ///            other proxy on the next hop.
    pub protocol_type: String,
    /// JSON array of upstream resolvers used to satisfy DNS queries the
    /// client tunnels via `DNS_QUERY_REQ`. Default `["1.1.1.1:53","1.0.0.1:53"]`.
    pub dns_upstream_servers: String,
    /// Used only when `protocol_type = "TCP"`, OR
    /// `protocol_type = "SOCKS5"` AND `use_external_socks5 = true`.
    /// Empty otherwise.
    pub forward_ip: String,
    /// Same usage as `forward_ip`. `0` is the unused-default sentinel.
    pub forward_port: i64,
    /// In SOCKS5 mode, when true the server doesn't connect to the final
    /// destination directly — it chains through another SOCKS5 proxy at
    /// `forward_ip:forward_port`. Useful for upstreaming mdnsvpn to a
    /// Shadowsocks / 3X-UI panel as the README describes.
    pub use_external_socks5: bool,
    /// Username/password for the upstream SOCKS5 proxy (when
    /// `use_external_socks5 = true` and the upstream requires it).
    pub socks5_auth: bool,
    pub socks5_user: String,
    pub socks5_pass: String,
    /// Free-form TOML appended verbatim to the generated
    /// `server_config.toml`. Mirrors `XrayInbound::additional_config` —
    /// escape hatch for keys the UI doesn't model (extra ARQ tunables,
    /// custom MTU bounds, log paths, etc.).
    pub additional_config: String,
    /// When false the supervisor refuses to spawn. Disabled by default —
    /// operator opts in after generating a key, picking a domain, and
    /// confirming the NS delegation is live.
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// One MasterDnsVPN client (peer). Bookkeeping for the share-link UX —
/// coffeeblack-vpn maintains the per-client roster so the admin UI can show
/// "expires", "enabled", and stable download URLs even though MasterDnsVPN
/// itself has no per-user concept (every client uses the singleton
/// `encryption_key`).
///
/// Per-client knobs that *do* differ from the inbound default land in
/// columns of their own (resolvers, listen port, encryption-method
/// override). Anything else lives in `additional_config_toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MdnsvpnClient {
    pub id: i64,
    pub user_id: Option<i64>,
    pub inbound_id: String,
    pub name: String,
    /// Per-client public DNS resolver list as JSON array of strings.
    /// Matches the format of `client_resolvers.txt` (one resolver per
    /// line, but expressed here as JSON for stable storage).
    /// Each entry is one of:
    ///   "8.8.8.8"
    ///   "1.1.1.1:5353"
    ///   "192.168.1.0/30"
    ///   "[2001:4860:4860::8888]:53"
    /// Empty string means "let the operator's default resolver list be
    /// used at config-generation time."
    pub resolvers: String,
    /// Local SOCKS5 listen port the client opens for the user's apps.
    /// Default 18000 — matches MasterDnsVPN's sample. Operators can hand
    /// out different ports per client to make app-side configuration
    /// easier when many users share the same machine.
    pub listen_port: i64,
    /// Local SOCKS5 username for the client-side proxy auth. Empty
    /// disables auth (the share config sets `SOCKS5_AUTH = false`).
    pub socks5_user: String,
    /// Local SOCKS5 password.
    pub socks5_pass: String,
    pub expires_at: Option<String>,
    /// Per-client TOML appended to the generated `client_config.toml`.
    /// Same escape-hatch model as MtproxyInbound::additional_config.
    pub additional_config_toml: Option<String>,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// One Xray (VLESS) peer. The `inbound_id` FK supports multi-inbound
/// later; v1 always points at `'xray0'`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XrayClient {
    pub id: i64,
    pub user_id: Option<i64>,
    pub inbound_id: String,
    pub name: String,
    /// Per-client UUID — goes into `realitySettings.clients[].id` and the
    /// `vless://uuid@…` share URL.
    pub uuid: String,
    /// Per-client Reality short-id (8 hex bytes by default). Pushed into
    /// `realitySettings.shortIds[]` and the `?sid=…` share param.
    pub short_id: String,
    pub expires_at: Option<String>,
    pub additional_config: Option<String>,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneTimeLink {
    pub id: i64,
    pub one_time_link: String,
    pub expires_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Data required to create a new client.
#[derive(Debug, Clone)]
pub struct CreateClientParams {
    pub user_id: Option<i64>,
    pub interface_id: Option<String>,
    pub name: String,
    pub ipv4_address: Option<String>,
    pub ipv6_address: Option<String>,
    pub private_key: String,
    pub public_key: String,
    pub pre_shared_key: Option<String>,
    pub pre_up: Option<String>,
    pub post_up: Option<String>,
    pub pre_down: Option<String>,
    pub post_down: Option<String>,
    pub expires_at: Option<String>,
    pub allowed_ips: Option<String>,
    pub server_allowed_ips: Option<String>,
    pub firewall_ips: Option<String>,
    pub persistent_keepalive: i64,
    pub mtu: i64,
    pub j_c: Option<i64>,
    pub j_min: Option<i64>,
    pub j_max: Option<i64>,
    pub i1: Option<String>,
    pub i2: Option<String>,
    pub i3: Option<String>,
    pub i4: Option<String>,
    pub i5: Option<String>,
    pub dns: Option<String>,
    pub server_endpoint: Option<String>,
    pub advanced_security: Option<bool>,
    pub enabled: bool,
}

/// Data required to insert a new MasterDnsVPN client. The handlers
/// generate sensible defaults for `resolvers` / `listen_port` / etc.
/// when omitted by the caller.
#[derive(Debug, Clone)]
pub struct CreateMdnsvpnClientParams {
    pub user_id: Option<i64>,
    pub inbound_id: String,
    pub name: String,
    pub resolvers: String,
    pub listen_port: i64,
    pub socks5_user: String,
    pub socks5_pass: String,
    pub expires_at: Option<String>,
    pub additional_config_toml: Option<String>,
    pub enabled: bool,
}

/// Data required to insert a new MTProxy user. The 32-hex `secret_hex`
/// is generated by the caller (typically via `rand::OsRng`) so the DB
/// layer never depends on the rng crate.
#[derive(Debug, Clone)]
pub struct CreateMtproxyUserParams {
    pub user_id: Option<i64>,
    pub inbound_id: String,
    pub username: String,
    pub secret_hex: String,
    pub ad_tag: Option<String>,
    pub enabled: bool,
}

/// Data required to create a new user.
#[derive(Debug, Clone)]
pub struct CreateUserParams {
    pub username: String,
    pub password: String,
    pub email: Option<String>,
    pub name: String,
    pub role: i64,
    pub totp_key: Option<String>,
    pub totp_verified: bool,
    pub enabled: bool,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn bool_to_int(b: bool) -> i64 {
    if b { 1 } else { 0 }
}

fn int_to_bool(i: i64) -> bool {
    i != 0
}

/// Check if an IPv4/IPv6 address string is contained in the supplied CIDR.
pub fn ip_in_cidr(ip: &str, cidr: &str) -> bool {
    if let (Ok(net), Ok(addr)) = (cidr.parse::<Ipv4Net>(), ip.parse::<std::net::Ipv4Addr>()) {
        return net.contains(&addr);
    }
    if let (Ok(net), Ok(addr)) = (cidr.parse::<Ipv6Net>(), ip.parse::<std::net::Ipv6Addr>()) {
        return net.contains(&addr);
    }
    false
}

// ---------------------------------------------------------------------------
// from_row constructors
// ---------------------------------------------------------------------------

impl Interface {
    fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self> {
        Ok(Interface {
            name: row.get("name")?,
            device: row.get("device")?,
            port: row.get("port")?,
            private_key: dec(&row.get::<_, String>("private_key")?)?,
            public_key: row.get("public_key")?,
            ipv4_cidr: row.get("ipv4_cidr")?,
            ipv6_cidr: row.get("ipv6_cidr")?,
            mtu: row.get("mtu")?,
            j_c: row.get("j_c")?,
            j_min: row.get("j_min")?,
            j_max: row.get("j_max")?,
            s1: row.get("s1")?,
            s2: row.get("s2")?,
            s3: row.get("s3")?,
            s4: row.get("s4")?,
            h1: row.get("h1")?,
            h2: row.get("h2")?,
            h3: row.get("h3")?,
            h4: row.get("h4")?,
            i1: row.get("i1")?,
            i2: row.get("i2")?,
            i3: row.get("i3")?,
            i4: row.get("i4")?,
            i5: row.get("i5")?,
            // AWG 3 columns arrived after these rows did; `.ok().flatten()`
            // keeps a pre-migration DB readable in the window before
            // apply_migrations() ALTERs them in, exactly like the DNS
            // lockdown trio below.
            header_protection_key: row
                .get::<_, Option<String>>("header_protection_key")
                .ok()
                .flatten()
                .map(|v| dec(&v))
                .transpose()?
                .unwrap_or_default(),
            content_padding_addition: row
                .get("content_padding_addition")
                .unwrap_or_default(),
            rekey_after_time: row.get("rekey_after_time").unwrap_or_default(),
            rekey_timeout: row.get("rekey_timeout").unwrap_or_default(),
            reject_after_time: row.get("reject_after_time").unwrap_or_default(),
            keepalive_timeout: row.get("keepalive_timeout").unwrap_or_default(),
            max_handshake_attempts: row
                .get("max_handshake_attempts")
                .unwrap_or_default(),
            random_trailers: row
                .get::<_, Option<i64>>("random_trailers")
                .ok()
                .flatten()
                .map(int_to_bool)
                .unwrap_or(false),
            disable_cookies: row
                .get::<_, Option<i64>>("disable_cookies")
                .ok()
                .flatten()
                .map(int_to_bool)
                .unwrap_or(false),
            firewall_enabled: int_to_bool(row.get::<_, i64>("firewall_enabled")?),
            // Older DBs (pre DNS-lockdown) may not have these columns yet;
            // default to a disabled / empty configuration so behavior is
            // unchanged on upgrade. apply_migrations() ALTERs them in on
            // boot, so this fallback only matters during the brief window
            // before the first migration pass.
            dns_lockdown: row
                .get::<_, Option<i64>>("dns_lockdown")
                .ok()
                .flatten()
                .map(int_to_bool)
                .unwrap_or(false),
            dns_lockdown_target: row.get("dns_lockdown_target").unwrap_or_default(),
            dns_block_external: row
                .get::<_, Option<i64>>("dns_block_external")
                .ok()
                .flatten()
                .map(int_to_bool)
                .unwrap_or(true),
            // Older DBs may not have this column yet; tolerate it.
            additional_config: row.get("additional_config").unwrap_or_default(),
            enabled: int_to_bool(row.get::<_, i64>("enabled")?),
            created_at: row.get("created_at")?,
            updated_at: row.get("updated_at")?,
        })
    }
}

impl Client {
    fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self> {
        Ok(Client {
            id: row.get("id")?,
            user_id: row.get("user_id")?,
            interface_id: row.get("interface_id")?,
            name: row.get("name")?,
            ipv4_address: row.get("ipv4_address")?,
            ipv6_address: row.get("ipv6_address")?,
            private_key: dec(&row.get::<_, String>("private_key")?)?,
            public_key: row.get("public_key")?,
            pre_shared_key: dec_opt(row.get("pre_shared_key")?)?,
            pre_up: row.get("pre_up")?,
            post_up: row.get("post_up")?,
            pre_down: row.get("pre_down")?,
            post_down: row.get("post_down")?,
            expires_at: row.get("expires_at")?,
            allowed_ips: row.get("allowed_ips")?,
            server_allowed_ips: row.get("server_allowed_ips")?,
            firewall_ips: row.get("firewall_ips")?,
            persistent_keepalive: row.get("persistent_keepalive")?,
            mtu: row.get("mtu")?,
            j_c: row.get("j_c")?,
            j_min: row.get("j_min")?,
            j_max: row.get("j_max")?,
            i1: row.get("i1")?,
            i2: row.get("i2")?,
            i3: row.get("i3")?,
            i4: row.get("i4")?,
            i5: row.get("i5")?,
            dns: row.get("dns")?,
            server_endpoint: row.get("server_endpoint")?,
            // Older DBs (created before the column was added) may not have
            // this column; tolerate the missing-column case by defaulting
            // to None so the [Peer] block omits the key and the kernel
            // auto-detects from the H1 magic header.
            advanced_security: row
                .get::<_, Option<i64>>("advanced_security")
                .ok()
                .flatten()
                .map(int_to_bool),
            // Older DBs may not have this column yet; tolerate it.
            additional_config: row.get::<_, Option<String>>("additional_config").ok().flatten(),
            enabled: int_to_bool(row.get::<_, i64>("enabled")?),
            created_at: row.get("created_at")?,
            updated_at: row.get("updated_at")?,
        })
    }
}

impl Client {
    /// Whether the server still holds this peer's private key.
    ///
    /// Empty rather than NULL is the "not retained" marker: the column is
    /// `NOT NULL` from the original schema and SQLite cannot drop that
    /// constraint without rebuilding the table, so an empty string carries
    /// the meaning instead. Every read goes through here rather than
    /// comparing to `""` at the call site.
    pub fn has_private_key(&self) -> bool {
        !self.private_key.is_empty()
    }
}

impl User {
    fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self> {
        Ok(User {
            id: row.get("id")?,
            username: row.get("username")?,
            password: row.get("password")?,
            email: row.get("email")?,
            name: row.get("name")?,
            role: row.get("role")?,
            // Transparently decrypted on the way out, so no call site has to
            // know whether this instance has encryption configured. A value
            // stored before a key was supplied has no `enc$` prefix and comes
            // back unchanged.
            //
            // A decryption failure is an ERROR, not a `None`. Returning None
            // here would mean the login path sees no TOTP secret, skips the
            // second-factor check entirely, and accepts a password alone —
            // turning a key misconfiguration into a silent 2FA bypass. Failing
            // the whole row load instead means such a user simply cannot
            // authenticate until the key is fixed. Fail closed.
            totp_key: dec_opt(row.get("totp_key")?)?,
            totp_verified: int_to_bool(row.get::<_, i64>("totp_verified")?),
            enabled: int_to_bool(row.get::<_, i64>("enabled")?),
            created_at: row.get("created_at")?,
            updated_at: row.get("updated_at")?,
        })
    }
}

impl UserConfig {
    fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self> {
        Ok(UserConfig {
            id: row.get("id")?,
            default_mtu: row.get("default_mtu")?,
            default_persistent_keepalive: row.get("default_persistent_keepalive")?,
            default_dns: row.get("default_dns")?,
            default_allowed_ips: row.get("default_allowed_ips")?,
            default_j_c: row.get("default_j_c")?,
            default_j_min: row.get("default_j_min")?,
            default_j_max: row.get("default_j_max")?,
            default_i1: row.get("default_i1")?,
            default_i2: row.get("default_i2")?,
            default_i3: row.get("default_i3")?,
            default_i4: row.get("default_i4")?,
            default_i5: row.get("default_i5")?,
            // Older DBs may not have this column yet; tolerate it.
            default_additional_config: row
                .get("default_additional_config")
                .unwrap_or_default(),
            host: row.get("host")?,
            port: row.get("port")?,
        })
    }
}

impl Hooks {
    fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self> {
        Ok(Hooks {
            id: row.get("id")?,
            pre_up: row.get("pre_up")?,
            post_up: row.get("post_up")?,
            pre_down: row.get("pre_down")?,
            post_down: row.get("post_down")?,
            created_at: row.get("created_at")?,
            updated_at: row.get("updated_at")?,
        })
    }
}

impl General {
    fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self> {
        Ok(General {
            id: row.get("id")?,
            setup_step: row.get("setup_step")?,
            session_password: dec(&row.get::<_, String>("session_password")?)?,
            session_timeout: row.get("session_timeout")?,
            metrics_prometheus: int_to_bool(row.get::<_, i64>("metrics_prometheus")?),
            metrics_json: int_to_bool(row.get::<_, i64>("metrics_json")?),
            metrics_password: dec_opt(row.get("metrics_password")?)?,
            // Tolerate the pre-migration shape (see Client::from_row): fall
            // back to the same 90-day default the DDL declares.
            activity_retention_days: row
                .get::<_, i64>("activity_retention_days")
                .unwrap_or(DEFAULT_ACTIVITY_RETENTION_DAYS),
            // Pre-migration rows fall back to the safe mode, not the
            // permissive one: an unreadable setting must never be the reason
            // key material starts being retained.
            private_key_retention: row
                .get::<_, String>("private_key_retention")
                .unwrap_or_else(|_| RETENTION_NEVER.to_string()),
            created_at: row.get("created_at")?,
            updated_at: row.get("updated_at")?,
        })
    }
}

impl OneTimeLink {
    fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self> {
        Ok(OneTimeLink {
            id: row.get("id")?,
            // The struct field carries the *token*, which is what every caller
            // needs (building the /cnf/<token> URL). The column now holds a
            // digest, so the usable value comes from the encrypted copy —
            // falling back to the column itself for rows written before the
            // split, which still hold the plaintext token there.
            one_time_link: match dec_opt(row.get("token_enc").unwrap_or(None))? {
                Some(t) if !t.is_empty() => t,
                _ => row.get("one_time_link")?,
            },
            expires_at: row.get("expires_at")?,
            created_at: row.get("created_at")?,
            updated_at: row.get("updated_at")?,
        })
    }
}

impl XrayInbound {
    fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self> {
        Ok(XrayInbound {
            id: row.get("id")?,
            port: row.get("port")?,
            dest: row.get("dest")?,
            server_names: row.get("server_names")?,
            private_key: dec(&row.get::<_, String>("private_key")?)?,
            public_key: row.get("public_key")?,
            fingerprint_default: row.get("fingerprint_default")?,
            transport: row.get("transport")?,
            xhttp_path: row.get("xhttp_path")?,
            additional_config: row.get("additional_config")?,
            enabled: int_to_bool(row.get::<_, i64>("enabled")?),
            created_at: row.get("created_at")?,
            updated_at: row.get("updated_at")?,
        })
    }
}

impl ProxySettings {
    fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self> {
        Ok(ProxySettings {
            id: row.get("id")?,
            enabled: int_to_bool(row.get::<_, i64>("enabled")?),
            protocol: row.get("protocol")?,
            backend_port: row.get("backend_port")?,
            quic_handshake: int_to_bool(row.get::<_, i64>("quic_handshake")?),
            quic_cert_domain: row.get("quic_cert_domain")?,
            dns_forward: int_to_bool(row.get::<_, i64>("dns_forward")?),
            dns_upstream: row.get("dns_upstream")?,
            additional_config: row.get("additional_config")?,
            max_sessions: row.get("max_sessions")?,
            session_ttl: row.get("session_ttl")?,
            created_at: row.get("created_at")?,
            updated_at: row.get("updated_at")?,
        })
    }
}

impl QqdnsSettings {
    fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self> {
        Ok(QqdnsSettings {
            id: row.get("id")?,
            enabled: int_to_bool(row.get::<_, i64>("enabled")?),
            dns_ips: row.get("dns_ips")?,
            send_domains: row.get("send_domains")?,
            recv_domains: row.get("recv_domains")?,
            send_interface_ip: row.get("send_interface_ip")?,
            receive_interface_ip: row.get("receive_interface_ip")?,
            receive_port: row.get("receive_port")?,
            h_in_address: row.get("h_in_address")?,
            cb_target_port: row.get("cb_target_port")?,
            max_domain_len: row.get("max_domain_len")?,
            max_sub_len: row.get("max_sub_len")?,
            retries: row.get("retries")?,
            send_query_type: row.get("send_query_type")?,
            packets_send_interval_ms: row.get("packets_send_interval_ms")?,
            packets_wait_time_limit_ms: row.get("packets_wait_time_limit_ms")?,
            send_sock_numbers: row.get("send_sock_numbers")?,
            created_at: row.get("created_at")?,
            updated_at: row.get("updated_at")?,
        })
    }
}

impl XrayClient {
    fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self> {
        Ok(XrayClient {
            id: row.get("id")?,
            user_id: row.get("user_id")?,
            inbound_id: row.get("inbound_id")?,
            name: row.get("name")?,
            uuid: dec(&row.get::<_, String>("uuid")?)?,
            short_id: dec(&row.get::<_, String>("short_id")?)?,
            expires_at: row.get("expires_at")?,
            additional_config: row.get("additional_config")?,
            enabled: int_to_bool(row.get::<_, i64>("enabled")?),
            created_at: row.get("created_at")?,
            updated_at: row.get("updated_at")?,
        })
    }
}

impl DnsBundle {
    fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self> {
        Ok(DnsBundle {
            id: row.get("id")?,
            enabled: int_to_bool(row.get::<_, i64>("enabled")?),
            listen_port: row.get("listen_port")?,
            upstream_resolvers: row.get("upstream_resolvers")?,
            require_dnssec: int_to_bool(row.get::<_, i64>("require_dnssec")?),
            require_nolog: int_to_bool(row.get::<_, i64>("require_nolog")?),
            require_nofilter: int_to_bool(row.get::<_, i64>("require_nofilter")?),
            tor_enabled: int_to_bool(row.get::<_, i64>("tor_enabled")?),
            tor_socks_port: row.get("tor_socks_port")?,
            tor_exit_nodes: row.get("tor_exit_nodes")?,
            tor_dns_exit_nodes: row.get("tor_dns_exit_nodes")?,
            tor_use_bridges: int_to_bool(row.get::<_, i64>("tor_use_bridges")?),
            tor_plugin: row.get("tor_plugin")?,
            additional_config: row.get("additional_config")?,
            created_at: row.get("created_at")?,
            updated_at: row.get("updated_at")?,
        })
    }
}

impl MtproxyInbound {
    fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self> {
        Ok(MtproxyInbound {
            id: row.get("id")?,
            port: row.get("port")?,
            public_host: row.get("public_host")?,
            public_port: row.get("public_port")?,
            tls_domain: row.get("tls_domain")?,
            mask_enabled: int_to_bool(row.get::<_, i64>("mask_enabled")?),
            modes_classic: int_to_bool(row.get::<_, i64>("modes_classic")?),
            modes_secure: int_to_bool(row.get::<_, i64>("modes_secure")?),
            modes_tls: int_to_bool(row.get::<_, i64>("modes_tls")?),
            use_middle_proxy: int_to_bool(row.get::<_, i64>("use_middle_proxy")?),
            ad_tag: row.get("ad_tag")?,
            additional_config: row.get("additional_config")?,
            enabled: int_to_bool(row.get::<_, i64>("enabled")?),
            created_at: row.get("created_at")?,
            updated_at: row.get("updated_at")?,
        })
    }
}

impl MdnsvpnInbound {
    fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self> {
        Ok(MdnsvpnInbound {
            id: row.get("id")?,
            domains: row.get("domains")?,
            port: row.get("port")?,
            bind: row.get("bind")?,
            encryption_method: row.get("encryption_method")?,
            encryption_key: dec(&row.get::<_, String>("encryption_key")?)?,
            protocol_type: row.get("protocol_type")?,
            dns_upstream_servers: row.get("dns_upstream_servers")?,
            forward_ip: row.get("forward_ip")?,
            forward_port: row.get("forward_port")?,
            use_external_socks5: int_to_bool(row.get::<_, i64>("use_external_socks5")?),
            socks5_auth: int_to_bool(row.get::<_, i64>("socks5_auth")?),
            socks5_user: row.get("socks5_user")?,
            socks5_pass: dec(&row.get::<_, String>("socks5_pass")?)?,
            additional_config: row.get("additional_config")?,
            enabled: int_to_bool(row.get::<_, i64>("enabled")?),
            created_at: row.get("created_at")?,
            updated_at: row.get("updated_at")?,
        })
    }
}

impl MdnsvpnClient {
    fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self> {
        Ok(MdnsvpnClient {
            id: row.get("id")?,
            user_id: row.get("user_id")?,
            inbound_id: row.get("inbound_id")?,
            name: row.get("name")?,
            resolvers: row.get("resolvers")?,
            listen_port: row.get("listen_port")?,
            socks5_user: row.get("socks5_user")?,
            socks5_pass: dec(&row.get::<_, String>("socks5_pass")?)?,
            expires_at: row.get::<_, Option<String>>("expires_at")?,
            additional_config_toml: row.get::<_, Option<String>>("additional_config_toml")?,
            enabled: int_to_bool(row.get::<_, i64>("enabled")?),
            created_at: row.get("created_at")?,
            updated_at: row.get("updated_at")?,
        })
    }
}

impl MtproxyUser {
    fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self> {
        Ok(MtproxyUser {
            id: row.get("id")?,
            user_id: row.get("user_id")?,
            inbound_id: row.get("inbound_id")?,
            username: row.get("username")?,
            secret_hex: dec(&row.get::<_, String>("secret_hex")?)?,
            // ad_tag is nullable — None means "use the inbound default".
            ad_tag: row.get::<_, Option<String>>("ad_tag")?,
            enabled: int_to_bool(row.get::<_, i64>("enabled")?),
            created_at: row.get("created_at")?,
            updated_at: row.get("updated_at")?,
        })
    }
}

// ---------------------------------------------------------------------------
// SQL DDL – all seven tables with the final schema
// ---------------------------------------------------------------------------

const CREATE_INTERFACES: &str = r#"
CREATE TABLE IF NOT EXISTS interfaces_table (
    name              TEXT PRIMARY KEY,
    device            TEXT NOT NULL,
    port              INTEGER NOT NULL UNIQUE,
    private_key       TEXT NOT NULL,
    public_key        TEXT NOT NULL,
    ipv4_cidr         TEXT NOT NULL,
    ipv6_cidr         TEXT NOT NULL,
    mtu               INTEGER NOT NULL DEFAULT 1420,
    j_c               INTEGER NOT NULL DEFAULT 7,
    j_min             INTEGER NOT NULL DEFAULT 10,
    j_max             INTEGER NOT NULL DEFAULT 1000,
    s1                INTEGER NOT NULL DEFAULT 128,
    s2                INTEGER NOT NULL DEFAULT 56,
    s3                INTEGER,
    s4                INTEGER,
    h1                TEXT NOT NULL DEFAULT '',
    h2                TEXT NOT NULL DEFAULT '',
    h3                TEXT NOT NULL DEFAULT '',
    h4                TEXT NOT NULL DEFAULT '',
    i1                TEXT NOT NULL DEFAULT '',
    i2                TEXT NOT NULL DEFAULT '',
    i3                TEXT NOT NULL DEFAULT '',
    i4                TEXT NOT NULL DEFAULT '',
    i5                TEXT NOT NULL DEFAULT '',
    -- AmneziaWG 3 device knobs. All default to "unset", which renders no
    -- config line at all, so an upgraded deployment's wire format is
    -- byte-identical until an operator turns one on.
    header_protection_key    TEXT NOT NULL DEFAULT '',
    content_padding_addition TEXT NOT NULL DEFAULT '',
    rekey_after_time         TEXT NOT NULL DEFAULT '',
    rekey_timeout            TEXT NOT NULL DEFAULT '',
    reject_after_time        TEXT NOT NULL DEFAULT '',
    keepalive_timeout        TEXT NOT NULL DEFAULT '',
    max_handshake_attempts   TEXT NOT NULL DEFAULT '',
    random_trailers          INTEGER NOT NULL DEFAULT 0,
    disable_cookies          INTEGER NOT NULL DEFAULT 0,
    firewall_enabled  INTEGER NOT NULL DEFAULT 0,
    -- DNS-leak prevention. dns_lockdown turns on the DNAT redirect of all
    -- peer :53/:853 traffic to dns_lockdown_target; dns_block_external adds
    -- a belt-and-braces drop for any DNS query that slipped past the DNAT.
    -- Default off so upgraded DBs preserve previous behaviour.
    dns_lockdown          INTEGER NOT NULL DEFAULT 0,
    dns_lockdown_target   TEXT    NOT NULL DEFAULT '',
    dns_block_external    INTEGER NOT NULL DEFAULT 1,
    additional_config TEXT NOT NULL DEFAULT '',
    enabled           INTEGER NOT NULL DEFAULT 1,
    created_at        TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
)"#;

const CREATE_CLIENTS: &str = r#"
CREATE TABLE IF NOT EXISTS clients_table (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id             INTEGER,
    interface_id        TEXT,
    name                TEXT NOT NULL,
    ipv4_address        TEXT UNIQUE,
    ipv6_address        TEXT UNIQUE,
    private_key         TEXT NOT NULL,
    public_key          TEXT NOT NULL,
    pre_shared_key      TEXT,
    pre_up              TEXT,
    post_up             TEXT,
    pre_down            TEXT,
    post_down           TEXT,
    expires_at          TEXT,
    allowed_ips         TEXT,
    server_allowed_ips  TEXT,
    firewall_ips        TEXT,
    persistent_keepalive INTEGER NOT NULL DEFAULT 0,
    mtu                 INTEGER NOT NULL DEFAULT 1420,
    j_c                 INTEGER,
    j_min               INTEGER,
    j_max               INTEGER,
    i1                  TEXT,
    i2                  TEXT,
    i3                  TEXT,
    i4                  TEXT,
    i5                  TEXT,
    dns                 TEXT,
    server_endpoint     TEXT,
    advanced_security   INTEGER,
    additional_config   TEXT,
    enabled             INTEGER NOT NULL DEFAULT 1,
    -- NOTE: there are deliberately no traffic/activity-accounting columns
    -- here. Per-peer connection history never enters the schema, because
    -- everything in the schema is written to disk when `IN_MEMORY=false`,
    -- and is copied verbatim into the durable snapshot when
    -- `COFFEEBLACK_PERSIST_DB` is set. That history lives in process memory
    -- only — see `src/activity.rs`.
    created_at          TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at          TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id)      REFERENCES users_table(id),
    FOREIGN KEY (interface_id) REFERENCES interfaces_table(name)
)"#;


const CREATE_USERS: &str = r#"
CREATE TABLE IF NOT EXISTS users_table (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT UNIQUE NOT NULL,
    password        TEXT NOT NULL,
    email           TEXT,
    name            TEXT NOT NULL DEFAULT '',
    role            INTEGER NOT NULL DEFAULT 0,
    totp_key        TEXT,
    totp_verified   INTEGER NOT NULL DEFAULT 0,
    totp_last_step  INTEGER NOT NULL DEFAULT 0,
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
)"#;

const CREATE_USER_CONFIGS: &str = r#"
CREATE TABLE IF NOT EXISTS user_configs_table (
    id                              TEXT PRIMARY KEY,
    default_mtu                     INTEGER NOT NULL DEFAULT 1420,
    default_persistent_keepalive    INTEGER NOT NULL DEFAULT 0,
    default_dns                     TEXT NOT NULL DEFAULT '[]',
    default_allowed_ips             TEXT NOT NULL DEFAULT '[]',
    default_j_c                     INTEGER NOT NULL DEFAULT 7,
    default_j_min                   INTEGER NOT NULL DEFAULT 10,
    default_j_max                   INTEGER NOT NULL DEFAULT 1000,
    default_i1                      TEXT NOT NULL DEFAULT '',
    default_i2                      TEXT NOT NULL DEFAULT '',
    default_i3                      TEXT NOT NULL DEFAULT '',
    default_i4                      TEXT NOT NULL DEFAULT '',
    default_i5                      TEXT NOT NULL DEFAULT '',
    default_additional_config       TEXT NOT NULL DEFAULT '',
    host                            TEXT NOT NULL DEFAULT '',
    port                            INTEGER NOT NULL DEFAULT 51820,
    created_at                      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at                      TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (id) REFERENCES interfaces_table(name)
)"#;

const CREATE_HOOKS: &str = r#"
CREATE TABLE IF NOT EXISTS hooks_table (
    id              TEXT PRIMARY KEY,
    pre_up          TEXT NOT NULL DEFAULT '',
    post_up         TEXT NOT NULL DEFAULT '',
    pre_down        TEXT NOT NULL DEFAULT '',
    post_down       TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (id) REFERENCES interfaces_table(name)
)"#;

const CREATE_GENERAL: &str = r#"
CREATE TABLE IF NOT EXISTS general_table (
    id                  INTEGER PRIMARY KEY,
    setup_step          INTEGER NOT NULL DEFAULT 1,
    session_password    TEXT NOT NULL,
    session_timeout     INTEGER NOT NULL DEFAULT 3600,
    metrics_prometheus  INTEGER NOT NULL DEFAULT 0,
    metrics_json        INTEGER NOT NULL DEFAULT 0,
    metrics_password    TEXT,
    -- How many days of per-client activity history the poller keeps in
    -- memory (never on disk — see src/activity.rs). 0 disables collection
    -- entirely *and* makes the poller purge whatever is already held — the
    -- operator's off switch is a real off switch, not just a
    -- stop-writing-more switch.
    -- Keep in step with DEFAULT_ACTIVITY_RETENTION_DAYS; the round-trip
    -- test in tests/activity.rs fails if these two ever drift apart.
    activity_retention_days INTEGER NOT NULL DEFAULT 30,
    -- Whether peer private keys are kept after the config is issued.
    -- 'never' (default) hands the key over exactly once at create time and
    -- stores nothing; 'plaintext' keeps it so the config can be re-rendered.
    -- Instance-wide on purpose — see PRIVATE_KEY_RETENTION_MODES.
    private_key_retention TEXT NOT NULL DEFAULT 'never',
    created_at          TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at          TEXT NOT NULL DEFAULT (datetime('now'))
)"#;

const CREATE_ONE_TIME_LINKS: &str = r#"
CREATE TABLE IF NOT EXISTS one_time_links_table (
    id              INTEGER PRIMARY KEY,
    -- SHA-256 hex of the token, not the token. This column is the lookup
    -- key, so it cannot be randomly encrypted (every write would produce a
    -- different value and `WHERE` would never match). Hashing gives the
    -- same protection for free: the server only ever needs to *recognise* a
    -- token, never to reproduce it.
    one_time_link   TEXT UNIQUE NOT NULL,
    -- The token itself, encrypted, kept solely so an active link can still be
    -- re-displayed in the UI within its short lifetime. Lookup never touches
    -- this column.
    token_enc       TEXT,
    expires_at      TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (id) REFERENCES clients_table(id) ON DELETE CASCADE
)"#;

const CREATE_XRAY_INBOUND: &str = r#"
CREATE TABLE IF NOT EXISTS xray_inbound_table (
    id                   TEXT PRIMARY KEY,
    port                 INTEGER NOT NULL DEFAULT 443,
    dest                 TEXT NOT NULL DEFAULT 'www.microsoft.com:443',
    server_names         TEXT NOT NULL DEFAULT '["www.microsoft.com"]',
    private_key          TEXT NOT NULL DEFAULT '',
    public_key           TEXT NOT NULL DEFAULT '',
    fingerprint_default  TEXT NOT NULL DEFAULT 'chrome',
    -- Stream transport multiplexed on top of Reality. Either 'tcp' (the
    -- classic VLESS+Vision stack) or 'xhttp' (amnezia-client/#2339 —
    -- HTTP-framed with a secret routing path). Vision flow is dropped
    -- when transport is xhttp; the two are mutually exclusive.
    transport            TEXT NOT NULL DEFAULT 'tcp',
    -- Secret '/' + 32 hex chars path used by xhttpSettings. Empty
    -- when transport is tcp; persisted across restarts so client
    -- configs and the server's expected path don't drift.
    xhttp_path           TEXT NOT NULL DEFAULT '',
    additional_config    TEXT NOT NULL DEFAULT '',
    enabled              INTEGER NOT NULL DEFAULT 0,
    created_at           TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at           TEXT NOT NULL DEFAULT (datetime('now'))
)"#;

const CREATE_XRAY_CLIENTS: &str = r#"
CREATE TABLE IF NOT EXISTS xray_clients_table (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id             INTEGER,
    inbound_id          TEXT NOT NULL DEFAULT 'xray0',
    name                TEXT NOT NULL,
    uuid                TEXT NOT NULL UNIQUE,
    short_id            TEXT NOT NULL UNIQUE,
    expires_at          TEXT,
    additional_config   TEXT,
    enabled             INTEGER NOT NULL DEFAULT 1,
    created_at          TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at          TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id)    REFERENCES users_table(id),
    FOREIGN KEY (inbound_id) REFERENCES xray_inbound_table(id)
)"#;

// proxy_settings_table — singleton (id always 'proxy0'). Configuration
// for the in-process DPI-imitation proxy that fronts the AmneziaWG UDP
// port. Disabled by default (AmneziaWG keeps the public port directly).
// Mirrors xray_inbound_table's singleton pattern. Column-level defaults
// give QUIC imitation with the stateful handshake responder on, DNS
// forwarding off, and backend_port auto (0 → interface.port ± 1).
const CREATE_PROXY_SETTINGS: &str = r#"
CREATE TABLE IF NOT EXISTS proxy_settings_table (
    id                TEXT PRIMARY KEY,
    enabled           INTEGER NOT NULL DEFAULT 0,
    protocol          TEXT NOT NULL DEFAULT 'quic',
    backend_port      INTEGER NOT NULL DEFAULT 0,
    quic_handshake    INTEGER NOT NULL DEFAULT 1,
    quic_cert_domain  TEXT NOT NULL DEFAULT 'www.cloudflare.com',
    dns_forward       INTEGER NOT NULL DEFAULT 0,
    dns_upstream      TEXT NOT NULL DEFAULT '1.1.1.1:53',
    additional_config TEXT NOT NULL DEFAULT '',
    max_sessions      INTEGER NOT NULL DEFAULT 2048,
    session_ttl       INTEGER NOT NULL DEFAULT 120,
    created_at        TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
)"#;

// qqdns_settings_table — singleton (id always 'qqdns0'). Configuration for
// the in-process QQ-Tunnel UDP-over-DNS transport (server side). Disabled
// by default. Mirrors proxy_settings_table's singleton pattern. JSON-array
// columns default to '[]'; the operator fills them from the admin UI.
const CREATE_QQDNS_SETTINGS: &str = r#"
CREATE TABLE IF NOT EXISTS qqdns_settings_table (
    id                          TEXT PRIMARY KEY,
    enabled                     INTEGER NOT NULL DEFAULT 0,
    dns_ips                     TEXT NOT NULL DEFAULT '[]',
    send_domains                TEXT NOT NULL DEFAULT '[]',
    recv_domains                TEXT NOT NULL DEFAULT '[]',
    send_interface_ip           TEXT NOT NULL DEFAULT '',
    receive_interface_ip        TEXT NOT NULL DEFAULT '0.0.0.0',
    receive_port                INTEGER NOT NULL DEFAULT 53,
    h_in_address                TEXT NOT NULL DEFAULT '127.0.0.1:10443',
    cb_target_port             INTEGER NOT NULL DEFAULT 0,
    max_domain_len              INTEGER NOT NULL DEFAULT 253,
    max_sub_len                 INTEGER NOT NULL DEFAULT 63,
    retries                     INTEGER NOT NULL DEFAULT 1,
    send_query_type             INTEGER NOT NULL DEFAULT 1,
    packets_send_interval_ms    INTEGER NOT NULL DEFAULT 1,
    packets_wait_time_limit_ms  INTEGER NOT NULL DEFAULT 1000,
    send_sock_numbers           INTEGER NOT NULL DEFAULT 512,
    created_at                  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at                  TEXT NOT NULL DEFAULT (datetime('now'))
)"#;

// dns_bundle_table — singleton (id always 'dns0'). Configuration for the
// bundled dnscrypt-proxy + (opt-in) tor stack. Defaults match the
// "minimum risk" posture: dnscrypt off, tor off. The supervisor reads
// this row at startup and after every admin POST.
//
// Mirrors xray_inbound_table's singleton pattern. additional_config is a
// free-form TOML fragment merged into the generated dnscrypt-proxy.toml
// — escape hatch for keys the UI doesn't model (e.g. custom server
// stamps, advanced caching tuning).
const CREATE_DNS_BUNDLE: &str = r#"
CREATE TABLE IF NOT EXISTS dns_bundle_table (
    id                   TEXT PRIMARY KEY,
    -- Master switch — ON by default. Fresh deployments get
    -- dnscrypt-proxy running on the listen port immediately, with
    -- DNSSEC + no-log requirements enforced; the WireGuard side's
    -- generated configs point peers at it. Operators who don't want
    -- a bundled resolver flip this off in the admin UI; existing
    -- DBs that already have an explicit setting keep it (column
    -- defaults only apply on INSERT, not on subsequent boots).
    enabled              INTEGER NOT NULL DEFAULT 1,
    listen_port          INTEGER NOT NULL DEFAULT 5353,
    upstream_resolvers   TEXT NOT NULL DEFAULT '[]',
    require_dnssec       INTEGER NOT NULL DEFAULT 1,
    require_nolog        INTEGER NOT NULL DEFAULT 1,
    require_nofilter     INTEGER NOT NULL DEFAULT 0,
    -- Tor: opt-in, off by default — even when the master switch is
    -- on. Tor adds latency, exit-node trust assumptions, and
    -- BridgeDB network calls — operators who want it flip this
    -- explicitly in the admin UI. (See feedback_dns_bundle.md
    -- memory: tor stays off independent of dnscrypt-proxy.)
    tor_enabled          INTEGER NOT NULL DEFAULT 0,
    tor_socks_port       INTEGER NOT NULL DEFAULT 9053,
    tor_exit_nodes       TEXT NOT NULL DEFAULT '',
    tor_dns_exit_nodes   TEXT NOT NULL DEFAULT '',
    tor_use_bridges      INTEGER NOT NULL DEFAULT 0,
    tor_plugin           TEXT NOT NULL DEFAULT '',
    additional_config    TEXT NOT NULL DEFAULT '',
    created_at           TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at           TEXT NOT NULL DEFAULT (datetime('now'))
)"#;

// mtproxy_inbound_table — singleton (id always 'mtproxy0'). Configuration
// for the bundled telemt MTProxy server. Defaults match the user's setup
// choice: port 8080, Fake-TLS only, masking on, disabled until the
// operator opts in. Mirrors xray_inbound_table's singleton pattern.
//
// Per-user records (the username → 32-hex-secret map telemt's HTTP API
// manages at runtime) live in mtproxy_users_table. We don't write
// [access.users] into telemt's config.toml — the supervisor reconciles
// the durable DB roster into telemt via POST /v1/users on startup.
const CREATE_MTPROXY_INBOUND: &str = r#"
CREATE TABLE IF NOT EXISTS mtproxy_inbound_table (
    id                   TEXT PRIMARY KEY,
    port                 INTEGER NOT NULL DEFAULT 8080,
    public_host          TEXT NOT NULL DEFAULT '',
    public_port          INTEGER NOT NULL DEFAULT 0,
    tls_domain           TEXT NOT NULL DEFAULT 'petrovich.ru',
    mask_enabled         INTEGER NOT NULL DEFAULT 1,
    modes_classic        INTEGER NOT NULL DEFAULT 0,
    modes_secure         INTEGER NOT NULL DEFAULT 0,
    modes_tls            INTEGER NOT NULL DEFAULT 1,
    use_middle_proxy     INTEGER NOT NULL DEFAULT 1,
    ad_tag               TEXT NOT NULL DEFAULT '',
    additional_config    TEXT NOT NULL DEFAULT '',
    enabled              INTEGER NOT NULL DEFAULT 0,
    created_at           TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at           TEXT NOT NULL DEFAULT (datetime('now'))
)"#;

// mtproxy_users_table — durable roster. UNIQUE(username) so the
// reconciler can pick rows up by name without ambiguity. user_id is
// nullable so an MTProxy user doesn't have to map back to an admin
// login user (mirrors xray_clients_table.user_id).
const CREATE_MTPROXY_USERS: &str = r#"
CREATE TABLE IF NOT EXISTS mtproxy_users_table (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id             INTEGER,
    inbound_id          TEXT NOT NULL DEFAULT 'mtproxy0',
    username            TEXT NOT NULL UNIQUE,
    secret_hex          TEXT NOT NULL,
    ad_tag              TEXT,
    enabled             INTEGER NOT NULL DEFAULT 1,
    created_at          TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at          TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id)    REFERENCES users_table(id),
    FOREIGN KEY (inbound_id) REFERENCES mtproxy_inbound_table(id)
)"#;

// mdnsvpn_inbound_table — singleton MasterDnsVPN server config. Defaults
// match the upstream sample (XOR encryption on, SOCKS5 mode, UDP/53,
// 1.1.1.1 upstreams). `enabled=0` keeps the supervisor from spawning
// until the operator explicitly opts in (a generated key + a real
// NS-delegated domain are both required).
const CREATE_MDNSVPN_INBOUND: &str = r#"
CREATE TABLE IF NOT EXISTS mdnsvpn_inbound_table (
    id                      TEXT PRIMARY KEY,
    domains                 TEXT NOT NULL DEFAULT '[]',
    port                    INTEGER NOT NULL DEFAULT 53,
    bind                    TEXT NOT NULL DEFAULT '0.0.0.0',
    -- 5 = AES-256-GCM. Upstream's own sample defaults to 1 (XOR against a
    -- repeating key), which is neither confidential nor authenticated — an
    -- active on-path attacker can tamper with tunnel payloads undetected.
    -- We default new installs to the strongest AEAD instead. No key format
    -- change is implied: upstream derives the AES key as sha256(rawKey) for
    -- methods 2 and 5, so our 32-hex-char keys work unchanged.
    --
    -- Deliberately NOT retrofitted onto existing rows by a migration: the
    -- method is baked into every client config already handed out, so
    -- flipping it under a live deployment would break every peer. Existing
    -- installs are warned instead (see api/mdnsvpn.rs securityWarnings).
    encryption_method       INTEGER NOT NULL DEFAULT 5,
    encryption_key          TEXT NOT NULL DEFAULT '',
    protocol_type           TEXT NOT NULL DEFAULT 'SOCKS5',
    dns_upstream_servers    TEXT NOT NULL DEFAULT '["1.1.1.1:53","1.0.0.1:53"]',
    forward_ip              TEXT NOT NULL DEFAULT '',
    forward_port            INTEGER NOT NULL DEFAULT 0,
    use_external_socks5     INTEGER NOT NULL DEFAULT 0,
    socks5_auth             INTEGER NOT NULL DEFAULT 0,
    socks5_user             TEXT NOT NULL DEFAULT '',
    socks5_pass             TEXT NOT NULL DEFAULT '',
    additional_config       TEXT NOT NULL DEFAULT '',
    enabled                 INTEGER NOT NULL DEFAULT 0,
    created_at              TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at              TEXT NOT NULL DEFAULT (datetime('now'))
)"#;

// mdnsvpn_clients_table — per-client bookkeeping. MasterDnsVPN itself
// has no per-user secret; every client shares the singleton
// `encryption_key` on the inbound. This table exists so the admin UI
// can hand out stable per-user share-URL slots, expire individual
// configs, and toggle them on/off without affecting the rest.
//
// UNIQUE(name) means two clients can't have the same display name —
// keeps the per-name download URLs unambiguous.
const CREATE_MDNSVPN_CLIENTS: &str = r#"
CREATE TABLE IF NOT EXISTS mdnsvpn_clients_table (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id                 INTEGER,
    inbound_id              TEXT NOT NULL DEFAULT 'mdnsvpn0',
    name                    TEXT NOT NULL UNIQUE,
    resolvers               TEXT NOT NULL DEFAULT '',
    listen_port             INTEGER NOT NULL DEFAULT 18000,
    socks5_user             TEXT NOT NULL DEFAULT '',
    socks5_pass             TEXT NOT NULL DEFAULT '',
    expires_at              TEXT,
    additional_config_toml  TEXT,
    enabled                 INTEGER NOT NULL DEFAULT 1,
    created_at              TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at              TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id)    REFERENCES users_table(id),
    FOREIGN KEY (inbound_id) REFERENCES mdnsvpn_inbound_table(id)
)"#;

// ---------------------------------------------------------------------------
// Hook templates
// ---------------------------------------------------------------------------

// Native nftables hooks. All rules live inside one `inet coffeeblack`
// table so PostDown can wipe everything atomically with a single
// `nft delete table`. Per-client filtering rules go into the empty
// `wg-clients` chain — those are populated separately by `firewall.rs`
// via `nft -f -` transactions when the firewall toggle is enabled.
//
// Forward-chain policy is `accept`. With no jump rules in place, all
// traffic forwards as before. When firewall.rs adds the jumps, traffic
// from the AWG interface diverts into `wg-clients`, hits per-peer
// accept rules or the final `drop`, and only returns to forward (and
// thus the accept policy) for explicitly-allowed flows.
pub(crate) const POST_UP_TEMPLATE: &str = concat!(
    "nft add table inet coffeeblack;",
    " nft 'add chain inet coffeeblack forward { type filter hook forward priority filter; policy accept; }';",
    " nft 'add chain inet coffeeblack nat-postrouting { type nat hook postrouting priority srcnat; }';",
    " nft 'add chain inet coffeeblack filter-input { type filter hook input priority filter; policy accept; }';",
    " nft 'add chain inet coffeeblack wg-clients';",
    " nft add rule inet coffeeblack nat-postrouting ip saddr {{ipv4Cidr}} oifname \"{{device}}\" masquerade;",
    " nft add rule inet coffeeblack nat-postrouting ip6 saddr {{ipv6Cidr}} oifname \"{{device}}\" masquerade;",
    " nft add rule inet coffeeblack filter-input udp dport {{port}} accept;",
);

// One-line teardown: deleting the table atomically removes every chain
// and every rule we added in PostUp, plus anything firewall.rs put in
// the `wg-clients` chain. The `2>/dev/null || true` keeps awg-quick
// from aborting interface bring-down if the table is already gone
// (e.g. after a host reboot where state is lost but PostDown still runs).
pub(crate) const POST_DOWN_TEMPLATE: &str =
    "nft delete table inet coffeeblack 2>/dev/null || true";

// ---------------------------------------------------------------------------
// Initialisation
// ---------------------------------------------------------------------------

fn create_tables(conn: &Connection) -> Result<()> {
    conn.execute_batch("PRAGMA journal_mode=WAL;")?;
    conn.execute_batch("PRAGMA foreign_keys=ON;")?;
    conn.execute_batch(CREATE_INTERFACES)?;
    conn.execute_batch(CREATE_CLIENTS)?;
    conn.execute_batch(CREATE_USERS)?;
    conn.execute_batch(CREATE_USER_CONFIGS)?;
    conn.execute_batch(CREATE_HOOKS)?;
    conn.execute_batch(CREATE_GENERAL)?;
    conn.execute_batch(CREATE_ONE_TIME_LINKS)?;
    conn.execute_batch(CREATE_DNS_BUNDLE)?;
    conn.execute_batch(CREATE_XRAY_INBOUND)?;
    conn.execute_batch(CREATE_XRAY_CLIENTS)?;
    conn.execute_batch(CREATE_PROXY_SETTINGS)?;
    conn.execute_batch(CREATE_QQDNS_SETTINGS)?;
    conn.execute_batch(CREATE_MTPROXY_INBOUND)?;
    conn.execute_batch(CREATE_MTPROXY_USERS)?;
    conn.execute_batch(CREATE_MDNSVPN_INBOUND)?;
    conn.execute_batch(CREATE_MDNSVPN_CLIENTS)?;
    apply_migrations(conn)?;
    Ok(())
}

/// Apply additive schema migrations needed for upgrading from an older
/// coffeeblack-vpn / awg-easy DB. Each migration is idempotent — checking column
/// existence via `PRAGMA table_info` before issuing ALTER TABLE.
fn apply_migrations(conn: &Connection) -> Result<()> {
    if !column_exists(conn, "clients_table", "advanced_security")? {
        conn.execute_batch(
            "ALTER TABLE clients_table ADD COLUMN advanced_security INTEGER",
        )?;
        crate::info!(
            "DB migration: added clients_table.advanced_security (per-peer AdvancedSecurity flag)"
        );
    }
    // totp_last_step: highest TOTP timestep already consumed for this user.
    // Enables single-use enforcement so a captured code can't be replayed
    // within its ±1-window validity.
    if !column_exists(conn, "users_table", "totp_last_step")? {
        conn.execute_batch(
            "ALTER TABLE users_table ADD COLUMN totp_last_step INTEGER NOT NULL DEFAULT 0",
        )?;
        crate::info!("DB migration: added users_table.totp_last_step (TOTP replay guard)");
    }
    // additional_config: free-form append-to-config text. Mirrors amnezia-client's
    // additionalServerConfig / additionalClientConfig escape hatch — operators
    // need a place to drop in lines awg-quick understands but the UI doesn't
    // model (e.g. `Table = off`, `FwMark = …`).
    if !column_exists(conn, "interfaces_table", "additional_config")? {
        conn.execute_batch(
            "ALTER TABLE interfaces_table ADD COLUMN additional_config TEXT NOT NULL DEFAULT ''",
        )?;
        crate::info!(
            "DB migration: added interfaces_table.additional_config (free-form Interface append)"
        );
    }
    if !column_exists(conn, "clients_table", "additional_config")? {
        conn.execute_batch(
            "ALTER TABLE clients_table ADD COLUMN additional_config TEXT",
        )?;
        crate::info!(
            "DB migration: added clients_table.additional_config (per-peer free-form append)"
        );
    }
    if !column_exists(conn, "user_configs_table", "default_additional_config")? {
        conn.execute_batch(
            "ALTER TABLE user_configs_table ADD COLUMN default_additional_config TEXT NOT NULL DEFAULT ''",
        )?;
        crate::info!(
            "DB migration: added user_configs_table.default_additional_config"
        );
    }
    // AmneziaWG 3 device knobs. Same column-at-a-time shape as the DNS
    // trio below: every one defaults to "unset", so an upgraded DB keeps
    // rendering exactly the config it rendered before until an operator
    // turns one on.
    for (col, ddl) in [
        ("header_protection_key", "TEXT NOT NULL DEFAULT ''"),
        ("content_padding_addition", "TEXT NOT NULL DEFAULT ''"),
        ("rekey_after_time", "TEXT NOT NULL DEFAULT ''"),
        ("rekey_timeout", "TEXT NOT NULL DEFAULT ''"),
        ("reject_after_time", "TEXT NOT NULL DEFAULT ''"),
        ("keepalive_timeout", "TEXT NOT NULL DEFAULT ''"),
        ("max_handshake_attempts", "TEXT NOT NULL DEFAULT ''"),
        ("random_trailers", "INTEGER NOT NULL DEFAULT 0"),
        ("disable_cookies", "INTEGER NOT NULL DEFAULT 0"),
    ] {
        if !column_exists(conn, "interfaces_table", col)? {
            conn.execute_batch(&format!(
                "ALTER TABLE interfaces_table ADD COLUMN {col} {ddl}"
            ))?;
            crate::info!("DB migration: added interfaces_table.{col} (AmneziaWG 3)");
        }
    }

    // DNS-leak-prevention columns. Three separate ALTERs — SQLite ALTER
    // doesn't support multiple ADD COLUMN in one statement, and column-by-
    // column existence checks let an upgrade that crashed mid-way through
    // resume cleanly on the next boot.
    if !column_exists(conn, "interfaces_table", "dns_lockdown")? {
        conn.execute_batch(
            "ALTER TABLE interfaces_table ADD COLUMN dns_lockdown INTEGER NOT NULL DEFAULT 0",
        )?;
        crate::info!(
            "DB migration: added interfaces_table.dns_lockdown (DNS leak-prevention master switch)"
        );
    }
    if !column_exists(conn, "interfaces_table", "dns_lockdown_target")? {
        conn.execute_batch(
            "ALTER TABLE interfaces_table ADD COLUMN dns_lockdown_target TEXT NOT NULL DEFAULT ''",
        )?;
        crate::info!(
            "DB migration: added interfaces_table.dns_lockdown_target (resolver IP DNAT redirects to)"
        );
    }
    if !column_exists(conn, "interfaces_table", "dns_block_external")? {
        conn.execute_batch(
            "ALTER TABLE interfaces_table ADD COLUMN dns_block_external INTEGER NOT NULL DEFAULT 1",
        )?;
        crate::info!(
            "DB migration: added interfaces_table.dns_block_external (drop residual peer :53/:853 leaks)"
        );
    }
    // Xray transport + xhttp routing path. Tracks amnezia-client/#2339,
    // which lets operators flip a single inbound between classic
    // VLESS+Vision (transport='tcp') and HTTP-framed (transport='xhttp').
    // Defaults preserve the historical behaviour — every existing row
    // keeps 'tcp' transport with an empty path.
    if !column_exists(conn, "xray_inbound_table", "transport")? {
        conn.execute_batch(
            "ALTER TABLE xray_inbound_table ADD COLUMN transport TEXT NOT NULL DEFAULT 'tcp'",
        )?;
        crate::info!(
            "DB migration: added xray_inbound_table.transport (tcp|xhttp)"
        );
    }
    if !column_exists(conn, "xray_inbound_table", "xhttp_path")? {
        conn.execute_batch(
            "ALTER TABLE xray_inbound_table ADD COLUMN xhttp_path TEXT NOT NULL DEFAULT ''",
        )?;
        crate::info!(
            "DB migration: added xray_inbound_table.xhttp_path (xhttpSettings.path)"
        );
    }
    // DPI-proxy session caps. Bound the spoofed-source fd/session-exhaustion
    // blast radius; conservative defaults, operator-tunable in the admin UI.
    if !column_exists(conn, "proxy_settings_table", "max_sessions")? {
        conn.execute_batch(
            "ALTER TABLE proxy_settings_table ADD COLUMN max_sessions INTEGER NOT NULL DEFAULT 2048",
        )?;
        crate::info!("DB migration: added proxy_settings_table.max_sessions");
    }
    if !column_exists(conn, "proxy_settings_table", "session_ttl")? {
        conn.execute_batch(
            "ALTER TABLE proxy_settings_table ADD COLUMN session_ttl INTEGER NOT NULL DEFAULT 120",
        )?;
        crate::info!("DB migration: added proxy_settings_table.session_ttl");
    }
    if !column_exists(conn, "one_time_links_table", "token_enc")? {
        conn.execute_batch("ALTER TABLE one_time_links_table ADD COLUMN token_enc TEXT")?;
        crate::info!(
            "DB migration: added one_time_links_table.token_enc \
             (tokens are now stored hashed, with an encrypted copy for display)"
        );
    }
    if !column_exists(conn, "general_table", "private_key_retention")? {
        // Existing installs created every peer in what is now 'plaintext'
        // mode, and their rows still hold those keys. Defaulting the column
        // to 'plaintext' would be the honest description of that state, but
        // it would also silently keep the weaker behaviour forever on every
        // upgraded box. Default to 'never' instead — new peers stop leaving
        // key material behind immediately, and the admin UI offers a purge
        // for the keys already stored.
        conn.execute_batch(&format!(
            "ALTER TABLE general_table ADD COLUMN private_key_retention \
             TEXT NOT NULL DEFAULT '{RETENTION_NEVER}'"
        ))?;
        crate::info!(
            "DB migration: added general_table.private_key_retention \
             (default '{RETENTION_NEVER}' — new peers no longer store private keys)"
        );
    }
    if !column_exists(conn, "general_table", "activity_retention_days")? {
        conn.execute_batch(&format!(
            "ALTER TABLE general_table ADD COLUMN activity_retention_days \
             INTEGER NOT NULL DEFAULT {DEFAULT_ACTIVITY_RETENTION_DAYS}"
        ))?;
        crate::info!(
            "DB migration: added general_table.activity_retention_days \
             (activity history window, 0 = disabled)"
        );
    }
    // One-shot: replace the iptables-flavoured default hooks from earlier
    // versions with the native nftables equivalents. Only fires when the
    // stored post_up still contains "iptables" — operators who already
    // customised their hooks (with `nft`, with no commands, etc.) get
    // left alone. Idempotent because we re-check on every boot.
    let needs_nft_hooks: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM hooks_table \
             WHERE id = 'cb0' AND post_up LIKE '%iptables%')",
            [],
            |r| r.get::<_, i64>(0).map(|v| v != 0),
        )
        .unwrap_or(false);
    if needs_nft_hooks {
        conn.execute(
            "UPDATE hooks_table SET post_up = ?1, post_down = ?2 WHERE id = 'cb0'",
            params![POST_UP_TEMPLATE, POST_DOWN_TEMPLATE],
        )?;
        crate::info!(
            "DB migration: replaced legacy iptables hooks with native nftables defaults"
        );
    }

    // Backfill singleton rows for tables that may have been added in a
    // later release than this DB was first seeded against. INSERT OR
    // IGNORE makes this safe to run on every boot — the row only lands
    // when it's missing. The original `seed_if_empty` path early-exits
    // when general_table is populated, which used to mean an upgraded
    // DB never saw new singleton rows (e.g. xray_inbound).
    ensure_singleton_rows(conn)?;
    Ok(())
}

/// Idempotently ensure every singleton table has its default row.
/// Pulled out of `seed_if_empty` so the migration step can call it
/// even on already-populated DBs.
fn ensure_singleton_rows(conn: &Connection) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO xray_inbound_table \
         (id, port, dest, server_names, fingerprint_default, enabled) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            "xray0",
            443,
            "www.microsoft.com:443",
            r#"["www.microsoft.com"]"#,
            "chrome",
            0,
        ],
    )?;
    // dns_bundle: every field defaults to its column-level default in
    // CREATE_DNS_BUNDLE — most-conservative posture (everything off).
    // Operators flip the toggles explicitly; tor stays off independent
    // of the master enable.
    conn.execute(
        "INSERT OR IGNORE INTO dns_bundle_table (id) VALUES (?1)",
        params!["dns0"],
    )?;
    // mtproxy_inbound: defaults match the operator-chosen posture (port
    // 8080, Fake-TLS only, masking on, disabled). All three toggles
    // (modes_*) and `enabled` get column-level defaults from
    // CREATE_MTPROXY_INBOUND, so a bare INSERT is enough.
    conn.execute(
        "INSERT OR IGNORE INTO mtproxy_inbound_table (id) VALUES (?1)",
        params!["mtproxy0"],
    )?;
    // mdnsvpn_inbound: every field defaults to its column-level default
    // in CREATE_MDNSVPN_INBOUND — encryption method 1 (XOR), no key
    // until the operator regenerates one, no domains until the operator
    // sets the NS-delegated FQDN. `enabled = 0`.
    conn.execute(
        "INSERT OR IGNORE INTO mdnsvpn_inbound_table (id) VALUES (?1)",
        params!["mdnsvpn0"],
    )?;
    Ok(())
}

fn column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    // SQLite's `PRAGMA table_info(<name>)` returns one row per column; the
    // `name` field is the second column.
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get("name")?;
        if name == column {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Every user table in the live schema.
///
/// Schema introspection exists so the "activity history is never persisted"
/// guarantee can be asserted against the database itself rather than against
/// the current call graph — a future table or column would otherwise
/// reintroduce on-disk history silently.
pub fn table_names() -> Result<Vec<String>> {
    let c = conn();
    let mut stmt = c.prepare(
        "SELECT name FROM sqlite_master WHERE type = 'table' \
         AND name NOT LIKE 'sqlite_%' ORDER BY name",
    )?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// Every column of `table`, in declaration order. See [`table_names`].
pub fn column_names(table: &str) -> Result<Vec<String>> {
    let c = conn();
    // `table` is a caller-supplied identifier and cannot be bound as a
    // parameter in a PRAGMA, so reject anything that is not a plain
    // identifier rather than interpolating it blind.
    if !table.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_') {
        return Err(anyhow!("invalid table name: {table}"));
    }
    let mut stmt = c.prepare(&format!("PRAGMA table_info({table})"))?;
    let rows = stmt.query_map([], |row| row.get::<_, String>("name"))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// Read `users_table.totp_key` exactly as stored, bypassing the decryption
/// that [`User::from_row`] applies.
///
/// Exists so the encryption boundary can be asserted rather than assumed: a
/// test that only ever reads through the mapper cannot tell an encrypted
/// column from a plaintext one, because the mapper makes them look identical
/// — which is the whole point of the mapper and precisely why it cannot be
/// the thing that verifies itself.
pub fn raw_totp_key(user_id: i64) -> Result<Option<String>> {
    let c = conn();
    let v: Option<String> = c
        .query_row(
            "SELECT totp_key FROM users_table WHERE id = ?1",
            params![user_id],
            |row| row.get(0),
        )
        .optional()?
        .flatten();
    Ok(v)
}

/// Read every non-empty value of `table.column` exactly as stored, bypassing
/// the decryption the row mappers apply. See [`raw_totp_key`] for why this has
/// to exist: a test that reads through a mapper cannot distinguish an
/// encrypted column from a plaintext one.
pub fn raw_column(table: &str, column: &str) -> Result<Vec<String>> {
    if !ident_ok(table) || !ident_ok(column) {
        return Err(anyhow!("invalid identifier: {table}.{column}"));
    }
    let c = conn();
    let mut stmt = c.prepare(&format!(
        "SELECT {column} FROM {table} WHERE {column} IS NOT NULL AND {column} <> ''"
    ))?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// Write `table.column` verbatim for every row, bypassing encryption.
///
/// Test support only: it manufactures the pre-encryption shape that
/// [`encrypt_plaintext_secrets`] is meant to upgrade.
#[doc(hidden)]
pub fn force_raw_column(table: &str, column: &str, value: &str) -> Result<()> {
    if !ident_ok(table) || !ident_ok(column) {
        return Err(anyhow!("invalid identifier: {table}.{column}"));
    }
    let c = conn();
    c.execute(&format!("UPDATE {table} SET {column} = ?1"), params![value])?;
    Ok(())
}

/// Plain-identifier guard for the few places a table or column name has to be
/// interpolated (PRAGMA and dynamic SELECT cannot bind identifiers).
fn ident_ok(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Write `users_table.totp_key` verbatim, bypassing encryption.
///
/// Test support only: it manufactures the pre-encryption row shape that
/// [`encrypt_plaintext_totp_secrets`] is meant to upgrade. Nothing in the
/// service calls it — writes go through [`update_user`], which encrypts.
#[doc(hidden)]
pub fn force_raw_totp_key(user_id: i64, value: &str) -> Result<()> {
    let c = conn();
    c.execute(
        "UPDATE users_table SET totp_key = ?1 WHERE id = ?2",
        params![value, user_id],
    )?;
    Ok(())
}

/// Seed default rows when general_table is empty (first run).
fn seed_if_empty(conn: &Connection) -> Result<()> {
    let count: i64 =
        conn.query_row("SELECT COUNT(*) FROM general_table", [], |r| r.get(0))?;
    if count > 0 {
        return Ok(());
    }

    // Generate a random 512-character session password (256 bytes hex-encoded).
    let mut rand_bytes = [0u8; 256];
    crate::rng::fill(&mut rand_bytes);
    let session_pass = crate::encoding::hex_encode(rand_bytes);

    // interfaces_table default
    conn.execute(
        "INSERT OR IGNORE INTO interfaces_table \
         (name, device, port, private_key, public_key, ipv4_cidr, ipv6_cidr, mtu, enabled) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            "cb0",
            "eth0",
            51820,
            "---default---",
            "---default---",
            "10.8.0.0/24",
            "fdcc:ad94:bacf:61a4::cafe:0/112",
            1420,
            1,
        ],
    )?;

    // general_table default
    conn.execute(
        "INSERT OR IGNORE INTO general_table \
         (id, setup_step, session_password, session_timeout) \
         VALUES (?1, ?2, ?3, ?4)",
        // Seeded through `enc` like every other secret write; the seed path
        // predates the encryption layer and would otherwise be the one place
        // a credential still landed in plaintext.
        params![1, 1, enc(&session_pass)?, 3600],
    )?;

    // hooks_table default
    conn.execute(
        "INSERT OR IGNORE INTO hooks_table \
         (id, pre_up, post_up, pre_down, post_down) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params!["cb0", "", POST_UP_TEMPLATE, "", POST_DOWN_TEMPLATE],
    )?;

    // user_configs_table default
    conn.execute(
        "INSERT OR IGNORE INTO user_configs_table \
         (id, default_mtu, default_persistent_keepalive, default_dns, default_allowed_ips, host, port) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            "cb0",
            1420,
            0,
            r#"["1.1.1.1","2606:4700:4700::1111"]"#,
            r#"["0.0.0.0/0","::/0"]"#,
            "",
            51820,
        ],
    )?;

    // xray_inbound default — disabled until the operator generates keys
    // and confirms the dest. Defaults to www.microsoft.com:443 because it's
    // reachable from most jurisdictions including ones that have blocked
    // GitHub-related infra. Operator can change via the admin UI.
    conn.execute(
        "INSERT OR IGNORE INTO xray_inbound_table \
         (id, port, dest, server_names, fingerprint_default, enabled) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            "xray0",
            443,
            "www.microsoft.com:443",
            r#"["www.microsoft.com"]"#,
            "chrome",
            0,
        ],
    )?;

    // proxy_settings default — disabled until the operator opts in.
    // Column-level defaults supply QUIC imitation, handshake responder on,
    // DNS forwarding off, backend_port auto.
    conn.execute(
        "INSERT OR IGNORE INTO proxy_settings_table (id) VALUES (?1)",
        params!["proxy0"],
    )?;

    // qqdns_settings default — disabled until the operator lists resolvers,
    // sets NS-delegated send/recv domains, and flips the toggle. Column-
    // level defaults supply port 53, A queries, and the upstream pacing.
    conn.execute(
        "INSERT OR IGNORE INTO qqdns_settings_table (id) VALUES (?1)",
        params!["qqdns0"],
    )?;

    // mtproxy_inbound default — disabled until the operator picks a TLS
    // domain + opts in. Column-level defaults provide port 8080,
    // Fake-TLS only, masking on, middle-proxy on.
    conn.execute(
        "INSERT OR IGNORE INTO mtproxy_inbound_table (id) VALUES (?1)",
        params!["mtproxy0"],
    )?;

    // mdnsvpn_inbound default — disabled until the operator generates a
    // key, sets a NS-delegated domain, and flips the toggle. Column-
    // level defaults supply port 53, SOCKS5 mode, XOR encryption, and
    // the 1.1.1.1 / 1.0.0.1 upstreams (matching the upstream sample).
    conn.execute(
        "INSERT OR IGNORE INTO mdnsvpn_inbound_table (id) VALUES (?1)",
        params!["mdnsvpn0"],
    )?;

    crate::info!("Seeded default database rows");
    Ok(())
}

/// Open the database, create tables, seed defaults, and install the global
/// handle.  Must be called once at startup.
pub fn init_db() -> Result<()> {
    if CONFIG.in_memory {
        return init_in_memory_db();
    }

    // Pre-create the file 0600 so it is never briefly world-readable. SQLite
    // honours an existing file's mode, whereas letting `Connection::open`
    // create it applies the process umask (commonly 0644) and the chmod below
    // only closes the window afterwards. Same hazard `privhelper::wg_sync` and
    // `snapshot_to` already avoid; best-effort, since a filesystem without
    // Unix modes must still work.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        if !std::path::Path::new(&CONFIG.db_path).exists() {
            let _ = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&CONFIG.db_path);
        }
    }
    let c = Connection::open(&CONFIG.db_path).context("Failed to open SQLite database")?;
    // The DB holds service private keys, MTProxy secrets, the MasterDnsVPN
    // encryption key, and password/TOTP material. Restrict it to the owner so
    // it isn't world-readable on a shared host. Best-effort — a missing chmod
    // (e.g. on a filesystem that doesn't support Unix perms) is non-fatal.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(
            &CONFIG.db_path,
            std::fs::Permissions::from_mode(0o600),
        ) {
            crate::warn!("could not chmod 0600 the database file: {e}");
        }
    }
    create_tables(&c)?;
    seed_if_empty(&c)?;
    let mut guard = db_slot().lock().expect("Database lock poisoned");
    *guard = Some(c);
    crate::info!("Database ready at {}", CONFIG.db_path);
    Ok(())
}

/// Open the database purely in RAM (`:memory:`) so no query ever touches a
/// block device. When `COFFEEBLACK_PERSIST_DB` is set and a snapshot already
/// exists there, the RAM database is seeded from it via SQLite's online
/// restore — that is the only time the durable file is read, and it happens
/// before the server starts serving. Schema migrations then run against the
/// restored data (idempotent), and seeding fills a genuinely empty database.
///
/// A snapshot that is *absent* is not fatal: that is a genuine first boot, so
/// we seed a fresh database. A snapshot that is *present but will not restore*
/// is fatal, and deliberately so — seeding fresh there would bring the service
/// up as an unclaimed first-run install (the setup wizard needs no
/// authentication) and the snapshot task would then overwrite the operator's
/// only durable copy with the empty database. The "come up regardless of disk
/// health" premise does not reach that case: with no restored roster there is
/// no data plane to keep alive, only an open front door.
fn init_in_memory_db() -> Result<()> {
    let mut c = Connection::open_in_memory().context("open in-memory SQLite database")?;

    let restored = match &CONFIG.persist_db_path {
        Some(path) if snapshot_is_restorable(path) => match restore_from(&mut c, path) {
            Ok(()) => {
                crate::info!("Restored in-memory database from snapshot {path}");
                true
            }
            Err(e) => {
                // Fail closed. Seeding a fresh database here would bring the
                // service up as an *unclaimed first-run install*: setup_step
                // returns to 1 with zero users, and `POST /api/setup/2` needs
                // no authentication, so whoever reaches the panel first
                // becomes the administrator. The periodic snapshot task would
                // then write that empty database over the operator's only
                // durable copy, destroying the roster as well.
                //
                // The "come up regardless of disk health" premise does not
                // apply: a snapshot that exists but will not restore means
                // there is no roster to serve, so there is no data plane to
                // keep alive — only an open front door.
                return Err(e).with_context(|| {
                    format!(
                        "snapshot {path} exists but could not be restored. Refusing to \
                         start: continuing would serve an unauthenticated first-run \
                         setup wizard and overwrite the snapshot with an empty database. \
                         Move the file aside to start fresh deliberately."
                    )
                });
            }
        },
        _ => false,
    };

    // Always (re)run schema creation + migrations: harmless on a fresh DB,
    // and it upgrades the schema of an older restored snapshot in place.
    create_tables(&c)?;
    // Only seed when nothing was restored — a restored snapshot already holds
    // the operator's interface/general rows and must not be clobbered.
    if !restored {
        seed_if_empty(&c)?;
    }

    let mut guard = db_slot().lock().expect("Database lock poisoned");
    *guard = Some(c);
    match &CONFIG.persist_db_path {
        Some(path) => crate::info!(
            "Database ready in RAM (in-memory mode); snapshots persist to {path}"
        ),
        None => crate::info!(
            "Database ready in RAM (in-memory mode); no persistence configured \
             (COFFEEBLACK_PERSIST_DB unset) — state is lost on restart"
        ),
    }
    Ok(())
}

/// True when `path` names a non-empty regular file — i.e. a snapshot worth
/// attempting to restore. An absent or zero-byte file is the "first boot"
/// case and is not an error.
fn snapshot_is_restorable(path: &str) -> bool {
    std::fs::metadata(path).map(|m| m.is_file() && m.len() > 0).unwrap_or(false)
}

/// Restore a durable on-disk snapshot into the live in-memory connection
/// using SQLite's online backup (restore) API. The source file is opened
/// read-only-ish and copied page-by-page into `dst`; `dst`'s prior contents
/// are replaced.
fn restore_from(dst: &mut Connection, src_path: &str) -> Result<()> {
    let src = Connection::open(src_path)
        .with_context(|| format!("open snapshot {src_path} for restore"))?;
    // Verify the snapshot before adopting it. A truncated/corrupt/foreign file
    // that still parses as a SQLite header would otherwise be copied straight
    // into the live DB. `quick_check` is a cheap structural pass (skips the
    // full per-row index cross-check of `integrity_check`) — enough to reject
    // bit-rot or a swapped file at boot without a lengthy scan.
    let verdict: String = src
        .query_row("PRAGMA quick_check", [], |r| r.get(0))
        .context("integrity-check snapshot before restore")?;
    if verdict != "ok" {
        return Err(anyhow!(
            "refusing to restore snapshot {src_path}: integrity check failed ({verdict})"
        ));
    }
    let backup = rusqlite::backup::Backup::new(&src, dst)
        .context("init restore backup handle")?;
    backup
        .run_to_completion(64, std::time::Duration::from_millis(0), None)
        .context("run restore to completion")?;
    Ok(())
}

/// Snapshot the live (RAM) database to a durable file, atomically.
///
/// Used by the background persistence task and by graceful shutdown. The
/// backup is written to a sibling temp file and renamed into place so a crash
/// mid-snapshot can never truncate the previous good snapshot. Holds the
/// global connection lock only for the duration of the page copy — for an
/// academy-sized roster (tens of thousands of rows) that is a few-MB,
/// sub-100ms copy, and the lock is contended only by admin API calls, never
/// by the WireGuard data plane.
///
/// Every failure mode (no persist path, unwritable directory, dying disk) is
/// surfaced as an `Err` for the caller to log-and-swallow — it must never
/// propagate into a panic or block the server.
pub fn snapshot_to(dst_path: &str) -> Result<()> {
    use std::path::{Path, PathBuf};

    // Back up into a freshly-created, PRIVATE (0700) sibling directory, then
    // rename the finished file into place. This closes three holes the old
    // `{dst}.partial` path had, all of which briefly exposed every secret in
    // the DB (WireGuard/Xray private keys, TOTP secrets, session-signing key,
    // hashed passwords):
    //   1. `backup()` created the temp file with the default umask (0644) and
    //      only chmod'd it 0600 *after* the whole file was on disk — a
    //      world-readable window. Now the enclosing dir is 0700 from creation.
    //   2. The temp name `{dst}.partial` was predictable, so on a shared
    //      directory an attacker could pre-plant a symlink and redirect the
    //      secret dump. The dir name now carries a CSPRNG suffix and is made
    //      with `create_dir` (fails if the path already exists).
    //   3. Transient SQLite journal/WAL siblings (`snapshot.db-journal`, …)
    //      inherited default perms too; keeping them inside the 0700 dir
    //      contains them, and the dir is removed on every exit path.
    // The chmod result is now surfaced as an error: we never promote a
    // snapshot we could not lock down.
    let parent: PathBuf = Path::new(dst_path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));

    let mut rand_suffix = [0u8; 8];
    crate::rng::fill(&mut rand_suffix);
    let base = Path::new(dst_path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("db");
    let tmp_dir = parent.join(format!(
        ".{base}.snap.{}.{}",
        std::process::id(),
        crate::encoding::hex_encode(rand_suffix)
    ));

    std::fs::create_dir(&tmp_dir)
        .with_context(|| format!("create private snapshot dir {}", tmp_dir.display()))?;
    // Remove the private dir (and any journal siblings) on every return path.
    let _cleanup = TmpDirGuard(tmp_dir.clone());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp_dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("lock down snapshot dir {}", tmp_dir.display()))?;
    }

    let tmp_db = tmp_dir.join("snapshot.db");
    {
        let guard = conn();
        guard
            .backup(rusqlite::DatabaseName::Main, &tmp_db, None)
            .with_context(|| format!("online-backup database to {}", tmp_db.display()))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp_db, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 0600 snapshot {}", tmp_db.display()))?;
    }
    std::fs::rename(&tmp_db, dst_path)
        .with_context(|| format!("promote snapshot {} → {dst_path}", tmp_db.display()))?;
    Ok(())
}

/// Removes a directory tree on drop — used to guarantee the private snapshot
/// scratch dir never lingers, even when `snapshot_to` returns early on error.
struct TmpDirGuard(std::path::PathBuf);

impl Drop for TmpDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Reset the global DB handle to a fresh in-memory database for tests.
/// Always compiled so integration tests can use it.
pub fn init_test_db() {
    let c = Connection::open_in_memory().expect("in-memory DB open");
    create_tables(&c).expect("test db create_tables");
    seed_if_empty(&c).expect("test db seed");
    let mut guard = db_slot().lock().expect("Database lock poisoned");
    *guard = Some(c);
}

// ---------------------------------------------------------------------------
// Generic UPDATE helper – maps HashMap entries -> SET col = ? clauses
// ---------------------------------------------------------------------------

/// Reference to a single bound value used in the WHERE clause of a generic
/// UPDATE.  Strings are matched case-sensitively, integers via SQLite's
/// numeric comparison.
#[derive(Debug, Clone)]
pub enum WhereVal<'a> {
    Str(&'a str),
    I64(i64),
}

fn build_update<'a>(
    table: &str,
    where_col: &str,
    where_val: WhereVal<'a>,
    fields: &'a UpdateMap,
    valid_columns: &[&str],
    valid_where_columns: &[&str],
) -> Result<(String, Vec<Box<dyn rusqlite::types::ToSql + 'a>>)> {
    if !valid_where_columns.contains(&where_col) {
        return Err(anyhow!(
            "Invalid where column '{}' for table {}",
            where_col,
            table
        ));
    }
    for col in fields.keys() {
        if !valid_columns.contains(&col.as_str()) {
            return Err(anyhow!("Invalid column '{}' for table {}", col, table));
        }
    }
    let mut sets: Vec<String> = Vec::with_capacity(fields.len() + 1);
    let mut vals: Vec<Box<dyn rusqlite::types::ToSql + 'a>> = Vec::with_capacity(fields.len() + 1);
    for (col, val) in fields {
        sets.push(format!("{} = ?", col));
        // Single choke point for every update in the codebase: a secret column
        // is encrypted here, so no caller can write one in plaintext by
        // forgetting a step. Encryption failure must abort the write rather
        // than fall through to storing the plaintext.
        let val: String = if is_encrypted_column(table, col) {
            enc(val).map_err(|e| anyhow!("encrypting {table}.{col}: {e}"))?
        } else {
            val.clone()
        };
        vals.push(Box::new(val));
    }
    if sets.is_empty() {
        return Err(anyhow!("No fields to update on {}", table));
    }
    sets.push("updated_at = datetime('now')".into());
    let sql = format!(
        "UPDATE {} SET {} WHERE {} = ?",
        table,
        sets.join(", "),
        where_col,
    );
    match where_val {
        WhereVal::Str(s) => vals.push(Box::new(s.to_string())),
        WhereVal::I64(n) => vals.push(Box::new(n)),
    }
    Ok((sql, vals))
}

fn exec_update<'a>(
    table: &str,
    where_col: &str,
    where_val: WhereVal<'a>,
    fields: &'a UpdateMap,
    valid_columns: &[&str],
    valid_where_columns: &[&str],
) -> Result<()> {
    let (sql, vals) = build_update(
        table,
        where_col,
        where_val,
        fields,
        valid_columns,
        valid_where_columns,
    )?;
    let refs: Vec<&dyn rusqlite::types::ToSql> =
        vals.iter().map(|b| b.as_ref() as &dyn rusqlite::types::ToSql).collect();
    conn().execute(&sql, refs.as_slice())?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Interface helpers
// ---------------------------------------------------------------------------

pub fn get_interface() -> Result<Interface> {
    let c = conn();
    let iface = c
        .query_row(
            "SELECT * FROM interfaces_table WHERE name = 'cb0'",
            [],
            Interface::from_row,
        )
        .context("No interface row found")?;
    Ok(iface)
}

const VALID_INTERFACE_COLUMNS: &[&str] = &[
    "name", "device", "port", "private_key", "public_key", "ipv4_cidr", "ipv6_cidr",
    "mtu", "j_c", "j_min", "j_max", "s1", "s2", "s3", "s4",
    "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5",
    "header_protection_key", "content_padding_addition",
    "rekey_after_time", "rekey_timeout", "reject_after_time",
    "keepalive_timeout", "max_handshake_attempts",
    "random_trailers", "disable_cookies",
    "firewall_enabled",
    "dns_lockdown", "dns_lockdown_target", "dns_block_external",
    "additional_config", "enabled",
];

pub fn update_interface(fields: &UpdateMap) -> Result<()> {
    exec_update(
        "interfaces_table",
        "name",
        WhereVal::Str("cb0"),
        fields,
        VALID_INTERFACE_COLUMNS,
        &["name"],
    )
}

pub fn update_key_pair(pub_key: &str, priv_key: &str) -> Result<()> {
    let mut fields = UpdateMap::new();
    fields.insert("public_key".into(), pub_key.into());
    fields.insert("private_key".into(), priv_key.into());
    update_interface(&fields)
}

pub fn update_cidr(v4: &str, v6: &str) -> Result<()> {
    let mut fields = UpdateMap::new();
    fields.insert("ipv4_cidr".into(), v4.into());
    fields.insert("ipv6_cidr".into(), v6.into());
    update_interface(&fields)
}

pub fn update_interface_cb_params(params: &crate::wg::params::CbParams) -> Result<()> {
    let mut fields = UpdateMap::new();
    fields.insert("j_c".into(), params.jc.to_string());
    fields.insert("j_min".into(), params.jmin.to_string());
    fields.insert("j_max".into(), params.jmax.to_string());
    fields.insert("s1".into(), params.s1.to_string());
    fields.insert("s2".into(), params.s2.to_string());
    if let Some(ref s3) = params.s3 { fields.insert("s3".into(), s3.to_string()); }
    if let Some(ref s4) = params.s4 { fields.insert("s4".into(), s4.to_string()); }
    fields.insert("h1".into(), params.h1.clone());
    fields.insert("h2".into(), params.h2.clone());
    fields.insert("h3".into(), params.h3.clone());
    fields.insert("h4".into(), params.h4.clone());
    if let Some(ref i1) = params.i1 { fields.insert("i1".into(), i1.clone()); }
    if let Some(ref i2) = params.i2 { fields.insert("i2".into(), i2.clone()); }
    if let Some(ref i3) = params.i3 { fields.insert("i3".into(), i3.clone()); }
    if let Some(ref i4) = params.i4 { fields.insert("i4".into(), i4.clone()); }
    if let Some(ref i5) = params.i5 { fields.insert("i5".into(), i5.clone()); }
    update_interface(&fields)
}

pub fn set_firewall_enabled(enabled: bool) -> Result<()> {
    let mut fields = UpdateMap::new();
    fields.insert("firewall_enabled".into(), bool_to_int(enabled).to_string());
    update_interface(&fields)
}

/// Update all three DNS-lockdown fields in one transaction. Used by the
/// admin API change handler when the operator flips any of the toggles —
/// keeps the firewall rebuild and DB write in sync.
pub fn set_dns_lockdown(enabled: bool, target: &str, block_external: bool) -> Result<()> {
    let mut fields = UpdateMap::new();
    fields.insert("dns_lockdown".into(), bool_to_int(enabled).to_string());
    fields.insert("dns_lockdown_target".into(), target.to_string());
    fields.insert(
        "dns_block_external".into(),
        bool_to_int(block_external).to_string(),
    );
    update_interface(&fields)
}

// ---------------------------------------------------------------------------
// Client helpers
// ---------------------------------------------------------------------------

pub fn get_all_clients() -> Result<Vec<Client>> {
    let c = conn();
    let mut stmt = c.prepare("SELECT * FROM clients_table ORDER BY id")?;
    let rows = stmt.query_map([], Client::from_row)?;
    let mut clients = Vec::new();
    for row in rows {
        clients.push(row?);
    }
    Ok(clients)
}

pub fn get_client(id: i64) -> Result<Client> {
    let c = conn();
    c.query_row("SELECT * FROM clients_table WHERE id = ?1", params![id], |row| {
        Client::from_row(row)
    })
    .context(format!("Client {id} not found"))
}

/// Insert a client row within an existing transaction. Shared by
/// [`create_client`] and [`create_client_alloc_ip`] so the column list lives
/// in exactly one place.
fn insert_client(tx: &rusqlite::Transaction, data: &CreateClientParams) -> Result<i64> {
    tx.execute(
        "INSERT INTO clients_table \
         (user_id, interface_id, name, ipv4_address, ipv6_address, private_key, public_key, \
          pre_shared_key, pre_up, post_up, pre_down, post_down, expires_at, \
          allowed_ips, server_allowed_ips, firewall_ips, \
          persistent_keepalive, mtu, j_c, j_min, j_max, i1, i2, i3, i4, i5, \
          dns, server_endpoint, advanced_security, enabled) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,\
                 ?22,?23,?24,?25,?26,?27,?28,?29,?30)",
        params![
            data.user_id,
            data.interface_id,
            data.name,
            data.ipv4_address,
            data.ipv6_address,
            enc(&data.private_key)?,
            data.public_key,
            data.pre_shared_key.as_deref().map(enc).transpose()?,
            data.pre_up,
            data.post_up,
            data.pre_down,
            data.post_down,
            data.expires_at,
            data.allowed_ips,
            data.server_allowed_ips,
            data.firewall_ips,
            data.persistent_keepalive,
            data.mtu,
            data.j_c,
            data.j_min,
            data.j_max,
            data.i1,
            data.i2,
            data.i3,
            data.i4,
            data.i5,
            data.dns,
            data.server_endpoint,
            data.advanced_security.map(bool_to_int),
            bool_to_int(data.enabled),
        ],
    )?;
    Ok(tx.last_insert_rowid())
}

/// Count the clients owned by a given user — used to enforce the per-user
/// create quota.
pub fn count_clients_for_user(user_id: i64) -> Result<i64> {
    conn()
        .query_row(
            "SELECT COUNT(*) FROM clients_table WHERE user_id = ?1",
            params![user_id],
            |r| r.get(0),
        )
        .map_err(Into::into)
}

/// Atomically allocate the next free IPv4 (and IPv6, when `ipv6_cidr` is
/// non-empty) and insert the client — all under a single held DB lock. This
/// closes the check-then-insert race where two concurrent creates read the
/// same "used IPs" snapshot and pick the same address (the loser then hit the
/// UNIQUE constraint with a spurious 500). `data`'s `ipv4_address` /
/// `ipv6_address` are overwritten with the freshly-allocated values.
pub fn create_client_alloc_ip(
    data: &mut CreateClientParams,
    ipv4_cidr: &str,
    ipv6_cidr: &str,
) -> Result<i64> {
    let mut c = conn();
    let tx = c.transaction()?;
    let (mut used_v4, mut used_v6): (Vec<String>, Vec<String>) = (Vec::new(), Vec::new());
    {
        let mut stmt = tx.prepare("SELECT ipv4_address, ipv6_address FROM clients_table")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, Option<String>>(0)?,
                r.get::<_, Option<String>>(1)?,
            ))
        })?;
        for row in rows {
            let (v4, v6) = row?;
            if let Some(v) = v4 {
                used_v4.push(v);
            }
            if let Some(v) = v6 {
                used_v6.push(v);
            }
        }
    }
    data.ipv4_address = Some(next_ipv4(ipv4_cidr, &used_v4)?);
    data.ipv6_address = if ipv6_cidr.is_empty() {
        None
    } else {
        Some(next_ipv6(ipv6_cidr, &used_v6)?)
    };
    let id = insert_client(&tx, data)?;
    tx.commit()?;
    Ok(id)
}

pub fn create_client(data: &CreateClientParams) -> Result<i64> {
    let mut c = conn();
    let tx = c.transaction()?;
    let id = insert_client(&tx, data)?;
    tx.commit()?;
    Ok(id)
}

const VALID_CLIENT_COLUMNS: &[&str] = &[
    "user_id", "interface_id", "name", "ipv4_address", "ipv6_address",
    "private_key", "public_key", "pre_shared_key", "pre_up", "post_up",
    "pre_down", "post_down", "expires_at", "allowed_ips", "server_allowed_ips",
    "firewall_ips", "persistent_keepalive", "mtu", "j_c", "j_min", "j_max",
    "i1", "i2", "i3", "i4", "i5", "dns", "server_endpoint",
    "advanced_security", "additional_config", "enabled",
];

pub fn update_client(id: i64, fields: &UpdateMap) -> Result<()> {
    exec_update(
        "clients_table",
        "id",
        WhereVal::I64(id),
        fields,
        VALID_CLIENT_COLUMNS,
        &["id"],
    )
}

pub fn delete_client(id: i64) -> Result<()> {
    let c = conn();
    let n = c.execute("DELETE FROM clients_table WHERE id = ?1", params![id])?;
    if n == 0 {
        return Err(anyhow!("Client {id} not found"));
    }
    // The activity history lives outside SQLite (see `src/activity.rs`), so
    // there is no foreign key to cascade it away — dropping it is this
    // function's job. Doing it here rather than in the delete handler means
    // no future caller can delete a peer and silently leave its connection
    // record behind in memory.
    drop(c);
    crate::activity::forget_client(id);
    Ok(())
}

/// Replace a client's keypair. Used by the rotate flow — the recovery path
/// when a config was issued once and lost, and the revocation path when a
/// device is compromised.
///
/// `private_key` is `""` when the caller is not retaining it, which is the
/// same representation [`Client::has_private_key`] reads.
pub fn update_client_keypair(id: i64, private_key: &str, public_key: &str) -> Result<()> {
    let c = conn();
    let n = c.execute(
        "UPDATE clients_table SET private_key = ?1, public_key = ?2, \
         updated_at = datetime('now') WHERE id = ?3",
        params![enc(private_key)?, public_key, id],
    )?;
    if n == 0 {
        return Err(anyhow!("Client {id} not found"));
    }
    Ok(())
}

/// Forget every stored peer private key. Run when the operator switches
/// retention to `never`: without it, flipping the mode would protect only
/// peers created afterwards while every existing key stayed on disk — the
/// setting would describe an intention rather than a fact.
///
/// Returns how many rows actually held a key.
pub fn purge_client_private_keys() -> Result<usize> {
    let c = conn();
    let n = c.execute(
        "UPDATE clients_table SET private_key = '', updated_at = datetime('now') \
         WHERE private_key <> ''",
        [],
    )?;
    Ok(n)
}

pub fn toggle_client(id: i64, enabled: bool) -> Result<()> {
    let mut fields = UpdateMap::new();
    fields.insert("enabled".into(), bool_to_int(enabled).to_string());
    update_client(id, &fields)
}

/// Set the per-peer AmneziaWG flag. `None` clears the column to SQL NULL —
/// emitted configs will then omit the `AdvancedSecurity` line and the
/// kernel will auto-detect from the H1 magic header.
pub fn set_client_advanced_security(id: i64, value: Option<bool>) -> Result<()> {
    let c = conn();
    let n = match value {
        Some(b) => c.execute(
            "UPDATE clients_table \
             SET advanced_security = ?1, updated_at = datetime('now') \
             WHERE id = ?2",
            params![bool_to_int(b), id],
        )?,
        None => c.execute(
            "UPDATE clients_table \
             SET advanced_security = NULL, updated_at = datetime('now') \
             WHERE id = ?1",
            params![id],
        )?,
    };
    if n == 0 {
        return Err(anyhow!("Client {id} not found"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// User helpers
// ---------------------------------------------------------------------------

pub fn get_user(id: i64) -> Result<User> {
    let c = conn();
    c.query_row(
        "SELECT * FROM users_table WHERE id = ?1",
        params![id],
        User::from_row,
    )
    .context(format!("User {id} not found"))
}

pub fn get_user_by_username(username: &str) -> Result<User> {
    let c = conn();
    c.query_row(
        "SELECT * FROM users_table WHERE username = ?1",
        params![username],
        User::from_row,
    )
    .context(format!("User '{username}' not found"))
}

pub fn get_user_count() -> Result<i64> {
    let c = conn();
    c.query_row("SELECT COUNT(*) FROM users_table", [], |row| row.get(0))
        .context("Failed to count users")
}

pub fn create_user(data: &CreateUserParams) -> Result<i64> {
    let c = conn();
    c.execute(
        "INSERT INTO users_table \
         (username, password, email, name, role, totp_key, totp_verified, enabled) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        params![
            data.username,
            data.password,
            data.email,
            data.name,
            data.role,
            // Encrypted here rather than at the call site, for the same
            // reason it is decrypted in `User::from_row`: a secret that is
            // only protected when someone remembers to protect it is not
            // protected.
            data.totp_key.as_deref().map(enc).transpose()?,
            bool_to_int(data.totp_verified),
            bool_to_int(data.enabled),
        ],
    )?;
    Ok(c.last_insert_rowid())
}

const VALID_USER_COLUMNS: &[&str] = &[
    "username", "password", "email", "name", "role",
    "totp_key", "totp_verified", "totp_last_step", "enabled",
];

/// Highest TOTP timestep already consumed for this user (0 if never).
pub fn get_totp_last_step(user_id: i64) -> Result<i64> {
    conn()
        .query_row(
            "SELECT totp_last_step FROM users_table WHERE id = ?1",
            params![user_id],
            |r| r.get(0),
        )
        .map_err(Into::into)
}

/// Record the TOTP timestep just consumed. Monotonic: only advances, so a
/// concurrent request that matched an earlier step can't lower the watermark.
pub fn set_totp_last_step(user_id: i64, step: i64) -> Result<()> {
    conn().execute(
        "UPDATE users_table SET totp_last_step = ?2 \
         WHERE id = ?1 AND totp_last_step < ?2",
        params![user_id, step],
    )?;
    Ok(())
}

pub fn update_user(id: i64, fields: &UpdateMap) -> Result<()> {
    // `totp_key` is the one column here that carries a secret, and callers
    // hand it over in plaintext. Encrypting inside the generic updater rather
    // than at each call site means a future caller cannot introduce a
    // plaintext write by forgetting a step. Already-encrypted input is left
    // alone so a re-save is idempotent.
    let mut fields = fields.clone();
    if let Some(v) = fields.get("totp_key") {
        if !v.is_empty() && !crate::crypto::is_encrypted(v) {
            let enc = crate::crypto::encrypt(v)?;
            fields.insert("totp_key".into(), enc);
        }
    }
    exec_update(
        "users_table",
        "id",
        WhereVal::I64(id),
        &fields,
        VALID_USER_COLUMNS,
        &["id"],
    )
}

/// Encrypt every secret column that is still stored as plaintext.
///
/// Runs at startup once a key is configured. Without it, enabling encryption
/// would only protect secrets written afterwards, leaving every peer key,
/// pre-shared key, Reality key, client UUID and MTProxy secret readable in the
/// database — the same "the setting describes an intention, not a fact" trap
/// the private-key retention switch avoids.
///
/// Reads each column directly rather than through a row mapper, because the
/// mappers have already decrypted and so cannot tell the two shapes apart.
/// Idempotent: values that already carry the `enc$` prefix are skipped.
///
/// Returns the number of values upgraded.
pub fn encrypt_plaintext_secrets() -> Result<usize> {
    if !crate::crypto::is_configured() {
        return Ok(0);
    }
    let mut upgraded = 0usize;
    for (table, column) in ENCRYPTED_COLUMNS {
        // The primary key column differs per table; `rowid` is present on all
        // of them (none is WITHOUT ROWID) and is stable for an in-place update.
        let rows: Vec<(i64, String)> = {
            let c = conn();
            let mut stmt = c.prepare(&format!(
                "SELECT rowid, {column} FROM {table} \
                 WHERE {column} IS NOT NULL AND {column} <> ''"
            ))?;
            let mapped = stmt.query_map([], |row| Ok((row.get(0)?, row.get::<_, String>(1)?)))?;
            let mut out = Vec::new();
            for r in mapped {
                out.push(r?);
            }
            out
        };
        for (rowid, stored) in rows {
            if crate::crypto::is_encrypted(&stored) {
                continue;
            }
            let enc_val = enc(&stored)?;
            let c = conn();
            c.execute(
                &format!("UPDATE {table} SET {column} = ?1 WHERE rowid = ?2"),
                params![enc_val, rowid],
            )?;
            upgraded += 1;
        }
    }
    Ok(upgraded)
}

/// Re-encrypt any TOTP secret still stored as plaintext.
///
/// Runs at startup once a key is configured. Without it, enabling encryption
/// would only protect secrets created afterwards, leaving every existing
/// second factor readable in the database — the same "the setting describes an
/// intention, not a fact" trap the private-key retention switch avoids.
///
/// Reads the column directly rather than through `get_user`, whose row mapper
/// has already decrypted it and so cannot tell the two shapes apart.
///
/// Returns how many rows were upgraded.
pub fn encrypt_plaintext_totp_secrets() -> Result<usize> {
    if !crate::crypto::is_configured() {
        return Ok(0);
    }
    let rows: Vec<(i64, String)> = {
        let c = conn();
        let mut stmt = c.prepare(
            "SELECT id, totp_key FROM users_table \
             WHERE totp_key IS NOT NULL AND totp_key <> ''",
        )?;
        let mapped = stmt.query_map([], |row| Ok((row.get(0)?, row.get::<_, String>(1)?)))?;
        let mut out = Vec::new();
        for r in mapped {
            out.push(r?);
        }
        out
    };

    let mut upgraded = 0;
    for (id, stored) in rows {
        if crate::crypto::is_encrypted(&stored) {
            continue;
        }
        let enc = crate::crypto::encrypt(&stored)?;
        let c = conn();
        c.execute(
            "UPDATE users_table SET totp_key = ?1 WHERE id = ?2",
            params![enc, id],
        )?;
        upgraded += 1;
    }
    Ok(upgraded)
}

pub fn update_password(id: i64, hash: &str) -> Result<()> {
    let mut fields = UpdateMap::new();
    fields.insert("password".into(), hash.into());
    update_user(id, &fields)
}

// ---------------------------------------------------------------------------
// User config helpers
// ---------------------------------------------------------------------------

pub fn get_user_config() -> Result<UserConfig> {
    let c = conn();
    c.query_row(
        "SELECT * FROM user_configs_table WHERE id = 'cb0'",
        [],
        UserConfig::from_row,
    )
    .context("No user config row found")
}

const VALID_USER_CONFIG_COLUMNS: &[&str] = &[
    "default_mtu", "default_persistent_keepalive", "default_dns", "default_allowed_ips",
    "default_j_c", "default_j_min", "default_j_max",
    "default_i1", "default_i2", "default_i3", "default_i4", "default_i5",
    "default_additional_config",
    "host", "port",
];

pub fn update_user_config(fields: &UpdateMap) -> Result<()> {
    exec_update(
        "user_configs_table",
        "id",
        WhereVal::Str("cb0"),
        fields,
        VALID_USER_CONFIG_COLUMNS,
        &["id"],
    )
}

pub fn update_host_port(host: &str, port: i64) -> Result<()> {
    let mut fields = UpdateMap::new();
    fields.insert("host".into(), host.into());
    fields.insert("port".into(), port.to_string());
    update_user_config(&fields)
}

// ---------------------------------------------------------------------------
// Hooks helpers
// ---------------------------------------------------------------------------

pub fn get_hooks() -> Result<Hooks> {
    let c = conn();
    c.query_row(
        "SELECT * FROM hooks_table WHERE id = 'cb0'",
        [],
        Hooks::from_row,
    )
    .context("No hooks row found")
}

const VALID_HOOKS_COLUMNS: &[&str] = &["pre_up", "post_up", "pre_down", "post_down"];

pub fn update_hooks(data: &UpdateMap) -> Result<()> {
    exec_update(
        "hooks_table",
        "id",
        WhereVal::Str("cb0"),
        data,
        VALID_HOOKS_COLUMNS,
        &["id"],
    )
}

// ---------------------------------------------------------------------------
// General helpers
// ---------------------------------------------------------------------------

pub fn get_general() -> Result<General> {
    let c = conn();
    c.query_row(
        "SELECT * FROM general_table WHERE id = 1",
        [],
        General::from_row,
    )
    .context("No general row found")
}

const VALID_GENERAL_COLUMNS: &[&str] = &[
    "setup_step", "session_timeout",
    "metrics_prometheus", "metrics_json", "metrics_password",
    "activity_retention_days", "private_key_retention",
];

pub fn update_general(data: &UpdateMap) -> Result<()> {
    exec_update(
        "general_table",
        "id",
        WhereVal::I64(1),
        data,
        VALID_GENERAL_COLUMNS,
        &["id"],
    )
}

pub fn get_setup_step() -> Result<i64> {
    let c = conn();
    c.query_row(
        "SELECT setup_step FROM general_table WHERE id = 1",
        [],
        |row| row.get(0),
    )
    .context("No general row found")
}

pub fn set_setup_step(step: i64) -> Result<()> {
    let mut fields = UpdateMap::new();
    fields.insert("setup_step".into(), step.to_string());
    update_general(&fields)
}

// ---------------------------------------------------------------------------
// One-time link helpers
// ---------------------------------------------------------------------------

pub fn create_one_time_link(client_id: i64, token: &str, expires: &str) -> Result<()> {
    let digest = crate::auth::sha256(token);
    let token_enc = enc(token)?;
    let c = conn();
    c.execute(
        "INSERT OR REPLACE INTO one_time_links_table \
         (id, one_time_link, token_enc, expires_at) VALUES (?1, ?2, ?3, ?4)",
        params![client_id, digest, token_enc, expires],
    )?;
    Ok(())
}

pub fn get_one_time_link(token: &str) -> Result<OneTimeLink> {
    let c = conn();
    // Primary lookup is by digest. The second attempt matches rows written
    // before this column held a hash: links live about five minutes, so the
    // legacy shape disappears on its own shortly after an upgrade, but a link
    // already in a user's hands should not break the moment the service
    // restarts under them.
    c.query_row(
        "SELECT * FROM one_time_links_table WHERE one_time_link = ?1",
        params![crate::auth::sha256(token)],
        OneTimeLink::from_row,
    )
    .or_else(|_| {
        c.query_row(
            "SELECT * FROM one_time_links_table WHERE one_time_link = ?1",
            params![token],
            OneTimeLink::from_row,
        )
    })
    .context("One-time link not found")
}

/// Atomically consume the one-time link matching `token`, returning it only to
/// the caller that actually claimed it.
///
/// Single-use has to be one statement. Looking the row up and deleting it
/// afterwards left a window in which two concurrent requests both passed the
/// lookup and both received the peer configuration — which embeds the private
/// key — so the endpoint's whole reason for existing did not hold under a
/// race. `DELETE … RETURNING` makes the claim and the read the same operation:
/// exactly one caller can observe a given row.
pub fn claim_one_time_link(token: &str) -> Result<OneTimeLink> {
    let c = conn();
    // Digest first, then the pre-hash shape for links issued by an older
    // version — same two-step lookup the previous read path used, so a link
    // already in a user's hands keeps working across an upgrade.
    for candidate in [crate::auth::sha256(token), token.to_string()] {
        let row = c
            .query_row(
                "DELETE FROM one_time_links_table WHERE one_time_link = ?1 RETURNING *",
                params![candidate],
                OneTimeLink::from_row,
            )
            .optional()?;
        if let Some(link) = row {
            return Ok(link);
        }
    }
    Err(anyhow!("One-time link not found"))
}

pub fn delete_one_time_link(client_id: i64) -> Result<()> {
    let c = conn();
    let n = c.execute(
        "DELETE FROM one_time_links_table WHERE id = ?1",
        params![client_id],
    )?;
    if n == 0 {
        return Err(anyhow!("One-time link for client {client_id} not found"));
    }
    Ok(())
}

/// Active (non-expired) one-time link for *client_id*, if any.
/// The schema enforces at most one row per client (id is both primary key
/// and the foreign-key reference into clients_table), so this is a unique
/// lookup. Returns None when no link exists or the link has expired.
pub fn get_active_one_time_link(client_id: i64) -> Result<Option<OneTimeLink>> {
    let now = crate::datetime::now_rfc3339();
    let c = conn();
    let row = c
        .query_row(
            "SELECT * FROM one_time_links_table \
             WHERE id = ?1 AND (expires_at IS NULL OR expires_at > ?2)",
            params![client_id, now],
            OneTimeLink::from_row,
        )
        .ok();
    Ok(row)
}

// ---------------------------------------------------------------------------
// IP allocation
// ---------------------------------------------------------------------------

/// Find the first host address inside *cidr* that is not in *used_ips*.
pub fn next_ipv4(cidr: &str, used_ips: &[String]) -> Result<String> {
    let net: Ipv4Net = cidr.parse().context("Invalid IPv4 CIDR")?;
    // The server occupies network_addr + 1 (mirrored in wg::config_gen::server_ip).
    // Allocating that to a peer collides with the server's interface address
    // and `awg syncconf` rejects with "Invalid argument". Treat it as taken.
    let server_ip = std::net::Ipv4Addr::from(u32::from(net.addr()) + 1).to_string();
    for host in net.hosts() {
        let ip = host.to_string();
        if ip != server_ip && !used_ips.contains(&ip) {
            return Ok(ip);
        }
    }
    Err(anyhow!("No available IPv4 address in {cidr}"))
}

/// Find the first host address inside *cidr* that is not in *used_ips*.
pub fn next_ipv6(cidr: &str, used_ips: &[String]) -> Result<String> {
    let net: Ipv6Net = cidr.parse().context("Invalid IPv6 CIDR")?;
    // cidr::Ipv6Net::hosts() includes the network address (IPv6 has no
    // broadcast). Skip both the network address and the server IP
    // (network + 1, mirrored in wg::config_gen::server_ip).
    let network_addr = net.addr().to_string();
    let server_ip = std::net::Ipv6Addr::from(u128::from(net.addr()) + 1).to_string();
    for host in net.hosts() {
        let ip = host.to_string();
        if ip != network_addr && ip != server_ip && !used_ips.contains(&ip) {
            return Ok(ip);
        }
    }
    Err(anyhow!("No available IPv6 address in {cidr}"))
}

// ---------------------------------------------------------------------------
// Xray inbound + clients helpers
// ---------------------------------------------------------------------------

pub fn get_xray_inbound() -> Result<XrayInbound> {
    let c = conn();
    c.query_row(
        "SELECT * FROM xray_inbound_table WHERE id = 'xray0'",
        [],
        XrayInbound::from_row,
    )
    .context("No xray_inbound row found")
}

const VALID_XRAY_INBOUND_COLUMNS: &[&str] = &[
    "port", "dest", "server_names", "private_key", "public_key",
    "fingerprint_default", "transport", "xhttp_path",
    "additional_config", "enabled",
];

pub fn update_xray_inbound(fields: &UpdateMap) -> Result<()> {
    exec_update(
        "xray_inbound_table",
        "id",
        WhereVal::Str("xray0"),
        fields,
        VALID_XRAY_INBOUND_COLUMNS,
        &["id"],
    )
}

pub fn get_proxy_settings() -> Result<ProxySettings> {
    let c = conn();
    c.query_row(
        "SELECT * FROM proxy_settings_table WHERE id = 'proxy0'",
        [],
        ProxySettings::from_row,
    )
    .context("No proxy_settings row found")
}

const VALID_PROXY_SETTINGS_COLUMNS: &[&str] = &[
    "enabled", "protocol", "backend_port", "quic_handshake",
    "quic_cert_domain", "dns_forward", "dns_upstream", "additional_config",
    "max_sessions", "session_ttl",
];

pub fn update_proxy_settings(fields: &UpdateMap) -> Result<()> {
    exec_update(
        "proxy_settings_table",
        "id",
        WhereVal::Str("proxy0"),
        fields,
        VALID_PROXY_SETTINGS_COLUMNS,
        &["id"],
    )
}

pub fn get_qqdns_settings() -> Result<QqdnsSettings> {
    let c = conn();
    c.query_row(
        "SELECT * FROM qqdns_settings_table WHERE id = 'qqdns0'",
        [],
        QqdnsSettings::from_row,
    )
    .context("No qqdns_settings row found")
}

const VALID_QQDNS_SETTINGS_COLUMNS: &[&str] = &[
    "enabled",
    "dns_ips",
    "send_domains",
    "recv_domains",
    "send_interface_ip",
    "receive_interface_ip",
    "receive_port",
    "h_in_address",
    "cb_target_port",
    "max_domain_len",
    "max_sub_len",
    "retries",
    "send_query_type",
    "packets_send_interval_ms",
    "packets_wait_time_limit_ms",
    "send_sock_numbers",
];

pub fn update_qqdns_settings(fields: &UpdateMap) -> Result<()> {
    exec_update(
        "qqdns_settings_table",
        "id",
        WhereVal::Str("qqdns0"),
        fields,
        VALID_QQDNS_SETTINGS_COLUMNS,
        &["id"],
    )
}

/// Replace the inbound's keypair atomically. Used by the
/// "regenerate keys" admin action — both columns move together so the
/// inbound never lands in a state where the public key on disk doesn't
/// pair with the private key in `realitySettings`.
pub fn update_xray_keypair(private_key: &str, public_key: &str) -> Result<()> {
    let mut fields = UpdateMap::new();
    fields.insert("private_key".into(), private_key.into());
    fields.insert("public_key".into(), public_key.into());
    update_xray_inbound(&fields)
}

pub fn list_xray_clients() -> Result<Vec<XrayClient>> {
    let c = conn();
    let mut stmt = c.prepare(
        "SELECT * FROM xray_clients_table ORDER BY created_at ASC, id ASC",
    )?;
    let rows = stmt
        .query_map([], XrayClient::from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub fn get_xray_client(id: i64) -> Result<XrayClient> {
    let c = conn();
    c.query_row(
        "SELECT * FROM xray_clients_table WHERE id = ?1",
        params![id],
        XrayClient::from_row,
    )
    .context(format!("Xray client {id} not found"))
}

/// Data required to insert a new xray peer. `uuid` and `short_id` are
/// generated by the caller (see `xray::keys`) so the DB layer never has
/// to fork a process.
#[derive(Debug, Clone)]
pub struct CreateXrayClientParams {
    pub user_id: Option<i64>,
    pub inbound_id: String,
    pub name: String,
    pub uuid: String,
    pub short_id: String,
    pub expires_at: Option<String>,
    pub additional_config: Option<String>,
    pub enabled: bool,
}

pub fn create_xray_client(data: &CreateXrayClientParams) -> Result<i64> {
    let c = conn();
    c.execute(
        "INSERT INTO xray_clients_table \
         (user_id, inbound_id, name, uuid, short_id, expires_at, additional_config, enabled) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            data.user_id,
            data.inbound_id,
            data.name,
            enc(&data.uuid)?,
            enc(&data.short_id)?,
            data.expires_at,
            data.additional_config,
            bool_to_int(data.enabled),
        ],
    )?;
    Ok(c.last_insert_rowid())
}

const VALID_XRAY_CLIENT_COLUMNS: &[&str] = &[
    "user_id", "inbound_id", "name", "uuid", "short_id",
    "expires_at", "additional_config", "enabled",
];

pub fn update_xray_client(id: i64, fields: &UpdateMap) -> Result<()> {
    exec_update(
        "xray_clients_table",
        "id",
        WhereVal::I64(id),
        fields,
        VALID_XRAY_CLIENT_COLUMNS,
        &["id"],
    )
}

pub fn delete_xray_client(id: i64) -> Result<()> {
    let c = conn();
    let n = c.execute(
        "DELETE FROM xray_clients_table WHERE id = ?1",
        params![id],
    )?;
    if n == 0 {
        return Err(anyhow!("Xray client {id} not found"));
    }
    Ok(())
}

pub fn toggle_xray_client(id: i64, enabled: bool) -> Result<()> {
    let mut fields = UpdateMap::new();
    fields.insert("enabled".into(), bool_to_int(enabled).to_string());
    update_xray_client(id, &fields)
}

// ---------------------------------------------------------------------------
// DNS bundle helpers
// ---------------------------------------------------------------------------

pub fn get_dns_bundle() -> Result<DnsBundle> {
    let c = conn();
    c.query_row(
        "SELECT * FROM dns_bundle_table WHERE id = 'dns0'",
        [],
        DnsBundle::from_row,
    )
    .context("No dns_bundle row found")
}

const VALID_DNS_BUNDLE_COLUMNS: &[&str] = &[
    "enabled",
    "listen_port",
    "upstream_resolvers",
    "require_dnssec",
    "require_nolog",
    "require_nofilter",
    "tor_enabled",
    "tor_socks_port",
    "tor_exit_nodes",
    "tor_dns_exit_nodes",
    "tor_use_bridges",
    "tor_plugin",
    "additional_config",
];

pub fn update_dns_bundle(fields: &UpdateMap) -> Result<()> {
    exec_update(
        "dns_bundle_table",
        "id",
        WhereVal::Str("dns0"),
        fields,
        VALID_DNS_BUNDLE_COLUMNS,
        &["id"],
    )
}

// ---------------------------------------------------------------------------
// MTProxy inbound + users helpers
// ---------------------------------------------------------------------------

pub fn get_mtproxy_inbound() -> Result<MtproxyInbound> {
    let c = conn();
    c.query_row(
        "SELECT * FROM mtproxy_inbound_table WHERE id = 'mtproxy0'",
        [],
        MtproxyInbound::from_row,
    )
    .context("No mtproxy_inbound row found")
}

const VALID_MTPROXY_INBOUND_COLUMNS: &[&str] = &[
    "port",
    "public_host",
    "public_port",
    "tls_domain",
    "mask_enabled",
    "modes_classic",
    "modes_secure",
    "modes_tls",
    "use_middle_proxy",
    "ad_tag",
    "additional_config",
    "enabled",
];

pub fn update_mtproxy_inbound(fields: &UpdateMap) -> Result<()> {
    exec_update(
        "mtproxy_inbound_table",
        "id",
        WhereVal::Str("mtproxy0"),
        fields,
        VALID_MTPROXY_INBOUND_COLUMNS,
        &["id"],
    )
}

pub fn list_mtproxy_users() -> Result<Vec<MtproxyUser>> {
    let c = conn();
    let mut stmt = c.prepare(
        "SELECT * FROM mtproxy_users_table ORDER BY created_at ASC, id ASC",
    )?;
    let rows = stmt
        .query_map([], MtproxyUser::from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub fn get_mtproxy_user_by_username(username: &str) -> Result<MtproxyUser> {
    let c = conn();
    c.query_row(
        "SELECT * FROM mtproxy_users_table WHERE username = ?1",
        params![username],
        MtproxyUser::from_row,
    )
    .context(format!("MTProxy user {username:?} not found"))
}

pub fn create_mtproxy_user(data: &CreateMtproxyUserParams) -> Result<i64> {
    let c = conn();
    c.execute(
        "INSERT INTO mtproxy_users_table \
         (user_id, inbound_id, username, secret_hex, ad_tag, enabled) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            data.user_id,
            data.inbound_id,
            data.username,
            enc(&data.secret_hex)?,
            data.ad_tag,
            bool_to_int(data.enabled),
        ],
    )?;
    Ok(c.last_insert_rowid())
}

const VALID_MTPROXY_USER_COLUMNS: &[&str] = &[
    "user_id",
    "inbound_id",
    "secret_hex",
    "ad_tag",
    "enabled",
];

/// Update by username (the natural key telemt's API also uses). We
/// deliberately don't expose username-rename through this helper —
/// renaming a user is a rotate-secret-and-recreate flow because telemt
/// has no equivalent rename API endpoint.
pub fn update_mtproxy_user(username: &str, fields: &UpdateMap) -> Result<()> {
    exec_update(
        "mtproxy_users_table",
        "username",
        WhereVal::Str(username),
        fields,
        VALID_MTPROXY_USER_COLUMNS,
        &["username"],
    )
}

pub fn delete_mtproxy_user(username: &str) -> Result<()> {
    let c = conn();
    let n = c.execute(
        "DELETE FROM mtproxy_users_table WHERE username = ?1",
        params![username],
    )?;
    if n == 0 {
        return Err(anyhow!("MTProxy user {username:?} not found"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// MasterDnsVPN inbound + clients helpers
// ---------------------------------------------------------------------------

pub fn get_mdnsvpn_inbound() -> Result<MdnsvpnInbound> {
    let c = conn();
    c.query_row(
        "SELECT * FROM mdnsvpn_inbound_table WHERE id = 'mdnsvpn0'",
        [],
        MdnsvpnInbound::from_row,
    )
    .context("No mdnsvpn_inbound row found")
}

const VALID_MDNSVPN_INBOUND_COLUMNS: &[&str] = &[
    "domains",
    "port",
    "bind",
    "encryption_method",
    "encryption_key",
    "protocol_type",
    "dns_upstream_servers",
    "forward_ip",
    "forward_port",
    "use_external_socks5",
    "socks5_auth",
    "socks5_user",
    "socks5_pass",
    "additional_config",
    "enabled",
];

pub fn update_mdnsvpn_inbound(fields: &UpdateMap) -> Result<()> {
    exec_update(
        "mdnsvpn_inbound_table",
        "id",
        WhereVal::Str("mdnsvpn0"),
        fields,
        VALID_MDNSVPN_INBOUND_COLUMNS,
        &["id"],
    )
}

/// Replace just the encryption key. Pulled out so the regenerate-key
/// admin endpoint can issue a single-column UPDATE without smuggling
/// the rest of the inbound's state into an UpdateMap.
pub fn update_mdnsvpn_encryption_key(key: &str) -> Result<()> {
    // Raw UPDATE, so it bypasses `exec_update`'s encryption choke point and
    // has to encrypt here itself.
    let stored = enc(key)?;
    let c = conn();
    c.execute(
        "UPDATE mdnsvpn_inbound_table \
         SET encryption_key = ?1, updated_at = datetime('now') \
         WHERE id = 'mdnsvpn0'",
        params![stored],
    )?;
    Ok(())
}

pub fn list_mdnsvpn_clients() -> Result<Vec<MdnsvpnClient>> {
    let c = conn();
    let mut stmt = c.prepare(
        "SELECT * FROM mdnsvpn_clients_table ORDER BY created_at ASC, id ASC",
    )?;
    let rows = stmt
        .query_map([], MdnsvpnClient::from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub fn get_mdnsvpn_client(id: i64) -> Result<MdnsvpnClient> {
    let c = conn();
    c.query_row(
        "SELECT * FROM mdnsvpn_clients_table WHERE id = ?1",
        params![id],
        MdnsvpnClient::from_row,
    )
    .context(format!("MasterDnsVPN client #{id} not found"))
}

pub fn create_mdnsvpn_client(data: &CreateMdnsvpnClientParams) -> Result<i64> {
    let c = conn();
    c.execute(
        "INSERT INTO mdnsvpn_clients_table \
         (user_id, inbound_id, name, resolvers, listen_port, \
          socks5_user, socks5_pass, expires_at, additional_config_toml, enabled) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            data.user_id,
            data.inbound_id,
            data.name,
            data.resolvers,
            data.listen_port,
            data.socks5_user,
            data.socks5_pass,
            data.expires_at,
            data.additional_config_toml,
            bool_to_int(data.enabled),
        ],
    )?;
    Ok(c.last_insert_rowid())
}

const VALID_MDNSVPN_CLIENT_COLUMNS: &[&str] = &[
    "user_id",
    "inbound_id",
    "name",
    "resolvers",
    "listen_port",
    "socks5_user",
    "socks5_pass",
    "expires_at",
    "additional_config_toml",
    "enabled",
];

pub fn update_mdnsvpn_client(id: i64, fields: &UpdateMap) -> Result<()> {
    exec_update(
        "mdnsvpn_clients_table",
        "id",
        WhereVal::I64(id),
        fields,
        VALID_MDNSVPN_CLIENT_COLUMNS,
        &["id"],
    )
}

pub fn delete_mdnsvpn_client(id: i64) -> Result<()> {
    let c = conn();
    let n = c.execute(
        "DELETE FROM mdnsvpn_clients_table WHERE id = ?1",
        params![id],
    )?;
    if n == 0 {
        return Err(anyhow!("MasterDnsVPN client #{id} not found"));
    }
    Ok(())
}

pub fn toggle_mdnsvpn_client(id: i64, enabled: bool) -> Result<()> {
    let c = conn();
    c.execute(
        "UPDATE mdnsvpn_clients_table \
         SET enabled = ?1, updated_at = datetime('now') WHERE id = ?2",
        params![bool_to_int(enabled), id],
    )?;
    Ok(())
}

#[cfg(test)]
mod migration_tests {
    use super::*;

    #[test]
    fn migrations_land_columns_and_are_idempotent() {
        let conn = Connection::open_in_memory().expect("open in-memory");
        // create_tables runs apply_migrations once as part of setup.
        create_tables(&conn).expect("create_tables");

        // Columns introduced by additive migrations must be present.
        for (table, col) in [
            ("clients_table", "advanced_security"),
            ("clients_table", "additional_config"),
            ("interfaces_table", "additional_config"),
            ("interfaces_table", "dns_lockdown"),
            ("interfaces_table", "header_protection_key"),
            ("interfaces_table", "random_trailers"),
            ("user_configs_table", "default_additional_config"),
        ] {
            assert!(
                column_exists(&conn, table, col).unwrap(),
                "expected {table}.{col} after migrations"
            );
        }

        // Re-running migrations must be a no-op, never an error (each ALTER is
        // guarded by a column-existence check). Run twice more to be sure.
        apply_migrations(&conn).expect("second apply");
        apply_migrations(&conn).expect("third apply");
        assert!(column_exists(&conn, "clients_table", "advanced_security").unwrap());
    }

    #[test]
    fn cb3_columns_are_added_to_a_pre_cb3_interfaces_table() {
        // The upgrade path that matters: a DB written by the previous
        // release has none of these columns, and every one must arrive with
        // a default that renders no config line — otherwise upgrading would
        // silently change the wire format of a running deployment.
        let conn = Connection::open_in_memory().expect("open in-memory");
        create_tables(&conn).expect("create_tables");

        let cb3_cols = [
            "header_protection_key",
            "content_padding_addition",
            "rekey_after_time",
            "rekey_timeout",
            "reject_after_time",
            "keepalive_timeout",
            "max_handshake_attempts",
            "random_trailers",
            "disable_cookies",
        ];
        for col in cb3_cols {
            conn.execute_batch(&format!(
                "ALTER TABLE interfaces_table DROP COLUMN {col};"
            ))
            .unwrap_or_else(|e| panic!("drop {col}: {e}"));
            assert!(!column_exists(&conn, "interfaces_table", col).unwrap());
        }

        apply_migrations(&conn).expect("apply_migrations re-adds the AWG 3 columns");
        for col in cb3_cols {
            assert!(
                column_exists(&conn, "interfaces_table", col).unwrap(),
                "expected interfaces_table.{col} after migration"
            );
        }

        // Defaults must be "unset", read back through the same row mapper
        // the rest of the code uses.
        conn.execute_batch(
            "INSERT OR REPLACE INTO interfaces_table \
             (name, device, port, private_key, public_key, ipv4_cidr, ipv6_cidr) \
             VALUES ('cb0', 'eth0', 51820, '', 'PUB', '10.8.0.0/24', 'fdcc::/112')",
        )
        .expect("seed interface row");
        let iface = conn
            .query_row(
                "SELECT * FROM interfaces_table WHERE name = 'cb0'",
                [],
                Interface::from_row,
            )
            .expect("read back migrated row");
        assert!(iface.header_protection_key.is_empty());
        assert!(iface.content_padding_addition.is_empty());
        assert!(iface.rekey_after_time.is_empty());
        assert!(iface.rekey_timeout.is_empty());
        assert!(iface.reject_after_time.is_empty());
        assert!(iface.keepalive_timeout.is_empty());
        assert!(iface.max_handshake_attempts.is_empty());
        assert!(!iface.random_trailers);
        assert!(!iface.disable_cookies);

        // Idempotent, like every other migration here.
        apply_migrations(&conn).expect("second apply");
    }

    #[test]
    fn migration_adds_column_to_old_schema() {
        // Simulate a pre-migration DB: build the full schema, then drop a
        // migrated column by recreating clients_table without it, and confirm
        // apply_migrations re-adds it.
        let conn = Connection::open_in_memory().expect("open in-memory");
        create_tables(&conn).expect("create_tables");
        conn.execute_batch(
            "ALTER TABLE clients_table DROP COLUMN advanced_security;",
        )
        .expect("drop column");
        assert!(!column_exists(&conn, "clients_table", "advanced_security").unwrap());

        apply_migrations(&conn).expect("apply_migrations re-adds column");
        assert!(column_exists(&conn, "clients_table", "advanced_security").unwrap());
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;

    /// The whole point of in-memory mode's durability story: a RAM database
    /// can be snapshotted to a file and that file restored into a fresh RAM
    /// database with no data loss. We drive the same online-backup API
    /// `snapshot_to` / `restore_from` use, side-stepping the global DB slot
    /// so the test is hermetic.
    #[test]
    fn snapshot_then_restore_preserves_data() {
        // Source RAM DB with schema + a sentinel mutation.
        let src = Connection::open_in_memory().expect("open src");
        create_tables(&src).expect("create_tables src");
        seed_if_empty(&src).expect("seed src");
        src.execute("UPDATE general_table SET session_timeout = 4242", [])
            .expect("mutate src");

        // Persist it to a durable file via SQLite online backup.
        let tmp = std::env::temp_dir().join(format!(
            "coffeeblack-snap-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        src.backup(rusqlite::DatabaseName::Main, &tmp, None)
            .expect("backup to file");

        // Restore into an empty RAM DB and confirm the sentinel survived.
        let mut dst = Connection::open_in_memory().expect("open dst");
        restore_from(&mut dst, tmp.to_str().unwrap()).expect("restore");
        let timeout: i64 = dst
            .query_row("SELECT session_timeout FROM general_table", [], |r| r.get(0))
            .expect("read restored value");
        assert_eq!(timeout, 4242, "restored DB must carry the snapshot's data");

        let _ = std::fs::remove_file(&tmp);
    }

    /// A missing or empty snapshot is the first-boot case, not an error —
    /// `snapshot_is_restorable` must report it as "nothing to restore".
    #[test]
    fn missing_or_empty_snapshot_is_not_restorable() {
        assert!(!snapshot_is_restorable("/no/such/coffeeblack-snapshot.db"));

        let empty = std::env::temp_dir().join(format!("coffeeblack-empty-{}.db", std::process::id()));
        std::fs::write(&empty, b"").expect("write empty file");
        assert!(!snapshot_is_restorable(empty.to_str().unwrap()));
        let _ = std::fs::remove_file(&empty);
    }
}
