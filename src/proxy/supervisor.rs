//! Lifecycle supervisor for the in-process DPI-imitation proxy.
//!
//! Mirrors the facade of the subprocess supervisors (`xray`, `mtproxy`,
//! …) — `ensure_running` / `stop` / `status` / `shutdown_for_exit` — but
//! drives an in-process Tokio task instead of a child process. There is no
//! binary to spawn and no SIGHUP: a config change is applied by tearing
//! the old task down (via its [`ShutdownHandle`]) and binding a fresh
//! [`Proxy`] with the new settings. Sessions are cheap and re-establish on
//! the client's next keepalive, so a reconfigure is a sub-second blip.
//!
//! Enabling/disabling the proxy also rebinds AmneziaWG between the public
//! port and a loopback backend port — that orchestration lives in
//! [`apply_and_reconcile`], which the admin API calls after mutating
//! `proxy_settings_table`.

use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use anyhow::{Context, Result};
use serde::Serialize;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use crate::config::CONFIG;
use crate::db;
use crate::proxy::config::{self as pconfig, CbParams, ProxyConfig};
use crate::proxy::proxy::{Proxy, ShutdownHandle};

/// What we keep while the proxy task is alive.
struct Live {
    shutdown: ShutdownHandle,
    join: JoinHandle<()>,
    /// Hash of the effective (ProxyConfig + CbParams) inputs. When an
    /// `ensure_running` recomputes the same hash the task is left running
    /// untouched; a different hash triggers a stop+restart.
    cfg_hash: u64,
    /// Generation this task belongs to — lets a stale task's completion
    /// handler avoid clobbering a newer `Live`.
    generation: u64,
    started_at: Instant,
    listen: String,
    backend: String,
    protocol: String,
}

#[derive(Default)]
struct State {
    live: Option<Live>,
    /// Reason the supervisor declined to run (disabled flag, no
    /// interface, …). Surfaced verbatim through `Status::Disabled`.
    disabled_reason: Option<String>,
    /// Last unexpected task exit / bind error, surfaced as `Status::Crashed`.
    last_error: Option<String>,
}

static STATE: Mutex<Option<State>> = Mutex::const_new(None);
static GENERATION: AtomicU64 = AtomicU64::new(0);

async fn lock_state<'a>() -> tokio::sync::MutexGuard<'a, Option<State>> {
    let mut guard = STATE.lock().await;
    if guard.is_none() {
        *guard = Some(State::default());
    }
    guard
}

/// Public status snapshot for `/api/admin/proxy/status`.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum Status {
    Disabled {
        reason: String,
    },
    Running {
        listen: String,
        backend: String,
        protocol: String,
        uptime_seconds: u64,
    },
    Crashed {
        last_error: String,
    },
}

/// Resolve the loopback backend port AmneziaWG is moved onto while the
/// proxy fronts the public port. `0` in the settings means "auto": one
/// above the public port, or one below when the public port is the last
/// usable port.
pub fn effective_backend_port(settings: &db::ProxySettings, iface_port: i64) -> i64 {
    if settings.backend_port != 0 {
        return settings.backend_port;
    }
    if iface_port < 65535 {
        iface_port + 1
    } else {
        iface_port - 1
    }
}

/// The port AmneziaWG's generated config should actually listen on. When
/// the proxy is active AmneziaWG is pushed onto the loopback backend port
/// (the proxy owns the public port); otherwise it keeps the public port.
/// Consulted by `wg::save_config`.
pub fn effective_listen_port(iface: &db::Interface) -> i64 {
    match db::get_proxy_settings() {
        Ok(s) if s.enabled && should_remain_disabled(&s, iface).is_none() => {
            effective_backend_port(&s, iface.port)
        }
        _ => iface.port,
    }
}

/// Reason we'd refuse to run — propagated to the admin UI verbatim.
fn should_remain_disabled(settings: &db::ProxySettings, iface: &db::Interface) -> Option<String> {
    if !settings.enabled {
        return Some("proxy is disabled in admin settings".to_string());
    }
    if !iface.enabled {
        return Some("AmneziaWG interface is disabled".to_string());
    }
    let valid = ["quic", "dns", "stun", "sip", "auto"];
    if !valid.contains(&settings.protocol.as_str()) {
        return Some(format!(
            "unsupported imitate protocol '{}' (expected quic|dns|stun|sip|auto)",
            settings.protocol
        ));
    }
    if settings.quic_handshake
        && matches!(settings.protocol.as_str(), "quic" | "auto")
        && settings.quic_cert_domain.trim().is_empty()
    {
        return Some("QUIC handshake responder needs a certificate domain".to_string());
    }
    let backend = effective_backend_port(settings, iface.port);
    if backend == iface.port {
        return Some(format!(
            "backend port {backend} collides with the public port — pick a different loopback port"
        ));
    }
    if !(1..=65535).contains(&backend) {
        return Some(format!("backend port {backend} out of range"));
    }
    // AmneziaWG 3 knobs that change the datagram shape this proxy parses.
    // The admin API rejects the combination from either direction, so this
    // is the backstop for a DB that got into the state some other way: it
    // is much better to leave the proxy off (peers keep working on the
    // native port) than to front a port whose packets we would misread as
    // probes and answer with imitation traffic.
    if let Some(reason) = crate::wg::cb3::proxy_conflict(
        &iface.header_protection_key,
        iface.random_trailers,
    ) {
        return Some(reason.to_string());
    }
    None
}

/// Build the proxy's `ProxyConfig` and `CbParams` from DB state.
///
/// The proxy always binds the interface's *public* port; AmneziaWG is
/// reachable on `127.0.0.1:<backend_port>`. AWG obfuscation params are
/// synthesised into the INI the upstream parser expects so we reuse its
/// H-range parsing and overlap validation; a malformed/pre-2.0 param set
/// degrades to "no padding transform" (matching upstream `main`), never a
/// hard failure.
fn build_config(
    settings: &db::ProxySettings,
    iface: &db::Interface,
) -> (ProxyConfig, Option<CbParams>) {
    let public_port = iface.port;
    let backend_port = effective_backend_port(settings, iface.port);

    let mut cfg = ProxyConfig {
        listen: format!("0.0.0.0:{public_port}"),
        backend: format!("127.0.0.1:{backend_port}"),
        imitate_protocol: settings.protocol.clone(),
        quic_handshake_enabled: settings.quic_handshake,
        // Fall back to a plausible public domain rather than "localhost" if the
        // operator clears the field — a self-signed cert for "localhost" is a
        // giveaway on a public QUIC responder.
        quic_certificate_domain: if settings.quic_cert_domain.trim().is_empty() {
            "www.cloudflare.com".to_string()
        } else {
            settings.quic_cert_domain.clone()
        },
        dns_forward_enabled: settings.dns_forward,
        dns_upstream: settings.dns_upstream.clone(),
        status_file: proxy_status_file(),
        // Session caps bound the spoofed-source fd/exhaustion blast radius.
        // Clamp to sane ranges so a bad DB value can't set 0 (which would
        // reject all clients) or an absurd fd count.
        max_sessions: (settings.max_sessions.clamp(16, 65_536)) as usize,
        session_ttl_secs: settings.session_ttl.clamp(15, 3_600) as u64,
        ..ProxyConfig::default()
    };
    // dns_forward only composes with dns/auto; drop it otherwise so the
    // proxy's own validate() (were it ever run) and the responder stay
    // consistent.
    if !matches!(cfg.imitate_protocol.as_str(), "dns" | "auto") {
        cfg.dns_forward_enabled = false;
    }

    let cb = build_cb_params(iface);
    (cfg, cb)
}

/// Where the proxy writes its live-sessions JSON. Lives under the runtime
/// conf dir so a single tmpfs/volume mount covers it.
fn proxy_status_file() -> String {
    format!("{}/proxy/sessions.json", CONFIG.wg_conf_dir.trim_end_matches('/'))
}

fn build_cb_params(iface: &db::Interface) -> Option<CbParams> {
    // Reuse the upstream INI parser (H-range parse + overlap/Jmin<=Jmax
    // validation). S3/S4 fall back to 0 for pre-2.0 interfaces that never
    // generated them.
    let s3 = iface.s3.unwrap_or(0);
    let s4 = iface.s4.unwrap_or(0);
    let text = format!(
        "[Interface]\nJc={}\nJmin={}\nJmax={}\nS1={}\nS2={}\nS3={}\nS4={}\nH1={}\nH2={}\nH3={}\nH4={}\n",
        iface.j_c, iface.j_min, iface.j_max, iface.s1, iface.s2, s3, s4,
        norm_h(&iface.h1), norm_h(&iface.h2), norm_h(&iface.h3), norm_h(&iface.h4),
    );
    match pconfig::parse_cb_config(&text) {
        Ok(p) => Some(p),
        Err(e) => {
            crate::warn!(
                error = %e,
                "proxy: AmneziaWG params unusable; running without padding transform"
            );
            None
        }
    }
}

/// Normalise an H field for the upstream parser, which accepts a `u32`
/// (single) or `min-max` (u32 pair) in **decimal only**. AmneziaWG /
/// amnezia-client also accept `0x`-hex, and a blank field is possible.
///
/// Audit finding F3: a hex H value would make `parse_cb_config` fail,
/// which drops the proxy to `cb_params = None` and silently disables the
/// *entire* padding transform (global pass-through). We convert every hex
/// token to decimal here so that never happens. A blank field maps to `0`
/// (an all-zero range never matches → that type is pass-through, which is
/// the correct fail-safe). If a token is genuinely unparseable it is left
/// verbatim so `parse_cb_config` still surfaces a clear diagnostic.
fn norm_h(h: &str) -> String {
    let h = h.trim();
    if h.is_empty() {
        return "0".to_string();
    }
    match h.split_once('-') {
        Some((lo, hi)) => match (parse_h_token(lo), parse_h_token(hi)) {
            (Some(a), Some(b)) => format!("{a}-{b}"),
            _ => h.to_string(),
        },
        None => match parse_h_token(h) {
            Some(v) => v.to_string(),
            None => h.to_string(),
        },
    }
}

/// Parse a single H token as decimal or `0x`/`0X` hex `u32`.
fn parse_h_token(tok: &str) -> Option<u32> {
    let tok = tok.trim();
    match tok.strip_prefix("0x").or_else(|| tok.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16).ok(),
        None => tok.parse::<u32>().ok(),
    }
}

/// True when the proxy is actively fronting the public port. In that state
/// AmneziaWG's own pre-handshake junk — the `Jc` dummy datagrams and the
/// `I1–I5` templated packets — is both redundant with the proxy's
/// imitation and counterproductive: those are *separate* datagrams from
/// the four WireGuard message types the proxy rewrites, so they cross the
/// wire un-imitated as random/templated UDP, re-exposing exactly the
/// fingerprint the proxy exists to erase (audit finding F1). The config
/// generator consults this to drop `Jc`/`I1–I5` from the effective
/// AmneziaWG config while keeping `S1–S4`/`H1–H4` (which the proxy needs).
/// Non-destructive — the stored DB values are untouched, so disabling the
/// proxy restores native junk on the next render.
pub fn suppress_native_junk() -> bool {
    is_active()
}

fn hash_config(cfg: &ProxyConfig, cb: &Option<CbParams>) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    cfg.listen.hash(&mut hasher);
    cfg.backend.hash(&mut hasher);
    cfg.imitate_protocol.hash(&mut hasher);
    cfg.quic_handshake_enabled.hash(&mut hasher);
    cfg.quic_certificate_domain.hash(&mut hasher);
    cfg.dns_forward_enabled.hash(&mut hasher);
    cfg.dns_upstream.hash(&mut hasher);
    if let Some(p) = cb {
        // Debug-format is stable for these plain-data structs and captures
        // every field that changes classification/padding behaviour.
        format!("{p:?}").hash(&mut hasher);
    } else {
        "no-cb".hash(&mut hasher);
    }
    hasher.finish()
}

/// Reconcile the running proxy task with desired DB state. The single
/// "do the right thing" entry point — call after any mutation that could
/// affect the proxy. Does NOT touch AmneziaWG's own config; see
/// [`apply_and_reconcile`] for the enable/disable rebind.
pub async fn ensure_running() -> Result<()> {
    let settings = db::get_proxy_settings().context("get_proxy_settings")?;
    let iface = match db::get_interface() {
        Ok(i) => i,
        Err(_) => {
            // No interface yet (pre-setup) — nothing to front.
            stop_if_running("no AmneziaWG interface configured yet").await;
            return Ok(());
        }
    };

    if let Some(reason) = should_remain_disabled(&settings, &iface) {
        stop_if_running(&reason).await;
        return Ok(());
    }

    let (cfg, cb) = build_config(&settings, &iface);
    let cfg_hash = hash_config(&cfg, &cb);

    {
        let guard = lock_state().await;
        if let Some(state) = guard.as_ref() {
            if let Some(live) = state.live.as_ref() {
                if live.cfg_hash == cfg_hash {
                    // Already running with exactly this config — no-op.
                    return Ok(());
                }
            }
        }
    }

    // Config differs (or not running) — stop any current task and start fresh.
    stop_if_running("reconfiguring").await;
    start(cfg, cb, cfg_hash).await
}

async fn start(cfg: ProxyConfig, cb: Option<CbParams>, cfg_hash: u64) -> Result<()> {
    let listen = cfg.listen.clone();
    let backend = cfg.backend.clone();
    let protocol = cfg.imitate_protocol.clone();

    // Make sure the status-file directory exists before the proxy tries to
    // write it, and lock it to the owner: the status JSON maps proxy
    // sessions to real client source IPs, so it must not be world-readable.
    if let Some(parent) = std::path::Path::new(&cfg.status_file).parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }

    // The proxy binds IPv4 (0.0.0.0) only. On a dual-stack server, IPv6
    // clients would hit the (now loopback-locked) backend port directly and
    // get nothing — warn loudly rather than fail, since v4 clients are fine.
    if !CONFIG.disable_ipv6 {
        crate::warn!(
            "DPI proxy binds IPv4 (0.0.0.0) only — IPv6 clients cannot reach it \
             while the proxy is enabled. Use an IPv4 endpoint for clients, or set \
             DISABLE_IPV6=true."
        );
    }

    let proxy = Proxy::bind(cfg, cb)
        .await
        .with_context(|| format!("bind DPI proxy on {listen}"))?;
    let shutdown = proxy.shutdown_handle();
    let generation = GENERATION.fetch_add(1, Ordering::SeqCst) + 1;

    let join = tokio::spawn(async move {
        let result = proxy.run().await;
        // Task ended. If this is still the current generation and the exit
        // wasn't an administrative stop, record it as a crash.
        let mut guard = lock_state().await;
        let state = guard.as_mut().expect("state initialised");
        let is_current = state
            .live
            .as_ref()
            .map(|l| l.generation == generation)
            .unwrap_or(false);
        if is_current {
            state.live = None;
            match result {
                Ok(()) => {
                    // Clean self-exit without a stop request is unusual but
                    // not an error — leave no crash marker.
                    crate::info!("DPI proxy task exited");
                }
                Err(e) => {
                    crate::error!(error = %e, "DPI proxy task exited with error");
                    state.last_error = Some(format!("{e:#}"));
                }
            }
        }
    });

    let mut guard = lock_state().await;
    let state = guard.as_mut().expect("state initialised");
    state.live = Some(Live {
        shutdown,
        join,
        cfg_hash,
        generation,
        started_at: Instant::now(),
        listen: listen.clone(),
        backend: backend.clone(),
        protocol: protocol.clone(),
    });
    state.disabled_reason = None;
    state.last_error = None;
    crate::info!(%listen, %backend, %protocol, "DPI proxy started");
    Ok(())
}

async fn stop_if_running(reason: &str) {
    let live = {
        let mut guard = lock_state().await;
        let state = guard.as_mut().expect("state initialised");
        let live = state.live.take();
        state.disabled_reason = Some(reason.to_string());
        live
    };
    let Some(live) = live else { return };
    crate::info!(%reason, "stopping DPI proxy");
    // Signal the run loop to drain and return, then wait for the task to
    // actually finish so a follow-up rebind/start can reclaim the port.
    live.shutdown.shutdown();
    match tokio::time::timeout(std::time::Duration::from_secs(5), live.join).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => crate::warn!(error = %e, "DPI proxy task join error"),
        Err(_) => crate::warn!("DPI proxy task did not stop within 5s"),
    }
}

/// Administrative stop.
pub async fn stop() -> Result<()> {
    stop_if_running("administrative stop").await;
    Ok(())
}

/// Snapshot for the admin UI.
pub async fn status() -> Status {
    let guard = lock_state().await;
    let s = match guard.as_ref() {
        Some(s) => s,
        None => {
            return Status::Disabled {
                reason: "proxy not initialised".to_string(),
            }
        }
    };
    if let Some(live) = s.live.as_ref() {
        return Status::Running {
            listen: live.listen.clone(),
            backend: live.backend.clone(),
            protocol: live.protocol.clone(),
            uptime_seconds: live.started_at.elapsed().as_secs(),
        };
    }
    if let Some(err) = s.last_error.as_ref() {
        return Status::Crashed {
            last_error: err.clone(),
        };
    }
    Status::Disabled {
        reason: s
            .disabled_reason
            .clone()
            .unwrap_or_else(|| "proxy is disabled".to_string()),
    }
}

/// Whether the proxy is currently fronting the public port. Consulted by
/// the wg config generator and firewall to decide AmneziaWG's effective
/// ListenPort and the loopback lockdown.
pub fn is_active() -> bool {
    db::get_proxy_settings()
        .map(|s| {
            s.enabled
                && db::get_interface()
                    .map(|i| should_remain_disabled(&s, &i).is_none())
                    .unwrap_or(false)
        })
        .unwrap_or(false)
}

/// Full enable/disable orchestration: reconfigure AmneziaWG (rebind
/// between the public and loopback port), reapply the firewall lockdown,
/// then reconcile the proxy task. Called by the admin API after writing
/// `proxy_settings_table`. Restarting AmneziaWG on the new ListenPort is
/// what actually frees/claims the public UDP port for the proxy.
pub async fn apply_and_reconcile() -> Result<()> {
    // Re-render the AmneziaWG config so its ListenPort matches the new
    // proxy state (public port when disabled, backend port when enabled).
    if let Err(e) = crate::wg::save_config() {
        crate::warn!(error = %e, "wg save_config during proxy apply failed (non-fatal)");
    }
    // Apply the backend-port firewall lockdown BEFORE restarting AmneziaWG.
    // Ordering matters: `restart` binds AmneziaWG on the loopback backend
    // port, which (being an all-addresses UDP bind) is briefly reachable
    // from the WAN until the drop rule lands. Installing the lockdown first
    // closes that window so the raw AmneziaWG listener is never exposed.
    // `apply_proxy_lockdown` is a no-op (and removes the chain) when the
    // proxy is inactive, so this also correctly tears the lockdown down on
    // disable before AmneziaWG reclaims the public port.
    if let Ok(iface) = db::get_interface() {
        if let Err(e) = crate::firewall::apply_proxy_lockdown(&iface) {
            // Fail closed while the proxy is being enabled. The comment above
            // is the whole reason this call is ordered here: AmneziaWG is
            // about to be rebound onto the backend port with an all-addresses
            // UDP bind, and the lockdown is what keeps that raw, un-imitated
            // listener off the WAN. Warning and carrying on left it exposed on
            // a predictable `public_port ± 1` indefinitely, while the UI
            // reported the proxy as Running — the opposite of what enabling
            // the proxy is for.
            //
            // On the disable path the lockdown is a teardown and a failure
            // only leaves a stale drop rule, which is not an exposure, so that
            // direction stays non-fatal.
            let enabling = db::get_proxy_settings().map(|s| s.enabled).unwrap_or(false);
            if enabling {
                crate::error!(
                    error = %e,
                    "proxy firewall lockdown failed; refusing to rebind AmneziaWG onto \
                     the backend port, which would leave the raw listener WAN-reachable"
                );
                return Err(anyhow::anyhow!(
                    "backend-port lockdown failed, proxy not enabled: {e}"
                ));
            }
            crate::warn!(error = %e, "proxy lockdown teardown failed (non-fatal)");
        }
    }
    // Restart so the kernel/userspace listener actually moves and the public
    // UDP port is freed for / reclaimed from the proxy. Best-effort: a wg
    // failure still lets the proxy reconcile so the operator sees a coherent
    // status.
    if let Err(e) = crate::wg::restart() {
        crate::warn!(error = %e, "wg restart during proxy apply failed (non-fatal)");
    }
    ensure_running().await
}

/// Used by main.rs during graceful shutdown. Best-effort.
pub async fn shutdown_for_exit() {
    let _ = stop().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(port: i64) -> db::Interface {
        db::Interface {
            name: "cb0".into(),
            device: "eth0".into(),
            port,
            private_key: "k".into(),
            public_key: "K".into(),
            ipv4_cidr: "10.8.0.0/24".into(),
            ipv6_cidr: "fdcc::cafe:0/112".into(),
            mtu: 1420,
            j_c: 7,
            j_min: 10,
            j_max: 1000,
            s1: 128,
            s2: 56,
            s3: Some(40),
            s4: Some(120),
            h1: "5-100".into(),
            h2: "200-300".into(),
            h3: "400-500".into(),
            h4: "600-700".into(),
            i1: String::new(),
            i2: String::new(),
            i3: String::new(),
            i4: String::new(),
            i5: String::new(),
            header_protection_key: String::new(),
            content_padding_addition: String::new(),
            rekey_after_time: String::new(),
            rekey_timeout: String::new(),
            reject_after_time: String::new(),
            keepalive_timeout: String::new(),
            max_handshake_attempts: String::new(),
            random_trailers: false,
            disable_cookies: false,
            firewall_enabled: false,
            dns_lockdown: false,
            dns_lockdown_target: String::new(),
            dns_block_external: true,
            additional_config: String::new(),
            enabled: true,
            created_at: "now".into(),
            updated_at: "now".into(),
        }
    }

    fn settings() -> db::ProxySettings {
        db::ProxySettings {
            id: "proxy0".into(),
            enabled: true,
            protocol: "quic".into(),
            backend_port: 0,
            quic_handshake: true,
            quic_cert_domain: "www.cloudflare.com".into(),
            dns_forward: false,
            dns_upstream: "1.1.1.1:53".into(),
            additional_config: String::new(),
            max_sessions: 2048,
            session_ttl: 120,
            created_at: "now".into(),
            updated_at: "now".into(),
        }
    }

    #[test]
    fn parse_h_token_decimal_and_hex() {
        assert_eq!(parse_h_token("100"), Some(100));
        assert_eq!(parse_h_token(" 100 "), Some(100));
        assert_eq!(parse_h_token("0x64"), Some(100));
        assert_eq!(parse_h_token("0X64"), Some(100));
        assert_eq!(parse_h_token("0xffffffff"), Some(u32::MAX));
        assert_eq!(parse_h_token("nothex"), None);
        assert_eq!(parse_h_token("0x1_0"), None); // no underscores
    }

    #[test]
    fn norm_h_converts_hex_to_decimal() {
        // Single hex value → decimal (audit F3: a hex H must not break the
        // decimal-only upstream parser and silently disable the transform).
        assert_eq!(norm_h("0x64"), "100");
        // Hex range → decimal range.
        assert_eq!(norm_h("0x5-0x64"), "5-100");
        // Mixed hex/decimal range.
        assert_eq!(norm_h("5-0x64"), "5-100");
        // Decimal passes through unchanged.
        assert_eq!(norm_h("5-100"), "5-100");
        assert_eq!(norm_h("42"), "42");
        // Blank → "0" (fail-safe: never matches, that type is pass-through).
        assert_eq!(norm_h(""), "0");
        assert_eq!(norm_h("   "), "0");
        // Genuinely unparseable → left verbatim for a clear parser diagnostic.
        assert_eq!(norm_h("garbage"), "garbage");
    }

    #[test]
    fn hex_h_interface_still_parses_cb_params() {
        // An interface whose H fields are hex must still yield usable AWG
        // params (not None → which would globally disable the transform).
        let mut i = iface(51820);
        i.h1 = "0x5-0x64".into();
        i.h2 = "0xc8-0x12c".into();
        i.h3 = "0x190-0x1f4".into();
        i.h4 = "0x258-0x2bc".into();
        let cb = build_cb_params(&i);
        assert!(cb.is_some(), "hex H must normalise to decimal and parse");
    }

    #[test]
    fn backend_port_auto_is_public_plus_one() {
        assert_eq!(effective_backend_port(&settings(), 51820), 51821);
    }

    #[test]
    fn backend_port_auto_wraps_at_max() {
        assert_eq!(effective_backend_port(&settings(), 65535), 65534);
    }

    #[test]
    fn backend_port_explicit_wins() {
        let mut s = settings();
        s.backend_port = 40000;
        assert_eq!(effective_backend_port(&s, 51820), 40000);
    }

    #[test]
    fn disabled_when_off() {
        let mut s = settings();
        s.enabled = false;
        assert!(should_remain_disabled(&s, &iface(51820))
            .unwrap()
            .contains("disabled"));
    }

    #[test]
    fn disabled_on_backend_collision() {
        let mut s = settings();
        s.backend_port = 51820;
        assert!(should_remain_disabled(&s, &iface(51820))
            .unwrap()
            .contains("collides"));
    }

    #[test]
    fn disabled_on_bad_protocol() {
        let mut s = settings();
        s.protocol = "http".into();
        assert!(should_remain_disabled(&s, &iface(51820))
            .unwrap()
            .contains("unsupported"));
    }

    #[test]
    fn disabled_on_quic_without_cert_domain() {
        let mut s = settings();
        s.quic_cert_domain = "   ".into();
        assert!(should_remain_disabled(&s, &iface(51820))
            .unwrap()
            .contains("certificate domain"));
    }

    #[test]
    fn enabled_config_builds_and_binds_loopback() {
        let s = settings();
        let i = iface(51820);
        assert!(should_remain_disabled(&s, &i).is_none());
        let (cfg, cb) = build_config(&s, &i);
        assert_eq!(cfg.listen, "0.0.0.0:51820");
        assert_eq!(cfg.backend, "127.0.0.1:51821");
        assert_eq!(cfg.imitate_protocol, "quic");
        assert!(cb.is_some(), "2.0 params should parse");
    }

    #[test]
    fn dns_forward_dropped_for_non_dns_protocol() {
        let mut s = settings();
        s.dns_forward = true; // but protocol is quic
        let (cfg, _) = build_config(&s, &iface(51820));
        assert!(!cfg.dns_forward_enabled);
    }

    #[test]
    fn dns_forward_kept_for_dns_protocol() {
        let mut s = settings();
        s.protocol = "dns".into();
        s.dns_forward = true;
        let (cfg, _) = build_config(&s, &iface(51820));
        assert!(cfg.dns_forward_enabled);
    }
}
