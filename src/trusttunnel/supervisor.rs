//! Subprocess supervisor for the bundled TrustTunnel endpoint.
//!
//! State machine, in plain English (same shape as `mdnsvpn::supervisor`):
//!
//! - **Disabled** — inbound off, no usable TLS hostname, or no active user.
//! - **Running** — child alive, PID + start time tracked.
//! - **Crashed** — child exited unexpectedly; the watchdog restarts it with
//!   capped exponential backoff and gives up after ten quick failures.
//!
//! ## Why every change is a restart
//!
//! The endpoint reads `vpn.toml`, `credentials.toml` and `rules.toml` once,
//! at startup; there is no control API. `SIGHUP` reloads only `hosts.toml`,
//! and a hosts file that fails to parse there *panics the process*
//! (`endpoint/src/main.rs`, the SIGHUP arm uses `expect`). So a change is
//! applied as stop → rewrite → start, and only when the rendered files
//! actually differ ([`Rendered::fingerprint`]) — a no-op save does not drop
//! every user's tunnel.
//!
//! Roster edits arrive in bursts (adding five users is five POSTs), so the
//! user API calls [`request_reconcile`], which waits for
//! [`RECONCILE_DEBOUNCE`] of quiet before restarting once.
//!
//! ## Stopping
//!
//! The endpoint drains gracefully on `SIGINT` and installs no `SIGTERM`
//! handler, so `SIGTERM` would kill it with no drain. Stop sends `SIGINT`,
//! then `SIGKILL` after the grace period.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, Notify};
use tokio::time::sleep;

use crate::config::CONFIG;
use crate::db;
use crate::proc::{pid_alive, restart_backoff, send_signal, HEALTHY_UPTIME};
use crate::trusttunnel::config::{self as cfggen, Paths};
use crate::trusttunnel::{cert, runtime, stats};

/// Quiet period before a requested reconcile runs.
pub const RECONCILE_DEBOUNCE: Duration = Duration::from_millis(1500);

/// How long `/health-check` gets to come up after a spawn before we log
/// that the endpoint is slow (not fatal — the watchdog owns crashes).
const STARTUP_HEALTH_DEADLINE: Duration = Duration::from_secs(15);

const STOP_GRACE: Duration = Duration::from_secs(10);

const MAX_RESTART_ATTEMPTS: u32 = 10;

fn runtime_dir() -> PathBuf {
    PathBuf::from(&CONFIG.trusttunnel_dir)
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum Status {
    Disabled { reason: String },
    Running { pid: u32, uptime_seconds: u64, healthy: bool, users: usize },
    Crashed { last_error: String, restart_attempts: u32 },
}

#[derive(Debug)]
struct LiveProcess {
    pid: u32,
    started_at: Instant,
    shutdown_requested: Arc<AtomicBool>,
    fingerprint: String,
    users: usize,
}

#[derive(Debug, Default)]
struct CrashState {
    last_error: Option<String>,
    restart_attempts: u32,
}

#[derive(Debug, Default)]
struct State {
    proc: Option<LiveProcess>,
    crash: CrashState,
    disabled_reason: Option<String>,
    healthy: bool,
}

static STATE: Mutex<Option<State>> = Mutex::const_new(None);

/// Serialises whole reconciles so two admin saves cannot interleave a
/// stop/start pair.
static RECONCILE_LOCK: Mutex<()> = Mutex::const_new(());

static RECONCILE_REQUESTED: Notify = Notify::const_new();
static BACKGROUND_STARTED: AtomicBool = AtomicBool::new(false);

async fn lock_state<'a>() -> tokio::sync::MutexGuard<'a, Option<State>> {
    let mut guard = STATE.lock().await;
    if guard.is_none() {
        *guard = Some(State::default());
    }
    guard
}

/// Everything rendered for one spawn.
struct Rendered {
    vpn: String,
    hosts: String,
    credentials: String,
    rules: String,
    chain_pem: String,
    key_pem: String,
    users: usize,
    passwords: Vec<String>,
    usernames: Vec<String>,
    metrics_port: u16,
}

impl Rendered {
    /// Restart only when this changes.
    fn fingerprint(&self) -> String {
        let mut h = Sha256::new();
        for part in [&self.vpn, &self.hosts, &self.credentials, &self.rules, &self.chain_pem, &self.key_pem] {
            h.update((part.len() as u64).to_be_bytes());
            h.update(part.as_bytes());
        }
        crate::encoding::hex_encode(h.finalize())
    }
}

/// Reconcile process state with the DB. Call after every inbound change;
/// roster changes should prefer [`request_reconcile`].
pub async fn ensure_running() -> Result<()> {
    ensure_background_tasks();
    ensure_running_inner(true).await
}

/// Debounced [`ensure_running`] for bursts of roster edits. Errors surface
/// through [`status`].
pub fn request_reconcile() {
    ensure_background_tasks();
    RECONCILE_REQUESTED.notify_one();
}

/// Reason we'd refuse to start, shown verbatim in the admin UI.
fn should_remain_disabled(
    inbound: &db::TrustTunnelInbound,
    users: &[db::TrustTunnelUser],
    host: &str,
    now: time::OffsetDateTime,
) -> Option<String> {
    if !inbound.enabled {
        return Some("TrustTunnel is disabled in admin settings".to_string());
    }
    if let Err(e) = cfggen::effective_hostname(inbound, host) {
        return Some(e.to_string());
    }
    if !users.iter().any(|u| cfggen::is_active(u, now)) {
        // Upstream refuses an empty credentials list on a public address
        // (NoCredentialsOnPublicAddress), so this is a hard precondition.
        return Some("TrustTunnel has no active users — add one to start the endpoint".to_string());
    }
    None
}

/// Make sure the inbound has TLS material for `hostname`, issuing or
/// re-issuing the self-signed certificate when needed. Returns the row as
/// it now stands in the DB.
pub fn ensure_certificate(
    inbound: db::TrustTunnelInbound,
    hostname: &str,
) -> Result<db::TrustTunnelInbound> {
    let missing = inbound.tls_chain_pem.trim().is_empty() || inbound.tls_key_pem.trim().is_empty();
    match inbound.tls_mode.as_str() {
        "self_signed" if missing || inbound.tls_cert_hostname != hostname => {
            let m = cert::self_signed(hostname)?;
            let mut fields = db::UpdateMap::new();
            fields.insert("tls_chain_pem".into(), m.chain_pem);
            fields.insert("tls_key_pem".into(), m.key_pem);
            fields.insert("tls_cert_hostname".into(), hostname.to_string());
            db::update_trusttunnel_inbound(&fields)?;
            crate::info!(hostname, "TrustTunnel: issued a self-signed certificate (existing links must be re-shared)");
            db::get_trusttunnel_inbound()
        }
        "custom" if missing => Err(anyhow!(
            "TLS mode is 'custom' but no certificate chain and key have been uploaded"
        )),
        _ => Ok(inbound),
    }
}

fn render(
    inbound: &db::TrustTunnelInbound,
    users: &[db::TrustTunnelUser],
    hostname: &str,
    paths: &Paths,
    now: time::OffsetDateTime,
) -> Result<Rendered> {
    cfggen::validate_roster(inbound, users, now)?;
    let material = cert::Material {
        chain_pem: inbound.tls_chain_pem.clone(),
        key_pem: inbound.tls_key_pem.clone(),
    };
    // Re-checked on every render, not only at upload: the endpoint
    // load-tests certificates at startup, and an expired or mismatched one
    // is a crash loop rather than an error the UI can show.
    cert::validate(&material, hostname).context("TrustTunnel TLS certificate")?;

    let icmp_iface = if inbound.icmp_enabled {
        let configured = inbound.icmp_interface.trim();
        if configured.is_empty() {
            cfggen::default_route_interface()
        } else {
            Some(configured.to_string())
        }
    } else {
        None
    };
    let active: Vec<&db::TrustTunnelUser> = users.iter().filter(|u| cfggen::is_active(u, now)).collect();
    Ok(Rendered {
        vpn: cfggen::generate_vpn(inbound, paths, !CONFIG.disable_ipv6, icmp_iface.as_deref())?,
        hosts: cfggen::generate_hosts(inbound, hostname, paths)?,
        credentials: cfggen::generate_credentials(users, now)?,
        rules: cfggen::generate_rules(users, now, inbound.require_client_random_prefix)?,
        chain_pem: material.chain_pem,
        key_pem: material.key_pem,
        users: active.len(),
        passwords: active.iter().map(|u| u.password.clone()).collect(),
        usernames: active.iter().map(|u| u.username.clone()).collect(),
        metrics_port: u16::try_from(inbound.metrics_port).context("metrics port")?,
    })
}

async fn write_files(r: &Rendered, paths: &Paths) -> Result<()> {
    crate::secretfile::ensure_dir(&runtime_dir()).await?;
    crate::secretfile::ensure_dir(&paths.tls_dir).await?;
    // Certificate first: hosts.toml must never point at a key that is not
    // on disk yet.
    crate::secretfile::write_atomic(&paths.chain, r.chain_pem.as_bytes()).await?;
    crate::secretfile::write_atomic(&paths.key, r.key_pem.as_bytes()).await?;
    crate::secretfile::write_atomic(&paths.credentials, r.credentials.as_bytes()).await?;
    crate::secretfile::write_atomic(&paths.rules, r.rules.as_bytes()).await?;
    crate::secretfile::write_atomic(&paths.hosts, r.hosts.as_bytes()).await?;
    crate::secretfile::write_atomic(&paths.vpn, r.vpn.as_bytes()).await?;
    Ok(())
}

async fn ensure_running_inner(reset_crash: bool) -> Result<()> {
    let _serial = RECONCILE_LOCK.lock().await;
    let inbound = db::get_trusttunnel_inbound().context("get_trusttunnel_inbound")?;
    let users = db::list_trusttunnel_users().context("list_trusttunnel_users")?;
    let host = db::get_user_config().map(|c| c.host).unwrap_or_default();
    let now = crate::datetime::now_utc();
    stats::retain(&users.iter().map(|u| u.username.clone()).collect::<Vec<_>>());

    if let Some(reason) = should_remain_disabled(&inbound, &users, &host, now) {
        stop_if_running(&reason).await;
        return Ok(());
    }

    let result = async {
        let hostname = cfggen::effective_hostname(&inbound, &host)?;
        let inbound = ensure_certificate(inbound, &hostname)?;
        let paths = Paths::new(&runtime_dir());
        let rendered = render(&inbound, &users, &hostname, &paths, now)?;
        Ok::<_, anyhow::Error>((rendered, paths))
    }
    .await;
    let (rendered, paths) = match result {
        Ok(v) => v,
        Err(e) => {
            // A config we refuse to render must not leave a stale endpoint
            // serving the previous roster (a removed user would keep access).
            stop_if_running("configuration error").await;
            let mut guard = lock_state().await;
            let state = guard.as_mut().expect("state initialised");
            state.disabled_reason = Some(format!("{e:#}"));
            return Err(e);
        }
    };
    let fingerprint = rendered.fingerprint();

    let unchanged = {
        let guard = lock_state().await;
        guard
            .as_ref()
            .and_then(|s| s.proc.as_ref())
            .is_some_and(|p| p.fingerprint == fingerprint && pid_alive(p.pid))
    };
    if unchanged {
        crate::debug!("TrustTunnel config unchanged; endpoint left running");
        return Ok(());
    }

    stop_if_running("config-driven restart").await;
    write_files(&rendered, &paths).await?;

    let bin = runtime::extract_bundled_binary().context("extract trusttunnel_endpoint")?;
    let child = spawn(&bin, &paths, &rendered).await?;
    let pid = child
        .id()
        .ok_or_else(|| anyhow!("trusttunnel_endpoint child has no PID — race during spawn"))?;
    stats::mark_endpoint_restarted();
    let shutdown_requested = Arc::new(AtomicBool::new(false));
    {
        let mut guard = lock_state().await;
        let state = guard.as_mut().expect("state initialised");
        state.proc = Some(LiveProcess {
            pid,
            started_at: Instant::now(),
            shutdown_requested: shutdown_requested.clone(),
            fingerprint,
            users: rendered.users,
        });
        if reset_crash {
            state.crash = CrashState::default();
        } else {
            state.crash.last_error = None;
        }
        state.disabled_reason = None;
        state.healthy = false;
    }
    spawn_watchdog(child, shutdown_requested);

    let port = rendered.metrics_port;
    tokio::spawn(async move {
        let ok = stats::wait_until_healthy(port, STARTUP_HEALTH_DEADLINE).await;
        if ok {
            crate::info!(pid, "TrustTunnel endpoint is healthy");
        } else {
            crate::warn!(pid, "TrustTunnel endpoint did not answer /health-check within {STARTUP_HEALTH_DEADLINE:?}");
        }
        let mut guard = lock_state().await;
        if let Some(state) = guard.as_mut() {
            if state.proc.as_ref().is_some_and(|p| p.pid == pid) {
                state.healthy = ok;
            }
        }
    });
    Ok(())
}

async fn spawn(bin: &Path, paths: &Paths, rendered: &Rendered) -> Result<Child> {
    let mut cmd = Command::new(bin);
    cmd.arg("--loglvl")
        .arg("info")
        .arg(&paths.vpn)
        .arg(&paths.hosts)
        // Upstream resolves relative paths against the CWD; ours are all
        // absolute, but pin the CWD anyway so nothing resolves against
        // wherever coffeeblack-vpn happened to start.
        .current_dir(runtime_dir())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(false);
    crate::proc::harden_child(&mut cmd);
    let mut child = cmd.spawn().with_context(|| format!("spawn {}", bin.display()))?;
    let scrubber = Arc::new(Scrubber::new(&rendered.usernames, &rendered.passwords));
    if let Some(stdout) = child.stdout.take() {
        spawn_log_pump(stdout, "trusttunnel.stdout", crate::log::Level::Info, scrubber.clone());
    }
    if let Some(stderr) = child.stderr.take() {
        spawn_log_pump(stderr, "trusttunnel.stderr", crate::log::Level::Warn, scrubber);
    }
    crate::info!(
        pid = child.id().unwrap_or(0),
        users = rendered.users,
        config = %paths.vpn.display(),
        "trusttunnel_endpoint spawned"
    );
    Ok(child)
}

/// Defence in depth for the child's log stream. Upstream already scrubs
/// SNI-embedded credentials (`net_utils::scrub_sni`), but a password, or the
/// `base64(user:pass)` form both Basic auth and SNI auth carry, must never
/// reach journald through a log line we have not read.
struct Scrubber {
    needles: Vec<String>,
}

impl Scrubber {
    fn new(usernames: &[String], passwords: &[String]) -> Self {
        let mut needles: Vec<String> = Vec::new();
        for (u, p) in usernames.iter().zip(passwords) {
            needles.push(p.clone());
            let basic = crate::encoding::b64_encode(format!("{u}:{p}"));
            needles.push(basic.trim_end_matches('=').to_string());
            needles.push(basic);
        }
        needles.retain(|n| n.len() >= 8);
        // Longest first, so the padded base64 form is replaced whole.
        needles.sort_by_key(|n| std::cmp::Reverse(n.len()));
        needles.dedup();
        Scrubber { needles }
    }

    fn scrub<'a>(&self, line: &'a str) -> std::borrow::Cow<'a, str> {
        let mut out = std::borrow::Cow::Borrowed(line);
        for n in &self.needles {
            if out.contains(n.as_str()) {
                out = std::borrow::Cow::Owned(out.replace(n.as_str(), "<redacted>"));
            }
        }
        out
    }
}

fn spawn_log_pump<R>(reader: R, target: &'static str, level: crate::log::Level, scrubber: Arc<Scrubber>)
where
    R: tokio::io::AsyncRead + Send + Unpin + 'static,
{
    tokio::spawn(async move {
        let mut lines = BufReader::new(reader).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let line = line.trim_end();
            if line.is_empty() {
                continue;
            }
            let line = scrubber.scrub(line);
            let line = line.as_ref();
            match level {
                crate::log::Level::Error => crate::error!(target: "trusttunnel", source = target, "{line}"),
                crate::log::Level::Warn  => crate::warn!(target:  "trusttunnel", source = target, "{line}"),
                crate::log::Level::Info  => crate::info!(target:  "trusttunnel", source = target, "{line}"),
                _                        => crate::debug!(target: "trusttunnel", source = target, "{line}"),
            }
        }
    });
}

async fn stop_if_running(reason: &str) {
    let live = {
        let mut guard = lock_state().await;
        let state = guard.as_mut().expect("state initialised");
        let live = state.proc.take();
        state.disabled_reason = Some(reason.to_string());
        state.healthy = false;
        live
    };
    let Some(live) = live else { return };

    live.shutdown_requested.store(true, Ordering::SeqCst);
    let pid = live.pid;
    crate::info!(pid, %reason, "stopping trusttunnel_endpoint");
    if let Err(e) = send_signal(pid, libc::SIGINT) {
        if e.raw_os_error() != Some(libc::ESRCH) {
            crate::warn!(pid, error = ?e, "SIGINT failed; will SIGKILL");
        }
    }

    let deadline = Instant::now() + STOP_GRACE;
    while Instant::now() < deadline {
        if !pid_alive(pid) {
            crate::info!(pid, "trusttunnel_endpoint exited cleanly within grace period");
            stats::mark_endpoint_restarted();
            return;
        }
        sleep(Duration::from_millis(50)).await;
    }
    crate::warn!(pid, "trusttunnel_endpoint did not exit within {STOP_GRACE:?}, sending SIGKILL");
    let _ = send_signal(pid, libc::SIGKILL);
    for _ in 0..50 {
        if !pid_alive(pid) {
            stats::mark_endpoint_restarted();
            return;
        }
        sleep(Duration::from_millis(40)).await;
    }
    crate::error!(pid, "trusttunnel_endpoint failed to exit even after SIGKILL");
}

fn spawn_watchdog(mut child: Child, shutdown_requested: Arc<AtomicBool>) {
    tokio::spawn(async move {
        let pid = child.id().unwrap_or(0);
        let exit = child.wait().await;
        let exit_str = match exit {
            Ok(s) => format!("{s}"),
            Err(e) => format!("wait error: {e}"),
        };

        let started_at = {
            let mut guard = lock_state().await;
            let state = guard.as_mut().expect("state initialised");
            // Only clear the slot if it still holds *this* child — a
            // config-driven restart may already have installed its
            // successor.
            if state.proc.as_ref().is_some_and(|p| p.pid == pid) {
                state.healthy = false;
                state.proc.take().map(|p| p.started_at).unwrap_or_else(Instant::now)
            } else {
                Instant::now()
            }
        };

        if shutdown_requested.load(Ordering::SeqCst) {
            crate::info!(pid, exit = %exit_str, "trusttunnel_endpoint exited (administrative)");
            return;
        }
        stats::mark_endpoint_restarted();
        crate::warn!(pid, exit = %exit_str, "trusttunnel_endpoint exited unexpectedly");

        let attempts = {
            let mut guard = lock_state().await;
            let state = guard.as_mut().expect("state initialised");
            if started_at.elapsed() >= HEALTHY_UPTIME {
                state.crash.restart_attempts = 0;
            }
            state.crash.restart_attempts += 1;
            state.crash.last_error = Some(format!("exited after {:?}: {exit_str}", started_at.elapsed()));
            state.crash.restart_attempts
        };
        if attempts > MAX_RESTART_ATTEMPTS {
            crate::error!(attempts, "trusttunnel_endpoint restart attempts exceeded; supervisor giving up");
            return;
        }
        let backoff = restart_backoff(attempts);
        crate::info!(attempts, backoff_ms = backoff.as_millis() as u64, "scheduling trusttunnel_endpoint restart");
        sleep(backoff).await;
        if let Err(e) = ensure_running_inner(false).await {
            crate::error!(error = ?e, "trusttunnel_endpoint restart failed");
        }
    });
}

/// Start, once per process, the debounce worker and the poll loop that
/// folds per-user traffic into [`stats`] and applies user expiry.
fn ensure_background_tasks() {
    if BACKGROUND_STARTED.swap(true, Ordering::SeqCst) {
        return;
    }

    tokio::spawn(async {
        loop {
            RECONCILE_REQUESTED.notified().await;
            // Absorb the rest of the burst.
            while tokio::time::timeout(RECONCILE_DEBOUNCE, RECONCILE_REQUESTED.notified())
                .await
                .is_ok()
            {}
            if let Err(e) = ensure_running_inner(true).await {
                crate::warn!(error = ?e, "TrustTunnel reconcile failed");
            }
        }
    });

    tokio::spawn(async {
        let mut tick = tokio::time::interval(stats::POLL_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let (running, fingerprint) = {
                let guard = lock_state().await;
                match guard.as_ref().and_then(|s| s.proc.as_ref()) {
                    Some(p) => (true, p.fingerprint.clone()),
                    None => (false, String::new()),
                }
            };
            if !running {
                continue;
            }
            let Ok(inbound) = db::get_trusttunnel_inbound() else { continue };
            let Ok(port) = u16::try_from(inbound.metrics_port) else { continue };
            match stats::fetch_clients(port).await {
                Ok(rows) => {
                    stats::record(&rows, &crate::datetime::now_rfc3339());
                    let mut guard = lock_state().await;
                    if let Some(s) = guard.as_mut() {
                        s.healthy = true;
                    }
                }
                Err(e) => crate::debug!(error = %e, "TrustTunnel metrics poll failed"),
            }

            // Expiry: a user whose `expires_at` passed drops out of the
            // rendered credentials, which changes the fingerprint. Only
            // then is a restart worth its cost.
            if expiry_changed_roster(&inbound, &fingerprint) {
                crate::info!("TrustTunnel: a user expired; reloading credentials");
                if let Err(e) = ensure_running_inner(true).await {
                    crate::warn!(error = ?e, "TrustTunnel expiry reconcile failed");
                }
            }
        }
    });
}

fn expiry_changed_roster(inbound: &db::TrustTunnelInbound, running_fingerprint: &str) -> bool {
    let Ok(users) = db::list_trusttunnel_users() else { return false };
    let host = db::get_user_config().map(|c| c.host).unwrap_or_default();
    let Ok(hostname) = cfggen::effective_hostname(inbound, &host) else { return false };
    let paths = Paths::new(&runtime_dir());
    match render(inbound, &users, &hostname, &paths, crate::datetime::now_utc()) {
        Ok(r) => r.fingerprint() != running_fingerprint,
        Err(_) => true,
    }
}

pub async fn stop() -> Result<()> {
    stop_if_running("administrative stop").await;
    Ok(())
}

pub async fn restart() -> Result<()> {
    stop().await?;
    ensure_running().await
}

pub async fn status() -> Status {
    let guard = lock_state().await;
    let s = guard.as_ref().expect("state initialised");
    if let Some(ref running) = s.proc {
        return Status::Running {
            pid: running.pid,
            uptime_seconds: running.started_at.elapsed().as_secs(),
            healthy: s.healthy,
            users: running.users,
        };
    }
    if let Some(ref err) = s.crash.last_error {
        return Status::Crashed { last_error: err.clone(), restart_attempts: s.crash.restart_attempts };
    }
    Status::Disabled {
        reason: s.disabled_reason.clone().unwrap_or_else(|| "TrustTunnel is disabled".to_string()),
    }
}

/// Used by main.rs during graceful shutdown.
pub async fn shutdown_for_exit() {
    let _ = stop().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inbound(enabled: bool) -> db::TrustTunnelInbound {
        db::TrustTunnelInbound {
            id: "trusttunnel0".into(),
            port: 8443,
            listen_http1: false,
            listen_http2: true,
            listen_quic: true,
            hostname: String::new(),
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
            enabled,
            created_at: "n".into(),
            updated_at: "n".into(),
        }
    }

    fn user(enabled: bool) -> db::TrustTunnelUser {
        db::TrustTunnelUser {
            id: 1,
            user_id: None,
            name: "a".into(),
            username: "alice".into(),
            password: "abcdefghijklmnopqrstuvwx".into(),
            client_random_prefix: String::new(),
            expires_at: None,
            enabled,
            created_at: "n".into(),
            updated_at: "n".into(),
        }
    }

    fn now() -> time::OffsetDateTime {
        crate::datetime::now_utc()
    }

    #[test]
    fn disabled_reasons_in_priority_order() {
        let r = should_remain_disabled(&inbound(false), &[user(true)], "vpn.example.com", now());
        assert!(r.unwrap().contains("disabled"));
        let r = should_remain_disabled(&inbound(true), &[user(true)], "203.0.113.1", now());
        assert!(r.unwrap().contains("hostname"));
        let r = should_remain_disabled(&inbound(true), &[user(false)], "vpn.example.com", now());
        assert!(r.unwrap().contains("no active users"));
        assert!(should_remain_disabled(&inbound(true), &[user(true)], "vpn.example.com", now()).is_none());
    }

    #[test]
    fn render_is_deterministic_and_tracks_the_roster() {
        let m = cert::self_signed("vpn.example.com").unwrap();
        let mut ib = inbound(true);
        ib.tls_chain_pem = m.chain_pem;
        ib.tls_key_pem = m.key_pem;
        let paths = Paths::new(Path::new("/run/tt"));
        let a = render(&ib, &[user(true)], "vpn.example.com", &paths, now()).unwrap();
        let b = render(&ib, &[user(true)], "vpn.example.com", &paths, now()).unwrap();
        assert_eq!(a.fingerprint(), b.fingerprint(), "no-op saves must not restart");
        let mut other = user(true);
        other.password = "zzzzzzzzzzzzzzzzzzzzzzzz".into();
        let c = render(&ib, &[other], "vpn.example.com", &paths, now()).unwrap();
        assert_ne!(a.fingerprint(), c.fingerprint());
        assert!(render(&ib, &[user(true)], "other.example.com", &paths, now()).is_err(), "cert/hostname mismatch");
    }

    #[test]
    fn scrubber_masks_passwords_and_basic_auth() {
        let s = Scrubber::new(&["alice".into()], &["abcdefghijklmnopqrstuvwx".into()]);
        let basic = crate::encoding::b64_encode("alice:abcdefghijklmnopqrstuvwx");
        let line = format!("auth failed pw=abcdefghijklmnopqrstuvwx hdr=Basic {basic} sni={}.vpn", basic.trim_end_matches('='));
        let out = s.scrub(&line);
        assert!(!out.contains("abcdefghijklmnopqrstuvwx"));
        assert!(!out.contains(basic.trim_end_matches('=')));
        assert!(matches!(s.scrub("nothing here"), std::borrow::Cow::Borrowed(_)));
    }

    #[test]
    fn runtime_dir_is_the_configured_one() {
        assert_eq!(runtime_dir(), PathBuf::from(&CONFIG.trusttunnel_dir));
        let p = Paths::new(&runtime_dir());
        assert!(p.key.starts_with(&CONFIG.trusttunnel_dir));
    }
}
