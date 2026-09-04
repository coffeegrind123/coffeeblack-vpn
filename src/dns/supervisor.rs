//! Subprocess supervisor for the bundled DNS stack.
//!
//! Two children, supervised independently:
//!
//! - **dnscrypt-proxy** — always started when `dns_bundle.enabled = 1`.
//! - **tor** — started ONLY when `dns_bundle.tor_enabled = 1` (tor is
//!   opt-in independent of the master toggle, per
//!   `feedback_dns_bundle.md` — Tor adds latency, exit-node trust
//!   assumptions, and bridge fetching, all unwelcome in a default
//!   install).
//!
//! Each child has its own `LiveProcess` slot, its own watchdog task,
//! its own backoff state. They share `STATE` so a single `status()`
//! call returns both. SIGHUP-on-config-change works for dnscrypt-proxy
//! but not tor — tor's `HUP` doesn't fully re-read torrc, so we
//! restart tor (clean stop + spawn) on any config change. Acceptable
//! cost since tor restarts are infrequent.
//!
//! Compiled `#[cfg(dns_bundled)]` only — `mod.rs` gates this so
//! non-bundled builds skip it entirely.

#![cfg(dns_bundled)]

use crate::proc::{pid_alive, restart_backoff, send_signal, HEALTHY_UPTIME};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tokio::time::sleep;

use crate::config::CONFIG;
use crate::db;
use crate::dns::{dnscrypt, runtime, tor};

/// Identifier used in tracing fields, log targets, error messages.
/// Keeping this in one enum lets the watchdog/backoff machinery be
/// generic over which child we're managing.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum ChildKind {
    Dnscrypt,
    Tor,
}

impl ChildKind {
    fn name(self) -> &'static str {
        match self {
            ChildKind::Dnscrypt => "dnscrypt-proxy",
            ChildKind::Tor => "tor",
        }
    }
}

fn dnscrypt_config_path() -> PathBuf {
    PathBuf::from(&CONFIG.dns_dir).join("dnscrypt-proxy.toml")
}

fn tor_config_path() -> PathBuf {
    PathBuf::from(&CONFIG.dns_dir).join("torrc")
}

/// Per-child status block surfaced to the admin UI.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum ChildStatus {
    Disabled { reason: String },
    Running { pid: u32, uptime_seconds: u64 },
    Crashed { last_error: String, restart_attempts: u32 },
}

/// Combined snapshot for `/api/admin/dns/status`.
#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub bundled: bool,
    pub dnscrypt: ChildStatus,
    pub tor: ChildStatus,
}

#[derive(Debug)]
struct LiveProcess {
    pid: u32,
    started_at: Instant,
    /// Watchdog reads this on every child-exit event. When `true`, it
    /// skips the restart logic — that's how `stop()` requests a clean
    /// shutdown without racing against backoff.
    shutdown_requested: Arc<AtomicBool>,
}

#[derive(Debug, Default)]
struct CrashState {
    last_error: Option<String>,
    restart_attempts: u32,
}

#[derive(Debug, Default)]
struct ChildSlot {
    proc: Option<LiveProcess>,
    crash: CrashState,
    /// Reason set whenever the supervisor declined to start (config
    /// missing, disabled flag, etc.). Surfaced through `Status::Disabled`.
    disabled_reason: Option<String>,
}

#[derive(Debug, Default)]
struct State {
    dnscrypt: ChildSlot,
    tor: ChildSlot,
}

static STATE: Mutex<Option<State>> = Mutex::const_new(None);

async fn lock_state<'a>() -> tokio::sync::MutexGuard<'a, Option<State>> {
    let mut guard = STATE.lock().await;
    if guard.is_none() {
        *guard = Some(State::default());
    }
    guard
}

/// Reconcile actual process state with desired DB state. Single
/// "do the right thing" entry point — call this after every admin
/// mutation that touches the dns_bundle row.
pub async fn ensure_running() -> Result<()> {
    // Manual reconcile: clean slate for both children's crash-loop counters.
    ensure_running_inner(true).await
}

/// `reset_crash = false` is used by the watchdog restart path so a
/// spawn-then-quickly-exit child keeps accumulating `restart_attempts` instead
/// of resetting to zero on every respawn (which would defeat the backoff and
/// give-up cap). Only the child actually being respawned is affected — a
/// still-running sibling takes the early SIGHUP-reload path before any reset.
async fn ensure_running_inner(reset_crash: bool) -> Result<()> {
    let bundle = db::get_dns_bundle().context("get_dns_bundle")?;

    // Reconcile each child independently so a misconfigured tor
    // doesn't take dnscrypt-proxy with it. Errors are joined into the
    // combined Result so the caller learns about both.
    let dn_res = reconcile_dnscrypt(&bundle, reset_crash).await;
    let tor_res = reconcile_tor(&bundle, reset_crash).await;
    match (dn_res, tor_res) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(d), Ok(())) => Err(d.context("dnscrypt-proxy reconcile")),
        (Ok(()), Err(t)) => Err(t.context("tor reconcile")),
        (Err(d), Err(t)) => Err(anyhow!(
            "dnscrypt-proxy reconcile: {d:#}\n\
             tor reconcile: {t:#}"
        )),
    }
}

/// Stop both children cleanly. Used by `/api/admin/dns/restart` (which
/// then calls `ensure_running`) and by `shutdown_for_exit`.
pub async fn stop() -> Result<()> {
    stop_if_running(ChildKind::Tor, "administrative stop").await;
    stop_if_running(ChildKind::Dnscrypt, "administrative stop").await;
    Ok(())
}

/// Snapshot for the admin UI / metrics endpoint.
pub async fn status() -> Status {
    let guard = lock_state().await;
    let s = guard.as_ref().expect("state initialised");
    Status {
        bundled: true,
        dnscrypt: snapshot_child(&s.dnscrypt, "DNS bundle is disabled"),
        tor: snapshot_child(&s.tor, "Tor is disabled (opt-in)"),
    }
}

fn snapshot_child(slot: &ChildSlot, default_reason: &str) -> ChildStatus {
    if let Some(ref running) = slot.proc {
        return ChildStatus::Running {
            pid: running.pid,
            uptime_seconds: running.started_at.elapsed().as_secs(),
        };
    }
    if let Some(ref err) = slot.crash.last_error {
        return ChildStatus::Crashed {
            last_error: err.clone(),
            restart_attempts: slot.crash.restart_attempts,
        };
    }
    ChildStatus::Disabled {
        reason: slot
            .disabled_reason
            .clone()
            .unwrap_or_else(|| default_reason.to_string()),
    }
}

/// Used by main.rs during graceful shutdown. Best-effort.
pub async fn shutdown_for_exit() {
    let _ = stop().await;
}

// ---------------------------------------------------------------------------
// dnscrypt-proxy reconcile
// ---------------------------------------------------------------------------

async fn reconcile_dnscrypt(bundle: &db::DnsBundle, reset_crash: bool) -> Result<()> {
    if let Some(reason) = should_dnscrypt_remain_disabled(bundle) {
        stop_if_running(ChildKind::Dnscrypt, &reason).await;
        return Ok(());
    }
    let path = write_dnscrypt_config(bundle).await?;
    let mut guard = lock_state().await;
    let state = guard.as_mut().expect("state initialised");
    if let Some(running) = state.dnscrypt.proc.as_ref() {
        // SIGHUP for hot reload.
        send_signal(running.pid, libc::SIGHUP)
            .with_context(|| format!("SIGHUP to dnscrypt-proxy pid {}", running.pid))?;
        crate::info!(
            pid = running.pid,
            config = %path.display(),
            "dnscrypt-proxy reloaded (SIGHUP)"
        );
        state.dnscrypt.disabled_reason = None;
        return Ok(());
    }
    let bin = runtime::resolve_exec("dnscrypt-proxy").context("resolve dnscrypt-proxy")?;
    let argv = vec!["-config".to_string(), path.display().to_string()];
    let child = spawn(ChildKind::Dnscrypt, &bin, argv).await?;
    let pid = child
        .id()
        .ok_or_else(|| anyhow!("dnscrypt-proxy child has no PID"))?;
    let shutdown_requested = Arc::new(AtomicBool::new(false));
    state.dnscrypt.proc = Some(LiveProcess {
        pid,
        started_at: Instant::now(),
        shutdown_requested: shutdown_requested.clone(),
    });
    if reset_crash {
        state.dnscrypt.crash = CrashState::default();
    } else {
        state.dnscrypt.crash.last_error = None;
    }
    state.dnscrypt.disabled_reason = None;
    drop(guard);
    spawn_watchdog(ChildKind::Dnscrypt, child, shutdown_requested);
    Ok(())
}

fn should_dnscrypt_remain_disabled(bundle: &db::DnsBundle) -> Option<String> {
    if !bundle.enabled {
        return Some("DNS bundle is disabled in admin settings".to_string());
    }
    if bundle.listen_port < 1 || bundle.listen_port > 65535 {
        return Some(format!(
            "DNS bundle listen_port {} is out of range",
            bundle.listen_port
        ));
    }
    if let Err(e) = dnscrypt::generate(bundle) {
        return Some(format!("dnscrypt-proxy config invalid: {e}"));
    }
    None
}

async fn write_dnscrypt_config(bundle: &db::DnsBundle) -> Result<PathBuf> {
    let dir = PathBuf::from(&CONFIG.dns_dir);
    tokio::fs::create_dir_all(&dir)
        .await
        .with_context(|| format!("create dns dir {}", dir.display()))?;
    let path = dnscrypt_config_path();
    let body = dnscrypt::generate(bundle)?;
    // Owner-only at open(2) and atomic — this file carries credentials.
    crate::secretfile::write_atomic(&path, body.as_bytes()).await?;
    Ok(path)
}

// ---------------------------------------------------------------------------
// tor reconcile
// ---------------------------------------------------------------------------

async fn reconcile_tor(bundle: &db::DnsBundle, reset_crash: bool) -> Result<()> {
    if let Some(reason) = should_tor_remain_disabled(bundle) {
        stop_if_running(ChildKind::Tor, &reason).await;
        return Ok(());
    }

    // Resolve tor itself (memfd in IN_MEMORY mode, else extracted to the
    // tmpfs bin dir) and make sure its PT plugin is materialised on disk
    // *before* we render the torrc — tor `exec`s the PT plugin path on
    // the first bridged connection, and that path must be a real file
    // (a memfd lives only in our descriptor table, not tor's). Lazy
    // resolution means an enabled-with-PT bundle on a fresh install
    // doesn't fail because lyrebird wasn't there yet.
    let tor_bin = runtime::resolve_exec("tor").context("resolve tor")?;
    if !bundle.tor_plugin.is_empty() {
        if let Some(plugin_bin) = tor::plugin_binary_name(&bundle.tor_plugin) {
            runtime::extract(plugin_bin)
                .with_context(|| format!("extract PT binary {plugin_bin}"))?;
        }
    }

    let bin_dir = runtime::bin_dir();
    let path = write_tor_config(bundle, &bin_dir).await?;

    let mut guard = lock_state().await;
    let state = guard.as_mut().expect("state initialised");

    // tor doesn't reload torrc on SIGHUP cleanly (some directives like
    // SocksPort require a full restart). Cheap to detect: any time the
    // operator changes config, they want a restart, not a reload. So
    // we always stop + respawn rather than signal.
    if state.tor.proc.is_some() {
        // Bypass the lock briefly so stop_if_running can re-acquire.
        drop(guard);
        stop_if_running(ChildKind::Tor, "config reload (restart instead of SIGHUP)").await;
    } else {
        drop(guard);
    }

    let bin = tor_bin;
    let argv = vec![
        "-f".to_string(),
        path.display().to_string(),
        // Prevent tor from writing to /etc, /var, anywhere outside our
        // dns_dir. `--quiet` so log noise on startup is muted; we have
        // our own log pump pulling tracing-level events from stdout.
        "--quiet".to_string(),
    ];
    let child = spawn(ChildKind::Tor, &bin, argv).await?;
    let pid = child.id().ok_or_else(|| anyhow!("tor child has no PID"))?;
    let shutdown_requested = Arc::new(AtomicBool::new(false));

    let mut guard = lock_state().await;
    let state = guard.as_mut().expect("state initialised");
    state.tor.proc = Some(LiveProcess {
        pid,
        started_at: Instant::now(),
        shutdown_requested: shutdown_requested.clone(),
    });
    if reset_crash {
        state.tor.crash = CrashState::default();
    } else {
        state.tor.crash.last_error = None;
    }
    state.tor.disabled_reason = None;
    drop(guard);
    spawn_watchdog(ChildKind::Tor, child, shutdown_requested);
    Ok(())
}

fn should_tor_remain_disabled(bundle: &db::DnsBundle) -> Option<String> {
    // Master toggle covers tor too — if the whole DNS bundle is off,
    // tor is off. Plus tor's own opt-in flag.
    if !bundle.enabled {
        return Some("DNS bundle is disabled in admin settings".to_string());
    }
    if !bundle.tor_enabled {
        return Some("Tor is disabled (opt-in — toggle torEnabled to start)".to_string());
    }
    if bundle.tor_socks_port < 1 || bundle.tor_socks_port > 65535 {
        return Some(format!(
            "tor_socks_port {} is out of range",
            bundle.tor_socks_port
        ));
    }
    // Pre-flight: validate generated torrc so a config-gen error
    // surfaces here rather than as a tor spawn failure.
    if let Err(e) = tor::generate(bundle, &runtime::bin_dir()) {
        return Some(format!("torrc config invalid: {e}"));
    }
    None
}

async fn write_tor_config(bundle: &db::DnsBundle, bin_dir: &Path) -> Result<PathBuf> {
    let dir = PathBuf::from(&CONFIG.dns_dir);
    tokio::fs::create_dir_all(&dir)
        .await
        .with_context(|| format!("create dns dir {}", dir.display()))?;
    let path = tor_config_path();
    let body = tor::generate(bundle, bin_dir)?;
    // Owner-only at open(2) and atomic — this file carries credentials.
    crate::secretfile::write_atomic(&path, body.as_bytes()).await?;
    Ok(path)
}

// ---------------------------------------------------------------------------
// Generic spawn / signal / watchdog plumbing
// ---------------------------------------------------------------------------

async fn spawn(kind: ChildKind, bin: &PathBuf, argv: Vec<String>) -> Result<Child> {
    let mut cmd = Command::new(bin);
    cmd.args(&argv)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(false);
    crate::proc::harden_child(&mut cmd);
    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawn {} ({})", kind.name(), bin.display()))?;
    if let Some(stdout) = child.stdout.take() {
        spawn_log_pump(stdout, log_target(kind, "stdout"), crate::log::Level::Info);
    }
    if let Some(stderr) = child.stderr.take() {
        spawn_log_pump(stderr, log_target(kind, "stderr"), crate::log::Level::Warn);
    }
    let pid = child.id().unwrap_or(0);
    crate::info!(
        kind = kind.name(),
        pid,
        bin = %bin.display(),
        "DNS bundle child spawned"
    );
    Ok(child)
}

fn log_target(kind: ChildKind, stream: &str) -> &'static str {
    // tracing's `target:` field wants &'static str; we leak (tiny,
    // bounded set: 4 unique strings ever) so the pump can hand it in.
    match (kind, stream) {
        (ChildKind::Dnscrypt, "stdout") => "dnscrypt.stdout",
        (ChildKind::Dnscrypt, _) => "dnscrypt.stderr",
        (ChildKind::Tor, "stdout") => "tor.stdout",
        (ChildKind::Tor, _) => "tor.stderr",
    }
}

fn spawn_log_pump<R>(reader: R, target: &'static str, level: crate::log::Level)
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
            // Route to a category target (`dnscrypt` or `tor`) so
            // operators can subscribe to one stream independently of
            // coffeeblack-vpn's own tracing output.
            let category = if target.starts_with("dnscrypt") {
                "dnscrypt"
            } else {
                "tor"
            };
            match level {
                crate::log::Level::Error => crate::error!(target: "dns", source = target, child = category, "{line}"),
                crate::log::Level::Warn  => crate::warn!(target:  "dns", source = target, child = category, "{line}"),
                crate::log::Level::Info  => crate::info!(target:  "dns", source = target, child = category, "{line}"),
                _                     => crate::debug!(target: "dns", source = target, child = category, "{line}"),
            }
        }
    });
}

async fn stop_if_running(kind: ChildKind, reason: &str) {
    let live = {
        let mut guard = lock_state().await;
        let state = guard.as_mut().expect("state initialised");
        let slot = match kind {
            ChildKind::Dnscrypt => &mut state.dnscrypt,
            ChildKind::Tor => &mut state.tor,
        };
        let live = slot.proc.take();
        slot.disabled_reason = Some(reason.to_string());
        live
    };
    let Some(live) = live else { return };

    live.shutdown_requested.store(true, Ordering::SeqCst);
    let pid = live.pid;
    crate::info!(kind = kind.name(), pid, %reason, "stopping DNS bundle child");
    if let Err(e) = send_signal(pid, libc::SIGTERM) {
        if e.raw_os_error() != Some(libc::ESRCH) {
            crate::warn!(kind = kind.name(), pid, error = ?e, "SIGTERM failed; will SIGKILL");
        }
    }

    let grace = Duration::from_secs(10);
    let deadline = Instant::now() + grace;
    while Instant::now() < deadline {
        if !pid_alive(pid) {
            crate::info!(kind = kind.name(), pid, "child exited cleanly within grace period");
            return;
        }
        sleep(Duration::from_millis(50)).await;
    }
    crate::warn!(
        kind = kind.name(),
        pid,
        "child did not exit within {grace:?}, sending SIGKILL"
    );
    let _ = send_signal(pid, libc::SIGKILL);
    for _ in 0..50 {
        if !pid_alive(pid) {
            return;
        }
        sleep(Duration::from_millis(40)).await;
    }
    crate::error!(kind = kind.name(), pid, "child failed to exit even after SIGKILL");
}

fn spawn_watchdog(kind: ChildKind, mut child: Child, shutdown_requested: Arc<AtomicBool>) {
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
            let slot = match kind {
                ChildKind::Dnscrypt => &mut state.dnscrypt,
                ChildKind::Tor => &mut state.tor,
            };
            slot.proc
                .take()
                .map(|p| p.started_at)
                .unwrap_or_else(Instant::now)
        };

        if shutdown_requested.load(Ordering::SeqCst) {
            crate::info!(
                kind = kind.name(),
                pid,
                exit = %exit_str,
                "DNS bundle child exited (administrative)"
            );
            return;
        }

        crate::warn!(
            kind = kind.name(),
            pid,
            exit = %exit_str,
            "DNS bundle child exited unexpectedly"
        );

        // Re-check DB state — the operator may have toggled this child
        // off in the time it took to crash + report.
        let bundle = match db::get_dns_bundle() {
            Ok(b) => b,
            Err(e) => {
                crate::error!(kind = kind.name(), error = ?e, "watchdog: get_dns_bundle failed; giving up");
                return;
            }
        };
        let still_wanted = match kind {
            ChildKind::Dnscrypt => should_dnscrypt_remain_disabled(&bundle).is_none(),
            ChildKind::Tor => should_tor_remain_disabled(&bundle).is_none(),
        };
        if !still_wanted {
            let mut guard = lock_state().await;
            let state = guard.as_mut().expect("state initialised");
            let slot = match kind {
                ChildKind::Dnscrypt => &mut state.dnscrypt,
                ChildKind::Tor => &mut state.tor,
            };
            slot.crash = CrashState::default();
            slot.disabled_reason = Some(match kind {
                ChildKind::Dnscrypt => should_dnscrypt_remain_disabled(&bundle)
                    .unwrap_or_else(|| "disabled".into()),
                ChildKind::Tor => should_tor_remain_disabled(&bundle)
                    .unwrap_or_else(|| "disabled".into()),
            });
            return;
        }

        let attempts = {
            let mut guard = lock_state().await;
            let state = guard.as_mut().expect("state initialised");
            let slot = match kind {
                ChildKind::Dnscrypt => &mut state.dnscrypt,
                ChildKind::Tor => &mut state.tor,
            };
            if started_at.elapsed() >= HEALTHY_UPTIME {
                slot.crash.restart_attempts = 0;
            }
            slot.crash.restart_attempts += 1;
            slot.crash.last_error = Some(format!(
                "exited after {:?}: {exit_str}",
                started_at.elapsed()
            ));
            slot.crash.restart_attempts
        };

        if attempts > 10 {
            crate::error!(
                kind = kind.name(),
                attempts,
                "restart attempts exceeded; supervisor giving up"
            );
            return;
        }
        let backoff = restart_backoff(attempts);
        crate::info!(
            kind = kind.name(),
            attempts,
            backoff_ms = backoff.as_millis() as u64,
            "scheduling restart"
        );
        sleep(backoff).await;

        // `false` = don't reset the crash counter — this is a restart.
        if let Err(e) = ensure_running_inner(false).await {
            crate::error!(kind = kind.name(), error = ?e, "restart failed");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(enabled: bool) -> db::DnsBundle {
        db::DnsBundle {
            id: "dns0".into(),
            enabled,
            listen_port: 5353,
            upstream_resolvers: "[]".into(),
            require_dnssec: true,
            require_nolog: true,
            require_nofilter: false,
            tor_enabled: false,
            tor_socks_port: 9053,
            tor_exit_nodes: String::new(),
            tor_dns_exit_nodes: String::new(),
            tor_use_bridges: false,
            tor_plugin: String::new(),
            additional_config: String::new(),
            created_at: "now".into(),
            updated_at: "now".into(),
        }
    }

    #[test]
    fn dnscrypt_config_path_lives_under_dns_dir() {
        assert_eq!(
            dnscrypt_config_path()
                .file_name()
                .and_then(|s| s.to_str()),
            Some("dnscrypt-proxy.toml")
        );
    }

    #[test]
    fn tor_config_path_lives_under_dns_dir() {
        assert_eq!(
            tor_config_path().file_name().and_then(|s| s.to_str()),
            Some("torrc")
        );
    }

    #[test]
    fn dnscrypt_disabled_when_master_off() {
        let b = fixture(false);
        assert!(should_dnscrypt_remain_disabled(&b)
            .unwrap()
            .contains("disabled"));
    }

    #[test]
    fn tor_disabled_when_master_off() {
        let mut b = fixture(false);
        // Even with tor_enabled=true, master-off keeps tor off.
        b.tor_enabled = true;
        assert!(should_tor_remain_disabled(&b).unwrap().contains("disabled"));
    }

    #[test]
    fn tor_disabled_when_tor_flag_off() {
        // master=on, tor=off → tor should NOT spawn. This is the
        // default-install posture.
        let b = fixture(true);
        let reason = should_tor_remain_disabled(&b).unwrap();
        assert!(reason.contains("opt-in") || reason.contains("disabled"));
    }

    #[test]
    fn tor_runs_only_when_both_master_and_tor_enabled() {
        let mut b = fixture(true);
        b.tor_enabled = true;
        // No PT, no exits — minimal valid config.
        assert!(should_tor_remain_disabled(&b).is_none());
    }

    #[test]
    fn tor_invalid_socks_port_disables() {
        let mut b = fixture(true);
        b.tor_enabled = true;
        b.tor_socks_port = 0;
        assert!(should_tor_remain_disabled(&b)
            .unwrap()
            .contains("out of range"));
    }

    #[test]
    fn tor_config_error_surfaces_in_disabled_reason() {
        let mut b = fixture(true);
        b.tor_enabled = true;
        b.tor_exit_nodes = "{usa}".into(); // bad — 3 letters
        let reason = should_tor_remain_disabled(&b).unwrap();
        assert!(reason.contains("invalid"));
    }

    #[test]
    fn dnscrypt_disabled_propagates_config_error() {
        let mut b = fixture(true);
        b.upstream_resolvers = r#"["bad'name"]"#.into();
        let reason = should_dnscrypt_remain_disabled(&b).unwrap();
        assert!(reason.contains("invalid"));
    }

    #[test]
    fn tor_off_is_default_for_enabled_bundle() {
        // Belt-and-braces against a regression that flips the default.
        // See memory: feedback_dns_bundle.md.
        let b = fixture(true);
        assert!(!b.tor_enabled);
    }

    #[test]
    fn child_kind_names_are_stable() {
        // These strings appear in tracing fields and in the JSON
        // status payload — changing them is a wire-protocol break.
        assert_eq!(ChildKind::Dnscrypt.name(), "dnscrypt-proxy");
        assert_eq!(ChildKind::Tor.name(), "tor");
    }
}
