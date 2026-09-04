//! Subprocess supervisor for the bundled MasterDnsVPN server.
//!
//! State machine, in plain English:
//!
//! - **Disabled** — no `mdnsvpn_inbound` row, or `enabled = 0`, or the
//!   inbound is missing a key / domains. The supervisor refuses to spawn.
//!   `ensure_running` is the right call to make this clear in the API.
//! - **Running** — child process alive, PID + start time tracked.
//! - **Crashed** — child exited unexpectedly. The watchdog task captures
//!   the exit status and restarts with capped exponential backoff.
//!
//! Mirror of `src/xray/supervisor.rs`. MasterDnsVPN does not provide a
//! `SIGHUP`-style reload, so config changes are applied via "stop, rewrite,
//! start fresh". Telemt's HTTP control-plane reconciliation isn't needed
//! here either — mdnsvpn has no per-user concept; the singleton encryption
//! key in the inbound row authenticates every client.

use crate::proc::{pid_alive, restart_backoff, send_signal, HEALTHY_UPTIME};
use std::path::PathBuf;
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
use crate::mdnsvpn::logscrub::LogScrubber;
use crate::mdnsvpn::{config as cfggen, keys, runtime};

fn config_path() -> PathBuf {
    PathBuf::from(&CONFIG.mdnsvpn_dir).join("server_config.toml")
}

fn key_path() -> PathBuf {
    PathBuf::from(&CONFIG.mdnsvpn_dir).join(cfggen::KEY_FILENAME)
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum Status {
    Disabled { reason: String },
    Running { pid: u32, uptime_seconds: u64 },
    Crashed { last_error: String, restart_attempts: u32 },
}

#[derive(Debug)]
struct LiveProcess {
    pid: u32,
    started_at: Instant,
    shutdown_requested: Arc<AtomicBool>,
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
/// "do the right thing" entry point — call after every admin mutation
/// that could affect the proxy.
pub async fn ensure_running() -> Result<()> {
    // Manual reconcile: clean slate for the crash-loop counter.
    ensure_running_inner(true).await
}

/// `reset_crash = false` is used by the watchdog restart path so a
/// spawn-then-quickly-exit child keeps accumulating `restart_attempts` instead
/// of resetting to zero on every respawn (which would defeat the backoff and
/// give-up cap).
async fn ensure_running_inner(reset_crash: bool) -> Result<()> {
    let inbound = db::get_mdnsvpn_inbound().context("get_mdnsvpn_inbound")?;

    if let Some(reason) = should_remain_disabled(&inbound) {
        stop_if_running(&reason).await;
        return Ok(());
    }

    // Always re-render config + key file first.
    let path = write_config(&inbound).await?;
    write_key_file(&inbound).await?;

    // mdnsvpn doesn't expose hot-reload, so any time the inbound row
    // changes we restart the process. The cost is one momentary blip
    // per admin save (a few hundred ms); the upside is no special-case
    // logic for "config changed but binary still running on stale state".
    let was_running = {
        let guard = lock_state().await;
        guard
            .as_ref()
            .and_then(|s| s.proc.as_ref())
            .map(|p| p.pid)
            .is_some()
    };
    if was_running {
        crate::info!(config = %path.display(), "mdnsvpn config changed; restarting");
        stop_if_running("config-driven restart").await;
    }

    let bin = runtime::extract_bundled_binary().context("extract mdnsvpn binary")?;
    let child = spawn(&bin, &path, &inbound.encryption_key).await?;
    let pid = child
        .id()
        .ok_or_else(|| anyhow!("mdnsvpn child has no PID — race during spawn"))?;
    let shutdown_requested = Arc::new(AtomicBool::new(false));
    {
        let mut guard = lock_state().await;
        let state = guard.as_mut().expect("state initialised");
        state.proc = Some(LiveProcess {
            pid,
            started_at: Instant::now(),
            shutdown_requested: shutdown_requested.clone(),
        });
        if reset_crash {
            state.crash = CrashState::default();
        } else {
            state.crash.last_error = None;
        }
        state.disabled_reason = None;
    }
    spawn_watchdog(child, shutdown_requested);
    Ok(())
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
        };
    }
    if let Some(ref err) = s.crash.last_error {
        return Status::Crashed {
            last_error: err.clone(),
            restart_attempts: s.crash.restart_attempts,
        };
    }
    Status::Disabled {
        reason: s
            .disabled_reason
            .clone()
            .unwrap_or_else(|| "MasterDnsVPN inbound is disabled".to_string()),
    }
}

/// Reason we'd refuse to start — propagated to the admin UI verbatim
/// so the operator sees "no domains set" instead of a generic "not
/// running" badge.
fn should_remain_disabled(inbound: &db::MdnsvpnInbound) -> Option<String> {
    if !inbound.enabled {
        return Some("MasterDnsVPN inbound is disabled in admin settings".to_string());
    }
    if inbound.encryption_key.trim().is_empty() {
        return Some(
            "MasterDnsVPN encryption_key is empty — generate one before enabling".to_string(),
        );
    }
    let domains_trimmed = inbound.domains.trim();
    // Treat both empty string and `[]` as "no domains".
    if domains_trimmed.is_empty() || domains_trimmed == "[]" {
        return Some(
            "MasterDnsVPN has no `domains` set — add the NS-delegated FQDN before enabling"
                .to_string(),
        );
    }
    // Defer the rest of the structural checks to cfggen::validate via
    // write_config, which will surface a sharper error if e.g. the
    // protocol_type is wrong. We don't duplicate that logic here so the
    // two stay in sync.
    None
}

async fn write_config(inbound: &db::MdnsvpnInbound) -> Result<PathBuf> {
    let dir = PathBuf::from(&CONFIG.mdnsvpn_dir);
    tokio::fs::create_dir_all(&dir)
        .await
        .with_context(|| format!("create mdnsvpn dir {}", dir.display()))?;

    let path = config_path();
    let body = cfggen::generate(inbound, &dir)?;
    // Owner-only at open(2) and atomic — this file carries credentials.
    crate::secretfile::write_atomic(&path, body.as_bytes()).await?;
    Ok(path)
}

/// Write the singleton encryption key to `<mdnsvpn_dir>/encrypt_key.txt`.
/// `chmod 0600` so a sloppy umask on the host doesn't leak it. mdnsvpn
/// re-reads this on every spawn so a key rotation is a stop-rewrite-start
/// cycle handled by `ensure_running`.
async fn write_key_file(inbound: &db::MdnsvpnInbound) -> Result<()> {
    let path = key_path();
    // Owner-only at open(2) and atomic — this file carries credentials.
    crate::secretfile::write_atomic(&path, inbound.encryption_key.as_bytes()).await?;
    Ok(())
}

/// Spawn mdnsvpn. `encryption_key` is not passed to the child (it reads it
/// from `encrypt_key.txt`) — it is used to build the log scrubber, because the
/// pinned upstream binary prints that key verbatim at INFO on every start and
/// our log pump would otherwise forward it into the operator's log stream.
async fn spawn(bin: &PathBuf, config: &PathBuf, encryption_key: &str) -> Result<Child> {
    let mut cmd = Command::new(bin);
    cmd.arg("-config")
        .arg(config)
        // -nowait keeps mdnsvpn from prompting on stdin during fatal
        // errors. We're running detached; the prompt would dead-lock
        // the watchdog otherwise.
        .arg("-nowait")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(false);
    crate::proc::harden_child(&mut cmd);
    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawn {}", bin.display()))?;
    let scrubber = Arc::new(LogScrubber::new(encryption_key));
    if let Some(stdout) = child.stdout.take() {
        spawn_log_pump(
            stdout,
            "mdnsvpn.stdout",
            crate::log::Level::Info,
            scrubber.clone(),
        );
    }
    if let Some(stderr) = child.stderr.take() {
        spawn_log_pump(
            stderr,
            "mdnsvpn.stderr",
            crate::log::Level::Warn,
            scrubber.clone(),
        );
    }
    let pid = child.id().unwrap_or(0);
    // Log the fingerprint ourselves so operators keep the "did the server and
    // this client load the same key?" affordance that the (now-scrubbed)
    // upstream line used to provide — without the key itself.
    let trimmed_key = encryption_key.trim();
    if !trimmed_key.is_empty() {
        crate::info!(
            fingerprint = %keys::key_fingerprint(trimmed_key),
            "mdnsvpn encryption key fingerprint (sha256 prefix; raw key never logged)"
        );
    }
    crate::info!(pid, config = %config.display(), "mdnsvpn spawned");
    Ok(child)
}

fn spawn_log_pump<R>(
    reader: R,
    target: &'static str,
    level: crate::log::Level,
    scrubber: Arc<LogScrubber>,
) where
    R: tokio::io::AsyncRead + Send + Unpin + 'static,
{
    tokio::spawn(async move {
        let mut lines = BufReader::new(reader).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let line = line.trim_end();
            if line.is_empty() {
                continue;
            }
            // Scrub before the line reaches `tracing` — once it is in the
            // subscriber it is in journald / `docker logs` / the shipper.
            let line = scrubber.scrub(line);
            let line = line.as_ref();
            match level {
                crate::log::Level::Error => crate::error!(target: "mdnsvpn", source = target, "{line}"),
                crate::log::Level::Warn  => crate::warn!(target:  "mdnsvpn", source = target, "{line}"),
                crate::log::Level::Info  => crate::info!(target:  "mdnsvpn", source = target, "{line}"),
                _                     => crate::debug!(target: "mdnsvpn", source = target, "{line}"),
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
        live
    };
    let Some(live) = live else { return };

    live.shutdown_requested.store(true, Ordering::SeqCst);
    let pid = live.pid;
    crate::info!(pid, %reason, "stopping mdnsvpn");
    if let Err(e) = send_signal(pid, libc::SIGTERM) {
        if e.raw_os_error() != Some(libc::ESRCH) {
            crate::warn!(pid, error = ?e, "SIGTERM failed; will SIGKILL");
        }
    }

    let grace = Duration::from_secs(10);
    let deadline = Instant::now() + grace;
    while Instant::now() < deadline {
        if !pid_alive(pid) {
            crate::info!(pid, "mdnsvpn exited cleanly within grace period");
            return;
        }
        sleep(Duration::from_millis(50)).await;
    }
    crate::warn!(pid, "mdnsvpn did not exit within {grace:?}, sending SIGKILL");
    let _ = send_signal(pid, libc::SIGKILL);
    for _ in 0..50 {
        if !pid_alive(pid) {
            return;
        }
        sleep(Duration::from_millis(40)).await;
    }
    crate::error!(pid, "mdnsvpn failed to exit even after SIGKILL");
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
            state.proc.take().map(|p| p.started_at).unwrap_or_else(Instant::now)
        };

        if shutdown_requested.load(Ordering::SeqCst) {
            crate::info!(pid, exit = %exit_str, "mdnsvpn exited (administrative)");
            return;
        }

        crate::warn!(pid, exit = %exit_str, "mdnsvpn child exited unexpectedly");

        let inbound = match db::get_mdnsvpn_inbound() {
            Ok(i) => i,
            Err(e) => {
                crate::error!(error = ?e, "watchdog: get_mdnsvpn_inbound failed; giving up");
                return;
            }
        };
        if let Some(reason) = should_remain_disabled(&inbound) {
            let mut guard = lock_state().await;
            let state = guard.as_mut().expect("state initialised");
            state.crash = CrashState::default();
            state.disabled_reason = Some(reason);
            return;
        }

        let attempts = {
            let mut guard = lock_state().await;
            let state = guard.as_mut().expect("state initialised");
            if started_at.elapsed() >= HEALTHY_UPTIME {
                state.crash.restart_attempts = 0;
            }
            state.crash.restart_attempts += 1;
            state.crash.last_error = Some(format!(
                "exited after {:?}: {exit_str}",
                started_at.elapsed()
            ));
            state.crash.restart_attempts
        };

        if attempts > 10 {
            crate::error!(attempts, "mdnsvpn restart attempts exceeded; supervisor giving up");
            return;
        }
        let backoff = restart_backoff(attempts);
        crate::info!(
            attempts,
            backoff_ms = backoff.as_millis() as u64,
            "scheduling mdnsvpn restart"
        );
        sleep(backoff).await;

        // `false` = don't reset the crash counter — this is a restart.
        if let Err(e) = ensure_running_inner(false).await {
            crate::error!(error = ?e, "mdnsvpn restart failed");
        }
    });
}

/// Used by main.rs during graceful shutdown.
pub async fn shutdown_for_exit() {
    let _ = stop().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_inbound(enabled: bool, key: &str, domains: &str) -> db::MdnsvpnInbound {
        db::MdnsvpnInbound {
            id: "mdnsvpn0".into(),
            domains: domains.into(),
            port: 53,
            bind: "0.0.0.0".into(),
            encryption_method: 1,
            encryption_key: key.into(),
            protocol_type: "SOCKS5".into(),
            dns_upstream_servers: r#"["1.1.1.1:53"]"#.into(),
            forward_ip: String::new(),
            forward_port: 0,
            use_external_socks5: false,
            socks5_auth: false,
            socks5_user: String::new(),
            socks5_pass: String::new(),
            additional_config: String::new(),
            enabled,
            created_at: "n".into(),
            updated_at: "n".into(),
        }
    }

    #[test]
    fn disabled_when_inbound_off() {
        let r = should_remain_disabled(&fixture_inbound(
            false,
            "0123456789abcdef",
            r#"["v.example.com"]"#,
        ));
        assert!(r.unwrap().contains("disabled"));
    }

    #[test]
    fn disabled_when_no_key() {
        let r = should_remain_disabled(&fixture_inbound(true, "", r#"["v.example.com"]"#));
        assert!(r.unwrap().contains("encryption_key"));
    }

    #[test]
    fn disabled_when_no_domains() {
        for empty in &["", "[]"] {
            let r = should_remain_disabled(&fixture_inbound(true, "0123456789abcdef", empty));
            assert!(r.unwrap().contains("domains"));
        }
    }

    #[test]
    fn ready_when_all_conditions_met() {
        let inbound = fixture_inbound(true, "0123456789abcdef", r#"["v.example.com"]"#);
        assert!(should_remain_disabled(&inbound).is_none());
    }

    #[test]
    fn config_path_lives_under_mdnsvpn_dir() {
        let p = config_path();
        assert!(p.starts_with(&CONFIG.mdnsvpn_dir));
        assert_eq!(p.file_name().unwrap(), "server_config.toml");
        let k = key_path();
        assert!(k.starts_with(&CONFIG.mdnsvpn_dir));
        assert_eq!(k.file_name().unwrap(), "encrypt_key.txt");
    }
}
