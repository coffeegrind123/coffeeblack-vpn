//! Subprocess supervisor for the bundled Xray-core.
//!
//! State machine, in plain English:
//!
//! - **Disabled** — no `xray_inbound` row, or `enabled = 0`, or the
//!   keypair is missing. The supervisor refuses to spawn. `ensure_running`
//!   is the right call to make this clear in the API.
//! - **Running** — child process alive, PID + start time tracked.
//! - **Reloading** — same child, fresh config on disk, SIGHUP sent.
//!   Xray-core supports this since v25.x.
//! - **Crashed** — child exited unexpectedly. The watchdog task captures
//!   the exit status and restarts with capped exponential backoff.
//!
//! The supervisor is a thin facade over a `Mutex<Option<Child>>`. Only
//! one task ever holds the mutex at a time, which sidesteps every fancy
//! channel-based design we don't actually need: ensure/stop/status are
//! short critical sections, and the watchdog runs on a separate clone of
//! the same child handle via `child.id()` for liveness probing.

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
use crate::xray::{config_gen, runtime};

/// Path the supervisor writes the active server.json to. Lives next to
/// the extracted Xray binary so a single `COFFEEBLACK_XRAY_DIR` mount covers
/// the whole runtime surface.
fn config_path() -> PathBuf {
    PathBuf::from(&CONFIG.xray_dir).join("server.json")
}

/// Public-facing snapshot for `/api/admin/xray/status`. `Disabled` is the
/// "everything is off" state; `Running` is the happy path; `Crashed`
/// covers the "child exited unexpectedly and we're backing off" case.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum Status {
    Disabled { reason: String },
    Running { pid: u32, uptime_seconds: u64 },
    Crashed { last_error: String, restart_attempts: u32 },
}

/// What we keep in `STATE` while the child is alive. The `Child` itself
/// is owned by the watchdog task — keeping it in state would mean the
/// watchdog has to take it out before calling `wait()`, which leaves
/// `state.proc = None` even when Xray is running. The split-ownership
/// design keeps observability separate from process lifecycle.
#[derive(Debug)]
struct LiveProcess {
    pid: u32,
    started_at: Instant,
    /// Watchdog reads this on every child-exit event. When `true`,
    /// it skips the restart logic — that's how `stop()` requests a
    /// clean shutdown without racing against backoff.
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
    /// Reason set whenever the supervisor declined to start (config
    /// missing, disabled flag, etc.). Surfaced through `Status::Disabled`.
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

/// Reconcile actual process state with desired DB state. The single
/// "do the right thing" entry point — call this after every admin
/// mutation that could affect Xray.
pub async fn ensure_running() -> Result<()> {
    // A manual/administrative reconcile is a clean slate: clear any prior
    // crash-loop counter so the operator's action gets a full backoff budget.
    ensure_running_inner(true).await
}

/// `reset_crash = false` is used by the watchdog's restart path so a
/// spawn-then-quickly-exit child does NOT wipe its own `restart_attempts`
/// counter — otherwise the exponential backoff never climbs and the
/// "give up after N failures" cap is never reached (permanent ~1/s respawn).
async fn ensure_running_inner(reset_crash: bool) -> Result<()> {
    let inbound = db::get_xray_inbound().context("get_xray_inbound")?;
    let clients = db::list_xray_clients().context("list_xray_clients")?;

    // Decide whether to run at all.
    if let Some(reason) = should_remain_disabled(&inbound, &clients) {
        stop_if_running(&reason).await;
        return Ok(());
    }

    // Always re-render config first; the result is the source of truth
    // both for fresh starts and for SIGHUP reloads.
    let path = write_config(&inbound, &clients).await?;

    let mut guard = lock_state().await;
    let state = guard.as_mut().expect("state initialised");

    if let Some(running) = state.proc.as_ref() {
        // Already running — SIGHUP for hot reload. Xray re-reads the
        // file and applies the new client list without dropping
        // existing connections.
        send_signal(running.pid, libc::SIGHUP)
            .with_context(|| format!("SIGHUP to xray pid {}", running.pid))?;
        crate::info!(pid = running.pid, config = %path.display(), "xray reloaded (SIGHUP)");
        state.disabled_reason = None;
        return Ok(());
    }

    // Not running — spawn fresh and detach a watchdog.
    let bin = runtime::resolve_binary().context("resolve xray binary")?;
    let child = spawn(&bin, &path).await?;
    let pid = child
        .id()
        .ok_or_else(|| anyhow!("xray child has no PID — race during spawn"))?;
    let shutdown_requested = Arc::new(AtomicBool::new(false));
    state.proc = Some(LiveProcess {
        pid,
        started_at: Instant::now(),
        shutdown_requested: shutdown_requested.clone(),
    });
    if reset_crash {
        state.crash = CrashState::default();
    } else {
        // Watchdog-driven respawn: keep the accumulating attempt counter,
        // just clear the stale error string now that we're up again.
        state.crash.last_error = None;
    }
    state.disabled_reason = None;
    drop(guard);
    spawn_watchdog(child, shutdown_requested);
    Ok(())
}

/// Stop Xray if it's running. SIGTERM with a 10 second grace period,
/// then SIGKILL — matches what systemd and Docker do.
pub async fn stop() -> Result<()> {
    stop_if_running("administrative stop").await;
    Ok(())
}

/// Snapshot for the admin UI / metrics endpoint.
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
            .unwrap_or_else(|| "Xray inbound is disabled".to_string()),
    }
}

/// Reason we'd refuse to start — propagated to the admin UI verbatim so
/// the operator sees "no public key set" instead of a generic "not
/// running" badge.
fn should_remain_disabled(
    inbound: &db::XrayInbound,
    clients: &[db::XrayClient],
) -> Option<String> {
    if !inbound.enabled {
        return Some("xray inbound is disabled in admin settings".to_string());
    }
    if inbound.private_key.trim().is_empty() || inbound.public_key.trim().is_empty() {
        return Some(
            "xray inbound has no Reality keypair — generate one before enabling".to_string(),
        );
    }
    if !clients.iter().any(|c| c.enabled) {
        return Some(
            "no enabled xray peers — Reality requires at least one shortId in the inbound"
                .to_string(),
        );
    }
    None
}

async fn write_config(inbound: &db::XrayInbound, clients: &[db::XrayClient]) -> Result<PathBuf> {
    let path = config_path();
    let body = config_gen::generate_server_config(inbound, clients)?;
    // Atomic AND owner-only: this file holds the Reality private key and every
    // client's UUID + shortId, so a world-readable render would hand any local
    // account working tunnel credentials. `write_atomic` creates it 0600 at
    // open(2) and tightens the directory, in every deployment mode.
    crate::secretfile::write_atomic(&path, body.as_bytes()).await?;
    Ok(path)
}

async fn spawn(bin: &PathBuf, config: &PathBuf) -> Result<Child> {
    let mut cmd = Command::new(bin);
    cmd.arg("run")
        .arg("-c")
        .arg(config)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Xray-core respects $XRAY_LOCATION_ASSET for geoip.dat / geosite.dat;
        // we don't ship those because our generated config doesn't
        // reference them, but pinning the env var to xray_dir means a
        // future operator who drops them in vendor/ can light them up.
        .env("XRAY_LOCATION_ASSET", &CONFIG.xray_dir)
        .kill_on_drop(false);
    crate::proc::harden_child(&mut cmd);
    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawn {}", bin.display()))?;
    // Pipe stdout/stderr through tracing so operators get useful logs
    // alongside everything else coffeeblack-vpn emits. `take()` removes the
    // pipes from the Child so it doesn't block on full pipe buffers.
    if let Some(stdout) = child.stdout.take() {
        spawn_log_pump(stdout, "xray.stdout", crate::log::Level::Info);
    }
    if let Some(stderr) = child.stderr.take() {
        spawn_log_pump(stderr, "xray.stderr", crate::log::Level::Warn);
    }
    let pid = child.id().unwrap_or(0);
    crate::info!(pid, config = %config.display(), "xray spawned");
    Ok(child)
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
            match level {
                crate::log::Level::Error => crate::error!(target: "xray", source = target, "{line}"),
                crate::log::Level::Warn  => crate::warn!(target:  "xray", source = target, "{line}"),
                crate::log::Level::Info  => crate::info!(target:  "xray", source = target, "{line}"),
                _                     => crate::debug!(target: "xray", source = target, "{line}"),
            }
        }
    });
}

async fn stop_if_running(reason: &str) {
    // Pull the LiveProcess out and signal the watchdog that this is a
    // clean shutdown so it doesn't bounce-back-restart Xray. We wait
    // for exit by polling /proc/<pid> rather than holding the Child
    // (which lives in the watchdog task), since `kill -0 pid` works
    // for any process the supervisor can signal.
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
    crate::info!(pid, %reason, "stopping xray");
    if let Err(e) = send_signal(pid, libc::SIGTERM) {
        // ESRCH means the child already exited under our feet — fine.
        if e.raw_os_error() != Some(libc::ESRCH) {
            crate::warn!(pid, error = ?e, "SIGTERM failed; will SIGKILL");
        }
    }

    // Poll for exit. SIGTERM gets a 10s grace; after that we escalate.
    let grace = Duration::from_secs(10);
    let deadline = Instant::now() + grace;
    while Instant::now() < deadline {
        if !pid_alive(pid) {
            crate::info!(pid, "xray exited cleanly within grace period");
            return;
        }
        sleep(Duration::from_millis(50)).await;
    }
    crate::warn!(pid, "xray did not exit within {grace:?}, sending SIGKILL");
    let _ = send_signal(pid, libc::SIGKILL);
    // Final reap window — the watchdog still owns the Child handle and
    // will collect the zombie via Child::wait inside its loop.
    for _ in 0..50 {
        if !pid_alive(pid) {
            return;
        }
        sleep(Duration::from_millis(40)).await;
    }
    crate::error!(pid, "xray failed to exit even after SIGKILL");
}

/// Detached task that owns the `Child` handle and reacts to its exit.
/// One watchdog runs per spawn — when the child exits, it either
/// requests a restart (transient crash) or exits cleanly (administrative
/// shutdown).
fn spawn_watchdog(mut child: Child, shutdown_requested: Arc<AtomicBool>) {
    tokio::spawn(async move {
        let pid = child.id().unwrap_or(0);
        let exit = child.wait().await;
        let exit_str = match exit {
            Ok(s) => format!("{s}"),
            Err(e) => format!("wait error: {e}"),
        };

        // Always clear `state.proc` — the process is provably gone.
        let started_at = {
            let mut guard = lock_state().await;
            let state = guard.as_mut().expect("state initialised");
            state.proc.take().map(|p| p.started_at).unwrap_or_else(Instant::now)
        };

        if shutdown_requested.load(Ordering::SeqCst) {
            crate::info!(pid, exit = %exit_str, "xray exited (administrative)");
            return;
        }

        crate::warn!(pid, exit = %exit_str, "xray child exited unexpectedly");

        // Decide whether to restart based on current DB state.
        let inbound = match db::get_xray_inbound() {
            Ok(i) => i,
            Err(e) => {
                crate::error!(error = ?e, "watchdog: get_xray_inbound failed; giving up");
                return;
            }
        };
        let clients = db::list_xray_clients().unwrap_or_default();
        if let Some(reason) = should_remain_disabled(&inbound, &clients) {
            let mut guard = lock_state().await;
            let state = guard.as_mut().expect("state initialised");
            state.crash = CrashState::default();
            state.disabled_reason = Some(reason);
            return;
        }

        // Backoff. First retry is fast (1s); doubles up to 60s.
        // After 10 failures, surface the crash and stop respawning.
        let attempts = {
            let mut guard = lock_state().await;
            let state = guard.as_mut().expect("state initialised");
            // A child that stayed up past the healthy threshold has proven it
            // can run; treat its eventual death as a fresh incident so a
            // long-lived process that dies once doesn't inherit an old counter.
            // A child that dies faster than this keeps accumulating, so the
            // backoff escalates and the give-up cap is actually reachable.
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
            crate::error!(attempts, "xray restart attempts exceeded; supervisor giving up");
            return;
        }
        let backoff = restart_backoff(attempts);
        crate::info!(attempts, backoff_ms = backoff.as_millis() as u64, "scheduling xray restart");
        sleep(backoff).await;

        // ensure_running re-reads DB and spawns. Single source of
        // truth for "should we be running?". `false` = don't reset the
        // crash counter — this is a restart, not a manual reconcile.
        if let Err(e) = ensure_running_inner(false).await {
            crate::error!(error = ?e, "xray restart failed");
        }
    });
}

/// Used by main.rs to take Xray down during graceful shutdown. Best-
/// effort — failures are logged but don't propagate, since the rest
/// of coffeeblack-vpn needs to finish its own teardown.
pub async fn shutdown_for_exit() {
    let _ = stop().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_path_lives_under_xray_dir() {
        let p = config_path();
        // The exact dir varies with COFFEEBLACK_XRAY_DIR, but the filename
        // must always be `server.json`.
        assert_eq!(p.file_name().and_then(|s| s.to_str()), Some("server.json"));
    }

    #[test]
    fn disabled_reason_inbound_off() {
        let inbound = db::XrayInbound {
            id: "xray0".into(),
            port: 443,
            dest: "x".into(),
            server_names: "[]".into(),
            private_key: "p".into(),
            public_key: "P".into(),
            fingerprint_default: "chrome".into(),
            transport: "tcp".into(),
            xhttp_path: String::new(),
            additional_config: String::new(),
            enabled: false,
            created_at: "n".into(),
            updated_at: "n".into(),
        };
        assert!(should_remain_disabled(&inbound, &[])
            .unwrap()
            .contains("disabled"));
    }

    #[test]
    fn disabled_reason_no_keys() {
        let inbound = db::XrayInbound {
            id: "xray0".into(),
            port: 443,
            dest: "x".into(),
            server_names: "[]".into(),
            private_key: "".into(),
            public_key: "".into(),
            fingerprint_default: "chrome".into(),
            transport: "tcp".into(),
            xhttp_path: String::new(),
            additional_config: String::new(),
            enabled: true,
            created_at: "n".into(),
            updated_at: "n".into(),
        };
        assert!(should_remain_disabled(&inbound, &[])
            .unwrap()
            .contains("keypair"));
    }

    #[test]
    fn disabled_reason_no_enabled_clients() {
        let inbound = db::XrayInbound {
            id: "xray0".into(),
            port: 443,
            dest: "x".into(),
            server_names: "[]".into(),
            private_key: "p".into(),
            public_key: "P".into(),
            fingerprint_default: "chrome".into(),
            transport: "tcp".into(),
            xhttp_path: String::new(),
            additional_config: String::new(),
            enabled: true,
            created_at: "n".into(),
            updated_at: "n".into(),
        };
        // No clients at all.
        assert!(should_remain_disabled(&inbound, &[])
            .unwrap()
            .contains("enabled xray peers"));
        // Only-disabled clients.
        let disabled_client = db::XrayClient {
            id: 1,
            user_id: None,
            inbound_id: "xray0".into(),
            name: "alice".into(),
            uuid: "u".into(),
            short_id: "s".into(),
            expires_at: None,
            additional_config: None,
            enabled: false,
            created_at: "n".into(),
            updated_at: "n".into(),
        };
        assert!(should_remain_disabled(&inbound, std::slice::from_ref(&disabled_client))
            .unwrap()
            .contains("enabled xray peers"));
    }

    /// End-to-end: seed an in-memory DB, generate keys, mark the
    /// inbound enabled, add a peer, call `ensure_running`, confirm
    /// Xray is alive, then call `stop` and confirm it's gone. This is
    /// the test that catches "I refactored the spawn path and forgot
    /// to wire stderr through" type bugs.
    ///
    /// Bound to a high port so the test doesn't require root or
    /// collide with anything real on the host. Marked `#[ignore]` only
    /// because it spawns a real subprocess and uses ~30MB of RSS.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "spawns real xray subprocess; run with --ignored"]
    async fn supervisor_lifecycle_e2e() {
        // Per-test xray dir so we don't fight other e2e tests.
        let dir = format!(
            "/tmp/coffeeblack-vpn-sup-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0),
        );
        std::env::set_var("COFFEEBLACK_XRAY_DIR", &dir);

        // Fresh in-memory DB.
        db::init_test_db();

        // Pick a high random port to avoid clashes.
        let port: u16 = 14000 + (std::process::id() as u16 % 1000);
        let mut fields = db::UpdateMap::new();
        fields.insert("port".into(), port.to_string());
        // Real Reality keypair (fresh from `xray x25519`).
        fields.insert(
            "private_key".into(),
            "WNBaVNH48CG9SumFGQPEVCs1oSoZWS_hbclKHISa3ng".into(),
        );
        fields.insert(
            "public_key".into(),
            "7qWmW4TmzGw3YcFUZg6xiI4TDbeS5TTVZO8S1-1SUgg".into(),
        );
        fields.insert("enabled".into(), "1".into());
        db::update_xray_inbound(&fields).unwrap();

        db::create_xray_client(&db::CreateXrayClientParams {
            user_id: None,
            inbound_id: "xray0".into(),
            name: "alice".into(),
            uuid: "11111111-2222-3333-4444-555555555555".into(),
            short_id: "0123456789abcdef".into(),
            expires_at: None,
            additional_config: None,
            enabled: true,
        }).unwrap();

        // Start.
        ensure_running().await.expect("ensure_running");
        // Give Xray a beat to actually start listening.
        tokio::time::sleep(Duration::from_millis(800)).await;
        match status().await {
            Status::Running { pid, .. } => {
                assert!(pid > 0);
                // Process actually exists in the kernel.
                assert_eq!(unsafe { libc::kill(pid as libc::pid_t, 0) }, 0);
            }
            other => panic!("expected Running, got {other:?}"),
        }

        // Reload (SIGHUP) — must keep the same PID.
        let pid_before = match status().await {
            Status::Running { pid, .. } => pid,
            _ => unreachable!(),
        };
        ensure_running().await.unwrap();
        match status().await {
            Status::Running { pid, .. } => assert_eq!(pid, pid_before, "SIGHUP must not respawn"),
            other => panic!("after reload: expected Running, got {other:?}"),
        }

        // Stop.
        stop().await.expect("stop");
        match status().await {
            Status::Disabled { .. } => {}
            other => panic!("after stop: expected Disabled, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ready_when_all_conditions_met() {
        let inbound = db::XrayInbound {
            id: "xray0".into(),
            port: 443,
            dest: "x".into(),
            server_names: "[]".into(),
            private_key: "p".into(),
            public_key: "P".into(),
            fingerprint_default: "chrome".into(),
            transport: "tcp".into(),
            xhttp_path: String::new(),
            additional_config: String::new(),
            enabled: true,
            created_at: "n".into(),
            updated_at: "n".into(),
        };
        let client = db::XrayClient {
            id: 1,
            user_id: None,
            inbound_id: "xray0".into(),
            name: "alice".into(),
            uuid: "u".into(),
            short_id: "s".into(),
            expires_at: None,
            additional_config: None,
            enabled: true,
            created_at: "n".into(),
            updated_at: "n".into(),
        };
        assert!(should_remain_disabled(&inbound, std::slice::from_ref(&client)).is_none());
    }
}

