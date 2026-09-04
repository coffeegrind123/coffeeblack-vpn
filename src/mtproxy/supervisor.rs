//! Subprocess supervisor for the bundled telemt MTProxy server.
//!
//! State machine, in plain English:
//!
//! - **Disabled** — no `mtproxy_inbound` row, or `enabled = 0`, or the
//!   inbound has no modes enabled. The supervisor refuses to spawn.
//!   `ensure_running` is the right call to make this clear in the API.
//! - **Running** — child process alive, PID + start time tracked.
//! - **Reconciling** — same child, post-spawn user push to telemt's
//!   `127.0.0.1:9091/v1/users` API in progress.
//! - **Crashed** — child exited unexpectedly. The watchdog task captures
//!   the exit status and restarts with capped exponential backoff.
//!
//! Mirror of `src/xray/supervisor.rs` with two additional concerns:
//!
//! 1. **Config reload**: telemt watches `config.toml` via the `notify`
//!    crate, so rewriting the file is enough to make telemt pick up
//!    new settings without a restart. The `reload` subcommand is also
//!    available (sends SIGHUP via PID file) but the file-watch path
//!    works without it. We trust `notify` and rely on rewrite-only.
//!
//! 2. **User reconciliation**: awg-easy-rs is the durable source of
//!    truth for users; telemt's runtime state isn't. After every
//!    successful spawn (or whenever the DB roster changes through the
//!    admin API) we POST/PATCH/DELETE through telemt's `/v1/users` to
//!    converge on the DB roster.

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
use crate::mtproxy::{client, config as cfggen, runtime};

fn config_path() -> PathBuf {
    PathBuf::from(&CONFIG.mtproxy_dir).join("config.toml")
}

fn pid_file_path() -> PathBuf {
    PathBuf::from(&CONFIG.mtproxy_dir).join("telemt.pid")
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
/// spawn-then-quickly-exit child keeps accumulating `restart_attempts` (so the
/// backoff escalates and the give-up cap is reachable) instead of resetting to
/// zero on every respawn.
async fn ensure_running_inner(reset_crash: bool) -> Result<()> {
    let inbound = db::get_mtproxy_inbound().context("get_mtproxy_inbound")?;

    if let Some(reason) = should_remain_disabled(&inbound) {
        stop_if_running(&reason).await;
        return Ok(());
    }

    // Re-render config first; it's the source of truth for both fresh
    // starts and live-reload (telemt's `notify` watcher picks it up).
    let path = write_config(&inbound).await?;

    let already_running = {
        let guard = lock_state().await;
        guard
            .as_ref()
            .and_then(|s| s.proc.as_ref())
            .map(|p| p.pid)
    };

    if let Some(pid) = already_running {
        // Telemt's notify watcher will hot-reload from the file we
        // just rewrote. We don't need to touch the process. The user
        // reconciler runs in the background to push roster changes.
        crate::info!(pid, config = %path.display(), "telemt config rewritten; relying on notify hot-reload");
        spawn_user_reconciler();
        return Ok(());
    }

    // Not running — spawn fresh.
    let bin = runtime::extract_bundled_binary().context("extract telemt binary")?;
    let child = spawn(&bin, &path).await?;
    let pid = child
        .id()
        .ok_or_else(|| anyhow!("telemt child has no PID — race during spawn"))?;
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
    spawn_user_reconciler();
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
            .unwrap_or_else(|| "MTProxy inbound is disabled".to_string()),
    }
}

/// Reason we'd refuse to start — propagated to the admin UI verbatim
/// so the operator sees "no modes enabled" instead of a generic "not
/// running" badge.
fn should_remain_disabled(inbound: &db::MtproxyInbound) -> Option<String> {
    if !inbound.enabled {
        return Some("MTProxy inbound is disabled in admin settings".to_string());
    }
    if !inbound.modes_classic && !inbound.modes_secure && !inbound.modes_tls {
        return Some(
            "no MTProxy modes enabled — pick at least one of classic / secure / fake-TLS"
                .to_string(),
        );
    }
    if inbound.modes_tls && inbound.tls_domain.trim().is_empty() {
        return Some(
            "Fake-TLS mode is enabled but tls_domain is empty — set a masking domain"
                .to_string(),
        );
    }
    None
}

async fn write_config(inbound: &db::MtproxyInbound) -> Result<PathBuf> {
    let dir = PathBuf::from(&CONFIG.mtproxy_dir);
    tokio::fs::create_dir_all(&dir)
        .await
        .with_context(|| format!("create mtproxy dir {}", dir.display()))?;
    // tls_front_dir lives inside mtproxy_dir; create it too so telemt
    // doesn't have to mkdir at startup.
    tokio::fs::create_dir_all(dir.join("tlsfront"))
        .await
        .with_context(|| format!("create tlsfront dir under {}", dir.display()))?;

    let path = config_path();
    let body = cfggen::generate(inbound, &dir)?;
    // Owner-only at open(2) and atomic — this file carries credentials.
    crate::secretfile::write_atomic(&path, body.as_bytes()).await?;
    Ok(path)
}

async fn spawn(bin: &PathBuf, config: &PathBuf) -> Result<Child> {
    let mut cmd = Command::new(bin);
    cmd.arg("run")
        .arg("--pid-file")
        .arg(pid_file_path())
        .arg(config)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(false);
    crate::proc::harden_child(&mut cmd);
    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawn {}", bin.display()))?;
    if let Some(stdout) = child.stdout.take() {
        spawn_log_pump(stdout, "telemt.stdout", crate::log::Level::Info);
    }
    if let Some(stderr) = child.stderr.take() {
        spawn_log_pump(stderr, "telemt.stderr", crate::log::Level::Warn);
    }
    let pid = child.id().unwrap_or(0);
    crate::info!(pid, config = %config.display(), "telemt spawned");
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
                crate::log::Level::Error => crate::error!(target: "telemt", source = target, "{line}"),
                crate::log::Level::Warn  => crate::warn!(target:  "telemt", source = target, "{line}"),
                crate::log::Level::Info  => crate::info!(target:  "telemt", source = target, "{line}"),
                _                     => crate::debug!(target: "telemt", source = target, "{line}"),
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
    crate::info!(pid, %reason, "stopping telemt");
    if let Err(e) = send_signal(pid, libc::SIGTERM) {
        if e.raw_os_error() != Some(libc::ESRCH) {
            crate::warn!(pid, error = ?e, "SIGTERM failed; will SIGKILL");
        }
    }

    let grace = Duration::from_secs(10);
    let deadline = Instant::now() + grace;
    while Instant::now() < deadline {
        if !pid_alive(pid) {
            crate::info!(pid, "telemt exited cleanly within grace period");
            return;
        }
        sleep(Duration::from_millis(50)).await;
    }
    crate::warn!(pid, "telemt did not exit within {grace:?}, sending SIGKILL");
    let _ = send_signal(pid, libc::SIGKILL);
    for _ in 0..50 {
        if !pid_alive(pid) {
            return;
        }
        sleep(Duration::from_millis(40)).await;
    }
    crate::error!(pid, "telemt failed to exit even after SIGKILL");
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
            crate::info!(pid, exit = %exit_str, "telemt exited (administrative)");
            return;
        }

        crate::warn!(pid, exit = %exit_str, "telemt child exited unexpectedly");

        let inbound = match db::get_mtproxy_inbound() {
            Ok(i) => i,
            Err(e) => {
                crate::error!(error = ?e, "watchdog: get_mtproxy_inbound failed; giving up");
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
            crate::error!(attempts, "telemt restart attempts exceeded; supervisor giving up");
            return;
        }
        let backoff = restart_backoff(attempts);
        crate::info!(attempts, backoff_ms = backoff.as_millis() as u64, "scheduling telemt restart");
        sleep(backoff).await;

        // `false` = don't reset the crash counter — this is a restart.
        if let Err(e) = ensure_running_inner(false).await {
            crate::error!(error = ?e, "telemt restart failed");
        }
    });
}

/// Used by main.rs during graceful shutdown.
pub async fn shutdown_for_exit() {
    let _ = stop().await;
}

// ---------------------------------------------------------------------------
// User reconciliation
// ---------------------------------------------------------------------------

/// Background task: wait for telemt to be ready, then push the durable
/// user roster (mtproxy_users_table) into telemt's runtime store.
///
/// Algorithm (idempotent — running it twice converges to the same
/// state):
///
/// 1. `wait_until_alive` (up to 30 s) — telemt's startup involves
///    fetching real TLS records for `tls_domain`, which can take a few
///    seconds on the first run.
/// 2. List telemt's current users (`GET /v1/users`).
/// 3. For each DB user:
///    - Not in telemt → `POST /v1/users`.
///    - In telemt with different secret/ad_tag/enabled → `PATCH`.
///    - Match → no-op.
/// 4. For each telemt user **not** in our DB → `DELETE`. We assume the
///    operator manages MTProxy users only through awg-easy-rs; users
///    created out-of-band against telemt directly will be reaped on
///    the next reconcile.
///
/// We log per-user outcomes; callers don't have to wait for the
/// reconcile to finish (it's "fire and forget" from ensure_running's
/// perspective).
pub fn spawn_user_reconciler() {
    tokio::spawn(async move {
        if let Err(e) = reconcile_users_now().await {
            crate::warn!(error = ?e, "telemt user reconciliation failed");
        }
    });
}

/// Synchronous variant — used by the admin API after a single-user
/// CRUD operation, so the response can wait until the change is live
/// in telemt. Safe to call concurrently; telemt's API is its own
/// serializer.
pub async fn reconcile_users_now() -> Result<()> {
    // Wait up to 30 s for telemt's API to come alive (`/v1/health`
    // returns 2xx). We deliberately don't wait on `/v1/health/ready`
    // — that endpoint also gates on Telegram middle-end pool
    // reachability, which can take 20+ s on first boot and may
    // never resolve in degraded networks. The user CRUD API works
    // as soon as the listener is bound, which is what `/v1/health`
    // reports.
    client::wait_until_alive(Duration::from_secs(30))
        .await
        .context("wait for telemt /v1/health")?;

    let db_users = db::list_mtproxy_users().context("list_mtproxy_users")?;
    let live_users_value = client::list_users().await.context("list users from telemt")?;

    // Telemt wraps responses in {"ok": true, "data": [...], "revision": "..."}.
    // Pull the user array out before mapping.
    let live_map = extract_live_user_map(&live_users_value);

    let mut db_names = std::collections::HashSet::with_capacity(db_users.len());

    for u in &db_users {
        db_names.insert(u.username.clone());
        let live = live_map.get(&u.username);
        match live {
            None => {
                // Create.
                let req = client::CreateUser {
                    username: &u.username,
                    secret: &u.secret_hex,
                    ad_tag: u.ad_tag.as_deref(),
                };
                match client::create_user(&req).await {
                    Ok(_) => crate::info!(username = %u.username, "reconcile: created in telemt"),
                    Err(e) => crate::warn!(
                        username = %u.username,
                        error = ?e,
                        "reconcile: create failed"
                    ),
                }
            }
            Some(live) => {
                // Telemt's GET response doesn't include the secret (it's
                // only returned on POST and rotate-secret), so we can't
                // detect a stale secret from the reconcile path. Secret
                // updates flow through the explicit rotate-secret admin
                // API instead.
                //
                // ad_tag is named `user_ad_tag` everywhere in telemt's
                // API — responses *and* POST/PATCH bodies (measured on
                // 3.4.24 and 3.5.5; a body keyed `ad_tag` is accepted
                // with 2xx and silently dropped, which made this PATCH
                // fire on every reconcile pass and never converge).
                // `client::{CreateUser,PatchUser}` carry the rename.
                // PATCH the override when our DB value differs.
                let live_ad_tag = live.get("user_ad_tag").and_then(|v| v.as_str());
                let want_ad_tag = u.ad_tag.as_deref();
                if live_ad_tag != want_ad_tag {
                    let patch = client::PatchUser {
                        secret: None,
                        ad_tag: Some(want_ad_tag.unwrap_or("")),
                        enabled: None,
                    };
                    match client::patch_user(&u.username, &patch).await {
                        Ok(_) => crate::info!(
                            username = %u.username,
                            ad_tag = ?want_ad_tag,
                            "reconcile: ad_tag patched"
                        ),
                        Err(e) => crate::warn!(
                            username = %u.username,
                            error = ?e,
                            "reconcile: ad_tag patch failed"
                        ),
                    }
                }
            }
        }
    }

    // Anything in telemt that's not in the DB → delete it. This is the
    // step that makes awg-easy-rs the durable source of truth.
    for live_name in live_map.keys() {
        if !db_names.contains(live_name) {
            match client::delete_user(live_name).await {
                Ok(_) => crate::info!(
                    username = %live_name,
                    "reconcile: deleted orphan from telemt"
                ),
                Err(e) => crate::warn!(
                    username = %live_name,
                    error = ?e,
                    "reconcile: delete failed"
                ),
            }
        }
    }

    Ok(())
}

/// Pull a `name → JSON` map out of telemt's `/v1/users` response.
/// Telemt wraps every response in an envelope:
///
/// ```text
/// { "ok": true, "data": [<user>, ...], "revision": "<sha>" }
/// ```
///
/// (Confirmed against v3.4.11 — see the smoke-test traces in the PR
/// description.) We unwrap `data`, then iterate. As a fallback we also
/// accept a bare array and a `{ users: [...] }` shape so a future
/// upstream rename doesn't immediately break this module.
fn extract_live_user_map(
    value: &serde_json::Value,
) -> std::collections::HashMap<String, &serde_json::Value> {
    use serde_json::Value;
    let mut map = std::collections::HashMap::new();
    let array_opt: Option<&Vec<Value>> = if let Value::Array(arr) = value {
        Some(arr)
    } else if let Value::Object(obj) = value {
        // `data` is the canonical key in v3.4.11 envelopes.
        obj.get("data")
            .and_then(|v| v.as_array())
            .or_else(|| obj.get("users").and_then(|v| v.as_array()))
    } else {
        None
    };
    if let Some(arr) = array_opt {
        for entry in arr {
            if let Some(name) = entry.get("username").and_then(|v| v.as_str()) {
                map.insert(name.to_string(), entry);
            }
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_inbound(enabled: bool, modes_tls: bool) -> db::MtproxyInbound {
        db::MtproxyInbound {
            id: "mtproxy0".into(),
            port: 8080,
            public_host: String::new(),
            public_port: 0,
            tls_domain: "petrovich.ru".into(),
            mask_enabled: true,
            modes_classic: false,
            modes_secure: false,
            modes_tls,
            use_middle_proxy: true,
            ad_tag: String::new(),
            additional_config: String::new(),
            enabled,
            created_at: "n".into(),
            updated_at: "n".into(),
        }
    }

    #[test]
    fn disabled_when_inbound_off() {
        let r = should_remain_disabled(&fixture_inbound(false, true));
        assert!(r.unwrap().contains("disabled"));
    }

    #[test]
    fn disabled_when_no_modes() {
        let r = should_remain_disabled(&fixture_inbound(true, false));
        assert!(r.unwrap().contains("no MTProxy modes enabled"));
    }

    #[test]
    fn disabled_when_tls_domain_empty() {
        let mut inbound = fixture_inbound(true, true);
        inbound.tls_domain = String::new();
        let r = should_remain_disabled(&inbound);
        assert!(r.unwrap().contains("tls_domain"));
    }

    #[test]
    fn ready_when_all_conditions_met() {
        let inbound = fixture_inbound(true, true);
        assert!(should_remain_disabled(&inbound).is_none());
    }

    #[test]
    fn extract_live_user_map_handles_array_shape() {
        let v = serde_json::json!([
            { "username": "alice", "secret": "aaa" },
            { "username": "bob",   "secret": "bbb" },
        ]);
        let m = extract_live_user_map(&v);
        assert_eq!(m.len(), 2);
        assert!(m.contains_key("alice"));
        assert!(m.contains_key("bob"));
    }

    #[test]
    fn extract_live_user_map_handles_object_shape() {
        let v = serde_json::json!({
            "users": [
                { "username": "alice" },
            ]
        });
        let m = extract_live_user_map(&v);
        assert_eq!(m.len(), 1);
        assert!(m.contains_key("alice"));
    }

    #[test]
    fn extract_live_user_map_handles_unexpected_shape() {
        // A 200 with no recognizable users field returns an empty map
        // — not an error. The reconciler then treats every DB user as
        // "missing in telemt" and POSTs them, which is the right thing.
        let v = serde_json::json!({ "ok": true });
        assert!(extract_live_user_map(&v).is_empty());
    }

    #[test]
    fn extract_live_user_map_handles_data_envelope() {
        // The actual v3.4.11 shape — confirmed via smoke test against
        // a live binary. Parsed BEFORE client.rs unwraps the envelope,
        // so this fallback is what kicks in if a caller forgets to
        // unwrap (or upstream rolls back the unwrap).
        let v = serde_json::json!({
            "ok": true,
            "data": [
                { "username": "default", "user_ad_tag": null },
                { "username": "alice",   "user_ad_tag": "aaaa" },
            ],
            "revision": "deadbeef",
        });
        let m = extract_live_user_map(&v);
        assert_eq!(m.len(), 2);
        assert!(m.contains_key("default"));
        assert!(m.contains_key("alice"));
    }
}
